"""Attack-path command."""

from __future__ import annotations

import argparse
import itertools
from dataclasses import replace
from pathlib import Path

from cmd2 import Choices, Cmd2ArgumentParser, RawDescriptionCmd2HelpFormatter, with_argparser

from bhshell.errors import BHError
from bhshell.models.entities import Node
from bhshell.queries.edges import EDGE_GROUPS
from bhshell.queries.paths import PathResult, PathService
from bhshell.queries.service import PATH_KINDS
from bhshell.render import export, png, svg
from bhshell.render.views import first_n
from bhshell.shell.commands.base import BaseCommands, add_output_args


def _path_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(
        description="Find attack paths.",
        epilog="path SRC DST              shortest path between two objects\n"
               "path SRC                  shortest paths from SRC to any Tier Zero object\n"
               "path SRC [DST] --via X    go through X on the way (repeat --via for more steps, in order)\n"
               "path --owned [DST]        shortest paths from every owned object to Tier Zero (or to DST)",
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("src", nargs="?", help="source object (user, computer, group, domain, OU, GPO)",
                   choices_provider=BaseCommands.recent_names)
    p.add_argument("dst", nargs="?", help="destination object (default: Tier Zero)",
                   choices_provider=BaseCommands.recent_names)
    p.add_argument("--via", action="append", default=[], metavar="NAME", choices_provider=BaseCommands.recent_names,
                   help="intermediate step (repeatable, visited in the order given)")
    p.add_argument("--owned", action="store_true", help="start from every owned object")
    p.add_argument("--exclude", action="append", default=[], metavar="EDGE", type=_edge_group,
                   choices_provider=lambda _self: Choices.from_values(sorted(EDGE_GROUPS)),
                   help="skip these edges/groups: " + ", ".join(sorted(EDGE_GROUPS)) + " (repeatable)")
    p.add_argument("-d", "--domain", help="restrict name resolution to a domain")
    p.add_argument("--include-disabled", action="store_true",
                   help="allow paths through disabled objects that cannot be re-enabled")
    p.add_argument("-g", "--graph", action="store_true",
                   help="draw the paths as a graph (asks which ones when there are several)")
    p.add_argument("-p", "--pick", type=_selection, metavar="N",
                   help="only these paths, numbered as in the list: 2, 1,3 or 2-4")
    p.add_argument("-n", "--max-paths", type=int, default=20, metavar="N", help="paths shown (default 20, 0 = all)")
    add_output_args(p, formats=(".json", ".csv", ".svg", ".png"), names=False)
    p.add_argument("--svg-layout", choices=("auto", "horizontal", "vertical", "wrapped"), default="auto",
                   help="SVG/PNG layout (default auto: whichever prints largest on a portrait page; "
                        "wrapped: rows of hops, like lines of text)")
    p.add_argument("--png-scale", type=_scale, default=2.0, metavar="N",
                   help="PNG pixels per SVG pixel (default 2: sharp in print, same size in Word)")
    return p


def _edge_group(text: str) -> frozenset[str]:
    try:
        return EDGE_GROUPS[text.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"unknown edge group {text!r} (choose from {', '.join(sorted(EDGE_GROUPS))})") from None


def _scale(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not 1 <= value <= 8:
        raise argparse.ArgumentTypeError("must be between 1 and 8")
    return value


def _selection(text: str) -> list[int]:
    """Parse `2`, `1,3` or `2-4` into path numbers."""
    numbers: list[int] = []
    try:
        for part in text.replace(" ", "").split(","):
            first, _, last = part.partition("-")
            numbers += range(int(first), int(last or first) + 1)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a path selection: {text!r} (use e.g. 2, 1,3 or 2-4)") from None
    if not numbers or min(numbers) < 1:
        raise argparse.ArgumentTypeError(f"path numbers start at 1: {text!r}")
    return list(dict.fromkeys(numbers))


def _pick(result: PathResult, numbers: list[int]) -> PathResult:
    if max(numbers) > len(result.paths):
        raise BHError(f"There are only {len(result.paths)} path(s); cannot pick {max(numbers)}")
    picked = [result.paths[n - 1] for n in numbers]
    note = f"Showing path {', '.join(map(str, numbers))} of {len(result.paths)}."
    return replace(result, paths=picked, notes=[*result.notes, note], numbers=numbers)


class PathCommands(BaseCommands):
    DEFAULT_CATEGORY = "Analysis"

    @with_argparser(_path_parser)
    def do_path(self, args: argparse.Namespace) -> None:
        """Find attack paths between objects or towards Tier Zero."""
        app = self.app
        app.require_auth()
        exclude = frozenset().union(*args.exclude) if args.exclude else frozenset()
        service = PathService(app.entities, include_disabled=args.include_disabled, exclude=exclude)
        if args.owned:
            if args.via or (args.src and args.dst):
                raise BHError("--owned takes no SRC or --via (an optional DST is allowed)")
            dst = args.dst or args.src  # a lone positional is the optional DST
            if dst:
                result = service.owned_to(self._resolve(dst, args.domain))
            else:
                result = service.owned_to_tier_zero()
        elif not args.src:
            raise BHError("Give a SRC object or --owned")
        else:
            src = self._resolve(args.src, args.domain)
            waypoints = [self._resolve(name, args.domain) for name in args.via]
            dst = self._resolve(args.dst, args.domain) if args.dst else None
            steps = [src, *waypoints] + ([dst] if dst else [])
            for a, b in itertools.pairwise(steps):
                if a.objectid == b.objectid:
                    raise BHError(f"{a.name} appears twice in a row in the route")
            if waypoints:
                result = service.route(src, waypoints, dst)
            elif dst:
                result = service.shortest(src, dst)
            else:
                result = service.to_tier_zero(src)
        if args.pick:
            result = _pick(result, args.pick)
        elif args.graph and not args.json and len(result.paths) > 1 and app.can_ask():
            app.ui.paths(result, args.max_paths)
            shown = len(first_n(result.paths, args.max_paths))
            answer = app.read_input(f"Path(s) to draw [1-{shown}, e.g. 2, 1,3 or 2-4; Enter = all]: ").strip()
            if answer:
                try:
                    numbers = _selection(answer)
                except argparse.ArgumentTypeError as exc:
                    raise BHError(str(exc)) from exc
                result = _pick(result, numbers)
        if args.json:
            app.poutput(export.to_json(result.as_dict()))
        elif args.graph:
            app.ui.path_graph(result, args.max_paths)
        else:
            app.ui.paths(result, args.max_paths)
        if args.output and args.output.lower().endswith((".svg", ".png")):
            shown = first_n(result.paths, args.max_paths)
            out = Path(args.output).expanduser()
            document = svg.render(result, shown, args.svg_layout)
            if out.suffix.lower() == ".png":
                out.write_bytes(png.from_svg(document, args.png_scale))
            else:
                out.write_text(document, encoding="utf-8")
            app.ui.success(f"Diagram of {len(shown)} path(s) written to {out}")
        elif args.output:
            rows = result.rows()
            fields = ["path", "hop", "source", "edge", "target", "target_kind", "tier_zero"]
            self.export(args.output, result.as_dict(), (fields, rows))

    def _resolve(self, name: str, domain: str | None) -> Node:
        node = self.app.entities.resolve(name, domain=domain, kinds=PATH_KINDS)
        self.app.remember(node)
        return node
