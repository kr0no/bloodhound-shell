"""Owned / high-value (Tier Zero) marking commands."""

from __future__ import annotations

import argparse
from pathlib import Path

import cmd2
from cmd2 import Cmd2ArgumentParser, with_argparser

from bhshell.errors import AuthError, BHError, ConnectionFailed
from bhshell.queries.marking import Tag
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

_LABEL = {"owned": "Owned", "tier0": "Tier Zero / High Value"}


def _marking_parser(tag: Tag) -> Cmd2ArgumentParser:
    label = _LABEL[tag]
    p = Cmd2ArgumentParser(description=f"List or change {label} objects.")
    sub = p.add_subparsers(dest="action", required=True, metavar="{list,add,remove}")
    ls = sub.add_parser("list", help=f"list {label} objects")
    ls.add_argument("-n", "--max-rows", type=int, metavar="N",
                    help="max table rows (default: config display_rows; 0 = all)")
    add_output_args(ls)
    for action in ("add", "remove"):
        a = sub.add_parser(action, help=f"{action} objects {'to' if action == 'add' else 'from'} {label}")
        a.add_argument("names", nargs="*", metavar="NAME", help="samaccountname, NAME@DOMAIN, DOMAIN\\NAME or SID",
                       choices_provider=BaseCommands.recent_names)
        a.add_argument("-f", "--file", help="read names from FILE, one per line (lines starting with '#' are skipped)",
                       completer=cmd2.Cmd.path_complete)
        a.add_argument("-t", "--type", choices=["user", "computer", "group"], help="object type (default: any)")
        a.add_argument("-d", "--domain", help="restrict the lookup to a domain")
    return p


def _read_names(path: str) -> list[str]:
    """Names in a file written by '-o FILE.txt' or by hand.

    Only whole lines starting with '#' are comments: AD names may contain '#'.
    """
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise BHError(f"Cannot read {path}: {exc.strerror}") from exc
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


class MarkingCommands(BaseCommands):
    DEFAULT_CATEGORY = "Marking"

    def _run(self, args: argparse.Namespace, tag: Tag) -> None:
        app = self.app
        app.require_auth()
        if args.action == "list":
            nodes = app.marking.list(tag)
            names = export.node_names(nodes)
            if args.json:
                app.poutput(export.to_json([n.as_dict() for n in nodes]))
            elif args.names_only:
                self.print_names(names)
            else:
                app.ui.nodes(nodes, _LABEL[tag], self.max_rows(args))
            if args.output:
                self.export(args.output, [n.as_dict() for n in nodes], export.node_rows(nodes), names)
            return
        names = list(dict.fromkeys([*args.names, *(_read_names(args.file) if args.file else [])]))
        if not names:
            raise BHError("Give at least one NAME or -f FILE")
        kind = args.type.capitalize() if args.type else None
        add = args.action == "add"
        tag_obj = app.marking.tag(tag)
        failed = 0
        for name in app.client.steps(names):
            try:
                node = app.entities.resolve(name, kind, args.domain)
                app.remember(node)
                app.ui.success(app.marking.mark(node, tag_obj, add=add))
            except (AuthError, ConnectionFailed):
                raise  # the session or the server is gone: the rest would fail the same way
            except BHError as exc:
                app.pexcept(exc)
                failed += 1
        if len(names) > 1:
            done = f"{'Marked' if add else 'Unmarked'} {len(names) - failed} of {len(names)}"
            app.ui.info(f"{done} ({failed} failed)." if failed else f"{done}.")

    @with_argparser(lambda: _marking_parser("owned"))
    def do_owned(self, args: argparse.Namespace) -> None:
        """List, add or remove owned objects."""
        self._run(args, "owned")

    @with_argparser(lambda: _marking_parser("tier0"))
    def do_hvt(self, args: argparse.Namespace) -> None:
        """List, add or remove Tier Zero / high value targets."""
        self._run(args, "tier0")
