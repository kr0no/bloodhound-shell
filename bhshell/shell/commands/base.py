"""Shared helpers for bhshell command sets."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Any, cast

from cmd2 import Choices, CommandSet

from bhshell.queries import cypher as Q
from bhshell.render import export

if TYPE_CHECKING:
    from bhshell.models.entities import Graph
    from bhshell.shell.app import BHShell


class BaseCommands(CommandSet):
    @property
    def app(self) -> BHShell:
        return cast("BHShell", self._cmd)

    def recent_names(self) -> Choices:
        """Tab-completion provider: names resolved earlier in this session."""
        return Choices.from_values(self.app.recent_names)

    def max_rows(self, args: argparse.Namespace) -> int:
        return self.app.config.display_rows if args.max_rows is None else args.max_rows

    def check_domain(self, domain: str | None) -> None:
        """Warn when `-d` matches no domain BloodHound knows: the results would just be empty."""
        if not domain:
            return
        names = self.app.entities.domain_names()
        if names and not any(Q.domain_matches(domain, name) for name in names):
            self.app.ui.warn(f"No domain matches '{domain}' (known: {', '.join(names)}).")

    def export(self, path: str, data: Any, csv_table: tuple[list[str], list[dict[str, Any]]]) -> None:
        self.app.ui.success(f"Exported to {export.write(path, data, csv_table)}")

    def show_graph(self, graph: Graph, *, as_json: bool, output: str | None) -> None:
        """Print a raw Cypher result (table or JSON), exporting it when `output` is set."""
        if as_json:
            self.app.poutput(export.to_json(export.graph_dict(graph)))
        else:
            self.app.ui.graph(graph)
        if output:
            self.export(output, export.graph_dict(graph), export.graph_rows(graph))


def output_path(value: str, formats: tuple[str, ...] = (".json", ".csv")) -> str:
    """argparse type for `-o/--output`: the file extension must be one of `formats`."""
    if not value.lower().endswith(formats):
        raise argparse.ArgumentTypeError(f"output file must end in {_one_of(formats)}")
    return value


def add_output_args(parser: Any, formats: tuple[str, ...] = (".json", ".csv")) -> None:
    """`--json` and `-o FILE` on a parser or argument group."""
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    parser.add_argument("-o", "--output", type=lambda value: output_path(value, formats), metavar="FILE",
                        help=f"export to FILE ({_one_of(formats)})")


def _one_of(formats: tuple[str, ...]) -> str:
    """`.json`, `.json or .csv`, `.json, .csv or .svg`, ..."""
    if len(formats) == 1:
        return formats[0]
    return f"{', '.join(formats[:-1])} or {formats[-1]}"
