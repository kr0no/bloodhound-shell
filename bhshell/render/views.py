"""Rich renderers for entities, relationship views and graphs."""

from __future__ import annotations

import itertools
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeVar

from rich import box
from rich.console import Console
from rich.console import Group as RichGroup
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bhshell.errors import AmbiguousMatchError, BHError
from bhshell.models.entities import Graph, Node, SummaryField, epoch_to_datetime
from bhshell.models.results import Column, EntityReport, ViewResult
from bhshell.queries.edges import severity, severity_rank
from bhshell.render import graph
from bhshell.render.styles import KIND_STYLE, SEVERITY_STYLE

if TYPE_CHECKING:
    from bhshell.queries.hunt import Finding
    from bhshell.queries.paths import PathResult

T = TypeVar("T")

_NARROW_FORMATS = ("t0", "owned", "bool", "risk", "depth")
RISK_STYLE = {"high": "bold red", "medium": "yellow", "info": "cyan", "none": ""}


def first_n(items: list[T], limit: int) -> list[T]:
    """The first `limit` items; all of them when `limit` is 0."""
    return items[:limit] if limit > 0 else items


def fmt_date(value: Any) -> Text:
    dt = epoch_to_datetime(value)
    if dt is None:
        return Text("never", style="dim")
    days = (datetime.now(UTC) - dt).days
    return Text(f"{dt:%Y-%m-%d %H:%M} UTC ({days}d ago)")


def fmt_bool(value: bool | None, risk: str = "none") -> Text:
    if value is None:
        return Text("-", style="dim")
    if value:
        return Text("yes", style=RISK_STYLE.get(risk) or "green")
    return Text("no", style="dim")


def fmt_field(f: SummaryField) -> Text:
    if f.type == "bool":
        return fmt_bool(f.value, f.risk)
    if f.type == "date":
        return fmt_date(f.value)
    if f.type == "list":
        items = f.value or []
        return Text("\n".join(map(str, items)) if items else "-", style="" if items else "dim")
    text = str(f.value) if f.value not in (None, "") else "-"
    return Text(text, style=RISK_STYLE.get(f.risk, "") if text != "-" else "dim")


def fmt_kind(kind: str) -> Text:
    return Text(kind, style=KIND_STYLE.get(kind, ""))


def _marker(value: bool, symbol: str, style: str) -> Text:
    return Text(symbol, style=style) if value else Text("")


def _with_tags(text: Text, node: Node) -> Text:
    if node.tier_zero:
        text.append(" [T0]", style="bold red")
    if node.owned:
        text.append(" [owned]", style="bold cyan")
    if node.properties.get("enabled") is False:
        text.append(" [disabled]", style="dim")
    return text


def _path_summary(result: PathResult) -> Text:
    fewest = min((p.actions for p in result.paths), default=0)
    return Text(f"{len(result.paths)} path(s), shortest {result.shortest} hop(s), "
                f"fewest {fewest} action(s), "
                f"{len(result.first_hops())} distinct first hop(s)", style="dim")


def _titled(title: str, backend: str) -> str:
    return f"{title} (REST)" if backend == "rest" else title


def _more(shown: int, total: int, what: str, flag: str) -> Text:
    return Text(f"showing {shown} of {total} {what}; use {flag} 0 to show all or -o FILE to export", style="yellow")


class Renderer:
    """Turn bhshell models into rich renderables on a console.

    Results go to `console` (stdout); errors and status messages go to
    `status` (stderr) so that `bhshell -c "... --json" > out.json` stays clean.
    Object names come from AD and may contain `[...]`: they are always wrapped
    in `Text` so they are never parsed as rich markup.
    """

    def __init__(self, console: Console | None = None, status: Console | None = None) -> None:
        self.console = console or Console(highlight=False)
        self.status = status or Console(stderr=True, highlight=False)

    def summary(self, report: EntityReport) -> None:
        entity = report.entity
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
        table.add_column(style="bold")
        table.add_column(overflow="fold")
        for f in entity.summary():
            if f.type == "list" and not f.value:
                continue
            table.add_row(f.label, fmt_field(f))
        node = report.node
        self._panel(_with_tags(Text.assemble(fmt_kind(node.kind), " ", (node.name, "bold")), node), [table])

    def header(self, node: Node) -> None:
        """One-line identification used when only views were requested."""
        line = Text.assemble(fmt_kind(node.kind), " ", (node.name, "bold"), "  ", (node.objectid, "dim"))
        self.console.print(_with_tags(line, node))

    def _panel(self, title: str | Text, parts: list[Any], notes: Iterable[str] = ()) -> None:
        parts = [*parts, *(Text(f"note: {n}", style="dim italic") for n in notes)]
        self.console.print(Panel(RichGroup(*parts), title=escape(title) if isinstance(title, str) else title,
                                 title_align="left", border_style="bright_black"))

    def report(self, report: EntityReport, max_rows: int = 0) -> None:
        if report.show_summary:
            self.summary(report)
        else:
            self.header(report.node)
        for view in report.views:
            self.view(view, max_rows)

    @staticmethod
    def _breakdown(view: ViewResult) -> Text | None:
        """Per-edge counts, shown when a view has many rows of several kinds."""
        if len(view.rows) < 10 or not any(c.attr == "edge" for c in view.columns):
            return None
        counts = Counter(r.edge for r in view.rows)
        text = Text("by right: ", style="dim")
        for i, (edge, n) in enumerate(sorted(counts.items(), key=lambda kv: (severity_rank(kv[0]), -kv[1]))):
            if i:
                text.append(", ", style="dim")
            text.append(edge, style=SEVERITY_STYLE[severity(edge)])
            text.append(f" x{n}", style="dim")
        t0 = sum(1 for r in view.rows if r.tier_zero)
        owned = sum(1 for r in view.rows if r.owned)
        if t0 or owned:
            text.append(f"   |   T0: {t0}  owned: {owned}", style="dim")
        return text

    def view(self, view: ViewResult, max_rows: int = 0) -> None:
        breakdown = self._breakdown(view)
        self.table(_titled(view.title, view.backend), view.columns, [r.as_dict() for r in view.rows],
                   max_rows=max_rows, notes=view.notes, lead=[] if breakdown is None else [breakdown])

    @staticmethod
    def fmt_value(value: Any, fmt: str) -> Text:
        """Format one cell according to a `Column` `fmt` hint."""
        if fmt == "date":
            return fmt_date(value)
        if fmt == "bool":
            return fmt_bool(None if value is None else bool(value))
        if fmt == "risk":
            return fmt_bool(None if value is None else bool(value), "high")
        if fmt == "edge":
            return Text(str(value), style=SEVERITY_STYLE[severity(str(value))])
        if fmt == "kind":
            return fmt_kind(str(value))
        if fmt == "t0":
            return _marker(bool(value), "T0", "bold red")
        if fmt == "owned":
            return _marker(bool(value), "owned", "bold cyan")
        if fmt == "severity":
            return Text(str(value), style=SEVERITY_STYLE.get(str(value), ""))
        if fmt == "depth":
            return Text("-" if value is None else str(value), style="" if value else "dim")
        if fmt == "via":
            return Text(value or "-", style="dim" if value in ("direct", "") else "")
        if value is None or value == "":
            return Text("-", style="dim")
        if isinstance(value, (list, tuple)):
            return Text(", ".join(map(str, value)))
        return Text(str(value))

    def table(self, title: str, columns: Iterable[Column], rows: list[dict[str, Any]], *,
              max_rows: int = 0, notes: Iterable[str] = (), lead: Iterable[Any] = ()) -> None:
        """`lead` goes above the table, inside the panel."""
        columns = list(columns)
        parts: list[Any] = list(lead)
        if not rows:
            parts.append(Text("No results.", style="dim"))
        else:
            shown = first_n(rows, max_rows)
            table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
            for col in columns:
                table.add_column(col.header, overflow="fold", no_wrap=col.fmt in _NARROW_FORMATS)
            for row in shown:
                table.add_row(*(self.fmt_value(row.get(c.attr), c.fmt) for c in columns))
            parts.append(table)
            if len(shown) < len(rows):
                parts.append(_more(len(shown), len(rows), "rows", "--max-rows"))
        self._panel(f"{title} [{len(rows)}]", parts, notes)

    def paths(self, result: PathResult, max_paths: int = 0) -> None:
        parts: list[Any] = []
        if result.paths:
            parts.append(_path_summary(result))
            shown = first_n(result.paths, max_paths)
            for i, path in zip(result.numbers or itertools.count(1), shown):
                line = Text(f"{i:>3}. ", style="dim")
                line.append_text(self._path_node(path.start))
                for hop in path.hops:
                    line.append(" ─", style="bright_black")
                    line.append(hop.edge, style=SEVERITY_STYLE[severity(hop.edge)])
                    line.append("→ ", style="bright_black")
                    line.append_text(self._path_node(hop.target))
                parts.append(line)
            if len(shown) < len(result.paths):
                parts.append(_more(len(shown), len(result.paths), "paths", "-n"))
        else:
            parts.append(Text("No path found.", style="dim"))
        self._panel(_titled(result.title, result.backend), parts, result.notes)

    def path_graph(self, result: PathResult, max_paths: int = 0) -> None:
        """Render attack paths as one graph, falling back to the list when it is wider than the terminal."""
        shown = first_n(result.paths, max_paths)
        if not shown:
            self.paths(result, max_paths)
            return
        lines, notes = graph.draw(result, shown, max_width=self.console.width - 4)
        width = max(line.cell_len for line in lines)
        if width + 4 > self.console.width:
            self.warn(f"The graph is {width} columns wide and the terminal {self.console.width}; showing the "
                      "list instead (fewer paths with -n, or widen the terminal).")
            self.paths(result, max_paths)
            return
        parts: list[Any] = [_path_summary(result), Text(), *lines, Text(), graph.legend(shown, bool(result.waypoints))]
        if len(shown) < len(result.paths):
            parts.append(_more(len(shown), len(result.paths), "paths", "-n"))
        self._panel(_titled(result.title, result.backend), parts, [*notes, *result.notes])

    @staticmethod
    def _path_node(node: Node) -> Text:
        return _with_tags(Text(node.name, style=KIND_STYLE.get(node.kind, "")), node)

    def hunt_summary(self, findings: list[Finding]) -> None:
        table = Table(title="Hunt summary", title_justify="left", box=box.SIMPLE_HEAD, header_style="bold")
        for header in ("Severity", "Check", "Count", "Example", "Description"):
            table.add_column(header, overflow="fold")
        for f in findings:
            if f.error:
                count = Text("error", style="yellow")
            elif f.total is not None:
                count = Text(f"~{f.total}", style="bold")
            else:
                count = Text(f"{'≥' if f.truncated else ''}{len(f.rows)}",
                             style="bold" if f.rows else "dim")
            example = ""
            if f.rows:
                first = f.rows[0]
                example = str(first.get("name") or first.get("principal") or first.get("trusting") or "")
            severity = Text(f.check.severity, style=SEVERITY_STYLE.get(f.check.severity, "blue"))
            table.add_row(severity, f.check.id, count,
                          Text(example), Text(f.error or f.check.title, style="yellow" if f.error else ""))
        self.console.print(table)

    def nodes(self, nodes: Iterable[Node], title: str) -> None:
        self.console.print(self._nodes_table(nodes, title))

    @staticmethod
    def _nodes_table(nodes: Iterable[Node], title: str) -> Table:
        nodes = list(nodes)
        table = Table(title=Text(f"{title} [{len(nodes)}]"), title_justify="left", box=box.SIMPLE_HEAD,
                      header_style="bold")
        for header in ("Type", "Name", "Domain", "Object ID", "Enabled", "T0", "Owned"):
            table.add_column(header, overflow="fold")
        for n in nodes:
            enabled = n.properties.get("enabled")
            table.add_row(
                fmt_kind(n.kind), Text(n.name), Text(n.domain), Text(n.objectid, style="dim"),
                fmt_bool(None if enabled is None else bool(enabled)),
                _marker(n.tier_zero, "T0", "bold red"), _marker(n.owned, "owned", "bold cyan"),
            )
        return table

    def graph(self, graph: Graph) -> None:
        if not graph.nodes and not graph.edges:
            self.console.print(Text("No results.", style="dim"))
            return
        self.nodes(graph.nodes.values(), "Nodes")
        if graph.edges:
            table = Table(title=f"Edges [{len(graph.edges)}]", title_justify="left", box=box.SIMPLE_HEAD,
                          header_style="bold")
            for header in ("Source", "Edge", "Target"):
                table.add_column(header, overflow="fold")
            for e in graph.edges:
                src, tgt = graph.nodes.get(e.source), graph.nodes.get(e.target)
                table.add_row(Text(src.name if src else e.source),
                              Text(e.kind, style=SEVERITY_STYLE[severity(e.kind)]),
                              Text(tgt.name if tgt else e.target))
            self.console.print(table)

    def key_values(self, title: str, rows: list[tuple[str, Any]]) -> None:
        table = Table(box=None, show_header=False, padding=(0, 2))
        table.add_column(style="bold")
        table.add_column(overflow="fold")
        for key, value in rows:
            table.add_row(key, value if isinstance(value, Text) else Text(str(value)))
        self.console.print(Panel(table, title=escape(title), title_align="left", border_style="bright_black"))

    def error(self, err: BHError) -> None:
        self.status.print(Text.assemble(("error: ", "bold red"), err.message))
        if isinstance(err, AmbiguousMatchError):
            self.status.print(self._nodes_table(err.candidates, "Candidates"))
        if err.hint:
            self.status.print(Text(f"hint: {err.hint}", style="dim"))

    def success(self, message: str) -> None:
        self.status.print(Text.assemble(("[+] ", "bold green"), message))

    def info(self, message: str) -> None:
        self.status.print(Text.assemble(("[*] ", "bold blue"), message))

    def warn(self, message: str) -> None:
        self.status.print(Text.assemble(("[!] ", "bold yellow"), message))
