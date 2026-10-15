"""JSON / CSV / name-list export of query results."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from bhshell.models.entities import Graph, Node
from bhshell.models.results import Column, EntityReport, RelationshipRow

ROW_FIELDS = list(RelationshipRow.__dataclass_fields__)
NODE_FIELDS = ["kind", "name", "domain", "objectid", "tier_zero", "owned"]
# Row keys that hold an object name. The first one among a table's columns is what the table lists:
# the principal of an inbound view, the target of an outbound one.
NAME_KEYS = ("name", "principal", "target", "gpo", "linked_to")


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def report_rows(report: EntityReport) -> tuple[list[str], list[dict[str, Any]]]:
    """Flatten a report into CSV rows (summary as key/value, views as relationships)."""
    summary = [{"field": f.label, "value": _flat(f.value)} for f in report.summary()]
    if not report.views:
        return ["field", "value"], summary
    # With --all the summary comes first, as in the JSON export.
    rows = [{"view": "summary", **s} for s in summary] if report.show_summary else []
    rows += [{"view": v.key, **r.as_dict()} for v in report.views for r in v.rows]
    if not rows:
        return ["view", *ROW_FIELDS], rows
    # Views have different row types: the columns are every field seen, in order.
    return list(dict.fromkeys(key for row in rows for key in row)), rows


def node_rows(nodes: Iterable[Node]) -> tuple[list[str], list[dict[str, Any]]]:
    return NODE_FIELDS, [{k: v for k, v in n.as_dict().items() if k in NODE_FIELDS} for n in nodes]


def names(columns: Sequence[Column], rows: Iterable[Any]) -> list[str]:
    """The object each row of a table is about, once each, for `--names-only` and `.txt` files."""
    attrs = ["name" if c.attr == "label" else c.attr for c in columns]
    dicts = [row if isinstance(row, dict) else row.as_dict() for row in rows]
    key = next((a for a in attrs if a in NAME_KEYS), None)
    if key is None and dicts:  # a table showing a location instead: the name is in the row data
        key = next((k for k in ("name", "gpo", "linked_to") if k in dicts[0]), None)
    if key is None:
        return []
    return list(dict.fromkeys(str(row.get(key)) for row in dicts if row.get(key)))


def node_names(nodes: Iterable[Node]) -> list[str]:
    return list(dict.fromkeys(n.name for n in nodes if n.name))


def graph_dict(graph: Graph) -> dict[str, Any]:
    out: dict[str, Any] = {
        "nodes": [n.as_dict() for n in graph.nodes.values()],
        "edges": [
            {"source": graph.nodes[e.source].name if e.source in graph.nodes else e.source,
             "edge": e.kind,
             "target": graph.nodes[e.target].name if e.target in graph.nodes else e.target}
            for e in graph.edges
        ],
    }
    if graph.rows:
        out["rows"] = graph.rows
    return out


def graph_rows(graph: Graph) -> tuple[list[str], list[dict[str, Any]]]:
    """CSV of a raw Cypher result: the nodes, or the returned values when there are no nodes."""
    if graph.rows and not graph.nodes:
        return list(dict.fromkeys(key for row in graph.rows for key in row)), graph.rows
    return node_rows(graph.nodes.values())


def _flat(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return ";".join(map(str, value))
    return value


# Leading characters that make spreadsheet applications evaluate a cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> Any:
    """Flatten a value and neutralise formulas: AD data (descriptions, GPO names) is attacker-controlled."""
    value = _flat(value)
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write(path: str, data: Any, csv_table: tuple[list[str], list[dict[str, Any]]],
          names: list[str] | None = None) -> Path:
    """Write `data` as JSON, `csv_table` as CSV or `names` one per line, depending on the file extension."""
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix.lower() == ".csv":
        fields, rows = csv_table
        with out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows({k: _csv_cell(v) for k, v in row.items()} for row in rows)
    elif out.suffix.lower() == ".json":
        out.write_text(to_json(data) + "\n", encoding="utf-8")
    elif out.suffix.lower() == ".txt" and names is not None:
        out.write_text("".join(f"{name}\n" for name in names), encoding="utf-8")
    else:
        raise ValueError("Output file must end in .json, .csv or .txt")
    return out
