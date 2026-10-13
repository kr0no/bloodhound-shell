"""Result containers returned by the query layer and consumed by renderers/exporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from bhshell.models.entities import ADObject, Node

Backend = Literal["cypher", "rest"]


@dataclass
class RelationshipRow:
    """One relationship in a view.

    Not every view fills every field; `Column` definitions on the
    owning `ViewResult` select which ones are displayed.
    """

    principal: str = ""
    principal_kind: str = ""
    edge: str = ""
    target: str = ""
    target_kind: str = ""
    via: str = ""
    depth: int | None = None
    tier_zero: bool = False
    owned: bool = False
    objectid: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Column:
    """A table column: `attr` is a row key; `fmt` picks the cell formatting (see `Renderer.fmt_value`)."""

    header: str
    attr: str
    fmt: str = ""


@dataclass
class ViewResult:
    """The outcome of one relationship view (groups, outbound, ...)."""

    key: str
    title: str
    columns: list[Column]
    rows: list[RelationshipRow] = field(default_factory=list)
    backend: Backend = "cypher"
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "view": self.key,
            "title": self.title,
            "backend": self.backend,
            "notes": self.notes,
            "rows": [r.as_dict() for r in self.rows],
        }


@dataclass
class EntityReport:
    """A summary and/or a set of relationship views for one entity."""

    node: Node
    show_summary: bool = True
    views: list[ViewResult] = field(default_factory=list)

    @property
    def entity(self) -> ADObject:
        return ADObject.wrap(self.node)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"entity": self.node.as_dict()}
        if self.show_summary:
            out["summary"] = {f.label: f.value for f in self.entity.summary()}
        out["views"] = {v.key: v.as_dict() for v in self.views}
        return out
