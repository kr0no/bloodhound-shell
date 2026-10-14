"""Result containers returned by the query layer and consumed by renderers/exporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from bhshell.models.entities import ADObject, Node, SummaryField

Backend = Literal["cypher", "rest"]


class Row:
    """A view row (a dataclass): `as_dict` is what is exported, `as_display` what the table shows."""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def as_display(self) -> dict[str, Any]:
        return self.as_dict()


@dataclass
class RelationshipRow(Row):
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


def _with_enabled(total: int, enabled: int) -> str:
    return f"{total} ({enabled})" if total else "0"


@dataclass
class ContainerRow(Row):
    """One OU or container of a `tree` view; the counts cover everything below it."""

    name: str
    kind: str
    depth: int
    # The name indented under its parent, for display.
    label: str = ""
    users: int | None = None
    enabled_users: int | None = None
    computers: int | None = None
    enabled_computers: int | None = None
    groups: int | None = None
    tier_zero_below: int | None = None
    owned_below: int | None = None
    gpo_links: int = 0
    blocks_inheritance: bool | None = None
    tier_zero: bool = False
    owned: bool = False
    distinguishedname: str = ""
    objectid: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if k != "label"}

    def as_display(self) -> dict[str, Any]:
        out = asdict(self)
        for key in ("users", "computers"):
            total, enabled = out[key], out[f"enabled_{key}"]
            out[key] = None if total is None else _with_enabled(total, enabled or 0)
        return out


@dataclass
class ContainedRow(Row):
    """An object below an OU or container (`contents` view)."""

    name: str
    kind: str
    enabled: bool | None = None
    # Containers between the explored one and the object ("direct" when it is a direct child).
    location: str = ""
    depth: int = 1
    tier_zero: bool = False
    owned: bool = False
    distinguishedname: str = ""
    objectid: str = ""


@dataclass
class GPOLinkRow(Row):
    """A GPO linked to the object or to a container above it (`gpos` view)."""

    gpo: str
    linked_to: str
    linked_kind: str
    enforced: bool | None = None
    # `None` when unknown (REST fallback).
    applies: bool | None = True
    # Why it does not apply ("inheritance blocked at X"), why the link adds nothing ("duplicate: ..."), or ''.
    reason: str = ""
    # Principals outside Tier Zero that can edit the GPO.
    editable_by: list[str] = field(default_factory=list)
    tier_zero: bool = False
    owned: bool = False
    objectid: str = ""

    def as_display(self) -> dict[str, Any]:
        out = asdict(self)
        if self.applies is None:
            out["applies"] = None
        else:
            out["applies"] = ("yes" if self.applies else "no") + (f" ({self.reason})" if self.reason else "")
        shown = self.editable_by[:3]
        if len(self.editable_by) > len(shown):
            shown = [*shown, f"+{len(self.editable_by) - len(shown)} more"]
        out["editable_by"] = shown
        return out


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
    rows: list[Any] = field(default_factory=list)  # `Row`s; `RelationshipRow`s for relationship views
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
    # Summary fields computed by queries (OU contents, linked GPOs, ...), shown after the node's own.
    extra: list[SummaryField] = field(default_factory=list)

    @property
    def entity(self) -> ADObject:
        return ADObject.wrap(self.node)

    def summary(self) -> list[SummaryField]:
        return [*self.entity.summary(), *self.extra]

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"entity": self.node.as_dict()}
        if self.show_summary:
            out["summary"] = {f.label: f.value for f in self.summary()}
        out["views"] = {v.key: v.as_dict() for v in self.views}
        return out
