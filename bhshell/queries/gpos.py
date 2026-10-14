"""GPO views: where a GPO is linked and which users and computers it applies to.

A link applies to everything below the linked domain or OU, except below an OU that blocks
inheritance, unless the link is enforced. BloodHound's own GPO panel goes one level further:
it also counts the objects placed directly in an OU that blocks inheritance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from bhshell.errors import NotFoundError
from bhshell.models.entities import Graph, Node, SummaryField, opt_bool
from bhshell.models.results import Column, ContainedRow, GPOTargetRow, ViewResult
from bhshell.queries import cypher as Q
from bhshell.queries.containers import (
    GPO_CAVEAT,
    GPO_TARGET_KINDS,
    Counts,
    dn_location,
    is_container,
    location_below,
    rest_unavailable,
    short_name,
)
from bhshell.queries.edges import CONTAINS, GP_LINK, GPO_EDIT_EDGES

if TYPE_CHECKING:
    from bhshell.queries.service import EntityService

NOT_LINKED = ("BloodHound has no links for this GPO: it is not linked anywhere, or the domain was collected "
              "without SharpHound's Container method.")

FLAGS = [Column("T0", "tier_zero", "t0"), Column("Owned", "owned", "owned")]
LINK_COLS = [
    Column("Linked to", "location"), Column("Type", "kind", "kind"), Column("Enforced", "enforced", "bool"),
    Column("Users (enabled)", "users"), Column("Computers (enabled)", "computers"),
    Column("T0 affected", "tier_zero_affected"), Column("Owned affected", "owned_affected"),
    Column("Blocked at", "blocked_at"), *FLAGS,
]
AFFECTED_COLS = [
    Column("Object", "name"), Column("Type", "kind", "kind"), Column("Enabled", "enabled", "bool"),
    Column("Location", "location"), *FLAGS,
]

# Computers first: a GPO runs code on them as SYSTEM.
_KIND_ORDER = {"Computer": 0, "User": 1}


@dataclass
class Link:
    """A GPO link and the containers it applies to."""

    target: Node
    enforced: bool | None
    # The linked domain or OU and the containers below it the link reaches, by objectid.
    reached: set[str] = field(default_factory=set)
    # The OUs that stop the link: the highest ones below the target that block inheritance.
    blocked_at: list[Node] = field(default_factory=list)
    # The containers below the target, as queried.
    tree: Graph = field(default_factory=Graph)


def reach(target: Node, tree: Graph, enforced: bool) -> tuple[set[str], list[Node]]:
    """The containers a link on `target` applies to, and the OUs below it that block the link.

    `tree` holds the `Contains` edges between `target` and the containers below it. The target's
    own `blocksinheritance` does not matter: it only stops links above it.
    """
    children: dict[str, list[Node]] = {}
    for e in tree.edges:
        if e.kind == CONTAINS and e.source in tree.nodes and e.target in tree.nodes:
            children.setdefault(tree.nodes[e.source].objectid, []).append(tree.nodes[e.target])
    reached = {target.objectid}
    blocked: list[Node] = []
    queue = [target.objectid]
    while queue:
        for child in children.get(queue.pop(), []):
            if child.objectid in reached or not is_container(child):
                continue
            if not enforced and child.properties.get("blocksinheritance") is True:
                blocked.append(child)
                continue
            reached.add(child.objectid)
            queue.append(child.objectid)
    blocked.sort(key=lambda n: short_name(n).upper())
    return reached, blocked


def _locations(link: Link) -> dict[str, tuple[int, str]]:
    """Depth and location (`SERVERS/WEB`) of each container the link reaches; the linked one is at depth 0."""
    out = {link.target.objectid: (0, short_name(link.target))}
    start = link.tree.find(link.target.objectid)
    if start:
        below = link.tree.bfs(start.id, CONTAINS)
        for nid, (depth, _) in below.items():
            node = link.tree.nodes[nid]
            if node.objectid in link.reached:
                path = location_below(link.tree, below, start.id, nid)
                out[node.objectid] = (depth, f"{short_name(link.target)}/{path}")
    return out


def _affected(total: Counts) -> list[SummaryField]:
    return [
        SummaryField("Computers affected (enabled)", f"{total.computers} ({total.enabled_computers})"),
        SummaryField("Users affected (enabled)", f"{total.users} ({total.enabled_users})"),
        SummaryField("Tier Zero users / computers affected", total.tier_zero_targets,
                     risk="medium" if total.tier_zero_targets else "none"),
        SummaryField("Owned users / computers affected", total.owned_targets,
                     risk="info" if total.owned_targets else "none"),
    ]


class GPOService:
    """The summary of a GPO, and the `links` and `affected` views."""

    def __init__(self, entities: EntityService) -> None:
        self.entities = entities

    def linked(self, gpo: Node) -> list[Link]:
        """Where the GPO is linked, domains first."""
        g = self.entities.run_cypher(Q.gp_links_from(gpo.objectid))
        links: list[Link] = []
        for e in g.edges:
            if e.kind != GP_LINK or e.target not in g.nodes:
                continue
            target = g.nodes[e.target]
            enforced = opt_bool(e.properties, "enforced")
            tree = self.entities.containers.tree_graph(Q.sub_containers(target.objectid, self.entities.max_results))
            reached, blocked = reach(target, tree, bool(enforced))
            links.append(Link(target, enforced, reached, blocked, tree))
        links.sort(key=lambda link: (link.target.kind != "Domain", link.target.name))
        return links

    def _counts(self, links: list[Link]) -> dict[str, Counts] | None:
        """Direct children of every container below the links, by parent objectid (`None` without aggregates)."""
        out: dict[str, Counts] = {}
        for link in links:
            counts = self.entities.containers.counts(link.target)
            if counts is None:
                return None
            out.update(counts)
        return out

    # Summary

    def summary(self, gpo: Node) -> list[SummaryField]:
        """Links, the users and computers it applies to, and who outside Tier Zero can edit it."""

        def via_cypher() -> list[SummaryField]:
            links = self.linked(gpo)
            if not links:
                out = [SummaryField("Linked to", "nowhere")]
            else:
                out = [SummaryField("Linked to", [
                    f"{link.target.name}{' (enforced)' if link.enforced else ''}" for link in links], "list")]
                blocked = sorted({dn_location(n) for link in links for n in link.blocked_at})
                out.append(SummaryField("Stopped by blocked inheritance at", blocked, "list"))
                counts = self._counts(links)
                if counts is not None:
                    reached = set().union(*(link.reached for link in links))
                    out += _affected(sum((counts.get(oid, Counts()) for oid in reached), Counts()))
            editors, _ = self.entities.outside_t0({gpo.objectid}, GPO_EDIT_EDGES)
            names = editors.get(gpo.objectid)
            if names:
                out.append(SummaryField("Editable by (outside Tier Zero)", names, "list", "high"))
            else:
                out.append(SummaryField("Editable by (outside Tier Zero)", "nobody"))
            return out

        def via_rest(_: str) -> list[SummaryField]:
            try:
                counts = self.entities.client.entity_counts("GPO", gpo.objectid)
            except (NotFoundError, ValueError):
                return []
            labels = {"computers": "Computers affected", "users": "Users affected", "ous": "OUs affected",
                      "controllers": "Controllers"}
            return [SummaryField(label, counts[key]) for key, label in labels.items() if key in counts]

        return self.entities._with_fallback(via_cypher, via_rest)

    # Views

    def links(self, gpo: Node) -> list[ViewResult]:
        title = "Links (counts cover the users and computers each link applies to)"

        def via_cypher() -> list[ViewResult]:
            links = self.linked(gpo)
            view = ViewResult("links", title, LINK_COLS)
            missing_counts = False
            for link in links:
                counts = self.entities.containers.counts(link.target)
                total = None
                if counts is None:
                    missing_counts = True
                else:
                    total = sum((counts.get(oid, Counts()) for oid in link.reached), Counts())
                target = link.target
                view.rows.append(GPOTargetRow(
                    linked_to=target.name, kind=target.kind, location=dn_location(target), enforced=link.enforced,
                    users=total and total.users, enabled_users=total and total.enabled_users,
                    computers=total and total.computers, enabled_computers=total and total.enabled_computers,
                    tier_zero_affected=total and total.tier_zero_targets,
                    owned_affected=total and total.owned_targets,
                    blocked_at=[dn_location(n) for n in link.blocked_at],
                    tier_zero=target.tier_zero, owned=target.owned,
                    distinguishedname=str(target.properties.get("distinguishedname") or ""),
                    objectid=target.objectid,
                ))
            if not links:
                view.notes.append(NOT_LINKED)
            if missing_counts:
                view.notes.append("Object counts unavailable: the server does not run aggregate queries.")
            return [self.entities._capped(view, *(link.tree for link in links))]

        return self.entities._with_fallback(via_cypher, lambda why: [rest_unavailable("links", title, LINK_COLS, why)])

    def affected(self, gpo: Node) -> list[ViewResult]:
        title = "Users and computers it applies to"

        def via_cypher() -> list[ViewResult]:
            links = self.linked(gpo)
            view = ViewResult("affected", title, AFFECTED_COLS)
            if not links:
                view.notes.append(NOT_LINKED)
                return [view]
            # Each reached container under its closest link.
            where: dict[str, tuple[int, str]] = {}
            for link in links:
                for oid, (depth, location) in _locations(link).items():
                    if oid not in where or depth < where[oid][0]:
                        where[oid] = (depth, location)
            g = self.entities.containers.tree_graph(
                Q.children_of(where, GPO_TARGET_KINDS, self.entities.max_results))
            rows: dict[str, ContainedRow] = {}
            for e in g.edges:
                if e.kind != CONTAINS or e.source not in g.nodes or e.target not in g.nodes:
                    continue
                parent, obj = g.nodes[e.source], g.nodes[e.target]
                if obj.kind not in GPO_TARGET_KINDS or parent.objectid not in where:
                    continue
                depth, location = where[parent.objectid]
                rows[obj.objectid] = ContainedRow(
                    name=obj.name, kind=obj.kind, enabled=opt_bool(obj.properties, "enabled"), location=location,
                    depth=depth + 1, tier_zero=obj.tier_zero, owned=obj.owned,
                    distinguishedname=str(obj.properties.get("distinguishedname") or ""), objectid=obj.objectid,
                )
            view.rows = sorted(rows.values(), key=lambda r: (not r.tier_zero, not r.owned,
                                                              _KIND_ORDER.get(r.kind, 2), r.enabled is False, r.name))
            if view.rows:
                view.notes.append(GPO_CAVEAT)
            return [self.entities._capped(view, g)]

        def via_rest(why: str) -> list[ViewResult]:
            view = ViewResult("affected", title, AFFECTED_COLS, backend="rest")
            if why:
                view.notes.append(f"Cypher query failed ({why}); used REST fallback.")
            for relation in ("computers", "users"):
                try:
                    items = self.entities.client.entity_related("GPO", gpo.objectid, relation,
                                                                limit=self.entities.max_results)
                except NotFoundError:
                    view.notes.append(f"Endpoint '{relation}' is not available on this server.")
                    continue
                for item in items:
                    obj = Node.from_rest("", item)
                    view.rows.append(ContainedRow(name=obj.name, kind=obj.kind, tier_zero=obj.tier_zero,
                                                  owned=obj.owned, objectid=obj.objectid))
            view.notes.append("REST fallback: this is BloodHound's own list, which also counts the objects placed "
                              "directly in an OU that blocks inheritance. Locations need Cypher.")
            return [self.entities._capped(view)]

        return self.entities._with_fallback(via_cypher, via_rest)
