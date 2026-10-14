"""OU and container views: the directory tree, the objects in it and the GPOs that apply.

BloodHound models the tree with `Contains` edges (domain -> OU / container -> ... -> object, one
parent per object) and GPO links with `GPLink` edges (GPO -> domain / OU, with `enforced` on the
edge). Both come from SharpHound's Container collection: a domain collected without it has neither.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any

from bhshell.errors import ApiError, NotFoundError
from bhshell.models.entities import OWNED_LABEL, TIER_ZERO_LABEL, Graph, Node, SummaryField, opt_bool
from bhshell.models.results import Column, ContainedRow, ContainerRow, GPOLinkRow, ViewResult
from bhshell.queries import cypher as Q
from bhshell.queries.edges import CONTAINS, GP_LINK, GPO_EDIT_EDGES

if TYPE_CHECKING:
    from bhshell.queries.service import EntityService

# The nodes of the directory tree; the `ou` command accepts all three.
CONTAINER_KINDS = ("OU", "Container", "Domain")
# Kinds GPOs are applied to.
GPO_TARGET_KINDS = ("User", "Computer")

NO_TREE_DATA = ("BloodHound has no OU data for this object (no Contains edges); the domain was probably "
                "collected without SharpHound's Container method.")
NO_GPO_LINKS = ("BloodHound has no GPO links for this domain; they are collected by SharpHound's Container "
                "method.")
NEEDS_CYPHER = "This view needs Cypher; the REST API has no equivalent."
GPO_CAVEAT = ("BloodHound does not collect security filtering, WMI filters or the link order within one OU, "
              "so a GPO listed as applying may still be filtered out.")

FLAGS = [Column("T0", "tier_zero", "t0"), Column("Owned", "owned", "owned")]
TREE_COLS = [
    Column("OU / container", "label"), Column("Users (enabled)", "users"), Column("Computers (enabled)", "computers"),
    Column("Groups", "groups"), Column("T0 below", "tier_zero_below"), Column("Owned below", "owned_below"),
    Column("GPO links", "gpo_links"), Column("Blocks inheritance", "blocks_inheritance", "bool"), *FLAGS,
]
CONTENT_COLS = [
    Column("Object", "name"), Column("Type", "kind", "kind"), Column("Enabled", "enabled", "bool"),
    Column("Location", "location", "via"), Column("Depth", "depth", "depth"), *FLAGS,
]
GPO_COLS = [
    Column("GPO", "gpo"), Column("Linked to", "linked_to"), Column("Enforced", "enforced", "bool"),
    Column("Applies", "applies"), Column("Editable by (outside Tier Zero)", "editable_by"), *FLAGS,
]

_KIND_ORDER = {"User": 0, "Computer": 1, "Group": 2}
# REST endpoints listing the objects below an OU or a domain (all levels).
_REST_CONTENTS = ("users", "computers", "groups")


def short_name(node: Node) -> str:
    """`SERVERS` for `OU=SERVERS,...` / `SERVERS@CORP.LOCAL`; a domain keeps its full name."""
    if node.kind == "Domain":
        return node.name
    dn = str(node.properties.get("distinguishedname") or "")
    if "=" in dn:
        rdn = dn.split("=", 1)[1]
        end = next((i for i, ch in enumerate(rdn) if ch == "," and (i == 0 or rdn[i - 1] != "\\")), len(rdn))
        return rdn[:end].replace("\\,", ",")
    return node.name.rsplit("@", 1)[0]


def is_container(node: Node) -> bool:
    return node.kind in ("OU", "Container")


@dataclass
class Counts:
    """Objects below a container, by kind. OUs and containers are counted apart from the objects."""

    users: int = 0
    enabled_users: int = 0
    computers: int = 0
    enabled_computers: int = 0
    groups: int = 0
    other: int = 0
    containers: int = 0
    tier_zero: int = 0
    owned: int = 0

    def add(self, kinds: list[str], enabled: Any, total: int) -> None:
        if "OU" in kinds or "Container" in kinds:
            self.containers += total
            return
        if "User" in kinds:
            self.users += total
            self.enabled_users += total if enabled is True else 0
        elif "Computer" in kinds:
            self.computers += total
            self.enabled_computers += total if enabled is True else 0
        elif "Group" in kinds:
            self.groups += total
        else:
            self.other += total
        self.tier_zero += total if TIER_ZERO_LABEL in kinds else 0
        self.owned += total if OWNED_LABEL in kinds else 0

    def __add__(self, other: Counts) -> Counts:
        return Counts(**{f.name: getattr(self, f.name) + getattr(other, f.name) for f in fields(self)})

    @property
    def objects(self) -> int:
        return self.users + self.computers + self.groups + self.other

    def summary(self) -> list[SummaryField]:
        return [
            SummaryField("Users below (enabled)", f"{self.users} ({self.enabled_users})"),
            SummaryField("Computers below (enabled)", f"{self.computers} ({self.enabled_computers})"),
            SummaryField("Groups below", self.groups),
            SummaryField("OUs / containers below", self.containers),
            SummaryField("Tier Zero objects below", self.tier_zero, risk="medium" if self.tier_zero else "none"),
            SummaryField("Owned objects below", self.owned, risk="info" if self.owned else "none"),
        ]


def chain_to(graph: Graph, objectid: str) -> list[Node]:
    """The containers above the object in a `Contains` graph, domain first."""
    parent = {e.target: e.source for e in graph.edges if e.kind == CONTAINS}
    start = graph.find(objectid)
    chain: list[Node] = []
    current = start.id if start else None
    while current in parent and parent[current] not in {n.id for n in chain}:
        current = parent[current]
        chain.append(graph.nodes[current])
    return chain[::-1]


def applied_gpos(levels: list[Node], graph: Graph) -> list[GPOLinkRow]:
    """The GPO links on `levels` (domain first, down to the innermost container), by precedence.

    An OU that blocks inheritance stops the links above it, except enforced ones. Enforced links
    come first (the highest one wins), then the others from the closest container up, then those
    that do not apply. A GPO linked more than once is applied once: its later links are duplicates.
    """
    index = {n.objectid: i for i, n in enumerate(levels)}
    found: list[tuple[int, GPOLinkRow]] = []
    for e in graph.edges:
        if e.kind != GP_LINK or e.source not in graph.nodes or e.target not in graph.nodes:
            continue
        gpo, target = graph.nodes[e.source], graph.nodes[e.target]
        level = index.get(target.objectid)
        if level is None:
            continue
        enforced = opt_bool(e.properties, "enforced")
        blocker = next((n for n in levels[level + 1:] if n.properties.get("blocksinheritance") is True), None)
        applies = bool(enforced) or blocker is None
        found.append((level, GPOLinkRow(
            gpo=gpo.name, linked_to=target.name, linked_kind=target.kind, enforced=enforced, applies=applies,
            reason="" if applies or blocker is None else f"inheritance blocked at {short_name(blocker)}",
            tier_zero=gpo.tier_zero, owned=gpo.owned, objectid=gpo.objectid,
        )))

    def precedence(item: tuple[int, GPOLinkRow]) -> tuple[int, int, str]:
        level, row = item
        if not row.applies:
            return 2, level, row.gpo
        return (0, level, row.gpo) if row.enforced else (1, -level, row.gpo)

    rows = [row for _, row in sorted(found, key=precedence)]
    first: dict[str, GPOLinkRow] = {}
    for row in rows:
        if row.applies and first.setdefault(row.objectid, row) is not row:
            row.reason = f"duplicate: already applied through {first[row.objectid].linked_to}"
    return rows


class ContainerService:
    """The `tree`, `contents` and `gpos` views, and the summary of OUs, containers and domains."""

    def __init__(self, entities: EntityService) -> None:
        self.entities = entities

    def chain(self, node: Node) -> list[Node]:
        """The containers holding the object, domain first (empty without OU data)."""
        return chain_to(self.entities.run_cypher(Q.containers_above(node.objectid)), node.objectid)

    def counts(self, node: Node) -> dict[str, Counts] | None:
        """Direct children of the node and of each container below it, by parent objectid.

        `None` when the server cannot run aggregate queries.
        """
        out: dict[str, Counts] = {}
        for nested in (False, True):
            rows = self.entities.scalar_rows(Q.contained_counts(node.objectid, nested=nested))
            if rows is None:
                return None
            for row in rows:
                kinds = row.get("kinds") or []
                out.setdefault(str(row.get("parent")), Counts()).add(
                    list(kinds) if isinstance(kinds, list) else [str(kinds)], row.get("enabled"),
                    int(row.get("total") or 0))
        return out

    def _links_to(self, node: Node) -> Graph:
        return self.entities.run_cypher(Q.gp_links_to(node.objectid))

    # Summary

    def summary(self, node: Node) -> list[SummaryField]:
        """Location, contents and linked GPOs of an OU, container or domain."""

        def via_cypher() -> list[SummaryField]:
            out: list[SummaryField] = []
            if node.kind != "Domain":
                chain = self.chain(node)
                out.append(SummaryField("Location", " > ".join(short_name(n) for n in chain)))
            counts = self.counts(node)
            if counts is not None:
                out += sum(counts.values(), Counts()).summary()
            if node.kind != "Container":
                links = self._links_to(node)
                out.append(SummaryField("Linked GPOs", sorted(
                    f"{links.nodes[e.source].name}{' (enforced)' if e.properties.get('enforced') else ''}"
                    for e in links.edges if e.kind == GP_LINK and e.source in links.nodes), "list"))
            return out

        def via_rest(_: str) -> list[SummaryField]:
            try:
                counts = self.entities.client.entity_counts(node.kind, node.objectid)
            except (NotFoundError, ValueError):
                return []
            labels = {"users": "Users below", "computers": "Computers below", "groups": "Groups below",
                      "ous": "OUs below",
                      "gpos": "GPOs in the domain" if node.kind == "Domain" else "GPOs linked here or above"}
            return [SummaryField(label, counts[key]) for key, label in labels.items() if key in counts]

        return self.entities._with_fallback(via_cypher, via_rest)

    # Views

    def tree(self, node: Node) -> list[ViewResult]:
        title = "OU tree (counts cover everything below each entry)"

        def via_cypher() -> list[ViewResult]:
            g = self.entities.run_cypher(Q.sub_containers(node.objectid, self.entities.max_results))
            counts = self.counts(node)
            link_rows = self.entities.scalar_rows(Q.gp_link_counts(node.objectid)) or []
            links = {str(r.get("parent")): int(r.get("total") or 0) for r in link_rows}
            links[node.objectid] = sum(1 for e in self._links_to(node).edges if e.kind == GP_LINK)
            view = ViewResult("tree", title, TREE_COLS)
            view.rows, hidden = _tree_rows(node, g, counts, links)
            if counts is None:
                view.notes.append("Object counts unavailable: the server does not run aggregate queries.")
            if hidden:
                view.notes.append(f"{hidden} empty container(s) hidden.")
            if node.kind == "Domain" and not g.edges and not counts:
                view.notes.append(NO_TREE_DATA)
            return [self.entities._capped(view, g)]

        return self.entities._with_fallback(via_cypher, lambda why: [_rest_unavailable("tree", title, TREE_COLS, why)])

    def contents(self, node: Node) -> list[ViewResult]:
        title = "Objects below (all levels)"

        def via_cypher() -> list[ViewResult]:
            g = self.entities.run_cypher(Q.contained_objects(node.objectid, self.entities.max_results))
            rows: list[ContainedRow] = []
            start = g.find(node.objectid)
            if start:
                reached = g.bfs(start.id, CONTAINS)
                for nid, (depth, parent) in reached.items():
                    obj = g.nodes[nid]
                    if is_container(obj):
                        continue
                    rows.append(ContainedRow(
                        name=obj.name, kind=obj.kind, enabled=opt_bool(obj.properties, "enabled"),
                        location=_location(g, reached, start.id, parent), depth=depth,
                        tier_zero=obj.tier_zero, owned=obj.owned,
                        distinguishedname=str(obj.properties.get("distinguishedname") or ""), objectid=obj.objectid,
                    ))
            rows.sort(key=lambda r: (not r.tier_zero, not r.owned, _KIND_ORDER.get(r.kind, 3),
                                     r.enabled is False, r.name))
            return [self.entities._capped(ViewResult("contents", title, CONTENT_COLS, rows), g)]

        def via_rest(why: str) -> list[ViewResult]:
            if node.kind not in ("OU", "Domain"):
                return [_rest_unavailable("contents", title, CONTENT_COLS, why)]
            view = ViewResult("contents", title, CONTENT_COLS, backend="rest")
            if why:
                view.notes.append(f"Cypher query failed ({why}); used REST fallback.")
            for relation in _REST_CONTENTS:
                try:
                    items = self.entities.client.entity_related(node.kind, node.objectid, relation,
                                                                limit=self.entities.max_results)
                except NotFoundError:
                    view.notes.append(f"Endpoint '{relation}' is not available on this server.")
                    continue
                for item in items:
                    obj = Node.from_rest("", item)
                    view.rows.append(ContainedRow(name=obj.name, kind=obj.kind, tier_zero=obj.tier_zero,
                                                  owned=obj.owned, objectid=obj.objectid))
            view.notes.append("REST fallback: locations and enabled state need Cypher.")
            return [self.entities._capped(view)]

        return self.entities._with_fallback(via_cypher, via_rest)

    def gpos(self, node: Node) -> list[ViewResult]:
        scope = "to objects in it " if node.kind in CONTAINER_KINDS else ""
        title = f"GPOs applied {scope}(in precedence order: the first wins)"

        def via_cypher() -> list[ViewResult]:
            levels = self.chain(node)
            graphs = [self.entities.run_cypher(Q.gp_links_above(node.objectid))]
            if node.kind in CONTAINER_KINDS:
                levels.append(node)
                graphs.append(self._links_to(node))
            view = ViewResult("gpos", title, GPO_COLS)
            if not levels:
                view.notes.append(NO_TREE_DATA)
                return [view]
            view.rows = applied_gpos(levels, Graph.union(graphs))
            if view.rows:
                self._add_editors(view)
                view.notes.append(GPO_CAVEAT)
            elif levels[0].kind == "Domain":  # every domain has the Default Domain Policy linked
                view.notes.append(NO_GPO_LINKS)
            return [view]

        def via_rest(why: str) -> list[ViewResult]:
            if node.kind != "OU":
                return [_rest_unavailable("gpos", title, GPO_COLS, why)]
            view = ViewResult("gpos", "GPOs linked to this OU or above it", GPO_COLS, backend="rest")
            if why:
                view.notes.append(f"Cypher query failed ({why}); used REST fallback.")
            try:
                items = self.entities.client.entity_related(node.kind, node.objectid, "gpos",
                                                            limit=self.entities.max_results)
            except NotFoundError:
                items = []
                view.notes.append("Endpoint 'gpos' is not available on this server.")
            for item in items:
                gpo = Node.from_rest("", item)
                view.rows.append(GPOLinkRow(gpo=gpo.name, linked_to="", linked_kind="", applies=None,
                                            tier_zero=gpo.tier_zero, owned=gpo.owned, objectid=gpo.objectid))
            view.notes.append("REST fallback: where each GPO is linked, enforcement and blocked inheritance "
                              "need Cypher.")
            return [self.entities._capped(view)]

        return self.entities._with_fallback(via_cypher, via_rest)

    def _add_editors(self, view: ViewResult) -> None:
        """Fill `editable_by` with the principals outside Tier Zero that can edit each GPO."""
        ids = {r.objectid for r in view.rows}
        limit = self.entities.max_results
        try:
            g = self.entities.run_cypher(Q.controllers_outside_t0(ids, GPO_EDIT_EDGES, limit))
        except ApiError:  # an edge kind unknown to this server: filter locally instead
            g = self.entities.run_cypher(Q.controllers_outside_t0(ids, None, limit))
        editors: dict[str, dict[str, bool]] = {}
        for e in g.edges:
            if e.kind in GPO_EDIT_EDGES and e.source in g.nodes and e.target in g.nodes:
                src = g.nodes[e.source]
                editors.setdefault(g.nodes[e.target].objectid, {})[src.name] = src.owned
        for row in view.rows:
            found = editors.get(row.objectid, {})
            row.editable_by = [f"{name} (owned)" if owned else name
                               for name, owned in sorted(found.items(), key=lambda kv: (not kv[1], kv[0]))]
        self.entities._capped(view, g)


def _tree_rows(root: Node, graph: Graph, counts: dict[str, Counts] | None,
               links: dict[str, int]) -> tuple[list[ContainerRow], int]:
    """Rows of the tree below `root` (itself first), and how many empty containers were left out.

    Counts cover each entry's whole subtree. Containers (`CN=`) with no objects below are left out:
    most are system containers. OUs are always shown.
    """
    children: dict[str, list[Node]] = {}
    for e in graph.edges:
        if e.kind == CONTAINS and e.source in graph.nodes and e.target in graph.nodes:
            child = graph.nodes[e.target]
            if is_container(child):
                children.setdefault(graph.nodes[e.source].objectid, []).append(child)
    for kids in children.values():
        kids.sort(key=lambda n: (n.kind != "OU", short_name(n).upper()))

    totals: dict[str, Counts] = {}

    def total(oid: str) -> Counts:
        if oid not in totals:
            totals[oid] = Counts()  # placeholder: guards against a malformed (cyclic) tree
            own = (counts or {}).get(oid, Counts())
            totals[oid] = sum((total(c.objectid) for c in children.get(oid, [])), own)
        return totals[oid]

    rows: list[ContainerRow] = []
    visited: set[str] = set()
    hidden = 0

    def walk(n: Node, depth: int, prefix: str, last: bool) -> None:
        nonlocal hidden
        visited.add(n.objectid)
        t = total(n.objectid) if counts is not None else None
        branch = "" if depth == 0 else "└─ " if last else "├─ "
        rows.append(ContainerRow(
            name=n.name, kind=n.kind, depth=depth, label=f"{prefix}{branch}{short_name(n)}",
            users=t and t.users, enabled_users=t and t.enabled_users,
            computers=t and t.computers, enabled_computers=t and t.enabled_computers,
            groups=t and t.groups, tier_zero_below=t and t.tier_zero, owned_below=t and t.owned,
            gpo_links=links.get(n.objectid, 0),
            blocks_inheritance=opt_bool(n.properties, "blocksinheritance") if n.kind == "OU" else None,
            tier_zero=n.tier_zero, owned=n.owned,
            distinguishedname=str(n.properties.get("distinguishedname") or ""), objectid=n.objectid,
        ))
        kids = [c for c in children.get(n.objectid, []) if c.objectid not in visited]
        if counts is not None:
            empty = [c for c in kids if c.kind == "Container" and total(c.objectid).objects == 0]
            hidden += len(empty)
            kids = [c for c in kids if c not in empty]
        inner = prefix + ("" if depth == 0 else "   " if last else "│  ")
        for i, child in enumerate(kids):
            walk(child, depth + 1, inner, i == len(kids) - 1)

    walk(graph.find(root.objectid) or root, 0, "", True)
    return rows, hidden


def _location(graph: Graph, reached: dict[str, tuple[int, str]], start: str, parent: str) -> str:
    """`WEB/DMZ`: the containers from just below `start` down to `parent`; "direct" when `parent` is `start`."""
    names: list[str] = []
    current = parent
    while current != start and current in reached:
        names.append(short_name(graph.nodes[current]))
        current = reached[current][1]
    return "/".join(reversed(names)) or "direct"


def _rest_unavailable(key: str, title: str, columns: list[Column], why: str) -> ViewResult:
    view = ViewResult(key, title, columns, backend="rest")
    if why:
        view.notes.append(f"Cypher query failed ({why}).")
    view.notes.append(NEEDS_CYPHER)
    return view
