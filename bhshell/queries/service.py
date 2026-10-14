"""Entity resolution and relationship views.

Everything goes through Cypher first and falls back to the REST entity endpoints when
Cypher is disabled or a query is rejected.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, TypeVar

from bhshell.client.client import BHClient
from bhshell.errors import (
    AmbiguousMatchError,
    ApiError,
    BHError,
    CypherDisabledError,
    NotFoundError,
)
from bhshell.models.entities import BROAD_SIDS, Graph, Node, SummaryField, literal_rows
from bhshell.models.results import Column, EntityReport, RelationshipRow, ViewResult
from bhshell.queries import cypher as Q
from bhshell.queries.adcs import ADCSService
from bhshell.queries.containers import CONTAINER_KINDS, GPO_TARGET_KINDS, ContainerService
from bhshell.queries.edges import (
    CONTROL_EDGES,
    EXEC_EDGES,
    HAS_SESSION,
    MEMBER_OF,
    SEVERITIES,
    severity,
    severity_rank,
)
from bhshell.queries.gpos import GPOService

T = TypeVar("T")

RAISE_LIMIT = "raise it with 'config max_results N'"

ENTITY_KINDS = ("User", "Computer", "Group")
ADCS_KINDS = ("EnterpriseCA", "CertTemplate")
# Kinds accepted as attack-path endpoints: AD CS objects too, the targets of ESC4 / ESC5 / ESC7.
PATH_KINDS = (*ENTITY_KINDS, "Domain", "OU", "GPO", "Container", *ADCS_KINDS, "RootCA", "AIACA", "NTAuthStore",
              "IssuancePolicy")
_SID_RE = re.compile(r"(^|-)S-1-\d+(-\d+)+$", re.IGNORECASE)
_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_DN_RE = re.compile(r"^(CN|OU|DC)=.+", re.IGNORECASE)
DN_HINT = "Use the distinguished name ('OU=Servers,OU=Tier1,DC=corp,DC=local') or the object ID (GUID)."
# For objects identified by a GUID rather than a SID (GPOs, certificate templates, CAs, ...).
GUID_HINT = "Qualify the name with its domain ('NAME@corp.local' or '--domain corp.local') or use the object ID (GUID)."
SID_KINDS = ("User", "Computer", "Group", "Domain")

# View keys in display order, and which entity kinds support them.
VIEWS: dict[str, tuple[str, ...]] = {
    "groups": ENTITY_KINDS,
    "members": ("Group",),
    "tree": CONTAINER_KINDS,
    "contents": CONTAINER_KINDS,
    "links": ("GPO",),
    "affected": ("GPO",),
    "templates": ("EnterpriseCA",),
    "outbound": ENTITY_KINDS,
    "inbound": (*ENTITY_KINDS, *CONTAINER_KINDS, "GPO", *ADCS_KINDS),
    "sessions": ENTITY_KINDS,
    "privs": ENTITY_KINDS,
    "gpos": (*GPO_TARGET_KINDS, *CONTAINER_KINDS),
}
# Views served by `ContainerService`, `GPOService` and `ADCSService`.
CONTAINER_VIEWS = frozenset({"tree", "contents", "gpos"})
GPO_VIEWS = frozenset({"links", "affected"})
ADCS_VIEWS = frozenset({"templates"})

FLAGS = [Column("T0", "tier_zero", "t0"), Column("Owned", "owned", "owned")]
DEPTH, VIA = Column("Depth", "depth", "depth"), Column("Via", "via", "via")
GROUP_COLS = [Column("Group", "target"), DEPTH, VIA, *FLAGS]
MEMBER_COLS = [Column("Member", "principal"), Column("Type", "principal_kind", "kind"), DEPTH, VIA, *FLAGS]
OUTBOUND_COLS = [Column("Right", "edge", "edge"), Column("Target", "target"), Column("Type", "target_kind", "kind"),
                 VIA, *FLAGS]
INBOUND_COLS = [Column("Principal", "principal"), Column("Type", "principal_kind", "kind"),
                Column("Right", "edge", "edge"), VIA, *FLAGS]
SESSION_COLS = {
    "User": [Column("Computer", "target"), *FLAGS],
    "Computer": [Column("User", "principal"), *FLAGS],
    "Group": [Column("User", "principal"), Column("Computer", "target"), *FLAGS],
}

# (relation path, edge label, direction) - "out": items are targets, "in": items are principals.
RestRoute = tuple[str, str, str]
_EXEC_HELD: list[RestRoute] = [
    ("admin-rights", "AdminTo", "out"), ("rdp-rights", "CanRDP", "out"),
    ("dcom-rights", "ExecuteDCOM", "out"), ("ps-remote-rights", "CanPSRemote", "out"),
]
REST_ROUTES: dict[tuple[str, str], list[RestRoute]] = {
    ("User", "groups"): [("memberships", MEMBER_OF, "out")],
    ("Computer", "groups"): [("group-membership", MEMBER_OF, "out")],
    ("Group", "groups"): [("memberships", MEMBER_OF, "out")],
    ("Group", "members"): [("members", MEMBER_OF, "in")],
    ("User", "outbound"): [("controllables", "Controls", "out"),
                           ("constrained-delegation-rights", "AllowedToDelegate", "out")],
    ("Computer", "outbound"): [("controllables", "Controls", "out"),
                               ("constrained-delegation-rights", "AllowedToDelegate", "out")],
    ("Group", "outbound"): [("controllables", "Controls", "out")],
    ("User", "inbound"): [("controllers", "Controls", "in")],
    ("Computer", "inbound"): [("controllers", "Controls", "in"), ("constrained-users", "AllowedToDelegate", "in")],
    ("Group", "inbound"): [("controllers", "Controls", "in")],
    ("OU", "inbound"): [("controllers", "Controls", "in")],
    ("Container", "inbound"): [("controllers", "Controls", "in")],
    ("Domain", "inbound"): [("controllers", "Controls", "in")],
    ("GPO", "inbound"): [("controllers", "Controls", "in")],
    ("EnterpriseCA", "inbound"): [("controllers", "Controls", "in")],
    ("CertTemplate", "inbound"): [("controllers", "Controls", "in")],
    ("User", "sessions"): [("sessions", HAS_SESSION, "out")],
    ("Computer", "sessions"): [("sessions", HAS_SESSION, "in")],
    ("Group", "sessions"): [("sessions", HAS_SESSION, "out")],
    ("User", "privs_held"): [*_EXEC_HELD, ("sql-admin-rights", "SQLAdmin", "out")],
    ("Computer", "privs_held"): _EXEC_HELD,
    ("Group", "privs_held"): _EXEC_HELD,
    ("Computer", "privs_inbound"): [
        ("admin-users", "AdminTo", "in"), ("rdp-users", "CanRDP", "in"), ("dcom-users", "ExecuteDCOM", "in"),
        ("ps-remote-users", "CanPSRemote", "in"), ("sql-admins", "SQLAdmin", "in"),
    ],
}


@dataclass(frozen=True)
class Identifier:
    raw: str
    sam: str = ""
    domain: str = ""
    fqdn: str = ""
    objectid: str = ""
    # Distinguished name, upper-cased.
    dn: str = ""


def parse_identifier(raw: str, *, domain: str | None = None, kind: str | None = None) -> Identifier:
    """Parse `jdoe`, `jdoe@corp.local`, `CORP\\jdoe`, `WS01.corp.local`, a SID/GUID or a distinguished name."""
    text = raw.strip()
    if not text:
        raise ValueError("Empty object name")
    if _SID_RE.search(text) or _GUID_RE.match(text):
        return Identifier(raw=text, objectid=text.upper())
    if _DN_RE.match(text):
        return Identifier(raw=text, dn=re.sub(r"(?<!\\),\s+", ",", text).upper())
    sam, dom, fqdn = text, "", ""
    if "\\" in text:
        dom, sam = text.split("\\", 1)
    elif "@" in text:
        sam, dom = text.rsplit("@", 1)
        fqdn = f"{sam}@{dom}"
    elif "." in text and kind == "Computer":
        sam, dom = text.split(".", 1)
        fqdn = text
    elif "." in text and kind is None:
        # Could be a dotted username ("j.doe") or a computer FQDN: try both.
        fqdn = text
    if domain:
        dom = domain
    return Identifier(raw=text, sam=sam, domain=dom.upper(), fqdn=fqdn.upper())


def _node_domain(node: Node) -> str:
    if node.domain:
        return node.domain.upper()
    name = node.name.upper()
    if "@" in name:
        return name.rsplit("@", 1)[1]
    return name.split(".", 1)[1] if "." in name else ""


def _matches(node: Node, ident: Identifier, kinds: tuple[str, ...]) -> bool:
    if node.kind not in kinds:
        return False
    if ident.objectid:
        return node.objectid.upper() == ident.objectid
    if ident.dn:
        return str(node.properties.get("distinguishedname") or "").upper() == ident.dn
    sam = ident.sam.upper()
    name = node.name.upper()
    node_sam = node.samaccountname.upper()
    if node.kind == "Computer" and "@" in ident.fqdn and kinds != ("Computer",):
        # NAME@DOMAIN names a user or a group: a computer only in its NAME$@DOMAIN form.
        ok = sam.endswith("$") and node_sam == sam
    elif node.kind == "Computer":
        host = sam.rstrip("$")
        ok = name == ident.fqdn or name.split(".", 1)[0] == host or node_sam == f"{host}$"
    elif node.kind not in ENTITY_KINDS:  # Domain, OU, GPO, Container: match the full name
        ok = name in (ident.fqdn, sam) or name.rsplit("@", 1)[0] == sam
    else:
        ok = name.rsplit("@", 1)[0] == sam or node_sam == sam
    if not ok:
        return False
    if ident.domain:
        dom = _node_domain(node)
        return dom == ident.domain or dom.startswith(ident.domain + ".")
    return True


# One CA shows up as up to three nodes of the same name, in this order of preference: the Enterprise CA
# (enrolled on) stands for it.
_CA_KINDS = ("EnterpriseCA", "RootCA", "AIACA")


def _one_ca(nodes: dict[str, Node]) -> dict[str, Node]:
    """The Enterprise CA, when `nodes` are the CA nodes of a single CA; `nodes` otherwise."""
    found = list(nodes.values())
    if len({(n.name, n.domain) for n in found}) > 1 or any(n.kind not in _CA_KINDS for n in found):
        return nodes
    best = min(found, key=lambda n: _CA_KINDS.index(n.kind))
    return {best.objectid: best}


def truncation_note(limit: int, totals: Iterable[int | None], what: str = "paths") -> str:
    """Note for results cut off at `limit`; `totals` are the server-side counts (`None` = unknown)."""
    totals = list(totals)
    if not totals or None in totals:
        return f"Results may be truncated at {limit} {what} ({RAISE_LIMIT})."
    counts = ", ".join(f"{t:,}" for t in totals)
    return f"Results truncated at {limit} {what} (server total: {counts}); {RAISE_LIMIT}."


class EntityService:
    def __init__(self, client: BHClient, *, max_results: int = 5000) -> None:
        self.client = client
        self.max_results = max_results
        # `None` = not probed yet, `True`/`False` once known.
        self.cypher_available: bool | None = None
        self._cache: dict[str, Graph] = {}
        self._scalars: dict[str, list[dict[str, Any]] | None] = {}
        self.containers = ContainerService(self)
        self.gpo = GPOService(self)
        self.adcs = ADCSService(self)

    def reset_cache(self) -> None:
        self._cache.clear()
        self._scalars.clear()

    def reset(self) -> None:
        """Forget everything learned about the backend (after URL/auth change)."""
        self.reset_cache()
        self.cypher_available = None

    def run_cypher(self, query: str) -> Graph:
        """Results are cached until the next shell command."""
        if query in self._cache:
            return self._cache[query]
        if self.cypher_available is False:
            raise CypherDisabledError("Cypher is unavailable on this server")
        try:
            data = self.client.cypher(query)
        except CypherDisabledError:
            self.cypher_available = False
            raise
        self.cypher_available = True
        graph = Graph.from_cypher(data)
        graph.query = query
        self._cache[query] = graph
        return graph

    def count(self, query: str) -> int | None:
        """Run a `RETURN count(...)` query; `None` if scalars are unsupported or Cypher is off."""
        if self.cypher_available is False:
            return None
        try:
            literals = self.client.cypher(query).get("literals") or []
            return int(literals[0]["value"])
        except (ApiError, CypherDisabledError, IndexError, KeyError, TypeError, ValueError):
            return None

    def scalar_rows(self, query: str) -> list[dict[str, Any]] | None:
        """Rows of a query returning scalars (`RETURN a AS x, count(b) AS y`), cached like `run_cypher`.

        `None` if the server cannot run it (Cypher off, or aggregates unsupported).
        """
        if query not in self._scalars:
            rows: list[dict[str, Any]] | None = None
            if self.cypher_available is not False:
                try:
                    literals = self.client.cypher(query).get("literals") or []
                except (ApiError, CypherDisabledError):
                    pass
                else:
                    rows = literal_rows(literals)
            self._scalars[query] = rows
        return self._scalars[query]

    def outside_t0(self, objectids: set[str], edges: frozenset[str], *,
                   rights: bool = False) -> tuple[dict[str, list[str]], Graph]:
        """The principals outside Tier Zero holding any of `edges` over each object, and the graph they came from.

        Owned principals come first, as `NAME (owned)`; with `rights`, the rights are listed too:
        `NAME (ManageCA, owned)`.
        """
        try:
            g = self.run_cypher(Q.controllers_outside_t0(objectids, edges, self.max_results))
        except ApiError:  # an edge kind unknown to this server: filter locally instead
            g = self.run_cypher(Q.controllers_outside_t0(objectids, None, self.max_results))
        found: dict[str, dict[str, tuple[bool, set[str]]]] = {}
        for e in g.edges:
            if e.kind in edges and e.source in g.nodes and e.target in g.nodes:
                src = g.nodes[e.source]
                held = found.setdefault(g.nodes[e.target].objectid, {}).setdefault(src.name, (src.owned, set()))
                held[1].add(e.kind)
        out: dict[str, list[str]] = {}
        for oid, names in found.items():
            out[oid] = []
            for name, (owned, kinds) in sorted(names.items(), key=lambda kv: (not kv[1][0], kv[0])):
                tags = [*(sorted(kinds) if rights else []), *(["owned"] if owned else [])]
                out[oid].append(f"{name} ({', '.join(tags)})" if tags else name)
        return out, g

    def truncation(self, graph: Graph) -> tuple[bool, int | None]:
        """Was `graph`'s LIMITed query cut off? Returns `(truncated, server_total)`.

        Rows cannot be counted from a result graph, but a cheap upper bound can
        (nodes for `RETURN n`, simple paths for `RETURN p`). Only when that
        bound reaches the LIMIT is an exact `count()` query sent. The total is
        `None` when the server cannot count (truncation is then assumed).
        """
        limit = Q.limit_of(graph.query)
        if limit is None:
            return False, None
        upper = graph.count_paths(limit) if graph.edges else len(graph.nodes)
        if upper < limit:
            return False, None
        count_query = Q.to_count(graph.query)
        total = self.count(count_query) if count_query else None
        if total is None:
            return True, None
        return total > limit, total

    def _with_fallback(self, via_cypher: Callable[[], T], via_rest: Callable[[str], T]) -> T:
        """`via_rest` gets the reason the Cypher query failed ('' when Cypher is off)."""
        if self.cypher_available is not False:
            try:
                return via_cypher()
            except CypherDisabledError:
                pass
            except ApiError as exc:
                return via_rest(exc.message)
        return via_rest("")

    def resolve(self, name: str, kind: str | None = None, domain: str | None = None,
                *, kinds: tuple[str, ...] | None = None) -> Node:
        """The one node named `name`. `kinds` limits the accepted kinds when `kind` is not given.

        Raises NotFoundError, or AmbiguousMatchError when the name exists in several domains.
        """
        ident = parse_identifier(name, domain=domain, kind=kind)
        kinds = (kind,) if kind else (kinds or ENTITY_KINDS)
        candidates = self._with_fallback(
            lambda: self._resolve_cypher(ident, kind),
            lambda _: self._resolve_rest(ident, kinds),
        )
        unique: dict[str, Node] = {}
        for node in candidates:
            if _matches(node, ident, kinds):
                unique.setdefault(node.objectid, node)
        if not unique:
            what = (kind or "object").lower()
            scope = f" in domain {ident.domain}" if ident.domain else ""
            raise NotFoundError(f"No {what} named '{name}'{scope}")
        if len(unique) > 1:
            unique = _one_ca(unique)
        if len(unique) > 1:
            found = sorted(unique.values(), key=lambda n: (n.domain, n.name))
            if any(n.kind in ("OU", "Container") for n in found):
                hint = DN_HINT
            else:
                hint = "" if any(n.kind in SID_KINDS for n in found) else GUID_HINT
            raise AmbiguousMatchError(name, found, hint=hint)
        node = next(iter(unique.values()))
        if self.cypher_available is False:
            node = self._hydrate_rest(node)
        return node

    def _resolve_cypher(self, ident: Identifier, kind: str | None) -> list[Node]:
        if ident.objectid:
            query = Q.by_objectid(ident.objectid)
        elif ident.dn:
            query = Q.by_name([Q.dn_condition(ident.dn)], kind, limit=100)
        else:
            query = Q.by_name(Q.name_conditions(ident.sam, ident.fqdn or None, kind), kind, limit=100)
        return list(self.run_cypher(query).nodes.values())

    def _resolve_rest(self, ident: Identifier, kinds: tuple[str, ...]) -> list[Node]:
        # A DN is searched by its first RDN value (`OU=SERVERS,...` -> `SERVERS`), then matched in full.
        term = ident.objectid or re.split(r"(?<!\\),", ident.dn)[0].split("=", 1)[-1] or ident.sam.rstrip("$")
        found: list[Node] = []
        for k in kinds:
            for item in self.client.search(term, k):
                found.append(Node.from_rest(k, {**item, "kind": item.get("type") or k}))
        return found

    def _hydrate_rest(self, node: Node) -> Node:
        try:
            props = self.client.entity(node.kind, node.objectid)
        except (NotFoundError, ValueError):
            return node
        merged = Node.from_rest(node.kind, {**node.properties, **props, "kind": node.kind})
        merged.tier_zero = merged.tier_zero or node.tier_zero
        merged.owned = merged.owned or node.owned
        return merged

    def domain_names(self) -> list[str] | None:
        """The FQDNs of the Active Directory domains BloodHound knows (`None` if it cannot list them)."""
        try:
            listed = (self.client.get("api/v2/available-domains") or {}).get("data") or []
        except BHError:  # no such endpoint, no permission, ...: nothing to check against
            return None
        return sorted(str(d.get("name") or "").upper() for d in listed
                      if d.get("type", "active-directory") == "active-directory")

    def applicable_views(self, node: Node) -> list[str]:
        return [key for key, kinds in VIEWS.items() if node.kind in kinds]

    def report(self, node: Node, views: list[str], *, show_summary: bool) -> EntityReport:
        report = EntityReport(node=node, show_summary=show_summary)
        if show_summary:
            report.extra = self._queried_summary(node)
        for key in views:
            if node.kind in VIEWS.get(key, ()):
                report.views.extend(self.view(node, key))
        return report

    def _queried_summary(self, node: Node) -> list[SummaryField]:
        """The summary fields that take queries (OU contents, GPO scope, ...), for the kinds that have them."""
        if node.kind in CONTAINER_KINDS:
            return self.containers.summary(node)
        if node.kind == "GPO":
            return self.gpo.summary(node)
        if node.kind in ADCS_KINDS:
            return self.adcs.summary(node)
        return []

    def view(self, node: Node, key: str) -> list[ViewResult]:
        owner = (self.containers if key in CONTAINER_VIEWS else self.gpo if key in GPO_VIEWS
                 else self.adcs if key in ADCS_VIEWS else self)
        return getattr(owner, key)(node)  # every VIEWS key is a method

    def groups(self, node: Node) -> list[ViewResult]:
        title = "Group memberships (direct + nested)"

        def via_cypher() -> list[ViewResult]:
            g = self.run_cypher(Q.member_of(node.objectid))
            rows: list[RelationshipRow] = []
            start = g.find(node.objectid)
            if start:
                for gid, (depth, parent) in g.bfs(start.id, MEMBER_OF).items():
                    grp = g.nodes[gid]
                    rows.append(RelationshipRow(
                        principal=node.name, edge=MEMBER_OF, target=grp.name, target_kind=grp.kind,
                        via="direct" if depth == 1 else g.nodes[parent].name, depth=depth,
                        tier_zero=grp.tier_zero, owned=grp.owned, objectid=grp.objectid,
                    ))
            rows.sort(key=lambda r: (r.depth or 0, r.target))
            return [ViewResult("groups", title, GROUP_COLS, rows)]

        return self._with_fallback(via_cypher, lambda why: self._rest_view(node, "groups", title, GROUP_COLS, why))

    def members(self, node: Node) -> list[ViewResult]:
        title = "Group members (direct + nested)"

        def via_cypher() -> list[ViewResult]:
            g = self.run_cypher(Q.members(node.objectid, self.max_results))
            rows: list[RelationshipRow] = []
            start = g.find(node.objectid)
            if start:
                for mid, (depth, parent) in g.bfs(start.id, MEMBER_OF, reverse=True).items():
                    m = g.nodes[mid]
                    rows.append(RelationshipRow(
                        principal=m.name, principal_kind=m.kind, edge=MEMBER_OF, target=node.name,
                        via="direct" if depth == 1 else g.nodes[parent].name, depth=depth,
                        tier_zero=m.tier_zero, owned=m.owned, objectid=m.objectid,
                    ))
            rows.sort(key=lambda r: (r.depth or 0, not r.owned, r.principal_kind != "User", r.principal))
            return [self._capped(ViewResult("members", title, MEMBER_COLS, rows), g)]

        return self._with_fallback(via_cypher, lambda why: self._rest_view(node, "members", title, MEMBER_COLS, why))

    def outbound(self, node: Node) -> list[ViewResult]:
        title = "Outbound object control (rights held over other objects)"
        return self._with_fallback(
            lambda: [self._effective_view(node, "outbound", title, CONTROL_EDGES)],
            lambda why: self._rest_view(node, "outbound", title, OUTBOUND_COLS, why),
        )

    def inbound(self, node: Node) -> list[ViewResult]:
        title = "Inbound object control (principals with rights over this object, direct + via groups)"

        def via_cypher() -> list[ViewResult]:
            oid, limit = node.objectid, self.max_results
            graphs = [
                *self._tiered(lambda ks: Q.incoming(oid, ks, limit) if ks else Q.incoming_any(oid, limit),
                              CONTROL_EDGES),
                # Members of broad groups (Domain Users, Everyone, ...) are everyone: the group row says it.
                *self._tiered(lambda ks: Q.incoming_unrolled(oid, ks, limit, BROAD_SIDS), CONTROL_EDGES),
            ]
            g = Graph.union(graphs)
            rows: list[RelationshipRow] = []
            target = g.find(node.objectid)
            if target:
                # Each holding group's most severe right: its members are listed once, with that right.
                strongest: dict[str, str] = {}
                for e in g.edges_to([target.id], CONTROL_EDGES):
                    src = g.nodes[e.source]
                    rows.append(RelationshipRow(
                        principal=src.name, principal_kind=src.kind, edge=e.kind, target=node.name,
                        target_kind=node.kind, via="direct", depth=0, tier_zero=src.tier_zero, owned=src.owned,
                        objectid=src.objectid,
                    ))
                    if src.kind == "Group" and not src.objectid.upper().endswith(BROAD_SIDS):
                        best = strongest.get(e.source)
                        if best is None or (severity_rank(e.kind), e.kind) < (severity_rank(best), best):
                            strongest[e.source] = e.kind
                for gid, edge in strongest.items():
                    group = g.nodes[gid]
                    for mid, (depth, _) in g.bfs(gid, MEMBER_OF, reverse=True).items():
                        m = g.nodes[mid]
                        rows.append(RelationshipRow(
                            principal=m.name, principal_kind=m.kind, edge=edge, target=node.name,
                            target_kind=node.kind, via=group.name, depth=depth, tier_zero=m.tier_zero,
                            owned=m.owned, objectid=m.objectid,
                        ))
            rows.sort(key=lambda r: (severity_rank(r.edge), r.depth or 0, not r.owned, not r.tier_zero, r.edge,
                                     r.principal))
            return [self._capped(ViewResult("inbound", title, INBOUND_COLS, rows), *graphs)]

        return self._with_fallback(via_cypher, lambda why: self._rest_view(node, "inbound", title, INBOUND_COLS, why))

    def sessions(self, node: Node) -> list[ViewResult]:
        titles = {
            "User": "Sessions (computers where this user is logged on)",
            "Computer": "Sessions (users logged on to this computer)",
            "Group": "Sessions of group members (direct + nested)",
        }
        title, cols = titles[node.kind], SESSION_COLS[node.kind]

        def via_cypher() -> list[ViewResult]:
            query = {
                "User": Q.sessions_of_user,
                "Computer": Q.sessions_on_computer,
                "Group": Q.sessions_of_group_members,
            }[node.kind](node.objectid, self.max_results)
            g = self.run_cypher(query)
            rows: list[RelationshipRow] = []
            for e in g.edges:
                if e.kind != HAS_SESSION:
                    continue
                comp, user = g.nodes[e.source], g.nodes[e.target]
                flag_node = user if node.kind == "Computer" else comp
                rows.append(RelationshipRow(
                    principal=user.name, principal_kind=user.kind, edge=HAS_SESSION,
                    target=comp.name, target_kind=comp.kind,
                    tier_zero=flag_node.tier_zero, owned=flag_node.owned, objectid=flag_node.objectid,
                ))
            rows.sort(key=lambda r: (not r.tier_zero, r.principal, r.target))
            return [self._capped(ViewResult("sessions", title, cols, rows), g)]

        return self._with_fallback(via_cypher, lambda why: self._rest_view(node, "sessions", title, cols, why))

    def privs(self, node: Node) -> list[ViewResult]:
        held_title = "Execution privileges held (AdminTo, CanRDP, ExecuteDCOM, CanPSRemote, SQLAdmin)"
        results = self._with_fallback(
            lambda: [self._effective_view(node, "privs_held", held_title, EXEC_EDGES)],
            lambda why: self._rest_view(node, "privs_held", held_title, OUTBOUND_COLS, why),
        )
        if node.kind == "Computer":
            in_title = "Principals with execution privileges on this computer (direct + via groups)"
            results += self._with_fallback(
                lambda: [self._exec_inbound(node, in_title)],
                lambda why: self._rest_view(node, "privs_inbound", in_title, INBOUND_COLS, why),
            )
        return results

    def _capped(self, view: ViewResult, *graphs: Graph) -> ViewResult:
        """Flag views whose underlying (LIMITed) queries hit `max_results`."""
        limit = self.max_results
        cut = [total for truncated, total in map(self.truncation, graphs) if truncated]
        if view.backend == "rest" and len(view.rows) >= limit:
            cut.append(None)
        if cut:
            view.notes.append(truncation_note(limit, cut, "paths per query"))
        return view

    def _tiered(self, build: Callable[[frozenset[str] | None], str], kinds: frozenset[str]) -> list[Graph]:
        """Run one query per severity tier of `kinds`.

        Each query has its own LIMIT, so a flood of low-impact edges can never
        crowd critical ones out of the result. If the server rejects a kind it does
        not know, a single unfiltered query (`build(None)`) is used instead.
        """
        tiers: dict[str, set[str]] = {}
        for kind in kinds:
            tiers.setdefault(severity(kind), set()).add(kind)
        try:
            return [self.run_cypher(build(frozenset(tiers[t]))) for t in SEVERITIES if t in tiers]
        except ApiError:
            return [self.run_cypher(build(None))]

    def _effective_view(self, node: Node, key: str, title: str, kinds: frozenset[str]) -> ViewResult:
        """Edges of `kinds` held by the node directly or through nested groups."""
        oid, limit = node.objectid, self.max_results
        graphs = [
            *self._tiered(lambda ks: Q.outgoing_direct(oid, limit, ks), kinds),
            *self._tiered(lambda ks: Q.outgoing_inherited(oid, limit, ks), kinds),
        ]
        view = ViewResult(key, title, OUTBOUND_COLS)
        g = Graph.union(graphs)
        start = g.find(node.objectid)
        if not start:
            return self._capped(view, *graphs)
        groups = g.bfs(start.id, MEMBER_OF)
        rows: list[RelationshipRow] = []
        for e in g.edges_from({start.id, *groups}, kinds):
            src, tgt = g.nodes[e.source], g.nodes[e.target]
            is_direct = e.source == start.id
            rows.append(RelationshipRow(
                principal=src.name, principal_kind=src.kind, edge=e.kind, target=tgt.name,
                target_kind=tgt.kind, via="direct" if is_direct else src.name,
                depth=0 if is_direct else groups[e.source][0],
                tier_zero=tgt.tier_zero, owned=tgt.owned, objectid=tgt.objectid,
            ))
        # Worst rights first, whichever group holds them: depth only orders rights of equal severity.
        rows.sort(key=lambda r: (severity_rank(r.edge), not r.tier_zero, r.depth or 0, r.edge, r.target))
        view.rows = rows
        return self._capped(view, *graphs)

    def _exec_inbound(self, node: Node, title: str) -> ViewResult:
        oid, limit = node.objectid, self.max_results
        graphs = [
            *self._tiered(lambda ks: Q.incoming(oid, ks or EXEC_EDGES, limit), EXEC_EDGES),
            *self._tiered(lambda ks: Q.exec_rights_inbound_unrolled(oid, limit, ks or EXEC_EDGES), EXEC_EDGES),
        ]
        g = Graph.union(graphs)
        target = g.find(node.objectid)
        rows: list[RelationshipRow] = []
        if target:
            for e in g.edges_to([target.id], EXEC_EDGES):
                src = g.nodes[e.source]
                rows.append(RelationshipRow(
                    principal=src.name, principal_kind=src.kind, edge=e.kind, target=node.name, via="direct",
                    depth=0, tier_zero=src.tier_zero, owned=src.owned, objectid=src.objectid,
                ))
                if src.kind == "Group":
                    for mid, (depth, _parent) in g.bfs(src.id, MEMBER_OF, reverse=True).items():
                        m = g.nodes[mid]
                        rows.append(RelationshipRow(
                            principal=m.name, principal_kind=m.kind, edge=e.kind, target=node.name,
                            via=src.name, depth=depth, tier_zero=m.tier_zero, owned=m.owned, objectid=m.objectid,
                        ))
        rows.sort(key=lambda r: (severity_rank(r.edge), r.depth or 0, not r.owned, not r.tier_zero, r.edge,
                                 r.principal))
        return self._capped(ViewResult("privs_inbound", title, INBOUND_COLS, rows), *graphs)

    def _rest_view(self, node: Node, key: str, title: str, columns: list[Column], why: str) -> list[ViewResult]:
        view = ViewResult(key, title, columns, backend="rest")
        if why:
            view.notes.append(f"Cypher query failed ({why}); used REST fallback.")
        for relation, label, direction in REST_ROUTES.get((node.kind, key), []):
            try:
                items = self.client.entity_related(node.kind, node.objectid, relation, limit=self.max_results)
            except NotFoundError:
                view.notes.append(f"Endpoint '{relation}' is not available on this server.")
                continue
            for item in items:
                other = Node.from_rest("", item)
                row = RelationshipRow(edge=label, tier_zero=other.tier_zero, owned=other.owned,
                                      objectid=other.objectid)
                if direction == "out":
                    row.principal, row.principal_kind = node.name, node.kind
                    row.target, row.target_kind = other.name, other.kind
                else:
                    row.principal, row.principal_kind = other.name, other.kind
                    row.target, row.target_kind = node.name, node.kind
                view.rows.append(row)
        if key in ("outbound", "inbound"):
            view.notes.append("REST fallback: exact right names are not exposed; enable Cypher for full detail.")
        return [self._capped(view)]
