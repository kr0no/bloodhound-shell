"""Graph and Active Directory entity models.

The BH Cypher endpoint returns graphs shaped like::

    {"nodes": {"<id>": {"label", "kind", "kinds", "objectId", "isTierZero",
                        "isOwnedObject", "properties": {...}}},
     "edges": [{"source", "target", "kind", "properties"}]}

These are normalised into `Node`, `Edge` and `Graph`.
Typed AD views (`User`, `Computer`, `Group`) expose the
triage summary for each object type.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

PRIMARY_KINDS = (
    "User",
    "Computer",
    "Group",
    "Domain",
    "GPO",
    "OU",
    "Container",
    "AIACA",
    "RootCA",
    "EnterpriseCA",
    "NTAuthStore",
    "CertTemplate",
    "IssuancePolicy",
)

TIER_ZERO_LABEL = "Tag_Tier_Zero"
OWNED_LABEL = "Tag_Owned"

# Extended key usages, by the OIDs BloodHound stores.
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "2.5.29.37.0": "Any Purpose",
}


@dataclass
class Node:
    id: str
    objectid: str
    kind: str
    name: str
    kinds: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    tier_zero: bool = False
    owned: bool = False

    @classmethod
    def from_cypher(cls, node_id: str, raw: dict[str, Any]) -> Node:
        props = raw.get("properties") or {}
        kinds = list(raw.get("kinds") or [])
        primary = raw.get("kind") or ""
        for candidate in PRIMARY_KINDS:
            if candidate in kinds or candidate == primary:
                primary = candidate
                break
        return cls._build(
            node_id=str(node_id),
            objectid=raw.get("objectId") or props.get("objectid") or "",
            kind=primary or "Unknown",
            name=props.get("name") or raw.get("label") or "",
            kinds=kinds,
            props=props,
            tier_zero=bool(raw.get("isTierZero")),
            owned=bool(raw.get("isOwnedObject")),
        )

    @classmethod
    def from_rest(cls, kind: str, raw: dict[str, Any]) -> Node:
        """Build a node from a REST entity's `props` or from an item of a related-objects list.

        Entity props spell it `objectid`; list items use `objectID` and put the kind in `label`.
        """
        objectid = raw.get("objectid") or raw.get("objectID") or ""
        item_kind = raw.get("kind") or raw.get("label") or kind
        return cls._build(
            node_id=objectid,
            objectid=objectid,
            kind=str(item_kind),
            name=raw.get("name") or objectid,
            kinds=[str(k) for k in raw.get("kinds") or [item_kind]],
            props=raw,
            tier_zero=bool(raw.get("isTierZero")),
            owned=bool(raw.get("isOwnedObject")),
        )

    @classmethod
    def _build(cls, *, node_id: str, objectid: str, kind: str, name: str, kinds: list[str],
               props: dict[str, Any], tier_zero: bool, owned: bool) -> Node:
        return cls(
            id=node_id,
            objectid=objectid,
            kind=kind,
            name=name,
            kinds=kinds,
            properties=props,
            tier_zero=tier_zero or TIER_ZERO_LABEL in kinds,
            owned=owned or OWNED_LABEL in kinds,
        )

    @property
    def domain(self) -> str:
        return str(self.properties.get("domain") or "")

    @property
    def samaccountname(self) -> str:
        return str(self.properties.get("samaccountname") or "")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "objectid": self.objectid,
            "domain": self.domain,
            "tier_zero": self.tier_zero,
            "owned": self.owned,
            "properties": self.properties,
        }


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @classmethod
    def from_cypher(cls, raw: dict[str, Any]) -> Edge:
        return cls(
            source=str(raw.get("source")),
            target=str(raw.get("target")),
            kind=str(raw.get("kind") or ""),
            properties=raw.get("properties") or {},
        )


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    # The Cypher query this graph came from ('' when built otherwise).
    query: str = field(default="", compare=False, repr=False)

    @classmethod
    def from_cypher(cls, data: dict[str, Any]) -> Graph:
        graph = cls()
        for node_id, raw in (data.get("nodes") or {}).items():
            graph.nodes[str(node_id)] = Node.from_cypher(node_id, raw)
        seen: set[Edge] = set()
        for raw in data.get("edges") or []:
            edge = Edge.from_cypher(raw)
            if edge not in seen:
                seen.add(edge)
                graph.edges.append(edge)
        return graph

    def merge(self, other: Graph) -> Graph:
        self.nodes.update(other.nodes)
        seen = set(self.edges)
        self.edges.extend(e for e in other.edges if e not in seen)
        return self

    @classmethod
    def union(cls, graphs: Iterable[Graph]) -> Graph:
        merged = cls()
        for g in graphs:
            merged.merge(g)
        return merged

    def find(self, objectid: str) -> Node | None:
        return next((n for n in self.nodes.values() if n.objectid == objectid), None)

    def edges_from(self, sources: Iterable[str], kinds: Iterable[str] | None = None) -> Iterator[Edge]:
        srcs = set(sources)
        wanted = set(kinds) if kinds is not None else None
        return (e for e in self.edges if e.source in srcs and (wanted is None or e.kind in wanted))

    def edges_to(self, targets: Iterable[str], kinds: Iterable[str] | None = None) -> Iterator[Edge]:
        tgts = set(targets)
        wanted = set(kinds) if kinds is not None else None
        return (e for e in self.edges if e.target in tgts and (wanted is None or e.kind in wanted))

    def paths(self, sources: Iterable[str], targets: Iterable[str], *, max_paths: int = 1000) -> list[list[Edge]]:
        """Enumerate shortest chains from each source to the nearest-reachable targets.

        Path APIs return the *union* of all paths as one subgraph; this splits
        it back into individual chains. A chain ends at the first target it
        reaches, and only edges that advance the BFS distance from the source
        are followed, so every chain is a shortest path to its target.
        """
        adjacency: dict[str, list[Edge]] = {}
        for e in self.edges:
            adjacency.setdefault(e.source, []).append(e)
        tgts = set(targets)
        found: list[list[Edge]] = []

        for src in sources:
            dist = {src: 0}
            queue: deque[str] = deque([src])
            while queue:
                current = queue.popleft()
                if current in tgts and current != src:
                    continue  # never expand beyond a target
                for e in adjacency.get(current, []):
                    if e.target not in dist:
                        dist[e.target] = dist[current] + 1
                        queue.append(e.target)

            # Iterative DFS along distance-increasing edges: (node, chain so far).
            stack: list[tuple[str, list[Edge]]] = [(src, [])]
            while stack and len(found) < max_paths:
                node, chain = stack.pop()
                if chain and node in tgts:
                    found.append(chain)
                    continue
                for e in reversed(adjacency.get(node, [])):
                    if dist.get(e.target) == dist[node] + 1:
                        stack.append((e.target, [*chain, e]))
        return found

    def count_paths(self, cap: int) -> int:
        """Count simple paths (one edge or more) in the graph, stopping at `cap`.

        Every row of a `RETURN p` query is a simple path of its result graph,
        so this is an upper bound on the number of rows the server returned.
        """
        adjacency: dict[str, list[str]] = {}
        for e in self.edges:
            adjacency.setdefault(e.source, []).append(e.target)
        total = 0
        for start, targets in adjacency.items():
            on_path = {start}
            stack: list[tuple[str, Iterator[str]]] = [(start, iter(targets))]
            while stack:
                node, successors = stack[-1]
                nxt = next(successors, None)
                if nxt is None:
                    stack.pop()
                    on_path.discard(node)
                    continue
                if nxt in on_path:
                    continue
                total += 1
                if total >= cap:
                    return total
                if nxt in adjacency:
                    on_path.add(nxt)
                    stack.append((nxt, iter(adjacency[nxt])))
        return total

    def bfs(self, start: str, kind: str, *, reverse: bool = False) -> dict[str, tuple[int, str]]:
        """`{node_id: (depth, parent_id)}` of every node reachable along `kind` edges, `start` excluded."""
        adjacency: dict[str, list[str]] = {}
        for e in self.edges:
            if e.kind != kind:
                continue
            a, b = (e.target, e.source) if reverse else (e.source, e.target)
            adjacency.setdefault(a, []).append(b)
        found: dict[str, tuple[int, str]] = {}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            for nxt in adjacency.get(current, []):
                if nxt != start and nxt not in found:
                    found[nxt] = (depth + 1, current)
                    queue.append((nxt, depth + 1))
        return found


Risk = Literal["high", "medium", "info", "none"]
FieldType = Literal["text", "bool", "date", "list"]


@dataclass(frozen=True)
class SummaryField:
    label: str
    value: Any
    type: FieldType = "text"
    risk: Risk = "none"


def epoch_to_datetime(value: Any) -> datetime | None:
    """`None` for never/unset (BloodHound stores 0 or -1)."""
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=UTC)


def opt_bool(props: dict[str, Any], key: str) -> bool | None:
    value = props.get(key)
    return None if value is None else bool(value)


def last_logon(props: dict[str, Any]) -> int | float | None:
    """Most recent of `lastlogon` and the replicated `lastlogontimestamp`."""
    values = [v for v in (props.get("lastlogon"), props.get("lastlogontimestamp")) if isinstance(v, (int, float))]
    return max(values) if values else None


def _risk_if(value: bool | None, risk: Risk = "high") -> Risk:
    return risk if value else "none"


class ADObject:
    def __init__(self, node: Node) -> None:
        self.node = node
        self.props = node.properties

    @staticmethod
    def wrap(node: Node) -> ADObject:
        kinds = {"User": User, "Computer": Computer, "Group": Group, "GPO": GPO,
                 "OU": DirectoryContainer, "Container": DirectoryContainer, "Domain": DirectoryContainer,
                 "CertTemplate": CertTemplate, "EnterpriseCA": EnterpriseCA}
        return kinds.get(node.kind, ADObject)(node)

    def _common_head(self) -> list[SummaryField]:
        sid = self.node.kind in ("User", "Computer", "Group", "Domain")
        oid = "Object ID (SID)" if sid else "Object ID (GUID)"
        fields = [
            SummaryField("Name", self.node.name),
            SummaryField("Type", self.node.kind),
            SummaryField(oid, self.node.objectid),
            SummaryField("Domain", self.node.domain),
        ]
        if self.props.get("distinguishedname"):
            fields.append(SummaryField("Distinguished Name", self.props["distinguishedname"]))
        return fields

    def _common_tail(self) -> list[SummaryField]:
        return [
            SummaryField("Description", self.props.get("description") or ""),
            SummaryField("Tier Zero / High Value", self.node.tier_zero, "bool",
                         _risk_if(self.node.tier_zero, "medium")),
            SummaryField("Owned", self.node.owned, "bool", _risk_if(self.node.owned, "info")),
        ]

    def summary(self) -> list[SummaryField]:
        return [*self._common_head(), *self._common_tail()]


class User(ADObject):
    def summary(self) -> list[SummaryField]:
        p = self.props
        enabled = opt_bool(p, "enabled")
        admincount = opt_bool(p, "admincount")
        hasspn = opt_bool(p, "hasspn")
        asrep = opt_bool(p, "dontreqpreauth")
        unconstrained = opt_bool(p, "unconstraineddelegation")
        t2a = opt_bool(p, "trustedtoauth")
        sensitive = opt_bool(p, "sensitive")
        return [
            *self._common_head(),
            SummaryField("Enabled", enabled, "bool"),
            SummaryField("AdminCount", admincount, "bool", _risk_if(admincount, "medium")),
            SummaryField("Kerberoastable (hasspn)", hasspn, "bool", _risk_if(hasspn and enabled is not False)),
            SummaryField("SPNs", p.get("serviceprincipalnames") or [], "list"),
            SummaryField("AS-REP Roastable (dontreqpreauth)", asrep, "bool", _risk_if(asrep and enabled is not False)),
            SummaryField("Unconstrained Delegation", unconstrained, "bool", _risk_if(unconstrained)),
            SummaryField("Constrained Delegation (trustedtoauth)", t2a, "bool", _risk_if(t2a)),
            SummaryField("Allowed To Delegate To", p.get("allowedtodelegate") or [], "list"),
            SummaryField("Password Never Expires", opt_bool(p, "pwdneverexpires"), "bool",
                         _risk_if(opt_bool(p, "pwdneverexpires"), "medium")),
            SummaryField("Password Not Required", opt_bool(p, "passwordnotreqd"), "bool",
                         _risk_if(opt_bool(p, "passwordnotreqd"))),
            SummaryField("Password Last Set", p.get("pwdlastset"), "date"),
            SummaryField("Last Logon", last_logon(p), "date"),
            SummaryField("Sensitive (cannot be delegated)", sensitive, "bool"),
            *self._common_tail(),
        ]


class Computer(ADObject):
    def summary(self) -> list[SummaryField]:
        p = self.props
        unconstrained = opt_bool(p, "unconstraineddelegation")
        t2a = opt_bool(p, "trustedtoauth")
        haslaps = opt_bool(p, "haslaps")
        return [
            *self._common_head(),
            SummaryField("Enabled", opt_bool(p, "enabled"), "bool"),
            SummaryField("Operating System", p.get("operatingsystem") or ""),
            SummaryField("Unconstrained Delegation", unconstrained, "bool",
                         _risk_if(unconstrained and not self.node.tier_zero)),
            SummaryField("Constrained Delegation (trustedtoauth)", t2a, "bool", _risk_if(t2a)),
            SummaryField("Allowed To Delegate To", p.get("allowedtodelegate") or [], "list"),
            SummaryField("LAPS Enabled", haslaps, "bool", "medium" if haslaps is False else "none"),
            SummaryField("Last Logon", last_logon(p), "date"),
            *self._common_tail(),
        ]


class Group(ADObject):
    def summary(self) -> list[SummaryField]:
        admincount = opt_bool(self.props, "admincount")
        return [
            *self._common_head(),
            SummaryField("AdminCount", admincount, "bool", _risk_if(admincount, "medium")),
            *self._common_tail(),
        ]


class GPO(ADObject):
    def summary(self) -> list[SummaryField]:
        p = self.props
        fields = self._common_head()
        if p.get("gpcpath"):
            fields.append(SummaryField("SYSVOL Path", p["gpcpath"]))
        if p.get("whencreated"):
            fields.append(SummaryField("Created", p["whencreated"], "date"))
        return [*fields, *self._common_tail()]


class DirectoryContainer(ADObject):
    """An OU, a container or a domain: the nodes of the directory tree."""

    def summary(self) -> list[SummaryField]:
        p = self.props
        fields = self._common_head()
        if self.node.kind == "Domain":
            fields.append(SummaryField("Functional Level", p.get("functionallevel") or ""))
        if self.node.kind == "OU":
            blocks = opt_bool(p, "blocksinheritance")
            fields.append(SummaryField("Blocks GPO Inheritance", blocks, "bool", _risk_if(blocks, "info")))
        if p.get("whencreated"):
            fields.append(SummaryField("Created", p["whencreated"], "date"))
        return [*fields, *self._common_tail()]


def effective_ekus(props: dict[str, Any]) -> list[str] | None:
    """The EKUs a template's certificates carry (`None` when not collected); empty means any use."""
    ekus = props.get("effectiveekus")
    if ekus is None:
        ekus = props.get("ekus")
    return None if ekus is None else [str(e) for e in ekus]


def _registry_flag(props: dict[str, Any], key: str, collected: str, label: str, risk: Risk = "none") -> SummaryField:
    """A CA setting read from the CA host's registry, which SharpHound cannot always reach."""
    if props.get(collected) is False:
        return SummaryField(label, "not collected")
    value = opt_bool(props, key)
    return SummaryField(label, value, "bool", _risk_if(value, risk))


class CertTemplate(ADObject):
    def summary(self) -> list[SummaryField]:
        p = self.props
        auth = opt_bool(p, "authenticationenabled")
        supplies = opt_bool(p, "enrolleesuppliessubject")
        nosid = opt_bool(p, "nosecurityextension")
        fields = [
            *self._common_head(),
            SummaryField("Display Name", p.get("displayname") or ""),
            SummaryField("Template OID", p.get("oid") or ""),
            SummaryField("Schema Version", p.get("schemaversion")),
        ]
        ekus = effective_ekus(p)
        if ekus == []:
            fields.append(SummaryField("Effective EKUs", "none (any purpose)"))
        elif ekus:
            fields.append(SummaryField("Effective EKUs", [EKU_NAMES.get(e, e) for e in ekus], "list"))
        return [
            *fields,
            SummaryField("Authentication Enabled", auth, "bool"),
            SummaryField("Enrollee Supplies Subject", supplies, "bool", _risk_if(supplies and auth)),
            SummaryField("Requires Manager Approval", opt_bool(p, "requiresmanagerapproval"), "bool"),
            SummaryField("Authorized Signatures Required", p.get("authorizedsignatures")),
            SummaryField("No Security Extension", nosid, "bool", _risk_if(nosid and auth)),
            SummaryField("Validity Period", p.get("validityperiod") or ""),
            SummaryField("Renewal Period", p.get("renewalperiod") or ""),
            *self._common_tail(),
        ]


class EnterpriseCA(ADObject):
    def summary(self) -> list[SummaryField]:
        p = self.props
        fields = [
            *self._common_head(),
            SummaryField("CA Name", p.get("caname") or ""),
            SummaryField("DNS Hostname", p.get("dnshostname") or ""),
            SummaryField("Certificate Thumbprint", p.get("certthumbprint") or ""),
            _registry_flag(p, "isuserspecifiessanenabled", "isuserspecifiessanenabledcollected",
                           "User Specified SAN (ESC6)", "high"),
            _registry_flag(p, "roleseparationenabled", "roleseparationenabledcollected", "Role Separation"),
            _registry_flag(p, "hasenrollmentagentrestrictions", "enrollmentagentrestrictionscollected",
                           "Enrollment Agent Restrictions"),
        ]
        endpoints = [*(p.get("httpenrollmentendpoints") or []), *(p.get("httpsenrollmentendpoints") or [])]
        if endpoints:
            fields.append(SummaryField("Web Enrollment Endpoints", endpoints, "list"))
        if "hasvulnerableendpoint" in p:
            vulnerable = opt_bool(p, "hasvulnerableendpoint")
            fields.append(SummaryField("Relayable Web Enrollment (ESC8)", vulnerable, "bool", _risk_if(vulnerable)))
        if p.get("whencreated"):
            fields.append(SummaryField("Created", p["whencreated"], "date"))
        return [*fields, *self._common_tail()]
