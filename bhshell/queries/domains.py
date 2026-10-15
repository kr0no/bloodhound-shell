"""Domain overview and trust analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from bhshell.errors import CypherDisabledError, NotFoundError, UnsupportedFeature
from bhshell.models.entities import TIER_ZERO_LABEL, Graph, Node, opt_bool
from bhshell.queries import cypher as Q
from bhshell.queries.edges import TRUST_ABUSE_EDGES, TRUST_EDGES
from bhshell.queries.service import EntityService

TRUSTS_QUERY = "MATCH p=(a:Domain)-[r]->(b:Domain) RETURN p"
REST_DOMAINS_NOTE = "Cypher is unavailable: enabled and Tier Zero counts need it."
_COUNT_KEYS = ("users", "enabled_users", "computers", "enabled_computers", "groups", "tier_zero")


@dataclass
class DomainInfo:
    name: str
    sid: str
    functional_level: str = ""
    collected: bool | None = None
    last_collected: str = ""
    counts: dict[str, int | None] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {**{k: v for k, v in asdict(self).items() if k != "counts"}, **self.counts}


@dataclass
class TrustInfo:
    """One trust: `trusting` trusts `trusted`; principals of `trusted` can access `trusting`."""

    trusting: str
    trusted: str
    kind: str
    trust_type: str = ""
    transitive: bool | None = None
    sid_filtering: bool | None = None
    tgt_delegation: bool | None = None
    abuse: list[str] = field(default_factory=list)

    @property
    def same_forest(self) -> bool:
        return self.kind == "SameForestTrust"

    @property
    def issues(self) -> list[str]:
        """Weaknesses the collected data shows.

        SID filtering is on by default for cross-forest (and external) trusts and off within a
        forest, so a missing `spoofsidhistoryblocked` property on a cross-forest trust is not
        reported: only an explicit `false`, a same-forest trust, or a BloodHound abuse edge is.
        """
        out = [f"abusable: {a}" for a in self.abuse]
        if self.same_forest:
            out.append("same forest: SID filtering not enforced")
        elif self.sid_filtering is False:
            out.append("SID filtering disabled")
        if self.tgt_delegation:
            out.append("TGT delegation enabled")
        return out

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "abuse": ", ".join(self.abuse), "issues": "; ".join(self.issues)}


def trusts_from_graph(graph: Graph) -> list[TrustInfo]:
    trusts: dict[tuple[str, str], TrustInfo] = {}
    abuse: dict[tuple[str, str], list[str]] = {}
    for e in graph.edges:
        src, dst = graph.nodes[e.source].name, graph.nodes[e.target].name
        if e.kind in TRUST_EDGES:
            trusts[(src, dst)] = TrustInfo(
                trusting=src, trusted=dst, kind=e.kind,
                trust_type=str(e.properties.get("trusttype") or ""),
                transitive=opt_bool(e.properties, "transitive"),
                sid_filtering=opt_bool(e.properties, "spoofsidhistoryblocked"),
                tgt_delegation=opt_bool(e.properties, "tgtdelegation"),
            )
        elif e.kind in TRUST_ABUSE_EDGES:
            # Abuse edges point in the direction of access: trusted -> trusting.
            abuse.setdefault((dst, src), []).append(e.kind)
    for key, kinds in abuse.items():
        trust = trusts.setdefault(key, TrustInfo(trusting=key[0], trusted=key[1], kind="(abuse only)"))
        trust.abuse = sorted(set(kinds))
    return sorted(trusts.values(), key=lambda t: (not t.issues, t.trusting, t.trusted))


class DomainService:
    def __init__(self, entities: EntityService) -> None:
        self.entities = entities
        self.client = entities.client
        self.notes: list[str] = []

    def domains(self) -> list[DomainInfo]:
        try:
            listed = (self.client.get("api/v2/available-domains") or {}).get("data") or []
        except NotFoundError:
            listed = []
        try:
            nodes = {n.objectid: n for n in self.entities.run_cypher("MATCH (n:Domain) RETURN n").nodes.values()}
        except CypherDisabledError:
            self.notes.append(REST_DOMAINS_NOTE)
            return sorted((self._rest_info(item) for item in listed if _active_directory(item)),
                          key=lambda d: d.name)
        pending: list[tuple[str, str, Node | None, bool | None]] = []
        seen: set[str] = set()
        for item in listed:
            if not _active_directory(item):
                continue
            sid = item.get("id", "")
            seen.add(sid)
            pending.append((item.get("name", sid), sid, nodes.get(sid), item.get("collected")))
        pending += [(node.name, sid, node, None) for sid, node in nodes.items() if sid not in seen]
        infos = [self._info(*args) for args in self.client.steps(pending)]
        return sorted(infos, key=lambda d: d.name)

    def _info(self, name: str, sid: str, node: Node | None, collected: bool | None) -> DomainInfo:
        props = node.properties if node is not None else {}
        info = DomainInfo(
            name=name, sid=sid, collected=collected,
            functional_level=str(props.get("functionallevel") or ""),
            last_collected=str(props.get("lastcollected") or props.get("lastseen") or "")[:19],
        )
        if collected is False:  # only known through trusts: no objects to count
            info.last_collected = ""
            info.counts = dict.fromkeys(_COUNT_KEYS)
            return info
        in_domain, enabled = f"n.domain = {Q.lit(name.upper())}", "n.enabled = true"
        info.counts = {
            "users": self._count("(n:User)", in_domain),
            "enabled_users": self._count("(n:User)", in_domain, enabled),
            "computers": self._count("(n:Computer)", in_domain),
            "enabled_computers": self._count("(n:Computer)", in_domain, enabled),
            "groups": self._count("(n:Group)", in_domain),
            "tier_zero": self._count(f"(n:{TIER_ZERO_LABEL})", in_domain),
        }
        return info

    def _rest_info(self, item: dict[str, Any]) -> DomainInfo:
        """A domain from the REST API: the domain entity carries its object counts."""
        sid = item.get("id", "")
        info = DomainInfo(name=item.get("name", sid), sid=sid, collected=item.get("collected"))
        if info.collected is False:
            info.counts = dict.fromkeys(_COUNT_KEYS)
            return info
        try:
            data = (self.client.get(f"api/v2/domains/{sid}", counts="true") or {}).get("data") or {}
        except NotFoundError:
            return info
        props = data.get("props") or {}
        info.functional_level = str(props.get("functionallevel") or "")
        info.last_collected = str(props.get("lastcollected") or props.get("lastseen") or "")[:19]
        info.counts = {"users": data.get("users"), "enabled_users": None, "computers": data.get("computers"),
                       "enabled_computers": None, "groups": data.get("groups"), "tier_zero": None}
        return info

    def _count(self, match: str, *conditions: str) -> int | None:
        return self.entities.count(f"MATCH {match}{Q.where(*conditions)} RETURN count(n)")

    def trusts(self) -> list[TrustInfo]:
        # The REST API lists trusted domains, transitive ones included, but not the trusts' properties.
        try:
            return trusts_from_graph(self.entities.run_cypher(TRUSTS_QUERY))
        except CypherDisabledError as exc:
            raise UnsupportedFeature("'trusts' needs the Cypher endpoint") from exc


def _active_directory(item: dict[str, Any]) -> bool:
    """An Active Directory domain of `available-domains` (Azure tenants are listed there too)."""
    return item.get("type", "active-directory") == "active-directory"
