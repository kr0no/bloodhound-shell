"""Cypher query templates.

BH's Cypher endpoint does not accept bound parameters, so every value is
embedded as an escaped string literal via `lit`. Queries return paths or
nodes (not scalars) so that results come back as a graph.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from bhshell.models.entities import TIER_ZERO_LABEL
from bhshell.queries.edges import (
    CONTAINS,
    EXEC_EDGES,
    EXTENDED_BY_POLICY,
    GP_LINK,
    HAS_SESSION,
    MEMBER_OF,
    OID_GROUP_LINK,
)


def lit(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


_RETURN_LIMIT = re.compile(r"\s+RETURN\s+(\w+)(?:\s+ORDER\s+BY\s+.+?)?\s+LIMIT\s+(\d+)\s*$", re.IGNORECASE)


def limit_of(query: str) -> int | None:
    """The LIMIT of a `... RETURN x [ORDER BY ...] LIMIT n` query (`None` for other shapes)."""
    m = _RETURN_LIMIT.search(query)
    return int(m.group(2)) if m else None


def to_count(query: str) -> str | None:
    """Turn `... RETURN x [ORDER BY ...] LIMIT n` into `... RETURN count(x)` (`None` for other shapes)."""
    m = _RETURN_LIMIT.search(query)
    return f"{query[:m.start()]} RETURN count({m.group(1)})" if m else None


def where(*conds: str) -> str:
    """` WHERE a AND b` from the non-empty conditions, or ''."""
    present = [c for c in conds if c]
    return f" WHERE {' AND '.join(present)}" if present else ""


def domain_matches(domain: str, fqdn: str) -> bool:
    """Whether `fqdn` is in `domain`, the way `domain_condition` matches it ('' matches everything)."""
    if not domain:
        return True
    d, name = domain.upper(), fqdn.upper()
    return name == d or ("." not in d and name.startswith(d + "."))


def domain_condition(alias: str, domain: str) -> str:
    """Restrict `alias` to `domain`: an FQDN matches exactly, a NetBIOS name any FQDN it starts ('' = all)."""
    if not domain:
        return ""
    d = domain.upper()
    if "." in d:
        return f"{alias}.domain = {lit(d)}"
    return f"({alias}.domain = {lit(d)} OR {alias}.domain STARTS WITH {lit(d + '.')})"


def edge_types(edges: Iterable[str]) -> str:
    """`A|B|C`, for a relationship pattern."""
    return "|".join(sorted(edges))


def _label(kind: str | None) -> str:
    return f":{kind}" if kind else ":Base"


def by_objectid(objectid: str, *, any_domain: bool = False) -> str:
    """`any_domain`: also the `DOMAIN-SID` objects BloodHound makes of a well-known SID."""
    cond = f"n.objectid = {lit(objectid)}"
    if any_domain:
        cond = f"({cond} OR n.objectid ENDS WITH {lit('-' + objectid)})"
    return f"MATCH (n:Base) WHERE {cond} RETURN n"


def dn_condition(dn: str) -> str:
    """Match a distinguished name; BloodHound stores them upper-cased."""
    return f"n.distinguishedname = {lit(dn.upper())}"


def by_name(conditions: list[str], kind: str | None, limit: int) -> str:
    return f"MATCH (n{_label(kind)}) WHERE {' OR '.join(conditions)} RETURN n LIMIT {limit}"


def name_conditions(sam: str, fqdn: str | None, kind: str | None) -> list[str]:
    """WHERE conditions matching an object by samaccountname or FQDN.

    BloodHound stores `name` upper-cased as `SAM@DOMAIN` (users, groups)
    or `HOST.DOMAIN` (computers); `samaccountname` keeps the original case.
    """
    upper = sam.upper()
    host = upper.rstrip("$")
    conds: list[str] = []
    if fqdn:
        conds.append(f"n.name = {lit(fqdn.upper())}")
    if kind in (None, "User", "Group"):
        conds.append(f"n.name STARTS WITH {lit(upper + '@')}")
    if kind in (None, "Computer"):
        conds += [
            f"n.name STARTS WITH {lit(host + '.')}",
            f"n.name = {lit(host)}",
            f"n.samaccountname = {lit(host + '$')}",
        ]
    conds.append(f"n.samaccountname = {lit(sam)}")
    return list(dict.fromkeys(conds))


def member_of(objectid: str) -> str:
    return f"MATCH p=(n:Base)-[:{MEMBER_OF}*1..]->(g:Group) WHERE n.objectid = {lit(objectid)} RETURN p"


def members(objectid: str, limit: int) -> str:
    return f"MATCH p=(m:Base)-[:{MEMBER_OF}*1..]->(g:Group) WHERE g.objectid = {lit(objectid)} RETURN p LIMIT {limit}"


def _rel(edges: Iterable[str] | None) -> str:
    return f"[r:{edge_types(edges)}]" if edges else "[r]"


def outgoing_direct(objectid: str, limit: int, edges: Iterable[str] | None = None) -> str:
    """Outgoing edges of the node (all kinds when `edges` is `None`)."""
    return f"MATCH p=(n:Base)-{_rel(edges)}->(t:Base) WHERE n.objectid = {lit(objectid)} RETURN p LIMIT {limit}"


def outgoing_inherited(objectid: str, limit: int, edges: Iterable[str] | None = None) -> str:
    """Edges held by any group the node is (transitively) a member of."""
    return (
        f"MATCH p=(n:Base)-[:{MEMBER_OF}*1..]->(g:Group)-{_rel(edges)}->(t:Base) "
        f"WHERE n.objectid = {lit(objectid)} RETURN p LIMIT {limit}"
    )


def incoming(objectid: str, edges: Iterable[str], limit: int) -> str:
    return (
        f"MATCH p=(s:Base)-[r:{edge_types(edges)}]->(n:Base) "
        f"WHERE n.objectid = {lit(objectid)} RETURN p LIMIT {limit}"
    )


def incoming_any(objectid: str, limit: int) -> str:
    """Fallback for `incoming` when a kind in the filter is unknown to the server."""
    return f"MATCH p=(s:Base)-[r]->(n:Base) WHERE n.objectid = {lit(objectid)} RETURN p LIMIT {limit}"


def incoming_unrolled(objectid: str, edges: Iterable[str] | None, limit: int, skip: Iterable[str] = ()) -> str:
    """Members (nested) of the groups holding `edges` (any edge when `None`) over the object.

    Groups whose objectid ends with one of `skip` are listed but not unrolled.
    """
    broad = " OR ".join(f"x.objectid ENDS WITH {lit(s)}" for s in skip)
    keep = f" AND all(x IN nodes(p) WHERE x = m OR x = n OR NOT ({broad}))" if broad else ""
    return (
        f"MATCH p=(m:Base)-[:{MEMBER_OF}*1..]->(g:Group)-{_rel(edges)}->(n:Base) "
        f"WHERE n.objectid = {lit(objectid)}{keep} RETURN p LIMIT {limit}"
    )


def exec_rights_inbound_unrolled(objectid: str, limit: int, edges: Iterable[str] = EXEC_EDGES) -> str:
    return (
        f"MATCH p=(m:Base)-[:{MEMBER_OF}*1..]->(g:Group)-[r:{edge_types(edges)}]->(c:Computer) "
        f"WHERE c.objectid = {lit(objectid)} RETURN p LIMIT {limit}"
    )


def sessions_of_user(objectid: str, limit: int) -> str:
    return (
        f"MATCH p=(c:Computer)-[:{HAS_SESSION}]->(u:User) "
        f"WHERE u.objectid = {lit(objectid)} RETURN p LIMIT {limit}"
    )


def sessions_on_computer(objectid: str, limit: int) -> str:
    return (
        f"MATCH p=(c:Computer)-[:{HAS_SESSION}]->(u:User) "
        f"WHERE c.objectid = {lit(objectid)} RETURN p LIMIT {limit}"
    )


def sessions_of_group_members(objectid: str, limit: int) -> str:
    return (
        f"MATCH p=(c:Computer)-[:{HAS_SESSION}]->(u:User)-[:{MEMBER_OF}*1..]->(g:Group) "
        f"WHERE g.objectid = {lit(objectid)} RETURN p LIMIT {limit}"
    )



# Directory tree. `Contains` runs domain -> OU / container -> ... -> object, one parent per object.

_IS_CONTAINER = "(n:OU OR n:Container)"


def containers_above(objectid: str) -> str:
    """The chain of containers (domain first) holding the object."""
    return f"MATCH p=(c:Base)-[:{CONTAINS}*1..]->(n:Base) WHERE n.objectid = {lit(objectid)} RETURN p"


def gp_links_to(objectid: str) -> str:
    """GPOs linked to the object itself (a domain or an OU)."""
    return f"MATCH p=(g:GPO)-[r:{GP_LINK}]->(n:Base) WHERE n.objectid = {lit(objectid)} RETURN p"


def gp_links_from(objectid: str) -> str:
    """Where a GPO is linked (domains and OUs)."""
    return f"MATCH p=(g:GPO)-[r:{GP_LINK}]->(n:Base) WHERE g.objectid = {lit(objectid)} RETURN p"


def gp_links_above(objectid: str) -> str:
    """GPOs linked to any container above the object, with the containment chain down to it."""
    return (
        f"MATCH p=(g:GPO)-[r:{GP_LINK}]->(c:Base)-[:{CONTAINS}*1..]->(n:Base) "
        f"WHERE n.objectid = {lit(objectid)} RETURN p"
    )


def moved_objects(limit: int) -> str:
    """Objects in two containers or more: moved between two collections (see `containers.stale_contains`)."""
    return f"MATCH p=(a:Base)-[:{CONTAINS}]->(n:Base)<-[:{CONTAINS}]-(b:Base) WHERE a <> b RETURN p LIMIT {limit}"


def sub_containers(objectid: str, limit: int) -> str:
    """Every OU and container below the object."""
    return (
        f"MATCH p=(o:Base)-[:{CONTAINS}*1..]->(n:Base) "
        f"WHERE o.objectid = {lit(objectid)} AND {_IS_CONTAINER} RETURN p LIMIT {limit}"
    )


def contained_objects(objectid: str, limit: int) -> str:
    """Every object (other than OUs and containers) below the object, with the chain down to it."""
    return (
        f"MATCH p=(o:Base)-[:{CONTAINS}*1..]->(n:Base) "
        f"WHERE o.objectid = {lit(objectid)} AND NOT {_IS_CONTAINER} RETURN p LIMIT {limit}"
    )


def children_of(objectids: Iterable[str], kinds: Iterable[str], limit: int) -> str:
    """Objects of `kinds` placed directly in any of the containers."""
    ids = ", ".join(lit(o) for o in sorted(objectids))
    which = " OR ".join(f"n:{k}" for k in kinds)
    return (
        f"MATCH p=(c:Base)-[:{CONTAINS}]->(n:Base) "
        f"WHERE c.objectid IN [{ids}] AND ({which}) RETURN p LIMIT {limit}"
    )


def contained_counts(objectid: str, *, nested: bool) -> str:
    """Scalar rows `parent, kinds, enabled, total`: the direct children of each container, by kind.

    `nested=False` covers the object's own children, `nested=True` those of every container below it.
    """
    if nested:
        match, anchor = f"(o:Base)-[:{CONTAINS}*1..]->(c:Base)-[:{CONTAINS}]->(n:Base)", "o"
    else:
        match, anchor = f"(c:Base)-[:{CONTAINS}]->(n:Base)", "c"
    return (
        f"MATCH {match} WHERE {anchor}.objectid = {lit(objectid)} "
        f"RETURN c.objectid AS parent, labels(n) AS kinds, n.enabled AS enabled, count(n) AS total"
    )


def gp_link_counts(objectid: str) -> str:
    """Scalar rows `parent, total`: the number of GPO links on each container below the object."""
    return (
        f"MATCH (o:Base)-[:{CONTAINS}*1..]->(c:Base)<-[r:{GP_LINK}]-(g:GPO) "
        f"WHERE o.objectid = {lit(objectid)} RETURN c.objectid AS parent, count(g) AS total"
    )


def controllers_outside_t0(objectids: Iterable[str], edges: Iterable[str] | None, limit: int) -> str:
    """Principals outside Tier Zero holding `edges` (any edge when `None`) over any of the objects."""
    ids = ", ".join(lit(o) for o in sorted(objectids))
    return (
        f"MATCH p=(s:Base)-{_rel(edges)}->(t:Base) "
        f"WHERE t.objectid IN [{ids}] AND NOT s:{TIER_ZERO_LABEL} RETURN p LIMIT {limit}"
    )


def policy_groups(template_ids: Iterable[str]) -> str:
    """Groups linked to an issuance policy of the templates (ESC13)."""
    ids = ", ".join(lit(o) for o in sorted(template_ids))
    return (
        f"MATCH p=(t:CertTemplate)-[:{EXTENDED_BY_POLICY}]->(i:IssuancePolicy)-[:{OID_GROUP_LINK}]->(g:Group) "
        f"WHERE t.objectid IN [{ids}] RETURN p"
    )
