"""Cypher query templates.

BH's Cypher endpoint does not accept bound parameters, so every value is
embedded as an escaped string literal via `lit`. Queries return paths or
nodes (not scalars) so that results come back as a graph.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from bhshell.queries.edges import EXEC_EDGES, HAS_SESSION, MEMBER_OF


def lit(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


_RETURN_LIMIT = re.compile(r"\s+RETURN\s+(\w+)\s+LIMIT\s+(\d+)\s*$", re.IGNORECASE)


def limit_of(query: str) -> int | None:
    """The LIMIT of a `... RETURN x LIMIT n` query (`None` for other shapes)."""
    m = _RETURN_LIMIT.search(query)
    return int(m.group(2)) if m else None


def to_count(query: str) -> str | None:
    """Turn `... RETURN x LIMIT n` into `... RETURN count(x)` (`None` for other shapes)."""
    m = _RETURN_LIMIT.search(query)
    return f"{query[:m.start()]} RETURN count({m.group(1)})" if m else None


def where(*conds: str) -> str:
    """` WHERE a AND b` from the non-empty conditions, or ''."""
    present = [c for c in conds if c]
    return f" WHERE {' AND '.join(present)}" if present else ""


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


def by_objectid(objectid: str) -> str:
    return f"MATCH (n:Base) WHERE n.objectid = {lit(objectid)} RETURN n"


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

