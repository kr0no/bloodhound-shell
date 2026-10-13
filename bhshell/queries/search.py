"""Attribute search (`search`): find objects whose properties match a set of filters.

A filter is `ATTR OP VALUE` (`hasspn=true`, `name~svc`, `pwdlastset<2020-01-01`), a bare
`ATTR` (true) or `!ATTR` (false or missing). Filters are ANDed and compiled to one
`MATCH (n:Kind) WHERE ... RETURN n LIMIT n` query; every value is embedded via `Q.lit`
and attribute names are restricted to identifiers, so nothing typed reaches the query unescaped.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from bhshell.errors import BHError, CypherDisabledError, UnsupportedFeature
from bhshell.models.entities import Graph, Node
from bhshell.models.results import Column
from bhshell.queries import cypher as Q
from bhshell.queries.service import EntityService

Value = str | int | float | bool | None

# Longest operators first, so `>=` is not read as `>` followed by `=VALUE`.
OPERATORS = ("!=", ">=", "<=", "!~", "=", "~", ">", "<")
_FILTER_RE = re.compile(rf"^(?P<neg>!?)(?P<attr>[A-Za-z_][A-Za-z0-9_]*)"
                        rf"(?:(?P<op>{'|'.join(map(re.escape, OPERATORS))})(?P<value>.*))?$", re.DOTALL)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DAYS_AGO_RE = re.compile(r"^(\d+)d$", re.IGNORECASE)
_NUMBER_RE = re.compile(r"^-?\d+(\.\d+)?$")

# Properties BloodHound stores as epoch seconds.
DATE_PROPS = frozenset({"pwdlastset", "lastlogon", "lastlogontimestamp", "whencreated", "lastseen", "lastcollected"})
# Common properties, offered for tab completion.
COMMON_PROPS = (
    "name", "samaccountname", "displayname", "description", "email", "domain", "objectid", "distinguishedname",
    "enabled", "admincount", "hasspn", "dontreqpreauth", "passwordnotreqd", "pwdneverexpires",
    "unconstraineddelegation", "trustedtoauth", "sensitive", "pwdlastset", "lastlogon", "lastlogontimestamp",
    "whencreated", "operatingsystem", "haslaps", "isdc", "title", "homedirectory", "userpassword",
)
# Attributes already shown by the base columns.
_BASE_ATTRS = frozenset({"name", "kind", "domain", "objectid", "enabled"})


@dataclass(frozen=True)
class Filter:
    attr: str
    op: str
    value: Value


def _parse_value(raw: str, op: str, now: float) -> Value:
    if raw.lower() == "null":
        return None
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    if _NUMBER_RE.match(raw):
        return float(raw) if "." in raw else int(raw)
    if op in (">", "<", ">=", "<="):
        if _DATE_RE.match(raw):
            try:
                return int(datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=UTC).timestamp())
            except ValueError as exc:
                raise BHError(f"Invalid date '{raw}' (use YYYY-MM-DD)") from exc
        if m := _DAYS_AGO_RE.match(raw):
            return int(now - int(m.group(1)) * 86400)
        raise BHError(f"'{op}' needs a number, a date (YYYY-MM-DD) or an age (90d), not '{raw}'")
    return raw


def parse_filter(text: str, now: float | None = None) -> Filter:
    """Parse one filter token: `ATTR`, `!ATTR` or `ATTR OP VALUE`."""
    m = _FILTER_RE.match(text.strip())
    if not m:
        raise BHError(f"Invalid filter '{text}' (expected ATTR, !ATTR or ATTR OP VALUE with OP one of "
                        f"{' '.join(OPERATORS)})")
    attr, op = m.group("attr").lower(), m.group("op")
    if op is None:
        return Filter(attr, "!=" if m.group("neg") else "=", True)
    if m.group("neg"):
        raise BHError(f"Invalid filter '{text}': '!' only negates a bare attribute (!{attr})")
    value = _parse_value(m.group("value"), op, time.time() if now is None else now)
    if value is None and op not in ("=", "!="):
        raise BHError(f"Invalid filter '{text}': null only works with = and !=")
    if isinstance(value, bool) and op not in ("=", "!="):
        raise BHError(f"Invalid filter '{text}': true/false only work with = and !=")
    if op in ("~", "!~") and not isinstance(value, str):
        value = str(m.group("value"))
    return Filter(attr, op, value)


def _glob(prop: str, pattern: str) -> str:
    """Case-insensitive match of a string property against `pattern` (`*` at either end only)."""
    body = pattern.strip("*")
    if "*" in body:
        raise BHError(f"'*' is only supported at the start or end of a value ('{pattern}'); use 'cypher'")
    lowered, value = f"toLower({prop})", Q.lit(body.lower())
    starts, ends = pattern.startswith("*"), pattern.endswith("*") and len(pattern) > 1
    if starts and ends:
        return f"{lowered} CONTAINS {value}"
    if starts:
        return f"{lowered} ENDS WITH {value}"
    if ends:
        return f"{lowered} STARTS WITH {value}"
    return f"{lowered} = {value}"


def condition(f: Filter, alias: str = "n") -> str:
    prop = f"{alias}.{f.attr}"
    if f.value is None:
        return f"{prop} IS {'NOT ' if f.op == '!=' else ''}NULL"
    if isinstance(f.value, bool):
        if f.op == "=":
            return f"{prop} = {str(f.value).lower()}"
        # Missing counts as "not this value": '!enabled' also finds objects without the property.
        return f"({prop} = {str(not f.value).lower()} OR {prop} IS NULL)"
    if f.op in ("~", "!~"):
        cond = f"toLower({prop}) CONTAINS {Q.lit(str(f.value).lower())}"
        return cond if f.op == "~" else f"NOT ({cond})"
    if isinstance(f.value, (int, float)):
        if f.op == "=":  # numeric-looking strings ('samaccountname=1234') are stored as text
            return f"({prop} = {f.value} OR {prop} = {Q.lit(str(f.value))})"
        if f.op == "!=":
            return f"({prop} <> {f.value} AND {prop} <> {Q.lit(str(f.value))})"
        return f"{prop} {f.op} {f.value}"
    cond = _glob(prop, f.value)
    return cond if f.op == "=" else f"NOT ({cond})"


@dataclass
class SearchOptions:
    filters: list[Filter] = field(default_factory=list)
    kind: str | None = None
    domain: str = ""
    limit: int = 5000

    def query(self) -> str:
        conds = [condition(f) for f in self.filters]
        label = f":{self.kind}" if self.kind else ":Base"
        return f"MATCH (n{label}){Q.where(*conds, Q.domain_condition('n', self.domain))} RETURN n LIMIT {self.limit}"

    def extra_attrs(self, columns: Iterable[str] = ()) -> list[str]:
        """Attributes shown after the base columns: the filtered ones, then `columns`."""
        attrs = [f.attr for f in self.filters] + [c.lower() for c in columns]
        return [a for a in dict.fromkeys(attrs) if a not in _BASE_ATTRS]


@dataclass
class SearchResult:
    query: str
    nodes: list[Node]
    attrs: list[str]
    truncated: bool = False
    total: int | None = None

    @property
    def columns(self) -> list[Column]:
        cols = [Column("Type", "kind", "kind"), Column("Name", "name"), Column("Domain", "domain"),
                Column("Enabled", "enabled", "bool")]
        cols += [Column(a, a, self._fmt(a)) for a in self.attrs]
        return [*cols, Column("T0", "tier_zero", "t0"), Column("Owned", "owned", "owned")]

    def _fmt(self, attr: str) -> str:
        if attr in DATE_PROPS:
            return "date"
        values = [n.properties[attr] for n in self.nodes if n.properties.get(attr) is not None]
        return "bool" if values and all(isinstance(v, bool) for v in values) else ""

    def rows(self) -> list[dict[str, Any]]:
        return [{"kind": n.kind, "name": n.name, "domain": n.domain, "objectid": n.objectid,
                 "enabled": n.properties.get("enabled"), "tier_zero": n.tier_zero, "owned": n.owned,
                 **{a: n.properties.get(a) for a in self.attrs}} for n in self.nodes]

    def as_dict(self) -> dict[str, Any]:
        return {"query": self.query, "count": len(self.nodes), "total": self.total, "truncated": self.truncated,
                "results": [n.as_dict() for n in self.nodes]}


def _sorted(graph: Graph) -> list[Node]:
    return sorted(graph.nodes.values(), key=lambda n: (n.kind, n.name))


class SearchService:
    def __init__(self, entities: EntityService) -> None:
        self.entities = entities

    def search(self, opts: SearchOptions, columns: Iterable[str] = ()) -> SearchResult:
        query = opts.query()
        try:
            graph = self.entities.run_cypher(query)
        except CypherDisabledError as exc:
            raise UnsupportedFeature("'search' needs the Cypher endpoint") from exc
        truncated, total = self.entities.truncation(graph)
        return SearchResult(query, _sorted(graph), opts.extra_attrs(columns), truncated, total)
