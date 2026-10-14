"""Domain-wide weakness checks (`hunt`).

Each `Check` is declarative: a Cypher builder, the columns to display
and a function turning the returned graph into rows.

Checks marked `scoped` also run from a set of principals (`hunt --owned`,
`hunt --from NAME`): the owned objects or the named one, plus every group
they belong to. Their query builders restrict the principal side with
`HuntOptions.scope`, which is empty outside that mode.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from bhshell.errors import ApiError, CypherDisabledError, UnsupportedFeature
from bhshell.models.entities import BROAD_SIDS, OWNED_LABEL, TIER_ZERO_LABEL, Edge, Graph, Node, last_logon
from bhshell.models.results import Column
from bhshell.queries import cypher as Q
from bhshell.queries.adcs import template_escs
from bhshell.queries.domains import TRUSTS_QUERY, trusts_from_graph
from bhshell.queries.edges import (
    ACL_EDGES,
    ADCS_EDGES,
    CA_MANAGE_EDGES,
    COERCION_EDGES,
    CONTROL_EDGES,
    DELEGATION_EDGES,
    ENABLE_EDGES,
    ENROLL_EDGES,
    EXEC_EDGES,
    GPO_EDIT_EDGES,
    HAS_SESSION,
    MEMBER_OF,
    PKI_CONTROL_EDGES,
    PUBLISHED_TO,
    severity_rank,
)
from bhshell.queries.paths import PathService
from bhshell.queries.service import EntityService

Row = dict[str, Any]
HuntSeverity = Literal["critical", "high", "medium", "low", "info"]

LEGACY_OS = ("2000", "2003", "2008", " XP", "VISTA", "WINDOWS 7", "2012", "WINDOWS 8")
# Windows 10 left support in October 2025; the LTSC/LTSB editions are still supported.
WINDOWS_10 = "WINDOWS 10"
LTSC = ("LTSC", "LTSB")
PROTECTED_USERS_RID = "-525"
DCSYNC_EDGES = ("DCSync", "GetChanges", "GetChangesAll")
ERODC_RID = "-498"
ESC8_EDGE = "CoerceAndRelayNTLMToADCS"
ADCS_ABUSE_EDGES = frozenset(k for k in ADCS_EDGES if k.startswith("ADCSESC")) | {"GoldenCert", ESC8_EDGE}
BROAD_RIGHT_EDGES = (CONTROL_EDGES | EXEC_EDGES) - {"Enroll"}
CRED_READ_EDGES = frozenset({"ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword", "DumpSMSAPassword"})
# Control of a Tier Zero object, other than the DCSync, SID history and AD CS edges reported by their own checks.
T0_CONTROL_EDGES = ACL_EDGES | DELEGATION_EDGES | CRED_READ_EDGES | EXEC_EDGES
TAKEOVER = {
    "AddKeyCredentialLink": "Shadow Credentials",
    "WriteSPN": "Targeted Kerberoasting",
    "AddAllowedToAct": "RBCD",
    "WriteAccountRestrictions": "RBCD",
    "WriteAltSecurityIdentities": "ESC14 (explicit certificate mapping)",
}
TAKEOVER_EDGES = frozenset(TAKEOVER)
GPO_CONTROL_EDGES = GPO_EDIT_EDGES | {"WriteGPLink"}
RELAY_EDGES = COERCION_EDGES - {ESC8_EDGE}
# ESC techniques BloodHound has no edge for, found from the template's settings.
TEMPLATE_ONLY_ESCS = ("ESC2", "ESC15")
PKI_KINDS = ("CertTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore", "IssuancePolicy")
FOREIGN_EDGES = ACL_EDGES | EXEC_EDGES | {MEMBER_OF}
# Attributes that may hold a cleartext (or reversibly encoded) password.
PASSWORD_ATTRS = ("userpassword", "unixpassword", "unicodepassword", "sfupassword")
PASSWORD_WORDS = ("pass", "pwd", "pw:", "pw=", "mdp", "contrase", "clave", "kennwort", "senha", "wachtwoord",
                  "losenord", "salasana", "parola", "haslo")
# "(?<!by)": "bypass" is not a password.
_PASSWORD_RE = re.compile("|".join(("(?<!by)" if w == "pass" else "") + re.escape(w) for w in PASSWORD_WORDS),
                          re.IGNORECASE)
# Default descriptions of built-in AD / Exchange groups that mention passwords (found in every domain).
DEFAULT_DESCRIPTIONS = (
    "members in this group can have their passwords replicated to all read-only domain controllers",
    "members in this group cannot have their passwords replicated to any read-only domain controllers",
    "this group contains all the exchange hosted organization mailboxes groups",
)
# Users scanned for a path to Tier Zero (kerberoastable, asreproast): one allShortestPaths query.
PATH_ENRICH_MAX = 500


@dataclass
class HuntOptions:
    domain: str = ""
    days: int = 1825
    limit: int = 5000
    now: float = field(default_factory=time.time)
    # Scoped mode: objectid of each principal checked -> the owned (or --from) objects holding its rights.
    principals: dict[str, list[str]] | None = None
    # Run the extra queries some checks use to enrich their rows (skipped for the summary).
    enrich: bool = True

    @property
    def scoped(self) -> bool:
        return self.principals is not None

    def dom(self, alias: str) -> str:
        """A Cypher condition restricting `alias` to the selected domain ('' = all)."""
        return Q.domain_condition(alias, self.domain)

    def scope(self, alias: str) -> str:
        """A Cypher condition restricting `alias` to the scoped principals ('' outside scoped mode)."""
        if self.principals is None:
            return ""
        return f"{alias}.objectid IN [{', '.join(Q.lit(i) for i in sorted(self.principals))}]"

    def matches(self, domain: str) -> bool:
        """Whether `domain` (an FQDN) is in the selected domain, matched the same way as `dom`."""
        if not self.domain:
            return True
        d, name = self.domain.upper(), domain.upper()
        return name == d or ("." not in d and name.startswith(d + "."))


# Extra queries run after a check, filling in its rows; returns notes for the table.
Enricher = Callable[[EntityService, list["Row"], HuntOptions], list[str]]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: HuntSeverity
    description: str
    query: Callable[[HuntOptions], str]
    columns: tuple[Column, ...]
    rows: Callable[[Graph, HuntOptions], list[Row]]
    fallback: Callable[[HuntOptions], str] | None = None
    # Runs with --owned / --from (the query restricts its principals with `HuntOptions.scope`).
    scoped: bool = False
    # Columns shown instead of `columns` in scoped mode.
    scoped_columns: tuple[Column, ...] | None = None
    # Extra queries filling in the rows: only for details (not the summary).
    enrich: Enricher | None = None
    # Extra queries filtering the rows: always run.
    refine: Enricher | None = None


@dataclass
class Finding:
    check: Check
    rows: list[Row] = field(default_factory=list)
    truncated: bool = False
    error: str = ""
    # Server-side total when the row list was truncated (`None` if the server cannot count it).
    total: int | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"check": self.check.id, "title": self.check.title, "severity": self.check.severity,
                "count": len(self.rows), "total": self.total, "truncated": self.truncated,
                "error": self.error, "notes": self.notes, "rows": self.rows}


def node_row(n: Node, **extra: Any) -> Row:
    return {"name": n.name, "kind": n.kind, "domain": n.domain, "objectid": n.objectid,
            "enabled": n.properties.get("enabled"), "tier_zero": n.tier_zero, "owned": n.owned, **extra}


def edge_row(g: Graph, e: Edge, **extra: Any) -> Row:
    src, tgt = g.nodes[e.source], g.nodes[e.target]
    return {"principal": src.name, "principal_kind": src.kind, "edge": e.kind, "target": tgt.name,
            "target_kind": tgt.kind, "domain": src.domain, "objectid": src.objectid,
            "tier_zero": tgt.tier_zero, "owned": src.owned, **extra}


def enctypes(props: dict[str, Any]) -> str:
    """Kerberos encryption types a user's tickets can use: RC4 hashes crack far faster than AES."""
    raw = props.get("supportedencryptiontypes")
    values = [str(v).upper() for v in (raw if isinstance(raw, list) else [raw] if raw else [])]
    if not values or any("NOT DEFINED" in v for v in values):
        return "default (RC4)"
    if any("RC4" in v for v in values):
        return "RC4"
    if any("DES" in v for v in values):
        return "DES"
    return "AES only"


def _user_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [node_row(n, pwdlastset=n.properties.get("pwdlastset"), lastlogon=last_logon(n.properties),
                     admincount=bool(n.properties.get("admincount")),
                     spns=len(n.properties.get("serviceprincipalnames") or []),
                     enctypes=enctypes(n.properties))
            for n in g.nodes.values()
            if n.kind == "User" and n.samaccountname.lower() != "krbtgt"]
    # Oldest passwords first; unset (0 / missing) passwords last.
    rows.sort(key=lambda r: (not r["tier_zero"], not r["admincount"], (r["pwdlastset"] or 0) <= 0,
                             r["pwdlastset"] or 0))
    return rows


def _computer_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [node_row(n, os=n.properties.get("operatingsystem") or "", lastlogon=last_logon(n.properties))
            for n in g.nodes.values()]
    rows.sort(key=lambda r: (not r["tier_zero"], r["os"], r["name"]))
    return rows


NAME = Column("Name", "name")
DOMAIN = Column("Domain", "domain")
KIND = Column("Type", "kind", "kind")
T0 = Column("T0", "tier_zero", "t0")
OWNED = Column("Owned", "owned", "owned")
PWD = Column("Pwd last set", "pwdlastset", "date")
LOGON = Column("Last logon", "lastlogon", "date")
ADMINCOUNT = Column("AdminCount", "admincount", "bool")
OS = Column("Operating system", "os")
PRINCIPAL = Column("Principal", "principal")
PRINCIPAL_KIND = Column("Type", "principal_kind", "kind")
EDGE = Column("Right", "edge", "edge")
TARGET = Column("Target", "target")
TARGET_KIND = Column("Target type", "target_kind", "kind")
PATH_T0 = Column("Path to T0", "path_to_t0", "risk")
ENCTYPES = Column("Enc types", "enctypes")
FROM_OWNED = Column("From", "from_owned")


def _unconstrained_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [node_row(n, os=n.properties.get("operatingsystem") or "") for n in g.nodes.values()]
    return sorted(rows, key=lambda r: (r["kind"] != "User", r["name"]))


def _constrained(o: HuntOptions) -> str:
    return (f"MATCH p=(n:Base)-[:AllowedToDelegate]->(t:Base){Q.where('n.enabled = true', o.scope('n'), o.dom('n'))} "
            f"RETURN p LIMIT {o.limit}")


def _constrained_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [edge_row(g, e, protocol_transition=bool(g.nodes[e.source].properties.get("trustedtoauth")))
            for e in g.edges if e.kind == "AllowedToDelegate"]
    return sorted(rows, key=lambda r: (not r["tier_zero"], not r["protocol_transition"], r["principal"]))


def _dcsync(o: HuntOptions) -> str:
    return (f"MATCH p=(n:Base)-[:{Q.edge_types(DCSYNC_EDGES)}]->(d:Domain){Q.where(o.scope('n'), o.dom('d'))} "
            f"RETURN p LIMIT {o.limit}")


def _dcsync_rows(g: Graph, _: HuntOptions) -> list[Row]:
    by_principal: dict[tuple[str, str], set[str]] = {}
    for e in g.edges:
        if e.kind in DCSYNC_EDGES and not g.nodes[e.source].tier_zero:
            by_principal.setdefault((e.source, e.target), set()).add(e.kind)
    rows = []
    for (src, dst), rights in by_principal.items():
        if rights == {"GetChanges"} and g.nodes[src].objectid.endswith(ERODC_RID):
            continue
        full = "DCSync" in rights or {"GetChanges", "GetChangesAll"} <= rights
        rows.append(node_row(g.nodes[src], rights=", ".join(sorted(rights)), target=g.nodes[dst].name,
                             full_dcsync=full))
    return sorted(rows, key=lambda r: (not r["full_dcsync"], r["name"]))


def _broad(o: HuntOptions, edges: frozenset[str] | None = BROAD_RIGHT_EDGES) -> str:
    sids = " OR ".join(f"g.objectid ENDS WITH {Q.lit(s)}" for s in BROAD_SIDS)
    rel = f"[r:{Q.edge_types(edges)}]" if edges else "[r]"
    return (f"MATCH p=(g:Base)-{rel}->(t:Base){Q.where(f'({sids})', o.scope('g'), o.dom('g'))} "
            f"RETURN p LIMIT {o.limit}")


def _broad_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [edge_row(g, e) for e in g.edges
            if e.kind in BROAD_RIGHT_EDGES and g.nodes[e.source].objectid.upper().endswith(BROAD_SIDS)]
    return sorted(rows, key=lambda r: (not r["tier_zero"], r["edge"], r["target"]))


def _node_check(label: str, *conditions: str) -> Callable[[HuntOptions], str]:
    def build(o: HuntOptions) -> str:
        return f"MATCH (n:{label}){Q.where(*conditions, o.scope('n'), o.dom('n'))} RETURN n LIMIT {o.limit}"
    return build


def _edge_check(kinds: Iterable[str] | None, *conditions: str, target: str = "Base",
                dom: str = "n") -> Callable[[HuntOptions], str]:
    """`(n)-[kinds]->(t:target)` paths; `kinds=None` matches any relationship (a fallback for unknown kinds)."""
    rel = f"[:{Q.edge_types(kinds)}]" if kinds is not None else "[]"

    def build(o: HuntOptions) -> str:
        return (f"MATCH p=(n:Base)-{rel}->(t:{target}){Q.where(*conditions, o.scope('n'), o.dom(dom))} "
                f"RETURN p LIMIT {o.limit}")
    return build


def _edge_rows(kinds: Iterable[str]) -> Callable[[Graph, HuntOptions], list[Row]]:
    kinds = frozenset(kinds)

    def rows(g: Graph, _: HuntOptions) -> list[Row]:
        out = [edge_row(g, e) for e in g.edges if e.kind in kinds]
        return sorted(out, key=lambda r: (not r["tier_zero"], severity_rank(r["edge"]), r["edge"], r["principal"]))
    return rows


def _stale(o: HuntOptions) -> str:
    cutoff = int(o.now - o.days * 86400)
    where = Q.where("n.enabled = true", "n.pwdneverexpires = true", "n.pwdlastset > 0",
                   f"n.pwdlastset < {cutoff}", o.dom("n"))
    return f"MATCH (n:User){where} RETURN n LIMIT {o.limit}"


def _trusts(_: HuntOptions) -> str:
    return TRUSTS_QUERY


def _trust_rows(g: Graph, o: HuntOptions) -> list[Row]:
    rows = []
    for t in trusts_from_graph(g):
        if not t.issues:
            continue
        if not (o.matches(t.trusting) or o.matches(t.trusted)):
            continue
        rows.append({"trusting": t.trusting, "trusted": t.trusted, "kind": t.kind,
                     "trust_type": t.trust_type, "issues": "; ".join(t.issues)})
    return rows


_NOT_T0 = f"NOT n:{TIER_ZERO_LABEL}"
_LEGACY_OS_CONDITION = "(" + " OR ".join(
    [f"n.operatingsystem CONTAINS {Q.lit(v)}" for v in LEGACY_OS]
    + [f"(n.operatingsystem CONTAINS {Q.lit(WINDOWS_10)} AND "
       + " AND ".join(f"NOT n.operatingsystem CONTAINS {Q.lit(v)}" for v in LTSC) + ")"]) + ")"
_PRIVILEGED_USER = f"(u:{TIER_ZERO_LABEL} OR u.admincount = true)"


# Path to Tier Zero (kerberoastable, asreproast)

def _path_to_t0(entities: EntityService, rows: list[Row], _: HuntOptions) -> list[str]:
    """Mark the users with a path to Tier Zero, and list them first: their hashes are the ones to crack."""
    candidates = [r["objectid"] for r in rows if not r["tier_zero"]]
    if len(candidates) > PATH_ENRICH_MAX:
        return [f"Path to Tier Zero not checked: more than {PATH_ENRICH_MAX} users."]
    try:
        reach, notes = PathService(entities).reaching_tier_zero(candidates)
    except (ApiError, UnsupportedFeature) as exc:
        return [f"Path to Tier Zero not checked: {exc}"]
    for r in rows:
        r["path_to_t0"] = r["tier_zero"] or r["objectid"] in reach
    rows.sort(key=lambda r: (not r["path_to_t0"], r["enctypes"] == "AES only"))  # stable: keeps the age order
    return notes


# Credential exposure

def _t0_sessions(o: HuntOptions) -> str:
    conds = (_PRIVILEGED_USER, f"NOT c:{TIER_ZERO_LABEL}", o.dom("c"))
    if o.scoped:
        return (f"MATCH p=(n:Base)-[:{Q.edge_types(EXEC_EDGES)}]->(c:Computer)-[:{HAS_SESSION}]->(u:User)"
                f"{Q.where(o.scope('n'), *conds)} RETURN p LIMIT {o.limit}")
    return f"MATCH p=(c:Computer)-[:{HAS_SESSION}]->(u:User){Q.where(*conds)} RETURN p LIMIT {o.limit}"


def _t0_session_rows(g: Graph, o: HuntOptions) -> list[Row]:
    sessions: dict[str, list[Node]] = {}
    for e in g.edges:
        if e.kind == HAS_SESSION:
            sessions.setdefault(e.source, []).append(g.nodes[e.target])

    def row(c: Node, u: Node, **extra: Any) -> Row:
        return {"name": c.name, "os": c.properties.get("operatingsystem") or "", "user": u.name,
                "tier_zero": u.tier_zero, "admincount": bool(u.properties.get("admincount")),
                "domain": c.domain, "objectid": c.objectid, **extra}

    if o.scoped:
        rows = [row(g.nodes[e.target], u, access=e.kind, principal=g.nodes[e.source].name,
                    objectid=g.nodes[e.source].objectid)
                for e in g.edges if e.kind in EXEC_EDGES for u in sessions.get(e.target, [])]
    else:
        rows = [row(g.nodes[c], u) for c, users in sessions.items() for u in users]
    return sorted(rows, key=lambda r: (not r["tier_zero"], r["name"], r["user"]))


def _password_attrs(o: HuntOptions, *, lower: bool = True) -> str:
    if lower:
        words = [f"toLower(n.description) CONTAINS {Q.lit(w)}" for w in PASSWORD_WORDS]
    else:  # servers without toLower(): the usual spellings
        variants = dict.fromkeys(v for w in PASSWORD_WORDS for v in (w, w.capitalize(), w.upper()))
        words = [f"n.description CONTAINS {Q.lit(v)}" for v in variants]
    attrs = [f"n.{a} IS NOT NULL" for a in PASSWORD_ATTRS]
    return f"MATCH (n:Base){Q.where('(' + ' OR '.join(attrs + words) + ')', o.dom('n'))} RETURN n LIMIT {o.limit}"


def _password_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = []
    for n in g.nodes.values():
        for attr in PASSWORD_ATTRS:
            value = n.properties.get(attr)
            if value not in (None, "", []):
                rows.append(node_row(n, attribute=attr, value=str(value)))
        description = str(n.properties.get("description") or "")
        if _PASSWORD_RE.search(description) and not description.lower().startswith(DEFAULT_DESCRIPTIONS):
            rows.append(node_row(n, attribute="description", value=description))
    return sorted(rows, key=lambda r: (r["attribute"] == "description", not r["tier_zero"], r["name"]))


# NTLM relay

_NTLM_ISSUES = (
    ("smbsigning", False, "SMB signing not required"),
    ("webclientrunning", True, "WebClient running (HTTP coercion)"),
    ("ldapsigning", False, "LDAP signing not required"),
    ("ldapsepa", False, "LDAPS channel binding not required"),
)


def _ntlm(o: HuntOptions) -> str:
    issues = " OR ".join(f"n.{prop} = {str(bad).lower()}" for prop, bad, _ in _NTLM_ISSUES)
    return f"MATCH (n:Computer){Q.where('n.enabled = true', f'({issues})', o.dom('n'))} RETURN n LIMIT {o.limit}"


def _ntlm_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = []
    for n in g.nodes.values():
        issues = [text for prop, bad, text in _NTLM_ISSUES if n.properties.get(prop) is bad]
        rows.append(node_row(n, os=n.properties.get("operatingsystem") or "", issues="; ".join(issues)))
    return sorted(rows, key=lambda r: (not r["tier_zero"], r["name"]))


# Object takeover

def _takeover_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [edge_row(g, e, technique=TAKEOVER[e.kind],
                     admincount=bool(g.nodes[e.target].properties.get("admincount")))
            for e in g.edges if e.kind in TAKEOVER]
    return sorted(rows, key=lambda r: (not r["admincount"], r["technique"], r["target"], r["principal"]))


def _reenable_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [edge_row(g, e, admincount=bool(g.nodes[e.target].properties.get("admincount")))
            for e in g.edges if e.kind in ENABLE_EDGES]
    return sorted(rows, key=lambda r: (not r["tier_zero"], r["target"], severity_rank(r["edge"])))


def _foreign_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [edge_row(g, e, target_domain=g.nodes[e.target].domain)
            for e in g.edges if e.kind in FOREIGN_EDGES and g.nodes[e.source].domain != g.nodes[e.target].domain]
    return sorted(rows, key=lambda r: (not r["tier_zero"], r["edge"] == MEMBER_OF, r["principal"]))


# AD CS

def _templates(o: HuntOptions) -> str:
    return (f"MATCH p=(n:Base)-[:{Q.edge_types(ENROLL_EDGES)}]->(t:CertTemplate)-[:{PUBLISHED_TO}]->(ca:EnterpriseCA)"
            f"{Q.where(_NOT_T0, 't.requiresmanagerapproval = false', o.scope('n'), o.dom('t'))} "
            f"RETURN p LIMIT {o.limit}")


def _template_rows(g: Graph, _: HuntOptions) -> list[Row]:
    cas: dict[str, list[str]] = {}
    for e in g.edges:
        if e.kind == PUBLISHED_TO:
            cas.setdefault(e.source, []).append(g.nodes[e.target].name)
    rows = []
    for e in g.edges:
        if e.kind not in ENROLL_EDGES or g.nodes[e.target].kind != "CertTemplate":
            continue
        escs = [esc for esc in template_escs(g.nodes[e.target].properties) if esc in TEMPLATE_ONLY_ESCS]
        if escs:
            rows.append(edge_row(g, e, escs=", ".join(escs), cas=", ".join(sorted(cas.get(e.target, [])))))
    return sorted(rows, key=lambda r: (r["target"], r["principal"], r["edge"]))


def _pki_rows(g: Graph, _: HuntOptions) -> list[Row]:
    rows = [edge_row(g, e, technique="ESC4" if g.nodes[e.target].kind == "CertTemplate" else "ESC5")
            for e in g.edges if e.kind in PKI_CONTROL_EDGES and g.nodes[e.target].kind in PKI_KINDS]
    return sorted(rows, key=lambda r: (r["technique"], severity_rank(r["edge"]), r["target"], r["principal"]))


_PKI_TARGET = "(" + " OR ".join(f"t:{k}" for k in PKI_KINDS) + ")"


# OPSEC

def _decoys(o: HuntOptions) -> str:
    never = ("(n.lastlogon IS NULL OR n.lastlogon <= 0)",
             "(n.lastlogontimestamp IS NULL OR n.lastlogontimestamp <= 0)")
    lure = "(n.hasspn = true OR n.dontreqpreauth = true OR n.admincount = true)"
    where = Q.where("n.enabled = true", lure, *never, "n.samaccountname <> 'krbtgt'", o.dom("n"))
    return f"MATCH (n:User){where} RETURN n LIMIT {o.limit}"


def _decoy_rows(g: Graph, o: HuntOptions) -> list[Row]:
    rows = _user_rows(g, o)
    for r, n in zip(rows, (g.find(r["objectid"]) for r in rows), strict=True):
        props = n.properties if n else {}
        lures = [label for prop, label in (("hasspn", "SPN"), ("dontreqpreauth", "no preauth"),
                                           ("admincount", "adminCount")) if props.get(prop)]
        r.update(lures=", ".join(lures), created=props.get("whencreated"))
    return rows


def _drop_protected_users(entities: EntityService, rows: list[Row], o: HuntOptions) -> list[str]:
    """Drop members of Protected Users: their tickets cannot be delegated either."""
    query = (f"MATCH p=(m:User)-[:{MEMBER_OF}*1..]->(g:Group) "
             f"WHERE g.objectid ENDS WITH {Q.lit(PROTECTED_USERS_RID)} RETURN p")
    try:
        members = entities.run_cypher(query)
    except ApiError as exc:
        return [f"Protected Users members not excluded: {exc}"]
    protected = {n.objectid for n in members.nodes.values() if n.kind == "User"}
    kept = [r for r in rows if r["objectid"] not in protected]
    dropped = len(rows) - len(kept)
    rows[:] = kept
    return [f"{dropped} Protected Users member(s) left out."] if dropped else []


CHECKS: tuple[Check, ...] = (
    Check("dcsync", "Non-Tier-Zero principals with replication rights", "critical",
          "DCSync / GetChanges(All) on a domain held by principals outside Tier Zero.",
          _dcsync, (NAME, KIND, Column("Rights", "rights"), Column("Domain", "target"),
                    Column("Full DCSync", "full_dcsync", "risk"), OWNED), _dcsync_rows, scoped=True),
    Check("tier-zero-control", "Control of Tier Zero from outside it", "critical",
          "Non-Tier-Zero principals with ACL, delegation, credential-read or execution rights on Tier Zero "
          "objects (DCSync, SID history and AD CS have their own checks).",
          _edge_check(T0_CONTROL_EDGES, _NOT_T0, target=TIER_ZERO_LABEL, dom="t"),
          (PRINCIPAL, PRINCIPAL_KIND, EDGE, TARGET, TARGET_KIND, OWNED), _edge_rows(T0_CONTROL_EDGES),
          fallback=_edge_check(None, _NOT_T0, target=TIER_ZERO_LABEL, dom="t"), scoped=True),
    Check("broad-rights", "Dangerous rights held by broad groups", "critical",
          "Everyone / Anonymous / Authenticated Users / Domain Users / Domain Computers / Users / "
          "Pre-Windows 2000 Compatible Access holding control or execution rights.",
          _broad, (PRINCIPAL, EDGE, TARGET, TARGET_KIND, T0), _broad_rows,
          fallback=lambda o: _broad(o, None), scoped=True),
    Check("adcs", "AD CS escalation paths (ESC*, GoldenCert)", "critical",
          "Principals with a certificate-services escalation edge, including NTLM relay to web enrollment (ESC8). "
          "'ca NAME' and 'template NAME' show the CA and template behind a finding.",
          _edge_check(ADCS_ABUSE_EDGES), (PRINCIPAL, PRINCIPAL_KIND, EDGE, TARGET, T0),
          _edge_rows(ADCS_ABUSE_EDGES), scoped=True),
    Check("adcs-templates", "Certificate templates open to ESC2 / ESC15", "high",
          "Published templates that principals outside Tier Zero can enroll in, issued without approval, with "
          "any purpose or no EKU (ESC2) or schema version 1 and an enrollee-supplied subject (ESC15, unless "
          "the CA has the November 2024 update). BloodHound has no edge for these; enrollment rights on the "
          "CA are not checked. 'template NAME' shows the rest.",
          _templates, (PRINCIPAL, PRINCIPAL_KIND, EDGE, Column("Template", "target"), Column("ESC", "escs"),
                       Column("Published to", "cas"), OWNED), _template_rows, scoped=True),
    Check("adcs-pki-control", "Control of certificate templates and PKI objects (ESC4 / ESC5)", "high",
          "Principals outside Tier Zero that can rewrite a certificate template (ESC4) or a CA, root CA, AIA "
          "CA, NTAuth store or issuance policy object (ESC5).",
          _edge_check(PKI_CONTROL_EDGES, _NOT_T0, _PKI_TARGET, dom="t"),
          (PRINCIPAL, PRINCIPAL_KIND, EDGE, Column("Technique", "technique"), TARGET, TARGET_KIND, OWNED),
          _pki_rows, fallback=_edge_check(None, _NOT_T0, _PKI_TARGET, dom="t"), scoped=True),
    Check("adcs-ca-control", "Enterprise CA managed from outside Tier Zero (ESC7)", "high",
          "ManageCA / ManageCertificates on an Enterprise CA held by principals outside Tier Zero.",
          _edge_check(CA_MANAGE_EDGES, _NOT_T0, target="EnterpriseCA", dom="t"),
          (PRINCIPAL, PRINCIPAL_KIND, EDGE, TARGET, OWNED), _edge_rows(CA_MANAGE_EDGES), scoped=True),
    Check("kerberoastable", "Kerberoastable users", "high",
          "Enabled users with an SPN (excluding krbtgt); those with a path to Tier Zero first, then RC4, "
          "then the oldest passwords.",
          _node_check("User", "n.hasspn = true", "n.enabled = true"),
          (NAME, DOMAIN, PWD, ADMINCOUNT, Column("SPNs", "spns"), ENCTYPES, PATH_T0, T0, OWNED), _user_rows,
          enrich=_path_to_t0),
    Check("asreproast", "AS-REP roastable users", "high",
          "Enabled users without Kerberos pre-authentication; those with a path to Tier Zero first.",
          _node_check("User", "n.dontreqpreauth = true", "n.enabled = true"),
          (NAME, DOMAIN, PWD, ADMINCOUNT, ENCTYPES, PATH_T0, T0, OWNED), _user_rows, enrich=_path_to_t0),
    Check("t0-sessions", "Privileged sessions on non-Tier-Zero computers", "high",
          "Tier Zero or adminCount users logged on to computers outside Tier Zero (credential dumping "
          "targets). Scoped: those computers where the principals can execute code.",
          _t0_sessions, (NAME, OS, Column("Session user", "user"), T0, ADMINCOUNT), _t0_session_rows,
          scoped=True, scoped_columns=(NAME, OS, Column("Session user", "user"), T0, ADMINCOUNT,
                                       Column("Access", "access", "edge"), PRINCIPAL)),
    Check("cred-readers", "Readable LAPS / gMSA / sMSA passwords", "high",
          "Principals outside Tier Zero that can read LAPS, gMSA or sMSA passwords.",
          _edge_check(CRED_READ_EDGES, _NOT_T0), (PRINCIPAL, PRINCIPAL_KIND, EDGE, TARGET, TARGET_KIND, T0),
          _edge_rows(CRED_READ_EDGES), scoped=True),
    Check("passwords-in-attributes", "Passwords in AD attributes", "high",
          "Objects with userPassword / unixUserPassword / unicodePwd / msSFU30Password set, or a description "
          "mentioning a password.",
          _password_attrs, (NAME, KIND, DOMAIN, Column("Attribute", "attribute"), Column("Value", "value"), T0,
                            OWNED), _password_rows, fallback=lambda o: _password_attrs(o, lower=False)),
    Check("object-takeover", "Account and computer takeover primitives", "high",
          "Shadow Credentials (AddKeyCredentialLink), targeted Kerberoasting (WriteSPN), RBCD "
          "(AddAllowedToAct, WriteAccountRestrictions) and explicit certificate mappings "
          "(WriteAltSecurityIdentities, ESC14) between non-Tier-Zero objects.",
          _edge_check(TAKEOVER_EDGES, _NOT_T0, f"NOT t:{TIER_ZERO_LABEL}", "t.enabled = true"),
          (PRINCIPAL, PRINCIPAL_KIND, EDGE, Column("Technique", "technique"), TARGET, TARGET_KIND,
           Column("Target adminCount", "admincount", "bool")), _takeover_rows, scoped=True),
    Check("gpo-control", "GPO and OU link control", "high",
          "Principals outside Tier Zero that can edit a GPO or link GPOs to an OU (code execution on every "
          "computer below it). 'gpo NAME' shows what a GPO applies to.",
          _edge_check(GPO_CONTROL_EDGES, _NOT_T0, "(t:GPO OR t:OU)"),
          (PRINCIPAL, PRINCIPAL_KIND, EDGE, TARGET, TARGET_KIND, T0), _edge_rows(GPO_CONTROL_EDGES),
          fallback=_edge_check(None, _NOT_T0, "(t:GPO OR t:OU)"), scoped=True),
    Check("relay", "NTLM coercion and relay", "high",
          "CoerceAndRelayNTLMTo SMB / LDAP / LDAPS edges (relay to AD CS is in 'adcs').",
          _edge_check(RELAY_EDGES, dom="t"), (PRINCIPAL, EDGE, TARGET, TARGET_KIND, T0), _edge_rows(RELAY_EDGES)),
    Check("foreign-access", "Cross-domain memberships and rights", "high",
          "Non-Tier-Zero principals with membership, control or execution rights in another domain.",
          _edge_check(FOREIGN_EDGES, _NOT_T0, "n.domain <> t.domain", dom="t"),
          (PRINCIPAL, PRINCIPAL_KIND, DOMAIN, EDGE, TARGET, Column("Target domain", "target_domain"), T0),
          _foreign_rows, scoped=True),
    Check("unconstrained", "Unconstrained delegation outside Tier Zero", "high",
          "Enabled users/computers trusted for unconstrained delegation (DCs excluded).",
          _node_check("Base", "n.unconstraineddelegation = true", "n.enabled = true", _NOT_T0),
          (NAME, KIND, DOMAIN, OS, OWNED), _unconstrained_rows, scoped=True),
    Check("sidhistory", "SID history", "high",
          "Principals carrying the SID of another object (HasSIDHistory).",
          _edge_check(("HasSIDHistory",)), (PRINCIPAL, PRINCIPAL_KIND, TARGET, TARGET_KIND, T0),
          _edge_rows(("HasSIDHistory",)), scoped=True),
    Check("trust-sid-filtering", "Trusts with SID filtering disabled or abusable", "high",
          "Same-forest trusts (no SID filtering by default), cross-forest trusts with SID filtering "
          "explicitly disabled, or trusts with SpoofSIDHistory / AbuseTGTDelegation edges.",
          _trusts, (Column("Trusting", "trusting"), Column("Trusted", "trusted"), Column("Kind", "kind"),
                    Column("Type", "trust_type"), Column("Issues", "issues")), _trust_rows),
    Check("constrained", "Constrained delegation", "medium",
          "AllowedToDelegate edges; protocol transition (trustedtoauth) needs no victim interaction.",
          _constrained, (PRINCIPAL, PRINCIPAL_KIND, TARGET, Column("Protocol transition", "protocol_transition",
                                                                     "risk"), T0), _constrained_rows, scoped=True),
    Check("reenable", "Disabled privileged accounts that can be re-enabled", "medium",
          "Disabled Tier Zero or adminCount users on which principals outside Tier Zero hold a right to "
          "re-enable them.",
          _edge_check(ENABLE_EDGES, _NOT_T0, "t.enabled = false", f"(t:{TIER_ZERO_LABEL} OR t.admincount = true)",
                      target="User", dom="t"),
          (PRINCIPAL, PRINCIPAL_KIND, EDGE, TARGET, T0, Column("Target adminCount", "admincount", "bool")),
          _reenable_rows, scoped=True),
    Check("impersonable-admins", "Tier Zero users open to delegation", "medium",
          "Enabled Tier Zero users not marked sensitive and not in Protected Users: constrained delegation, "
          "RBCD and S4U can impersonate them.",
          _node_check("User", f"n:{TIER_ZERO_LABEL}", "n.enabled = true",
                      "(n.sensitive IS NULL OR n.sensitive = false)"),
          (NAME, DOMAIN, PWD, LOGON, ADMINCOUNT), _user_rows, refine=_drop_protected_users),
    Check("ntlm-hardening", "Missing NTLM relay protections", "medium",
          "Enabled computers without SMB signing, running WebClient, or DCs not requiring LDAP signing or "
          "LDAPS channel binding.",
          _ntlm, (NAME, DOMAIN, OS, Column("Issues", "issues"), T0), _ntlm_rows),
    Check("stale-passwords", "Old passwords that never expire", "medium",
          "Enabled users with pwdneverexpires and a password older than --days (default 5 years).",
          _stale, (NAME, DOMAIN, PWD, LOGON, ADMINCOUNT, T0), _user_rows),
    Check("pwd-not-required", "Password not required", "medium",
          "Enabled users with PASSWD_NOTREQD (may have an empty password).",
          _node_check("User", "n.passwordnotreqd = true", "n.enabled = true"),
          (NAME, DOMAIN, PWD, LOGON, T0), _user_rows),
    Check("legacy-os", "End-of-life operating systems", "medium",
          "Enabled computers running Windows 2000/2003/2008/2012, XP, Vista, 7, 8 or 10 (except LTSC).",
          _node_check("Computer", "n.enabled = true", _LEGACY_OS_CONDITION),
          (NAME, DOMAIN, OS, LOGON, T0), _computer_rows),
    Check("admincount-orphans", "AdminCount users outside Tier Zero", "low",
          "adminCount=1 users no longer in a protected group (stale ACLs, AdminSDHolder leftovers).",
          _node_check("User", "n.admincount = true", _NOT_T0),
          (NAME, DOMAIN, PWD, LOGON), _user_rows),
    Check("no-laps", "Computers without LAPS", "low",
          "Enabled non-Tier-Zero computers without LAPS (shared local admin passwords likely).",
          _node_check("Computer", "n.enabled = true", "n.haslaps = false", _NOT_T0),
          (NAME, DOMAIN, OS, LOGON), _computer_rows),
    Check("decoys", "Possible honeytokens", "info",
          "Enabled users that look attractive (SPN, no pre-authentication or adminCount) but have never "
          "logged on: check before roasting or using them.",
          _decoys, (NAME, DOMAIN, Column("Lures", "lures"), Column("Created", "created", "date"), PWD, T0),
          _decoy_rows),
)
CHECKS_BY_ID: dict[str, Check] = {c.id: c for c in CHECKS}
SCOPED_CHECKS: tuple[Check, ...] = tuple(c for c in CHECKS if c.scoped)


class HuntService:
    def __init__(self, entities: EntityService) -> None:
        self.entities = entities

    def run(self, check: Check, opts: HuntOptions) -> Finding:
        if opts.scoped and not check.scoped:
            raise UnsupportedFeature(f"'{check.id}' does not run with --owned / --from")
        try:
            graph = self._query(check, opts)
        except CypherDisabledError as exc:
            raise UnsupportedFeature("'hunt' needs the Cypher endpoint") from exc
        except ApiError as exc:
            return Finding(check, error=exc.message)
        truncated, total = self.entities.truncation(graph)
        finding = Finding(check, rows=check.rows(graph, opts), truncated=truncated, total=total)
        if check.refine and finding.rows:
            finding.notes += check.refine(self.entities, finding.rows, opts)
        if check.enrich and opts.enrich and finding.rows:
            finding.notes += check.enrich(self.entities, finding.rows, opts)
        if opts.principals is not None:
            for row in finding.rows:
                row["from_owned"] = ", ".join(opts.principals.get(row.get("objectid", ""), []))
        return finding

    def _query(self, check: Check, opts: HuntOptions) -> Graph:
        try:
            return self.entities.run_cypher(check.query(opts))
        except ApiError:
            if check.fallback is None:
                raise
            return self.entities.run_cypher(check.fallback(opts))

    def owned_scope(self) -> dict[str, list[str]]:
        """Owned objects and the groups they belong to, each mapped to the owned objects behind it."""
        owned = self._cypher(f"MATCH (n:{OWNED_LABEL}) RETURN n")
        memberships = self._cypher(f"MATCH p=(n:{OWNED_LABEL})-[:{MEMBER_OF}*1..]->(g:Group) RETURN p")
        return _scope(owned.nodes.values(), memberships)

    def principal_scope(self, node: Node) -> dict[str, list[str]]:
        """`node` and the groups it belongs to, each mapped to `node`."""
        return _scope([node], self._cypher(Q.member_of(node.objectid)))

    def _cypher(self, query: str) -> Graph:
        try:
            return self.entities.run_cypher(query)
        except CypherDisabledError as exc:
            raise UnsupportedFeature("'hunt' needs the Cypher endpoint") from exc


def _scope(starts: Iterable[Node], memberships: Graph) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for e in memberships.edges:
        if e.kind == MEMBER_OF:
            groups.setdefault(e.source, []).append(e.target)
    by_objectid = {n.objectid: nid for nid, n in memberships.nodes.items()}
    scope: dict[str, list[str]] = {}
    for start in starts:
        scope.setdefault(start.objectid, []).append(start.name)
        seen: set[str] = set()
        todo = [by_objectid[start.objectid]] if start.objectid in by_objectid else []
        while todo:
            for group in groups.get(todo.pop(), []):
                if group not in seen:
                    seen.add(group)
                    todo.append(group)
                    scope.setdefault(memberships.nodes[group].objectid, []).append(start.name)
    return scope
