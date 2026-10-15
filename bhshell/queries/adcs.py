"""AD CS views: what a certificate template allows and what an Enterprise CA issues.

BloodHound only adds an ESC edge (ADCSESC1, ADCSESC3, ...) when the whole chain holds: a published
template the principal can enroll in, a CA it can enroll on, trusted for NT authentication. Here the
template conditions are read on their own, including those of the techniques BloodHound has no
edge for (ESC2, ESC15), so a template shows what it allows before every other condition is met.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from bhshell.models.entities import Graph, Node, Risk, SummaryField, effective_ekus, opt_bool
from bhshell.models.results import Column, TemplateRow, ViewResult
from bhshell.queries import cypher as Q
from bhshell.queries.containers import rest_unavailable
from bhshell.queries.edges import (
    CA_MANAGE_EDGES,
    ENROLL_EDGES,
    ENROLL_ON_BEHALF_OF,
    EXTENDED_BY_POLICY,
    HOSTS_CA_SERVICE,
    ISSUED_SIGNED_BY,
    OID_GROUP_LINK,
    PKI_CONTROL_EDGES,
    PUBLISHED_TO,
    TRUSTED_FOR_NTAUTH,
)

if TYPE_CHECKING:
    from bhshell.queries.service import EntityService

ANY_PURPOSE = "2.5.29.37.0"
REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
# EKUs that let a certificate log on (Kerberos PKINIT or Schannel): Client Authentication, PKINIT
# Client Authentication, Smart Card Logon and Any Purpose. A certificate with no EKU can too.
AUTH_EKUS = frozenset({"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2", ANY_PURPOSE})

ESC_LABELS = {
    "ESC1": "ESC1: enrollee supplies the subject",
    "ESC2": "ESC2: any purpose or no EKU",
    "ESC3": "ESC3: enrollment agent template",
    "ESC4": "ESC4: writable from outside Tier Zero",
    "ESC9": "ESC9: no security extension",
    "ESC13": "ESC13: issuance policy linked to a group",
    "ESC15": "ESC15: schema version 1, enrollee supplies the subject",
}
TEMPLATE_CAVEAT = ("ESC conditions cover the template only: the principal must also be able to enroll on the CA, "
                   "and logon certificates need a CA trusted for NT authentication.")

FLAGS = [Column("T0", "tier_zero", "t0"), Column("Owned", "owned", "owned")]
TEMPLATE_COLS = [
    Column("Template", "name"), Column("Schema", "schema_version"), Column("Auth", "authentication", "bool"),
    Column("Enrollee supplies subject", "enrollee_supplies_subject", "bool"),
    Column("Manager approval", "manager_approval", "bool"), Column("Signatures", "signatures"),
    Column("ESC conditions", "escs"), Column("Enrollable by (non-T0)", "enrollable_by"), *FLAGS,
]


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def issued_freely(props: dict[str, Any]) -> bool:
    """Issued without a manager's approval or an enrollment agent's signature (ignored on schema version 1)."""
    if props.get("requiresmanagerapproval") is not False:
        return False
    return _int(props.get("schemaversion")) == 1 or _int(props.get("authorizedsignatures")) == 0


def can_authenticate(props: dict[str, Any]) -> bool | None:
    """Whether the template's certificates can log on (`None` when not collected)."""
    auth = opt_bool(props, "authenticationenabled")
    ekus = effective_ekus(props)
    if auth is None and ekus is not None:
        auth = not ekus or bool(AUTH_EKUS & set(ekus))
    return auth


def template_escs(props: dict[str, Any]) -> list[str]:
    """The ESC techniques whose template conditions are met (ESC4 and ESC13 need edges: not checked here).

    Every one needs a certificate that is issued freely. Unknown settings never count.
    """
    if not issued_freely(props):
        return []
    schema = _int(props.get("schemaversion"))
    ekus = effective_ekus(props)
    auth = can_authenticate(props)
    supplies = props.get("enrolleesuppliessubject") is True
    found = []
    if auth and supplies:
        found.append("ESC1")
    if ekus is not None and (not ekus or ANY_PURPOSE in ekus):
        found.append("ESC2")
    if ekus is not None and REQUEST_AGENT in ekus:
        found.append("ESC3")
    if auth and props.get("nosecurityextension") is True:
        found.append("ESC9")
    if schema == 1 and supplies:
        found.append("ESC15")
    return found


def _names(label: str, names: list[str] | None, empty: str, risk: Risk = "none") -> SummaryField:
    return SummaryField(label, names, "list", risk) if names else SummaryField(label, empty)


class ADCSService:
    """Summaries of certificate templates and Enterprise CAs, and the CA's `templates` view."""

    def __init__(self, entities: EntityService) -> None:
        self.entities = entities

    def _linked(self, objectid: str, edge: str, *, incoming: bool = False) -> list[Node]:
        """The objects at the other end of the object's `edge` relationships, by name."""
        limit = self.entities.max_results
        query = Q.incoming(objectid, {edge}, limit) if incoming else Q.outgoing_direct(objectid, limit, {edge})
        g = self.entities.run_cypher(query)
        me = g.find(objectid)
        if not me:
            return []
        if incoming:
            ends = [g.nodes[e.source] for e in g.edges_to([me.id], {edge})]
        else:
            ends = [g.nodes[e.target] for e in g.edges_from([me.id], {edge})]
        return sorted({n.objectid: n for n in ends}.values(), key=lambda n: n.name)

    def _policy_groups(self, template_ids: set[str]) -> dict[str, list[str]]:
        """Groups linked to an issuance policy of each template (ESC13), by template objectid."""
        g = self.entities.run_cypher(Q.policy_groups(template_ids))
        groups: dict[str, list[str]] = {}
        for e in g.edges:
            if e.kind == OID_GROUP_LINK and e.target in g.nodes:
                groups.setdefault(e.source, []).append(g.nodes[e.target].name)
        out: dict[str, set[str]] = {}
        for e in g.edges:
            if e.kind == EXTENDED_BY_POLICY and e.source in g.nodes:
                out.setdefault(g.nodes[e.source].objectid, set()).update(groups.get(e.target, []))
        return {oid: sorted(names) for oid, names in out.items() if names}

    def _escs(self, templates: list[Node]) -> dict[str, list[tuple[str, str]]]:
        """`(technique, label)` of each ESC condition the templates meet, by template objectid."""
        if not templates:
            return {}
        ids = {t.objectid for t in templates}
        writers, _ = self.entities.outside_t0(ids, PKI_CONTROL_EDGES)
        groups = self._policy_groups(ids)
        out: dict[str, list[tuple[str, str]]] = {}
        for t in templates:
            found = [(esc, ESC_LABELS[esc]) for esc in template_escs(t.properties)]
            if t.objectid in writers:
                found.append(("ESC4", ESC_LABELS["ESC4"]))
            # The group's rights come with a logon as the certificate's subject.
            if t.objectid in groups and issued_freely(t.properties) and can_authenticate(t.properties):
                found.append(("ESC13", f"ESC13: issuance policy linked to {', '.join(groups[t.objectid])}"))
            out[t.objectid] = sorted(found, key=lambda f: int(f[0][3:]))
        return out

    # Summary

    def summary(self, node: Node) -> list[SummaryField]:
        build = self._ca_summary if node.kind == "EnterpriseCA" else self._template_summary
        return self.entities._with_fallback(lambda: build(node), lambda _: [])

    def _template_summary(self, template: Node) -> list[SummaryField]:
        oid = template.objectid
        cas = [ca.name for ca in self._linked(oid, PUBLISHED_TO)]
        escs = [label for _, label in self._escs([template])[oid]]
        enrollers, _ = self.entities.outside_t0({oid}, ENROLL_EDGES)
        writers, _ = self.entities.outside_t0({oid}, PKI_CONTROL_EDGES)
        fields = [
            _names("Published to", cas, "no Enterprise CA (nothing is issued from it)"),
            _names("ESC conditions met", escs, "none", "high" if cas else "medium"),
            _names("Enrollable by (outside Tier Zero)", enrollers.get(oid), "nobody"),
            _names("Writable by (outside Tier Zero)", writers.get(oid), "nobody", "high"),
        ]
        # ESC3: an agent template's certificate requests this one on behalf of another user, or the reverse.
        agents = [t.name for t in self._linked(oid, ENROLL_ON_BEHALF_OF, incoming=True)]
        if agents:
            fields.append(SummaryField("Requested on behalf of others with", agents, "list"))
        targets = [t.name for t in self._linked(oid, ENROLL_ON_BEHALF_OF)]
        if targets:
            fields.append(SummaryField("Agent certificate for", targets, "list"))
        return fields

    def _ca_summary(self, ca: Node) -> list[SummaryField]:
        oid = ca.objectid
        hosts = self._linked(oid, HOSTS_CA_SERVICE, incoming=True)
        templates = self._linked(oid, PUBLISHED_TO, incoming=True)
        escs = self._escs(templates)
        flagged = [f"{t.name}: {', '.join(esc for esc, _ in escs[t.objectid])}" for t in templates
                   if escs.get(t.objectid)]
        admins: dict[str, list[str]] = {}
        if hosts:
            admins, _ = self.entities.outside_t0({h.objectid for h in hosts}, frozenset({"AdminTo"}))
        enrollers, _ = self.entities.outside_t0({oid}, ENROLL_EDGES)
        managers, _ = self.entities.outside_t0({oid}, CA_MANAGE_EDGES, rights=True)
        # One issuing CA is often three nodes of the same name: its RootCA, AIACA and EnterpriseCA.
        issuers = list(dict.fromkeys(n.name for n in self._linked(oid, ISSUED_SIGNED_BY)))
        if not issuers and len(ca.properties.get("certchain") or []) == 1:
            issuers = ["itself (root CA)"]
        return [
            _names("Host", [h.name for h in hosts], "unknown"),
            _names("Admins of the host (outside Tier Zero)", [a for h in hosts for a in admins.get(h.objectid, [])],
                   "nobody", "high"),
            SummaryField("Trusted for NT Authentication", bool(self._linked(oid, TRUSTED_FOR_NTAUTH)), "bool"),
            _names("Issued by", issuers, "unknown"),
            SummaryField("Published templates", len(templates)),
            _names("Templates meeting ESC conditions", flagged, "none", "high"),
            _names("Enrollable by (outside Tier Zero)", enrollers.get(oid), "nobody"),
            _names("Managed by (outside Tier Zero, ESC7)", managers.get(oid), "nobody", "high"),
        ]

    # Views

    def templates(self, ca: Node) -> list[ViewResult]:
        title = "Published certificate templates"

        def via_cypher() -> list[ViewResult]:
            templates = self._linked(ca.objectid, PUBLISHED_TO, incoming=True)
            escs = self._escs(templates)
            graphs: list[Graph] = []
            enrollers: dict[str, list[str]] = {}
            if templates:
                enrollers, g = self.entities.outside_t0({t.objectid for t in templates}, ENROLL_EDGES)
                graphs.append(g)
            rows = []
            for t in templates:
                p = t.properties
                rows.append(TemplateRow(
                    name=t.name, schema_version=_int(p.get("schemaversion")),
                    authentication=opt_bool(p, "authenticationenabled"),
                    enrollee_supplies_subject=opt_bool(p, "enrolleesuppliessubject"),
                    manager_approval=opt_bool(p, "requiresmanagerapproval"),
                    signatures=_int(p.get("authorizedsignatures")),
                    escs=[esc for esc, _ in escs.get(t.objectid, [])],
                    enrollable_by=enrollers.get(t.objectid, []),
                    tier_zero=t.tier_zero, owned=t.owned, objectid=t.objectid,
                ))
            rows.sort(key=lambda r: (not (r.escs and r.enrollable_by), not r.escs,
                                     min((int(esc[3:]) for esc in r.escs), default=0), r.name))
            view = ViewResult("templates", title, TEMPLATE_COLS, rows)
            if any(r.escs for r in rows):
                view.notes.append(TEMPLATE_CAVEAT)
            unresolved = ca.properties.get("unresolvedpublishedtemplates") or []
            if unresolved:
                view.notes.append(f"Published but not found by SharpHound: {', '.join(map(str, unresolved))}.")
            return [self.entities._capped(view, *graphs)]

        return self.entities._with_fallback(
            via_cypher, lambda why: [rest_unavailable("templates", title, TEMPLATE_COLS, why)])
