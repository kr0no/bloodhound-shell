from __future__ import annotations

import json
from typing import Any

import pytest
import responses

from bhshell.client.client import BHClient
from bhshell.errors import AmbiguousMatchError
from bhshell.models.entities import Graph
from bhshell.queries import cypher as Q
from bhshell.queries.adcs import template_escs
from bhshell.queries.edges import (
    CA_MANAGE_EDGES,
    ENROLL_EDGES,
    ENROLL_ON_BEHALF_OF,
    HOSTS_CA_SERVICE,
    ISSUED_SIGNED_BY,
    PKI_CONTROL_EDGES,
    PUBLISHED_TO,
    TRUSTED_FOR_NTAUTH,
)
from bhshell.queries.hunt import CHECKS_BY_ID, HuntOptions
from bhshell.queries.service import PATH_KINDS, EntityService
from bhshell.shell.app import BHShell
from tests.conftest import BASE, L, graph, run

CYPHER = f"{BASE}api/v2/graphs/cypher"
DOM = "S-1-5-21-1000"
CA, ROOT, NTAUTH, POLICY = (f"2000000{i}-0000-0000-0000-000000000000" for i in range(1, 5))
VULN, ANY, WEB, SAFE, POLICYT = (f"3000000{i}-0000-0000-0000-000000000000" for i in range(1, 6))
TEMPLATES = {VULN, ANY, WEB, SAFE, POLICYT}
CA01, JDOE, HELPDESK = f"{DOM}-2010", f"{DOM}-1104", f"{DOM}-1106"
USERS, MANAGERS, PKI_ADMINS = f"{DOM}-513", f"{DOM}-1300", f"{DOM}-1301"
CLIENT_AUTH, SERVER_AUTH = "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"


def node(oid: str, kind: str, name: str, *, t0: bool = False, owned: bool = False, **props: Any) -> dict[str, Any]:
    kinds = ["Base", kind, *(["Tag_Tier_Zero"] if t0 else []), *(["Tag_Owned"] if owned else [])]
    return {"kind": kind, "kinds": kinds, "objectId": oid, "isTierZero": t0, "isOwnedObject": owned,
            "properties": {"name": name, "objectid": oid, "domain": "CORP.LOCAL", **props}}


def template(oid: str, name: str, **props: Any) -> dict[str, Any]:
    settings = {"schemaversion": 2, "requiresmanagerapproval": False, "authorizedsignatures": 0,
                "enrolleesuppliessubject": False, "authenticationenabled": True, "effectiveekus": [CLIENT_AUTH]}
    return node(oid, "CertTemplate", name, **{**settings, **props})


# CORP-CA, hosted on CA01 (HELPDESK is a local admin), publishes:
#   VULNUSER    enrollee supplies the subject                 ESC1, Domain Users can enroll
#   ANYPURPOSE  Any Purpose EKU, JDOE has GenericWrite         ESC2 + ESC4, Domain Users can enroll
#   WEBSERVER   schema 1, enrollee supplies the subject        ESC15, Domain Users can enroll
#   SAFE        same as VULNUSER, but needs manager approval   nothing
#   POLICY      issuance policy linked to PKI ADMINS           ESC13
NODES = {
    "ca": node(CA, "EnterpriseCA", "CORP-CA@CORP.LOCAL", t0=True, caname="CORP-CA", dnshostname="ca01.corp.local",
               isuserspecifiessanenabled=True, isuserspecifiessanenabledcollected=True,
               roleseparationenabledcollected=False, hasvulnerableendpoint=True,
               httpenrollmentendpoints=["http://ca01.corp.local/certsrv/"], unresolvedpublishedtemplates=["OLD"]),
    "root": node(ROOT, "RootCA", "CORP-ROOT@CORP.LOCAL", t0=True),
    "ntauth": node(NTAUTH, "NTAuthStore", "NTAUTHCERTIFICATES@CORP.LOCAL", t0=True),
    "policy": node(POLICY, "IssuancePolicy", "PKI POLICY@CORP.LOCAL"),
    "vuln": template(VULN, "VULNUSER@CORP.LOCAL", enrolleesuppliessubject=True),
    "any": template(ANY, "ANYPURPOSE@CORP.LOCAL", effectiveekus=["2.5.29.37.0"]),
    "web": template(WEB, "WEBSERVER@CORP.LOCAL", schemaversion=1, authenticationenabled=False,
                    enrolleesuppliessubject=True, effectiveekus=[SERVER_AUTH]),
    "safe": template(SAFE, "SAFE@CORP.LOCAL", enrolleesuppliessubject=True, requiresmanagerapproval=True),
    "policyt": template(POLICYT, "POLICY@CORP.LOCAL"),
    "ca01": node(CA01, "Computer", "CA01.CORP.LOCAL", t0=True),
    "users": node(USERS, "Group", "DOMAIN USERS@CORP.LOCAL"),
    "managers": node(MANAGERS, "Group", "CERT MANAGERS@CORP.LOCAL"),
    "pkiadmins": node(PKI_ADMINS, "Group", "PKI ADMINS@CORP.LOCAL"),
    "jdoe": node(JDOE, "User", "JDOE@CORP.LOCAL"),
    "helpdesk": node(HELPDESK, "User", "HELPDESK@CORP.LOCAL", owned=True),
}
PUBLISHED = [(t, PUBLISHED_TO, "ca") for t in ("vuln", "any", "web", "safe", "policyt")]
ENROLLS = [("users", "Enroll", t) for t in ("vuln", "any", "web")]


def g(*ids: str, edges: list[tuple[str, str, str]]) -> dict[str, Any]:
    return graph(list(ids), edges, nodes=NODES)


RESULTS: dict[str, dict[str, Any]] = {
    Q.by_name(Q.name_conditions("CORP-CA", None, None), None, 100): g("ca", edges=[]),
    Q.by_name(Q.name_conditions("VULNUSER", "VULNUSER@CORP.LOCAL", None), None, 100): g("vuln", edges=[]),
    # CORP-CA
    Q.incoming(CA, {HOSTS_CA_SERVICE}, L): g("ca01", "ca", edges=[("ca01", HOSTS_CA_SERVICE, "ca")]),
    Q.incoming(CA, {PUBLISHED_TO}, L): g("ca", "vuln", "any", "web", "safe", "policyt", edges=PUBLISHED),
    Q.outgoing_direct(CA, L, {TRUSTED_FOR_NTAUTH}): g("ca", "ntauth", edges=[("ca", TRUSTED_FOR_NTAUTH, "ntauth")]),
    Q.outgoing_direct(CA, L, {ISSUED_SIGNED_BY}): g("ca", "root", edges=[("ca", ISSUED_SIGNED_BY, "root")]),
    Q.controllers_outside_t0({CA}, ENROLL_EDGES, L): g("users", "ca", edges=[("users", "Enroll", "ca")]),
    Q.controllers_outside_t0({CA}, CA_MANAGE_EDGES, L): g("managers", "helpdesk", "ca", edges=[
        ("managers", "ManageCA", "ca"), ("helpdesk", "ManageCertificates", "ca"), ("helpdesk", "ManageCA", "ca")]),
    Q.controllers_outside_t0({CA01}, frozenset({"AdminTo"}), L): g("helpdesk", "ca01", edges=[
        ("helpdesk", "AdminTo", "ca01")]),
    Q.controllers_outside_t0(TEMPLATES, PKI_CONTROL_EDGES, L): g("jdoe", "any", edges=[("jdoe", "GenericWrite", "any")]),
    Q.controllers_outside_t0(TEMPLATES, ENROLL_EDGES, L): g("users", "vuln", "any", "web", edges=ENROLLS),
    Q.policy_groups(TEMPLATES): g("policyt", "policy", "pkiadmins", edges=[
        ("policyt", "ExtendedByPolicy", "policy"), ("policy", "OIDGroupLink", "pkiadmins")]),
    # VULNUSER
    Q.outgoing_direct(VULN, L, {PUBLISHED_TO}): g("vuln", "ca", edges=[("vuln", PUBLISHED_TO, "ca")]),
    Q.controllers_outside_t0({VULN}, ENROLL_EDGES, L): g("users", "vuln", edges=[("users", "Enroll", "vuln")]),
    Q.incoming(VULN, {ENROLL_ON_BEHALF_OF}, L): g("any", "vuln", edges=[("any", ENROLL_ON_BEHALF_OF, "vuln")]),
}


@pytest.fixture
def pki(mocked: responses.RequestsMock) -> list[str]:
    """Serve the PKI above; returns the Cypher queries sent."""
    queries: list[str] = []

    def callback(request: Any) -> tuple[int, dict[str, str], str]:
        query = json.loads(request.body)["query"]
        queries.append(query)
        if query in RESULTS:
            return 200, {}, json.dumps(RESULTS[query])
        if "RETURN count(" in query:
            return 200, {}, json.dumps({"data": {"nodes": {}, "edges": [], "literals": [{"key": "c", "value": 0}]}})
        return 404, {}, json.dumps({"errors": [{"message": "resource not found"}]})

    mocked.remove(responses.POST, CYPHER)
    mocked.add_callback(responses.POST, CYPHER, callback=callback)
    return queries


@pytest.fixture
def svc(client: BHClient, pki: list[str]) -> EntityService:
    return EntityService(client, max_results=L)


def props(key: str) -> dict[str, Any]:
    return NODES[key]["properties"]


def test_template_escs_from_the_settings() -> None:
    assert template_escs(props("vuln")) == ["ESC1"]
    assert template_escs(props("any")) == ["ESC2"]
    assert template_escs(props("web")) == ["ESC15"]
    assert template_escs(props("safe")) == []
    agent = {**props("policyt"), "effectiveekus": ["1.3.6.1.4.1.311.20.2.1"], "authenticationenabled": False}
    assert template_escs(agent) == ["ESC3"]
    nosid = {**props("policyt"), "nosecurityextension": True}
    assert template_escs(nosid) == ["ESC9"]


def test_template_escs_need_known_settings_and_no_cosigning() -> None:
    # No EKU at all: any purpose, and authentication is worked out from the EKUs when not stored.
    bare = {k: v for k, v in props("vuln").items() if k != "authenticationenabled"} | {"effectiveekus": []}
    assert template_escs(bare) == ["ESC1", "ESC2"]
    assert template_escs({**props("vuln"), "authorizedsignatures": 1}) == []
    assert template_escs({**props("vuln"), "authorizedsignatures": 1, "schemaversion": 1}) == ["ESC1", "ESC15"]
    unknown = {k: v for k, v in props("vuln").items() if k != "requiresmanagerapproval"}
    assert template_escs(unknown) == []


def test_esc13_needs_a_freely_issued_template(svc: EntityService, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(NODES["policyt"]["properties"], "requiresmanagerapproval", True)
    view = svc.view(svc.resolve("CORP-CA", kinds=("EnterpriseCA",)), "templates")[0]
    assert {r.name: r.escs for r in view.rows}["POLICY@CORP.LOCAL"] == []


def test_same_named_templates_point_to_the_domain_or_guid(svc: EntityService,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    dev = template("40000001-0000-0000-0000-000000000000", "VULNUSER@DEV.CORP.LOCAL", domain="DEV.CORP.LOCAL")
    nodes = {**NODES, "dev": dev}
    monkeypatch.setitem(RESULTS, Q.by_name(Q.name_conditions("VULNUSER", None, None), None, 100),
                        graph(["vuln", "dev"], [], nodes=nodes))
    with pytest.raises(AmbiguousMatchError) as exc:
        svc.resolve("VULNUSER", kinds=("CertTemplate",))
    assert "object ID (GUID)" in exc.value.hint and "SID" not in exc.value.hint


def test_path_endpoints_include_pki_objects_and_a_ca_name_means_the_enterprise_ca(
        svc: EntityService, monkeypatch: pytest.MonkeyPatch) -> None:
    root = node("50000001-0000-0000-0000-000000000000", "RootCA", "CORP-CA@CORP.LOCAL", t0=True)
    aia = node("50000002-0000-0000-0000-000000000000", "AIACA", "CORP-CA@CORP.LOCAL", t0=True)
    nodes = {**NODES, "root2": root, "aia": aia}
    monkeypatch.setitem(RESULTS, Q.by_name(Q.name_conditions("CORP-CA", None, None), None, 100),
                        graph(["ca", "root2", "aia"], [], nodes=nodes))
    assert svc.resolve("CORP-CA", kinds=PATH_KINDS).objectid == CA
    assert svc.resolve("VULNUSER@corp.local", kinds=PATH_KINDS).kind == "CertTemplate"


def test_ca_summary(svc: EntityService) -> None:
    ca = svc.resolve("CORP-CA", kinds=("EnterpriseCA",))
    fields = {f.label: f.value for f in svc.report(ca, [], show_summary=True).summary()}
    assert fields["User Specified SAN (ESC6)"] is True
    assert fields["Role Separation"] == "not collected"
    assert fields["Relayable Web Enrollment (ESC8)"] is True
    assert fields["Host"] == ["CA01.CORP.LOCAL"]
    assert fields["Admins of the host (outside Tier Zero)"] == ["HELPDESK@CORP.LOCAL (owned)"]
    assert fields["Trusted for NT Authentication"] is True
    assert fields["Issued by"] == ["CORP-ROOT@CORP.LOCAL"]
    assert fields["Published templates"] == 5
    assert fields["Templates meeting ESC conditions"] == [
        "ANYPURPOSE@CORP.LOCAL: ESC2, ESC4", "POLICY@CORP.LOCAL: ESC13", "VULNUSER@CORP.LOCAL: ESC1",
        "WEBSERVER@CORP.LOCAL: ESC15"]
    assert fields["Managed by (outside Tier Zero, ESC7)"] == [
        "HELPDESK@CORP.LOCAL (ManageCA, ManageCertificates, owned)", "CERT MANAGERS@CORP.LOCAL (ManageCA)"]


def test_ca_templates_view(svc: EntityService) -> None:
    view = svc.view(svc.resolve("CORP-CA", kinds=("EnterpriseCA",)), "templates")[0]
    assert [(r.name.split("@")[0], r.escs, bool(r.enrollable_by)) for r in view.rows] == [
        ("VULNUSER", ["ESC1"], True),  # meets a condition and someone can enroll; ESC1 first
        ("ANYPURPOSE", ["ESC2", "ESC4"], True),
        ("WEBSERVER", ["ESC15"], True),
        ("POLICY", ["ESC13"], False),
        ("SAFE", [], False),
    ]
    assert "Published but not found by SharpHound: OLD." in view.notes


def test_template_from_the_shell(shell: BHShell, pki: list[str]) -> None:
    run(shell, "login -u admin")
    out = run(shell, "template VULNUSER@corp.local")
    for expected in ("Client Authentication", "Enrollee Supplies Subject", "CORP-CA@CORP.LOCAL",
                     "ESC1: enrollee supplies the subject", "DOMAIN USERS@CORP.LOCAL",
                     "Requested on behalf of others with", "ANYPURPOSE@CORP.LOCAL"):
        assert expected in out
    out = run(shell, "ca CORP-CA -t")
    assert "ANYPURPOSE@CORP.LOCAL" in out and "Host" not in out


def _graph(nodes: dict[str, dict[str, Any]], edges: list[tuple[str, str, str]]) -> Graph:
    return Graph.from_cypher(graph(list(nodes), edges, nodes=nodes)["data"])


def test_hunt_template_rows_keep_escs_without_bloodhound_edges() -> None:
    edges = [*ENROLLS, ("vuln", PUBLISHED_TO, "ca"), ("any", PUBLISHED_TO, "ca"), ("web", PUBLISHED_TO, "ca")]
    rows = CHECKS_BY_ID["adcs-templates"].rows(_graph(NODES, edges), HuntOptions())
    assert [(r["target"], r["escs"], r["cas"]) for r in rows] == [
        ("ANYPURPOSE@CORP.LOCAL", "ESC2", "CORP-CA@CORP.LOCAL"),
        ("WEBSERVER@CORP.LOCAL", "ESC15", "CORP-CA@CORP.LOCAL"),
    ]


def test_hunt_pki_control_rows_name_the_technique() -> None:
    edges = [("jdoe", "GenericWrite", "any"), ("helpdesk", "WriteDacl", "ntauth"), ("jdoe", "MemberOf", "users")]
    rows = CHECKS_BY_ID["adcs-pki-control"].rows(_graph(NODES, edges), HuntOptions())
    assert [(r["technique"], r["principal"], r["target"]) for r in rows] == [
        ("ESC4", "JDOE@CORP.LOCAL", "ANYPURPOSE@CORP.LOCAL"),
        ("ESC5", "HELPDESK@CORP.LOCAL", "NTAUTHCERTIFICATES@CORP.LOCAL"),
    ]


def test_hunt_takeover_includes_esc14() -> None:
    rows = CHECKS_BY_ID["object-takeover"].rows(
        _graph(NODES, [("helpdesk", "WriteAltSecurityIdentities", "jdoe")]), HuntOptions())
    assert rows[0]["technique"] == "ESC14 (explicit certificate mapping)"
