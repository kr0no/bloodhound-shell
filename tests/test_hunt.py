from __future__ import annotations

import json
from typing import Any

import pytest
import responses

from bhshell.client.client import BHClient
from bhshell.models.entities import Graph
from bhshell.queries.hunt import (
    CHECKS,
    CHECKS_BY_ID,
    SCOPED_CHECKS,
    HuntOptions,
    HuntService,
    enctypes,
)
from bhshell.queries.service import EntityService
from bhshell.shell.app import BHShell
from tests.conftest import HELPDESK, IT_ADMINS, JDOE, NODES, graph, run

DEV = "DEV.CORP.LOCAL"


def node(kind: str, oid: str, name: str, *, t0: bool = False, owned: bool = False,
         domain: str = "CORP.LOCAL", **props: Any) -> dict[str, Any]:
    kinds = ["Base", kind] + (["Tag_Tier_Zero"] if t0 else []) + (["Tag_Owned"] if owned else [])
    return {"kind": kind, "kinds": kinds, "objectId": oid, "isTierZero": t0, "isOwnedObject": owned,
            "properties": {"name": name, "objectid": oid, "domain": domain, **props}}


def g(nodes: dict[str, dict[str, Any]], edges: list[tuple[str, str, str]]) -> Graph:
    return Graph.from_cypher(graph(list(nodes), edges, nodes=nodes)["data"])


def scoped(**principals: list[str]) -> HuntOptions:
    return HuntOptions(principals=principals)


def test_scope_condition() -> None:
    assert HuntOptions().scope("n") == ""
    assert scoped(b=["X"], a=["X"]).scope("n") == "n.objectid IN ['a', 'b']"


def test_scoped_checks_restrict_their_principals() -> None:
    opts = scoped(**{JDOE: ["JDOE@CORP.LOCAL"]})
    for check in SCOPED_CHECKS:
        assert f"objectid IN ['{JDOE}']" in check.query(opts), check.id
    assert "objectid IN" not in CHECKS_BY_ID["kerberoastable"].query(HuntOptions())


def test_adcs_leaves_out_tier_zero_principals() -> None:
    assert "NOT n:Tag_Tier_Zero" in CHECKS_BY_ID["adcs"].query(HuntOptions())


def test_every_check_has_a_unique_id_and_builds_a_query() -> None:
    assert len(CHECKS_BY_ID) == len(CHECKS)
    for check in CHECKS:
        assert check.query(HuntOptions(domain="corp.local")).startswith("MATCH")
        if check.fallback:
            assert check.fallback(HuntOptions()).startswith("MATCH")


def test_scoped_run_rejects_unscoped_checks(client: BHClient) -> None:
    with pytest.raises(Exception, match="does not run with --owned"):
        HuntService(EntityService(client)).run(CHECKS_BY_ID["kerberoastable"], scoped(x=["X"]))


@pytest.mark.parametrize("value, expected", [
    (None, "default (RC4)"),
    (["Not defined"], "default (RC4)"),
    (["RC4-HMAC-MD5", "AES256-CTS-HMAC-SHA1-96"], "RC4"),
    (["AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96"], "AES only"),
    (["DES-CBC-MD5"], "DES"),
])
def test_enctypes(value: Any, expected: str) -> None:
    assert enctypes({"supportedencryptiontypes": value} if value else {}) == expected


def test_kerberoastable_marks_paths_to_tier_zero(client: BHClient) -> None:
    finding = HuntService(EntityService(client)).run(CHECKS_BY_ID["kerberoastable"], HuntOptions())
    by_id = {r["objectid"]: r for r in finding.rows}
    assert by_id[JDOE]["path_to_t0"] is True and by_id[JDOE]["enctypes"] == "default (RC4)"
    assert finding.rows[0]["objectid"] == JDOE
    summary = HuntService(EntityService(client)).run(CHECKS_BY_ID["kerberoastable"], HuntOptions(enrich=False))
    assert "path_to_t0" not in summary.rows[0]


def test_owned_scope_maps_groups_to_owned_objects(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    nodes = {"7": NODES["7"], "2": NODES["2"], "3": NODES["3"]}
    results = {
        "MATCH (n:Tag_Owned) RETURN n": g({"7": NODES["7"]}, []),
        "MATCH p=(n:Tag_Owned)-[:MemberOf*1..]->(g:Group) RETURN p": g(nodes, [("7", "MemberOf", "2"),
                                                                              ("2", "MemberOf", "3")]),
    }
    monkeypatch.setattr(svc, "run_cypher", results.__getitem__)
    scope = HuntService(svc).owned_scope()
    assert scope == {HELPDESK: ["HELPDESK@CORP.LOCAL"], IT_ADMINS: ["HELPDESK@CORP.LOCAL"],
                     "S-1-5-21-1000-512": ["HELPDESK@CORP.LOCAL"]}


def test_scoped_rows_name_the_owned_object(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    nodes = {"2": NODES["2"], "c": node("Computer", "C1", "SRV01.CORP.LOCAL", operatingsystem="WINDOWS SERVER 2019"),
             "u": node("User", "U1", "ADM@CORP.LOCAL", t0=True)}
    result = g(nodes, [("2", "AdminTo", "c"), ("c", "HasSession", "u")])
    queries: list[str] = []

    def answer(query: str) -> Graph:
        queries.append(query)
        result.query = query
        return result

    monkeypatch.setattr(svc, "run_cypher", answer)
    finding = HuntService(svc).run(CHECKS_BY_ID["t0-sessions"], scoped(**{IT_ADMINS: ["HELPDESK@CORP.LOCAL"]}))
    assert queries[0].startswith("MATCH p=(n:Base)-[:AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|SQLAdmin]->(c:Computer)")
    assert finding.rows == [{"name": "SRV01.CORP.LOCAL", "os": "WINDOWS SERVER 2019", "user": "ADM@CORP.LOCAL",
                             "tier_zero": True, "admincount": False, "domain": "CORP.LOCAL",
                             "objectid": IT_ADMINS, "access": "AdminTo", "principal": "IT ADMINS@CORP.LOCAL",
                             "from_owned": "HELPDESK@CORP.LOCAL"}]


def test_t0_session_rows_unscoped() -> None:
    nodes = {"c": node("Computer", "C1", "WS01.CORP.LOCAL"), "u": node("User", "U1", "ADM@CORP.LOCAL", admincount=True)}
    rows = CHECKS_BY_ID["t0-sessions"].rows(g(nodes, [("c", "HasSession", "u")]), HuntOptions())
    assert [(r["name"], r["user"], r["admincount"]) for r in rows] == [("WS01.CORP.LOCAL", "ADM@CORP.LOCAL", True)]


def test_password_rows() -> None:
    nodes = {
        "a": node("User", "A", "A@CORP.LOCAL", description="Temp Password: Summer2026!"),
        "b": node("User", "B", "B@CORP.LOCAL", userpassword="hunter2", description="Service account"),
        "c": node("Computer", "C", "C.CORP.LOCAL", description="kiosk, mdp=kiosk"),
    }
    rows = CHECKS_BY_ID["passwords-in-attributes"].rows(g(nodes, []), HuntOptions())
    assert [(r["name"], r["attribute"], r["value"]) for r in rows] == [
        ("B@CORP.LOCAL", "userpassword", "hunter2"),
        ("A@CORP.LOCAL", "description", "Temp Password: Summer2026!"),
        ("C.CORP.LOCAL", "description", "kiosk, mdp=kiosk"),
    ]
    assert "toLower(n.description) CONTAINS 'pass'" in CHECKS_BY_ID["passwords-in-attributes"].query(HuntOptions())
    assert "n.description CONTAINS 'Pass'" in CHECKS_BY_ID["passwords-in-attributes"].fallback(HuntOptions())


def test_password_rows_skip_known_false_positives() -> None:
    nodes = {
        "a": node("Group", "A", "BACKUP OPERATORS@CORP.LOCAL", description="Members can bypass file security to back up files"),
        "b": node("Group", "B", "ALLOWED RODC PASSWORD REPLICATION GROUP@CORP.LOCAL",
                  description="Members in this group can have their passwords replicated to all read-only domain "
                              "controllers in the domain"),
        "c": node("User", "C", "C@CORP.LOCAL", description="bypass proxy; pass: Winter2026"),
    }
    rows = CHECKS_BY_ID["passwords-in-attributes"].rows(g(nodes, []), HuntOptions())
    assert [r["name"] for r in rows] == ["C@CORP.LOCAL"]


def test_dcsync_rows_skip_the_default_erodc_right() -> None:
    nodes = {"erodc": node("Group", "S-1-5-21-1-498", "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.LOCAL"),
             "some": node("Group", "S-1-5-21-1-1500", "SOMECHANGES@CORP.LOCAL"),
             "d": node("Domain", "S-1-5-21-1", "CORP.LOCAL", t0=True)}
    rows = CHECKS_BY_ID["dcsync"].rows(g(nodes, [("erodc", "GetChanges", "d"), ("some", "GetChanges", "d")]),
                                       HuntOptions())
    assert [(r["name"], r["full_dcsync"]) for r in rows] == [("SOMECHANGES@CORP.LOCAL", False)]


def test_summary_hint_names_a_check_with_findings(shell: BHShell) -> None:
    run(shell, "login -u admin")
    out = run(shell, "hunt")
    hint = next(line for line in out.splitlines() if "Details:" in line)
    assert "e.g. 'hunt dcsync'" in hint


def test_takeover_rows_name_the_technique() -> None:
    nodes = {"a": node("User", "A", "A@CORP.LOCAL"), "b": node("User", "B", "B@CORP.LOCAL", admincount=True),
             "c": node("Computer", "C", "C.CORP.LOCAL")}
    rows = CHECKS_BY_ID["object-takeover"].rows(
        g(nodes, [("a", "AddKeyCredentialLink", "c"), ("a", "WriteSPN", "b"), ("a", "AddAllowedToAct", "c")]),
        HuntOptions())
    assert [(r["technique"], r["target"]) for r in rows] == [
        ("Targeted Kerberoasting", "B@CORP.LOCAL"), ("RBCD", "C.CORP.LOCAL"), ("Shadow Credentials", "C.CORP.LOCAL")]


def test_ntlm_rows_list_the_issues() -> None:
    nodes = {"c": node("Computer", "C", "C.CORP.LOCAL", smbsigning=False, webclientrunning=True, ldapsigning=None)}
    rows = CHECKS_BY_ID["ntlm-hardening"].rows(g(nodes, []), HuntOptions())
    assert rows[0]["issues"] == "SMB signing not required; WebClient running (HTTP coercion)"


def test_foreign_rows_skip_same_domain_edges() -> None:
    nodes = {"a": node("User", "A", "A@DEV.CORP.LOCAL", domain=DEV), "g": node("Group", "G", "G@CORP.LOCAL"),
             "h": node("Group", "H", "H@DEV.CORP.LOCAL", domain=DEV)}
    rows = CHECKS_BY_ID["foreign-access"].rows(g(nodes, [("a", "MemberOf", "g"), ("a", "MemberOf", "h")]),
                                               HuntOptions())
    assert [(r["principal"], r["target"], r["target_domain"]) for r in rows] == [
        ("A@DEV.CORP.LOCAL", "G@CORP.LOCAL", "CORP.LOCAL")]


def test_decoy_rows_list_the_lures() -> None:
    nodes = {"a": node("User", "A", "SQLSVC@CORP.LOCAL", hasspn=True, admincount=True, whencreated=1600000000)}
    rows = CHECKS_BY_ID["decoys"].rows(g(nodes, []), HuntOptions())
    assert rows[0]["lures"] == "SPN, adminCount" and rows[0]["created"] == 1600000000


def test_sessions_count_as_logons() -> None:
    for check in ("decoys", "default-passwords"):
        assert "NOT (n)<-[:HasSession]-()" in CHECKS_BY_ID[check].query(HuntOptions()), check
    assert "NOT (n)-[:HasSession]->()" in CHECKS_BY_ID["pre2k"].query(HuntOptions())


def test_managed_accounts_are_not_guessed() -> None:
    for check in ("kerberoastable", "decoys", "default-passwords"):
        assert "(n.gmsa IS NULL OR n.gmsa = false)" in CHECKS_BY_ID[check].query(HuntOptions()), check
    assert "STARTS WITH 'healthmailbox'" in CHECKS_BY_ID["default-passwords"].query(HuntOptions())


def test_pre2k_rows_give_the_password_to_try() -> None:
    nodes = {"a": node("Computer", "A", "KIOSK01.CORP.LOCAL", samaccountname="KIOSK01$", whencreated=1600000000),
             "b": node("Computer", "B", "RECEPTIONDESK02.CORP.LOCAL", samaccountname="RECEPTIONDESK02$",
                       passwordnotreqd=True)}
    rows = CHECKS_BY_ID["pre2k"].rows(g(nodes, []), HuntOptions())
    assert [(r["name"], r["password"], r["passwordnotreqd"]) for r in rows] == [
        ("RECEPTIONDESK02.CORP.LOCAL", "receptiondesk0", True), ("KIOSK01.CORP.LOCAL", "kiosk01", False)]
    query = CHECKS_BY_ID["pre2k"].query(HuntOptions())
    assert "MATCH (n:Computer)" in query and "(n.pwdlastset - n.whencreated) < 50520" in query
    # A whencreated shifted by the collector's UTC offset still counts as set at creation.
    assert "((n.pwdlastset - n.whencreated) + 120) % 900 + 900) % 900 < 240" in query


def test_default_password_rows_put_must_change_then_newest_first() -> None:
    nodes = {"a": node("User", "A", "OLD@CORP.LOCAL", whencreated=1500000000, pwdlastset=1500000000),
             "b": node("User", "B", "NEW@CORP.LOCAL", whencreated=1700000000, pwdlastset=1700000000),
             "c": node("User", "C", "RESET@CORP.LOCAL", whencreated=1400000000, pwdlastset=0)}
    rows = CHECKS_BY_ID["default-passwords"].rows(g(nodes, []), HuntOptions())
    assert [(r["name"], r["must_change"]) for r in rows] == [
        ("RESET@CORP.LOCAL", True), ("NEW@CORP.LOCAL", False), ("OLD@CORP.LOCAL", False)]
    query = CHECKS_BY_ID["default-passwords"].query(HuntOptions())
    assert "(n.hasspn IS NULL OR n.hasspn = false)" in query
    assert query.endswith("ORDER BY n.pwdlastset = 0 DESC, n.whencreated DESC LIMIT 5000")


def test_twin_rows_pair_admin_and_standard_accounts() -> None:
    nodes = {
        "adm": node("User", "A1", "ADM_JDOE@CORP.LOCAL", t0=True, samaccountname="adm_jdoe"),
        "jdoe": node("User", "U1", "JDOE@CORP.LOCAL", samaccountname="jdoe", hasspn=True),
        "da": node("User", "A2", "ASMITH.DA@CORP.LOCAL", admincount=True, samaccountname="asmith.da",
                   displayname="Alice Smith (Domain Admin)"),
        "asmith": node("User", "U2", "ALICE@CORP.LOCAL", samaccountname="alice", displayname="Alice Smith",
                       owned=True),
        "administrator": node("User", "A3", "ADMINISTRATOR@CORP.LOCAL", t0=True, samaccountname="administrator"),
        "admin": node("User", "U3", "ADMIN@CORP.LOCAL", samaccountname="admin"),
        "smithers": node("User", "U4", "ASMITHERS@CORP.LOCAL", samaccountname="asmithers",
                         displayname="Alice Smithers"),
        "other": node("User", "U5", "JDOE@DEV.CORP.LOCAL", domain=DEV, samaccountname="jdoe"),
        "_bob": node("User", "A4", "_BOB@CORP.LOCAL", admincount=True, samaccountname="_bob"),
        "bob": node("User", "U6", "BOB@CORP.LOCAL", samaccountname="bob"),
    }
    rows = CHECKS_BY_ID["admin-twins"].rows(g(nodes, []), HuntOptions())
    assert [(r["name"], r["twin"], r["match"], r["twin_exposure"], r["twin_owned"]) for r in rows] == [
        ("ASMITH.DA@CORP.LOCAL", "ALICE@CORP.LOCAL", "display name", "", True),
        ("ADM_JDOE@CORP.LOCAL", "JDOE@CORP.LOCAL", "account name", "kerberoastable", False),
        ("_BOB@CORP.LOCAL", "BOB@CORP.LOCAL", "account name", "", False)]
    assert "UNWIND [u, n] AS x RETURN x LIMIT" in CHECKS_BY_ID["admin-twins"].query(HuntOptions())


def test_impersonable_admins_drop_protected_users(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    admins = {"a": node("User", "A", "A@CORP.LOCAL", t0=True), "b": node("User", "B", "B@CORP.LOCAL", t0=True)}
    protected = {"b": admins["b"], "p": node("Group", "S-1-5-21-1000-525", "PROTECTED USERS@CORP.LOCAL")}

    def answer(query: str) -> Graph:
        result = g(protected, [("b", "MemberOf", "p")]) if "-525" in query else g(admins, [])
        result.query = query
        return result

    monkeypatch.setattr(svc, "run_cypher", answer)
    finding = HuntService(svc).run(CHECKS_BY_ID["impersonable-admins"], HuntOptions(enrich=False))
    assert [r["name"] for r in finding.rows] == ["A@CORP.LOCAL"]
    assert finding.notes == ["1 Protected Users member(s) left out."]


def test_legacy_os_includes_windows_10_but_not_ltsc() -> None:
    query = CHECKS_BY_ID["legacy-os"].query(HuntOptions())
    assert "n.operatingsystem CONTAINS 'WINDOWS 10' AND NOT n.operatingsystem CONTAINS 'LTSC'" in query


def test_shell_hunt_owned(shell: BHShell, mocked: responses.RequestsMock) -> None:
    run(shell, "login -u admin")
    out = run(shell, "hunt --owned")
    assert "Hunt summary" in out and "tier-zero-control" in out and "asreproast" not in out
    queries = [json.loads(c.request.body)["query"] for c in mocked.calls if c.request.url.endswith("cypher")]
    assert any(f"n.objectid IN ['{HELPDESK}']" in q for q in queries)
    assert "not available with --owned" in run(shell, "hunt kerberoastable --owned")
    out = run(shell, "hunt dcsync --from helpdesk")
    assert "SVC_SQL@CORP.LOCAL" in out and "From" in out
    assert "Scoped" in run(shell, "hunt --list")
