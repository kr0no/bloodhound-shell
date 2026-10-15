from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import responses
from rich.console import Console

from bhshell.client.client import BHClient
from bhshell.config import Config
from bhshell.models.entities import BROAD_SIDS
from bhshell.queries import cypher as Q
from bhshell.queries.edges import CONTROL_EDGES, EXEC_EDGES, severity
from bhshell.shell.app import BHShell

BASE = "http://BH.test:8080/"
DOM = "S-1-5-21-1000"

JDOE = f"{DOM}-1104"
JDOE_DEV = "S-1-5-21-2000-1104"
IT_ADMINS = f"{DOM}-1200"
DOMAIN_ADMINS = f"{DOM}-512"
WS01 = f"{DOM}-1300"
SVC_SQL = f"{DOM}-1105"
HELPDESK = f"{DOM}-1106"

NODES: dict[str, dict[str, Any]] = {
    "1": {"kind": "User", "kinds": ["Base", "User"], "objectId": JDOE, "label": "JDOE@CORP.LOCAL",
          "properties": {"name": "JDOE@CORP.LOCAL", "objectid": JDOE, "samaccountname": "jdoe",
                         "domain": "CORP.LOCAL", "enabled": True, "hasspn": True, "dontreqpreauth": False,
                         "pwdlastset": 1700000000, "lastlogon": 1710000000, "description": "Test user"}},
    "2": {"kind": "Group", "kinds": ["Base", "Group"], "objectId": IT_ADMINS,
          "properties": {"name": "IT ADMINS@CORP.LOCAL", "objectid": IT_ADMINS, "domain": "CORP.LOCAL"}},
    "3": {"kind": "Group", "kinds": ["Base", "Group", "Tag_Tier_Zero"], "objectId": DOMAIN_ADMINS, "isTierZero": True,
          "properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "objectid": DOMAIN_ADMINS, "domain": "CORP.LOCAL"}},
    "4": {"kind": "Computer", "kinds": ["Base", "Computer"], "objectId": WS01,
          "properties": {"name": "WS01.CORP.LOCAL", "objectid": WS01, "samaccountname": "WS01$",
                         "domain": "CORP.LOCAL", "operatingsystem": "Windows 11", "haslaps": False}},
    "5": {"kind": "User", "kinds": ["Base", "User"], "objectId": SVC_SQL,
          "properties": {"name": "SVC_SQL@CORP.LOCAL", "objectid": SVC_SQL, "samaccountname": "svc_sql",
                         "domain": "CORP.LOCAL"}},
    "6": {"kind": "User", "kinds": ["Base", "User"], "objectId": JDOE_DEV,
          "properties": {"name": "JDOE@DEV.CORP.LOCAL", "objectid": JDOE_DEV, "samaccountname": "jdoe",
                         "domain": "DEV.CORP.LOCAL"}},
    "7": {"kind": "User", "kinds": ["Base", "User", "Tag_Owned"], "objectId": HELPDESK, "isOwnedObject": True,
          "properties": {"name": "HELPDESK@CORP.LOCAL", "objectid": HELPDESK, "samaccountname": "helpdesk",
                         "domain": "CORP.LOCAL"}},
    "8": {"kind": "Domain", "kinds": ["Base", "Domain", "Tag_Tier_Zero"], "objectId": DOM, "isTierZero": True,
          "properties": {"name": "CORP.LOCAL", "objectid": DOM, "domain": "CORP.LOCAL", "functionallevel": "2016"}},
    "9": {"kind": "Domain", "kinds": ["Base", "Domain"], "objectId": "S-1-5-21-2000",
          "properties": {"name": "DEV.CORP.LOCAL", "objectid": "S-1-5-21-2000", "domain": "DEV.CORP.LOCAL"}},
}


def graph(node_ids: list[str], edges: list[tuple[str, str, str]],
          edge_props: dict[tuple[str, str, str], dict[str, Any]] | None = None,
          nodes: dict[str, dict[str, Any]] = NODES) -> dict[str, Any]:
    props = edge_props or {}
    return {"data": {
        "nodes": {i: nodes[i] for i in node_ids},
        "edges": [{"source": s, "target": t, "kind": k, "label": k, "properties": props.get((s, k, t), {})}
                  for s, k, t in edges],
    }}


TOKEN = "a.eyJleHAiOjk5OTk5OTk5OTl9.c"  # payload {"exp": 9999999999}
L = Config().max_results


def tier(kinds: frozenset[str], level: str) -> frozenset[str]:
    """The kinds of one severity tier, as queried by EntityService._tiered."""
    return frozenset(k for k in kinds if severity(k) == level)


CYPHER_RESULTS: dict[str, dict[str, Any]] = {
    Q.by_name(Q.name_conditions("jdoe", None, "User"), "User", 100): graph(["1", "6"], []),
    Q.by_name(Q.name_conditions("jdoe", "JDOE@CORP.LOCAL", "User"), "User", 100): graph(["1"], []),
    Q.by_name(Q.name_conditions("jdoe", "JDOE@CORP.LOCAL", None), None, 100): graph(["1"], []),
    Q.by_objectid(DOMAIN_ADMINS): graph(["3"], []),
    Q.by_name(Q.name_conditions("corp.local", "CORP.LOCAL", None), None, 100): graph(["8"], []),
    Q.by_name(Q.name_conditions("svc_sql", None, "User"), "User", 100): graph(["5"], []),
    Q.by_name(Q.name_conditions("helpdesk", None, None), None, 100): graph(["7"], []),
    Q.by_name(Q.name_conditions("WS01", None, "Computer"), "Computer", 100): graph(["4"], []),
    Q.by_name(Q.name_conditions("IT Admins", None, "Group"), "Group", 100): graph(["2"], []),
    Q.member_of(JDOE): graph(["1", "2", "3"], [("1", "MemberOf", "2"), ("2", "MemberOf", "3")]),
    Q.outgoing_direct(JDOE, L, tier(CONTROL_EDGES, "critical")): graph(["1", "5"], [("1", "GenericAll", "5")]),
    Q.outgoing_inherited(JDOE, L, tier(EXEC_EDGES, "critical")): graph(
        ["1", "2", "4"], [("1", "MemberOf", "2"), ("2", "AdminTo", "4")]),
    # SVC_SQL: the server rejects the kind-filtered query, so the wildcard query is used.
    Q.outgoing_direct(SVC_SQL, L): graph(["5", "2", "1"], [("5", "MemberOf", "2"), ("5", "WriteDacl", "1")]),
    Q.incoming(JDOE, tier(CONTROL_EDGES, "high"), L): graph(["1", "7"], [("7", "ForceChangePassword", "1")]),
    Q.sessions_of_user(JDOE, L): graph(["1", "4"], [("4", "HasSession", "1")]),
    Q.incoming(WS01, tier(EXEC_EDGES, "critical"), L): graph(["2", "4"], [("2", "AdminTo", "4")]),
    Q.incoming_unrolled(WS01, tier(EXEC_EDGES, "critical"), L, BROAD_SIDS): graph(
        ["1", "2", "4"], [("1", "MemberOf", "2"), ("2", "AdminTo", "4")]),
    "MATCH (n:Tag_Owned) RETURN n": graph(["7"], []),
}


# Fallback matching on query substrings (checked after exact matches, in order).
CYPHER_CONTAINS: list[tuple[str, dict[str, Any]]] = [
    # owned -> T0: HELPDESK -ForceChangePassword-> JDOE -MemberOf-> IT ADMINS -MemberOf-> DOMAIN ADMINS (T0)
    ("allShortestPaths((s:Tag_Owned)", graph(["7", "1", "2", "3"], [
        ("7", "ForceChangePassword", "1"), ("1", "MemberOf", "2"), ("2", "MemberOf", "3")])),
    # JDOE -> T0
    ("allShortestPaths((s:Base)", graph(["1", "2", "3"], [("1", "MemberOf", "2"), ("2", "MemberOf", "3")])),
    ("n.hasspn = true", graph(["1", "6"], [])),
    ("(d:Domain)", graph(["5", "2", "8"], [("5", "GetChanges", "8"), ("5", "GetChangesAll", "8"),
                                           ("2", "GetChanges", "8")])),
    ("MATCH p=(a:Domain)-[r]->(b:Domain)", graph(["8", "9"], [
        ("8", "CrossForestTrust", "9"), ("9", "CrossForestTrust", "8"), ("8", "SpoofSIDHistory", "9")],
        {("8", "CrossForestTrust", "9"): {"trusttype": "Forest", "transitive": True,
                                          "spoofsidhistoryblocked": True}})),
    ("MATCH (n:Domain) RETURN n", graph(["8", "9"], [])),
]

REJECTED = {Q.outgoing_direct(SVC_SQL, L, tier(CONTROL_EDGES, "critical"))}


def cypher_callback(request: Any) -> tuple[int, dict[str, str], str]:
    query = json.loads(request.body)["query"]
    if query in REJECTED:
        return 400, {}, json.dumps({"errors": [{"message": "unknown relationship kind"}]})
    if query in CYPHER_RESULTS:
        return 200, {}, json.dumps(CYPHER_RESULTS[query])
    if "RETURN count(" in query:
        return 200, {}, json.dumps({"data": {"nodes": {}, "edges": [], "literals": [{"key": "count(n)", "value": 7}]}})
    for needle, result in CYPHER_CONTAINS:
        if needle in query:
            return 200, {}, json.dumps(result)
    return 404, {}, json.dumps({"errors": [{"message": "resource not found"}]})


@pytest.fixture
def mocked() -> Any:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback(responses.POST, f"{BASE}api/v2/graphs/cypher", callback=cypher_callback)
        rsps.add(responses.POST, f"{BASE}api/v2/login",
                 json={"data": {"user_id": "u1", "auth_expired": False, "session_token": TOKEN}})
        rsps.add(responses.GET, f"{BASE}api/v2/self",
                 json={"data": {"principal_name": "admin", "roles": [{"name": "Administrator"}]}})
        rsps.add(responses.GET, f"{BASE}api/version", json={"data": {"server_version": "v8.0.0"}})
        yield rsps


@pytest.fixture
def client(mocked: Any) -> BHClient:
    c = BHClient(BASE)
    c.set_jwt(TOKEN, "admin")
    return c


@pytest.fixture
def shell(mocked: Any, bhshell_home: Path, monkeypatch: pytest.MonkeyPatch) -> BHShell:
    monkeypatch.setenv("BH_PASSWORD", "pw")
    app = BHShell(Config(url=BASE), resume=False)
    app.ui.console = Console(record=True, width=200, force_terminal=False)
    app.ui.status = app.ui.console  # capture results and status messages together
    return app


def run(app: BHShell, line: str) -> str:
    """Run a shell command and return everything it printed."""
    app.ui.console.export_text(clear=True)
    app.onecmd_plus_hooks(line)
    return app.ui.console.export_text(clear=True)


@pytest.fixture
def bhshell_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BHSHELL_HOME", str(tmp_path / "home"))
    return tmp_path / "home"

