from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from bhshell.client.client import BHClient
from bhshell.errors import AmbiguousMatchError, BHError, NotFoundError, UnsupportedFeature
from bhshell.models.entities import Graph, Node, User, literal_rows
from bhshell.models.results import ViewResult
from bhshell.queries import cypher as Q
from bhshell.queries.marking import MarkingService
from bhshell.queries.service import EntityService, parse_identifier
from bhshell.shell.commands.cypher import parse_cypher_args
from tests.conftest import BASE, HELPDESK, IT_ADMINS, JDOE, NODES, SVC_SQL, WS01, graph


@pytest.mark.parametrize("raw, kind, sam, domain, fqdn, oid", [
    ("jdoe", "User", "jdoe", "", "", ""),
    ("jdoe@corp.local", "User", "jdoe", "CORP.LOCAL", "JDOE@CORP.LOCAL", ""),
    ("CORP\\jdoe", "User", "jdoe", "CORP", "", ""),
    ("WS01.corp.local", "Computer", "WS01", "CORP.LOCAL", "WS01.CORP.LOCAL", ""),
    ("j.doe", "User", "j.doe", "", "", ""),
    ("S-1-5-21-1-2-3-1104", None, "", "", "", "S-1-5-21-1-2-3-1104"),
    ("CORP.LOCAL-S-1-5-32-544", None, "", "", "", "CORP.LOCAL-S-1-5-32-544"),
])
def test_parse_identifier(raw: str, kind: str, sam: str, domain: str, fqdn: str, oid: str) -> None:
    ident = parse_identifier(raw, kind=kind)
    assert (ident.sam, ident.domain, ident.fqdn, ident.objectid) == (sam, domain, fqdn, oid)


def test_literal_rows_split_on_repeated_keys() -> None:
    literals = [{"key": "name", "value": "A"}, {"key": "n", "value": 1},
                {"key": "name", "value": "B"}, {"key": "n", "value": 2}, {"key": "name", "value": "C"}]
    assert literal_rows(literals) == [{"name": "A", "n": 1}, {"name": "B", "n": 2}, {"name": "C"}]


def test_cypher_literal_escaping() -> None:
    assert Q.lit("O'Brien\\x") == "'O\\'Brien\\\\x'"


def test_resolve_ambiguous_across_domains(client: BHClient) -> None:
    with pytest.raises(AmbiguousMatchError) as exc:
        EntityService(client).resolve("jdoe", "User")
    assert {n.domain for n in exc.value.candidates} == {"CORP.LOCAL", "DEV.CORP.LOCAL"}
    assert "SID" in exc.value.hint


@pytest.mark.parametrize("name, domain", [("CORP\\jdoe", None), ("jdoe", "corp.local")])
def test_resolve_with_domain(client: BHClient, name: str, domain: str | None) -> None:
    node = EntityService(client).resolve(name, "User", domain)
    assert node.objectid == JDOE


def test_resolve_not_found(client: BHClient) -> None:
    with pytest.raises(NotFoundError):
        EntityService(client).resolve("ghost", "User")


def test_user_summary_flags_kerberoastable(client: BHClient) -> None:
    node = EntityService(client).resolve("jdoe@corp.local", "User")
    fields = {f.label: f for f in User(node).summary()}
    assert fields["Kerberoastable (hasspn)"].risk == "high"
    assert fields["AS-REP Roastable (dontreqpreauth)"].risk == "none"


def test_groups_view_unrolls_nesting(client: BHClient) -> None:
    svc = EntityService(client)
    node = svc.resolve("jdoe", "User", "CORP.LOCAL")
    rows = svc.groups(node)[0].rows
    assert [(r.target, r.depth, r.via) for r in rows] == [
        ("IT ADMINS@CORP.LOCAL", 1, "direct"),
        ("DOMAIN ADMINS@CORP.LOCAL", 2, "IT ADMINS@CORP.LOCAL"),
    ]
    assert rows[1].tier_zero


def test_outbound_and_privs_include_inherited(client: BHClient) -> None:
    svc = EntityService(client)
    node = svc.resolve("jdoe", "User", "CORP.LOCAL")
    outbound = svc.outbound(node)[0].rows
    assert [(r.edge, r.target, r.via) for r in outbound] == [("GenericAll", "SVC_SQL@CORP.LOCAL", "direct")]
    privs = svc.privs(node)[0].rows
    assert [(r.edge, r.target, r.via) for r in privs] == [("AdminTo", "WS01.CORP.LOCAL", "IT ADMINS@CORP.LOCAL")]


def test_outbound_lists_worst_rights_first_whichever_group_holds_them(
        client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    jdoe = svc.resolve("jdoe", "User", "CORP.LOCAL")
    # A medium right held directly, a critical one held through IT ADMINS.
    held = Graph.from_cypher(graph(["1", "2", "5", "8"], [
        ("1", "Enroll", "5"), ("1", "MemberOf", "2"), ("2", "ADCSESC1", "8")])["data"])
    monkeypatch.setattr(svc, "run_cypher", lambda query: held)
    rows = svc.view(jdoe, "outbound")[0].rows
    assert [(r.edge, r.via) for r in rows] == [("ADCSESC1", "IT ADMINS@CORP.LOCAL"), ("Enroll", "direct")]


def test_inbound_lists_members_of_holding_groups_once(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    target = svc.resolve("svc_sql", "User")
    users = {"kind": "Group", "kinds": ["Base", "Group"], "objectId": "S-1-5-21-1000-513",
             "properties": {"name": "DOMAIN USERS@CORP.LOCAL", "objectid": "S-1-5-21-1000-513"}}
    nodes = {**NODES, "u": users}
    # IT ADMINS (JDOE inside) holds two critical rights; Domain Users (HELPDESK inside) holds one.
    held = Graph.from_cypher(graph(["1", "2", "5", "7", "u"], [
        ("2", "WriteDacl", "5"), ("2", "GenericAll", "5"), ("1", "MemberOf", "2"),
        ("u", "GenericWrite", "5"), ("7", "MemberOf", "u")], nodes=nodes)["data"])
    queries: list[str] = []
    monkeypatch.setattr(svc, "run_cypher", lambda query: queries.append(query) or held)
    rows = svc.view(target, "inbound")[0].rows
    assert [(r.principal, r.edge, r.via) for r in rows] == [
        ("IT ADMINS@CORP.LOCAL", "GenericAll", "direct"),
        ("IT ADMINS@CORP.LOCAL", "WriteDacl", "direct"),
        ("JDOE@CORP.LOCAL", "GenericAll", "IT ADMINS@CORP.LOCAL"),  # once, with the group's strongest right
        ("DOMAIN USERS@CORP.LOCAL", "GenericWrite", "direct"),  # a broad group is not unrolled
    ]
    assert any("ENDS WITH '-513'" in q for q in queries)


def test_outbound_falls_back_to_wildcard_query(client: BHClient) -> None:
    svc = EntityService(client)
    node = svc.resolve("svc_sql", "User")
    rows = svc.outbound(node)[0].rows
    assert [(r.edge, r.target) for r in rows] == [("WriteDacl", "JDOE@CORP.LOCAL")]


def _result(nodes: list[str], edges: list[tuple[str, str, str]], query: str) -> Graph:
    g = Graph.from_cypher(graph(nodes, edges)["data"])
    g.query = query
    return g


def test_count_paths_counts_simple_paths_up_to_cap() -> None:
    # 1 -> 2 -> 3 and 1 -> 4 -> 3: paths 1-2, 1-2-3, 1-4, 1-4-3, 2-3, 4-3
    g = _result(["1", "2", "3", "4"], [("1", "MemberOf", "2"), ("2", "GenericAll", "3"),
                                       ("1", "MemberOf", "4"), ("4", "GenericAll", "3")], "")
    assert g.count_paths(100) == 6
    assert g.count_paths(4) == 4
    cyclic = _result(["1", "2"], [("1", "MemberOf", "2"), ("2", "MemberOf", "1")], "")
    assert cyclic.count_paths(100) == 2


def test_truncation_uses_exact_count_when_bound_reaches_limit(client: BHClient) -> None:
    svc = EntityService(client, max_results=2)
    query = "MATCH p=(n:Base)-[:MemberOf*1..]->(g:Group)-[r]->(t:Base) WHERE n.objectid = 'X' RETURN p LIMIT 2"
    # Two membership chains reaching the same final edge: one unique non-MemberOf edge, but two rows.
    shared = _result(["1", "2", "3", "4", "5"], [("1", "MemberOf", "2"), ("1", "MemberOf", "3"),
                                                 ("2", "MemberOf", "4"), ("3", "MemberOf", "4"),
                                                 ("4", "GenericAll", "5")], query)
    assert svc.truncation(shared) == (True, 7)  # the mock server counts 7
    view = svc._capped(ViewResult("x", "x", []), shared)
    assert "server total: 7" in view.notes[0]

    small = _result(["1", "5"], [("1", "GenericAll", "5")], query)
    assert svc.truncation(small) == (False, None)
    assert not svc._capped(ViewResult("x", "x", []), small).notes


def test_truncation_exact_count_within_limit_is_complete(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client, max_results=2)
    g = _result(["1", "2", "5"], [("1", "MemberOf", "2"), ("1", "GenericAll", "5")],
                "MATCH p=(n:Base)-[r]->(t:Base) WHERE n.objectid = 'X' RETURN p LIMIT 2")
    monkeypatch.setattr(svc, "count", lambda q: 2)
    assert svc.truncation(g) == (False, 2)
    monkeypatch.setattr(svc, "count", lambda q: None)  # server cannot count: assume truncated
    assert svc.truncation(g) == (True, None)
    assert "may be truncated" in svc._capped(ViewResult("x", "x", []), g).notes[0]


def test_to_count_rewrites_return() -> None:
    assert Q.to_count("MATCH (n:User) WHERE n.enabled = true RETURN n LIMIT 50") == \
        "MATCH (n:User) WHERE n.enabled = true RETURN count(n)"
    assert Q.to_count("MATCH p=(a)-[r]->(b) RETURN p LIMIT 5") == "MATCH p=(a)-[r]->(b) RETURN count(p)"
    assert Q.to_count("MATCH (n) RETURN n") is None


def test_inbound_and_sessions(client: BHClient) -> None:
    svc = EntityService(client)
    node = svc.resolve("jdoe", "User", "CORP.LOCAL")
    inbound = svc.inbound(node)[0].rows
    assert [(r.principal, r.edge, r.owned) for r in inbound] == [("HELPDESK@CORP.LOCAL", "ForceChangePassword", True)]
    sessions = svc.sessions(node)[0].rows
    assert [r.target for r in sessions] == ["WS01.CORP.LOCAL"]


def test_computer_privs_inbound_unrolls_group_members(client: BHClient) -> None:
    svc = EntityService(client)
    node = svc.resolve("WS01", "Computer")
    assert node.objectid == WS01
    held, inbound = svc.privs(node)
    assert held.key == "privs_held" and inbound.key == "privs_inbound"
    assert [(r.principal, r.via) for r in inbound.rows] == [
        ("IT ADMINS@CORP.LOCAL", "direct"), ("JDOE@CORP.LOCAL", "IT ADMINS@CORP.LOCAL")]


def test_members_view_applies_to_groups(client: BHClient) -> None:
    svc = EntityService(client)
    node = svc.resolve("IT Admins", "Group")
    assert node.objectid == IT_ADMINS
    assert "members" in svc.applicable_views(node)


def test_rest_fallback_when_cypher_disabled() -> None:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/graphs/cypher", status=404, body="404 page not found")
        rsps.add(responses.GET, f"{BASE}api/v2/search",
                 json={"data": [{"objectid": JDOE, "type": "User", "name": "JDOE@CORP.LOCAL"}]})
        rsps.add(responses.GET, f"{BASE}api/v2/users/{JDOE}",
                 json={"data": {"props": {"name": "JDOE@CORP.LOCAL", "objectid": JDOE, "domain": "CORP.LOCAL",
                                          "hasspn": True}}})
        rsps.add(responses.GET, f"{BASE}api/v2/users/{JDOE}/memberships",
                 json={"count": 1, "data": [{"objectID": IT_ADMINS, "name": "IT ADMINS@CORP.LOCAL", "label": "Group"}]})
        client = BHClient(BASE)
        client.set_jwt("t")
        svc = EntityService(client)
        node = svc.resolve("jdoe", "User")
        assert svc.cypher_available is False
        assert node.properties["hasspn"] is True
        view = svc.groups(node)[0]
        assert view.backend == "rest"
        assert [r.target for r in view.rows] == ["IT ADMINS@CORP.LOCAL"]


def test_rest_items_carry_tier_zero_kind() -> None:
    item = {"objectID": "S-1-5-21-1-512", "name": "DOMAIN ADMINS@CORP.LOCAL", "label": "Group",
            "kinds": ["Group", "Base", "Tag_Tier_Zero"]}
    node = Node.from_rest("", item)
    assert node.kind == "Group" and node.tier_zero


def test_owned_list(client: BHClient) -> None:
    svc = EntityService(client)
    nodes = MarkingService(client, svc).list("owned")
    assert [n.objectid for n in nodes] == [HELPDESK]


def test_marking_without_asset_group_tags_is_unsupported(client: BHClient,
                                                         mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags", status=404, body="404 page not found")
    svc = EntityService(client)
    with pytest.raises(UnsupportedFeature):
        MarkingService(client, svc).mark(svc.resolve("svc_sql", "User"), "owned")


def test_owned_add_and_remove(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags",
               json={"data": {"tags": [{"id": 1, "name": "Tier Zero", "type": 1, "position": 1},
                                       {"id": 2, "name": "Owned", "type": 3}]}})
    post = mocked.add(responses.POST, f"{BASE}api/v2/asset-group-tags/2/selectors", json={"data": {}})
    # Listed once before the add (not selected yet), then before the remove.
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags/2/selectors",
               json={"data": {"selectors": [{"id": 10, "seeds": [{"type": 1, "value": "S-1-other"}]}]}})
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags/2/selectors",
               json={"data": {"selectors": [{"id": 9, "seeds": [{"type": 1, "value": SVC_SQL}]},
                                            {"id": 10, "seeds": [{"type": 1, "value": "S-1-other"}]}]}})
    delete = mocked.add(responses.DELETE, f"{BASE}api/v2/asset-group-tags/2/selectors/9")
    svc = EntityService(client)
    marking = MarkingService(client, svc)
    node = svc.resolve("svc_sql", "User")
    marking.mark(node, "owned")
    assert post.call_count == 1
    assert b'"value": "' + SVC_SQL.encode() in post.calls[0].request.body
    marking.mark(node, "owned", add=False)
    assert delete.call_count == 1


def _owned_tag(mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags", json={"data": {"tags": [{"id": 2, "name": "Owned",
                                                                                           "type": 3}]}})


def test_owned_remove_keeps_selectors_shared_with_other_objects(client: BHClient,
                                                                mocked: responses.RequestsMock) -> None:
    _owned_tag(mocked)
    # Paged listing: selector 9 (only svc_sql) is on page 2, selector 11 also seeds another object.
    url = f"{BASE}api/v2/asset-group-tags/2/selectors"
    mocked.add(responses.GET, url, json={"count": 3, "data": {"selectors": [
        {"id": 11, "name": "Team picks", "seeds": [{"type": 1, "value": SVC_SQL}, {"type": 1, "value": "S-1-other"}]},
        {"id": 10, "name": "other", "seeds": [{"type": 1, "value": "S-1-other"}]}]}},
        match=[responses.matchers.query_param_matcher({"skip": "0", "limit": "2"})])
    mocked.add(responses.GET, url, json={"count": 3, "data": {"selectors": [
        {"id": 9, "name": "bhshell: SVC_SQL@CORP.LOCAL", "seeds": [{"type": 1, "value": SVC_SQL}]}]}},
        match=[responses.matchers.query_param_matcher({"skip": "2", "limit": "2"})])
    delete_9 = mocked.add(responses.DELETE, f"{url}/9")
    delete_11 = mocked.add(responses.DELETE, f"{url}/11")
    client.page_size = 2
    svc = EntityService(client)
    message = MarkingService(client, svc).mark(svc.resolve("svc_sql", "User"), "owned", add=False)
    assert delete_9.call_count == 1 and delete_11.call_count == 0
    assert "Team picks" in message


def test_owned_remove_deletes_every_matching_selector_across_pages(client: BHClient,
                                                                  mocked: responses.RequestsMock) -> None:
    # Deleting while paginating would shift the server's offsets and skip selectors.
    _owned_tag(mocked)
    url = f"{BASE}api/v2/asset-group-tags/2/selectors"
    selectors = [{"id": i, "seeds": [{"type": 1, "value": SVC_SQL}]} for i in range(5)]

    def listing(request: Any) -> tuple[int, dict[str, str], str]:
        query = parse_qs(urlparse(request.url).query)
        skip, limit = int(query["skip"][0]), int(query["limit"][0])
        return 200, {}, json.dumps({"count": len(selectors), "data": {"selectors": selectors[skip:skip + limit]}})

    def delete(request: Any) -> tuple[int, dict[str, str], str]:
        selectors[:] = [s for s in selectors if s["id"] != int(request.url.rsplit("/", 1)[1])]
        return 200, {}, ""

    mocked.add_callback(responses.GET, url, callback=listing)
    mocked.add_callback(responses.DELETE, re.compile(rf"{re.escape(url)}/\d+", re.IGNORECASE), callback=delete)
    client.page_size = 2
    svc = EntityService(client)
    message = MarkingService(client, svc).mark(svc.resolve("svc_sql", "User"), "owned", add=False)
    assert selectors == [] and "Removed 5 selector(s)" in message


def test_owned_add_is_a_no_op_when_a_selector_already_targets_the_object(client: BHClient,
                                                                         mocked: responses.RequestsMock) -> None:
    _owned_tag(mocked)
    url = f"{BASE}api/v2/asset-group-tags/2/selectors"
    mocked.add(responses.GET, url, json={"count": 1, "data": {"selectors": [
        {"id": 7, "name": "SVC_SQL@CORP.LOCAL", "seeds": [{"type": 1, "value": SVC_SQL}]}]}})
    post = mocked.add(responses.POST, url, json={"data": {}})
    svc = EntityService(client)
    message = MarkingService(client, svc).mark(svc.resolve("svc_sql", "User"), "owned")
    assert post.call_count == 0
    assert "already in 'Owned' (selector: SVC_SQL@CORP.LOCAL)" in message


def test_hvt_add_and_remove_respect_rule_based_tier_zero(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags",
               json={"data": {"tags": [{"id": 1, "name": "Tier Zero", "type": 1, "position": 1}]}})
    url = f"{BASE}api/v2/asset-group-tags/1/selectors"
    mocked.add(responses.GET, url, json={"count": 0, "data": {"selectors": []}})
    post = mocked.add(responses.POST, url, json={"data": {}})
    svc = EntityService(client)
    marking = MarkingService(client, svc)
    node = svc.resolve("svc_sql", "User")
    node.tier_zero = True  # selected by a rule (e.g. a group membership), not by a selector naming it
    assert "already in 'Tier Zero'" in marking.mark(node, "tier0")
    assert post.call_count == 0
    with pytest.raises(BHError, match="rule-based selector"):
        marking.mark(node, "tier0", add=False)


def test_owned_add_name_clash_is_explained(client: BHClient, mocked: responses.RequestsMock) -> None:
    _owned_tag(mocked)
    url = f"{BASE}api/v2/asset-group-tags/2/selectors"
    mocked.add(responses.GET, url, json={"count": 0, "data": {"selectors": []}})
    mocked.add(responses.POST, url, status=409,
               json={"errors": [{"message": "asset group tag selector name must be unique"}]})
    svc = EntityService(client)
    with pytest.raises(BHError, match="already exists in 'Owned' but does not target"):
        MarkingService(client, svc).mark(svc.resolve("svc_sql", "User"), "owned")


def test_owned_remove_refuses_when_only_shared_selectors_match(client: BHClient,
                                                               mocked: responses.RequestsMock) -> None:
    _owned_tag(mocked)
    mocked.add(responses.GET, f"{BASE}api/v2/asset-group-tags/2/selectors", json={"count": 1, "data": {"selectors": [
        {"id": 11, "name": "Team picks", "seeds": [{"type": 1, "value": SVC_SQL}, {"type": 1, "value": "S-1-x"}]}]}})
    delete = mocked.add(responses.DELETE, f"{BASE}api/v2/asset-group-tags/2/selectors/11")
    svc = EntityService(client)
    with pytest.raises(BHError, match="Team picks"):
        MarkingService(client, svc).mark(svc.resolve("svc_sql", "User"), "owned", add=False)
    assert delete.call_count == 0


def test_parse_cypher_args() -> None:
    args = parse_cypher_args("--json -o out.csv MATCH p=(a)-[:A|B]->(b) RETURN p")
    assert args.json and args.output == "out.csv"
    assert args.query == "MATCH p=(a)-[:A|B]->(b) RETURN p"
    quoted = parse_cypher_args('"MATCH (n) WHERE n.name = \'X\' RETURN n"')
    assert quoted.query == "MATCH (n) WHERE n.name = 'X' RETURN n"
