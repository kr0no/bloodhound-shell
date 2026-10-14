from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import responses

from bhshell.client.client import BHClient
from bhshell.errors import UnsupportedFeature
from bhshell.models.entities import Graph
from bhshell.queries.domains import DomainService, trusts_from_graph
from bhshell.queries.hunt import CHECKS, CHECKS_BY_ID, HuntOptions, HuntService
from bhshell.queries.library import BUILTIN_DIR, QueryLibrary, parse_cyp, query_dirs
from bhshell.queries.paths import PathService
from bhshell.queries.service import PATH_KINDS, EntityService
from bhshell.shell.app import BHShell
from tests.conftest import BASE, DOMAIN_ADMINS, IT_ADMINS, JDOE, graph, run


def g(nodes: list[str], edges: list[tuple[str, str, str]], **kw: Any) -> Graph:
    return Graph.from_cypher(graph(nodes, edges, **kw)["data"])


def test_graph_paths_keeps_only_shortest_chains_and_stops_at_targets() -> None:
    # 1 -> 2 -> 3(T) ; 1 -> 5 -> 3(T) ; 1 -> 4 -> 6 -> 3 (longer, dropped) ; 3 -> 7 (beyond target, ignored)
    graph_ = g(["1", "2", "3", "4", "5", "6", "7"], [
        ("1", "MemberOf", "2"), ("2", "MemberOf", "3"), ("1", "GenericAll", "5"), ("5", "AddMember", "3"),
        ("1", "AdminTo", "4"), ("4", "HasSession", "6"), ("6", "MemberOf", "3"), ("3", "GenericAll", "7"),
    ])
    chains = graph_.paths(["1"], ["3", "7"])
    assert sorted([e.kind for e in c] for c in chains) == [["GenericAll", "AddMember"], ["MemberOf", "MemberOf"]]


def test_graph_paths_respects_max_paths() -> None:
    graph_ = g(["1", "2", "3", "5"], [("1", "MemberOf", "2"), ("1", "GenericAll", "5"),
                                      ("2", "MemberOf", "3"), ("5", "AddMember", "3")])
    assert len(graph_.paths(["1"], ["3"], max_paths=1)) == 1


def test_shortest_path_via_rest(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/graphs/shortest-path",
               json=graph(["1", "2", "3"], [("1", "MemberOf", "2"), ("2", "MemberOf", "3")]))
    svc = EntityService(client)
    src = svc.resolve("jdoe", "User", "CORP.LOCAL")
    dst = svc.resolve(DOMAIN_ADMINS, kinds=PATH_KINDS)
    result = PathService(svc).shortest(src, dst)
    assert result.backend == "rest"
    assert [[h.edge for h in p.hops] for p in result.paths] == [["MemberOf", "MemberOf"]]
    assert result.paths[0].end.tier_zero


def test_shortest_path_not_found_is_empty(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/graphs/shortest-path", status=404,
               json={"errors": [{"message": "path not found"}]})
    svc = EntityService(client)
    node = svc.resolve("jdoe", "User", "CORP.LOCAL")
    assert PathService(svc).shortest(node, node).paths == []


def test_to_tier_zero_and_owned(client: BHClient) -> None:
    svc = EntityService(client)
    paths = PathService(svc)
    jdoe = svc.resolve("jdoe", "User", "CORP.LOCAL")
    result = paths.to_tier_zero(jdoe)
    assert [h.target.name for h in result.paths[0].hops] == ["IT ADMINS@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]

    owned = paths.owned_to_tier_zero()
    assert [h.edge for h in owned.paths[0].hops] == ["ForceChangePassword", "MemberOf", "MemberOf"]
    assert owned.paths[0].start.owned
    assert owned.rows()[0] == {"path": 1, "hop": 1, "source": "HELPDESK@CORP.LOCAL", "edge": "ForceChangePassword",
                               "target": "JDOE@CORP.LOCAL", "target_kind": "User", "tier_zero": False}


def _shortest_path_leg(mocked: responses.RequestsMock, start: str, end: str, **kw: Any) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/graphs/shortest-path",
               match=[responses.matchers.query_param_matcher({"start_node": start, "end_node": end})], **kw)


def test_route_chains_legs_through_waypoints(client: BHClient, mocked: responses.RequestsMock) -> None:
    _shortest_path_leg(mocked, JDOE, IT_ADMINS, json=graph(["1", "2"], [("1", "MemberOf", "2")]))
    _shortest_path_leg(mocked, IT_ADMINS, DOMAIN_ADMINS, json=graph(["2", "3"], [("2", "MemberOf", "3")]))
    svc = EntityService(client)
    jdoe = svc.resolve("jdoe", "User", "CORP.LOCAL")
    it_admins = svc.resolve("IT Admins", "Group")
    domain_admins = svc.resolve(DOMAIN_ADMINS, kinds=PATH_KINDS)

    result = PathService(svc).route(jdoe, [it_admins], domain_admins)
    assert result.title == "Shortest route: JDOE@CORP.LOCAL → IT ADMINS@CORP.LOCAL → DOMAIN ADMINS@CORP.LOCAL"
    assert result.backend == "rest"
    assert [[h.target.name for h in p.hops] for p in result.paths] == [["IT ADMINS@CORP.LOCAL",
                                                                        "DOMAIN ADMINS@CORP.LOCAL"]]

    # Without a destination the last leg goes to Tier Zero (Cypher), so the backends are mixed.
    to_t0 = PathService(svc).route(jdoe, [it_admins], None)
    assert to_t0.backend == "mixed"
    assert [h.target.name for h in to_t0.paths[0].hops] == ["IT ADMINS@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]


def test_route_stops_at_a_leg_without_path(client: BHClient, mocked: responses.RequestsMock) -> None:
    _shortest_path_leg(mocked, JDOE, IT_ADMINS, status=404, json={"errors": [{"message": "path not found"}]})
    svc = EntityService(client)
    jdoe = svc.resolve("jdoe", "User", "CORP.LOCAL")
    it_admins = svc.resolve("IT Admins", "Group")

    result = PathService(svc).route(jdoe, [it_admins], None)
    assert result.paths == []
    assert result.notes == ["No path from JDOE@CORP.LOCAL to IT ADMINS@CORP.LOCAL."]


def test_route_ends_at_tier_zero_waypoint(client: BHClient, mocked: responses.RequestsMock) -> None:
    _shortest_path_leg(mocked, JDOE, DOMAIN_ADMINS, json=graph(["1", "2", "3"], [("1", "MemberOf", "2"),
                                                                                  ("2", "MemberOf", "3")]))
    svc = EntityService(client)
    jdoe = svc.resolve("jdoe", "User", "CORP.LOCAL")
    domain_admins = svc.resolve(DOMAIN_ADMINS, kinds=PATH_KINDS)

    result = PathService(svc).route(jdoe, [domain_admins], None)
    assert len(result.paths) == 1 and result.paths[0].end.name == "DOMAIN ADMINS@CORP.LOCAL"
    assert "already Tier Zero" in result.notes[0]


def test_resolve_domain_for_paths(client: BHClient) -> None:
    node = EntityService(client).resolve("corp.local", kinds=PATH_KINDS)
    assert node.kind == "Domain"


def test_hunt_options_domain_filter() -> None:
    assert HuntOptions().dom("n") == ""
    assert HuntOptions(domain="corp.local").dom("n") == "n.domain = 'CORP.LOCAL'"
    assert HuntOptions(domain="corp").dom("n") == "(n.domain = 'CORP' OR n.domain STARTS WITH 'CORP.')"


def test_every_check_builds_a_query() -> None:
    for check in CHECKS:
        assert check.query(HuntOptions(domain="corp")).startswith("MATCH")


def test_hunt_kerberoastable_and_dcsync(client: BHClient) -> None:
    hunt = HuntService(EntityService(client))
    kerb = hunt.run(CHECKS_BY_ID["kerberoastable"], HuntOptions())
    assert [r["objectid"] for r in kerb.rows][:1] == [JDOE]
    dcsync = hunt.run(CHECKS_BY_ID["dcsync"], HuntOptions())
    by_name = {r["name"]: r for r in dcsync.rows}
    assert by_name["SVC_SQL@CORP.LOCAL"]["full_dcsync"] is True
    assert by_name["IT ADMINS@CORP.LOCAL"]["full_dcsync"] is False


def test_hunt_truncation_reports_server_total(client: BHClient) -> None:
    finding = HuntService(EntityService(client)).run(CHECKS_BY_ID["kerberoastable"], HuntOptions(limit=2))
    assert finding.truncated and finding.total == 7


def test_hunt_total_excludes_tier_zero(client: BHClient, mocked: responses.RequestsMock,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)

    def one_node(query: str) -> Graph:
        result = g(["2"], [])
        result.query = query
        return result

    monkeypatch.setattr(svc, "run_cypher", one_node)
    finding = HuntService(svc).run(CHECKS_BY_ID["no-laps"], HuntOptions(limit=1))
    count_queries = [json.loads(c.request.body)["query"] for c in mocked.calls if b"count(" in c.request.body]
    assert finding.truncated and finding.total == 7
    assert count_queries[-1] == ("MATCH (n:Computer) WHERE n.enabled = true AND n.haslaps = false "
                                 "AND NOT n:Tag_Tier_Zero RETURN count(n)")


def test_trust_domain_filter_matches_whole_labels() -> None:
    assert HuntOptions(domain="corp").matches("CORP.LOCAL")
    assert not HuntOptions(domain="corp").matches("CORPORATE.LOCAL")
    assert HuntOptions(domain="dev.corp.local").matches("DEV.CORP.LOCAL")
    assert not HuntOptions(domain="corp.local").matches("DEV.CORP.LOCAL")


def test_hunt_error_is_captured(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.replace(responses.POST, f"{BASE}api/v2/graphs/cypher", status=400,
                   json={"errors": [{"message": "unknown relationship kind"}]})
    finding = HuntService(EntityService(client)).run(CHECKS_BY_ID["adcs"], HuntOptions())
    assert finding.error == "HTTP 400: unknown relationship kind"


def test_trusts_from_graph() -> None:
    trusts = trusts_from_graph(g(["8", "9"], [
        ("8", "CrossForestTrust", "9"), ("9", "CrossForestTrust", "8"), ("8", "SpoofSIDHistory", "9")],
        edge_props={("8", "CrossForestTrust", "9"): {"spoofsidhistoryblocked": True, "trusttype": "Forest"}}))
    by_pair = {(t.trusting, t.trusted): t for t in trusts}
    corp_trusts_dev = by_pair[("CORP.LOCAL", "DEV.CORP.LOCAL")]
    assert corp_trusts_dev.sid_filtering is True and corp_trusts_dev.issues == []
    dev_trusts_corp = by_pair[("DEV.CORP.LOCAL", "CORP.LOCAL")]
    # SpoofSIDHistory 8 -> 9 means principals of CORP can abuse DEV, i.e. the DEV-trusts-CORP trust.
    assert dev_trusts_corp.abuse == ["SpoofSIDHistory"]
    assert dev_trusts_corp.issues == ["abusable: SpoofSIDHistory"]


@pytest.mark.parametrize("kind, props, expected", [
    ("CrossForestTrust", {}, []),  # property not collected: default is enforced, not a finding
    ("CrossForestTrust", {"spoofsidhistoryblocked": True}, []),
    ("CrossForestTrust", {"spoofsidhistoryblocked": False}, ["SID filtering disabled"]),
    ("SameForestTrust", {}, ["same forest: SID filtering not enforced"]),
    ("CrossForestTrust", {"tgtdelegation": True}, ["TGT delegation enabled"]),
])
def test_trust_issues_are_evidence_based(kind: str, props: dict[str, Any], expected: list[str]) -> None:
    (trust,) = trusts_from_graph(g(["8", "9"], [("8", kind, "9")], edge_props={("8", kind, "9"): props}))
    assert trust.issues == expected


def test_domains_overview(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/available-domains",
               json={"data": [{"type": "active-directory", "name": "CORP.LOCAL", "id": "S-1-5-21-1000",
                               "collected": True}]})
    infos = DomainService(EntityService(client)).domains()
    assert [d.name for d in infos] == ["CORP.LOCAL", "DEV.CORP.LOCAL"]
    assert infos[0].functional_level == "2016" and infos[0].collected is True
    assert infos[0].counts["users"] == 7


def test_domains_overview_without_cypher(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.replace(responses.POST, f"{BASE}api/v2/graphs/cypher", status=404, body="404 page not found")
    mocked.add(responses.GET, f"{BASE}api/v2/available-domains", json={"data": [
        {"type": "active-directory", "name": "CORP.LOCAL", "id": "S-1-5-21-1000", "collected": True},
        {"type": "azure", "name": "CORP TENANT", "id": "tenant-id", "collected": True}]})
    mocked.add(responses.GET, f"{BASE}api/v2/domains/S-1-5-21-1000", json={"data": {
        "users": 7, "computers": 2, "groups": 40, "props": {"functionallevel": "2016"}}})
    service = DomainService(EntityService(client))
    (info,) = service.domains()
    assert (info.name, info.functional_level, info.counts["users"], info.counts["enabled_users"]) == (
        "CORP.LOCAL", "2016", 7, None)
    assert service.notes and "Tier Zero" in service.notes[0]
    with pytest.raises(UnsupportedFeature, match="'trusts' needs the Cypher endpoint"):
        service.trusts()


def test_count_returns_none_without_literals(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.replace(responses.POST, f"{BASE}api/v2/graphs/cypher", json={"data": {"nodes": {}, "edges": []}})
    assert EntityService(client).count("MATCH (n) RETURN count(n)") is None


def test_parse_cyp_header_and_body() -> None:
    q = parse_cyp("// name: x\n// description: d\n\nMATCH (n)\nRETURN n\n", "file", "user")
    assert (q.name, q.description, q.query, q.source) == ("x", "d", "MATCH (n)\nRETURN n", "user")
    assert parse_cyp("MATCH (n) RETURN n", "stem", "builtin").name == "stem"


def test_library_merges_sources(client: BHClient, mocked: responses.RequestsMock, bhshell_home: Path) -> None:
    user_dir = bhshell_home / "queries"
    user_dir.mkdir(parents=True)
    (user_dir / "mine.cyp").write_text("// description: custom\nMATCH (n:User) RETURN n\n")
    (user_dir / "owned-objects.cyp").write_text("MATCH (n:Base) RETURN n LIMIT 1\n")  # overrides bundled
    mocked.add(responses.GET, f"{BASE}api/v2/saved-queries",
               json={"count": 1, "data": [{"name": "Team query", "query": "MATCH (n) RETURN n"}]})
    queries = QueryLibrary(client).load()
    assert queries["mine"].source == "user"
    assert queries["owned-objects"].source == "user"
    assert queries["server:Team query"].source == "server"
    assert queries["kerberoastable-users"].source == "builtin"


def test_library_loads_query_dirs_after_the_user_folder(client: BHClient, bhshell_home: Path, tmp_path: Path) -> None:
    (bhshell_home / "queries").mkdir(parents=True)
    (bhshell_home / "queries" / "shared.cyp").write_text("MATCH (n:User) RETURN n\n")
    team = tmp_path / "team"
    team.mkdir()
    (team / "shared.cyp").write_text("// description: team version\nMATCH (n:Group) RETURN n\n")
    (team / "team-only.cyp").write_text("MATCH (n:Computer) RETURN n\n")
    library = QueryLibrary(client, extra_dirs=query_dirs(f"{team}{os.pathsep} {tmp_path / 'missing'} "))
    queries = library.load(include_server=False)
    assert queries["shared"].description == "team version"  # later folders override earlier ones
    assert queries["team-only"].source == "user"
    assert library.notes == [f"Query folder {tmp_path / 'missing'} not found (see 'config query_dirs')."]


def test_query_dirs_setting_is_used_by_the_shell(shell: BHShell, tmp_path: Path) -> None:
    (tmp_path / "mine.cyp").write_text("// description: from my folder\nMATCH (n:User) RETURN n\n")
    run(shell, f"config query_dirs {tmp_path}")
    out = run(shell, "query list")
    assert "mine" in out and "from my folder" in out


@pytest.mark.parametrize("name", sorted(p.stem for p in BUILTIN_DIR.glob("*.cyp")))
def test_bundled_queries_are_well_formed(name: str) -> None:
    q = parse_cyp((BUILTIN_DIR / f"{name}.cyp").read_text(), name, "builtin")
    assert q.name == name and q.description and q.query.startswith("MATCH")


def test_path_actions_count_ignores_passive_hops(client: BHClient) -> None:
    # HELPDESK -ForceChangePassword-> JDOE -MemberOf-> IT ADMINS -MemberOf-> DOMAIN ADMINS
    owned = PathService(EntityService(client)).owned_to_tier_zero()
    path = owned.paths[0]
    assert len(path) == 3 and path.actions == 1  # the two MemberOf hops are free
    assert path.as_dict()["actions"] == 1


def test_path_rank_prefers_fewer_actions() -> None:
    from bhshell.models.entities import Node
    from bhshell.queries.paths import AttackPath, Hop, _rank

    def hop(edge: str) -> Hop:
        n = Node(id="x", objectid="x", kind="User", name="x")
        return Hop(n, edge, n)

    few_actions = AttackPath([hop("GenericAll"), hop("MemberOf"), hop("MemberOf")])  # 1 action, 3 hops
    many_actions = AttackPath([hop("GenericAll"), hop("ForceChangePassword")])        # 2 actions, 2 hops
    assert sorted([many_actions, few_actions], key=_rank) == [few_actions, many_actions]


def test_exclude_uses_cypher_and_filters_edges(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from bhshell.queries.edges import HAS_SESSION

    svc = EntityService(client)
    jdoe = svc.resolve("jdoe", "User", "CORP.LOCAL")
    queries: list[str] = []

    def answer(query: str) -> Graph:
        queries.append(query)
        if "allShortestPaths" not in query:  # e.g. the disabled-object check: no match
            empty = g([], [])
            empty.query = query
            return empty
        # A session hop leaks in despite the filter (as if the server ignored it); it must be dropped.
        result = g(["1", "2", "3", "4"], [("1", "MemberOf", "2"), ("2", "MemberOf", "3"),
                                          ("4", "HasSession", "1")])
        result.query = query
        return result

    monkeypatch.setattr(svc, "run_cypher", answer)
    result = PathService(svc, exclude={HAS_SESSION}).to_tier_zero(jdoe)
    assert all(h.edge != HAS_SESSION for p in result.paths for h in p.hops)
    assert queries and "HasSession" not in queries[0]  # the edge is left out of the traversable set


def test_shortest_with_excluded_edges_keeps_every_shortest_path(client: BHClient,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    jdoe, admins = svc.resolve("jdoe", "User", "CORP.LOCAL"), svc.resolve(DOMAIN_ADMINS)
    queries: list[str] = []

    def answer(query: str) -> Graph:
        queries.append(query)
        if "allShortestPaths" not in query:  # the disabled-object check: no match
            result = g([], [])
        else:  # two paths of two hops: through IT ADMINS, and through SVC_SQL
            result = g(["1", "2", "3", "5"], [("1", "MemberOf", "2"), ("2", "MemberOf", "3"),
                                              ("1", "GenericAll", "5"), ("5", "AddMember", "3")])
        result.query = query
        return result

    monkeypatch.setattr(svc, "run_cypher", answer)
    result = PathService(svc, exclude={"HasSession"}).shortest(jdoe, admins)
    assert len(result.paths) == 2
    searches = [q for q in queries if "allShortestPaths" in q]
    assert searches and all(q.endswith(f"LIMIT {svc.max_results}") for q in searches)


def test_owned_to_target(client: BHClient, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = EntityService(client)
    target = svc.resolve("IT Admins", "Group")

    queries: list[str] = []

    def answer(query: str) -> Graph:
        queries.append(query)
        if "allShortestPaths" not in query:  # e.g. the disabled-object check
            empty = g([], [])
            empty.query = query
            return empty
        result = g(["7", "1", "2"], [("7", "ForceChangePassword", "1"), ("1", "MemberOf", "2")])
        result.query = query
        return result

    monkeypatch.setattr(svc, "run_cypher", answer)
    result = PathService(svc).owned_to(target)
    assert any(f"t.objectid = '{IT_ADMINS}'" in q for q in queries)
    assert result.title == "Shortest paths: owned objects → IT ADMINS@CORP.LOCAL"
    assert result.paths[0].end.name == "IT ADMINS@CORP.LOCAL" and result.paths[0].start.owned
