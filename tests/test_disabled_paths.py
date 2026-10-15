from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import responses

from bhshell.client.client import BHClient
from bhshell.models.entities import Node
from bhshell.queries.paths import PathService
from bhshell.queries.service import EntityService
from tests.conftest import BASE, graph

CYPHER = f"{BASE}api/v2/graphs/cypher"


def node(oid: str, kind: str, name: str, *, enabled: bool | None = None, t0: bool = False,
         owned: bool = False, props: bool = True) -> dict[str, Any]:
    raw: dict[str, Any] = {"kind": kind, "kinds": ["Base", kind], "objectId": oid, "isTierZero": t0,
                           "isOwnedObject": owned}
    if props:
        raw["properties"] = {"name": name, "objectid": oid, **({} if enabled is None else {"enabled": enabled})}
    else:
        raw["label"] = name
    return raw


# SRC -ForceChangePassword-> MSATASK$ (disabled) -MemberOf-> DA (T0)   2 hops, cannot re-enable
# SRC -ForceChangePassword-> HELPER -AddMember-> IT -MemberOf-> DA     3 hops, all enabled
NODES = {
    "1": node("S-1", "User", "SRC@CORP.LOCAL", enabled=True),
    "2": node("S-2", "Computer", "_MSATASK$@CORP.LOCAL", enabled=False),
    "3": node("S-3", "Group", "DOMAIN ADMINS@CORP.LOCAL", t0=True),
    "4": node("S-4", "User", "HELPER@CORP.LOCAL", enabled=True),
    "5": node("S-5", "Group", "IT@CORP.LOCAL"),
}
EDGES = [("1", "ForceChangePassword", "2"), ("2", "MemberOf", "3"),
         ("1", "ForceChangePassword", "4"), ("4", "AddMember", "5"), ("5", "MemberOf", "3")]


def payload(node_ids: list[str], edges: list[tuple[str, str, str]], nodes: dict[str, Any] = NODES) -> str:
    return json.dumps(graph(node_ids, edges, nodes=nodes))


ALL = payload(list(NODES), EDGES)
# What a server applying the all(...) predicate returns: only the enabled route.
ENABLED_ONLY = payload(["1", "3", "4", "5"], EDGES[2:])


@pytest.fixture
def cypher(mocked: responses.RequestsMock) -> Callable[[Callable[[str], tuple[int, str]]], list[str]]:
    """Install a Cypher handler `query -> (status, body)`; returns the list of queries sent."""
    queries: list[str] = []

    def install(handler: Callable[[str], tuple[int, str]]) -> list[str]:
        def callback(request: Any) -> tuple[int, dict[str, str], str]:
            query = json.loads(request.body)["query"]
            queries.append(query)
            status, body = handler(query)
            return status, {}, body
        mocked.remove(responses.POST, CYPHER)
        mocked.add_callback(responses.POST, CYPHER, callback=callback)
        return queries
    return install


def src() -> Node:
    return Node.from_cypher("1", NODES["1"])


def hops(result: Any) -> list[list[str]]:
    return [[h.target.name for h in p.hops] for p in result.paths]


def test_search_also_runs_around_disabled_objects(client: BHClient, cypher: Any) -> None:
    # BloodHound rejects `endNode(r).enabled`: an unfiltered search is merged with one avoiding disabled objects.
    queries = cypher(lambda q: (200, ENABLED_ONLY if "n.enabled" in q else ALL))
    result = PathService(EntityService(client)).to_tier_zero(src())
    assert "n.enabled" not in queries[0] and "endNode(r)." not in queries[0]
    assert "all(n IN nodes(p) WHERE n.enabled IS NULL OR n.enabled = true OR n = s)" in queries[1]
    assert hops(result) == [["HELPER@CORP.LOCAL", "IT@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]
    assert result.skipped_disabled == ["_MSATASK$@CORP.LOCAL"]


def test_disabled_objects_are_dropped_locally_when_the_server_ignores_the_filter(
        client: BHClient, cypher: Any) -> None:
    cypher(lambda q: (200, ALL))
    result = PathService(EntityService(client)).to_tier_zero(src())
    # The shorter path through the disabled computer is gone; the enabled route remains.
    assert hops(result) == [["HELPER@CORP.LOCAL", "IT@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]
    assert result.skipped_disabled == ["_MSATASK$@CORP.LOCAL"]
    assert "without a right to re-enable them: _MSATASK$@CORP.LOCAL (--include-disabled" in result.notes[0]


@pytest.mark.parametrize("right", ["GenericAll", "GenericWrite", "Owns", "WriteDacl", "WriteOwner",
                                   "WriteAccountRestrictions"])
def test_disabled_object_reached_with_a_right_to_re_enable_it_is_kept(
        client: BHClient, cypher: Any, right: str) -> None:
    cypher(lambda q: (200, payload(list(NODES), [("1", right, "2"), *EDGES[1:]])))
    result = PathService(EntityService(client)).to_tier_zero(src())
    assert hops(result) == [["_MSATASK$@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]
    assert result.skipped_disabled == []


def test_enable_right_held_through_a_group_counts(client: BHClient, cypher: Any) -> None:
    # SRC -MemberOf-> IT -GenericAll-> MSATASK$ (disabled) -MemberOf-> DA
    cypher(lambda q: (200, payload(["1", "2", "3", "5"], [("1", "MemberOf", "5"), ("5", "GenericAll", "2"),
                                                           ("2", "MemberOf", "3")])))
    result = PathService(EntityService(client)).to_tier_zero(src())
    assert hops(result) == [["IT@CORP.LOCAL", "_MSATASK$@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]


def test_rejected_filter_falls_back_with_a_note(client: BHClient, cypher: Any) -> None:
    queries = cypher(lambda q: (400, '{"errors": [{"message": "unsupported"}]}') if "n.enabled" in q
                     else (200, ALL))
    result = PathService(EntityService(client)).to_tier_zero(src())
    assert "n.enabled" not in queries[0] and "n.enabled" in queries[1] and len(queries) == 2
    assert "MemberOf|" in queries[0]  # still the traversable-edge filter
    assert any("rejected the disabled-object filter" in n for n in result.notes)
    assert hops(result) == [["HELPER@CORP.LOCAL", "IT@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]


def test_include_disabled_allows_any_disabled_object(client: BHClient, cypher: Any) -> None:
    queries = cypher(lambda q: (200, ALL))
    result = PathService(EntityService(client), include_disabled=True).to_tier_zero(src())
    assert len(queries) == 1 and "n.enabled" not in queries[0]
    assert hops(result) == [["_MSATASK$@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]


def test_disabled_source_and_destination_are_kept(client: BHClient, mocked: Any, cypher: Any) -> None:
    nodes = {**NODES, "1": node("S-1", "User", "SRC@CORP.LOCAL", enabled=False),
             "3": node("S-3", "User", "DST@CORP.LOCAL", enabled=False)}
    mocked.add(responses.GET, f"{BASE}api/v2/graphs/shortest-path",
               body=payload(["1", "4", "5", "3"], EDGES[2:4] + [("5", "GenericAll", "3")], nodes))
    cypher(lambda q: (200, payload([], [])))
    result = PathService(EntityService(client)).shortest(Node.from_cypher("1", nodes["1"]),
                                                         Node.from_cypher("3", nodes["3"]))
    assert hops(result) == [["HELPER@CORP.LOCAL", "IT@CORP.LOCAL", "DST@CORP.LOCAL"]]


def test_rest_result_without_properties_is_checked_and_retried_via_cypher(
        client: BHClient, mocked: Any, cypher: Any) -> None:
    bare = {k: node(v["objectId"], v["kind"], v["properties"]["name"], t0=v["isTierZero"], props=False)
            for k, v in NODES.items()}
    mocked.add(responses.GET, f"{BASE}api/v2/graphs/shortest-path",
               body=payload(["1", "2", "3"], EDGES[:2], bare))

    def handler(q: str) -> tuple[int, str]:
        if "n.objectid IN [" in q:
            return 200, payload(["2"], [])
        if "allShortestPaths(" in q and "n.enabled" in q:
            return 200, ENABLED_ONLY
        return 404, "{}"
    queries = cypher(handler)
    dst = Node.from_cypher("3", NODES["3"])
    result = PathService(EntityService(client)).shortest(src(), dst)
    assert "'S-2'" in queries[0] and "'S-1'" in queries[0]  # users/computers only
    assert result.backend == "cypher" and result.skipped_disabled == ["_MSATASK$@CORP.LOCAL"]
    assert hops(result) == [["HELPER@CORP.LOCAL", "IT@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]]
    assert any("n.enabled = true OR n = s OR n = t)" in q for q in queries)
    assert sum("Skipped paths through" in n for n in result.notes) == 1


def test_tier_zero_paths_stop_at_the_first_tier_zero_object(client: BHClient, cypher: Any) -> None:
    queries = cypher(lambda q: (200, ALL))
    PathService(EntityService(client), include_disabled=True).to_tier_zero(src())
    assert "all(n IN nodes(p) WHERE n = t OR NOT n:Tag_Tier_Zero)" in queries[0]


def test_tier_zero_stop_condition_is_dropped_when_rejected(client: BHClient, cypher: Any) -> None:
    queries = cypher(lambda q: (400, '{"errors": [{"message": "unsupported"}]}') if "n = t OR" in q
                     else (200, ALL))
    result = PathService(EntityService(client), include_disabled=True).to_tier_zero(src())
    assert "n = t OR" not in queries[-1] and result.paths


def test_hunt_path_to_tier_zero_skips_disabled_objects_like_path(client: BHClient, cypher: Any) -> None:
    # Only route: SRC -ForceChangePassword-> MSATASK$ (disabled) -MemberOf-> DA
    cypher(lambda q: (200, payload(["1", "2", "3"], EDGES[:2])))
    reach, notes = PathService(EntityService(client)).reaching_tier_zero(["S-1"])
    assert reach == set() and notes == []
