from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest
import responses

from bhshell.client.client import BHClient
from bhshell.errors import AmbiguousMatchError
from bhshell.models.entities import Graph, Node
from bhshell.queries import cypher as Q
from bhshell.queries.containers import (
    GPO_TARGET_KINDS,
    NO_TREE_DATA,
    Counts,
    applied_gpos,
    dn_location,
    parent_dn,
    short_name,
    stale_contains,
)
from bhshell.queries.edges import GPO_EDIT_EDGES
from bhshell.queries.gpos import reach
from bhshell.queries.service import EntityService, parse_identifier
from bhshell.shell.app import BHShell
from tests.conftest import BASE, L, graph, run

CYPHER = f"{BASE}api/v2/graphs/cypher"
DOM = "S-1-5-21-1000"
SERVERS, WEB, STAFF, STAFF2, USERS, SYSTEM = (f"0000000{i}-0000-0000-0000-000000000000" for i in range(1, 7))
DDP, WALLPAPER, SRVBASE, WEBGPO = (f"1000000{i}-0000-0000-0000-000000000000" for i in range(1, 5))
WEB01, SQL01, JDOE, HELPDESK = f"{DOM}-2001", f"{DOM}-2002", f"{DOM}-1104", f"{DOM}-1106"


def node(oid: str, kind: str, name: str, dn: str = "", *, t0: bool = False, owned: bool = False,
         **props: Any) -> dict[str, Any]:
    kinds = ["Base", kind, *(["Tag_Tier_Zero"] if t0 else []), *(["Tag_Owned"] if owned else [])]
    return {"kind": kind, "kinds": kinds, "objectId": oid, "isTierZero": t0, "isOwnedObject": owned,
            "properties": {"name": name, "objectid": oid, "domain": "CORP.LOCAL",
                           **({"distinguishedname": dn} if dn else {}), **props}}


# CORP.LOCAL                      GPO links: DEFAULT DOMAIN POLICY (enforced), WALLPAPER
# ├─ SERVERS (blocks inheritance) GPO link:  SERVER BASELINE
# │  ├─ WEB                       GPO link:  WEB HARDENING (editable by HELPDESK, owned)
# │  │  └─ WEB01
# │  ├─ STAFF                     (same name as the top-level STAFF)
# │  └─ SQL01 (Tier Zero)
# ├─ STAFF
# │  └─ JDOE
# ├─ USERS (container)
# │  └─ HELPDESK (owned)
# └─ SYSTEM (empty container)
NODES = {
    "d": node(DOM, "Domain", "CORP.LOCAL", "DC=CORP,DC=LOCAL", t0=True),
    "s": node(SERVERS, "OU", "SERVERS@CORP.LOCAL", "OU=SERVERS,DC=CORP,DC=LOCAL", blocksinheritance=True),
    "w": node(WEB, "OU", "WEB@CORP.LOCAL", "OU=WEB,OU=SERVERS,DC=CORP,DC=LOCAL", blocksinheritance=False),
    "st": node(STAFF, "OU", "STAFF@CORP.LOCAL", "OU=STAFF,DC=CORP,DC=LOCAL"),
    "st2": node(STAFF2, "OU", "STAFF@CORP.LOCAL", "OU=STAFF,OU=SERVERS,DC=CORP,DC=LOCAL"),
    "u": node(USERS, "Container", "USERS@CORP.LOCAL", "CN=USERS,DC=CORP,DC=LOCAL"),
    "sys": node(SYSTEM, "Container", "SYSTEM@CORP.LOCAL", "CN=SYSTEM,DC=CORP,DC=LOCAL"),
    "web01": node(WEB01, "Computer", "WEB01.CORP.LOCAL", "CN=WEB01,OU=WEB,OU=SERVERS,DC=CORP,DC=LOCAL",
                  samaccountname="WEB01$", enabled=True),
    "sql01": node(SQL01, "Computer", "SQL01.CORP.LOCAL", "CN=SQL01,OU=SERVERS,DC=CORP,DC=LOCAL", t0=True,
                  samaccountname="SQL01$", enabled=True),
    "jdoe": node(JDOE, "User", "JDOE@CORP.LOCAL", "CN=JDOE,OU=STAFF,DC=CORP,DC=LOCAL", enabled=False),
    "helpdesk": node(HELPDESK, "User", "HELPDESK@CORP.LOCAL", "CN=HELPDESK,CN=USERS,DC=CORP,DC=LOCAL",
                     owned=True, enabled=True),
    "ddp": node(DDP, "GPO", "DEFAULT DOMAIN POLICY@CORP.LOCAL", t0=True),
    "wall": node(WALLPAPER, "GPO", "WALLPAPER@CORP.LOCAL"),
    "srv": node(SRVBASE, "GPO", "SERVER BASELINE@CORP.LOCAL"),
    "webgpo": node(WEBGPO, "GPO", "WEB HARDENING@CORP.LOCAL"),
}
ENFORCED = {"enforced": True}
DOMAIN_LINKS = [("ddp", "GPLink", "d"), ("wall", "GPLink", "d")]
LINK_PROPS = {("ddp", "GPLink", "d"): ENFORCED}


def tree(*ids: str, edges: list[tuple[str, str, str]], props: dict[Any, Any] | None = None) -> dict[str, Any]:
    return graph(list(ids), edges, props, nodes=NODES)


def literals(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"data": {"nodes": {}, "edges": [], "literals": [{"key": k, "value": v} for r in rows for k, v in r.items()]}}


def counts(parent: str, kind: str, total: int, enabled: bool | None = None, *tags: str) -> dict[str, Any]:
    return {"parent": parent, "kinds": ["Base", kind, *tags], "enabled": enabled, "total": total}


RESULTS: dict[str, dict[str, Any]] = {
    Q.by_name(Q.name_conditions("SERVERS", "SERVERS@CORP.LOCAL", None), None, 100): tree("s", edges=[]),
    Q.by_name(Q.name_conditions("STAFF", None, None), None, 100): tree("st", "st2", edges=[]),
    Q.by_name([Q.dn_condition("OU=STAFF,OU=SERVERS,DC=CORP,DC=LOCAL")], None, 100): tree("st2", edges=[]),
    Q.by_name(Q.name_conditions("corp.local", "CORP.LOCAL", None), None, 100): tree("d", edges=[]),
    Q.by_name(Q.name_conditions("WEB01", None, "Computer"), "Computer", 100): tree("web01", edges=[]),
    Q.by_name(Q.name_conditions("jdoe", None, "User"), "User", 100): tree("jdoe", edges=[]),
    # WEB01
    Q.containers_above(WEB01): tree("d", "s", "w", "web01", edges=[
        ("d", "Contains", "s"), ("s", "Contains", "w"), ("w", "Contains", "web01")]),
    Q.gp_links_above(WEB01): tree("d", "s", "w", "web01", "ddp", "wall", "srv", "webgpo", edges=[
        *DOMAIN_LINKS, ("srv", "GPLink", "s"), ("webgpo", "GPLink", "w"),
        ("d", "Contains", "s"), ("s", "Contains", "w"), ("w", "Contains", "web01")], props=LINK_PROPS),
    Q.controllers_outside_t0({DDP, SRVBASE, WEBGPO, WALLPAPER}, GPO_EDIT_EDGES, L): tree(
        "helpdesk", "jdoe", "webgpo", edges=[("helpdesk", "GenericWrite", "webgpo"), ("jdoe", "Owns", "webgpo")]),
    # SERVERS
    Q.containers_above(SERVERS): tree("d", "s", edges=[("d", "Contains", "s")]),
    Q.gp_links_above(SERVERS): tree("d", "s", "ddp", "wall", edges=[*DOMAIN_LINKS, ("d", "Contains", "s")],
                                    props=LINK_PROPS),
    Q.gp_links_to(SERVERS): tree("s", "srv", edges=[("srv", "GPLink", "s")]),
    Q.controllers_outside_t0({DDP, SRVBASE}, GPO_EDIT_EDGES, L): tree(edges=[]),
    Q.contained_counts(SERVERS, nested=False): literals(
        counts(SERVERS, "OU", 2), counts(SERVERS, "Computer", 1, True, "Tag_Tier_Zero")),
    Q.contained_counts(SERVERS, nested=True): literals(counts(WEB, "Computer", 1, True)),
    Q.sub_containers(SERVERS, L): tree("s", "w", "st2", edges=[("s", "Contains", "w"), ("s", "Contains", "st2")]),
    Q.gp_link_counts(SERVERS): literals({"parent": WEB, "total": 1}),
    Q.contained_objects(SERVERS, L): tree("s", "w", "web01", "sql01", edges=[
        ("s", "Contains", "w"), ("w", "Contains", "web01"), ("s", "Contains", "sql01")]),
    # CORP.LOCAL
    Q.sub_containers(DOM, L): tree("d", "s", "w", "st", "st2", "u", "sys", edges=[
        ("d", "Contains", "s"), ("s", "Contains", "w"), ("s", "Contains", "st2"), ("d", "Contains", "st"),
        ("d", "Contains", "u"), ("d", "Contains", "sys")]),
    Q.contained_counts(DOM, nested=False): literals(counts(DOM, "OU", 2), counts(DOM, "Container", 2)),
    Q.contained_counts(DOM, nested=True): literals(
        counts(SERVERS, "OU", 2), counts(SERVERS, "Computer", 1, True, "Tag_Tier_Zero"),
        counts(WEB, "Computer", 1, True), counts(STAFF, "User", 1, False),
        counts(USERS, "User", 1, True, "Tag_Owned")),
    Q.gp_links_to(DOM): tree("d", "ddp", "wall", edges=DOMAIN_LINKS, props=LINK_PROPS),
    Q.gp_link_counts(DOM): literals({"parent": SERVERS, "total": 1}, {"parent": WEB, "total": 1}),
    # JDOE: in a domain collected without containers
    # GPOs
    Q.by_name(Q.name_conditions("WALLPAPER", None, None), None, 100): tree("wall", edges=[]),
    Q.gp_links_from(WALLPAPER): tree("wall", "d", edges=[("wall", "GPLink", "d")]),
    Q.children_of({DOM, STAFF, USERS, SYSTEM}, GPO_TARGET_KINDS, L): tree("st", "u", "jdoe", "helpdesk", edges=[
        ("st", "Contains", "jdoe"), ("u", "Contains", "helpdesk")]),
    Q.by_name(Q.name_conditions("WEB HARDENING", "WEB HARDENING@CORP.LOCAL", None), None, 100): tree(
        "webgpo", edges=[]),
    Q.gp_links_from(WEBGPO): tree("webgpo", "w", edges=[("webgpo", "GPLink", "w")]),
    Q.contained_counts(WEB, nested=False): literals(counts(WEB, "Computer", 1, True)),
    Q.controllers_outside_t0({WEBGPO}, GPO_EDIT_EDGES, L): tree(
        "helpdesk", "jdoe", "webgpo", edges=[("helpdesk", "GenericWrite", "webgpo"), ("jdoe", "Owns", "webgpo")]),
    Q.children_of({WEB}, GPO_TARGET_KINDS, L): tree("w", "web01", edges=[("w", "Contains", "web01")]),
}


# Queries the server rejects (an unknown edge kind, unsupported aggregates, ...); set per test.
REJECTED: set[str] = set()


@pytest.fixture
def directory(mocked: responses.RequestsMock) -> list[str]:
    """Serve the directory above; returns the Cypher queries sent."""
    queries: list[str] = []
    REJECTED.clear()

    def callback(request: Any) -> tuple[int, dict[str, str], str]:
        query = json.loads(request.body)["query"]
        queries.append(query)
        if query in REJECTED:
            return 400, {}, json.dumps({"errors": [{"message": "not supported"}]})
        if query in RESULTS:
            return 200, {}, json.dumps(RESULTS[query])
        if "RETURN count(" in query:
            return 200, {}, json.dumps(literals({"count(p)": 0}))
        return 404, {}, json.dumps({"errors": [{"message": "resource not found"}]})

    mocked.remove(responses.POST, CYPHER)
    mocked.add_callback(responses.POST, CYPHER, callback=callback)
    return queries


@pytest.fixture
def svc(client: BHClient, directory: list[str]) -> EntityService:
    return EntityService(client, max_results=L)


def ou(svc: EntityService, name: str) -> Node:
    return svc.resolve(name, kinds=("OU", "Container", "Domain"))


def test_distinguished_names_are_parsed_and_normalised() -> None:
    ident = parse_identifier("OU=Web, OU=Servers,DC=corp,DC=local")
    assert ident.dn == "OU=WEB,OU=SERVERS,DC=CORP,DC=LOCAL" and not ident.sam


def test_short_name_reads_the_first_rdn() -> None:
    user = Node.from_cypher("1", node("x", "User", "DOE@CORP.LOCAL", "CN=DOE\\, JOHN,OU=STAFF,DC=CORP,DC=LOCAL"))
    assert short_name(user) == "DOE, JOHN"
    assert short_name(Node.from_cypher("2", NODES["d"])) == "CORP.LOCAL"


def test_same_named_ous_are_told_apart_by_dn(svc: EntityService) -> None:
    with pytest.raises(AmbiguousMatchError) as exc:
        ou(svc, "STAFF")
    assert "distinguished name" in exc.value.hint
    assert ou(svc, "OU=Staff,OU=Servers,DC=corp,DC=local").objectid == STAFF2


def test_ambiguous_ou_lists_distinguished_names(shell: BHShell, directory: list[str]) -> None:
    run(shell, "login -u admin")
    out = run(shell, "ou STAFF")
    assert "OU=STAFF,OU=SERVERS,DC=CORP,DC=LOCAL" in out and "OU=STAFF,DC=CORP,DC=LOCAL" in out


def _gpo_graph(edges: list[tuple[str, str, str]], props: dict[Any, Any]) -> Graph:
    return Graph.from_cypher(graph(list(NODES), edges, props, nodes=NODES)["data"])


def test_gpo_precedence_blocking_and_enforcement() -> None:
    levels = [Node.from_cypher(k, NODES[k]) for k in ("d", "s", "w")]
    g = _gpo_graph([*DOMAIN_LINKS, ("srv", "GPLink", "s"), ("webgpo", "GPLink", "w"), ("ddp", "GPLink", "w")],
                   LINK_PROPS)
    rows = [(r.gpo.split("@")[0], r.linked_to, r.applies, r.reason) for r in applied_gpos(levels, g)]
    assert rows == [
        # Enforced first; SERVERS blocks inheritance, but not of enforced links.
        ("DEFAULT DOMAIN POLICY", "CORP.LOCAL", True, ""),
        # Then the closest link first.
        ("DEFAULT DOMAIN POLICY", "WEB@CORP.LOCAL", True, "duplicate: already applied through CORP.LOCAL"),
        ("WEB HARDENING", "WEB@CORP.LOCAL", True, ""),
        ("SERVER BASELINE", "SERVERS@CORP.LOCAL", True, ""),
        ("WALLPAPER", "CORP.LOCAL", False, "inheritance blocked at SERVERS"),
    ]


def test_computer_gpos_view_lists_editors_outside_tier_zero(svc: EntityService) -> None:
    computer = svc.resolve("WEB01", "Computer")
    view = svc.view(computer, "gpos")[0]
    assert [r.gpo for r in view.rows][:3] == [
        "DEFAULT DOMAIN POLICY@CORP.LOCAL", "WEB HARDENING@CORP.LOCAL", "SERVER BASELINE@CORP.LOCAL"]
    web = view.rows[1]
    assert web.editable_by == ["HELPDESK@CORP.LOCAL (owned)", "JDOE@CORP.LOCAL"]  # owned first
    assert web.as_display()["applies"] == "yes"
    assert view.rows[-1].as_display()["applies"] == "no (inheritance blocked at SERVERS)"


def test_editor_query_falls_back_when_an_edge_kind_is_rejected(svc: EntityService, directory: list[str],
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    gpos = {DDP, SRVBASE, WEBGPO, WALLPAPER}
    filtered, unfiltered = (Q.controllers_outside_t0(gpos, edges, L) for edges in (GPO_EDIT_EDGES, None))
    REJECTED.add(filtered)
    # Unfiltered, the server also returns edges that do not allow editing: they are dropped.
    monkeypatch.setitem(RESULTS, unfiltered, tree("helpdesk", "jdoe", "u", "webgpo", "srv", edges=[
        ("helpdesk", "GenericWrite", "webgpo"), ("jdoe", "Owns", "webgpo"), ("u", "Contains", "srv")]))
    view = svc.view(svc.resolve("WEB01", "Computer"), "gpos")[0]
    assert directory[-2:] == [filtered, unfiltered]
    assert view.rows[1].editable_by == ["HELPDESK@CORP.LOCAL (owned)", "JDOE@CORP.LOCAL"]
    assert all(not r.editable_by for r in view.rows if r.objectid != WEBGPO)


def test_object_without_ou_data_says_so(svc: EntityService) -> None:
    view = svc.view(svc.resolve("jdoe", "User"), "gpos")[0]
    assert not view.rows and view.notes == [NO_TREE_DATA]


def test_tree_counts_cover_each_subtree_and_hide_empty_containers(svc: EntityService) -> None:
    view = svc.view(ou(svc, "corp.local"), "tree")[0]
    rows = {r.label: r for r in view.rows}
    assert list(rows) == ["CORP.LOCAL", "├─ SERVERS", "│  ├─ STAFF", "│  └─ WEB", "├─ STAFF", "└─ USERS"]
    top, servers = rows["CORP.LOCAL"], rows["├─ SERVERS"]
    assert (top.users, top.enabled_users, top.computers, top.tier_zero_below, top.owned_below) == (2, 1, 2, 1, 1)
    assert (servers.computers, servers.tier_zero_below, servers.blocks_inheritance) == (2, 1, True)
    assert top.gpo_links == 2 and rows["│  └─ WEB"].gpo_links == 1
    assert view.notes == ["1 empty container(s) hidden."]
    assert rows["├─ SERVERS"].as_display()["computers"] == "2 (2)"


def test_tree_without_aggregates_shows_no_counts(svc: EntityService) -> None:
    REJECTED.update({Q.contained_counts(DOM, nested=False), Q.contained_counts(DOM, nested=True)})
    view = svc.view(ou(svc, "corp.local"), "tree")[0]
    assert len(view.rows) == 7  # nothing hidden: emptiness is unknown
    assert view.rows[0].users is None
    assert "aggregate queries" in view.notes[0]


def test_contents_lists_objects_with_their_location(svc: EntityService) -> None:
    view = svc.view(ou(svc, "SERVERS@CORP.LOCAL"), "contents")[0]
    assert [(r.name, r.location, r.depth, r.tier_zero) for r in view.rows] == [
        ("SQL01.CORP.LOCAL", "direct", 1, True),  # Tier Zero first
        ("WEB01.CORP.LOCAL", "WEB", 2, False),
    ]


def test_ou_summary_and_views_from_the_shell(shell: BHShell, directory: list[str], tmp_path: Path) -> None:
    run(shell, "login -u admin")
    out = run(shell, "ou SERVERS@corp.local")
    for expected in ("OU=SERVERS,DC=CORP,DC=LOCAL", "Blocks GPO Inheritance", "Location", "CORP.LOCAL",
                     "Computers below (enabled)", "2 (2)", "Tier Zero objects below", "SERVER BASELINE@CORP.LOCAL"):
        assert expected in out
    target = tmp_path / "servers.csv"
    out = run(shell, f"ou SERVERS@corp.local --all -o {target}")
    assert "OU tree" in out and "Objects below" in out and "GPOs applied" in out and "Inbound" in out
    rows = list(csv.DictReader(target.open()))
    assert {r["view"] for r in rows} >= {"tree", "contents", "gpos"}
    assert {"location", "linked_to", "users"} <= set(rows[0])


def test_user_gpos_flag(shell: BHShell, directory: list[str]) -> None:
    run(shell, "login -u admin")
    out = run(shell, "computer WEB01 -G")
    assert "WEB HARDENING@CORP.LOCAL" in out and "HELPDESK@CORP.LOCAL (owned)" in out
    assert "Group memberships" not in out


def test_rest_fallback_when_cypher_is_disabled() -> None:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.POST, CYPHER, status=404, body="404 page not found")
        rsps.add(responses.GET, f"{BASE}api/v2/search", json={"data": [
            {"objectid": SERVERS, "type": "OU", "name": "SERVERS@CORP.LOCAL",
             "distinguishedname": "OU=SERVERS,DC=CORP,DC=LOCAL"}]})
        rsps.add(responses.GET, f"{BASE}api/v2/ous/{SERVERS}", json={"data": {
            "computers": 2, "users": 0, "groups": 0, "gpos": 3, "props": NODES["s"]["properties"]}})
        rsps.add(responses.GET, f"{BASE}api/v2/ous/{SERVERS}/computers", json={"count": 1, "data": [
            {"objectID": SQL01, "name": "SQL01.CORP.LOCAL", "label": "Computer",
             "kinds": ["Computer", "Base", "Tag_Tier_Zero"]}]})
        rsps.add(responses.GET, f"{BASE}api/v2/ous/{SERVERS}/users", json={"count": 0, "data": []})
        rsps.add(responses.GET, f"{BASE}api/v2/ous/{SERVERS}/groups", json={"count": 0, "data": []})
        client = BHClient(BASE)
        client.set_jwt("t")
        svc = EntityService(client)
        node = svc.resolve("OU=SERVERS,DC=CORP,DC=LOCAL", kinds=("OU", "Container", "Domain"))
        assert node.objectid == SERVERS and svc.cypher_available is False
        report = svc.report(node, ["tree", "contents"], show_summary=True)
        assert {f.label: f.value for f in report.extra}["Computers below"] == 2
        tree_view, contents = report.views
        assert tree_view.backend == "rest" and not tree_view.rows and "needs Cypher" in tree_view.notes[-1]
        assert [(r.name, r.tier_zero) for r in contents.rows] == [("SQL01.CORP.LOCAL", True)]


def test_gpo_reach_stops_at_blocked_inheritance_unless_enforced() -> None:
    g = Graph.from_cypher(RESULTS[Q.sub_containers(DOM, L)]["data"])
    domain = g.find(DOM)
    assert domain
    reached, blocked = reach(domain, g, enforced=False)
    assert reached == {DOM, STAFF, USERS, SYSTEM} and [n.objectid for n in blocked] == [SERVERS]
    reached, blocked = reach(domain, g, enforced=True)
    assert len(reached) == 7 and not blocked


def test_gpo_summary_counts_only_what_the_links_reach(svc: EntityService) -> None:
    gpo = svc.resolve("WALLPAPER", kinds=("GPO",))
    fields = {f.label: f.value for f in svc.report(gpo, [], show_summary=True).extra}
    assert fields["Linked to"] == ["CORP.LOCAL"]
    assert fields["Stopped by blocked inheritance at"] == ["CORP.LOCAL/SERVERS"]
    # WEB01 and SQL01 sit below SERVERS, which blocks inheritance.
    assert fields["Computers affected (enabled)"] == "0 (0)"
    assert fields["Users affected (enabled)"] == "2 (1)"
    assert fields["Owned users / computers affected"] == 1
    assert fields["Editable by (outside Tier Zero)"] == "nobody"


def test_gpo_links_and_affected_views(svc: EntityService) -> None:
    gpo = svc.resolve("WALLPAPER", kinds=("GPO",))
    links, affected = (svc.view(gpo, key)[0] for key in ("links", "affected"))
    link = links.rows[0]
    assert (link.linked_to, link.enforced, link.users, link.computers, link.blocked_at) == (
        "CORP.LOCAL", None, 2, 0, ["CORP.LOCAL/SERVERS"])
    assert [(r.name, r.location, r.depth) for r in affected.rows] == [
        ("HELPDESK@CORP.LOCAL", "CORP.LOCAL/USERS", 2),  # owned first
        ("JDOE@CORP.LOCAL", "CORP.LOCAL/STAFF", 2),
    ]


def test_gpo_from_the_shell(shell: BHShell, directory: list[str]) -> None:
    run(shell, "login -u admin")
    out = run(shell, "gpo 'WEB HARDENING@corp.local'")
    for expected in ("WEB@CORP.LOCAL", "Computers affected (enabled)", "1 (1)", "HELPDESK@CORP.LOCAL (owned)"):
        assert expected in out
    out = run(shell, "gpo 'WEB HARDENING@corp.local' -c")
    assert "WEB01.CORP.LOCAL" in out and "Linked to" not in out


def test_gpo_rest_fallback_uses_bloodhound_lists() -> None:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.POST, CYPHER, status=404, body="404 page not found")
        rsps.add(responses.GET, f"{BASE}api/v2/search", json={"data": [
            {"objectid": WEBGPO, "type": "GPO", "name": "WEB HARDENING@CORP.LOCAL"}]})
        rsps.add(responses.GET, f"{BASE}api/v2/gpos/{WEBGPO}", json={"data": {
            "computers": 1, "users": 0, "ous": 1, "controllers": 2, "props": NODES["webgpo"]["properties"]}})
        rsps.add(responses.GET, f"{BASE}api/v2/gpos/{WEBGPO}/computers", json={"count": 1, "data": [
            {"objectID": WEB01, "name": "WEB01.CORP.LOCAL", "label": "Computer", "kinds": ["Computer", "Base"]}]})
        rsps.add(responses.GET, f"{BASE}api/v2/gpos/{WEBGPO}/users", json={"count": 0, "data": []})
        client = BHClient(BASE)
        client.set_jwt("t")
        svc = EntityService(client)
        gpo = svc.resolve("WEB HARDENING@corp.local", kinds=("GPO",))
        report = svc.report(gpo, ["links", "affected"], show_summary=True)
        assert {f.label: f.value for f in report.extra}["Computers affected"] == 1
        links, affected = report.views
        assert not links.rows and "needs Cypher" in links.notes[-1]
        assert [r.name for r in affected.rows] == ["WEB01.CORP.LOCAL"]


def test_dn_location_reads_the_dn_from_the_domain_down() -> None:
    web = Node.from_cypher("w", NODES["w"])
    assert dn_location(web) == "CORP.LOCAL/SERVERS/WEB"
    assert dn_location(Node.from_cypher("d", NODES["d"])) == "CORP.LOCAL"
    odd = Node.from_cypher("x", node("x", "OU", "A@CORP.LOCAL", "OU=A\\, B,DC=CORP,DC=LOCAL"))
    assert dn_location(odd) == "CORP.LOCAL/A, B"
    assert dn_location(Node.from_cypher("g", NODES["ddp"])) == "DEFAULT DOMAIN POLICY@CORP.LOCAL"  # no DN


def test_gpo_rows_say_where_each_link_sits() -> None:
    levels = [Node.from_cypher(k, NODES[k]) for k in ("d", "s", "w")]
    g = _gpo_graph([*DOMAIN_LINKS, ("webgpo", "GPLink", "w"), ("ddp", "GPLink", "w")], LINK_PROPS)
    rows = {(r.gpo.split("@")[0], r.location): r for r in applied_gpos(levels, g)}
    assert ("WEB HARDENING", "CORP.LOCAL/SERVERS/WEB") in rows
    assert rows[("DEFAULT DOMAIN POLICY", "CORP.LOCAL/SERVERS/WEB")].reason == (
        "duplicate: already applied through CORP.LOCAL")


def test_parent_dn_skips_escaped_commas() -> None:
    assert parent_dn("CN=DOE\\, JOHN,OU=Staff,DC=corp,DC=local") == "OU=STAFF,DC=CORP,DC=LOCAL"
    assert parent_dn("DC=CORP,DC=LOCAL") == "DC=LOCAL"


def test_stale_contains_keeps_the_container_named_by_the_dn() -> None:
    g = Graph.from_cypher(tree("st", "u", "jdoe", "w", "web01", edges=[
        ("st", "Contains", "jdoe"), ("u", "Contains", "jdoe"),  # JDOE moved from USERS to STAFF
        ("st", "Contains", "web01")])["data"])  # one container, even a wrong one, is kept
    assert stale_contains(g) == {(USERS, JDOE)}


@pytest.fixture
def moved(monkeypatch: pytest.MonkeyPatch) -> None:
    """JDOE moved from the USERS container to STAFF: BloodHound kept both Contains edges."""
    monkeypatch.setitem(RESULTS, Q.moved_objects(L), tree("st", "u", "jdoe", edges=[
        ("st", "Contains", "jdoe"), ("u", "Contains", "jdoe")]))
    monkeypatch.setitem(RESULTS, Q.contained_counts(DOM, nested=True), literals(
        counts(SERVERS, "OU", 2), counts(SERVERS, "Computer", 1, True, "Tag_Tier_Zero"),
        counts(WEB, "Computer", 1, True), counts(STAFF, "User", 1, False),
        counts(USERS, "User", 1, True, "Tag_Owned"), counts(USERS, "User", 1, False)))
    monkeypatch.setitem(RESULTS, Q.containers_above(JDOE), tree("d", "st", "u", "jdoe", edges=[
        ("d", "Contains", "st"), ("d", "Contains", "u"), ("st", "Contains", "jdoe"), ("u", "Contains", "jdoe")]))


def test_moved_object_is_counted_and_located_once(svc: EntityService, moved: None) -> None:
    rows = {r.label: r for r in svc.view(ou(svc, "corp.local"), "tree")[0].rows}
    assert (rows["CORP.LOCAL"].users, rows["CORP.LOCAL"].enabled_users) == (2, 1)
    assert rows["└─ USERS"].users == 1
    assert [n.name for n in svc.containers.chain(svc.resolve("jdoe", "User"))] == [
        "CORP.LOCAL", "STAFF@CORP.LOCAL"]


def test_summary_counts_other_objects_only_when_there_are_some() -> None:
    templates = Counts()
    templates.add(["Base", "CertTemplate", "Tag_Tier_Zero"], None, 63)
    fields = {f.label: f.value for f in templates.summary()}
    assert fields["Other objects below"] == 63 and fields["Tier Zero objects below"] == 63
    users = Counts()
    users.add(["Base", "User"], True, 2)
    assert "Other objects below" not in {f.label for f in users.summary()}
