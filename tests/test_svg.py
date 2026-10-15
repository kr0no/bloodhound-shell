from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET

import pytest

from bhshell.models.entities import Node
from bhshell.queries.paths import AttackPath, Hop, PathResult
from bhshell.render import svg
from bhshell.shell.commands.base import output_path

NS = "{http://www.w3.org/2000/svg}"


def node(name: str, kind: str = "User", **kw: bool) -> Node:
    return Node(id=name, objectid=f"S-{name}", kind=kind, name=name, **kw)


def chain(*items: Node | str) -> AttackPath:
    return AttackPath([Hop(items[i], items[i + 1], items[i + 2])  # type: ignore[arg-type]
                       for i in range(0, len(items) - 1, 2)])


def texts(doc: str) -> list[str]:
    return [t.text or "" for t in ET.fromstring(doc).iter(f"{NS}text")]


A, B, C = node("A@CORP.LOCAL", owned=True), node("B@CORP.LOCAL", "Group"), node("C@CORP.LOCAL", "Group", tier_zero=True)
D = node("D.CORP.LOCAL", "Computer")


def test_merges_paths_and_draws_each_object_once() -> None:
    result = PathResult("Owned → T0", paths=[chain(A, "MemberOf", B, "GenericAll", C),
                                              chain(A, "AdminTo", D, "HasSession", C)])
    labels = texts(svg.render(result))
    assert [labels.count(name) for name in ("A", "B", "C", "D")] == [1, 1, 1, 1]
    assert {"MemberOf", "GenericAll", "AdminTo", "HasSession", "OWNED", "T0"} <= set(labels)
    assert "CORP.LOCAL" not in labels  # one domain: not repeated under every node


def test_only_the_paths_and_legend_are_drawn() -> None:
    result = PathResult("Owned → T0", paths=[chain(A, "MemberOf", B, "GenericAll", C)])
    labels = texts(svg.render(result))
    assert not any(t.startswith(("Owned →", "bhshell")) or "path" in t for t in labels)
    assert set(labels) == {"A", "B", "C", "MemberOf", "GenericAll", "OWNED", "T0", "User", "Group",
                           "critical edge", "medium edge", "Tier Zero"}


def test_long_link_gets_its_own_lane() -> None:
    # A -> C skips the column of B, so it is routed through a lane point instead of a straight curve.
    result = PathResult("t", paths=[chain(A, "MemberOf", B, "MemberOf", C), chain(A, "GenericAll", C)])
    paths = [p.get("d", "") for p in ET.fromstring(svg.render(result)).iter(f"{NS}path") if " L" in p.get("d", "")]
    assert len(paths) == 1


def test_route_marks_waypoints_and_survives_cycles() -> None:
    # A route may revisit an object (A -> B -> A -> C): the loop is drawn as a back link.
    result = PathResult("route", waypoints=[B.objectid],
                        paths=[chain(A, "AddMember", B, "GenericAll", A, "MemberOf", C)])
    labels = texts(svg.render(result))
    assert "via" in labels and "waypoint (--via)" in labels
    assert labels.count("A") == 1


def test_empty_result() -> None:
    assert "No path found." in texts(svg.render(PathResult("Nothing")))


def test_svg_is_only_accepted_where_offered() -> None:
    assert output_path("x.svg", (".json", ".csv", ".svg")) == "x.svg"
    with pytest.raises(argparse.ArgumentTypeError, match="must end in .json or .csv"):
        output_path("x.svg")


def size(doc: str) -> tuple[float, float]:
    root = ET.fromstring(doc)
    return float(root.get("width", 0)), float(root.get("height", 0))


def arrows(doc: str) -> int:
    return sum(1 for _ in ET.fromstring(doc).iter(f"{NS}polygon"))


def long_chain(hops: int) -> PathResult:
    items: list[Node | str] = [A]
    for i in range(hops - 1):
        items += ["GenericWrite", node(f"HOP{i}@CORP.LOCAL")]
    return PathResult("long", paths=[chain(*items, "MemberOf", C)])


def test_long_chain_wraps_into_rows_to_fit_a_portrait_page() -> None:
    result = long_chain(6)
    sizes = {o: size(svg.render(result, orientation=o)) for o in ("horizontal", "vertical", "wrapped")}
    assert sizes["horizontal"][0] > sizes["horizontal"][1] and sizes["vertical"][1] > sizes["vertical"][0]
    fits = {o: svg.page_fit(*wh) for o, wh in sizes.items()}
    assert fits["wrapped"] > fits["vertical"] > fits["horizontal"]
    assert size(svg.render(result)) == sizes["wrapped"]


def test_wrapped_rows_continue_below() -> None:
    doc = svg.render(long_chain(6), orientation="wrapped")
    labels = texts(doc)
    assert [labels.count(f"HOP{i}") for i in range(5)] == [1] * 5 and labels.count("GenericWrite") == 5
    polygons = [p.get("points", "") for p in ET.fromstring(doc).iter(f"{NS}polygon")]
    downward = [p for p in polygons if (pts := [tuple(map(float, xy.split(","))) for xy in p.split()])
                and pts[0][1] > pts[1][1] and pts[1][1] == pts[2][1]]
    assert len(polygons) == 6 and downward  # some links wrap into the next row, arriving from above


def test_wrapped_rows_hold_at_least_three_nodes() -> None:
    # Wide captions would make two per row the largest print; rows still hold three nodes.
    items: list[Node | str] = [A]
    for i in range(7):
        items += ["ForceChangePassword", node(f"VERY_LONG_SERVICE_ACCOUNT_NAME_{i}@CORP.LOCAL")]
    doc = svg.render(PathResult("wide", paths=[chain(*items, "MemberOf", C)]), orientation="wrapped")
    rows: dict[float, int] = {}
    for circle in ET.fromstring(doc).iter(f"{NS}circle"):
        if circle.get("r") == str(svg.R):
            rows[float(circle.get("cy", 0))] = rows.get(float(circle.get("cy", 0)), 0) + 1
    counts = [rows[y] for y in sorted(rows)]
    assert counts[:-1] and all(c >= 3 for c in counts[:-1])


def test_link_skipping_rows_uses_the_gutter() -> None:
    hops: list[Node] = [node(f"H{i}@CORP.LOCAL") for i in range(8)]
    items: list[Node | str] = [A]
    for h in hops:
        items += ["GenericWrite", h]
    skip = chain(A, "AdminTo", D, "HasSession", hops[6])
    result = PathResult("skip", paths=[chain(*items, "MemberOf", C), skip])
    doc = svg.render(result, orientation="wrapped")
    assert any(f"L{svg.MARGIN / 2:.1f}," in p.get("d", "") for p in ET.fromstring(doc).iter(f"{NS}path"))
    assert texts(doc).count("HasSession") == 1


def test_many_links_skipping_rows_stay_on_the_canvas() -> None:
    hops: list[Node] = [node(f"H{i}@CORP.LOCAL") for i in range(24)]
    items: list[Node | str] = [A]
    for h in hops:
        items += ["GenericWrite", h]
    hosts = [node(f"SRV{i}.CORP.LOCAL", "Computer") for i in range(6)]
    skips = [chain(A, "AdminTo", host, "HasSession", hops[16 + i]) for i, host in enumerate(hosts)]
    doc = svg.render(PathResult("skip", paths=[chain(*items, "MemberOf", C), *skips]), orientation="wrapped")
    width = size(doc)[0]
    xs = [float(x) for p in ET.fromstring(doc).iter(f"{NS}path")
          for x, _ in re.findall(r"(-?[\d.]+),(-?[\d.]+)", p.get("d", ""))]
    assert xs and 0 < min(xs) and max(xs) < width


def test_wide_fan_in_stays_horizontal() -> None:
    sources = [node(f"USER{i}@CORP.LOCAL", owned=True) for i in range(8)]
    result = PathResult("fan", paths=[chain(s, "MemberOf", B, "GenericAll", C) for s in sources])
    horizontal = size(svg.render(result, orientation="horizontal"))
    assert size(svg.render(result)) == horizontal


def test_small_diagram_keeps_the_horizontal_layout() -> None:
    result = PathResult("short", paths=[chain(A, "MemberOf", B, "GenericAll", C)])
    assert svg.page_fit(*size(svg.render(result, orientation="vertical"))) == 1.0
    assert size(svg.render(result)) == size(svg.render(result, orientation="horizontal"))


def test_vertical_layout_draws_everything() -> None:
    result = PathResult("route", waypoints=[B.objectid],
                        paths=[chain(A, "AddMember", B, "GenericAll", A, "MemberOf", C),
                               chain(A, "AdminTo", D, "HasSession", C)])
    doc = svg.render(result, orientation="vertical")
    labels = texts(doc)
    assert [labels.count(name) for name in ("A", "B", "C", "D")] == [1, 1, 1, 1]
    assert {"AddMember", "GenericAll", "MemberOf", "AdminTo", "HasSession", "via"} <= set(labels)
    assert arrows(doc) == arrows(svg.render(result, orientation="horizontal"))


def test_disabled_badge() -> None:
    off = Node(id="X", objectid="S-X", kind="Computer", name="_MSATASK$@CORP.LOCAL", properties={"enabled": False})
    assert "DISABLED" in texts(svg.render(PathResult("t", paths=[chain(A, "GenericAll", off, "MemberOf", C)])))


def test_legend_wraps_in_portrait_diagrams() -> None:
    doc = svg.render(long_chain(6), orientation="vertical")
    width = size(doc)[0]
    legend_x = [float(t.get("x", 0)) for t in ET.fromstring(doc).iter(f"{NS}text")
                if t.text in ("User", "Group", "Tier Zero", "critical edge", "medium edge")]
    assert max(legend_x) < width
