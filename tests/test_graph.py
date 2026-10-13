from __future__ import annotations

import io

from rich.console import Console

from bhshell.queries.paths import PathResult
from bhshell.render import graph
from bhshell.render.views import Renderer
from tests.test_svg import A, B, C, D, chain


def plain(result: PathResult, width: int = 120) -> str:
    lines, notes = graph.draw(result, result.paths, max_width=width)
    return "\n".join(line.plain for line in lines) + "\n" + "\n".join(notes)


def test_boxes_arrows_and_labels() -> None:
    result = PathResult("t", paths=[chain(A, "MemberOf", B, "GenericAll", C), chain(A, "AdminTo", D, "HasSession", C)])
    out = plain(result)
    for text in ("● A OWNED", "● B", "● C T0", "● D", "MemberOf", "GenericAll", "AdminTo", "HasSession"):
        assert out.count(text) == 1, text
    assert out.count("▼") == 3  # into B, into D, and one shared arrow into C (fan-in)
    assert "[1]" not in out  # every label fitted next to its line


def test_single_chain_is_a_straight_column() -> None:
    path = chain(A, "MemberOf", B, "MemberOf", C)
    lines, _ = graph.draw(PathResult("t", paths=[path]), [path], max_width=80)
    columns = {line.plain.index(char) for line in lines for char in "┬▼" if char in line.plain}
    assert len(columns) == 1


def test_waypoints_get_a_double_border_and_loops_are_listed() -> None:
    result = PathResult("route", waypoints=[B.objectid], paths=[chain(A, "AddMember", B, "GenericAll", A,
                                                                      "MemberOf", C)])
    out = plain(result)
    assert "║ ● B via ║" in out
    assert "↺ B@CORP.LOCAL ─GenericAll→ A@CORP.LOCAL (back to an earlier step)" in out


def test_too_wide_for_the_terminal_falls_back_to_the_list() -> None:
    paths = [chain(A, kind, node) for kind, node in (("GenericAll", B), ("AdminTo", D), ("MemberOf", C))]
    out, status = io.StringIO(), io.StringIO()
    ui = Renderer(Console(file=out, width=24), Console(file=status, width=200))
    ui.path_graph(PathResult("t", paths=paths))
    assert "showing the list instead" in status.getvalue()
    assert "1. A@CORP.LOCAL" in out.getvalue()
