from __future__ import annotations

import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
import responses
from cmd2.string_utils import strip_style, stylize
from rich.console import Console

from bhshell.cli import main
from bhshell.config import CachedSession, Config
from bhshell.models.entities import Node
from bhshell.queries.paths import PathResult, PathService
from bhshell.render import export, views
from bhshell.render.views import Renderer
from bhshell.shell.app import BHShell
from tests.conftest import BASE, graph, run
from tests.test_svg import A, B, C, D, chain


def connected(app: BHShell) -> bool:
    """Read the auth state from the prompt colour ("shell" is green when authenticated, red otherwise)."""
    assert strip_style(app.prompt) == "[bh: shell] > "
    return stylize("shell", "green") in app.prompt


def test_prompt_reflects_auth_state(shell: BHShell) -> None:
    assert not connected(shell)
    out = run(shell, "login -u admin")
    assert "Logged in as admin" in out
    assert connected(shell)
    assert CachedSession.load() is not None
    run(shell, "logout")
    assert not connected(shell)
    assert CachedSession.load() is None


def test_session_is_resumed(shell: BHShell) -> None:
    run(shell, "login -u admin")
    resumed = BHShell(Config(url=BASE))
    assert resumed.client.is_authenticated
    assert connected(resumed)


def test_user_requires_login(shell: BHShell) -> None:
    assert "Not authenticated" in run(shell, "user jdoe")


def test_ambiguous_user_lists_candidates(shell: BHShell) -> None:
    run(shell, "login -u admin")
    out = run(shell, "user jdoe")
    assert "matches 2 objects" in out
    assert "DEV.CORP.LOCAL" in out and "CORP.LOCAL" in out


def test_user_all_report_and_csv_export(shell: BHShell, tmp_path: Path) -> None:
    run(shell, "login -u admin")
    target = tmp_path / "jdoe.csv"
    out = run(shell, f"user CORP\\jdoe --all -o {target}")
    for expected in ("Kerberoastable", "DOMAIN ADMINS@CORP.LOCAL", "GenericAll", "ForceChangePassword",
                     "AdminTo", "WS01.CORP.LOCAL", "Exported to"):
        assert expected in out
    rows = list(csv.DictReader(target.open()))
    assert {r["view"] for r in rows} >= {"groups", "outbound", "inbound", "sessions", "privs_held"}


def test_view_flags_only(shell: BHShell) -> None:
    run(shell, "login -u admin")
    out = run(shell, "user jdoe@corp.local --groups")
    assert "Group memberships" in out
    assert "Password Last Set" not in out


def test_cypher_command_keeps_pipes(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    out = run(shell, "cypher MATCH (n:Tag_Owned) RETURN n")
    assert "HELPDESK@CORP.LOCAL" in out
    run(shell, "cypher MATCH p=(a)-[:A|B]->(b) RETURN p")
    sent = json.loads(mocked.calls[-1].request.body)["query"]
    assert sent == "MATCH p=(a)-[:A|B]->(b) RETURN p"


def test_cypher_command_shows_and_exports_values(shell: BHShell, mocked: Any, tmp_path: Path) -> None:
    run(shell, "login -u admin")
    literals = [{"key": "os", "value": "WINDOWS SERVER 2019"}, {"key": "total", "value": 16},
                {"key": "os", "value": None}, {"key": "total", "value": 3}]
    mocked.replace(responses.POST, f"{BASE}api/v2/graphs/cypher",
                   json={"data": {"nodes": {}, "edges": [], "literals": literals}})
    target = tmp_path / "os.csv"
    out = run(shell, f"cypher -o {target} MATCH (n:Computer) RETURN n.operatingsystem AS os, count(n) AS total")
    assert "Rows [2]" in out and "WINDOWS SERVER 2019" in out and "No results" not in out
    assert list(csv.DictReader(target.open())) == [{"os": "WINDOWS SERVER 2019", "total": "16"},
                                                   {"os": "", "total": "3"}]


def test_marked_object_lists(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    assert "HELPDESK@CORP.LOCAL" in run(shell, "owned list")
    out = run(shell, "hvt list")  # nothing tagged Tier Zero in the fixtures
    assert "No results." in out and "Object ID" not in out
    mocked.replace(responses.POST, f"{BASE}api/v2/graphs/cypher", json=graph(["1", "5", "7"], []))
    out = run(shell, "owned list -n 2")
    assert "[3]" in out and "showing 2 of 3 rows" in out and "SVC_SQL@CORP.LOCAL" not in out


def test_auth_loss_drops_to_disconnected(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    mocked.replace(responses.POST, f"{BASE}api/v2/graphs/cypher", status=401,
                   json={"errors": [{"message": "session expired"}]})
    out = run(shell, "user jdoe")
    assert "session expired" in out
    assert not connected(shell)


def test_analysis_commands(shell: BHShell, mocked: Any, tmp_path: Path) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/available-domains", json={"data": []})
    run(shell, "login -u admin")
    out = run(shell, "path jdoe@corp.local")
    assert "IT ADMINS@CORP.LOCAL" in out and "DOMAIN ADMINS@CORP.LOCAL [T0]" in out
    out = run(shell, "path --owned")
    assert "HELPDESK@CORP.LOCAL [owned]" in out
    out = run(shell, "path --owned -g")
    assert "● HELPDESK OWNED" in out and "● DOMAIN ADMINS T0" in out and "ForceChangePassword" in out
    diagram = tmp_path / "owned.svg"
    run(shell, f"path --owned -o {diagram}")
    assert "DOMAIN ADMINS" in diagram.read_text()
    mocked.add(responses.GET, f"{BASE}api/v2/graphs/shortest-path",
               json={"data": {"nodes": {"7": {"kind": "User", "objectId": "S-1-5-21-1000-1106",
                                              "properties": {"name": "HELPDESK@CORP.LOCAL"}},
                                        "1": {"kind": "User", "objectId": "S-1-5-21-1000-1104",
                                              "properties": {"name": "JDOE@CORP.LOCAL"}}},
                              "edges": [{"source": "7", "target": "1", "kind": "ForceChangePassword"}]}})
    out = run(shell, "path helpdesk --via jdoe@corp.local")
    assert "Shortest route: HELPDESK@CORP.LOCAL → JDOE@CORP.LOCAL → Tier Zero" in out
    assert "ForceChangePassword→ JDOE@CORP.LOCAL ─MemberOf→ IT ADMINS@CORP.LOCAL" in out
    assert "appears twice in a row" in run(shell, "path helpdesk --via helpdesk")
    assert "takes no SRC or --via" in run(shell, "path --owned --via helpdesk")
    assert "takes no SRC or --via" in run(shell, "path --owned helpdesk jdoe@corp.local")
    out = run(shell, "hunt")
    assert "Hunt summary" in out and "kerberoastable" in out
    target = tmp_path / "kerb.csv"
    run(shell, f"hunt kerberoastable -o {target}")
    rows = list(csv.DictReader(target.open()))
    assert rows and rows[0]["check"] == "kerberoastable"
    assert "CORP.LOCAL" in run(shell, "domains")
    assert "SpoofSIDHistory" in run(shell, "trusts")
    assert "kerberoastable-users" in run(shell, "query list")
    assert "HELPDESK@CORP.LOCAL" in run(shell, "query run owned-objects")


def test_failed_relogin_keeps_active_session(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    mocked.replace(responses.POST, f"{BASE}api/v2/login", status=401, json={"errors": [{"message": "bad"}]})
    assert "Login failed" in run(shell, "login -u someone")
    assert shell.client.is_authenticated and connected(shell)
    assert CachedSession.load() is not None


def test_failures_are_counted(shell: BHShell) -> None:
    run(shell, "whoami")
    assert shell.command_failures == 0
    run(shell, "user jdoe")  # not authenticated
    run(shell, "hunt --no-such-flag")  # usage error
    run(shell, "hunt no-such-check")  # usage error
    run(shell, "no_such_command")
    assert shell.command_failures == 4


def test_status_goes_to_stderr_and_names_are_not_markup() -> None:
    out, err = Console(record=True, width=200), Console(record=True, width=200)
    ui = Renderer(out, err)
    ui.success("done")
    ui.nodes([Node(id="1", objectid="X", kind="GPO", name="BAD[/x]GPO@CORP.LOCAL")], "GPOs")
    assert "done" in err.export_text() and "done" not in out.export_text(clear=False)
    assert "BAD[/x]GPO@CORP.LOCAL" in out.export_text()


def test_spinner_only_for_slow_requests_on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(views, "SPINNER_DELAY", 0.05)
    tty, piped = io.StringIO(), io.StringIO()
    ui = Renderer(status=Console(file=tty, force_terminal=True))
    with ui.waiting("Running Cypher query"):
        pass
    assert tty.getvalue() == ""
    with ui.waiting("Running Cypher query"):
        time.sleep(0.3)
    assert "Running Cypher query..." in tty.getvalue()
    with Renderer(status=Console(file=piped)).waiting("Running Cypher query"):
        time.sleep(0.3)
    assert piped.getvalue() == ""


def test_cli_script_path_with_spaces_and_exit_codes(bhshell_home: Path, tmp_path: Path,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    script = tmp_path / "dir with space" / "cmds.txt"
    script.parent.mkdir()
    script.write_text("url\n")
    assert main(["-s", str(script)]) == 0
    assert main(["-c", "no_such_command"]) == 1
    assert main(["-c", "user jdoe"]) == 1  # not authenticated
    out = capsys.readouterr()
    assert "Not authenticated" in out.err and "Not authenticated" not in out.out


def test_config_rejects_invalid_values(shell: BHShell) -> None:
    assert "Invalid value for page_size" in run(shell, "config page_size 0")
    assert "Invalid value for max_results" in run(shell, "config max_results -5")
    assert "Invalid value for verify_tls" in run(shell, "config verify_tls maybe")
    run(shell, "config display_rows 0")
    assert shell.config.display_rows == 0 and shell.config.page_size == 500


def test_config_number_errors_say_what_is_expected(shell: BHShell) -> None:
    out = run(shell, "config display_rows abc")
    assert "expected a whole number, got 'abc'" in out and "invalid literal" not in out
    assert "expected a number, got 'soon'" in run(shell, "config read_timeout soon")


def test_config_query_dirs_are_stored_absolute(shell: BHShell, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    run(shell, f"config query_dirs q{os.pathsep}~/team{os.pathsep}/srv/queries")
    assert shell.config.query_dirs == os.pathsep.join([str(tmp_path / "q"), "~/team", "/srv/queries"])


def test_config_load_validates(bhshell_home: Path) -> None:
    bhshell_home.mkdir(parents=True, exist_ok=True)
    Config.path().write_text('verify_tls = "false"\npage_size = 0\nmax_results = 10\n')
    cfg = Config.load()
    assert cfg.verify_tls is False and cfg.page_size == 500 and cfg.max_results == 10


def test_config_rejects_non_finite_numbers(shell: BHShell) -> None:
    assert "Invalid value for connect_timeout" in run(shell, "config connect_timeout nan")
    assert "Invalid value for read_timeout" in run(shell, "config read_timeout inf")
    assert shell.config.connect_timeout == 5.0 and shell.config.read_timeout == 60.0


def test_invalid_url_in_config_falls_back_to_default(bhshell_home: Path) -> None:
    bhshell_home.mkdir(parents=True, exist_ok=True)
    Config.path().write_text('url = "ftp://bh.lab"\n')
    assert Config.load().url == Config().url


def test_malformed_session_cache_is_ignored(bhshell_home: Path) -> None:
    bhshell_home.mkdir(parents=True, exist_ok=True)
    CachedSession.path().write_text(json.dumps({"url": BASE, "token": 123}))
    assert CachedSession.load() is None
    assert not BHShell(Config(url=BASE)).client.is_authenticated


def test_csv_export_neutralises_formulas(tmp_path: Path) -> None:
    target = tmp_path / "x.csv"
    export.write(str(target), {}, (["a", "b", "c"], [{"a": "=HYPERLINK(\"http://x\")", "b": "@SUM(1)", "c": -3}]))
    row = next(csv.DictReader(target.open()))
    assert row == {"a": "'=HYPERLINK(\"http://x\")", "b": "'@SUM(1)", "c": "-3"}


@pytest.fixture
def three_paths(shell: BHShell, monkeypatch: pytest.MonkeyPatch) -> BHShell:
    paths = [chain(A, "MemberOf", C), chain(A, "GenericAll", B, "MemberOf", C), chain(A, "AdminTo", D, "HasSession", C)]
    monkeypatch.setattr(PathService, "owned_to_tier_zero", lambda self: PathResult("Owned → T0", paths=paths))
    run(shell, "login -u admin")
    return shell


def test_path_pick_selects_paths_by_list_number(three_paths: BHShell) -> None:
    out = run(three_paths, "path --owned -p 2-3")
    assert "2. A@CORP.LOCAL [owned] ─GenericAll→ B@CORP.LOCAL" in out  # keeps its number from the full list
    assert "3. A@CORP.LOCAL [owned] ─AdminTo→" in out and "1. " not in out
    assert "Showing path 2, 3 of 3." in out
    assert "only 3 path(s)" in run(three_paths, "path --owned -p 4")


def test_owned_lone_positional_is_dst(three_paths: BHShell, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(PathService, "owned_to",
                        lambda self, dst: seen.append(dst.name) or PathResult(f"Owned → {dst.name}"))
    run(three_paths, "path --owned jdoe@corp.local")
    assert seen == ["JDOE@CORP.LOCAL"]  # the lone positional is the DST, not a (rejected) SRC


def test_graph_asks_which_path_to_draw(three_paths: BHShell, monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(three_paths, "can_ask", lambda: True)
    monkeypatch.setattr(three_paths, "read_input", lambda prompt: prompts.append(prompt) or "3")
    out = run(three_paths, "path --owned -g")
    assert prompts == ["Path(s) to draw [1-3, e.g. 2, 1,3 or 2-4; Enter = all]: "]
    assert "3. A@CORP.LOCAL [owned] ─AdminTo→ D.CORP.LOCAL" in out  # the numbered list comes first
    graph_part = out.split("Owned → T0")[-1]
    assert "● D" in graph_part and "● B" not in graph_part and "Showing path 3 of 3." in graph_part

    monkeypatch.setattr(three_paths, "read_input", lambda prompt: "x")
    assert "not a path selection" in run(three_paths, "path --owned -g")


def test_graph_does_not_ask_outside_the_repl(three_paths: BHShell) -> None:
    assert not three_paths.can_ask()  # -c / -s runs and tests never reach preloop()
    out = run(three_paths, "path --owned -g")
    assert "● B" in out and "● D" in out
