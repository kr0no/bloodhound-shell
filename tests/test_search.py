from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
import responses

from bhshell.errors import BHError
from bhshell.queries.search import Filter, SearchOptions, condition, parse_filter
from bhshell.shell.app import BHShell
from tests.conftest import BASE, graph, run

NOW = 1_700_000_000


@pytest.mark.parametrize(("text", "expected"), [
    ("hasspn", Filter("hasspn", "=", True)),
    ("!Enabled", Filter("enabled", "!=", True)),
    ("admincount=false", Filter("admincount", "=", False)),
    ("description~Pass", Filter("description", "~", "Pass")),
    ("description!~x", Filter("description", "!~", "x")),
    ("samaccountname=1234", Filter("samaccountname", "=", 1234)),
    ("email=null", Filter("email", "=", None)),
    ("pwdlastset<2020-01-01", Filter("pwdlastset", "<", 1577836800)),
    ("lastlogon<=10d", Filter("lastlogon", "<=", NOW - 10 * 86400)),
    ("name=svc_*", Filter("name", "=", "svc_*")),
    ("description=a=b", Filter("description", "=", "a=b")),
])
def test_parse_filter(text: str, expected: Filter) -> None:
    assert parse_filter(text, NOW) == expected


@pytest.mark.parametrize("text", [
    "bad-attr=1", "n.name=x", "x) OR (1=1", "!name=x", "name>abc", "enabled>true", "email<null", "",
])
def test_parse_filter_rejects(text: str) -> None:
    with pytest.raises(BHError):
        parse_filter(text, NOW)


@pytest.mark.parametrize(("text", "cypher"), [
    ("hasspn", "n.hasspn = true"),
    ("!enabled", "(n.enabled = false OR n.enabled IS NULL)"),
    ("email=null", "n.email IS NULL"),
    ("email!=null", "n.email IS NOT NULL"),
    ("name=svc_*", "toLower(n.name) STARTS WITH 'svc_'"),
    ("name=*sql", "toLower(n.name) ENDS WITH 'sql'"),
    ("name=*SQL*", "toLower(n.name) CONTAINS 'sql'"),
    ("name=JDOE@CORP.LOCAL", "toLower(n.name) = 'jdoe@corp.local'"),
    ("name!=x", "(n.name IS NULL OR NOT (toLower(n.name) = 'x'))"),
    ("description~it's", "toLower(n.description) CONTAINS 'it\\'s'"),
    ("description!~pw", "(n.description IS NULL OR NOT (toLower(n.description) CONTAINS 'pw'))"),
    ("admincount!=1", "(n.admincount IS NULL OR (n.admincount <> 1 AND n.admincount <> '1'))"),
    ("samaccountname=1234", "(n.samaccountname = 1234 OR n.samaccountname = '1234')"),
    ("pwdlastset<2020-01-01", "n.pwdlastset < 1577836800"),
])
def test_condition(text: str, cypher: str) -> None:
    assert condition(parse_filter(text, NOW)) == cypher


def test_inner_wildcard_is_rejected() -> None:
    with pytest.raises(BHError, match="start or end"):
        condition(parse_filter("name=a*b"))


def test_query_combines_type_domain_and_filters() -> None:
    opts = SearchOptions([parse_filter("hasspn"), parse_filter("enabled")], kind="User", domain="corp", limit=50)
    assert opts.query() == ("MATCH (n:User) WHERE n.hasspn = true AND n.enabled = true AND "
                            "(n.domain = 'CORP' OR n.domain STARTS WITH 'CORP.') RETURN n LIMIT 50")
    assert SearchOptions(limit=5).query() == "MATCH (n:Base) RETURN n LIMIT 5"


def test_search_command(shell: BHShell, mocked: Any, tmp_path: Path) -> None:
    queries: list[str] = []

    def callback(request: Any) -> tuple[int, dict[str, str], str]:
        queries.append(json.loads(request.body)["query"])
        return 200, {}, json.dumps(graph(["5", "1"], []))

    mocked.remove(responses.POST, f"{BASE}api/v2/graphs/cypher")
    mocked.add_callback(responses.POST, f"{BASE}api/v2/graphs/cypher", callback=callback)
    run(shell, "login -u admin")

    out = run(shell, "search -t user hasspn 'description~test user' -c pwdlastset")
    assert queries[-1] == ("MATCH (n:User) WHERE n.hasspn = true AND toLower(n.description) CONTAINS 'test user' "
                           f"RETURN n LIMIT {shell.config.max_results}")
    assert "Search: User [2]" in out and "JDOE@CORP.LOCAL" in out and "SVC_SQL@CORP.LOCAL" in out
    assert "description" in out and "Test user" in out and "pwdlastset" in out
    assert out.index("JDOE@CORP.LOCAL") < out.index("SVC_SQL@CORP.LOCAL")

    target = tmp_path / "search.csv"
    run(shell, f"search -t USER hasspn -o {target}")
    rows = list(csv.DictReader(target.open()))
    assert [r["name"] for r in rows] == ["JDOE@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"]
    assert rows[0]["objectid"] and rows[0]["hasspn"] == "True"

    # cmd2 ends the arguments at '>' and '|' even with redirection off; nothing after them may be lost.
    run(shell, "search -t user lastlogon>=90d description~a|b enabled -c title")
    assert queries[-1].startswith("MATCH (n:User) WHERE n.lastlogon >= ")
    assert queries[-1].endswith(f"AND toLower(n.description) CONTAINS 'a|b' AND n.enabled = true "
                                f"RETURN n LIMIT {shell.config.max_results}")

    data = json.loads(shell_json(shell, "search hasspn --json"))
    assert data["count"] == 2 and data["results"][0]["properties"]["samaccountname"] == "jdoe"

    assert shell_json(shell, "search -t user hasspn --names-only") == "JDOE@CORP.LOCAL\nSVC_SQL@CORP.LOCAL\n"
    names = tmp_path / "users.txt"
    run(shell, f"search -t user hasspn -o {names}")
    assert names.read_text() == "JDOE@CORP.LOCAL\nSVC_SQL@CORP.LOCAL\n"
    failures = shell.command_failures
    assert shell_json(shell, "search hasspn --json --names-only") == ""  # usage error
    assert shell.command_failures == failures + 1


def shell_json(app: BHShell, line: str) -> str:
    """Run a command and return what it printed with `poutput` (the console only gets tables)."""
    app.stdout = io.StringIO()
    app.onecmd_plus_hooks(line)
    return app.stdout.getvalue()


def test_search_usage_errors(shell: BHShell) -> None:
    run(shell, "login -u admin")
    assert "at least one FILTER" in run(shell, "search")
    assert "Invalid filter" in run(shell, "search 'x) OR (1=1'")
    before = shell.command_failures
    run(shell, "search -t nosuchtype hasspn")
    assert shell.command_failures == before + 1


def test_unknown_domain_is_reported(shell: BHShell, mocked: Any) -> None:
    mocked.add(responses.GET, f"{BASE}api/v2/available-domains", json={"data": [
        {"type": "active-directory", "name": "CORP.LOCAL", "id": "S-1-5-21-1000", "collected": True}]})
    run(shell, "login -u admin")
    assert "No domain matches 'corpp' (known: CORP.LOCAL)" in run(shell, "search -t user -d corpp")
    assert "No domain matches" not in run(shell, "search -t user -d corp")
    assert "No domain matches" not in run(shell, "search -t user -d corp.local")
