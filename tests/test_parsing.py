"""User input parsing and file output that don't need a server."""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from bhshell.cli import main
from bhshell.config import CachedSession, Config
from bhshell.errors import BHError
from bhshell.models.entities import Graph, Node
from bhshell.queries import cypher as Q
from bhshell.queries.containers import applied_gpos
from bhshell.queries.library import BUILTIN_DIR, parse_cyp
from bhshell.queries.paths import AttackPath, Hop, PathResult
from bhshell.queries.search import Filter, condition, parse_filter
from bhshell.queries.service import parse_identifier
from bhshell.render import export, svg
from bhshell.shell.app import BHShell
from tests.conftest import BASE, run

NOW = 1_700_000_000


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


def test_cypher_literal_escaping() -> None:
    assert Q.lit("O'Brien\\x") == "'O\\'Brien\\\\x'"


@pytest.mark.parametrize(("text", "expected"), [
    ("hasspn", Filter("hasspn", "=", True)),
    ("!Enabled", Filter("enabled", "!=", True)),
    ("description~Pass", Filter("description", "~", "Pass")),
    ("samaccountname=1234", Filter("samaccountname", "=", 1234)),
    ("email=null", Filter("email", "=", None)),
    ("pwdlastset<2020-01-01", Filter("pwdlastset", "<", 1577836800)),
    ("lastlogon<=10d", Filter("lastlogon", "<=", NOW - 10 * 86400)),
    ("description=a=b", Filter("description", "=", "a=b")),
])
def test_parse_filter(text: str, expected: Filter) -> None:
    assert parse_filter(text, NOW) == expected


@pytest.mark.parametrize("text", [
    "bad-attr=1", "n.name=x", "x) OR (1=1", "!name=x", "name>abc", "enabled>true", "email<null", "",
    "pwdlastset~2023", "owned=1", "name=a*b",
])
def test_bad_filters_are_rejected(text: str) -> None:
    with pytest.raises(BHError):
        condition(parse_filter(text, NOW))


@pytest.mark.parametrize(("text", "cypher"), [
    ("!enabled", "(n.enabled = false OR n.enabled IS NULL)"),
    ("name=svc_*", "toLower(n.name) STARTS WITH 'svc_'"),
    ("description~it's", "toLower(n.description) CONTAINS 'it\\'s'"),
    ("description!~pw", "(n.description IS NULL OR NOT (toLower(n.description) CONTAINS 'pw'))"),
    ("samaccountname=1234", "(n.samaccountname = 1234 OR n.samaccountname = '1234')"),
    ("serviceprincipalnames~MSSQL", "any(x IN n.serviceprincipalnames WHERE toLower(x) CONTAINS 'mssql')"),
])
def test_filter_condition(text: str, cypher: str) -> None:
    assert condition(parse_filter(text, NOW)) == cypher


@pytest.mark.parametrize("name", sorted(p.stem for p in BUILTIN_DIR.glob("*.cyp")))
def test_bundled_queries_are_well_formed(name: str) -> None:
    q = parse_cyp((BUILTIN_DIR / f"{name}.cyp").read_text(), name, "builtin")
    assert q.name == name and q.description and q.query.startswith("MATCH")


def test_config_rejects_invalid_values(shell: BHShell) -> None:
    assert "Invalid value for page_size" in run(shell, "config page_size 0")
    assert "Invalid value for verify_tls" in run(shell, "config verify_tls maybe")
    assert "Invalid value for read_timeout" in run(shell, "config read_timeout inf")
    assert "expected a whole number, got 'abc'" in run(shell, "config display_rows abc")
    assert shell.config.page_size == 500 and shell.config.read_timeout == 60.0


def test_bad_config_file_values_fall_back_to_defaults(bhshell_home: Path) -> None:
    bhshell_home.mkdir(parents=True, exist_ok=True)
    Config.path().write_text('url = "ftp://bh.lab"\nverify_tls = "false"\npage_size = 0\nmax_results = 10\n')
    cfg = Config.load()
    assert cfg.url == Config().url
    assert cfg.verify_tls is False and cfg.page_size == 500 and cfg.max_results == 10


def test_malformed_session_cache_is_ignored(bhshell_home: Path) -> None:
    bhshell_home.mkdir(parents=True, exist_ok=True)
    CachedSession.path().write_text(json.dumps({"url": BASE, "token": 123}))
    assert CachedSession.load() is None
    assert not BHShell(Config(url=BASE)).client.is_authenticated


def test_cli_exit_codes(bhshell_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    script = tmp_path / "dir with space" / "cmds.txt"
    script.parent.mkdir()
    script.write_text("url\n")
    assert main(["-s", str(script)]) == 0
    assert main(["-c", "no_such_command"]) == 1
    assert main(["-c", "ou --no-such-flag"]) == 1
    assert main(["-c", "user jdoe"]) == 1  # not authenticated
    out = capsys.readouterr()
    assert "Not authenticated" in out.err and "Not authenticated" not in out.out


def test_csv_export_neutralises_formulas(tmp_path: Path) -> None:
    target = tmp_path / "x.csv"
    export.write(str(target), {}, (["a", "b", "c"], [{"a": "=HYPERLINK(\"http://x\")", "b": "@SUM(1)", "c": -3}]))
    row = next(csv.DictReader(target.open()))
    assert row == {"a": "'=HYPERLINK(\"http://x\")", "b": "'@SUM(1)", "c": "-3"}


def _node(key: str, kind: str, name: str, **props: Any) -> tuple[str, dict[str, Any]]:
    return key, {"kind": kind, "kinds": ["Base", kind], "objectId": key, "properties": {"name": name, **props}}


def test_gpo_precedence_blocking_and_enforcement() -> None:
    # CORP.LOCAL (DEFAULT DOMAIN POLICY enforced, WALLPAPER) > SERVERS (blocks inheritance) > WEB
    nodes = dict([
        _node("d", "Domain", "CORP.LOCAL"),
        _node("s", "OU", "SERVERS@CORP.LOCAL", blocksinheritance=True),
        _node("w", "OU", "WEB@CORP.LOCAL"),
        _node("ddp", "GPO", "DEFAULT DOMAIN POLICY@CORP.LOCAL"),
        _node("wall", "GPO", "WALLPAPER@CORP.LOCAL"),
        _node("srv", "GPO", "SERVER BASELINE@CORP.LOCAL"),
        _node("web", "GPO", "WEB HARDENING@CORP.LOCAL"),
    ])
    links = [("ddp", "d", {"enforced": True}), ("wall", "d", {}), ("srv", "s", {}), ("web", "w", {}), ("ddp", "w", {})]
    graph = Graph.from_cypher({"nodes": nodes, "edges": [
        {"source": s, "target": t, "kind": "GPLink", "properties": p} for s, t, p in links]})
    levels = [Node.from_cypher(k, nodes[k]) for k in ("d", "s", "w")]
    rows = [(r.gpo.split("@")[0], r.linked_to, r.applies, r.reason) for r in applied_gpos(levels, graph)]
    assert rows == [
        # Enforced first; SERVERS blocks inheritance, but not of enforced links.
        ("DEFAULT DOMAIN POLICY", "CORP.LOCAL", True, ""),
        # Then the closest link first.
        ("DEFAULT DOMAIN POLICY", "WEB@CORP.LOCAL", True, "duplicate: already applied through CORP.LOCAL"),
        ("WEB HARDENING", "WEB@CORP.LOCAL", True, ""),
        ("SERVER BASELINE", "SERVERS@CORP.LOCAL", True, ""),
        ("WALLPAPER", "CORP.LOCAL", False, "inheritance blocked at SERVERS"),
    ]


def test_svg_route_survives_a_cycle() -> None:
    # A route may revisit an object (A -> B -> A -> C): the loop is drawn as a back link.
    a = Node(id="a", objectid="S-A", kind="User", name="A@CORP.LOCAL", owned=True)
    b = Node(id="b", objectid="S-B", kind="Group", name="B@CORP.LOCAL")
    c = Node(id="c", objectid="S-C", kind="Group", name="C@CORP.LOCAL", tier_zero=True)
    path = AttackPath([Hop(a, "AddMember", b), Hop(b, "GenericAll", a), Hop(a, "MemberOf", c)])
    doc = svg.render(PathResult("route", waypoints=[b.objectid], paths=[path]))
    labels = [t.text or "" for t in ET.fromstring(doc).iter("{http://www.w3.org/2000/svg}text")]
    assert labels.count("A") == 1 and "via" in labels
