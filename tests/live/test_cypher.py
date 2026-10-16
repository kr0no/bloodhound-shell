from __future__ import annotations

import json
from pathlib import Path

import pytest

from bhshell.queries.library import BUILTIN_DIR
from bhshell.shell.app import BHShell
from tests.live.conftest import ok


def test_cypher_values(lab: BHShell, tmp_path: Path) -> None:
    target = tmp_path / "rows.json"
    ok(lab, f"cypher -o {target} MATCH (n:User) WHERE n.hasspn = true RETURN n.name AS name, n.enabled AS enabled")
    rows = json.loads(target.read_text())["rows"]
    assert {"name": "SVC_KERB_DEL@PHANTOM.CORP", "enabled": True} in rows


def test_cypher_graph(lab: BHShell, tmp_path: Path) -> None:
    target = tmp_path / "graph.json"
    ok(lab, f"cypher -o {target} MATCH p=(:User {{name: 'ALICE@PHANTOM.CORP'}})-[:MemberOf]->(:Group) RETURN p")
    result = json.loads(target.read_text())
    assert "SUBDAS@PHANTOM.CORP" in {n["name"] for n in result["nodes"]} and result["edges"]


@pytest.mark.parametrize("name", sorted(p.stem for p in BUILTIN_DIR.glob("*.cyp")))
def test_bundled_query_runs(lab: BHShell, name: str) -> None:
    ok(lab, f"query run {name}")
