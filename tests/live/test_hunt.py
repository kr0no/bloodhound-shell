from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bhshell.queries.hunt import CHECKS
from bhshell.shell.app import BHShell
from tests.live.conftest import export


@pytest.fixture(scope="module")
def findings(lab: BHShell, tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    path = tmp_path_factory.mktemp("hunt") / "hunt.json"
    return {f["check"]: f for f in export(lab, "hunt", path)}


@pytest.mark.parametrize("check", [c.id for c in CHECKS])
def test_check_runs_on_the_server(findings: dict[str, dict[str, Any]], check: str) -> None:
    assert findings[check]["error"] == ""


@pytest.mark.parametrize("check, expected", [
    ("dcsync", {"DCSYNCERS@PHANTOM.CORP"}),
    ("kerberoastable", {"ADMINISTRATOR@PHANTOM.CORP", "SVC_KERB_DEL@PHANTOM.CORP"}),
    ("asreproast", {"NOPREAUTH@PHANTOM.CORP"}),
    ("unconstrained", {"UNCON.WRAITH.CORP"}),
])
def test_known_findings(findings: dict[str, dict[str, Any]], check: str, expected: set[str]) -> None:
    assert expected <= {r["name"] for r in findings[check]["rows"]}


def test_adcs_templates_include_escs_without_bloodhound_edges(findings: dict[str, dict[str, Any]]) -> None:
    rows = findings["adcs-templates"]["rows"]
    assert {"SPICYTEMP@PHANTOM.CORP", "ESC3-SELF@PHANTOM.CORP"} <= {r["target"] for r in rows}


def test_hunt_from_one_object(lab: BHShell, tmp_path: Path) -> None:
    results = {f["check"]: f for f in export(lab, "hunt --from NOPREAUTH@PHANTOM.CORP", tmp_path / "hunt.json")}
    assert all(f["error"] == "" for f in results.values())
    assert results["adcs"]["rows"]  # Domain Users and Authenticated Users can enroll in ESC1 templates


def test_domain_filter(lab: BHShell, tmp_path: Path) -> None:
    results = export(lab, "hunt kerberoastable -d wraith", tmp_path / "hunt.json")
    assert results[0]["count"] == 0
