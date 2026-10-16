from __future__ import annotations

from pathlib import Path

import pytest

from bhshell.shell.app import BHShell
from tests.live.conftest import export


def test_ca_summary(lab: BHShell, tmp_path: Path) -> None:
    summary = export(lab, "ca PHANTOM-DC01-CA@PHANTOM.CORP", tmp_path / "ca.json")["summary"]
    assert summary["User Specified SAN (ESC6)"] is True
    assert summary["Trusted for NT Authentication"] is True
    assert summary["Published templates"] == 41


@pytest.mark.parametrize("template, escs", [
    ("ESC1@PHANTOM.CORP", []),  # needs an authorized signature
    ("ESC1SMARTCARD@PHANTOM.CORP", ["ESC1"]),
    ("ESC3-SELF@PHANTOM.CORP", ["ESC2"]),
    ("SUBCA@PHANTOM.CORP", ["ESC1", "ESC2", "ESC15"]),
    ("WEBSERVER@PHANTOM.CORP", ["ESC15"]),
    ("ENROLLMENTAGENT@PHANTOM.CORP", ["ESC3"]),
    ("ABUSABLETEMPLATE@PHANTOM.CORP", ["ESC4"]),
])
def test_template_escs(lab: BHShell, tmp_path: Path, template: str, escs: list[str]) -> None:
    summary = export(lab, f"template {template}", tmp_path / "template.json")["summary"]
    met = summary["ESC conditions met"]
    assert [e.split(":")[0] for e in met if met != "none"] == escs


def test_ca_templates_view_lists_every_published_template(lab: BHShell, tmp_path: Path) -> None:
    rows = export(lab, "ca PHANTOM-DC01-CA@PHANTOM.CORP -t", tmp_path / "templates.json")["views"]["templates"]["rows"]
    assert len(rows) == 41
