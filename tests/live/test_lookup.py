from __future__ import annotations

from pathlib import Path

import pytest

from bhshell.shell.app import BHShell
from tests.conftest import run
from tests.live.conftest import NOPREAUTH, PHANTOM_SID, export, ok


def test_user_report_covers_every_view(lab: BHShell, tmp_path: Path) -> None:
    report = export(lab, "user NOPREAUTH@PHANTOM.CORP --all", tmp_path / "user.json")
    assert report["entity"]["objectid"] == NOPREAUTH
    assert report["summary"]["AS-REP Roastable (dontreqpreauth)"] is True
    views = report["views"]
    assert set(views) == {"groups", "outbound", "inbound", "sessions", "privs_held", "gpos"}
    assert "AUTHENTICATED USERS@PHANTOM.CORP" in {r["target"] for r in views["groups"]["rows"]}  # nested
    assert {"ADCSESC1", "Enroll"} <= {r["edge"] for r in views["outbound"]["rows"]}
    assert "DOMAIN ADMINS@PHANTOM.CORP" in {r["principal"] for r in views["inbound"]["rows"]}
    assert ("AdminTo", "ADMINSERVER01.PHANTOM.CORP") in {(r["edge"], r["target"]) for r in views["privs_held"]["rows"]}


@pytest.mark.parametrize("name", [
    "NOPREAUTH@PHANTOM.CORP", "nopreauth", "PHANTOM\\nopreauth", NOPREAUTH,
    "CN=NOPREAUTH,OU=USERS,OU=TIER0,DC=PHANTOM,DC=CORP",
])
def test_every_name_form_finds_the_user(lab: BHShell, name: str) -> None:
    assert NOPREAUTH in ok(lab, f"user {name}")


def test_ambiguous_name_lists_the_candidates(lab: BHShell) -> None:
    out = run(lab, "user administrator")
    assert all(f"ADMINISTRATOR@{d}" in out for d in ("GHOST.CORP", "PHANTOM.CORP", "WRAITH.CORP"))
    assert f"{PHANTOM_SID}-500" in ok(lab, "user administrator -d phantom")


def test_group_members_include_nested_groups(lab: BHShell, tmp_path: Path) -> None:
    rows = export(lab, "group 'DOMAIN ADMINS@PHANTOM.CORP' -m", tmp_path / "da.json")["views"]["members"]["rows"]
    members = {r["principal"]: r for r in rows}
    assert members["SUBDAS@PHANTOM.CORP"]["depth"] == 1
    assert members["ALICE@PHANTOM.CORP"]["via"] == "SUBDAS@PHANTOM.CORP"


def test_applied_gpos_stop_at_blocked_inheritance(lab: BHShell, tmp_path: Path) -> None:
    rows = export(lab, "user NOPREAUTH@PHANTOM.CORP -G", tmp_path / "gpos.json")["views"]["gpos"]["rows"]
    gpos = {r["gpo"]: r for r in rows}
    assert gpos["TESTUSERSETTING@PHANTOM.CORP"]["applies"] is True
    assert gpos["DEFAULT DOMAIN POLICY@PHANTOM.CORP"]["applies"] is False
    assert "inheritance blocked at TIER0" in gpos["DEFAULT DOMAIN POLICY@PHANTOM.CORP"]["reason"]


def test_computer_gpos_name_editors_outside_tier_zero(lab: BHShell, tmp_path: Path) -> None:
    rows = export(lab, "computer DF-WIN10-DEV01.PHANTOM.CORP -G", tmp_path / "gpos.json")["views"]["gpos"]["rows"]
    av = next(r for r in rows if r["gpo"] == "ENABLE AV@PHANTOM.CORP")
    assert av["applies"] is True
    assert "GPO ADMINS - WORKSTATIONS@PHANTOM.CORP" in av["editable_by"]
