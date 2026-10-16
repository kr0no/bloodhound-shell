from __future__ import annotations

from pathlib import Path

from bhshell.shell.app import BHShell
from tests.live.conftest import export


def test_ou_tree_counts_and_blocked_inheritance(lab: BHShell, tmp_path: Path) -> None:
    rows = export(lab, "ou phantom.corp -t", tmp_path / "tree.json")["views"]["tree"]["rows"]
    domain = rows[0]
    assert (domain["name"], domain["users"], domain["enabled_users"], domain["computers"]) == ("PHANTOM.CORP", 51, 47, 21)
    tier0 = next(r for r in rows if r["name"] == "TIER0@PHANTOM.CORP")
    assert tier0["blocks_inheritance"] is True and tier0["users"] == 17


def test_ou_contents_cover_every_level(lab: BHShell, tmp_path: Path) -> None:
    rows = export(lab, "ou TIER0@PHANTOM.CORP -c", tmp_path / "contents.json")["views"]["contents"]["rows"]
    assert len(rows) == 31
    nopreauth = next(r for r in rows if r["name"] == "NOPREAUTH@PHANTOM.CORP")
    assert (nopreauth["location"], nopreauth["depth"]) == ("USERS", 2)


def test_gpo_links_affected_objects_and_editors(lab: BHShell, tmp_path: Path) -> None:
    report = export(lab, "gpo 'ENABLE AV@PHANTOM.CORP' --all", tmp_path / "gpo.json")
    assert report["summary"]["Linked to"] == ["COMPUTERS@PHANTOM.CORP"]
    assert report["summary"]["Editable by (outside Tier Zero)"] == ["GPO ADMINS - WORKSTATIONS@PHANTOM.CORP"]
    affected = {r["name"] for r in report["views"]["affected"]["rows"]}
    assert len(affected) == 5 and "DF-WIN10-DEV01.PHANTOM.CORP" in affected


def test_domains_tell_collected_from_trust_only(lab: BHShell, tmp_path: Path) -> None:
    domains = {d["name"]: d for d in export(lab, "domains", tmp_path / "domains.json")}
    assert {n for n, d in domains.items() if d["collected"]} == {"PHANTOM.CORP", "WRAITH.CORP", "GHOST.CORP"}
    assert {n for n, d in domains.items() if not d["collected"]} == {"REVENANT.CORP", "CHILD.WRAITH.CORP"}
    assert (domains["PHANTOM.CORP"]["users"], domains["PHANTOM.CORP"]["enabled_users"]) == (52, 47)


def test_trusts_report_sid_filtering(lab: BHShell, tmp_path: Path) -> None:
    trusts = {(t["trusting"], t["trusted"]): t for t in export(lab, "trusts", tmp_path / "trusts.json")}
    assert len(trusts) == 7
    external = trusts[("PHANTOM.CORP", "WRAITH.CORP")]
    assert (external["kind"], external["trust_type"], external["sid_filtering"]) == ("CrossForestTrust", "External", True)
    assert "SID filtering not enforced" in trusts[("GHOST.CORP", "PHANTOM.CORP")]["issues"]
