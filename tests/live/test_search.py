from __future__ import annotations

from pathlib import Path

import pytest

from bhshell.shell.app import BHShell
from tests.live.conftest import export


@pytest.mark.parametrize("filters, expected", [
    ("-t user hasspn enabled", {"ADMINISTRATOR@PHANTOM.CORP", "SVC_KERB_DEL@PHANTOM.CORP"}),
    ("-t user name=svc_k*", {"SVC_KERB_DEL@PHANTOM.CORP"}),
    ("-t user dontreqpreauth 'pwdlastset<2025-01-01'", {"NOPREAUTH@PHANTOM.CORP"}),
    ("-t EnterpriseCA", {"PHANTOM-DC01-CA@PHANTOM.CORP", "PHANTOM-SRV-SHARPHOUND-CA@PHANTOM.CORP",
                         "WRAITH-EXTCA01-CA@WRAITH.CORP", "WRAITH-EXTCA02-CA@WRAITH.CORP"}),
])
def test_search_filters(lab: BHShell, tmp_path: Path, filters: str, expected: set[str]) -> None:
    results = export(lab, f"search {filters}", tmp_path / "search.json")["results"]
    assert {r["name"] for r in results} == expected


def test_search_domain_and_negated_filter(lab: BHShell, tmp_path: Path) -> None:
    results = export(lab, "search -t user !enabled -d ghost", tmp_path / "search.json")["results"]
    assert {r["domain"] for r in results} == {"GHOST.CORP"}
    assert "KRBTGT@GHOST.CORP" in {r["name"] for r in results}
    assert not any(r["properties"].get("enabled") for r in results)
