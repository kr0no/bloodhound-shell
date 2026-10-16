from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from bhshell.shell.app import BHShell
from tests.live.conftest import export, ok


def test_paths_to_tier_zero(lab: BHShell, tmp_path: Path) -> None:
    paths = export(lab, "path NOPREAUTH@PHANTOM.CORP", tmp_path / "path.json")["paths"]
    assert len(paths) == 17
    assert all(p["start"] == "NOPREAUTH@PHANTOM.CORP" and p["hops"][-1]["tier_zero"] for p in paths)


def test_path_between_two_objects(lab: BHShell, tmp_path: Path) -> None:
    # HAYDEN is disabled: a destination named on purpose is kept.
    paths = export(lab, "path T1_TONYMONTANA@PHANTOM.CORP HAYDEN@PHANTOM.CORP", tmp_path / "path.json")["paths"]
    assert {p["end"] for p in paths} == {"HAYDEN@PHANTOM.CORP"}
    assert ["GenericAll", "MemberOf", "ReadGMSAPassword"] in [[h["edge"] for h in p["hops"]] for p in paths]


def test_paths_skip_disabled_objects_unless_asked(lab: BHShell, tmp_path: Path) -> None:
    def ends(result: dict) -> set[str]:
        return {p["end"] for p in result["paths"]}

    default = export(lab, "path T1_TONYMONTANA@PHANTOM.CORP -n 0", tmp_path / "default.json")
    assert default["skipped_disabled"] == ["HAYDEN@PHANTOM.CORP"]
    assert "HAYDEN@PHANTOM.CORP" not in ends(default)
    everything = export(lab, "path T1_TONYMONTANA@PHANTOM.CORP -n 0 --include-disabled", tmp_path / "all.json")
    assert "HAYDEN@PHANTOM.CORP" in ends(everything)


def test_route_goes_through_every_via_step(lab: BHShell, tmp_path: Path) -> None:
    line = "path NOPREAUTH@PHANTOM.CORP --via 'DOMAIN USERS@PHANTOM.CORP'"
    paths = export(lab, line, tmp_path / "route.json")["paths"]
    assert paths and all("DOMAIN USERS@PHANTOM.CORP" in {h["target"] for h in p["hops"]} for p in paths)


def test_excluded_edges_are_left_out(lab: BHShell, tmp_path: Path) -> None:
    paths = export(lab, "path NOPREAUTH@PHANTOM.CORP --exclude adcs", tmp_path / "path.json")["paths"]
    assert paths and not any(h["edge"].startswith("ADCS") for p in paths for h in p["hops"])


def test_path_diagrams(lab: BHShell, tmp_path: Path) -> None:
    assert "NOPREAUTH" in ok(lab, "path NOPREAUTH@PHANTOM.CORP -g -p 1")
    ok(lab, f"path NOPREAUTH@PHANTOM.CORP -p 1-3 -o {tmp_path / 'paths.svg'}")
    labels = [t.text for t in ET.parse(tmp_path / "paths.svg").iter("{http://www.w3.org/2000/svg}text")]
    assert "NOPREAUTH" in labels
    ok(lab, f"path NOPREAUTH@PHANTOM.CORP -p 1 -o {tmp_path / 'paths.png'}")
    assert (tmp_path / "paths.png").read_bytes().startswith(b"\x89PNG")
