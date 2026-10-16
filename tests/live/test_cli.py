from __future__ import annotations

import csv
import io
import json
import os
import sys
from pathlib import Path

import pytest

from bhshell.cli import main
from bhshell.config import CachedSession, Config
from bhshell.shell.app import BHShell
from tests.conftest import recording, run
from tests.live.conftest import URL, ok


def test_login_resume_and_logout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.environ.get("BH_TOKEN_ID"):
        pytest.skip("token logins are not cached")
    monkeypatch.setenv("BHSHELL_HOME", str(tmp_path))
    config = Config(url=URL, verify_tls=os.environ.get("BHSHELL_TEST_TLS") != "off")
    app = recording(BHShell(config, resume=False))
    ok(app, f"login -u {os.environ.get('BH_USER', 'admin')}")
    resumed = recording(BHShell(config))
    assert resumed.client.is_authenticated
    run(resumed, "logout")
    assert CachedSession.load() is None


def test_exit_codes_and_json_on_stdout(lab: BHShell, capsys: pytest.CaptureFixture[str]) -> None:
    # Reuses the session the lab fixture cached in its BHSHELL_HOME.
    capsys.readouterr()
    assert main(["-c", "hunt dcsync --json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["check"] == "dcsync"
    assert main(["-c", "user no-such-user"]) == 1


def test_export_formats(lab: BHShell, tmp_path: Path) -> None:
    ok(lab, f"hunt kerberoastable -o {tmp_path / 'kerb.csv'}")
    rows = list(csv.DictReader((tmp_path / "kerb.csv").open()))
    assert {r["name"] for r in rows} == {"ADMINISTRATOR@PHANTOM.CORP", "SVC_KERB_DEL@PHANTOM.CORP"}
    assert rows[0]["check"] == "kerberoastable"

    ok(lab, f"group 'DOMAIN ADMINS@PHANTOM.CORP' -m -o {tmp_path / 'da.txt'}")
    names = (tmp_path / "da.txt").read_text().split()
    assert "ALICE@PHANTOM.CORP" in names and "DOMAIN" not in names

    # Names go to the shell's stdout, not to the console, so they can be piped.
    lab.stdout = io.StringIO()
    try:
        ok(lab, "hunt kerberoastable --names-only")
        assert lab.stdout.getvalue().split() == ["ADMINISTRATOR@PHANTOM.CORP", "SVC_KERB_DEL@PHANTOM.CORP"]
    finally:
        lab.stdout = sys.stdout
