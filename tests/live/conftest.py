"""Tests against a BloodHound server loaded with the sample data from the BloodHound quickstart.

Set BHSHELL_TEST_URL plus BH_USER / BH_PASSWORD (or BH_TOKEN_ID / BH_TOKEN_KEY) to run them.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from bhshell.config import Config
from bhshell.shell.app import BHShell
from tests.conftest import recording, run

URL = os.environ.get("BHSHELL_TEST_URL", "")

PHANTOM_SID = "S-1-5-21-2697957641-2271029196-387917394"
NOPREAUTH = f"{PHANTOM_SID}-2220"  # NOPREAUTH@PHANTOM.CORP: AS-REP roastable, in an OU that blocks inheritance


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip = pytest.mark.skip(reason="set BHSHELL_TEST_URL to run the tests against a BloodHound server")
    here = Path(__file__).parent
    for item in items:
        if here in item.path.parents:
            item.add_marker(pytest.mark.live)
            if not URL:
                item.add_marker(skip)


@pytest.fixture(scope="session")
def lab_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A BHSHELL_HOME of its own, so the tests never touch ~/.bhshell."""
    home = tmp_path_factory.mktemp("home")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("BHSHELL_HOME", str(home))
        yield home


@pytest.fixture(scope="session")
def lab(lab_home: Path) -> BHShell:
    """A shell logged in to the lab, shared by every test."""
    app = recording(BHShell(Config(url=URL, verify_tls=os.environ.get("BHSHELL_TEST_TLS") != "off"), resume=False))
    if os.environ.get("BH_TOKEN_ID"):
        out = run(app, "login --token")
    else:
        out = run(app, f"login -u {os.environ.get('BH_USER', 'admin')}")
    assert app.client.is_authenticated, out
    return app


def ok(app: BHShell, line: str) -> str:
    """Run a command that must succeed and return its output."""
    failures = app.command_failures
    out = run(app, line)
    assert app.command_failures == failures, out
    return out


def export(app: BHShell, line: str, path: Path) -> Any:
    """Run a command with `-o PATH` (.json) and return what it wrote."""
    ok(app, f"{line} -o {path}")
    return json.loads(path.read_text())
