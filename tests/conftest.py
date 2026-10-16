from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import responses
from rich.console import Console

from bhshell.config import Config
from bhshell.shell.app import BHShell

BASE = "http://BH.test:8080/"
TOKEN = "a.eyJleHAiOjk5OTk5OTk5OTl9.c"  # payload {"exp": 9999999999}


def run(app: BHShell, line: str) -> str:
    """Run a shell command and return everything it printed."""
    app.ui.console.export_text(clear=True)
    app.onecmd_plus_hooks(line)
    return app.ui.console.export_text(clear=True)


def recording(app: BHShell) -> BHShell:
    app.ui.console = Console(record=True, width=200, force_terminal=False)
    app.ui.status = app.ui.console  # capture results and status messages together
    return app


@pytest.fixture
def bhshell_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BHSHELL_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
def mocked() -> Any:
    """A server that accepts logins; tests add or replace the endpoints they need."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/login",
                 json={"data": {"user_id": "u1", "auth_expired": False, "session_token": TOKEN}})
        rsps.add(responses.GET, f"{BASE}api/v2/self",
                 json={"data": {"principal_name": "admin", "roles": [{"name": "Administrator"}]}})
        rsps.add(responses.GET, f"{BASE}api/version", json={"data": {"server_version": "v8.0.0"}})
        yield rsps


@pytest.fixture
def shell(mocked: Any, bhshell_home: Path, monkeypatch: pytest.MonkeyPatch) -> BHShell:
    monkeypatch.setenv("BH_PASSWORD", "pw")
    return recording(BHShell(Config(url=BASE), resume=False))
