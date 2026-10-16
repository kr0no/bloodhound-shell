"""Transport and auth failures that the lab server can't be made to produce on demand."""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
import requests
import responses
from cmd2.string_utils import strip_style, stylize

from bhshell.client.auth import HMACAuth
from bhshell.client.client import BHClient, normalize_url
from bhshell.config import CachedSession, Config
from bhshell.errors import AuthError, ConnectionFailed, CypherDisabledError, LoginFailed, MFARequired
from bhshell.queries.service import EntityService
from bhshell.shell.app import BHShell
from tests.conftest import BASE, TOKEN, run


def connected(app: BHShell) -> bool:
    """Read the auth state from the prompt colour ("shell" is green when authenticated, red otherwise)."""
    assert strip_style(app.prompt) == "[bh: shell] > "
    return stylize("shell", "green") in app.prompt


@pytest.mark.parametrize("raw, expected", [
    ("127.0.0.1:8080", "http://127.0.0.1:8080/"),
    ("https://BH.lab:8443", "https://BH.lab:8443/"),
    ("https://BH.lab/prefix/", "https://BH.lab/prefix/"),
    ("", "http://127.0.0.1:8080/"),
])
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_normalize_url_rejects_bad_scheme() -> None:
    with pytest.raises(ValueError):
        normalize_url("ftp://host")


def test_hmac_signature_matches_reference_algorithm() -> None:
    fixed = datetime(2024, 5, 1, 12, 34, 56, tzinfo=UTC)
    auth = HMACAuth("token-id", "secret-key", clock=lambda: fixed)
    req = requests.Request("POST", f"{BASE}api/v2/graphs/cypher?x=1", json={"query": "q"}).prepare()
    auth(req)

    date = fixed.isoformat("T")
    k1 = hmac.new(b"secret-key", b"POST/api/v2/graphs/cypher?x=1", hashlib.sha256).digest()
    k2 = hmac.new(k1, date[:13].encode(), hashlib.sha256).digest()
    expected = base64.b64encode(hmac.new(k2, req.body, hashlib.sha256).digest()).decode()

    assert req.headers["Authorization"] == "bhesignature token-id"
    assert req.headers["RequestDate"] == date
    assert req.headers["Signature"] == expected


def test_login_detects_mfa() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/login", status=400,
                 json={"errors": [{"message": "one time password is required"}]})
        with pytest.raises(MFARequired):
            BHClient(BASE).login("admin", "pw")


def test_failed_login_keeps_the_previous_session() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/login", status=401, json={"errors": [{"message": "bad creds"}]})
        c = BHClient(BASE)
        c.set_jwt("old-token", "admin")
        with pytest.raises(LoginFailed):
            c.login("other", "wrong")
        assert c.jwt == "old-token" and c.username == "admin"


def test_401_maps_to_auth_error(mocked: responses.RequestsMock) -> None:
    mocked.replace(responses.GET, f"{BASE}api/v2/self", status=401, json={"errors": [{"message": "token expired"}]})
    c = BHClient(BASE)
    c.set_jwt(TOKEN, "admin")
    with pytest.raises(AuthError, match="token expired"):
        c.self_info()


def test_expired_session_drops_the_shell_to_disconnected(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    mocked.add(responses.POST, f"{BASE}api/v2/graphs/cypher", status=401,
               json={"errors": [{"message": "session expired"}]})
    assert "session expired" in run(shell, "user jdoe")
    assert not connected(shell)


def test_resumed_session_survives_a_server_error(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    mocked.replace(responses.GET, f"{BASE}api/v2/self", status=502, body="Bad Gateway")
    assert BHShell(Config(url=BASE)).client.is_authenticated


def test_failed_relogin_keeps_the_shell_connected(shell: BHShell, mocked: Any) -> None:
    run(shell, "login -u admin")
    mocked.replace(responses.POST, f"{BASE}api/v2/login", status=401, json={"errors": [{"message": "bad"}]})
    assert "Login failed" in run(shell, "login -u someone")
    assert shell.client.is_authenticated and connected(shell)
    assert CachedSession.load() is not None


def test_slow_post_is_sent_once_and_reported_as_timeout() -> None:
    # urllib3 must not retry a Cypher POST after a read timeout.
    hits: list[float] = []

    class Slow(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            hits.append(time.time())
            time.sleep(0.6)

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        c = BHClient(f"http://127.0.0.1:{server.server_port}", timeout=(1, 0.2))
        c.set_jwt("t")
        with pytest.raises(ConnectionFailed, match="timed out"):
            c.cypher("MATCH (n) RETURN n")
        assert len(hits) == 1
    finally:
        server.shutdown()


def test_missing_cypher_endpoint_means_cypher_is_disabled() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/graphs/cypher", status=404, body="404 page not found")
        c = BHClient(BASE)
        c.set_jwt("t")
        with pytest.raises(CypherDisabledError):
            c.cypher("MATCH (n) RETURN n")


def test_lookup_falls_back_to_rest_when_cypher_is_disabled() -> None:
    user, group = "S-1-5-21-1000-1104", "S-1-5-21-1000-1200"
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/graphs/cypher", status=404, body="404 page not found")
        rsps.add(responses.GET, f"{BASE}api/v2/search",
                 json={"data": [{"objectid": user, "type": "User", "name": "JDOE@CORP.LOCAL"}]})
        rsps.add(responses.GET, f"{BASE}api/v2/users/{user}",
                 json={"data": {"props": {"name": "JDOE@CORP.LOCAL", "objectid": user, "domain": "CORP.LOCAL",
                                          "hasspn": True}}})
        rsps.add(responses.GET, f"{BASE}api/v2/users/{user}/memberships",
                 json={"count": 1, "data": [{"objectID": group, "name": "IT ADMINS@CORP.LOCAL", "label": "Group"}]})
        client = BHClient(BASE)
        client.set_jwt("t")
        svc = EntityService(client)
        node = svc.resolve("jdoe", "User")
        assert svc.cypher_available is False
        assert node.properties["hasspn"] is True
        view = svc.groups(node)[0]
        assert view.backend == "rest"
        assert [r.target for r in view.rows] == ["IT ADMINS@CORP.LOCAL"]


def test_paginate_trusts_count_when_server_caps_page_size() -> None:
    with responses.RequestsMock() as rsps:
        c = BHClient(BASE, page_size=5)
        c.set_jwt("t")
        url = f"{BASE}api/v2/saved-queries"
        for skip, items in ((0, [1, 2, 3]), (3, [4, 5, 6]), (6, [7])):  # the server returns at most 3
            rsps.add(responses.GET, url, json={"count": 7, "data": items},
                     match=[responses.matchers.query_param_matcher({"skip": str(skip), "limit": "5"})])
        assert list(c.paginate("api/v2/saved-queries")) == [1, 2, 3, 4, 5, 6, 7]
