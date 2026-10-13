from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import responses

from bhshell.client.auth import HMACAuth
from bhshell.client.client import BHClient, jwt_claims, normalize_url
from bhshell.errors import (
    AuthError,
    ConnectionFailed,
    CypherDisabledError,
    LoginFailed,
    MFARequired,
    NotAuthenticated,
)
from tests.conftest import BASE


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


def test_login_sets_jwt(mocked: responses.RequestsMock) -> None:
    c = BHClient(BASE)
    c.login("admin", "pw")
    assert c.auth_mode == "jwt" and c.username == "admin"
    assert jwt_claims(c.jwt)["exp"] == 9999999999
    body = json.loads(mocked.calls[-1].request.body)
    assert body == {"login_method": "secret", "username": "admin", "secret": "pw"}


def test_login_detects_mfa() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/login", status=400,
                 json={"errors": [{"message": "one time password is required"}]})
        with pytest.raises(MFARequired):
            BHClient(BASE).login("admin", "pw")


def test_unauthenticated_request_is_refused_locally() -> None:
    with pytest.raises(NotAuthenticated):
        BHClient(BASE).self_info()


def test_401_maps_to_auth_error(client: BHClient, mocked: responses.RequestsMock) -> None:
    mocked.replace(responses.GET, f"{BASE}api/v2/self", status=401,
                   json={"errors": [{"message": "token expired"}]})
    with pytest.raises(AuthError, match="token expired"):
        client.self_info()


def test_cypher_empty_404_is_empty_graph(client: BHClient) -> None:
    assert client.cypher("MATCH (n:Nope) RETURN n") == {"nodes": {}, "edges": [], "literals": []}


def test_cypher_missing_endpoint_is_disabled() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/graphs/cypher", status=404, body="404 page not found")
        c = BHClient(BASE)
        c.set_jwt("t")
        with pytest.raises(CypherDisabledError):
            c.cypher("MATCH (n) RETURN n")


def test_connection_error() -> None:
    c = BHClient("http://127.0.0.1:1/", timeout=(0.5, 0.5))
    c.set_jwt("t")
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, "http://127.0.0.1:1/api/v2/self", body=requests.exceptions.ConnectionError())
        with pytest.raises(ConnectionFailed):
            c.self_info()


def test_paginate_follows_skip() -> None:
    with responses.RequestsMock() as rsps:
        c = BHClient(BASE, page_size=2)
        c.set_jwt("t")
        url = f"{BASE}api/v2/users/X/sessions"
        rsps.add(responses.GET, url, json={"count": 3, "data": [{"n": 1}, {"n": 2}]},
                 match=[responses.matchers.query_param_matcher({"skip": "0", "limit": "2", "type": "list"})])
        rsps.add(responses.GET, url, json={"count": 3, "data": [{"n": 3}]},
                 match=[responses.matchers.query_param_matcher({"skip": "2", "limit": "2", "type": "list"})])
        assert [i["n"] for i in c.entity_related("User", "X", "sessions")] == [1, 2, 3]


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


def test_failed_login_raises_login_failed_and_keeps_session() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, f"{BASE}api/v2/login", status=401, json={"errors": [{"message": "bad creds"}]})
        c = BHClient(BASE)
        c.set_jwt("old-token", "admin")
        with pytest.raises(LoginFailed):
            c.login("other", "wrong")
        assert c.jwt == "old-token" and c.username == "admin"


def test_auth_state_round_trip() -> None:
    c = BHClient(BASE)
    c.set_jwt("jwt", "admin")
    state = c.auth_state()
    c.set_hmac("id", "key")
    c.restore_auth(state)
    assert (c.auth_mode, c.jwt, c.username, c.token_id) == ("jwt", "jwt", "admin", "")


def test_paginate_stops_on_empty_page_despite_count() -> None:
    with responses.RequestsMock() as rsps:
        c = BHClient(BASE, page_size=2)
        c.set_jwt("t")
        url = f"{BASE}api/v2/saved-queries"
        rsps.add(responses.GET, url, json={"count": 50, "data": []})
        assert list(c.paginate("api/v2/saved-queries")) == []
        assert len(rsps.calls) == 1


def test_paginate_trusts_count_when_server_caps_page_size() -> None:
    with responses.RequestsMock() as rsps:
        c = BHClient(BASE, page_size=5)
        c.set_jwt("t")
        url = f"{BASE}api/v2/saved-queries"
        for skip, items in ((0, [1, 2, 3]), (3, [4, 5, 6]), (6, [7])):  # the server returns at most 3
            rsps.add(responses.GET, url, json={"count": 7, "data": items},
                     match=[responses.matchers.query_param_matcher({"skip": str(skip), "limit": "5"})])
        assert list(c.paginate("api/v2/saved-queries")) == [1, 2, 3, 4, 5, 6, 7]
