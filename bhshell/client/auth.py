"""Request authenticators for the BH API.

Two schemes are supported:

* `JWTAuth` - `Authorization: Bearer <session_token>` obtained from
  `POST /api/v2/login`.
* `HMACAuth` - BH API tokens (Token ID + Token Key). Each request is
  signed with a chained HMAC-SHA256 as documented by SpecterOps:

  1. `k1 = HMAC(token_key, METHOD + URI)`
  2. `k2 = HMAC(k1, RequestDate[:13])`  (RFC3339 date truncated to the hour)
  3. `signature = HMAC(k2, body)`

  Headers: `Authorization: bhesignature <token_id>`, `RequestDate` and
  `Signature` (base64).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit

from requests import PreparedRequest
from requests.auth import AuthBase


class JWTAuth(AuthBase):
    def __init__(self, token: str) -> None:
        self.token = token

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r


class HMACAuth(AuthBase):
    def __init__(
        self,
        token_id: str,
        token_key: str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.token_id = token_id
        self._key = token_key.encode()
        self._clock = clock or (lambda: datetime.now().astimezone())

    @staticmethod
    def _request_uri(url: str) -> str:
        parts = urlsplit(url)
        return parts.path + (f"?{parts.query}" if parts.query else "")

    def sign(self, method: str, uri: str, body: bytes | None, request_date: str) -> str:
        digester = hmac.new(self._key, None, hashlib.sha256)
        digester.update(f"{method.upper()}{uri}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        digester.update(request_date[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body:
            digester.update(body)
        return base64.b64encode(digester.digest()).decode()

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        request_date = self._clock().isoformat("T")
        body = r.body.encode() if isinstance(r.body, str) else r.body
        signature = self.sign(r.method or "GET", self._request_uri(r.url or ""), body, request_date)
        r.headers["Authorization"] = f"bhesignature {self.token_id}"
        r.headers["RequestDate"] = request_date
        r.headers["Signature"] = signature
        return r
