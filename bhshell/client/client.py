"""BH REST API v2 transport: auth, retries, error mapping and pagination.

Returns decoded JSON as-is; bhshell.queries makes sense of it."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Iterator
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from bhshell import __version__
from bhshell.client.auth import HMACAuth, JWTAuth
from bhshell.config import DEFAULT_URL
from bhshell.errors import (
    ApiError,
    AuthError,
    ConnectionFailed,
    CypherDisabledError,
    ForbiddenError,
    LoginFailed,
    MFARequired,
    NotAuthenticated,
    NotFoundError,
)

AuthMode = Literal["none", "jwt", "hmac"]

_MFA_MARKERS = ("otp", "one time", "one-time", "mfa", "totp")


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return DEFAULT_URL
    if "://" not in url:
        url = f"http://{url}"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"Invalid backend URL: {url!r}")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}/"


def route_missing(exc: NotFoundError) -> bool:
    """Whether a 404 means the endpoint does not exist (Go's router), not that nothing was found."""
    return "page not found" in exc.message.lower()


def jwt_claims(token: str) -> dict[str, Any]:
    """The payload of a JWT, not verified."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return {}


class BHClient:
    def __init__(
        self,
        base_url: str = DEFAULT_URL,
        *,
        verify_tls: bool = True,
        timeout: tuple[float, float] = (5.0, 60.0),
        page_size: int = 500,
    ) -> None:
        self.base_url = normalize_url(base_url)
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.page_size = page_size
        self.auth_mode: AuthMode = "none"
        self.username: str = ""
        self.token_id: str = ""
        self.jwt: str = ""
        self._auth: requests.auth.AuthBase | None = None

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": f"bhshell/{__version__}", "Accept": "application/json"})
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 502, 503, 504),
            # Only idempotent methods, and never after a read timeout: a slow Cypher
            # query (POST) would otherwise run up to four times on the server.
            read=False,
            allowed_methods=frozenset({"GET", "PUT", "DELETE"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).netloc

    @property
    def is_authenticated(self) -> bool:
        return self._auth is not None

    def set_url(self, url: str) -> None:
        """Credentials are dropped when the URL changes."""
        new = normalize_url(url)
        if new != self.base_url:
            self.clear_auth()
        self.base_url = new

    def set_jwt(self, token: str, username: str = "") -> None:
        self._auth = JWTAuth(token)
        self.auth_mode = "jwt"
        self.jwt = token
        self.username = username
        self.token_id = ""

    def set_hmac(self, token_id: str, token_key: str) -> None:
        self._auth = HMACAuth(token_id, token_key)
        self.auth_mode = "hmac"
        self.token_id = token_id
        self.jwt = ""
        self.username = ""

    def auth_state(self) -> tuple[Any, ...]:
        return (self._auth, self.auth_mode, self.username, self.token_id, self.jwt)

    def restore_auth(self, state: tuple[Any, ...]) -> None:
        self._auth, self.auth_mode, self.username, self.token_id, self.jwt = state

    def clear_auth(self) -> None:
        self._auth = None
        self.auth_mode = "none"
        self.username = ""
        self.token_id = ""
        self.jwt = ""

    def token_expiry(self) -> float | None:
        if self.auth_mode != "jwt":
            return None
        exp = jwt_claims(self.jwt).get("exp")
        return float(exp) if isinstance(exp, (int, float)) else None

    def token_expired(self) -> bool:
        exp = self.token_expiry()
        return exp is not None and exp <= time.time()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        auth: bool = True,
    ) -> Any:
        if auth and self._auth is None:
            raise NotAuthenticated("Not authenticated")
        url = urljoin(self.base_url, path.lstrip("/"))
        try:
            resp = self._session.request(
                method,
                url,
                params=params,
                json=json_body,
                auth=self._auth if auth else None,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except requests.exceptions.SSLError as exc:
            raise ConnectionFailed(
                f"TLS error talking to {self.host}: {exc}",
                hint="Use 'tls off' for self-signed certificates.",
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise ConnectionFailed(f"Request to {url} timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise ConnectionFailed(f"Cannot reach BH at {self.base_url} ({exc.__class__.__name__})") from exc
        return self._handle(resp)

    @staticmethod
    def _error_message(resp: requests.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return resp.text.strip()[:300] or resp.reason or "unknown error"
        if isinstance(body, dict):
            errors = body.get("errors")
            if isinstance(errors, list) and errors:
                msgs = [e.get("message", "") for e in errors if isinstance(e, dict)]
                if any(msgs):
                    return "; ".join(m for m in msgs if m)
            for key in ("message", "error"):
                if isinstance(body.get(key), str):
                    return body[key]
        return str(body)[:300]

    def _handle(self, resp: requests.Response) -> Any:
        if resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError as exc:
                raise ApiError(resp.status_code, "Response is not valid JSON") from exc
        msg = self._error_message(resp)
        if resp.status_code == 401:
            raise AuthError(f"Unauthorized: {msg}")
        if resp.status_code == 403:
            raise ForbiddenError(f"Forbidden: {msg}")
        if resp.status_code == 404:
            raise NotFoundError(msg or "Not found")
        raise ApiError(resp.status_code, msg)

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params or None)

    def paginate(self, path: str, *, limit: int | None = None, **params: Any) -> Iterator[dict[str, Any]]:
        skip = 0
        yielded = 0
        while True:
            page = self.get(path, skip=skip, limit=self.page_size, **params) or {}
            items = page.get("data") or []
            if isinstance(items, dict):  # e.g. asset-group-tags selectors: {"data": {"selectors": [...]}}
                items = next((v for v in items.values() if isinstance(v, list)), [])
            if not items:
                return
            for item in items:
                yield item
                yielded += 1
                if limit is not None and yielded >= limit:
                    return
            count = page.get("count")
            skip += len(items)
            # Trust the total when there is one: the server may cap `limit` below our page size.
            done = (skip >= count) if isinstance(count, int) else (len(items) < self.page_size)
            if done:
                return

    def login(self, username: str, password: str, otp: str | None = None) -> dict[str, Any]:
        """Switch to JWT auth. Returns the login response's `data` (user_id, auth_expired, session_token)."""
        body: dict[str, Any] = {"login_method": "secret", "username": username, "secret": password}
        if otp:
            body["otp"] = otp
        try:
            resp = self.request("POST", "api/v2/login", json_body=body, auth=False)
        except (AuthError, ApiError) as exc:
            text = exc.message.lower()
            if not otp and any(marker in text for marker in _MFA_MARKERS):
                raise MFARequired("A one-time password is required for this account") from exc
            if isinstance(exc, AuthError):
                raise LoginFailed("Login failed: invalid username or password") from exc
            raise
        data = (resp or {}).get("data") or {}
        token = data.get("session_token")
        if not token:
            raise ApiError(200, "Login response did not contain a session token")
        self.set_jwt(token, username)
        return data

    def logout(self) -> None:
        try:
            if self.auth_mode == "jwt":
                self.request("POST", "api/v2/logout")
        except (AuthError, NotFoundError, ApiError, ConnectionFailed):
            pass
        finally:
            self.clear_auth()

    def self_info(self) -> dict[str, Any]:
        # BH answers unauthenticated requests here with 200 {"data": null} instead of 401.
        data = (self.get("api/v2/self") or {}).get("data")
        if not data:
            raise AuthError("Not authenticated (server returned no principal)")
        return data

    def version(self) -> dict[str, Any]:
        return (self.get("api/version") or {}).get("data") or {}

    def cypher(self, query: str, include_properties: bool = True) -> dict[str, Any]:
        body = {"query": query, "include_properties": include_properties}
        try:
            resp = self.request("POST", "api/v2/graphs/cypher", json_body=body)
        except NotFoundError as exc:  # also how BH answers an empty result
            if route_missing(exc):
                raise CypherDisabledError("The cypher endpoint does not exist on this server") from exc
            return {"nodes": {}, "edges": [], "literals": []}
        except ForbiddenError as exc:
            raise CypherDisabledError(f"Cypher queries are not permitted: {exc.message}") from exc
        except ApiError as exc:
            if exc.status in (405, 501):
                raise CypherDisabledError(f"Cypher queries are disabled: {exc.detail}") from exc
            raise
        data = (resp or {}).get("data") or {}
        nodes = data.get("nodes") or {}
        edges = data.get("edges") or []
        return {"nodes": nodes, "edges": edges, "literals": data.get("literals") or []}

    def search(self, query: str, kind: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"q": query}
        if kind:
            params["type"] = kind
        resp = self.get("api/v2/search", **params) or {}
        data = resp.get("data") or []
        return data if isinstance(data, list) else []

    def entity(self, kind: str, objectid: str) -> dict[str, Any]:
        resp = self.get(f"api/v2/{_collection(kind)}/{objectid}", counts="false") or {}
        data = resp.get("data") or {}
        return data.get("props") or data

    def entity_related(
        self, kind: str, objectid: str, relation: str, *, limit: int | None = None
    ) -> list[dict[str, Any]]:
        path = f"api/v2/{_collection(kind)}/{objectid}/{relation}"
        return list(self.paginate(path, limit=limit, type="list"))


def _collection(kind: str) -> str:
    mapping = {
        "user": "users",
        "computer": "computers",
        "group": "groups",
        "domain": "domains",
        "gpo": "gpos",
        "ou": "ous",
        "container": "containers",
    }
    try:
        return mapping[kind.lower()]
    except KeyError as exc:
        raise ValueError(f"No REST collection for kind {kind!r}") from exc
