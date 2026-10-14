"""Everything the client and query layer raise derives from BHError, so the shell
can print it as a one-line error with an optional hint."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bhshell.models.entities import Node


class BHError(Exception):
    hint: str = ""

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        if hint:
            self.hint = hint


class ConnectionFailed(BHError):
    hint = "Check the backend with 'url' and 'tls', then retry."


class AuthError(BHError):
    hint = "Run 'login' to authenticate again."


class NotAuthenticated(AuthError):
    hint = "Run 'login' first."


class MFARequired(AuthError):
    hint = "Re-run 'login' and provide the one-time password."


class LoginFailed(AuthError):
    # Unlike a plain 401, a rejected login does not drop the session already in use.
    hint = "Check the credentials and retry; the previous session (if any) is still active."


class ForbiddenError(BHError):
    pass


class NotFoundError(BHError):
    pass


class ApiError(BHError):
    def __init__(self, status: int, message: str, *, hint: str = "") -> None:
        super().__init__(f"HTTP {status}: {message}", hint=hint)
        self.status = status
        self.detail = message


class CypherDisabledError(BHError):
    pass


class UnsupportedFeature(BHError):
    pass


class AmbiguousMatchError(BHError):
    hint = "Qualify the name: 'jdoe@corp.local', 'CORP\\jdoe', '--domain CORP.LOCAL' or use the SID."

    def __init__(self, query: str, candidates: Sequence[Node], *, hint: str = "") -> None:
        super().__init__(f"'{query}' matches {len(candidates)} objects", hint=hint)
        self.query = query
        self.candidates = list(candidates)
