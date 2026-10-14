"""Persistent configuration and session cache.

Layout (overridable with the `BHSHELL_HOME` environment variable):

    ~/.bhshell/
        config.toml    # backend URL, TLS, timeouts, last username, query folders
        session.json   # cached JWT (mode 0600)
        history        # cmd2 command history
"""

from __future__ import annotations

import json
import math
import os
import tomllib
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

DEFAULT_URL = "http://127.0.0.1:8080/"


def config_home() -> Path:
    home = Path(os.environ.get("BHSHELL_HOME", Path.home() / ".bhshell")).expanduser()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    return home


# Lowest accepted value of numeric settings (`display_rows` 0 means "all rows").
_MINIMUMS: dict[str, float] = {"connect_timeout": 1, "read_timeout": 1, "page_size": 1, "max_results": 1,
                               "display_rows": 0}


def parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"not a boolean: {value!r}")


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    # JSON string escaping is a valid subset of TOML basic strings.
    return json.dumps(str(value))


def _write_private(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, 0o600)


def _absolute_dirs(setting: str) -> str:
    """`query_dirs` with relative folders made absolute, so the setting works from any directory.

    `~` and absolute folders are kept as written.
    """
    parts = [p.strip() for p in setting.split(os.pathsep) if p.strip()]
    return os.pathsep.join(p if p.startswith("~") or Path(p).is_absolute() else str(Path(p).absolute())
                           for p in parts)


@dataclass
class Config:
    url: str = DEFAULT_URL
    verify_tls: bool = True
    connect_timeout: float = 5.0
    read_timeout: float = 60.0
    last_username: str = ""
    page_size: int = 500
    max_results: int = 5000
    display_rows: int = 100
    cache_session: bool = True
    # Extra folders of .cyp queries for 'query', separated like PATH (':' on Unix, ';' on Windows).
    query_dirs: str = ""

    @classmethod
    def path(cls) -> Path:
        return config_home() / "config.toml"

    @classmethod
    def load(cls) -> Config:
        """Unknown keys and invalid values are ignored."""
        path = cls.path()
        if not path.exists():
            return cls()
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return cls()
        known = {f.name for f in fields(cls)}
        cfg = cls()
        for key, value in data.items():
            if key in known:
                try:
                    setattr(cfg, key, cls.coerce(key, value))
                except (TypeError, ValueError):
                    pass
        return cfg

    @classmethod
    def coerce(cls, key: str, value: Any) -> Any:
        """Convert `value` to the type of setting `key`.

        Raises TypeError for a value of the wrong type, ValueError for an invalid one.
        """
        default = getattr(cls(), key)
        if isinstance(default, bool):
            return value if isinstance(value, bool) else parse_bool(str(value))
        if isinstance(default, (int, float)):
            if isinstance(value, bool):
                raise TypeError(f"expected a number, got {value!r}")
            try:
                number = type(default)(value)
            except ValueError:
                raise ValueError(f"expected {'a whole number' if isinstance(default, int) else 'a number'}, "
                                 f"got {value!r}") from None
            if not math.isfinite(number):
                raise ValueError(f"not a finite number: {value!r}")
            minimum = _MINIMUMS.get(key)
            if minimum is not None and number < minimum:
                raise ValueError(f"must be at least {minimum}")
            return number
        if key == "url":
            from bhshell.client.client import normalize_url  # late: the client imports this module

            return normalize_url(str(value))
        if key == "query_dirs":
            return _absolute_dirs(str(value))
        return str(value)

    def save(self) -> None:
        lines = ["# bhshell configuration", *(f"{k} = {_toml_value(v)}" for k, v in asdict(self).items())]
        _write_private(self.path(), "\n".join(lines) + "\n")


@dataclass
class CachedSession:
    url: str
    token: str
    username: str = ""

    @staticmethod
    def path() -> Path:
        return config_home() / "session.json"

    @classmethod
    def load(cls) -> CachedSession | None:
        path = cls.path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            session = cls(url=data["url"], token=data["token"], username=data.get("username", ""))
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if not all(isinstance(v, str) for v in (session.url, session.token, session.username)):
            return None
        return session

    def save(self) -> None:
        _write_private(self.path(), json.dumps(asdict(self)))

    @classmethod
    def clear(cls) -> None:
        try:
            cls.path().unlink()
        except FileNotFoundError:
            pass


def history_file() -> Path:
    return config_home() / "history"
