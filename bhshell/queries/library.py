"""Saved Cypher query library.

Sources, later ones overriding earlier ones by name:

1. bundled `bhshell/library/*.cyp`
2. the user's `~/.bhshell/queries/*.cyp`
3. the folders listed in the `query_dirs` setting, in order
4. the server's saved queries (`GET /api/v2/saved-queries`), named `server:<name>`

A `.cyp` file may start with `// name: ...` and `// description: ...`
header lines; the rest of the file is the query.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from bhshell.client.client import BHClient
from bhshell.config import config_home
from bhshell.errors import BHError

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "library"
Source = Literal["builtin", "user", "server"]


@dataclass(frozen=True)
class SavedQuery:
    name: str
    query: str
    description: str = ""
    source: Source = "builtin"


def parse_cyp(text: str, default_name: str, source: Source) -> SavedQuery:
    """Parse a `.cyp` file: `// key: value` header lines followed by the query."""
    meta: dict[str, str] = {}
    body: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not body and stripped.startswith("//"):
            key, sep, value = stripped[2:].partition(":")
            if sep:
                meta[key.strip().lower()] = value.strip()
            continue
        if stripped or body:
            body.append(line)
    return SavedQuery(name=meta.get("name") or default_name, query="\n".join(body).strip(),
                      description=meta.get("description", ""), source=source)


def user_dir() -> Path:
    return config_home() / "queries"


def query_dirs(setting: str) -> list[Path]:
    """The folders of the `query_dirs` setting, separated like PATH (':' on Unix, ';' on Windows)."""
    return [Path(part.strip()).expanduser() for part in setting.split(os.pathsep) if part.strip()]


@dataclass
class QueryLibrary:
    client: BHClient
    # Extra folders of `.cyp` files (`config query_dirs`), loaded after the user's own.
    extra_dirs: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def load(self, *, include_server: bool = True) -> dict[str, SavedQuery]:
        self.notes = []
        queries: dict[str, SavedQuery] = {}
        local: list[tuple[Path, Source]] = [(BUILTIN_DIR, "builtin"), (user_dir(), "user"),
                                            *((d, "user") for d in self.extra_dirs)]
        for directory, source in local:
            if directory in self.extra_dirs and not directory.is_dir():
                self.notes.append(f"Query folder {directory} not found (see 'config query_dirs').")
            for path in sorted(directory.glob("*.cyp")) if directory.is_dir() else []:
                try:
                    q = parse_cyp(path.read_text(encoding="utf-8"), path.stem, source)
                except OSError as exc:
                    self.notes.append(f"Cannot read {path}: {exc.strerror}")
                    continue
                if q.query:
                    queries[q.name] = q
        if include_server and self.client.is_authenticated:
            try:
                for item in self.client.paginate("api/v2/saved-queries"):
                    name = f"server:{item.get('name', item.get('id'))}"
                    queries[name] = SavedQuery(name=name, query=item.get("query", ""),
                                               description=item.get("description", ""), source="server")
            except BHError as exc:
                self.notes.append(f"Server saved queries unavailable: {exc.message}")
        return dict(sorted(queries.items()))
