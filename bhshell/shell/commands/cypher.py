"""Raw Cypher command."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from cmd2 import Statement

from bhshell.errors import BHError
from bhshell.shell.commands.base import BaseCommands, output_path

CYPHER_HELP = """\
Usage: cypher [--json | --names-only] [-o FILE] [-f QUERY_FILE] [QUERY]

Run a raw Cypher query against BH (POST /api/v2/graphs/cypher) and render
what it returns: nodes and edges, or values. The query is taken verbatim from
the command line, so '|', '>' and quotes need no escaping. For example:

  cypher MATCH (n:User) WHERE n.hasspn = true RETURN n LIMIT 20
  cypher MATCH p=(u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p
  cypher MATCH (n:Computer) RETURN n.operatingsystem AS os, count(n) AS total
  cypher -f queries/kerberoastable.cyp -o kerberoastable.csv
  cypher --names-only MATCH (n:Computer) WHERE n.enabled = true RETURN n

Options:
  --json        print the normalised result as JSON
  --names-only  print only the names of the returned objects, one per line
  -o FILE       export to FILE (.json, .csv or .txt; CSV contains the nodes, or the values;
                TXT the object names)
  -f FILE       read the query from FILE
"""


@dataclass
class CypherArgs:
    query: str
    json: bool = False
    names_only: bool = False
    output: str | None = None


def parse_cypher_args(text: str) -> CypherArgs:
    """Parse leading options from a raw `cypher` argument string."""
    rest = text.strip()
    args = CypherArgs(query="")
    query_file: str | None = None
    while rest.startswith("-"):
        flag, _, remainder = rest.partition(" ")
        remainder = remainder.lstrip()
        if flag == "--json":
            args.json = True
        elif flag == "--names-only":
            args.names_only = True
        elif flag in ("-o", "--output", "-f", "--file"):
            value, _, remainder = remainder.partition(" ")
            if not value:
                raise BHError(f"Option {flag} requires a value")
            if flag in ("-o", "--output"):
                try:
                    args.output = output_path(value, (".json", ".csv", ".txt"))
                except argparse.ArgumentTypeError as exc:
                    raise BHError(str(exc)) from exc
            else:
                query_file = value
        else:
            break
        rest = remainder.lstrip()
    if args.json and args.names_only:
        raise BHError("--json and --names-only cannot be combined")
    if query_file:
        try:
            rest = Path(query_file).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise BHError(f"Cannot read {query_file}: {exc.strerror}") from exc
    rest = rest.strip()
    if len(rest) > 1 and rest[0] in "\"'" and rest[-1] == rest[0]:
        rest = rest[1:-1].strip()
    args.query = rest
    return args


class CypherCommands(BaseCommands):
    DEFAULT_CATEGORY = "Cypher"

    def do_cypher(self, statement: Statement) -> None:
        """Run a raw Cypher query (see 'help cypher')."""
        raw = statement.raw.strip()
        text = raw.split(None, 1)[1] if " " in raw or "\t" in raw else ""
        if text.strip() in ("-h", "--help") or not text.strip():
            self.app.poutput(CYPHER_HELP)
            return
        args = parse_cypher_args(text)
        if not args.query:
            raise BHError("No query given")
        app = self.app
        app.require_auth()
        graph = app.entities.run_cypher(args.query)
        for node in graph.nodes.values():
            app.remember(node)
        self.show_graph(graph, as_json=args.json, output=args.output, names_only=args.names_only)

    def help_cypher(self) -> None:
        self.app.poutput(CYPHER_HELP)
