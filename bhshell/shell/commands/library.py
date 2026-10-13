"""Saved query library command."""

from __future__ import annotations

import argparse

from cmd2 import Choices, Cmd2ArgumentParser, with_argparser

from bhshell.errors import NotFoundError
from bhshell.models.results import Column
from bhshell.queries.library import QueryLibrary, query_dirs, user_dir
from bhshell.shell.commands.base import BaseCommands, add_output_args


def _query_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(description=f"Saved Cypher queries: bundled, {user_dir()}/*.cyp, the folders in "
                                       "'config query_dirs', and queries saved on the server.")
    sub = p.add_subparsers(dest="action", required=True, metavar="{list,show,run}")
    sub.add_parser("list", help="list available queries")
    show = sub.add_parser("show", help="print a query")
    show.add_argument("name", choices_provider=LibraryCommands.query_names)
    run = sub.add_parser("run", help="run a query")
    run.add_argument("name", choices_provider=LibraryCommands.query_names)
    add_output_args(run)
    return p


class LibraryCommands(BaseCommands):
    DEFAULT_CATEGORY = "Analysis"

    def _library(self) -> QueryLibrary:
        return QueryLibrary(self.app.client, extra_dirs=query_dirs(self.app.config.query_dirs))

    def query_names(self) -> Choices:
        """Tab-completion provider (local queries only, to stay fast)."""
        return Choices.from_values(self._library().load(include_server=False))

    @with_argparser(_query_parser)
    def do_query(self, args: argparse.Namespace) -> None:
        """List, show or run saved Cypher queries."""
        app = self.app
        library = self._library()
        queries = library.load()
        if args.action == "list":
            rows = [{"name": q.name, "source": q.source, "description": q.description} for q in queries.values()]
            app.ui.table("Saved queries", [Column("Name", "name"), Column("Source", "source"),
                                           Column("Description", "description")], rows, notes=library.notes)
            return
        query = queries.get(args.name)
        if query is None:
            raise NotFoundError(f"No saved query named '{args.name}'", hint="Run 'query list'.")
        if args.action == "show":
            app.poutput(query.query)
            return
        app.require_auth()
        self.show_graph(app.entities.run_cypher(query.query), as_json=args.json, output=args.output)
