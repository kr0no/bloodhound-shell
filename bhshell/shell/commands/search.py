"""Attribute search command."""

from __future__ import annotations

import argparse
import shlex

from cmd2 import (
    Choices,
    Cmd2ArgparseError,
    Cmd2ArgumentParser,
    RawDescriptionCmd2HelpFormatter,
    with_argparser,
)

from bhshell.errors import BHError
from bhshell.models.entities import PRIMARY_KINDS
from bhshell.queries.search import (
    COMMON_PROPS,
    SearchOptions,
    SearchService,
    parse_filter,
)
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

_KINDS = {k.lower(): k for k in PRIMARY_KINDS}


def _kind(value: str) -> str:
    try:
        return _KINDS[value.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(f"unknown type '{value}' (one of: {', '.join(PRIMARY_KINDS)})") from None


def _filter_names() -> list[str]:
    return [*COMMON_PROPS, *(f"!{p}" for p in COMMON_PROPS)]


def _search_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(
        description="List objects whose properties match every FILTER.",
        epilog="Filters (ANDed):\n"
               "  ATTR                 true            hasspn\n"
               "  !ATTR                false or unset  !enabled\n"
               "  ATTR=VALUE           equals          samaccountname=svc_sql\n"
               "  ATTR!=VALUE          differs\n"
               "  ATTR~TEXT            contains        description~pass\n"
               "  ATTR!~TEXT           doesn't contain\n"
               "  ATTR<VALUE  > <= >=  compare         pwdlastset<2020-01-01  lastlogontimestamp<90d\n\n"
               "Text matching ignores case; '*' at either end of a value is a wildcard (name=svc_*).\n"
               "VALUE can be true/false, null (unset), a number, a date (YYYY-MM-DD) or an age (90d =\n"
               "90 days ago). Quote filters containing spaces: 'description~service account'.\n\n"
               "Examples:\n"
               "  search -t user hasspn enabled\n"
               "  search -t computer operatingsystem~2012 -d CORP\n"
               "  search -t user pwdneverexpires 'pwdlastset<5000d' -c lastlogon -o old.csv",
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("filters", nargs="*", metavar="FILTER", help="property filter (see below)",
                   choices_provider=lambda _self: Choices.from_values(_filter_names()))
    p.add_argument("-t", "--type", type=_kind, metavar="TYPE",
                   choices_provider=lambda _self: Choices.from_values(PRIMARY_KINDS),
                   help="object type (User, Computer, Group, OU, GPO, ...; default: any)")
    p.add_argument("-d", "--domain", help="restrict to a domain (FQDN or NetBIOS)")
    p.add_argument("-c", "--columns", action="append", default=[], metavar="ATTR[,ATTR...]",
                   help="extra properties to show (filtered properties are always shown)")
    p.add_argument("-l", "--limit", type=int, metavar="N", help="max results fetched (default: config max_results)")
    p.add_argument("-n", "--max-rows", type=int, metavar="N",
                   help="max table rows shown (default: config display_rows; 0 = all)")
    add_output_args(p)
    return p


def _uncut(args: argparse.Namespace) -> argparse.Namespace:
    """Re-read the arguments when cmd2 cut them at '>', '|' or ';'.

    Redirection is disabled, but cmd2 still ends the argument list at those characters, which would
    silently drop the rest of `lastlogon>=90d enabled`.
    """
    stmt = args.cmd2_statement
    if not (stmt.redirector or stmt.terminator):
        return args
    try:
        return _search_parser().parse_args(shlex.split(stmt.raw.split(None, 1)[1]))
    except ValueError as exc:
        raise BHError(f"Cannot parse arguments: {exc}") from exc
    except SystemExit as exc:  # usage error: argparse already printed it
        raise Cmd2ArgparseError from exc


class SearchCommands(BaseCommands):
    DEFAULT_CATEGORY = "Entities"

    @with_argparser(_search_parser)
    def do_search(self, args: argparse.Namespace) -> None:
        """List objects matching property filters (e.g. 'search -t user hasspn enabled')."""
        app = self.app
        args = _uncut(args)
        if not (args.filters or args.type or args.domain):
            raise BHError("Give at least one FILTER, -t TYPE or -d DOMAIN (see 'help search')")
        if args.limit is not None and args.limit < 1:
            raise BHError("--limit must be at least 1")
        self.check_domain(args.domain)
        opts = SearchOptions(filters=[parse_filter(f) for f in args.filters], kind=args.type,
                             domain=args.domain or "", limit=args.limit or app.config.max_results)
        columns = [c.strip() for spec in args.columns for c in spec.split(",") if c.strip()]
        app.require_auth()
        result = SearchService(app.entities).search(opts, columns)
        for node in result.nodes:
            app.remember(node)

        names = export.node_names(result.nodes)
        truncated = ""
        if result.truncated:
            total = f" of {result.total:,}" if result.total is not None else ""
            truncated = f"Only the first {opts.limit:,}{total} results were fetched (raise --limit)."
        if args.json:
            app.poutput(export.to_json(result.as_dict()))
        elif args.names_only:
            if truncated:
                app.ui.warn(truncated)
            self.print_names(names)
        else:
            notes = [f"Filters: {' AND '.join(args.filters)}"] if args.filters else []
            if truncated:
                notes.append(truncated)
            app.ui.table(f"Search: {opts.kind or 'any type'}", result.columns, result.rows(),
                         max_rows=self.max_rows(args), notes=notes)
        if args.output:
            fields = [c.attr for c in result.columns]
            fields.insert(3, "objectid")
            self.export(args.output, result.as_dict(), (fields, result.rows()), names)
