"""Domain-wide weakness checks."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from cmd2 import (
    Choices,
    Cmd2ArgumentParser,
    RawDescriptionCmd2HelpFormatter,
    with_argparser,
)

from bhshell.errors import BHError
from bhshell.models.results import Column
from bhshell.queries.hunt import (
    CHECKS,
    CHECKS_BY_ID,
    FROM_OWNED,
    SCOPED_CHECKS,
    Check,
    Finding,
    HuntOptions,
    HuntService,
)
from bhshell.queries.service import PATH_KINDS, truncation_note
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args


def _check_id(value: str) -> str:
    # A type check rather than `choices=`: before Python 3.12, argparse validates the empty default
    # of an `nargs="*"` positional against `choices` and rejects a bare `hunt`.
    if value not in CHECKS_BY_ID:
        raise argparse.ArgumentTypeError(f"invalid choice: '{value}' (choose from {', '.join(CHECKS_BY_ID)})")
    return value


def _hunt_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(
        description="Run domain-wide weakness checks.",
        epilog="hunt               summary of every check\n"
               "hunt CHECK ...     details of the given checks\n"
               "hunt --all         details of every check\n"
               "hunt --list        describe the checks\n"
               "hunt --owned       what the owned objects (and their groups) can do\n"
               "hunt --from NAME   the same, from one object\n\n"
               "Checks: " + ", ".join(c.id for c in CHECKS),
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("checks", nargs="*", type=_check_id, metavar="CHECK", help="check id(s)",
                   choices_provider=lambda _self: Choices.from_values(CHECKS_BY_ID, is_sorted=True))
    p.add_argument("--all", action="store_true", help="show details of every check")
    p.add_argument("--list", action="store_true", help="list available checks")
    scope = p.add_mutually_exclusive_group()
    scope.add_argument("--owned", action="store_true",
                       help="only rights held by owned objects and their groups (checks marked 'scoped')")
    scope.add_argument("--from", dest="source", metavar="NAME",
                       help="only rights held by NAME and its groups (checks marked 'scoped')",
                       choices_provider=BaseCommands.recent_names)
    p.add_argument("-d", "--domain", help="restrict to a domain (FQDN or NetBIOS)")
    p.add_argument("--days", type=int, default=HuntOptions.days,
                   help="password age threshold for stale-passwords (days)")
    p.add_argument("-n", "--max-rows", type=int, metavar="N",
                   help="max table rows per check (default: config display_rows; 0 = all)")
    add_output_args(p)
    return p


def _csv_rows(findings: list[Finding]) -> tuple[list[str], list[dict]]:
    fields: list[str] = ["check", "severity"]
    rows: list[dict] = []
    for f in findings:
        for row in f.rows:
            for key in row:
                if key not in fields:
                    fields.append(key)
            rows.append({"check": f.check.id, "severity": f.check.severity, **row})
    return fields, rows


class HuntCommands(BaseCommands):
    DEFAULT_CATEGORY = "Analysis"

    @with_argparser(_hunt_parser)
    def do_hunt(self, args: argparse.Namespace) -> None:
        """Run domain-wide weakness checks (Kerberoasting, delegation, DCSync, AD CS, trusts, ...)."""
        app = self.app
        if args.list:
            rows = [{"severity": c.severity, "id": c.id, "scoped": c.scoped, "description": c.description}
                    for c in CHECKS]
            app.ui.table("Hunt checks", [Column("Severity", "severity", "severity"), Column("Check", "id"),
                                         Column("Scoped", "scoped", "bool"), Column("Description", "description")],
                         rows)
            return
        app.require_auth()
        detail = args.all or bool(args.checks)
        service = HuntService(app.entities)
        opts = HuntOptions(domain=args.domain or "", days=args.days, limit=app.config.max_results,
                           enrich=detail or args.json or bool(args.output))
        checks = [CHECKS_BY_ID[i] for i in dict.fromkeys(args.checks)] if args.checks else CHECKS
        if args.owned or args.source:
            checks = self._scoped_checks(checks, bool(args.checks))
            opts.principals = self._scope(service, args)
        findings = [service.run(check, opts) for check in checks]

        if args.json:
            app.poutput(export.to_json([f.as_dict() for f in findings]))
        elif not detail:
            app.ui.hunt_summary(findings)
            flag = " --owned" if args.owned else f" --from {args.source}" if args.source else ""
            example = next((f.check.id for f in findings if f.rows),
                           "tier-zero-control" if flag else "kerberoastable")
            app.ui.info(f"Details: 'hunt CHECK{flag}' (e.g. 'hunt {example}{flag}'), or 'hunt --all{flag}'.")
        else:
            max_rows = self.max_rows(args)
            for f in findings:
                notes = [f.check.description]
                if f.truncated:
                    notes.append(truncation_note(opts.limit, [f.total], "results"))
                if f.error:
                    notes.append(f"error: {f.error}")
                notes += f.notes
                columns = f.check.columns
                if opts.scoped:
                    columns = (*(f.check.scoped_columns or columns), FROM_OWNED)
                app.ui.table(f"[{f.check.severity}] {f.check.title}", columns, f.rows,
                             max_rows=max_rows, notes=notes)
        if args.output:
            self.export(args.output, [f.as_dict() for f in findings], _csv_rows(findings))

    @staticmethod
    def _scoped_checks(checks: Sequence[Check], explicit: bool) -> list[Check]:
        """The checks that run with --owned / --from: all of them when named explicitly, or an error."""
        if not explicit:
            return list(SCOPED_CHECKS)
        unscoped = [c.id for c in checks if not c.scoped]
        if unscoped:
            raise BHError(f"{', '.join(unscoped)}: not available with --owned / --from",
                          hint="'hunt --list' shows which checks are scoped.")
        return list(checks)

    def _scope(self, service: HuntService, args: argparse.Namespace) -> dict[str, list[str]]:
        if args.owned:
            scope = service.owned_scope()
            if not scope:
                raise BHError("Nothing is marked owned", hint="Mark objects with 'owned add NAME'.")
            return scope
        node = self.app.entities.resolve(args.source, domain=args.domain, kinds=PATH_KINDS)
        self.app.remember(node)
        return service.principal_scope(node)
