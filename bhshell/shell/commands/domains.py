"""Domain overview and trust commands."""

from __future__ import annotations

import argparse

from cmd2 import Cmd2ArgumentParser, with_argparser

from bhshell.models.results import Column
from bhshell.queries.domains import DomainService
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

DOMAIN_COLS = [
    Column("Domain", "name"), Column("SID", "sid"), Column("Level", "functional_level"),
    Column("Users (enabled)", "users_fmt"), Column("Computers (enabled)", "computers_fmt"),
    Column("Groups", "groups"), Column("Tier Zero", "tier_zero"), Column("Last collected", "last_collected"),
]
TRUST_COLS = [
    Column("Trusting (source)", "trusting"), Column("Trusted (target)", "trusted"), Column("Kind", "kind"),
    Column("Type", "trust_type"), Column("Transitive", "transitive", "bool"),
    Column("SID filtering", "sid_filtering_fmt"), Column("Abuse edges", "abuse"), Column("Issues", "issues"),
]


def _output_parser(description: str) -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(description=description)
    add_output_args(p)
    return p


def _pair(total: object, enabled: object) -> str:
    if total is None:
        return "-"
    return f"{total} ({enabled if enabled is not None else '-'})"


class DomainCommands(BaseCommands):
    DEFAULT_CATEGORY = "Analysis"

    @with_argparser(lambda: _output_parser("Per-domain overview (object counts, functional level, collection)."))
    def do_domains(self, args: argparse.Namespace) -> None:
        """Per-domain overview."""
        app = self.app
        app.require_auth()
        service = DomainService(app.entities)
        infos = service.domains()
        rows = [d.as_dict() for d in infos]
        if args.json:
            app.poutput(export.to_json(rows))
        else:
            display = [{**r, "users_fmt": _pair(r["users"], r["enabled_users"]),
                        "computers_fmt": _pair(r["computers"], r["enabled_computers"])} for r in rows]
            app.ui.table("Domains", DOMAIN_COLS, display, notes=service.notes)
        if args.output:
            fields = list(rows[0]) if rows else ["name"]
            self.export(args.output, rows, (fields, rows))

    @with_argparser(lambda: _output_parser(
        "Domain trusts. 'A trusts B' means principals of B can access resources in A."))
    def do_trusts(self, args: argparse.Namespace) -> None:
        """Domain trust map with SID-filtering status."""
        app = self.app
        app.require_auth()
        trusts = DomainService(app.entities).trusts()
        rows = [t.as_dict() for t in trusts]
        if args.json:
            app.poutput(export.to_json(rows))
        else:
            display = []
            for t, r in zip(trusts, rows, strict=True):
                if t.same_forest:
                    sid = "n/a (same forest)"
                else:
                    sid = {True: "enforced", False: "DISABLED", None: "unknown (default: enforced)"}[t.sid_filtering]
                display.append({**r, "sid_filtering_fmt": sid})
            app.ui.table("Trusts", TRUST_COLS, display,
                         notes=["Access flows from the trusted (target) domain into the trusting (source) domain."])
        if args.output:
            fields = list(rows[0]) if rows else ["trusting"]
            self.export(args.output, rows, (fields, rows))
