"""Entity lookup commands: user, computer, group, lookup."""

from __future__ import annotations

import argparse

from cmd2 import Cmd2ArgumentParser, RawDescriptionCmd2HelpFormatter, with_argparser

from bhshell.queries.service import VIEWS
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

_NAME_HELP = "samaccountname, NAME@DOMAIN, DOMAIN\\NAME, FQDN (computers) or SID"


def _entity_parser(kind: str | None) -> Cmd2ArgumentParser:
    what = kind.lower() if kind else "object (user, computer or group; type auto-detected)"
    p = Cmd2ArgumentParser(
        description=f"Show a triage summary for a {what}, and optional relationship views.",
        epilog="Without view flags the summary is shown. With view flags only those views are shown;\n"
               "--all shows the summary plus every applicable view.",
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("name", help=_NAME_HELP, choices_provider=BaseCommands.recent_names)
    p.add_argument("-d", "--domain", help="restrict the lookup to a domain (FQDN or NetBIOS)")

    views = p.add_argument_group("relationship views")
    views.add_argument("-g", "--groups", action="store_true", help="group memberships (direct + nested)")
    if kind in (None, "Group"):
        views.add_argument("-m", "--members", action="store_true", help="group members (direct + nested)")
    views.add_argument("-O", "--outbound", action="store_true", help="dangerous rights held over other objects")
    views.add_argument("-I", "--inbound", action="store_true", help="principals with dangerous rights over it")
    views.add_argument("-s", "--sessions", action="store_true", help="HasSession relationships")
    views.add_argument("-p", "--local-admin", "--privs", dest="privs", action="store_true",
                       help="AdminTo / CanRDP / ExecuteDCOM / CanPSRemote / SQLAdmin")
    views.add_argument("-a", "--all", action="store_true", help="summary + every applicable view")

    out = p.add_argument_group("output")
    out.add_argument("-n", "--max-rows", type=int, metavar="N",
                     help="max table rows per view (default: config display_rows; 0 = all)")
    add_output_args(out)
    return p


class EntityCommands(BaseCommands):
    DEFAULT_CATEGORY = "Entities"

    def _run(self, args: argparse.Namespace, kind: str | None) -> None:
        app = self.app
        app.require_auth()
        node = app.entities.resolve(args.name, kind, args.domain)
        app.remember(node)

        if args.all:
            selected = app.entities.applicable_views(node)
        else:
            requested = [key for key in VIEWS if getattr(args, key, False)]
            selected = [key for key in requested if node.kind in VIEWS[key]]
            for key in set(requested) - set(selected):
                app.ui.warn(f"View '{key}' does not apply to a {node.kind}; skipped.")
        report = app.entities.report(node, selected, show_summary=args.all or not selected)

        if args.json:
            app.poutput(export.to_json(report.as_dict()))
        else:
            app.ui.report(report, self.max_rows(args))
        if args.output:
            self.export(args.output, report.as_dict(), export.report_rows(report))

    @with_argparser(lambda: _entity_parser("User"))
    def do_user(self, args: argparse.Namespace) -> None:
        """Query a user by samaccountname."""
        self._run(args, "User")

    @with_argparser(lambda: _entity_parser("Computer"))
    def do_computer(self, args: argparse.Namespace) -> None:
        """Query a computer by name / samaccountname / FQDN."""
        self._run(args, "Computer")

    @with_argparser(lambda: _entity_parser("Group"))
    def do_group(self, args: argparse.Namespace) -> None:
        """Query a group by name."""
        self._run(args, "Group")

    @with_argparser(lambda: _entity_parser(None))
    def do_lookup(self, args: argparse.Namespace) -> None:
        """Query any user, computer or group (type auto-detected)."""
        self._run(args, None)
