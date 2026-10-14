"""Entity lookup commands: user, computer, group, lookup, ou."""

from __future__ import annotations

import argparse

from cmd2 import Cmd2ArgumentParser, RawDescriptionCmd2HelpFormatter, with_argparser

from bhshell.queries.containers import CONTAINER_KINDS
from bhshell.queries.service import VIEWS
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

_NAME_HELP = "samaccountname, NAME@DOMAIN, DOMAIN\\NAME, FQDN (computers), SID or distinguished name"
_OU_NAME_HELP = "NAME, NAME@DOMAIN, distinguished name (OU=...,DC=...), object ID, or a domain (corp.local)"


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
    if kind in (None, "User", "Computer"):
        views.add_argument("-G", "--gpos", action="store_true",
                           help="GPOs that apply to it (users and computers), and who outside Tier Zero "
                                "can edit them")
    views.add_argument("-a", "--all", action="store_true", help="summary + every applicable view")
    _add_view_output_args(p)
    return p


def _ou_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(
        description="Explore an OU, a container or a whole domain: where it sits, what is below it, "
                    "the GPOs that apply and who controls it.",
        epilog="ou corp.local -t              the whole OU tree of a domain\n"
               "ou SERVERS@corp.local -c      every object below an OU\n"
               "ou 'OU=WEB,OU=SERVERS,DC=corp,DC=local' -G   when several OUs share a name\n\n"
               "Without view flags the summary is shown (location, objects below, linked GPOs).\n"
               "With view flags only those views are shown; --all shows the summary plus every view.\n"
               "'search -t OU' lists OUs.",
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("name", help=_OU_NAME_HELP, choices_provider=BaseCommands.recent_names)
    p.add_argument("-d", "--domain", help="restrict the lookup to a domain (FQDN or NetBIOS)")

    views = p.add_argument_group("views")
    views.add_argument("-t", "--tree", action="store_true",
                       help="OUs and containers below it, with object, Tier Zero and owned counts")
    views.add_argument("-c", "--contents", action="store_true", help="every object below it, with its location")
    views.add_argument("-G", "--gpos", action="store_true",
                       help="GPOs applied to objects in it (enforced / blocked inheritance), and who outside "
                            "Tier Zero can edit them")
    views.add_argument("-I", "--inbound", action="store_true",
                       help="principals with dangerous rights over it (WriteGPLink, GenericAll, ...)")
    views.add_argument("-a", "--all", action="store_true", help="summary + every view")
    _add_view_output_args(p)
    return p


def _add_view_output_args(p: Cmd2ArgumentParser) -> None:
    out = p.add_argument_group("output")
    out.add_argument("-n", "--max-rows", type=int, metavar="N",
                     help="max table rows per view (default: config display_rows; 0 = all)")
    add_output_args(out)


class EntityCommands(BaseCommands):
    DEFAULT_CATEGORY = "Entities"

    def _run(self, args: argparse.Namespace, kind: str | None, kinds: tuple[str, ...] | None = None) -> None:
        app = self.app
        app.require_auth()
        node = app.entities.resolve(args.name, kind, args.domain, kinds=kinds)
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

    @with_argparser(_ou_parser)
    def do_ou(self, args: argparse.Namespace) -> None:
        """Explore an OU, container or domain: tree, contents, applied GPOs, inbound control."""
        self._run(args, None, CONTAINER_KINDS)
