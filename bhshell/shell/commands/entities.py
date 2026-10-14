"""Entity lookup commands: user, computer, group, lookup, ou, gpo, ca, template."""

from __future__ import annotations

import argparse

from cmd2 import Cmd2ArgumentParser, RawDescriptionCmd2HelpFormatter, with_argparser

from bhshell.queries.containers import CONTAINER_KINDS
from bhshell.queries.service import VIEWS
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

_NAME_HELP = "samaccountname, NAME@DOMAIN, DOMAIN\\NAME, FQDN (computers), SID or distinguished name"
_OU_NAME_HELP = "NAME, NAME@DOMAIN, distinguished name (OU=...,DC=...), object ID, or a domain (corp.local)"
_GPO_NAME_HELP = "display name, NAME@DOMAIN, distinguished name (CN={GUID},CN=POLICIES,...) or object ID"
_CA_NAME_HELP = "CA name, NAME@DOMAIN, distinguished name or object ID"
_TEMPLATE_NAME_HELP = "template name (not the display name), NAME@DOMAIN, distinguished name or object ID"


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


View = tuple[tuple[str, str], str]


def _explorer_parser(description: str, examples: str, summary: str, tip: str, name_help: str,
                     views: list[View]) -> Cmd2ArgumentParser:
    """A parser for the commands exploring one kind of object (ou, gpo, ca, template)."""
    p = Cmd2ArgumentParser(
        description=description,
        epilog=f"{examples}\n\nWithout view flags the summary is shown ({summary}).\n"
               "With view flags only those views are shown; --all shows the summary plus every view.\n"
               f"{tip}",
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("name", help=name_help, choices_provider=BaseCommands.recent_names)
    p.add_argument("-d", "--domain", help="restrict the lookup to a domain (FQDN or NetBIOS)")

    group = p.add_argument_group("views")
    for flags, help_text in views:
        group.add_argument(*flags, action="store_true", help=help_text)
    group.add_argument("-a", "--all", action="store_true", help="summary + every view")
    _add_view_output_args(p)
    return p


def _ou_parser() -> Cmd2ArgumentParser:
    return _explorer_parser(
        "Explore an OU, a container or a whole domain: where it sits, what is below it, the GPOs that apply "
        "and who controls it.",
        "ou corp.local -t              the whole OU tree of a domain\n"
        "ou SERVERS@corp.local -c      every object below an OU\n"
        "ou 'OU=WEB,OU=SERVERS,DC=corp,DC=local' -G   when several OUs share a name",
        "location, objects below, linked GPOs", "'search -t OU' lists OUs.", _OU_NAME_HELP, [
            (("-t", "--tree"), "OUs and containers below it, with object, Tier Zero and owned counts"),
            (("-c", "--contents"), "every object below it, with its location"),
            (("-G", "--gpos"), ("GPOs applied to objects in it (enforced / blocked inheritance), and who outside "
                               "Tier Zero can edit them")),
            (("-I", "--inbound"), "principals with dangerous rights over it (WriteGPLink, GenericAll, ...)"),
        ])


def _gpo_parser() -> Cmd2ArgumentParser:
    return _explorer_parser(
        "Show where a GPO is linked, which users and computers it applies to and who can edit it.",
        "gpo 'Default Domain Policy' -d corp.local\n"
        "gpo 'WEB HARDENING@corp.local' -c   the users and computers it applies to",
        "links, objects affected, editors outside Tier Zero",
        "'hunt gpo-control' lists the GPOs that principals outside Tier Zero can edit.", _GPO_NAME_HELP, [
            (("-l", "--links"), ("domains and OUs it is linked to, whether each link is enforced, what it reaches "
                                "and where blocked inheritance stops it")),
            (("-c", "--affected"), "users and computers it applies to, with their location"),
            (("-I", "--inbound"), "principals with dangerous rights over it (GenericAll, WriteDacl, ...)"),
        ])


def _ca_parser() -> Cmd2ArgumentParser:
    return _explorer_parser(
        "Show an Enterprise CA: its host, its settings (ESC6, ESC8), who can enroll or manage it (ESC7) and the "
        "templates it publishes.",
        "ca CORP-CA@corp.local\n"
        "ca CORP-CA -t                 the templates it publishes and the ESC conditions they meet",
        "host and its admins, NT authentication trust, ESC settings, enrollment and management rights",
        "'search -t EnterpriseCA' lists the CAs.", _CA_NAME_HELP, [
            (("-t", "--templates"), ("published templates, the ESC conditions each meets and who outside Tier Zero "
                                    "can enroll in it")),
            (("-I", "--inbound"), "principals with rights over it (ManageCA, Enroll, GenericAll, ...)"),
        ])


def _template_parser() -> Cmd2ArgumentParser:
    return _explorer_parser(
        "Show a certificate template: what its certificates can do, the ESC conditions it meets, the CAs that "
        "publish it and who can enroll in it or rewrite it.",
        "template USER@corp.local\n"
        "template WEBSERVER -I         everyone with rights over it",
        "settings, ESC conditions, publishing CAs, enrollment and write rights",
        "'search -t CertTemplate' lists the templates; 'hunt adcs-templates' those open to ESC2 / ESC15.",
        _TEMPLATE_NAME_HELP, [
            (("-I", "--inbound"), "principals with rights over it (Enroll, GenericAll, WriteDacl, ...)"),
        ])


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

    @with_argparser(_gpo_parser)
    def do_gpo(self, args: argparse.Namespace) -> None:
        """Explore a GPO: where it is linked, what it applies to, who can edit it."""
        self._run(args, None, ("GPO",))

    @with_argparser(_ca_parser)
    def do_ca(self, args: argparse.Namespace) -> None:
        """Explore an Enterprise CA: host, ESC settings, enrollment and management rights, templates."""
        self._run(args, None, ("EnterpriseCA",))

    @with_argparser(_template_parser)
    def do_template(self, args: argparse.Namespace) -> None:
        """Explore a certificate template: settings, ESC conditions, CAs, enrollment and write rights."""
        self._run(args, None, ("CertTemplate",))
