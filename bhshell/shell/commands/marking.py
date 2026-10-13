"""Owned / high-value (Tier Zero) marking commands."""

from __future__ import annotations

import argparse

from cmd2 import Cmd2ArgumentParser, with_argparser

from bhshell.queries.marking import Tag
from bhshell.render import export
from bhshell.shell.commands.base import BaseCommands, add_output_args

_LABEL = {"owned": "Owned", "tier0": "Tier Zero / High Value"}


def _marking_parser(tag: Tag) -> Cmd2ArgumentParser:
    label = _LABEL[tag]
    p = Cmd2ArgumentParser(description=f"List or change {label} objects.")
    sub = p.add_subparsers(dest="action", required=True, metavar="{list,add,remove}")
    ls = sub.add_parser("list", help=f"list {label} objects")
    add_output_args(ls)
    for action in ("add", "remove"):
        a = sub.add_parser(action, help=f"{action} an object {'to' if action == 'add' else 'from'} {label}")
        a.add_argument("name", help="samaccountname, NAME@DOMAIN, DOMAIN\\NAME or SID",
                       choices_provider=BaseCommands.recent_names)
        a.add_argument("-t", "--type", choices=["user", "computer", "group"], help="object type (default: any)")
        a.add_argument("-d", "--domain", help="restrict the lookup to a domain")
    return p


class MarkingCommands(BaseCommands):
    DEFAULT_CATEGORY = "Marking"

    def _run(self, args: argparse.Namespace, tag: Tag) -> None:
        app = self.app
        app.require_auth()
        if args.action == "list":
            nodes = app.marking.list(tag)
            if args.json:
                app.poutput(export.to_json([n.as_dict() for n in nodes]))
            else:
                app.ui.nodes(nodes, _LABEL[tag])
            if args.output:
                self.export(args.output, [n.as_dict() for n in nodes], export.node_rows(nodes))
            return
        kind = args.type.capitalize() if args.type else None
        node = app.entities.resolve(args.name, kind, args.domain)
        app.remember(node)
        app.ui.success(app.marking.mark(node, tag, add=args.action == "add"))

    @with_argparser(lambda: _marking_parser("owned"))
    def do_owned(self, args: argparse.Namespace) -> None:
        """List, add or remove owned objects."""
        self._run(args, "owned")

    @with_argparser(lambda: _marking_parser("tier0"))
    def do_hvt(self, args: argparse.Namespace) -> None:
        """List, add or remove Tier Zero / high value targets."""
        self._run(args, "tier0")
