"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from cmd2.string_utils import quote_if_needed

from bhshell import __version__
from bhshell.client.client import normalize_url
from bhshell.config import Config


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bhshell", description="Interactive shell for BloodHound.")
    p.add_argument("--url", help="BH backend URL (persisted; default http://127.0.0.1:8080/)")
    p.add_argument("-k", "--insecure", action="store_true", help="disable TLS certificate verification (persisted; 'tls on' re-enables it)")
    p.add_argument("--no-resume", action="store_true", help="do not resume the cached session")
    p.add_argument("-c", "--command", action="append", default=[], metavar="CMD",
                   help="run CMD and exit (repeatable)")
    p.add_argument("-s", "--script", metavar="FILE", help="run commands from FILE and exit")
    p.add_argument("--debug", action="store_true", help="show tracebacks for errors")
    p.add_argument("--version", action="version", version=f"bhshell {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config.load()
    changed = False
    if args.url:
        try:
            config.url = normalize_url(args.url)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        changed = True
    if args.insecure:
        config.verify_tls = False
        changed = True
    if changed:
        config.save()

    from bhshell.shell.app import BHShell  # imported late so '--help' stays fast

    app = BHShell(config, debug=args.debug, resume=not args.no_resume)
    if args.command or args.script:
        commands = list(args.command)
        if args.script:
            commands.append(f"run_script {quote_if_needed(args.script)}")
        app.runcmds_plus_hooks(commands)
        return app.exit_code or (1 if app.command_failures else 0)
    return app.cmdloop() or 0
