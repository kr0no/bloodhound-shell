"""The interactive bhshell REPL (cmd2 application)."""

from __future__ import annotations

import sys
import traceback
from collections import deque
from typing import Any

import cmd2
import urllib3
from cmd2 import Cmd2ArgparseError, Statement
from cmd2.string_utils import stylize
from urllib3.exceptions import InsecureRequestWarning

from bhshell import __version__
from bhshell.client.client import BHClient
from bhshell.config import CachedSession, Config, history_file
from bhshell.errors import (
    AuthError,
    BHError,
    ConnectionFailed,
    LoginFailed,
    MFARequired,
    NotAuthenticated,
)
from bhshell.models.entities import Node
from bhshell.queries.marking import MarkingService
from bhshell.queries.service import EntityService
from bhshell.render.views import Renderer
from bhshell.shell.commands.connection import ConnectionCommands
from bhshell.shell.commands.cypher import CypherCommands
from bhshell.shell.commands.domains import DomainCommands
from bhshell.shell.commands.entities import EntityCommands
from bhshell.shell.commands.hunt import HuntCommands
from bhshell.shell.commands.library import LibraryCommands
from bhshell.shell.commands.marking import MarkingCommands
from bhshell.shell.commands.paths import PathCommands
from bhshell.shell.commands.search import SearchCommands

BANNER = rf"""
  _     _         _          _ _
 | |__ | |__  ___| |__   ___| | |
 | '_ \| '_ \/ __| '_ \ / _ \ | |   BloodHound interactive shell v{__version__}
 | |_) | | | \__ \ | | |  __/ | |   Type 'help' for commands, 'help <command>' for details.
 |_.__/|_| |_|___/_| |_|\___|_|_|
"""

# Built-in cmd2 commands that are not useful here.
_HIDDEN_BUILTINS = ("edit", "run_pyscript", "shortcuts", "macro", "_relative_run_script")

# Help category of cmd2's built-in commands (help, history, quit, ...).
cmd2.Cmd.DEFAULT_CATEGORY = "Shell"


class BHShell(cmd2.Cmd):
    def __init__(self, config: Config, *, debug: bool = False, resume: bool = True) -> None:
        self.config = config
        self.client = BHClient(
            config.url,
            verify_tls=config.verify_tls,
            timeout=(config.connect_timeout, config.read_timeout),
            page_size=config.page_size,
        )
        self.entities = EntityService(self.client, max_results=config.max_results)
        self.marking = MarkingService(self.client, self.entities)
        self.ui = Renderer()
        self.recent_names: deque[str] = deque(maxlen=200)
        # Commands that failed (errors, usage errors, unknown commands); drives the exit code of -c/-s runs.
        self.command_failures = 0
        # True while the REPL itself is reading commands (never for -c / -s runs).
        self.interactive = False

        super().__init__(
            persistent_history_file=str(history_file()),
            allow_cli_args=False,
            # Disabled on purpose: Cypher uses '|' and '>' which cmd2 would
            # otherwise interpret as shell pipes/redirection. Use '-o FILE'.
            allow_redirection=False,
            auto_load_commands=False,
            command_sets=[ConnectionCommands(), EntityCommands(), SearchCommands(), CypherCommands(), MarkingCommands(),
                          PathCommands(), HuntCommands(), DomainCommands(), LibraryCommands()],
        )
        self.debug = debug
        self.intro = BANNER
        for name in _HIDDEN_BUILTINS:
            if name not in self.hidden_commands:
                self.hidden_commands.append(name)
        self.register_precmd_hook(self._before_command)
        self.register_postcmd_hook(self._after_command)
        self.apply_tls_setting()
        if resume:
            self._resume_session()
        self.update_prompt()

    def preloop(self) -> None:
        self.interactive = True

    def can_ask(self) -> bool:
        """Whether a command may stop and prompt the user for a choice."""
        return self.interactive and not self.in_script() and sys.stdin.isatty()

    def apply_tls_setting(self) -> None:
        self.client.verify_tls = self.config.verify_tls
        if not self.config.verify_tls:
            urllib3.disable_warnings(InsecureRequestWarning)

    def require_auth(self) -> None:
        if not self.client.is_authenticated:
            raise NotAuthenticated("Not authenticated")

    def remember(self, node: Node) -> None:
        """Record a resolved name for tab completion."""
        name = node.samaccountname or node.name
        if name and name not in self.recent_names:
            self.recent_names.appendleft(name)

    def on_auth_lost(self) -> None:
        self.client.clear_auth()
        CachedSession.clear()
        self.entities.reset()
        self.update_prompt()

    def update_prompt(self) -> None:
        """`[bh: shell] >`; "shell" is green when authenticated, red when not ('whoami' has details)."""
        colour = "green" if self.client.is_authenticated else "red"
        self.prompt = f"[{stylize('bh', 'bold')}: {stylize('shell', colour)}] > "

    def _resume_session(self) -> None:
        if not self.config.cache_session:
            return
        cached = CachedSession.load()
        if cached is None or cached.url != self.client.base_url:
            return
        self.client.set_jwt(cached.token, cached.username)
        if self.client.token_expired():
            self.on_auth_lost()
            self.ui.info("Cached session has expired; run 'login'.")
            return
        try:
            self.client.self_info()
        except AuthError:
            self.on_auth_lost()
            self.ui.info("Cached session is no longer valid; run 'login'.")
        except ConnectionFailed:
            self.ui.warn(f"Backend {self.client.base_url} unreachable; keeping cached session for {cached.username}.")
        else:
            self.ui.success(f"Resumed session for {cached.username or 'user'} on {self.client.host}")

    def _before_command(self, data: cmd2.plugin.PrecommandData) -> cmd2.plugin.PrecommandData:
        self.entities.reset_cache()
        if self.client.is_authenticated and self.client.token_expired():
            self.ui.warn("Session token has expired.")
            self.on_auth_lost()
        return data

    def _after_command(self, data: cmd2.plugin.PostcommandData) -> cmd2.plugin.PostcommandData:
        self.update_prompt()
        return data

    def onecmd(self, statement: Statement | str, *, add_to_history: bool = True) -> bool:
        try:
            return super().onecmd(statement, add_to_history=add_to_history)
        except Cmd2ArgparseError:  # usage error: argparse already printed it
            self.command_failures += 1
            raise

    def perror(self, *objects: Any, **kwargs: Any) -> None:
        self.command_failures += 1
        super().perror(*objects, **kwargs)

    def pexcept(self, msg: BaseException, **kwargs: Any) -> None:
        """Render bhshell errors concisely; full tracebacks only in debug mode."""
        if isinstance(msg, BHError):
            self.command_failures += 1
            # A rejected login leaves the active session alone; other 401s mean it is gone.
            session_lost = isinstance(msg, AuthError) and not isinstance(
                msg, (NotAuthenticated, MFARequired, LoginFailed))
            if session_lost and self.client.is_authenticated:
                self.on_auth_lost()
            self.ui.error(msg)
        elif isinstance(msg, (ValueError, OSError)):
            self.command_failures += 1
            self.ui.error(BHError(str(msg)))
        else:
            super().pexcept(msg, **kwargs)
            return
        if self.debug:
            self.ui.status.print("".join(traceback.format_exception(msg)), style="dim", markup=False)
