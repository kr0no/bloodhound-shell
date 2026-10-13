"""Connection, authentication and configuration commands."""

from __future__ import annotations

import argparse
import os
import time
from dataclasses import fields
from getpass import getpass

from cmd2 import Cmd2ArgumentParser, RawDescriptionCmd2HelpFormatter, with_argparser
from rich.text import Text

from bhshell.config import CachedSession, Config
from bhshell.errors import (
    ApiError,
    AuthError,
    BHError,
    CypherDisabledError,
    LoginFailed,
    MFARequired,
    NotFoundError,
)
from bhshell.shell.commands.base import BaseCommands


def _url_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(description="Show or set the BH backend URL (default http://127.0.0.1:8080/).")
    p.add_argument("url", nargs="?", help="new backend URL, e.g. https://BH.lab:8443")
    return p


def _tls_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(description="Show or toggle TLS certificate verification.")
    p.add_argument("state", nargs="?", choices=["on", "off"], help="'off' accepts self-signed certificates")
    return p


def _login_parser() -> Cmd2ArgumentParser:
    p = Cmd2ArgumentParser(
        description="Authenticate to BH.",
        epilog=(
            "Username/password (JWT): secrets are prompted for, or read from BH_PASSWORD.\n"
            "API token (HMAC): use --token; the ID/key are read from BH_TOKEN_ID / BH_TOKEN_KEY\n"
            "or prompted for. Secrets are never accepted as arguments so they stay out of history."
        ),
        formatter_class=RawDescriptionCmd2HelpFormatter,
    )
    p.add_argument("-u", "--username", help="BH username (defaults to the last one used)")
    p.add_argument("--otp", metavar="CODE", help="TOTP one-time password, if MFA is enabled")
    p.add_argument("--token", action="store_true", help="authenticate with an API token (ID + key)")
    p.add_argument("--token-id", metavar="ID", help="API token ID (implies --token)")
    return p


def _config_parser() -> Cmd2ArgumentParser:
    keys = [f.name for f in fields(Config)]
    p = Cmd2ArgumentParser(description="Show or change persistent settings (~/.bhshell/config.toml).")
    p.add_argument("key", nargs="?", choices=keys, help="setting name")
    p.add_argument("value", nargs="?", help="new value")
    return p


class ConnectionCommands(BaseCommands):
    DEFAULT_CATEGORY = "Connection"

    @with_argparser(_url_parser)
    def do_url(self, args: argparse.Namespace) -> None:
        """Show or set the BH backend URL."""
        app = self.app
        if not args.url:
            app.ui.info(f"Backend URL: {app.client.base_url}")
            return
        previous = app.client.base_url
        was_auth = app.client.is_authenticated
        app.client.set_url(args.url)
        app.config.url = app.client.base_url
        app.config.save()
        if app.client.base_url != previous:
            app.entities.reset()
            if was_auth:
                CachedSession.clear()
                app.ui.warn("Backend changed: local session cleared, run 'login' again.")
        app.ui.success(f"Backend URL set to {app.client.base_url}")

    @with_argparser(_tls_parser)
    def do_tls(self, args: argparse.Namespace) -> None:
        """Show or toggle TLS certificate verification."""
        app = self.app
        if args.state:
            app.config.verify_tls = args.state == "on"
            app.config.save()
            app.apply_tls_setting()
        state = "on" if app.config.verify_tls else "off (insecure)"
        app.ui.info(f"TLS certificate verification: {state}")

    @with_argparser(_login_parser)
    def do_login(self, args: argparse.Namespace) -> None:
        """Authenticate with username/password (JWT) or an API token (HMAC)."""
        if args.token or args.token_id:
            self._login_token(args.token_id)
        else:
            self._login_password(args.username, args.otp)

    def _login_token(self, token_id: str | None) -> None:
        app = self.app
        token_id = token_id or os.environ.get("BH_TOKEN_ID") or app.read_input("Token ID: ").strip()
        token_key = os.environ.get("BH_TOKEN_KEY") or getpass("Token key: ")
        if not token_id or not token_key:
            raise BHError("Token ID and key are required")
        previous = app.client.auth_state()
        app.client.set_hmac(token_id, token_key)
        try:
            me = app.client.self_info()
        except BHError as exc:
            app.client.restore_auth(previous)  # keep the session that was active before
            if isinstance(exc, AuthError):
                raise LoginFailed(f"API token rejected: {exc.message}") from exc
            raise
        CachedSession.clear()  # a token login supersedes any cached JWT
        app.entities.reset()
        app.ui.success(f"Authenticated with API token as {me.get('principal_name') or token_id}")

    def _login_password(self, username: str | None, otp: str | None) -> None:
        app = self.app
        username = username or app.read_input(f"Username [{app.config.last_username}]: ").strip()
        username = username or app.config.last_username
        if not username:
            raise BHError("A username is required")
        password = os.environ.get("BH_PASSWORD") or getpass("Password: ")
        try:
            data = app.client.login(username, password, otp)
        except MFARequired:
            code = app.read_input("One-time password: ").strip()
            data = app.client.login(username, password, code)
        app.entities.reset()
        app.config.last_username = username
        app.config.save()
        if app.config.cache_session:
            CachedSession(url=app.client.base_url, token=app.client.jwt, username=username).save()
        app.ui.success(f"Logged in as {username} on {app.client.host}")
        if data.get("auth_expired"):
            app.ui.warn("The password for this account has expired; change it in the BH UI.")

    def do_logout(self, _: object) -> None:
        """Invalidate the current session and clear cached credentials."""
        app = self.app
        if not app.client.is_authenticated:
            app.ui.info("Not logged in.")
            return
        app.client.logout()
        CachedSession.clear()
        app.entities.reset()
        app.ui.success("Logged out.")

    def do_whoami(self, _: object) -> None:
        """Show connection state, the authenticated principal and token validity."""
        app = self.app
        client = app.client
        rows: list[tuple[str, object]] = [
            ("Backend", client.base_url),
            ("TLS verification", "on" if client.verify_tls else Text("off", style="yellow")),
        ]
        if not client.is_authenticated:
            rows.append(("State", Text("disconnected", style="red")))
            app.ui.key_values("Status", rows)
            return
        me = client.self_info()
        roles = ", ".join(r.get("name", "") for r in me.get("roles") or []) or "-"
        rows += [
            ("State", Text("authenticated", style="green")),
            ("Auth mode", "JWT session" if client.auth_mode == "jwt" else f"API token ({client.token_id})"),
            ("Principal", me.get("principal_name") or client.username or "-"),
            ("Email", me.get("email_address") or "-"),
            ("Roles", roles),
        ]
        exp = client.token_expiry()
        if exp is not None:
            minutes = max(int(exp - time.time()), 0) // 60
            expires = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
            rows.append(("Token expires", f"{expires} (in {minutes} min)"))
        try:
            version = client.version()
            rows.append(("Server version", version.get("server_version") or "-"))
        except (NotFoundError, ApiError):
            rows.append(("Server version", "-"))
        rows.append(("Cypher", self._cypher_state()))
        app.ui.key_values("Status", rows)

    def _cypher_state(self) -> Text:
        entities = self.app.entities
        if entities.cypher_available is None:
            try:
                entities.run_cypher("MATCH (n:Domain) RETURN n LIMIT 1")
            except CypherDisabledError:
                pass
            except ApiError as exc:
                return Text(f"error ({exc.detail})", style="yellow")
        if entities.cypher_available:
            return Text("available", style="green")
        return Text("unavailable (using REST fallback)", style="yellow")

    def do_status(self, args: object) -> None:
        """Alias of 'whoami'."""
        self.do_whoami(args)

    @with_argparser(_config_parser)
    def do_config(self, args: argparse.Namespace) -> None:
        """Show or change persistent settings."""
        app = self.app
        cfg = app.config
        if args.key and args.value is not None:
            if args.key == "url":
                self.do_url(args.value)
                return
            try:
                value = Config.coerce(args.key, args.value)
            except (TypeError, ValueError) as exc:
                raise BHError(f"Invalid value for {args.key}: {exc}") from exc
            setattr(cfg, args.key, value)
            cfg.save()
            self._apply(cfg)
            app.ui.success(f"{args.key} = {value!r}")
            return
        keys = [args.key] if args.key else [f.name for f in fields(Config)]
        app.ui.key_values(f"Config ({Config.path()})", [(k, repr(getattr(cfg, k))) for k in keys])

    def _apply(self, cfg: Config) -> None:
        app = self.app
        app.client.timeout = (cfg.connect_timeout, cfg.read_timeout)
        app.client.page_size = cfg.page_size
        app.entities.max_results = cfg.max_results
        app.apply_tls_setting()
        if not cfg.cache_session:
            CachedSession.clear()

