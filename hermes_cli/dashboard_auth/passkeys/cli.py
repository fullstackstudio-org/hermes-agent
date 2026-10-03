"""``hermes dashboard passkey``: the operator's commands for the passkey store, run on the gateway host.

    status                         what is enabled, listed and stored, and why the level is unavailable
    base-url add|remove URL | base-url list
                                   the base URLs a challenge may name (confirm.passkey.base_urls)
    list [--user ID] [--all]       credentials (``--all`` includes revoked ones)
    invite [--user ID] [--ttl 15m] [--print]
                                   mint a one-time enrolment code (refused to a non-terminal without --print)
    revoke <credential id prefix> | revoke --user ID --all
    receipts [--user ID] [--since DATE] [--limit N]

This module is imported when the CLI parser is built, so it imports the store only inside the commands.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import sys
from typing import Callable, Optional, TextIO

_DURATION = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

REASONS = {
    "disabled": "confirm.passkey.enabled is false. Enable it with "
                "`hermes config set confirm.passkey.enabled true`.",
    "no_base_url": "No base URL is listed for passkeys. A confirmation binds to the address the client dialed, "
                   "and the gateway accepts only addresses listed here (not the dashboard's public URLs, which a "
                   "dashboard session can change): `hermes dashboard passkey base-url add "
                   "https://gateway.example.com`.",
    "private_origin": "Every listed base URL is private (plain http, a private or loopback address, or a local "
                      "name). Set confirm.passkey.allow_private_base_urls to true to accept them; browsers "
                      "still need https, the native app does not.",
    "no_identity": "No sign-in provider (password, OIDC or Nous) is configured, so no connection has a signed-in "
                   "user. Session-token and loopback connections never have one; passkeys belong to a user.",
}

_SIGN_IN_PROVIDERS = ("basic", "self_hosted", "nous")


def parse_duration(text: str) -> int:
    """``15m`` / ``2h`` / ``900`` / ``1d`` → seconds."""
    match = _DURATION.match(str(text))
    if not match:
        raise argparse.ArgumentTypeError(f"not a duration: {text!r} (use e.g. 15m, 2h, 900)")
    return int(match.group(1)) * _UNITS[match.group(2).lower()]


def parse_date(text: str) -> int:
    """``2026-10-01`` (UTC midnight) or an ISO date-time → Unix seconds."""
    try:
        value = _dt.datetime.fromisoformat(str(text).strip())
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a date: {text!r} (use YYYY-MM-DD)") from None
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return int(value.timestamp())


def _when(ts: Optional[int]) -> str:
    if ts is None:
        return "-"
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def add_passkey_parser(dashboard_subparsers) -> None:
    """Attach ``passkey`` under ``hermes dashboard``."""
    parser = dashboard_subparsers.add_parser(
        "passkey", help="Manage passkeys for confirmations at level passkey (operator, on the gateway host)",
        description="Manage the passkey store of this gateway: enrolment codes, credentials and receipts. "
                    "Run on the gateway host as the gateway's user.")
    sub = parser.add_subparsers(dest="passkey_command", metavar="{status,base-url,list,invite,revoke,receipts}")
    parser.set_defaults(func=cmd_dashboard_passkey, passkey_command=None)

    sub.add_parser("status", help="Show what is enabled, listed and stored")

    p_base = sub.add_parser(
        "base-url", help="List, add or remove the base URLs clients dial for this gateway",
        description="The base URLs a passkey challenge may name (confirm.passkey.base_urls), e.g. "
                    "https://gateway.example.com or https://shared.example/alice. Separate from "
                    "dashboard.public_url(s) on purpose: a dashboard session can change those.")
    p_base.add_argument("action", choices=("list", "add", "remove"))
    p_base.add_argument("url", nargs="?", default=None)

    p_list = sub.add_parser("list", help="List credentials")
    p_list.add_argument("--user", default=None, help="Only this user (<provider>:<user id>)")
    p_list.add_argument("--all", action="store_true", help="Include revoked credentials")

    p_invite = sub.add_parser("invite", help="Mint a one-time enrolment code")
    p_invite.add_argument("--user", default=None,
                          help="Bind the code to this user (<provider>:<user id>); recommended when known")
    p_invite.add_argument("--ttl", type=parse_duration, default=None,
                          help="Lifetime, e.g. 15m (default) up to 24h")
    p_invite.add_argument("--print", dest="print_code", action="store_true",
                          help="Print the code even when the output is not a terminal")

    p_revoke = sub.add_parser("revoke", help="Revoke a credential, or all of one user's")
    p_revoke.add_argument("credential", nargs="?", default=None, help="Credential id (or a unique prefix)")
    p_revoke.add_argument("--user", default=None, help="With --all: the user whose credentials to revoke")
    p_revoke.add_argument("--all", action="store_true", help="Revoke every active credential of --user")

    p_receipts = sub.add_parser("receipts", help="List receipts of verified answers")
    p_receipts.add_argument("--user", default=None, help="Only this user")
    p_receipts.add_argument("--since", type=parse_date, default=None, help="Only from this date (YYYY-MM-DD)")
    p_receipts.add_argument("--limit", type=int, default=50, help="At most this many (default 50)")


def cmd_dashboard_passkey(args) -> None:
    code = run(args)
    if code:
        sys.exit(code)


def run(args, *, out: TextIO | None = None, err: TextIO | None = None, store=None, settings=None,
        public_urls: Optional[list[str]] = None, isatty: Optional[Callable[[], bool]] = None,
        sign_in_providers: Optional[list[str]] = None) -> int:
    """The command; the keyword arguments are seams for tests. Returns the exit code."""
    out = out or sys.stdout
    err = err or sys.stderr
    if store is None:
        from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
        store = PasskeyStore.default()
    if settings is None:
        from hermes_cli.dashboard_auth.passkeys.settings import load_settings
        settings = load_settings()
    if public_urls is None:
        from hermes_cli.dashboard_auth.prefix import resolve_public_urls
        public_urls = resolve_public_urls()
    command = getattr(args, "passkey_command", None)
    if command == "base-url":
        return _base_url(args, out=out, err=err)
    handlers = {"status": _status, "list": _list, "invite": _invite, "revoke": _revoke, "receipts": _receipts}
    if command not in handlers:
        print("usage: hermes dashboard passkey {status,base-url,list,invite,revoke,receipts}", file=err)
        return 2
    if command == "status" and sign_in_providers is None:
        sign_in_providers = configured_sign_in_providers()
    from hermes_cli.dashboard_auth.passkeys.store import StoreError
    try:
        return handlers[command](args, out=out, err=err, store=store, settings=settings, public_urls=public_urls,
                                 isatty=isatty or out.isatty, sign_in_providers=sign_in_providers or [])
    except StoreError as exc:
        print(f"passkey store: {exc}", file=err)
        return 1


def configured_sign_in_providers() -> list[str]:
    """The bundled sign-in providers whose settings resolve (the ones that give a connection a user). A
    hint for ``status``: the running gateway decides, and a plugin can add others."""
    import importlib
    names = []
    for name in _SIGN_IN_PROVIDERS:
        try:
            importlib.import_module(f"plugins.dashboard_auth.{name}")._settings()
        except Exception:  # noqa: BLE001 - unconfigured raises SkipRegistration; anything else: not usable
            continue
        names.append(name)
    return names


def _status(args, *, out, err, store, settings, public_urls, isatty, sign_in_providers) -> int:
    from hermes_cli.dashboard_auth.passkeys.challenge import b64u
    from hermes_cli.dashboard_auth.passkeys.settings import gateway_context, serialise_base_urls

    exists = store.exists()
    identity = store.identity() if exists else (b"\0" * 16, b"\0" * 32)
    ctx = gateway_context(identity, settings)
    # Every reason that applies, not just the first: an operator enabling the level should learn now that
    # no base URL is listed, not after the next attempt.
    reasons = ([] if settings.enabled else ["disabled"]) + [r for r in [ctx.capability_reason()] if r]
    if not sign_in_providers:
        reasons.append("no_identity")
    print(f"Passkey confirmations: {'enabled' if settings.enabled else 'disabled'}", file=out)
    print(f"Store: {store.path}" + ("" if exists else " (not created yet; made on first use)"), file=out)
    if exists:
        print(f"Gateway id: {b64u(identity[0])}", file=out)
        counts = store.counts()
        print(f"Credentials: {counts['credentials']} active for {counts['users']} user(s), "
              f"{counts['revoked']} revoked; open codes: {counts['open_codes']}; receipts: {counts['receipts']}",
              file=out)
    print("Base URLs (confirm.passkey.base_urls): " + (", ".join(settings.base_urls) or "none"), file=out)
    print("Accepted base URLs: " + (", ".join(ctx.accepted_base_urls) or "none"), file=out)
    dashboard, _rejected = serialise_base_urls(public_urls)
    for url in dashboard:
        if url not in settings.base_urls:
            print(f"Hint: the dashboard is served on {url}, which is not a passkey base URL. If clients reach "
                  f"this gateway there: `hermes dashboard passkey base-url add {url}`.", file=out)
    for url in settings.base_urls:
        if url not in dashboard:
            print(f"Hint: {url} is a passkey base URL but not one of the dashboard's public URLs; make sure "
                  "it is the address clients dial.", file=out)
    print("Native RPs: " + (", ".join(sorted(settings.native_rps)) or "none")
          + ("" if ctx.native_rp_ids or not settings.native_rps else " (none accepted without an accepted base URL)"),
          file=out)
    print("Web RPs: " + (", ".join(sorted(ctx.web_rp_ids)) or "none (needs an https base URL without a path)"),
          file=out)
    print("Sign-in providers: " + (", ".join(sign_in_providers) or "none"), file=out)
    print(f"User invites: {'allowed' if settings.user_invites else 'off'}; "
          f"receipts kept {settings.receipts_days} days", file=out)
    print("Operator rules: " + _rules(settings.require), file=out)
    for problem in settings.problems:
        print(f"Config: {problem}", file=out)
    for reason in reasons:
        print(f"Unavailable ({reason}): {REASONS.get(reason, reason)}", file=out)
    if not reasons:
        print("Available to signed-in users with an enrolled passkey. Session-token and loopback connections "
              "have no signed-in user and never get it.", file=out)
    return 0


def _rules(require) -> str:
    """``confirm.passkey.require`` in one line: what forces a passkey confirmation (enforced whether or not
    the level is enabled; with it off, a match is blocked)."""
    parts = [f"commands {', '.join(require.commands)}" if require.commands else "",
             f"tools {', '.join(require.tools)}" if require.tools else "",
             "every dangerous-command approval" if require.approvals else "",
             "smart-approval DENY overrides" if require.smart_denied else ""]
    return "; ".join(p for p in parts if p) or "none (only the agent asks for a passkey)"


def _serialised_or_none(entry) -> Optional[str]:
    from hermes_cli.dashboard_auth.passkeys.challenge import NotABaseUrl, serialise_base_url
    try:
        return serialise_base_url(entry) if isinstance(entry, str) else None
    except NotABaseUrl:
        return None


def _base_url(args, *, out, err) -> int:
    """Read and write ``confirm.passkey.base_urls`` in this profile's config.yaml (operator only). Entries
    that are not base URLs are named and kept as written (they are not used); this command never drops
    something the operator wrote."""
    from hermes_cli.config import load_config, require_readable_config_before_write, save_config
    from hermes_cli.dashboard_auth.passkeys.settings import effective_section

    listed = effective_section(load_config()).get("base_urls")
    entries: list = list(listed) if isinstance(listed, list) else []
    unusable = [e for e in entries if _serialised_or_none(e) is None]
    usable = [u for u in (_serialised_or_none(e) for e in entries) if u is not None]
    for entry in unusable:
        print(f"Not a base URL, kept as written and not used: {entry!r}", file=err)
    if args.action == "list":
        print("\n".join(dict.fromkeys(usable)) if usable else "No base URLs listed.", file=out)
        return 0
    if not args.url:
        print(f"base-url {args.action} needs a URL", file=err)
        return 2
    url = _serialised_or_none(args.url)
    if url is None:
        print(f"Not an http(s) base URL: {args.url!r}", file=err)
        return 2
    if args.action == "add":
        if url in usable:
            print(f"Already listed: {url}", file=out)
            return 0
        updated = entries + [url]
    else:
        if url not in usable:
            print(f"Not listed: {url}", file=err)
            return 1
        updated = [e for e in entries if _serialised_or_none(e) != url]  # every spelling of it; the rest stays
    raw = require_readable_config_before_write()
    confirm: dict = raw["confirm"] if isinstance(raw.get("confirm"), dict) else {}
    passkey: dict = confirm["passkey"] if isinstance(confirm.get("passkey"), dict) else {}
    raw["confirm"] = {**confirm, "passkey": {**passkey, "base_urls": updated}}
    save_config(raw)
    from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
    audit_log(AuditEvent.PASSKEY_BASE_URLS_CHANGED, by="operator", action=args.action, base_url=url)
    print(("Added " if args.action == "add" else "Removed ") + url, file=out)
    print("Base URLs: " + (", ".join(str(e) for e in updated) or "none"), file=out)
    return 0


def _list(args, *, out, err, store, settings, public_urls, isatty, sign_in_providers) -> int:
    if not store.exists():
        print("No passkeys stored.", file=out)
        return 0
    records = store.credentials(args.user, include_revoked=args.all)
    if not records:
        print("No passkeys stored" + (f" for {args.user}." if args.user else "."), file=out)
        return 0
    for c in records:
        state = "active" if c.active else f"revoked {_when(c.revoked_at)} by {c.revoked_by}"
        print(f"{c.id_b64u[:16]}  {c.user_id!r}  rp={c.rp_id}  {c.name!r}  created {_when(c.created_at)} "
              f"via {c.created_via}  last used {_when(c.last_used_at)}  "
              f"{'synced' if c.backup_eligible else 'device-bound'}  {state}", file=out)
    return 0


def _invite(args, *, out, err, store, settings, public_urls, isatty, sign_in_providers) -> int:
    from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
    from hermes_cli.dashboard_auth.passkeys.store import OPERATOR

    if not args.print_code and not isatty():
        print("Refusing to print an enrolment code to something that is not a terminal (it would end up in a "
              "log or a pipe). Run it in a terminal, or pass --print if that is what you want.", file=err)
        return 2
    try:
        invite = store.mint_code(user_id=args.user, by=OPERATOR, ttl=args.ttl)
    except ValueError as exc:
        print(f"invite: {exc}", file=err)
        return 2
    audit_log(AuditEvent.PASSKEY_INVITE_MINTED, by=OPERATOR, user_id=invite.user_id or "",
              expires_at=invite.expires_at)
    print(f"Enrolment code: {invite.code}", file=out)
    print(f"Expires: {_when(invite.expires_at)}; single use; "
          + (f"only {invite.user_id!r} can redeem it." if invite.user_id
             else "anyone signed in can redeem it (pass --user to bind it)."), file=out)
    print("Hand it over out of band. Whoever redeems it while signed in gets a passkey for that account.",
          file=out)
    if not settings.enabled:
        print("Note: confirm.passkey.enabled is false; enrolment is refused until it is enabled.", file=out)
    return 0


def _revoke(args, *, out, err, store, settings, public_urls, isatty, sign_in_providers) -> int:
    from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
    from hermes_cli.dashboard_auth.passkeys.store import OPERATOR

    if args.all:
        if not args.user or args.credential:
            print("revoke --all needs --user and no credential id", file=err)
            return 2
        revoked = store.revoke_user(args.user, by=OPERATOR) if store.exists() else []
    else:
        if not args.credential or args.user:
            print("revoke needs a credential id (or --user ID --all)", file=err)
            return 2
        matches = store.find(args.credential) if store.exists() else []
        if not matches:
            print(f"No active credential starts with {args.credential!r}.", file=err)
            return 1
        if len(matches) > 1:
            print(f"{args.credential!r} matches {len(matches)} credentials; give more of the id:", file=err)
            for c in matches:
                print(f"  {c.id_b64u[:24]}  {c.user_id!r}  {c.name!r}", file=err)
            return 1
        one = store.revoke(matches[0].credential_id, by=OPERATOR)
        revoked = [one] if one else []
    for c in revoked:
        audit_log(AuditEvent.PASSKEY_REVOKED, by=OPERATOR, user_id=c.user_id, credential=c.id_b64u[:16],
                  rp_id=c.rp_id)
        print(f"Revoked {c.id_b64u[:16]}  {c.user_id!r}  {c.name!r}", file=out)
    if not revoked:
        print("Nothing to revoke.", file=out)
    return 0


def _receipts(args, *, out, err, store, settings, public_urls, isatty, sign_in_providers) -> int:
    from hermes_cli.dashboard_auth.passkeys.challenge import b64u

    if not store.exists():
        print("No receipts.", file=out)
        return 0
    store.prune(receipts_days=settings.receipts_days)
    rows = store.receipts(user_id=args.user, since=args.since, limit=args.limit)
    if not rows:
        print("No receipts.", file=out)
        return 0
    credentials = {c.row: c for c in store.credentials(include_revoked=True)}
    for r in rows:
        cred = credentials.get(r.credential_row)
        print(f"{_when(r.at)}  {r.purpose}  {r.user_id!r}  credential={cred.id_b64u[:16] if cred else '?'}  "
              f"rp={r.rp_id}  base_url={r.origin}  session={r.session_id!r}  request={r.request_id!r}  "
              f"text_digest={b64u(r.text_digest)}", file=out)
    return 0
