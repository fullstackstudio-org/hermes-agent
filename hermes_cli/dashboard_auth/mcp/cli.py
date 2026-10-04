"""``hermes dashboard mcp``: the operator's commands for the MCP grant registry, run on the gateway host.

    status                       whether the endpoint is configured on, and what the registry holds
    list [--user ID] [--all]     grants (live ones; ``--all`` includes revoked and ended ones)
    revoke <grant id | prefix>   revoke one grant and every token of it (``--id ID`` for an id starting with -)
    revoke --user ID             revoke every grant of one person (the recovery when a device is lost)
    prune                        drop what has expired (the gateway also does this on its own)

The commands work on ``$HERMES_HOME/dashboard_auth/mcp.db`` directly, so they work whether or not the
dashboard runs and whether or not the feature is on. Revocations are audited (``mcp_grant_revoked``,
``by: operator``). A revoked token stops working at the gateway's next check; no restart is needed.

This module is imported when the CLI parser is built, so it imports the store only inside the commands.
"""

from __future__ import annotations

import datetime as _dt
import sys
from typing import Optional, TextIO

PREFIX_MIN = 6


def add_mcp_parser(dashboard_subparsers) -> None:
    """Attach ``mcp`` under ``hermes dashboard``."""
    parser = dashboard_subparsers.add_parser(
        "mcp", help="Manage the remote MCP endpoint's grants (operator, on the gateway host)",
        description="List and revoke the MCP clients people connected to this gateway (dashboard.mcp). Run on "
                    "the gateway host as the gateway's user.")
    sub = parser.add_subparsers(dest="mcp_command", metavar="{status,list,revoke,prune}")
    parser.set_defaults(func=cmd_dashboard_mcp, mcp_command=None)
    sub.add_parser("status", help="Show whether the endpoint is on and what the registry holds")
    p_list = sub.add_parser("list", help="List grants")
    p_list.add_argument("--user", default=None, help="Only this person (<provider>:<user id>)")
    p_list.add_argument("--all", action="store_true", help="Include revoked and ended grants")
    p_revoke = sub.add_parser("revoke", help="Revoke a grant, or every grant of one person")
    p_revoke.add_argument("grant", nargs="?", default=None, help=f"Grant id (or a unique prefix of {PREFIX_MIN}+)")
    p_revoke.add_argument("--id", dest="grant_id", default=None,
                          help="The same, for an id that starts with '-' (made by an older build; ids are URL-safe "
                               "base64): write it as --id=<id>")
    p_revoke.add_argument("--user", default=None, help="Revoke every grant of this person (<provider>:<user id>)")
    sub.add_parser("prune", help="Drop expired consents, codes, tokens, old grants and unused registrations")


def cmd_dashboard_mcp(args) -> None:
    code = run(args)
    if code:
        sys.exit(code)


def _when(ts: Optional[int]) -> str:
    if ts is None:
        return "-"
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def run(args, *, out: TextIO | None = None, err: TextIO | None = None, store=None, settings=None) -> int:
    """The command; the keyword arguments are seams for tests. Returns the exit code."""
    out = out or sys.stdout
    err = err or sys.stderr
    command = getattr(args, "mcp_command", None)
    handlers = {"status": _status, "list": _list, "revoke": _revoke, "prune": _prune}
    if command not in handlers:
        print("usage: hermes dashboard mcp {status,list,revoke,prune}", file=err)
        return 2
    from hermes_cli.dashboard_auth.mcp.store import MCPStore, StoreError
    if store is None:
        store = MCPStore.default()
    if settings is None and command == "status":
        from hermes_cli.config import load_config
        from hermes_cli.dashboard_auth.mcp.settings import parse
        settings = parse(load_config())
    try:
        return handlers[command](args, out=out, err=err, store=store, settings=settings)
    except StoreError as exc:
        print(f"mcp store: {exc}", file=err)
        return 1


def _status(args, *, out, err, store, settings) -> int:
    values, problems = settings
    print(f"MCP endpoint: {'enabled' if values.enabled else 'disabled'} in config (dashboard.mcp.enabled)", file=out)
    if values.enabled:
        print("It runs only behind the sign-in gate, with an https dashboard.public_url without a path prefix and "
              "the mcp package installed; the dashboard log says why when it stays off.", file=out)
    exists = store.exists()
    print(f"Store: {store.path}" + ("" if exists else " (not created yet; made on first use)"), file=out)
    if exists:
        c = store.counts()
        print(f"Grants: {c['grants']} live for {c['users']} person(s); registered clients: {c['clients']}; "
              f"open consents: {c['consents']}; chats opened through MCP: {c['chats']}", file=out)
    print(f"Tokens: access {values.access_token_ttl}s, refresh {values.refresh_token_ttl}s (sliding), grant "
          f"{values.grant_max_age}s (absolute); at most {values.max_grants_per_user} live grants per person", file=out)
    for problem in problems:
        print(f"Config: {problem}", file=out)
    return 0


def _list(args, *, out, err, store, settings) -> int:
    grants = store.grants(args.user, include_inactive=bool(args.all)) if store.exists() else []
    if not grants:
        print("No grants.", file=out)
        return 0
    for g in grants:
        state = "live" if g.live else (f"revoked by {g.revoked_by} {_when(g.revoked_at)}" if g.revoked_at else "ended")
        print(f"{g.id}  {g.user_id} ({g.user_name or '-'})  client «{g.client_name}» {g.client_id}  {state}", file=out)
        print(f"    created {_when(g.created_at)} from {g.created_ip or '-'}; last used {_when(g.last_used_at)} from "
              f"{g.last_used_ip or '-'}; expires {_when(g.expires_at)}; scopes {' '.join(g.scopes)}", file=out)
    return 0


def _audit(grant) -> None:
    from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
    from hermes_cli.dashboard_auth.mcp.store import OPERATOR
    audit_log(AuditEvent.MCP_GRANT_REVOKED, by=OPERATOR, grant_id=grant.id, user_id=grant.user_id,
              client_id=grant.client_id, client_name=grant.client_name)


def _revoke(args, *, out, err, store, settings) -> int:
    from hermes_cli.dashboard_auth.mcp.store import OPERATOR
    if getattr(args, "grant_id", None):
        if args.grant:
            print("Name the grant once: as an argument or with --id.", file=err)
            return 2
        args.grant = args.grant_id
    if bool(args.grant) == bool(args.user):
        print("Name one grant id, or --user ID for every grant of one person.", file=err)
        return 2
    if args.user:
        revoked = store.revoke_grants_of(args.user, by=OPERATOR)
        for grant in revoked:
            _audit(grant)
        print(f"Revoked {len(revoked)} grant(s) of {args.user}.", file=out)
        return 0
    wanted = args.grant.strip()
    if len(wanted) < PREFIX_MIN:
        print(f"A grant id prefix needs at least {PREFIX_MIN} characters.", file=err)
        return 2
    matches = [g for g in store.grants(include_inactive=True) if g.id == wanted or g.id.startswith(wanted)]
    exact = [g for g in matches if g.id == wanted]
    matches = exact or matches
    if not matches:
        print(f"No grant {wanted}.", file=err)
        return 1
    if len(matches) > 1:
        print(f"{wanted} matches {len(matches)} grants; give more of the id.", file=err)
        return 1
    target = matches[0]
    if target.revoked_at is not None:
        print(f"Grant {target.id} was already revoked by {target.revoked_by} at {_when(target.revoked_at)}.", file=out)
        return 0
    grant = store.revoke_grant(target.id, by=OPERATOR)
    if grant is None:
        print(f"No grant {wanted}.", file=err)
        return 1
    _audit(grant)
    print(f"Revoked grant {grant.id} ({grant.user_id}, client «{grant.client_name}»).", file=out)
    return 0


def _prune(args, *, out, err, store, settings) -> int:
    if not store.exists():
        print("Nothing to prune: the store does not exist yet.", file=out)
        return 0
    counts = store.prune()
    print("Pruned: " + ", ".join(f"{name} {count}" for name, count in counts.items()), file=out)
    return 0
