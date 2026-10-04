"""The app's MCP routes: what Settings › MCP shows and the one thing it can do.

    GET  /api/auth/mcp                       the caller's page: endpoint, command, config, connected clients
    POST /api/auth/mcp/grants/{id}/revoke    end one of the caller's own grants (every token of it, at once)

Written against ``contract/gateway/mcp.md`` §2-§4. Rules both routes keep, modelled on the passkey routes:

- While the MCP endpoint is off (:func:`.mount.current` is None: ``dashboard.mcp.enabled`` false, no sign-in
  gate, no usable public URL, or the ``mcp`` extra missing) both answer what an unknown ``/api`` path gets on
  a gateway without them: 404 ``No such API endpoint`` for GET, 405 for any other method.
- Neither is public: the dashboard's auth gate runs first. The identity is the gate's verified session
  (``request.state.session``) and nothing in a body; without one (session-token or loopback mode) the answer
  is 403 ``no_identity``. A caller only ever sees or revokes their own grants.
- A cookie-authenticated write must carry an ``Origin`` that is one of the gateway's listed public origins
  (403 ``origin_not_listed``). A bearer caller (the native app) is exempt: a browser never attaches a bearer
  on its own.
- A body is a JSON object of at most 16 KiB; it never names a user.
- Revoking is one answer for every grant that is not the caller's live one (unknown, somebody else's, already
  revoked, ended, or not shaped like an id): 404 ``not_found``. There is no way to ask whether somebody
  else's grant exists.

This module imports nothing from the ``mcp`` package, so the router is always mounted; whether it answers is
the mount's decision.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import Session
from hermes_cli.dashboard_auth.mcp import mount
from hermes_cli.dashboard_auth.mcp.settings import server_label
from hermes_cli.dashboard_auth.mcp.store import Grant, StoreError
from hermes_cli.dashboard_auth.origins import classify_origin_header, configured_origins
from hermes_cli.dashboard_auth.request_utils import client_ip, extract_bearer

_log = logging.getLogger(__name__)

PREFIX = "/api/auth/mcp"
REVOKE_PATH = PREFIX + "/grants/{grant_id:path}/revoke"  # ``path``: an id with a slash is a 404 ``not_found``
BODY_CAP = 16 * 1024
VERSION = 1
USER_AGENT_LIMIT = 512  # a user agent is attacker-chosen text; the page never needs more than a screenful
GRANT_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store"}
#: Every method an unknown route could be asked with; the revoke route accepts all of them so that a
#: gateway with the endpoint off answers each exactly as one without the route (see :func:`_not_found`).
_ANY_METHOD = ["GET", "POST", "PUT", "PATCH", "DELETE"]


class _Fail(Exception):
    """An answer other than 200: status, ``error`` code and a human ``detail``."""

    def __init__(self, status: int, error: str, detail: str):
        super().__init__(error)
        self.status, self.error, self.detail = status, error, detail

    def response(self) -> JSONResponse:
        return JSONResponse({"error": self.error, "detail": self.detail}, status_code=self.status,
                            headers=dict(_NO_STORE))


def _not_found(request: Request) -> JSONResponse:
    """What a gateway without these routes answers for the same request: the SPA catch-all
    (``web_server_dashboard.serve_spa``, GET only) gives an unknown ``/api`` path a 404 with this body, and
    any other method on such a path is Starlette's 405."""
    if request.method == "GET":
        return JSONResponse({"detail": f"No such API endpoint: {request.url.path}"}, status_code=404)
    return JSONResponse({"detail": "Method Not Allowed"}, status_code=405, headers={"Allow": "GET"})


def _wrong_method(allowed: str) -> JSONResponse:
    return JSONResponse({"detail": "Method Not Allowed"}, status_code=405, headers={"Allow": allowed})


@dataclass(frozen=True)
class _Call:
    request: Request
    runtime: Any  # mount.MCPRuntime (routes.Runtime)
    user_id: str  # "<provider>:<user id>", the grants' owner key
    ip: str
    auth: str  # "bearer" | "cookie"


def _identity(request: Request) -> str:
    """``<provider>:<user id>`` of the gate's verified session, or ``""`` (session-token, loopback and the
    internal login have none)."""
    from hermes_cli.dashboard_auth.ws_tickets import INTERNAL_PROVIDER, INTERNAL_USER_ID

    session = getattr(request.state, "session", None)
    if not isinstance(session, Session):
        return ""
    provider, user = str(session.provider or "").strip(), str(session.user_id or "").strip()
    if not provider or not user or (provider, user) == (INTERNAL_PROVIDER, INTERNAL_USER_ID):
        return ""
    return f"{provider}:{user}"


async def _read_body(request: Request) -> dict:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > BODY_CAP:
                raise _Fail(413, "body_too_large", f"The body is larger than {BODY_CAP} bytes.")
        except ValueError:
            raise _Fail(400, "bad_request", "Malformed Content-Length.") from None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > BODY_CAP:
            raise _Fail(413, "body_too_large", f"The body is larger than {BODY_CAP} bytes.")
        chunks.append(chunk)
    try:
        data = json.loads(b"".join(chunks) or b"null")
    except (ValueError, RecursionError):
        raise _Fail(400, "bad_request", "The body is not JSON.") from None
    if not isinstance(data, dict):
        raise _Fail(400, "bad_request", "The body must be a JSON object.")
    return data


async def _run(request: Request, handler: Callable[[_Call], Any], *, write: bool) -> JSONResponse:
    """The shared front of both routes: 404 while off, identity, the Origin rule for a cookie write, the
    body; then *handler* in a worker thread (the store is SQLite, the announcement is synchronous)."""
    runtime = mount.current()
    if runtime is None:
        return _not_found(request)
    try:
        user_id = _identity(request)
        if not user_id:
            raise _Fail(403, "no_identity",
                        "MCP clients belong to a signed-in user; this connection has none.")
        auth = "bearer" if extract_bearer(request) else "cookie"
        if write and auth == "cookie" and \
                classify_origin_header(request.headers.get("origin", ""), configured_origins(request)) != "listed":
            audit_log(AuditEvent.MCP_WRITE_REFUSED, user_id=user_id, ip=client_ip(request), auth=auth,
                      path=request.url.path, reason="origin_not_listed")
            raise _Fail(403, "origin_not_listed",
                        "A browser write needs an Origin that is one of this gateway's own.")
        if write:
            await _read_body(request)
        call = _Call(request=request, runtime=runtime, user_id=user_id, ip=client_ip(request), auth=auth)
        result = await run_in_threadpool(handler, call)
    except _Fail as fail:
        return fail.response()
    except StoreError:
        _log.warning("MCP routes: the MCP store is unavailable", exc_info=False)
        return _Fail(503, "unavailable", "The MCP store is unavailable.").response()
    return JSONResponse(result, headers=_NO_STORE)


# ── GET /api/auth/mcp ────────────────────────────────────────────────────────────────────────────


def instructions(grant_max_age: int, max_grants: int) -> str:
    """The prose the page shows. English: a client localises its own chrome, never this text. Names no host."""
    days = max(1, grant_max_age // 86400)
    return (
        "Connect a coding agent such as Claude Code to the bots on this gateway. Run the command in a terminal, "
        "or add the JSON to your MCP client's configuration, then sign in when your browser opens and allow the "
        "connection. The agent works as you, marked as an agent: what it sends shows as your name followed by "
        "\"via\" and the agent's name. It cannot approve commands, confirm with a passkey or hand over secrets; "
        "those stay in your own app. A connection lasts "
        f"{days} day{'s' if days != 1 else ''}, then you allow it again, and you can have up to {max_grants} "
        "clients connected at once. Revoke a client here at any time.")


def grant_view(grant: Grant) -> dict:
    """One grant as the app sees it: nothing about the person, the tokens or the client's secret. Fields the
    gateway did not record are ``null``, never an empty string."""
    return {"id": grant.id, "client_name": grant.client_name, "client_id": grant.client_id,
            "scopes": list(grant.scopes), "created_at": grant.created_at,
            "created_ip": grant.created_ip or None,
            "created_user_agent": (grant.created_user_agent or "")[:USER_AGENT_LIMIT] or None,
            "last_used_at": grant.last_used_at, "last_used_ip": grant.last_used_ip or None,
            "expires_at": grant.expires_at}


def page(runtime: Any, grants: list[Grant]) -> dict:
    """The ``GET /api/auth/mcp`` answer for *runtime* and the caller's live *grants* (newest first)."""
    endpoint = runtime.issuer_url
    label = server_label(runtime.settings, runtime.primary_host)
    fragment = {"mcpServers": {label: {"type": "http", "url": endpoint}}}
    return {"v": VERSION, "enabled": True, "endpoint_url": endpoint, "issuer": runtime.issuer_url, "label": label,
            "claude_command": f"claude mcp add --transport http {label} {endpoint}",
            "config_json": json.dumps(fragment, indent=2, ensure_ascii=False),
            "instructions": instructions(runtime.settings.grant_max_age, runtime.settings.max_grants_per_user),
            "grants": [grant_view(g) for g in grants]}


def _page(call: _Call) -> dict:
    return page(call.runtime, call.runtime.store.grants_for(call.user_id))


@router.get(PREFIX, name="mcp_page")
async def mcp_page(request: Request):
    return await _run(request, _page, write=False)


# ── POST /api/auth/mcp/grants/{id}/revoke ────────────────────────────────────────────────────────


def announce(user_id: str, change: str, grant: Grant, at: int) -> None:
    """``mcp.changed`` to *user_id*'s live connections. Runs after the store committed; a failure here is
    logged and never undoes or fails the change."""
    try:
        from tui_gateway.user_events import announce_mcp_changed
        announce_mcp_changed(user_id, {"change": change, "grant": {"id": grant.id, "client_name": grant.client_name},
                                       "at": at})
    except Exception:  # noqa: BLE001 - no gateway in this process, or a contract drift: never fail the change
        _log.warning("mcp.changed could not be announced", exc_info=False)


def _revoke(call: _Call, grant_id: str) -> dict:
    store = call.runtime.store
    # Only the caller's own live grant: another person's, a revoked or ended one and a malformed id are the
    # same 404. The check and the revoke are one store transaction, so of two parallel requests exactly one
    # revokes (and announces).
    revoked = store.revoke_grant(grant_id, by=call.user_id, user_id=call.user_id, live_only=True) \
        if GRANT_ID.fullmatch(grant_id) else None
    if revoked is None:
        raise _Fail(404, "not_found", "No such grant.")
    audit_log(AuditEvent.MCP_GRANT_REVOKED, by=call.user_id, grant_id=revoked.id, user_id=call.user_id,
              client_id=revoked.client_id, client_name=revoked.client_name, ip=call.ip, auth=call.auth)
    announce(call.user_id, "revoked", revoked, store.now())
    return {"ok": True}


@router.api_route(REVOKE_PATH, methods=_ANY_METHOD, name="mcp_grant_revoke")
async def mcp_grant_revoke(request: Request, grant_id: str):
    if mount.current() is None:
        return _not_found(request)
    if request.method != "POST":
        return _wrong_method("POST")
    return await _run(request, lambda call: _revoke(call, grant_id), write=True)


__all__ = ["BODY_CAP", "PREFIX", "REVOKE_PATH", "grant_view", "instructions", "page", "router"]
