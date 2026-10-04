"""Switching the MCP authorization server and endpoint on, once, when the dashboard starts.

``web_server`` calls :func:`install` at import (one route object, placed before the SPA catch-all) and
:func:`configure` from ``_configure_auth_gate``, after the gate and the public origins are settled. The
feature is on only when all of these hold; otherwise it is off and says why in one log line:

- ``dashboard.mcp.enabled`` is true (operator-only: config file or ``HERMES_DASHBOARD_MCP_ENABLED``);
- the sign-in gate is engaged (``app.state.auth_required``): an ungated dashboard has no signed-in person
  to bind a grant to, so the endpoint is off there whatever the config says;
- a public URL is configured (``dashboard.public_url``/``public_urls``) whose primary is ``https://`` (or
  loopback ``http://``) without a path prefix: the issuer and the token audience are
  ``<primary>/mcp``, and RFC 8414/9728 metadata lives at the host root;
- the ``mcp`` package (the ``[mcp]`` extra) imports.

While off, the route matches nothing and the gate's public-path registry holds none of these paths, so
every ``/mcp*`` and ``/.well-known/oauth-*`` request is answered exactly as on a gateway without the
feature. While on, the paths are served on the primary public host only; on any other host (a second
listed origin, a bare address) they answer 404. Settings are read at startup; a change needs a restart.

This module imports neither the ``mcp`` package nor FastAPI's app: :mod:`.routes` (which needs ``mcp``)
is imported only when the feature turns on.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Match
from starlette.types import ASGIApp, Receive, Scope, Send

from hermes_cli.dashboard_auth.mcp.settings import MCPSettings, parse
from hermes_cli.dashboard_auth.public_paths import register_public_path, unregister_public_path

_log = logging.getLogger(__name__)

ENDPOINT_PATH = "/mcp"
CONSENT_PATH = "/mcp/consent"
AS_METADATA_PATHS = ("/.well-known/oauth-authorization-server/mcp", "/.well-known/oauth-authorization-server")
RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
#: Answered on their own credentials (client authentication, the MCP bearer, nothing), so the dashboard
#: gate lets them through while the feature is on. ``/mcp/consent`` is NOT among them: it needs the
#: dashboard's cookie sign-in.
PUBLIC_PATHS = (ENDPOINT_PATH, "/mcp/authorize", "/mcp/token", "/mcp/register", "/mcp/revoke",
                *AS_METADATA_PATHS, RESOURCE_METADATA_PATH)
SERVED_PATHS = frozenset((*PUBLIC_PATHS, CONSENT_PATH))


@dataclass(frozen=True)
class MCPRuntime:
    """Everything the routes use, built once by :func:`configure`."""
    settings: MCPSettings
    store: Any  # MCPStore
    provider: Any  # routes.RouteProvider
    verifier: Any  # MCPTokenVerifier
    issuer_url: str  # https://<primary>/mcp: the issuer AND the resource tokens are bound to
    primary_host: str
    primary_origin: str  # the browser Origin of the primary public URL
    app: ASGIApp  # the router behind :data:`SERVED_PATHS`


_runtime: Optional[MCPRuntime] = None


def current() -> Optional[MCPRuntime]:
    """The running authorization server, or None while the feature is off."""
    return _runtime


def _set(runtime: Optional[MCPRuntime]) -> None:
    global _runtime
    for path in PUBLIC_PATHS:
        if runtime is None:
            unregister_public_path(path)
        else:
            register_public_path(path)
    _runtime = runtime


def reset_for_tests() -> None:
    _set(None)
    with contextlib.suppress(ImportError):
        from hermes_cli.dashboard_auth.mcp import routes
        routes.reset_for_tests()


def _off(reason: str, *args: Any, level: int = logging.WARNING) -> None:
    _log.log(level, "MCP endpoint off: " + reason, *args)


def _issuer_for(origins: Any) -> tuple[str, Any] | None:
    """``(issuer, primary origin)`` or None (logged) when the primary public URL cannot carry one."""
    if not origins:
        _off("dashboard.mcp.enabled is true but no dashboard.public_url is configured; the issuer and the "
             "token audience are built from it.")
        return None
    primary = origins[0]
    path = urlsplit(primary.base_url).path
    if path not in ("", "/"):
        _off("the primary public URL %s has a path prefix; the OAuth metadata must be served at the host root, "
             "so the endpoint needs a public URL without one.", primary.base_url)
        return None
    if primary.scheme != "https" and primary.host not in ("localhost", "127.0.0.1", "::1"):
        _off("the primary public URL %s is not https; an OAuth issuer must be.", primary.base_url)
        return None
    return f"{primary.base_url.rstrip('/')}{ENDPOINT_PATH}", primary


def configure(app: Any, *, cfg: Any = None, store: Any = None) -> Optional[MCPRuntime]:
    """Turn the feature on or off for *app* from the config (*cfg*: the config mapping, read when None;
    *store*: an ``MCPStore``, the default file when None). Returns the runtime, or None when off."""
    _set(None)
    if cfg is None:
        try:
            from hermes_cli.config import load_config
            cfg = load_config()
        except Exception:  # noqa: BLE001 - an unreadable config never enables the endpoint
            _off("the config could not be read.")
            return None
    settings, problems = parse(cfg)
    for problem in problems:
        _log.warning("%s", problem)
    if not settings.enabled:
        return None
    if not getattr(app.state, "auth_required", False):
        _off("the dashboard has no sign-in gate (loopback bind), so no connection has a signed-in person to "
             "grant access as.")
        return None
    found = _issuer_for(tuple(getattr(app.state, "public_origins", None) or ()))
    if found is None:
        return None
    issuer, primary = found
    try:
        from hermes_cli.dashboard_auth.mcp import routes
    except ImportError as exc:
        _log.error("dashboard.mcp.enabled is true but the mcp package is not installed (%s); the MCP endpoint "
                   "stays off. Install the extra: pip install 'hermes-agent[mcp]'.", exc)
        return None
    try:
        runtime = routes.build_runtime(settings=settings, issuer_url=issuer, primary=primary, store=store)
    except ValueError as exc:
        _off("%s", exc)
        return None
    _set(runtime)
    _log.info("MCP endpoint on: %s (also the OAuth issuer; grants in %s)", issuer, runtime.store.path)
    return runtime


@contextlib.asynccontextmanager
async def lifespan(app: Any) -> AsyncIterator[None]:
    """Entered by the dashboard's lifespan: runs the MCP server's session manager (its task group serves every
    ``POST /mcp``) while the feature is on; nothing otherwise."""
    runtime = _runtime
    manager = getattr(runtime, "session_manager", None) if runtime is not None else None
    if manager is None:
        yield
        return
    async with manager.run():
        yield


# ── the route ─────────────────────────────────────────────────────────────────────────────────────


def _host(scope: Scope) -> str:
    from hermes_cli.dashboard_auth.origins import request_origin_key
    key = request_origin_key(Request(scope))
    return key[1] if key else ""


class _Switch(BaseRoute):
    """Matches :data:`SERVED_PATHS` while the feature is on and nothing otherwise, so a gateway with the
    feature off routes those paths exactly as one without it."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope.get("type") == "http" and _runtime is not None and scope.get("path") in SERVED_PATHS:
            return Match.FULL, {}
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any):
        from starlette.routing import NoMatchFound
        raise NoMatchFound(name, path_params)

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        runtime = _runtime
        if runtime is None:  # turned off between match and handle
            response = JSONResponse({"detail": "Not Found"}, status_code=404)
        elif _host(scope) != runtime.primary_host:
            response = JSONResponse({"detail": "Not Found"}, status_code=404)
        else:
            await runtime.app(scope, receive, send)
            return
        await response(scope, receive, send)


_ROUTE = _Switch()


def install(app: Any) -> None:
    """Add the route to *app* (once). FastAPI's ``include_router`` drops route types it does not know, so it
    is appended to the router directly; call this before the SPA catch-all is mounted."""
    if _ROUTE not in app.router.routes:
        app.router.routes.append(_ROUTE)
