"""Chat/terminal WebSocket plumbing: PTY bridge selection and registry, WS
client/origin/auth gates, chat argv resolution, gateway/sidecar URL building.
"""

import logging
import asyncio
import atexit
import concurrent.futures
import contextlib
import hmac
import os
import re
import sys
import tempfile
import threading
import urllib.request
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pathlib import Path
from typing import Optional
from hermes_cli.pty_session import PtySessionRegistry

# Same logger the code used before extraction (record parity).
_log = logging.getLogger("hermes_cli.web_server")


# /api/pty spawns ``hermes --tui`` behind a pseudo-terminal and forwards bytes +
# resize escapes to xterm.js.  POSIX uses pty_bridge (fcntl/termios); native
# Windows uses win_pty_bridge (pywinpty/ConPTY); same surface, no handler guards.
try:
    if sys.platform.startswith("win"):
        from hermes_cli.win_pty_bridge import WinPtyBridge as PtyBridge, PtyUnavailableError
    else:
        from hermes_cli.pty_bridge import PtyBridge, PtyUnavailableError
    _PTY_BRIDGE_AVAILABLE = True
except ImportError:  # pragma: no cover - pywinpty / ptyprocess missing
    PtyBridge = None  # type: ignore[assignment]
    _PTY_BRIDGE_AVAILABLE = False

    class PtyUnavailableError(RuntimeError):  # type: ignore[no-redef]
        """Stub when the platform PTY bridge cannot be imported."""
_RESIZE_RE = re.compile(rb"\x1b\[RESIZE:(\d+);(\d+)\]")
_PTY_READ_CHUNK_TIMEOUT = 0.2

# Back-off between idle PTY reads so a quiet terminal does not spin the event
# loop (keeps dashboard idle CPU low).
# A positive sleep lets other coroutines run and keeps dashboard idle CPU low (#42627).
_PTY_IDLE_BACKOFF = 0.05
PTY_REGISTRY = PtySessionRegistry(
    ttl=30 * 60, max_sessions=16, buffer_cap=1 * 1024 * 1024, read_timeout=_PTY_READ_CHUNK_TIMEOUT)


async def _close_stalled_pty_input(ws: "WebSocket", *, path: str) -> None:
    """Close only the terminal socket when its child stops accepting input."""
    _log.warning("pty input stalled path=%s; recycling terminal session", path)
    try:
        await ws.close(code=1013, reason="PTY input stalled")
    except Exception:
        pass


async def _legacy_pump(ws: "WebSocket", bridge) -> None:
    """Original 1:1 socket<->PTY pump: stream until disconnect, then close the
    bridge. Used when no ``?attach=`` token is supplied (keep-alive opt-in).

    Behavior is identical to the pre-keep-alive ``pty_ws`` body, including the 54028 half-open-socket
    protection (reader EOF → close the WS so the writer's ``ws.receive()`` unparks) and the #53227
    ``to_thread`` offloads for the blocking ``bridge.close()``.
    """
    loop = asyncio.get_running_loop()

    async def pump_pty_to_ws() -> None:
        try:
            while True:
                chunk = await loop.run_in_executor(None, bridge.read, _PTY_READ_CHUNK_TIMEOUT)
                if chunk is None:  # EOF
                    return
                if not chunk:  # no data this tick; yield control and retry
                    await asyncio.sleep(_PTY_IDLE_BACKOFF)
                    continue
                try:
                    await ws.send_bytes(chunk)
                except Exception:
                    return
        finally:
            # Close the WS so the writer's ``ws.receive()`` returns instead of
            # blocking forever on a half-open browser socket (fds would leak and
            # auto-reconnect stacks a fresh PTY on each orphan).  Reap the bridge
            # here too (idempotent): cancelling the handler the instant the WS
            # closes can skip the writer's ``finally``.
            with contextlib.suppress(Exception):
                # The child has exited (EOF) or the send side broke. Closing from the EOF path makes the
                # reap independent of that cancellation race (#54028).
                await asyncio.to_thread(bridge.close)
            with contextlib.suppress(Exception):
                await ws.close()

    reader_task = asyncio.create_task(pump_pty_to_ws())

    try:
        while True:
            try:
                msg = await ws.receive()
            except RuntimeError:
                # ws.receive() after the socket is already disconnected
                # (e.g. closed by the reader task above).
                break
            if msg.get("type") == "websocket.disconnect":
                break
            raw = msg.get("bytes")
            if raw is None:
                text = msg.get("text")
                raw = text.encode("utf-8") if isinstance(text, str) else b""
            if not raw:
                continue
            # Resize escape is consumed locally, never written to the PTY.
            match = _RESIZE_RE.match(raw)
            if match and match.end() == len(raw):
                bridge.resize(cols=int(match.group(1)), rows=int(match.group(2)))
                continue
            if not await bridge.write(raw):
                await _close_stalled_pty_input(ws, path="legacy")
                break
    except WebSocketDisconnect:
        pass
    finally:
        reader_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await reader_task
        await asyncio.to_thread(bridge.close)


# Starlette's TestClient reports the peer as "testclient"; treat it as
# loopback so tests don't need to rewrite request scope.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


def _ws_client_reason(ws: "WebSocket") -> Optional[str]:
    """Return a rejection reason token for the peer IP, or None when allowed.

    Loopback bind: only loopback peers (the legacy ``?token=`` is the only auth,
    LAN hosts must not get to guess it); an empty peer fails closed.  Explicit
    non-loopback bind (``--insecure``) or gated mode: any peer — DNS-rebinding is
    blocked by :func:`_ws_host_origin_reason`, and in gated mode
    ``ws.client.host`` is the X-Forwarded-For value anyway.
    """
    from hermes_cli.web_server import app
    if getattr(app.state, "auth_required", False):
        return None
    bound_host = (getattr(app.state, "bound_host", "") or "").strip().lower()
    if bound_host and bound_host not in _LOOPBACK_HOSTS:
        return None
    client_host = ws.client.host if ws.client else ""
    if not client_host:
        return f"missing_or_empty_peer bound={bound_host or '?'}"
    if client_host in _LOOPBACK_HOSTS:
        return None
    return f"peer_not_loopback peer={client_host} bound={bound_host or '?'}"


def _ws_client_is_allowed(ws: "WebSocket") -> bool:
    """True when the peer IP passes :func:`_ws_client_reason`."""
    return _ws_client_reason(ws) is None


def _ws_host_origin_reason(ws: "WebSocket") -> Optional[str]:
    """Return ``host_mismatch …`` / ``origin_mismatch …``, or None when allowed.

    HTTP middleware does not run for WebSocket routes, so the DNS-rebinding
    Host check is repeated here; an Origin header, when present, must target the
    bound host or be one of the listed public origins exactly (scheme, host and
    port; see ``dashboard_auth.origins``). Non-web origins (packaged Electron:
    file://, null, app://) are trusted — the credential check is the real auth
    boundary there.
    """
    from hermes_cli.dashboard_auth.origins import describe_origins, warn_refused_origin
    from hermes_cli.web_server import _is_accepted_host, app
    from hermes_cli.web_server_origin_guard import WS_ORIGIN_FIX, _is_accepted_origin
    bound_host = getattr(app.state, "bound_host", None)
    if not bound_host:
        return None
    trusted_public_hosts = getattr(app.state, "trusted_public_hosts", frozenset())
    public_origins = getattr(app.state, "public_origins", ())
    host_header = ws.headers.get("host", "")
    if not _is_accepted_host(host_header, bound_host, trusted_public_hosts):
        return f"host_mismatch host={host_header or '?'} bound={bound_host}"
    origin = ws.headers.get("origin", "")
    if not _is_accepted_origin(origin, bound_host, trusted_public_hosts, public_origins,
                               host_header=host_header):
        warn_refused_origin("WebSocket upgrade", origin, public_origins, WS_ORIGIN_FIX)
        expected = describe_origins(public_origins) if public_origins else bound_host
        return f"origin_mismatch origin={origin[:200]} expected={expected}"
    return None


def _ws_refusal_close_reason(ws: "WebSocket") -> Optional[str]:
    """Why the upgrade is refused (Host/Origin, then peer), clamped to RFC 6455's 123-byte close
    reason; ``None`` when allowed. The full reason is logged by the guard."""
    reason = _ws_host_origin_reason(ws) or _ws_client_reason(ws)
    if reason is None:
        return None
    encoded = reason.encode("utf-8", "replace")
    return reason if len(encoded) <= 123 else encoded[:120].decode("utf-8", "ignore") + "..."


def _ws_host_origin_is_allowed(ws: "WebSocket") -> bool:
    """True when the upgrade passes the dashboard Host/Origin guard."""
    return _ws_host_origin_reason(ws) is None


def _ws_request_is_allowed(ws: "WebSocket") -> bool:
    """Return True when the WebSocket upgrade matches dashboard boundaries."""
    return _ws_host_origin_is_allowed(ws) and _ws_client_is_allowed(ws)


_GATEWAY_WS_PROTOCOL = "hermes-gateway-v1"
_GATEWAY_WS_TICKET_PROTOCOL_PREFIX = "hermes-gateway-ticket."


def _gateway_ws_ticket_from_subprotocol(ws: "WebSocket") -> tuple[str, str]:
    """Return ``(ticket, reason)`` from an unambiguous gateway protocol set."""
    raw = str(ws.headers.get("sec-websocket-protocol", "") or "")
    protocols = [value.strip() for value in raw.split(",") if value.strip()]
    ticket_protocols = [
        value for value in protocols if value.startswith(_GATEWAY_WS_TICKET_PROTOCOL_PREFIX)]
    if not ticket_protocols:
        return "", "none"
    if _GATEWAY_WS_PROTOCOL not in protocols or len(ticket_protocols) != 1:
        return "", "invalid"
    ticket = ticket_protocols[0][len(_GATEWAY_WS_TICKET_PROTOCOL_PREFIX):]
    return (ticket, "ok") if ticket else ("", "invalid")


def _ws_auth_reason(ws: "WebSocket") -> tuple[Optional[str], str]:
    """Validate WS-upgrade auth; return ``(reason, credential)``.

    ``reason`` is None when accepted, else a short token (``no_credential``,
    ``token_mismatch``, ``ticket_invalid``, ``internal_invalid``);
    ``credential`` names what was presented so the accept path can log *how*.

    Loopback / ``--insecure``: legacy ``?token=`` (constant-time compared).
    Gated: ``?ticket=`` (browser-minted, single-use, 30s TTL) or ``?internal=``
    (process-lifetime, multi-use, only for server-spawned WS clients so the PTY
    child can reconnect; never injected into the SPA).  The legacy token is
    rejected in gated mode: a leaked ``_SESSION_TOKEN`` must not grant access.
    """
    from hermes_cli.web_server import _SESSION_TOKEN, app
    auth_required = bool(getattr(app.state, "auth_required", False))
    if auth_required:
        # Lazy import — keeps this function importable in test harnesses
        # that don't bring in the dashboard_auth layer.
        from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
        from hermes_cli.dashboard_auth.ws_tickets import TicketInvalid, consume_pty_credential, consume_ticket

        def _reject(reason: str) -> None:
            audit_log(
                AuditEvent.WS_TICKET_REJECTED, reason=reason,
                ip=(ws.client.host if ws.client else ""), path=ws.url.path)

        def _stamp_identity(info) -> None:
            # Server-minted {user_id, provider} stamped onto the WS object is the
            # sole identity authority downstream (gateway transport / controller
            # registration); a client can never supply it through RPC params.
            # Only identity fields are carried — bookkeeping such as ``minted_at`` is not part of
            # the identity contract. ``user_name`` is the provider-verified display name of THIS
            # user_id, minted with it (never client-supplied) and present only when the credential
            # carried one, so a nameless credential stamps exactly {user_id, provider}.
            identity = {"user_id": info.get("user_id"), "provider": info.get("provider")}
            if user_name := str(info.get("user_name") or "").strip():
                identity["user_name"] = user_name
            # The person's profile, minted with the same login (``Session.profile``), reduced once more to
            # the allowlisted, cleaned shape; absent from an older or profile-less credential.
            from agent.person_profile import coerce_profile
            if profile := coerce_profile(info.get("profile")):
                identity["profile"] = profile
            ws._hermes_auth_identity = identity

        pty = ws.query_params.get("pty", "")
        if pty:
            # The embedded Chat tab's terminal child: the login that opened that terminal, for its lifetime,
            # and only where the child itself connects (its two sidecar routes, from this host, not through
            # a proxy). Anywhere else the value would let its holder mint fresh terminals for that login.
            if not _pty_peer_allowed(ws):
                _reject("pty: refused on this route or from this peer")
                return "pty_refused", "pty"
            try:
                _stamp_identity(consume_pty_credential(pty))
                setattr(ws, "_hermes_pty_credential", pty)
                return None, "pty"
            except TicketInvalid as exc:
                _reject(f"pty: {exc}")
                return "pty_invalid", "pty"

        protocol_ticket, protocol_reason = _gateway_ws_ticket_from_subprotocol(ws)
        if protocol_reason == "invalid":
            return "ticket_invalid", "ticket-subprotocol"
        ticket = protocol_ticket or ws.query_params.get("ticket", "")
        if not ticket:
            return "no_credential", "none"

        try:
            info = consume_ticket(ticket)
            if info.get("provider") == "bot-desktop":
                # A display ticket admits one RFB bridge on /api/display/ws (a watch-only
                # capability handed to a screen viewer); it must not double as a login here.
                raise TicketInvalid("display ticket presented as a gateway login")
            _stamp_identity(info)
            if protocol_ticket:
                # Select only the stable public protocol during accept. The
                # ticket-bearing protocol is a credential and must never be
                # reflected back to the browser or retained after admission.
                ws._hermes_ws_subprotocol = _GATEWAY_WS_PROTOCOL
                return None, "ticket-subprotocol"
            return None, "ticket"
        except TicketInvalid as exc:
            _reject(str(exc))
            return "ticket_invalid", "ticket"

    token = ws.query_params.get("token", "")
    if not token:
        return "no_credential", "none"
    if hmac.compare_digest(token.encode(), _SESSION_TOKEN.encode()):
        return None, "token"
    return "token_mismatch", "token"


def _ws_auth_ok(ws: "WebSocket") -> bool:
    """True when the WS-upgrade credential is accepted. See _ws_auth_reason."""
    return _ws_auth_reason(ws)[0] is None


def _resolve_chat_argv(
    resume: Optional[str] = None, sidecar_url: Optional[str] = None, profile: Optional[str] = None,
    active_session_file: Optional[str] = None,
    workspace_cwd: Optional[str] = None,
    pty_credential: Optional[str] = None) -> tuple[list[str], Optional[str], Optional[dict]]:
    """Resolve the argv + cwd + env for the chat PTY (what ``hermes --tui`` runs).

    Tests monkeypatch this with a tiny fake command.  Env contract: resume goes
    through ``HERMES_TUI_RESUME`` (``ui-tui`` does not parse argv), resolved to
    the newest descendant; ``HERMES_TUI_GATEWAY_URL`` attaches to this process's
    in-memory gateway but is SKIPPED for profile-scoped chats (that gateway runs
    under the dashboard's own profile, so a scoped chat spawns its own);
    ``profile`` scopes the ENTIRE chat by pointing ``HERMES_HOME`` at the profile
    dir, the same propagation ``hermes -p <name>`` performs. ``workspace_cwd``
    (an already-validated host directory, ``chat_workspaces.resolve_chat_cwd``)
    is the workspace the user picked for a FRESH chat: it becomes ``HERMES_CWD``
    (where a self-spawned gateway starts) and ``HERMES_TUI_CWD`` (what the TUI
    passes as the explicit ``cwd`` of ``session.create`` when attached to the
    in-memory gateway, whose own cwd is the dashboard's launch dir).
    """
    from hermes_cli.web_server_profiles import _config_profile_scope, _resolve_profile_dir
    from hermes_cli.web_server_sessions import _open_session_db_for_profile, _session_latest_descendant
    from hermes_cli.main import PROJECT_ROOT
    from hermes_cli.main_tui_launch import _apply_tui_python_env, _make_tui_argv

    profile_dir: Optional[Path] = None
    requested = (profile or "").strip()
    if requested and requested.lower() != "current":
        profile_dir = _resolve_profile_dir(requested)

    argv, cwd = _make_tui_argv(PROJECT_ROOT / "ui-tui", tui_dev=False)
    # Secrets kept — the spawned agent needs provider creds.  An explicit profile
    # scope overrides HERMES_HOME before config is bridged into the env.
    from tools.environments.local import build_subprocess_env
    env = build_subprocess_env(scrub_secrets=False, inherit_profile_home=True)
    if profile_dir is not None:
        env["HERMES_HOME"] = str(profile_dir)
    try:
        from hermes_cli.config import (
            apply_terminal_config_to_env, read_raw_config, terminal_config_owned_env_vars)

        if profile_dir is not None:
            # Drop only the terminal keys the launch profile owns before applying
            # the selected profile; operator exports for other keys stay valid.
            raw_launch_terminal = read_raw_config().get("terminal")
            for env_var in terminal_config_owned_env_vars(raw_launch_terminal):
                env.pop(env_var, None)
            with _config_profile_scope(requested):
                apply_terminal_config_to_env(env=env)
        else:
            apply_terminal_config_to_env(env=env)
    except Exception:
        _log.warning("Failed to apply terminal config bridge for dashboard chat", exc_info=True)
    if workspace_cwd:
        env["HERMES_CWD"] = workspace_cwd
        env["HERMES_TUI_CWD"] = workspace_cwd
    _apply_tui_python_env(env)
    env.setdefault("NODE_ENV", "production")
    # Mouse tracking would swallow wheel events the browser needs for
    # transcript scrolling; disable it for the dashboard PTY only.
    env.setdefault("HERMES_TUI_DISABLE_MOUSE", "1")
    env.setdefault("HERMES_TUI_INLINE", "1")
    # chalk in the child picks its color depth from the SERVER env; hosted
    # deploys have no COLORTERM, so hex colors would snap to the 256 palette.
    env.setdefault("COLORTERM", "truecolor")
    env["HERMES_TUI_DASHBOARD"] = "1"

    if resume:
        _resume_db = _open_session_db_for_profile(
            requested if profile_dir is not None else None, read_only=True)
        try:
            latest_resume, _latest_path = _session_latest_descendant(resume, _resume_db)
        finally:
            _resume_db.close()
        if latest_resume:
            resume = latest_resume
        env["HERMES_TUI_RESUME"] = resume

    if sidecar_url:
        env["HERMES_TUI_SIDECAR_URL"] = sidecar_url

    if active_session_file:
        env["HERMES_TUI_ACTIVE_SESSION_FILE"] = active_session_file

    # Without the attach URL, gatewayClient spawns its own `tui_gateway.entry`,
    # which inherits the profile HERMES_HOME set above.
    if profile_dir is None and (gateway_ws_url := _build_gateway_ws_url(pty_credential)):
        env["HERMES_TUI_GATEWAY_URL"] = gateway_ws_url

    return list(argv), str(cwd) if cwd else None, env


# Wildcard bind hosts an in-container client must NOT dial: behind a forward
# proxy (HTTPS_PROXY without 0.0.0.0 in NO_PROXY) the handshake gets MITM'd.
_WILDCARD_HOSTS = frozenset({"0.0.0.0", "::"})


def _resolve_client_ws_host() -> Optional[str]:
    """Host the in-container WS client should dial: ``HERMES_DASHBOARD_WS_HOST``
    wins always; a wildcard bind becomes ``127.0.0.1``; others verbatim."""
    from hermes_cli.web_server import app
    explicit = os.environ.get("HERMES_DASHBOARD_WS_HOST", "").strip()
    if explicit:
        return explicit
    host = getattr(app.state, "bound_host", None)
    if not host:
        return None
    return "127.0.0.1" if host in _WILDCARD_HOSTS else host


def _server_internal_ws_url(path: str, pty_credential: Optional[str] = None, **extra_qs) -> Optional[str]:
    """``ws://<host>:<port><path>?<auth>&<extra>`` for the embedded-chat PTY child, or None when unbound.

    Gated mode uses the PTY's own credential (``ws_tickets.mint_pty_credential``, bound to the login that
    opened the Chat tab), NOT a single-use browser ticket: the child reads the URL once and reuses it on
    every reconnect, and a 30s-TTL ticket can expire before a slow cold boot dials. Without one (no login
    behind the PTY) there is no URL and the child runs its own gateway; the process-wide internal
    credential is never handed out, because a child's environment is readable by other processes.
    """
    from hermes_cli.web_server import _SESSION_TOKEN, app
    host = _resolve_client_ws_host()
    port = getattr(app.state, "bound_port", None)
    if not host or not port:
        return None
    netloc = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
    if getattr(app.state, "auth_required", False):
        if not pty_credential:
            return None
        auth = {"pty": pty_credential}
    else:
        auth = {"token": _SESSION_TOKEN}
    return f"ws://{netloc}{path}?{urllib.parse.urlencode({**auth, **extra_qs})}"


#: The only routes a terminal child dials with its credential.
_PTY_CREDENTIAL_PATHS = frozenset({"/api/ws", "/api/pub"})
#: Headers a proxy adds: a request carrying any of them did not come straight from the gateway host.
_FORWARDING_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip", "cf-connecting-ip", "true-client-ip")


def _pty_peer_allowed(ws) -> bool:
    """Whether a per-PTY credential may be presented on *ws*: on ``/api/ws`` or ``/api/pub`` only, from a
    loopback peer or the exact address the child is told to dial, with no forwarding header."""
    import ipaddress
    path = str(getattr(getattr(ws, "url", None), "path", "") or "")
    if path not in _PTY_CREDENTIAL_PATHS:
        return False
    headers = getattr(ws, "headers", {}) or {}
    if any(headers.get(name) for name in _FORWARDING_HEADERS):
        return False
    peer = str(getattr(getattr(ws, "client", None), "host", "") or "")
    try:
        if ipaddress.ip_address(peer).is_loopback:
            return True
    except ValueError:
        pass
    dial = _resolve_client_ws_host()
    return bool(peer) and peer == (dial or "").strip("[]")


def _build_gateway_ws_url(pty_credential: Optional[str] = None) -> Optional[str]:
    """ws:// URL the PTY child attaches to for JSON-RPC gateway traffic."""
    return _server_internal_ws_url("/api/ws", pty_credential)


def _build_sidecar_url(channel: str, pty_credential: Optional[str] = None) -> Optional[str]:
    """ws:// URL the PTY child publishes events to, or None when unbound."""
    return _server_internal_ws_url("/api/pub", pty_credential, channel=channel)


async def _resolve_chat_argv_async(
    resume: Optional[str] = None, sidecar_url: Optional[str] = None, profile: Optional[str] = None,
    active_session_file: Optional[str] = None,
    workspace_cwd: Optional[str] = None,
    pty_credential: Optional[str] = None) -> tuple[list[str], Optional[str], Optional[dict]]:
    """Resolve chat argv off the event loop (it may run ``npm run build``); the
    async lock keeps one-build-at-a-time without parking worker threads."""
    from hermes_cli.web_server import _get_chat_argv_lock, app
    kwargs = {"resume": resume, "sidecar_url": sidecar_url, "profile": profile}
    if active_session_file is not None:
        kwargs["active_session_file"] = active_session_file
    if workspace_cwd is not None:
        kwargs["workspace_cwd"] = workspace_cwd
    if pty_credential is not None:
        kwargs["pty_credential"] = pty_credential

    async with _get_chat_argv_lock(app):
        return await asyncio.to_thread(_resolve_chat_argv, **kwargs)


def _active_session_file_for_channel(app: "FastAPI", channel: str) -> Path:
    """Return the per-channel file where a dashboard TUI writes its active sid."""
    from hermes_cli.web_server import _get_pty_active_session_files
    files = _get_pty_active_session_files(app)
    if files.get(channel) is None:
        fd, raw_path = tempfile.mkstemp(prefix="hermes-pty-active-", suffix=".json")
        os.close(fd)
        files[channel] = Path(raw_path)
    return files[channel]


# On timeout asyncio cancels the awaitable but the console thread keeps running;
# a small dedicated pool caps the leak instead of exhausting the default pool.
_CONSOLE_EXECUTOR_MAX_WORKERS = 4
_console_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
_console_executor_lock = threading.Lock()


def _get_console_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Lazily create the bounded console worker pool (once per process)."""
    global _console_executor
    if _console_executor is None:
        with _console_executor_lock:
            if _console_executor is None:
                _console_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=_CONSOLE_EXECUTOR_MAX_WORKERS, thread_name_prefix="hermes-console")
                # Tear down on interpreter exit without waiting on in-flight
                # workers: a stuck 60s console command must not block shutdown.
                atexit.register(
                    lambda: _console_executor
                    and _console_executor.shutdown(wait=False, cancel_futures=True))
    return _console_executor
