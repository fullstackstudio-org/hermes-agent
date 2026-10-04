"""The MCP authorization server's HTTP surface on the dashboard app, built from the ``mcp`` SDK's handlers.

    GET  /.well-known/oauth-authorization-server/mcp   RFC 8414 metadata for the issuer <primary>/mcp
    GET  /.well-known/oauth-authorization-server       the same body (the root form some clients try)
    GET  /.well-known/oauth-protected-resource/mcp     RFC 9728 metadata for the resource <primary>/mcp
    GET|POST /mcp/authorize                            SDK handler; 302 to the consent page, or a refusal the
                                                       gateway answers itself (never a redirect to the client)
    GET|POST /mcp/consent                              the person decides (cookie sign-in; see consent.py)
    POST /mcp/token                                    SDK handler; code and refresh grants
    POST /mcp/register                                 SDK handler; RFC 7591 dynamic client registration
    POST /mcp/revoke                                   RFC 7009; public clients need no secret
    POST /mcp                                          the MCP endpoint, behind the SDK's bearer check

Only :mod:`.mount` decides whether these exist (and on which host); this module builds them. Every path
but ``/mcp/consent`` is public to the dashboard gate: each answers on its own credentials.

What the route layer adds to the SDK's handlers:

- the client's address (the one uvicorn settled, never a raw ``X-Forwarded-For``) and user agent are
  bound for the provider around every call (the SDK does not hand the request to the provider);
- client authentication on ``/mcp/token`` and ``/mcp/revoke`` is :class:`MCPClientAuthenticator`: the
  store keeps only a secret's hash, so the SDK's own authenticator would refuse every secret client;
- ``resource`` on ``/mcp/token`` is checked (the SDK ignores it): a different resource is
  ``invalid_target``;
- ``/mcp/authorize`` redirects only to the consent page. Every refusal the SDK would send back to the
  client's redirect URI (a bad scope, a non-S256 challenge, a foreign ``resource``) is a page or JSON from
  the gateway instead (400; 503 for ``temporarily_unavailable``): anyone may register a redirect URI, so
  redirecting before the person saw the client on the consent page would make the gateway an open
  redirector. The client hears an error only through the person's Deny on that page;
- the revocation endpoint is this module's, because the SDK's requires a ``client_secret`` field even
  from a public client;
- a store that cannot be used answers 503 ``temporarily_unavailable`` on every route, never a 400 or 401
  that would tell a client its credentials are bad;
- per-address limits: ``/mcp/register`` 10 an hour, ``/mcp/token`` and ``/mcp/revoke`` 60 a minute (429
  ``rate_limited`` with ``Retry-After``); ``/mcp/authorize`` holds at most 8 open consents per address
  (the store's cap);
- bodies of at most 16 KiB; metadata with ``Cache-Control: no-store`` and ``none`` among the client
  authentication methods (public clients use it), and ``authorization_response_iss_parameter_supported``:
  the consent page's answer to the client carries ``iss`` = the metadata's ``issuer`` (RFC 9207);
- audit lines (``mcp_client_registered``, ``mcp_authorize_start``, ``mcp_token_issued``,
  ``mcp_token_refreshed``, ``mcp_token_rejected``, ``mcp_grant_revoked``, ``mcp_rate_limited``) with ids,
  names, the address and an outcome; never a token, code, secret, state or nonce;
- ``mcp.changed`` to the person: ``granted`` when a code is exchanged, ``revoked`` when the client revokes
  its own grant (RFC 7009) and when a code or refresh token presented again made the store revoke one
  (``mcp_grant_revoked`` with ``by`` ``code_reuse`` / ``refresh_reuse``; the client hears ``invalid_grant``);
  a rotated refresh token refused inside the parallel-refresh window (``store.Raced``, the grant stays) is
  ``mcp_token_rejected`` with ``reason: refresh_raced`` and its ``grant_id``.

``POST /mcp`` is the MCP server (``tui_gateway.mcp_bridge.server``) behind the SDK's bearer check against this
store: a missing or invalid token gets the SDK's 401 with
``WWW-Authenticate: Bearer … resource_metadata="<primary>/.well-known/oauth-protected-resource/mcp"``; a valid
one reaches the tools as its person and agent (503 ``bridge_not_ready`` until the dashboard's lifespan has
started the server's session manager). ``GET`` and ``DELETE /mcp`` answer 405 (no server-initiated stream,
no sessions).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlsplit

import anyio.to_thread
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.middleware.client_auth import AuthenticationError
from mcp.server.auth.routes import build_metadata, cors_middleware, validate_issuer_url
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import ProtectedResourceMetadata
from pydantic import AnyHttpUrl
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, Router
from starlette.types import ASGIApp, Receive, Scope, Send

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.mcp import api_routes, mount
from hermes_cli.dashboard_auth.mcp.provider import (
    MCPAuthorizationCode, MCPClientAuthenticator, MCPProvider, MCPRefreshToken, MCPTokenVerifier)
from hermes_cli.dashboard_auth.mcp.settings import SCOPES, MCPSettings, server_label
from hermes_cli.dashboard_auth.mcp.store import (
    BY_CLIENT, CodeInvalid, ConsentInvalid, LimitReached, MCPStore, StoreError, TokenInvalid)
from hermes_cli.dashboard_auth.rate_limit import SlidingWindowLimiter, Verdict
from hermes_cli.dashboard_auth.request_utils import client_ip

_log = logging.getLogger(__name__)

BODY_CAP = 16 * 1024
PRUNE_EVERY_S = 3600.0
CLIENT_ID_LOG_LIMIT = 80
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

#: RFC 8252 §7.3 says a loopback redirect URI should match on any port, since a native client binds an
#: ephemeral one per run. Off: the SDK matches the registered URI exactly. Which form MCP clients
#: register is to be confirmed with a real client; turning this on is the one-line switch.
LOOPBACK_ANY_PORT = False

REGISTER_PER_IP = SlidingWindowLimiter(10, 3600)
TOKEN_PER_IP = SlidingWindowLimiter(60, 60)
REVOKE_PER_IP = SlidingWindowLimiter(60, 60)
LIMITERS = (REGISTER_PER_IP, TOKEN_PER_IP, REVOKE_PER_IP)

_REFUSALS = (LimitReached, ConsentInvalid, CodeInvalid, TokenInvalid)


def reset_for_tests() -> None:
    for limiter in LIMITERS:
        limiter.reset()
    with _prune_lock:
        _last_prune.clear()


# ── what one request learned from the provider ────────────────────────────────────────────────────


@dataclass
class CallNotes:
    store_down: bool = False
    grant_id: str = ""
    user_id: str = ""
    extra: dict = field(default_factory=dict)
    revoked_by_reuse: list = field(default_factory=list)  # store.Reused: grants a reused code/token revoked
    raced_grant: str = ""  # store.Raced: the grant of a refresh token refused inside the parallel-refresh window
    raced_user: str = ""  # store.Raced: the person holding that grant


_notes: ContextVar[Optional[CallNotes]] = ContextVar("dashboard_mcp_call_notes", default=None)


def _note() -> Optional[CallNotes]:
    return _notes.get()


class RouteProvider(MCPProvider):
    """:class:`MCPProvider` as the routes run it: a store that cannot be used is noted for the request (so
    the route answers 503 even where the SDK would turn the exception into an OAuth error), and the grant
    a token request issued for is noted for the audit line."""

    @staticmethod
    async def _run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return await MCPProvider._run(fn, *args, **kwargs)
        except StoreError as exc:
            notes = _note()
            if notes is not None and not isinstance(exc, _REFUSALS):
                notes.store_down = True
            raise

    def reused(self, exc) -> None:
        notes = _note()
        if notes is not None:
            notes.revoked_by_reuse.append(exc)

    def raced(self, exc) -> None:
        notes = _note()
        if notes is not None:
            notes.raced_grant = exc.grant_id
            notes.raced_user = exc.user_id

    async def get_client(self, client_id: str):
        info = await super().get_client(client_id)
        if info is not None and LOOPBACK_ANY_PORT:
            info = _LoopbackClient.model_validate(info.model_dump())
        return info

    async def exchange_authorization_code(self, client, authorization_code: MCPAuthorizationCode):
        token = await super().exchange_authorization_code(client, authorization_code)
        notes = _note()
        if notes is not None:
            notes.grant_id, notes.user_id = authorization_code.grant_id, authorization_code.subject or ""
        return token

    async def exchange_refresh_token(self, client, refresh_token: MCPRefreshToken, scopes: list[str]):
        token = await super().exchange_refresh_token(client, refresh_token, scopes)
        notes = _note()
        if notes is not None:
            notes.grant_id, notes.user_id = refresh_token.grant_id, refresh_token.subject or ""
        return token


def _loopback_client_class():
    from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull

    class LoopbackClient(OAuthClientInformationFull):
        """RFC 8252 §7.3: a registered loopback redirect URI matches the same URI on any port."""

        def validate_redirect_uri(self, redirect_uri):
            try:
                return super().validate_redirect_uri(redirect_uri)
            except InvalidRedirectUriError:
                if redirect_uri is None:
                    raise
                asked = urlsplit(str(redirect_uri))
                for uri in self.redirect_uris or ():
                    known = urlsplit(str(uri))
                    if asked.scheme == known.scheme == "http" and asked.hostname == known.hostname \
                            and asked.hostname in ("127.0.0.1", "localhost") \
                            and (asked.path, asked.query) == (known.path, known.query):
                        return redirect_uri
                raise

    return LoopbackClient


_LoopbackClient = _loopback_client_class()


# ── shared helpers ──────────────────────────────────────────────────────────────────────────────


def runtime() -> Any:
    rt = mount.current()
    if rt is None:  # the switch never routes here while off; defensive
        raise RuntimeError("the MCP authorization server is off")
    return rt


def error(status: int, code: str, description: str, *, headers: Optional[dict] = None) -> JSONResponse:
    """An OAuth-style error body (``error``, ``error_description``)."""
    return JSONResponse({"error": code, "error_description": description}, status_code=status,
                        headers={**_NO_STORE, **(headers or {})})


def unavailable() -> JSONResponse:
    return error(503, "temporarily_unavailable", "The gateway's MCP store is unavailable; try again later.",
                 headers={"Retry-After": "30"})


def _clip(value: Any, limit: int = CLIENT_ID_LOG_LIMIT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def limited(limiter: SlidingWindowLimiter, request: Request, route: str) -> Optional[Response]:
    ip = client_ip(request)
    verdict = limiter.check(ip)
    if verdict is Verdict.ALLOWED:
        return None
    if verdict is Verdict.REFUSED:
        audit_log(AuditEvent.MCP_RATE_LIMITED, route=route, ip=ip)
    retry = int(limiter.window_sec)
    return JSONResponse({"error": "rate_limited", "error_description": "Too many requests from this address.",
                         "retry_after_seconds": retry}, status_code=429,
                        headers={**_NO_STORE, "Retry-After": str(retry)})


class BodyTooLarge(Exception):
    pass


async def read_capped_body(request: Request, cap: int = BODY_CAP) -> bytes:
    """The body, refused past *cap* bytes; kept on the request so the SDK's ``form()``/``body()`` read it."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > cap:
                raise BodyTooLarge
        except ValueError:
            raise BodyTooLarge from None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > cap:
            raise BodyTooLarge
        chunks.append(chunk)
    body = b"".join(chunks)
    request._body = body  # what Request.body() caches; stream() and form() then read it
    return body


def too_large() -> JSONResponse:
    return error(413, "invalid_request", f"The body is larger than {BODY_CAP} bytes.")


_prune_lock = threading.Lock()
_last_prune: dict[str, float] = {}


def maybe_prune(store: MCPStore) -> None:
    """Expired consents, codes, tokens and unused registrations age out here, at most once an hour per store
    (as the passkey routes prune theirs). A failure is logged and never fails the request."""
    now = time.monotonic()
    with _prune_lock:
        last = _last_prune.get(str(store.path))
        if last is not None and now - last < PRUNE_EVERY_S:
            return
        _last_prune[str(store.path)] = now
    try:
        store.prune()
    except StoreError:
        _log.warning("MCP store: pruning failed", exc_info=False)


async def provider_call(request: Request, call: Callable[[], Awaitable[Response]]) -> tuple[Response, CallNotes]:
    """Run *call* with the client's address bound for the provider; a store that cannot be used becomes 503."""
    from hermes_cli.dashboard_auth.mcp.provider import request_bound

    rt = mount.current()
    if rt is not None:
        await anyio.to_thread.run_sync(maybe_prune, rt.store)
    notes = CallNotes()
    token = _notes.set(notes)
    try:
        with request_bound(client_ip(request), request.headers.get("user-agent", "")):
            response = await call()
    except StoreError as exc:
        if isinstance(exc, _REFUSALS):
            raise
        notes.store_down = True
        response = unavailable()
    finally:
        _notes.reset(token)
    if notes.store_down:
        _log.warning("MCP authorization server: the MCP store is unavailable")
        return unavailable(), notes
    return response, notes


def _body_json(response: Response) -> dict:
    try:
        data = json.loads(bytes(response.body))
    except (ValueError, TypeError, AttributeError):
        return {}
    return data if isinstance(data, dict) else {}


# ── metadata ────────────────────────────────────────────────────────────────────────────────────


def _metadata_endpoint(body: dict) -> Callable[[Request], Awaitable[Response]]:
    async def endpoint(request: Request) -> Response:
        return JSONResponse(body, headers={"Cache-Control": "no-store"})
    return endpoint


def authorization_server_metadata(issuer_url: str) -> dict:
    metadata = build_metadata(
        AnyHttpUrl(issuer_url), None,
        ClientRegistrationOptions(enabled=True, valid_scopes=list(SCOPES), default_scopes=list(SCOPES)),
        RevocationOptions(enabled=True))
    methods = ["none", "client_secret_post", "client_secret_basic"]
    metadata.token_endpoint_auth_methods_supported = methods
    metadata.revocation_endpoint_auth_methods_supported = methods
    # RFC 9207: every decision the consent page sends back carries ``iss`` (MCPProvider ``issuer``). A client
    # that reads this compares ``iss`` with ``issuer`` and refuses a response without it (mix-up defence).
    metadata.authorization_response_iss_parameter_supported = True
    return metadata.model_dump(mode="json", exclude_none=True)


def protected_resource_metadata(issuer_url: str) -> dict:
    metadata = ProtectedResourceMetadata(resource=AnyHttpUrl(issuer_url), authorization_servers=[AnyHttpUrl(issuer_url)],
                                         scopes_supported=list(SCOPES))
    return metadata.model_dump(mode="json", exclude_none=True)


# ── the AS endpoints ────────────────────────────────────────────────────────────────────────────


async def authorize_endpoint(request: Request) -> Response:
    rt = runtime()
    if request.method == "POST":
        try:
            await read_capped_body(request)
        except BodyTooLarge:
            return too_large()
        params: Any = await request.form()
    else:
        params = request.query_params
    response, notes = await provider_call(request, partial(rt.authorize_handler.handle, request))
    location = response.headers.get("location", "")
    consent = response.status_code == 302 and location.startswith(rt.provider.consent_url + "?")
    fields: dict[str, Any] = {"client_id": _clip(params.get("client_id")), "ip": client_ip(request),
                              "outcome": "consent" if consent else "refused"}
    if not consent and not notes.store_down:
        if location:
            answer = {k: (v or [""])[0] for k, v in parse_qs(urlsplit(location).query).items()}
        else:
            answer = _body_json(response)
        code = _clip(answer.get("error"), 40) or "invalid_request"
        fields["reason"] = code
        # Never back to the client from here: a registration is open to anyone, so a redirect URI is not a
        # host the person chose until they see it on the consent page. The client hears of a refusal only
        # through the person's Deny there.
        response = authorize_refusal(request, code, answer.get("error_description"))
    if not consent:
        fields["status"] = response.status_code
    audit_log(AuditEvent.MCP_AUTHORIZE_START, **fields)
    return response


_AUTHORIZE_STATUS = {"server_error": 500, "temporarily_unavailable": 503}


def authorize_refusal(request: Request, code: str, description: Any) -> Response:
    """A refused authorization request, answered by the gateway itself: a short HTML page for a browser
    (``Accept`` with ``text/html``), else ``{error, error_description}``. 400, or 503 / 500 for
    ``temporarily_unavailable`` / ``server_error``. Never a redirect."""
    from hermes_cli.dashboard_auth.mcp import consent

    status = _AUTHORIZE_STATUS.get(code, 400)
    detail = description if isinstance(description, str) and description.strip() else "The request is not valid."
    detail = detail[:300]
    headers = {"Retry-After": "60"} if status == 503 else {}
    if "text/html" in request.headers.get("accept", ""):
        return consent.refusal_page("This MCP client's sign-in request was refused",
                                    f"{detail} ({code}). Start the connection again from your MCP client.",
                                    status, headers)
    return error(status, code, detail, headers=headers)


async def report_reuse_revocations(request: Request, notes: CallNotes, store: MCPStore) -> None:
    """A code or refresh token presented again revoked a grant during this request: audit it
    (``mcp_grant_revoked`` with ``by`` ``code_reuse`` / ``refresh_reuse``) and tell the person
    (``mcp.changed {revoked}``), as a revoke from Settings › MCP does. The client only heard ``invalid_grant``."""
    for reuse in notes.revoked_by_reuse:
        grant = reuse.grant
        audit_log(AuditEvent.MCP_GRANT_REVOKED, by=reuse.by, grant_id=grant.id, user_id=grant.user_id,
                  client_id=grant.client_id, client_name=grant.client_name, ip=client_ip(request))
        await anyio.to_thread.run_sync(api_routes.announce, grant.user_id, "revoked", grant,
                                       grant.revoked_at or store.now())


def announce_granted(store: MCPStore, grant_id: str) -> None:
    """``mcp.changed {granted}`` to the person's live connections, so an open Settings › MCP page lists the new
    client. After the exchange committed; never fails or delays the token response."""
    try:
        grant = store.grant(grant_id)
    except StoreError:
        _log.warning("mcp.changed (granted): the grant could not be read", exc_info=False)
        return
    if grant is not None:
        api_routes.announce(grant.user_id, "granted", grant, grant.created_at)


async def token_endpoint(request: Request) -> Response:
    rt = runtime()
    if (refusal := limited(TOKEN_PER_IP, request, "token")) is not None:
        return refusal
    try:
        await read_capped_body(request)
    except BodyTooLarge:
        return too_large()
    form = await request.form()
    grant_type = _clip(form.get("grant_type"), 40)
    client_id = _clip(form.get("client_id"))
    ip = client_ip(request)
    resource = form.get("resource")
    if isinstance(resource, str) and not rt.provider.resource_matches(resource):
        audit_log(AuditEvent.MCP_TOKEN_REJECTED, client_id=client_id, grant_type=grant_type, ip=ip,
                  reason="invalid_target", status=400)
        return error(400, "invalid_target", "resource is not this gateway's MCP endpoint")
    response, notes = await provider_call(request, partial(rt.token_handler.handle, request))
    await report_reuse_revocations(request, notes, rt.store)
    if response.status_code == 200 and notes.grant_id:
        event = AuditEvent.MCP_TOKEN_REFRESHED if grant_type == "refresh_token" else AuditEvent.MCP_TOKEN_ISSUED
        audit_log(event, user_id=notes.user_id, grant_id=notes.grant_id, client_id=client_id, ip=ip)
        if event is AuditEvent.MCP_TOKEN_ISSUED:  # a grant exists from its code exchange, not from the consent
            await anyio.to_thread.run_sync(announce_granted, rt.store, notes.grant_id)
    elif notes.raced_grant and grant_type == "refresh_token":
        # A parallel refresh, or a thief and the real client within the window (plan D3 amendment): the grant
        # stays, so the refusal is named apart from an ordinary invalid_grant.
        audit_log(AuditEvent.MCP_TOKEN_REJECTED, user_id=notes.raced_user, grant_id=notes.raced_grant,
                  client_id=client_id, grant_type=grant_type, ip=ip, reason="refresh_raced",
                  status=response.status_code)
    else:
        audit_log(AuditEvent.MCP_TOKEN_REJECTED, client_id=client_id, grant_type=grant_type, ip=ip,
                  reason=_clip(_body_json(response).get("error"), 40), status=response.status_code)
    return response


async def register_endpoint(request: Request) -> Response:
    rt = runtime()
    if (refusal := limited(REGISTER_PER_IP, request, "register")) is not None:
        return refusal
    try:
        await read_capped_body(request)
    except BodyTooLarge:
        return error(413, "invalid_client_metadata", f"The body is larger than {BODY_CAP} bytes.")
    response, _ = await provider_call(request, partial(rt.register_handler.handle, request))
    data = _body_json(response)
    if response.status_code == 201:
        hosts = sorted({urlsplit(str(u)).netloc for u in data.get("redirect_uris") or ()})
        audit_log(AuditEvent.MCP_CLIENT_REGISTERED, client_id=_clip(data.get("client_id")),
                  client_name=_clip(data.get("client_name")), redirect_hosts=hosts,
                  auth_method=_clip(data.get("token_endpoint_auth_method"), 40), ip=client_ip(request),
                  outcome="registered")
    else:
        audit_log(AuditEvent.MCP_CLIENT_REGISTERED, ip=client_ip(request), outcome="refused",
                  reason=_clip(data.get("error"), 40), status=response.status_code)
    response.headers.update(_NO_STORE)
    return response


async def revoke_endpoint(request: Request) -> Response:
    """RFC 7009 with the SDK's semantics (an unknown token or another client's is a silent 200), except that a
    public client (``token_endpoint_auth_method: none``) sends no ``client_secret``."""
    rt = runtime()
    if (refusal := limited(REVOKE_PER_IP, request, "revoke")) is not None:
        return refusal
    try:
        await read_capped_body(request)
    except BodyTooLarge:
        return too_large()

    async def call() -> Response:
        try:
            client = await rt.client_authenticator.authenticate_request(request)
        except AuthenticationError as exc:
            return error(401, "unauthorized_client", exc.message)
        form = await request.form()
        token = form.get("token")
        hint = form.get("token_type_hint")
        if not isinstance(token, str) or not token or hint not in (None, "access_token", "refresh_token"):
            return error(400, "invalid_request", "token is required; token_type_hint is access_token or refresh_token")
        loaders = [rt.provider.load_access_token, partial(rt.provider.load_refresh_token, client)]
        if hint == "refresh_token":
            loaders.reverse()
        found = None
        for loader in loaders:
            found = await loader(token)
            if found is not None:
                break
        grant_id = getattr(found, "grant_id", "") if found is not None else ""
        if grant_id and found.client_id == client.client_id:
            # Live only, in one transaction: of two parallel revokes one reports (and announces) it.
            revoked = await rt.provider.revoke_grant(grant_id, by=BY_CLIENT, live_only=True)
            if revoked is not None:
                audit_log(AuditEvent.MCP_GRANT_REVOKED, grant_id=revoked.id, user_id=revoked.user_id,
                          client_id=client.client_id, client_name=revoked.client_name, by=BY_CLIENT,
                          ip=client_ip(request))
                await anyio.to_thread.run_sync(api_routes.announce, revoked.user_id, "revoked", revoked,
                                               revoked.revoked_at or rt.store.now())
        return Response(status_code=200, headers=_NO_STORE)

    response, notes = await provider_call(request, call)
    await report_reuse_revocations(request, notes, rt.store)
    return response


# ── the endpoint placeholder ────────────────────────────────────────────────────────────────────


async def _bridge_not_ready(scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse({"error": "bridge_not_ready",
                             "error_description": "The MCP server is not mounted on this gateway yet."},
                            status_code=503, headers={**_NO_STORE, "Retry-After": "60"})
    await response(scope, receive, send)


class StoreGuard:
    """Answers 503 ``temporarily_unavailable`` when the token check cannot read the store (instead of the
    500 an exception would give), with the client's address bound for the verifier."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        from hermes_cli.dashboard_auth.mcp.provider import request_bound

        request = Request(scope)
        started = False

        async def tracking_send(message: Any) -> None:
            nonlocal started
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        try:
            with request_bound(client_ip(request), request.headers.get("user-agent", "")):
                await self.app(scope, receive, tracking_send)
        except StoreError as exc:
            if started or isinstance(exc, _REFUSALS):
                raise
            _log.warning("MCP endpoint: the MCP store is unavailable")
            await unavailable()(scope, receive, send)


def endpoint_app(verifier: MCPTokenVerifier, resource_metadata_url: str, inner: ASGIApp = _bridge_not_ready) -> ASGIApp:
    """The ``/mcp`` stack: bearer authentication against the store, then the SDK's 401/403, then *inner*."""
    guarded = RequireAuthMiddleware(inner, required_scopes=[], resource_metadata_url=AnyHttpUrl(resource_metadata_url))
    return StoreGuard(AuthenticationMiddleware(guarded, backend=BearerAuthBackend(verifier)))


# ── assembly ────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Runtime(mount.MCPRuntime):
    authorize_handler: Any = None
    token_handler: Any = None
    register_handler: Any = None
    client_authenticator: Any = None
    as_metadata: dict = field(default_factory=dict)
    resource_metadata: dict = field(default_factory=dict)
    session_manager: Any = None  # the MCP server's StreamableHTTPSessionManager; run by mount.lifespan


def build_runtime(*, settings: MCPSettings, issuer_url: str, primary: Any, store: Optional[MCPStore] = None) -> Runtime:
    """The authorization server for *issuer_url* (also the resource), on *store* (the default file)."""
    from hermes_cli.dashboard_auth.mcp import consent

    validate_issuer_url(AnyHttpUrl(issuer_url))  # ValueError: not https (or loopback), or a query/fragment
    store = store if store is not None else MCPStore.default()
    origin = primary.serialize()
    as_metadata = authorization_server_metadata(issuer_url)
    provider = RouteProvider(store, resource_url=issuer_url, settings=settings,
                             consent_url=f"{origin}{mount.CONSENT_PATH}", issuer=as_metadata["issuer"])
    verifier = MCPTokenVerifier(provider)
    authenticator = MCPClientAuthenticator(provider)
    resource_metadata_url = f"{origin}{mount.RESOURCE_METADATA_PATH}"
    resource_metadata = protected_resource_metadata(issuer_url)
    as_endpoint = cors_middleware(_metadata_endpoint(as_metadata), ["GET", "OPTIONS"])
    mcp_app, session_manager = _mcp_server(store=store, settings=settings, issuer_url=issuer_url, origin=origin,
                                           host=primary.host)
    routes = [
        *(Route(path, endpoint=as_endpoint, methods=["GET", "OPTIONS"]) for path in mount.AS_METADATA_PATHS),
        Route(mount.RESOURCE_METADATA_PATH, methods=["GET", "OPTIONS"],
              endpoint=cors_middleware(_metadata_endpoint(resource_metadata), ["GET", "OPTIONS"])),
        Route("/mcp/authorize", endpoint=authorize_endpoint, methods=["GET", "POST"]),
        Route(mount.CONSENT_PATH, endpoint=consent.consent_endpoint, methods=["GET", "POST"]),
        Route("/mcp/token", endpoint=cors_middleware(token_endpoint, ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]),
        Route("/mcp/register", endpoint=cors_middleware(register_endpoint, ["POST", "OPTIONS"]),
              methods=["POST", "OPTIONS"]),
        Route("/mcp/revoke", endpoint=cors_middleware(revoke_endpoint, ["POST", "OPTIONS"]),
              methods=["POST", "OPTIONS"]),
        Route(mount.ENDPOINT_PATH, endpoint=endpoint_app(verifier, resource_metadata_url, inner=mcp_app),
              methods=["POST"]),
    ]
    return Runtime(
        settings=settings, store=store, provider=provider, verifier=verifier, issuer_url=issuer_url,
        primary_host=primary.host, primary_origin=origin, app=Router(routes=routes),
        authorize_handler=AuthorizationHandler(provider), token_handler=TokenHandler(provider, authenticator),
        register_handler=RegistrationHandler(provider, options=ClientRegistrationOptions(
            enabled=True, valid_scopes=list(SCOPES), default_scopes=list(SCOPES))),
        client_authenticator=authenticator, as_metadata=as_metadata, resource_metadata=resource_metadata,
        session_manager=session_manager)


def _audit_event(event: str, **fields: Any) -> None:
    audit_log(AuditEvent(event), **fields)


def _mcp_server(*, store: MCPStore, settings: MCPSettings, issuer_url: str, origin: str,
                host: str = "") -> tuple[ASGIApp, Any]:
    """The MCP server's ASGI app and its session manager (``tui_gateway.mcp_bridge.server``). Its ``whoami``
    names the gateway by the same label as ``GET /api/auth/mcp`` (:func:`settings.server_label`)."""
    from tui_gateway.mcp_bridge.server import build_endpoint
    from tui_gateway.mcp_bridge.tools import Bridge

    bridge = Bridge(store=store, settings=settings, endpoint_url=issuer_url, label=server_label(settings, host),
                    audit=_audit_event)
    return build_endpoint(bridge, primary_origin=origin)
