"""The passkey routes: enrolment, step-up and management for the confirm level ``passkey``.

    GET  /api/auth/passkeys                   the caller's passkey state and credentials
    POST /api/auth/passkeys/reauth/begin      open a re-authentication grant for self-enrolment (600 s)
    POST /api/auth/passkeys/register/begin    open a registration (300 s)
    POST /api/auth/passkeys/register/finish   enrol a credential: attestation + a one-time enrolment code
                                              or a fresh re-authentication grant
    POST /api/auth/passkeys/stepup/begin      open a step-up for ``invite`` or ``revoke`` (120 s, single use)
    POST /api/auth/passkeys/invites           mint an enrolment code for oneself, with an ``invite`` step-up
    POST /api/auth/passkeys/revoke            revoke one of one's own credentials, with a ``revoke`` step-up

Rules every route keeps:

- While ``confirm.passkey.enabled`` is false every route answers what an unknown ``/api`` path gets on a
  gateway without them: 404 ``No such API endpoint`` for GET, 405 for a POST.
- None is public: the dashboard's auth gate runs first. The identity is the gate's verified session
  (``request.state.session``) and nothing in a body; without one (session-token or loopback mode) the
  answer is 403 ``no_identity``. A caller only ever sees, adds to or revokes their own credentials.
- A cookie-authenticated write must carry an ``Origin`` that is the origin of one of the level's own
  accepted base URLs (``confirm.passkey.base_urls``, never the dashboard's public URLs), whatever
  ``dashboard.write_origin_check`` says. A bearer caller (the native app) is exempt: a browser never
  attaches a bearer on its own.
- Bodies are JSON objects of at most 16 KiB.
- Every enrolment-code failure is one answer, 403 ``code_invalid``; every grant that cannot authorise an
  enrolment is 403 ``reauth_invalid`` with the store's reason (``unknown`` for none, another user's,
  another client kind's or an expired one).
- Nothing from a body (code, assertion, attestation) and no token reaches a log; the audit log gets the
  user, the address, how the caller authenticated, the RP, the base URL, the ceremony id, the first 16
  characters of a credential id and a reason.

The store is the source of truth for single use and ownership (see ``store.py``); these routes add the
ceremony checks of ``contract/confirm-passkey/README.md`` §9 and §11, the rate limits, the audit lines and
the announcements (``passkey.changed`` to the user's live connections, the ``on_passkey_change`` hook).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import Session
from hermes_cli.dashboard_auth.passkeys.challenge import (
    GatewayContext, b64u, b64u_decode, host_of, is_private, origin_of, user_handle)
from hermes_cli.dashboard_auth.passkeys.settings import PasskeySettings, gateway_context, load_settings
from hermes_cli.dashboard_auth.passkeys.store import (
    CodeInvalid, CommitRefused, CredentialExists, CredentialRecord, Grant, GrantInvalid, PasskeyStore,
    PendingInvalid, StoreError, default_path)
from hermes_cli.dashboard_auth.passkeys.webauthn import (
    ALG_ES256, AssertionOk, AssertionRequest, RegistrationOk, verify_assertion, verify_registration)
from hermes_cli.dashboard_auth.rate_limit import SlidingWindowLimiter, Verdict
from hermes_cli.dashboard_auth.request_utils import client_ip, extract_bearer

_log = logging.getLogger(__name__)

PREFIX = "/api/auth/passkeys"
BODY_CAP = 16 * 1024
NAME_MAX = 100
ID_MAX = 64  # registration and step-up ids are 22 characters; anything far longer is not one
PRUNE_EVERY_S = 3600.0

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store"}

# Rate limits (plan, Security Considerations). Process-local, like every dashboard throttle.
REGISTER_BEGIN_PER_USER = SlidingWindowLimiter(5, 600)
REGISTER_BEGIN_PER_IP = SlidingWindowLimiter(5, 600)
CODE_FAILURES_PER_USER = SlidingWindowLimiter(5, 600)
CODE_FAILURES_PER_IP = SlidingWindowLimiter(5, 600)
CODE_FAILURES_GATEWAY = SlidingWindowLimiter(20, 3600)
STEPUP_BEGIN_PER_USER = SlidingWindowLimiter(10, 600)
REAUTH_BEGIN_PER_USER = SlidingWindowLimiter(5, 600)
REAUTH_BEGIN_PER_IP = SlidingWindowLimiter(5, 600)
_GATEWAY_KEY = "gateway"
# Code redemption is check → redeem → record-on-failure; without one lock around the three, a burst of
# parallel attempts all pass the check before any failure is counted. Only this process redeems codes
# (the operator CLI mints and revokes, it never redeems), so a process lock is enough.
_REDEEM_LOCK = threading.Lock()
_REGISTER_BEGIN_LOCK = threading.Lock()
LIMITERS = (REGISTER_BEGIN_PER_USER, REGISTER_BEGIN_PER_IP, CODE_FAILURES_PER_USER, CODE_FAILURES_PER_IP,
            CODE_FAILURES_GATEWAY, STEPUP_BEGIN_PER_USER, REAUTH_BEGIN_PER_USER, REAUTH_BEGIN_PER_IP)

#: The kwargs ``on_passkey_change`` is fired with (kept in step with ``VALID_HOOKS`` and hooks.md by a test).
HOOK_KWARGS = ("change", "user_id", "credential", "at", "via")


class _Fail(Exception):
    """An answer other than 200: status, ``error`` code, optional ``reason``, human ``detail``."""

    def __init__(self, status: int, error: str, detail: str, *, reason: str = "", failure: str = "",
                 retry_after: int = 0):
        super().__init__(error)
        self.status, self.error, self.detail, self.reason, self.retry_after = status, error, detail, reason, retry_after
        self.failure = failure

    def response(self) -> JSONResponse:
        body: dict[str, Any] = {"error": self.error, "detail": self.detail}
        if self.reason:
            body["reason"] = self.reason
        if self.failure:
            body["failure"] = self.failure
        headers = dict(_NO_STORE)
        if self.retry_after:
            headers["Retry-After"] = str(self.retry_after)
        return JSONResponse(body, status_code=self.status, headers=headers)


def _not_found(request: Request) -> JSONResponse:
    """What a gateway without these routes answers for the same request, so one with the level off is
    indistinguishable from it: the SPA catch-all (``web_server_dashboard.serve_spa``, GET only) gives an
    unknown ``/api`` path a 404 with this body, and any other method on such a path is Starlette's 405."""
    if request.method == "GET":
        return JSONResponse({"detail": f"No such API endpoint: {request.url.path}"}, status_code=404)
    return JSONResponse({"detail": "Method Not Allowed"}, status_code=405, headers={"Allow": "GET"})


# ── settings, store, context ─────────────────────────────────────────────────────────────────────

_stores: dict[str, PasskeyStore] = {}
_stores_lock = threading.Lock()
_prune_lock = threading.Lock()
_last_prune: dict[str, float] = {}


def _settings() -> PasskeySettings:
    return load_settings()


def _store() -> PasskeyStore:
    """One store object per file, so its identity is read once (the file follows ``$HERMES_HOME``)."""
    path = default_path()
    with _stores_lock:
        store = _stores.get(str(path))
        if store is None:
            store = _stores[str(path)] = PasskeyStore(path)
        return store


def _maybe_prune(store: PasskeyStore, settings: PasskeySettings) -> None:
    """Receipts, old codes and closed ceremonies age out here, at most once an hour per store."""
    now = time.monotonic()
    with _prune_lock:
        last = _last_prune.get(str(store.path))
        if last is not None and now - last < PRUNE_EVERY_S:
            return
        _last_prune[str(store.path)] = now
    try:
        store.prune(receipts_days=settings.receipts_days)
    except StoreError:
        _log.warning("passkey store: pruning failed", exc_info=False)


def _accepted_origins(settings: PasskeySettings) -> frozenset[str]:
    """The browser origins of the level's own accepted base URLs (README §10), for the CSRF check."""
    return frozenset(origin_of(u) for u in settings.base_urls if settings.allow_private_base_urls or not is_private(u))


@dataclass(frozen=True)
class _Call:
    request: Request
    settings: PasskeySettings
    store: PasskeyStore
    ctx: GatewayContext
    user_id: str  # "<provider>:<user id>"
    display_name: str
    ip: str
    auth: str  # "bearer" | "cookie"
    provider: str = ""  # the sign-in provider of the gate's session

    @property
    def client(self) -> str:
        """The grant client kind of this caller: a cookie caller is the web client, a bearer one the app."""
        return "web" if self.auth == "cookie" else "native"

    def audit(self, event: AuditEvent, **fields: Any) -> None:
        audit_log(event, user_id=self.user_id, ip=self.ip, auth=self.auth, **fields)


def _identity(request: Request) -> tuple[str, str, str]:
    """``(<provider>:<user id>, display name, provider)`` of the gate's session, or empty strings."""
    from hermes_cli.dashboard_auth.ws_tickets import INTERNAL_PROVIDER, INTERNAL_USER_ID

    session = getattr(request.state, "session", None)
    if not isinstance(session, Session):
        return "", "", ""
    provider, user = str(session.provider or "").strip(), str(session.user_id or "").strip()
    if not provider or not user or (provider, user) == (INTERNAL_PROVIDER, INTERNAL_USER_ID):
        return "", "", ""
    return f"{provider}:{user}", str(session.display_name or "").strip(), provider


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


@dataclass(frozen=True)
class _WithCookies:
    """A handler's answer that also sets cookies: *apply* gets the response before it is sent."""
    body: dict
    apply: Callable[[Response], None]


async def _run(request: Request, handler: Callable[[_Call, dict], Any], *, write: bool) -> JSONResponse:
    """The shared front of every route: 404 while disabled, identity, CSRF origin, body; then *handler* in
    a worker thread (the store is SQLite, the hook and the broadcast are synchronous)."""
    try:
        settings = await run_in_threadpool(_settings)
    except Exception:  # noqa: BLE001 - an unreadable config never enables the level
        _log.warning("passkey routes: confirm.passkey could not be read", exc_info=False)
        return _not_found(request)
    if not settings.enabled:
        return _not_found(request)
    try:
        user_id, display_name, provider = _identity(request)
        if not user_id:
            raise _Fail(403, "no_identity", "Passkeys belong to a signed-in user; this connection has none.")
        auth = "bearer" if extract_bearer(request) else "cookie"
        if write and auth == "cookie" and request.headers.get("origin", "") not in _accepted_origins(settings):
            path = request.url.path
            audit_log(AuditEvent.PASSKEY_REGISTER_REFUSED if path.startswith(f"{PREFIX}/register")
                      else AuditEvent.PASSKEY_REAUTH_REFUSED if path.startswith(f"{PREFIX}/reauth")
                      else AuditEvent.PASSKEY_STEPUP_REFUSED, user_id=user_id, ip=client_ip(request), auth=auth,
                      path=request.url.path, reason="origin_not_listed")
            raise _Fail(403, "origin_not_listed",
                        "A browser write needs an Origin that is one of this gateway's passkey base URLs.")
        body = await _read_body(request) if write else {}

        def work() -> dict:
            store = _store()
            ctx = gateway_context(store.identity(), settings)
            _maybe_prune(store, settings)
            call = _Call(request=request, settings=settings, store=store, ctx=ctx, user_id=user_id,
                         display_name=display_name, ip=client_ip(request), auth=auth, provider=provider)
            return handler(call, body)

        result = await run_in_threadpool(work)
    except _Fail as fail:
        return fail.response()
    except StoreError:
        _log.warning("passkey routes: the passkey store is unavailable", exc_info=False)
        return _Fail(503, "unavailable", "The passkey store is unavailable.").response()
    if isinstance(result, _WithCookies):
        response = JSONResponse(result.body, headers=_NO_STORE)
        result.apply(response)
        return response
    return JSONResponse(result, headers=_NO_STORE)


# ── body fields ──────────────────────────────────────────────────────────────────────────────────


def _string(body: dict, key: str, *, low: int = 1, high: int = 512) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not low <= len(value) <= high:
        raise _Fail(400, "bad_request", f"{key} must be a string of {low} to {high} characters.")
    return value


def _credential_name(body: dict) -> str:
    name = _string(body, "name", high=NAME_MAX * 4).strip()
    if not 1 <= len(name) <= NAME_MAX or any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in name):
        raise _Fail(400, "bad_request", f"name must be 1 to {NAME_MAX} printable characters.")
    return name


def _rp_and_base_url(ctx: GatewayContext, rp_id: str, base_url: str) -> str:
    """README §9 steps 3–5 for a ceremony being opened: ``native`` or ``web``."""
    if rp_id in ctx.native_rp_ids:
        kind = "native"
    elif rp_id in ctx.web_rp_ids:
        kind = "web"
    else:
        raise _Fail(400, "bad_request", "This RP is not accepted here.", reason="rp_not_accepted")
    if base_url not in ctx.accepted_base_urls:
        raise _Fail(400, "bad_request", "This base URL is not one of this gateway's passkey base URLs.",
                    reason="base_url_not_accepted")
    if kind == "web" and host_of(base_url) != rp_id:
        raise _Fail(400, "bad_request", "A browser RP must be the host of the base URL.", reason="rp_host_mismatch")
    return kind


# ── views and announcements ──────────────────────────────────────────────────────────────────────


def _credential_view(c: CredentialRecord, now: int) -> dict:
    """A credential as a client sees it; ``usable_from`` only while it is in its cooling-off period."""
    view = {"id": c.id_b64u, "name": c.name, "rp_id": c.rp_id, "aaguid": str(uuid.UUID(bytes=c.aaguid)),
            "created_at": c.created_at, "last_used_at": c.last_used_at, "backup_eligible": c.backup_eligible,
            "backed_up": c.backed_up, "created_via": c.created_via, "transports": list(c.transports)}
    if c.usable_from is not None and c.usable_from > now:
        view["usable_from"] = c.usable_from
    return view


def _credentials_by_rp(records: list[CredentialRecord]) -> list[dict]:
    by_rp: dict[str, list[str]] = {}
    for c in records:
        by_rp.setdefault(c.rp_id, []).append(c.id_b64u)
    return [{"rp_id": rp, "ids": ids} for rp, ids in sorted(by_rp.items())]


def _announce(call: _Call, change: str, credential: CredentialRecord, *, via: str) -> None:
    """``passkey.changed`` to the user's live connections and the ``on_passkey_change`` hook. Runs after the
    store committed; a failure here is logged and never undoes or fails the change."""
    ref = {"id": credential.id_b64u, "name": credential.name, "rp_id": credential.rp_id}
    at = call.store.now()
    try:
        from tui_gateway.user_events import announce_passkey_changed
        announce_passkey_changed(call.user_id, {"change": change, "credential": ref, "at": at})
    except Exception:  # noqa: BLE001 - no gateway in this process, or a contract drift: never fail the change
        _log.warning("passkey.changed could not be announced", exc_info=False)
    try:
        from hermes_cli.plugins import invoke_hook
        invoke_hook("on_passkey_change", change=change, user_id=call.user_id, credential=dict(ref), at=at, via=via)
    except Exception:  # noqa: BLE001 - a plugin must not fail the change
        _log.warning("on_passkey_change hook failed", exc_info=False)


# ── GET /api/auth/passkeys ───────────────────────────────────────────────────────────────────────


def _self_enrol_reason(call: _Call) -> str:
    """Why this caller cannot add a passkey by signing in again ("" when they can): ``disabled`` (the
    operator switched it off) or ``provider_no_reauth`` (their sign-in provider, as registered in this
    process, cannot force a fresh sign-in, e.g. Nous)."""
    from hermes_cli.dashboard_auth import get_provider
    from hermes_cli.dashboard_auth.passkeys.reauth import provider_reauth_reason

    if not call.settings.self_enrol.enabled:
        return "disabled"
    try:
        registered = get_provider(call.provider) if call.provider else None
    except Exception:  # noqa: BLE001 - a registry problem never enables self-enrolment
        registered = None
    return provider_reauth_reason(registered)


def _status(call: _Call, _body: dict) -> dict:
    ctx = call.ctx
    gateway_id, handle_key = call.store.identity()
    reason = ctx.capability_reason(enabled=True, identity=True)  # contract §8: enabled exactly when reason is ""
    self_reason = _self_enrol_reason(call)
    now = call.store.now()
    return {"v": 1, "enabled": reason == "", "reason": reason,
            "gateway_id": b64u(gateway_id),
            "user": {"id": call.user_id, "handle": b64u(user_handle(handle_key, call.user_id))},
            "rp": {"native": sorted(ctx.native_rp_ids), "web": sorted(ctx.web_rp_ids)},
            "base_urls": list(ctx.accepted_base_urls), "user_invites": call.settings.user_invites,
            "self_enrol": {"available": self_reason == "", "reason": self_reason,
                           "cooling_off_s": call.settings.self_enrol.cooling_off_s},
            "credentials": [_credential_view(c, now) for c in call.store.credentials(call.user_id)]}


@router.get(PREFIX, name="passkeys_status")
async def passkeys_status(request: Request):
    return await _run(request, _status, write=False)


# ── self-enrolment: the re-authentication grant ──────────────────────────────────────────────────


def _refuse_self_enrol(call: _Call, event: AuditEvent, **fields: Any) -> None:
    reason = _self_enrol_reason(call)
    if not reason:
        return
    call.audit(event, provider=call.provider, client=call.client, reason=reason, **fields)
    if reason == "disabled":
        raise _Fail(403, "self_enrol_disabled", "This gateway's operator has switched off adding a passkey by "
                                                "signing in again; use an enrolment code.")
    raise _Fail(403, "provider_no_reauth", "Your sign-in provider cannot ask you to sign in again; use an "
                                           "enrolment code.")


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})


def _browser_on_https(request: Request) -> bool:
    """Whether the browser behind a cookie call is on https (or a loopback dev host, which browsers treat as
    a secure context), so that it keeps a ``__Host-`` cookie. The Origin is the browser's own view, whatever
    the scheme a TLS-terminating proxy hands the gateway; the request scheme counts as evidence too."""
    from urllib.parse import urlsplit

    from hermes_cli.dashboard_auth.cookies import detect_https

    origin = request.headers.get("origin", "")
    try:
        parts = urlsplit(origin)
        host = (parts.hostname or "").lower()
    except ValueError:
        parts, host = None, ""
    if parts is not None and parts.scheme == "https":
        return True
    if parts is not None and parts.scheme == "http" and (host in _LOOPBACK_HOSTS or host.endswith(".localhost")):
        return True
    return detect_https(request) and not origin.startswith("http://")


def _reauth_begin(call: _Call, _body: dict) -> _WithCookies:
    _refuse_self_enrol(call, AuditEvent.PASSKEY_REAUTH_REFUSED)
    if call.client == "web" and not _browser_on_https(call.request):
        # The binding cookie is always ``__Host-`` (Secure): a browser on plain http would drop it, and any
        # weaker cookie could be tossed in by a sibling host. Codes still work.
        call.audit(AuditEvent.PASSKEY_REAUTH_REFUSED, provider=call.provider, client=call.client,
                   reason="insecure_binding")
        raise _Fail(403, "insecure_binding", "Adding a passkey by signing in again needs this page on https; "
                                             "use an enrolment code.")
    with _REGISTER_BEGIN_LOCK:  # ask both, then record both: one refusal never spends the other budget
        allowed = not (REAUTH_BEGIN_PER_USER.exhausted(call.user_id) or REAUTH_BEGIN_PER_IP.exhausted(call.ip))
        allowed = allowed and REAUTH_BEGIN_PER_USER.check(call.user_id) is Verdict.ALLOWED
        allowed = allowed and REAUTH_BEGIN_PER_IP.check(call.ip) is Verdict.ALLOWED
    if not allowed:
        call.audit(AuditEvent.PASSKEY_REAUTH_REFUSED, provider=call.provider, client=call.client,
                   reason="rate_limited")
        raise _Fail(429, "rate_limited", "Too many attempts to add a passkey; try again later.", retry_after=600)
    from hermes_cli.dashboard_auth.passkeys import reauth

    opened = reauth.open_grant(store=call.store, user_id=call.user_id, provider=call.provider, client=call.client,
                               ip=call.ip, auth=call.auth)
    grant, secret = opened.grant, opened.secret
    answer: dict[str, Any] = {"grant_id": grant.id, "expires_at": grant.expires_at, "provider": call.provider}
    if secret is None:
        return _WithCookies(answer, lambda _response: None)
    from urllib.parse import urlencode

    from hermes_cli.dashboard_auth.cookies import set_reauth_cookie
    from hermes_cli.dashboard_auth.prefix import prefix_from_request

    prefix = prefix_from_request(call.request)
    answer["login_path"] = f"{prefix}/auth/login?" + urlencode({"provider": call.provider, "reauth": grant.id})
    return _WithCookies(answer, lambda response: set_reauth_cookie(response, secret=secret))


@router.post(f"{PREFIX}/reauth/begin", name="passkeys_reauth_begin")
async def passkeys_reauth_begin(request: Request):
    return await _run(request, _reauth_begin, write=True)


def _grant_id(body: dict) -> str:
    return _string(body, "grant_id", high=ID_MAX)


def _reauth_invalid(call: _Call, exc: GrantInvalid, grant_id: str, **fields: Any) -> _Fail:
    call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, grant=grant_id[:8], reason="reauth_invalid",
               grant_reason=exc.reason, failure=exc.failure, **fields)
    return _Fail(403, "reauth_invalid", "This sign-in cannot add a passkey; sign in again.", reason=exc.reason,
                 failure=exc.failure)


def _grant_secret(call: _Call, body: dict) -> Optional[str]:
    """The grant's use binding as this caller presents it: the browser's ``__Host-hermes_reauth`` cookie for a
    cookie caller, the ``use_secret`` the token route gave the app for a bearer caller (body field)."""
    if call.client == "web":
        from hermes_cli.dashboard_auth.cookies import read_reauth_cookie
        return read_reauth_cookie(call.request)
    value = body.get("use_secret")
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= ID_MAX:
        raise _Fail(400, "bad_request", f"use_secret must be a string of 1 to {ID_MAX} characters.")
    return value


def _usable_grant(call: _Call, grant_id: str, secret: Optional[str]) -> Grant:
    """The caller's fresh grant, opened by this kind of client and presented with its use binding, or
    :class:`GrantInvalid`. A grant opened by the other kind of client, or without its binding, is ``unknown``:
    the same answer as another user's."""
    grant = call.store.fresh_grant(grant_id, user_id=call.user_id, secret=secret)
    if grant.client != call.client:
        raise GrantInvalid("unknown")
    return grant


# ── registration ─────────────────────────────────────────────────────────────────────────────────


def _register_begin(call: _Call, body: dict) -> dict:
    rp_id = _string(body, "rp_id", high=253)
    base_url = _string(body, "base_url")
    name = _credential_name(body)
    _rp_and_base_url(call.ctx, rp_id, base_url)
    grant: Optional[Grant] = None
    if body.get("grant_id") is not None:
        grant_id = _grant_id(body)
        _refuse_self_enrol(call, AuditEvent.PASSKEY_REGISTER_REFUSED, grant=grant_id[:8])
        try:
            grant = _usable_grant(call, grant_id, _grant_secret(call, body))
        except GrantInvalid as exc:
            raise _reauth_invalid(call, exc, grant_id, rp_id=rp_id, base_url=base_url) from None
    with _REGISTER_BEGIN_LOCK:  # ask both, then record both: one refusal never spends the other budget
        allowed = not (REGISTER_BEGIN_PER_USER.exhausted(call.user_id) or REGISTER_BEGIN_PER_IP.exhausted(call.ip))
        allowed = allowed and REGISTER_BEGIN_PER_USER.check(call.user_id) is Verdict.ALLOWED
        allowed = allowed and REGISTER_BEGIN_PER_IP.check(call.ip) is Verdict.ALLOWED
    if not allowed:
        call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, rp_id=rp_id, base_url=base_url, reason="rate_limited")
        raise _Fail(429, "rate_limited", "Too many registrations; try again later.", retry_after=600)
    pending = call.store.open_pending("register", user_id=call.user_id, rp_id=rp_id, base_url=base_url,
                                      subject=name)
    gateway_id, handle_key = call.store.identity()
    exclude = [{"type": "public-key", "id": c.id_b64u, "transports": list(c.transports)}
               for c in call.store.credentials(call.user_id) if c.rp_id == rp_id]
    answer = {"registration_id": pending.id, "nonce": b64u(pending.nonce), "expires_at": pending.expires_at,
              "gateway_id": b64u(gateway_id), "base_url": base_url, "rp": {"id": rp_id, "name": rp_id},
              "user": {"id": call.user_id, "handle": b64u(user_handle(handle_key, call.user_id)), "name": name,
                       "display_name": name},
              "exclude_credentials": exclude, "pub_key_cred_params": [{"type": "public-key", "alg": ALG_ES256}],
              "user_verification": "required", "attestation": "none"}
    if grant is not None:
        answer["grant"] = {"expires_at": grant.expires_at}
    return answer


@router.post(f"{PREFIX}/register/begin", name="passkeys_register_begin")
async def passkeys_register_begin(request: Request):
    return await _run(request, _register_begin, write=True)


def _refuse_if_code_failures_exhausted(call: _Call, registration_id: str) -> None:
    if CODE_FAILURES_GATEWAY.exhausted(_GATEWAY_KEY):
        wait = int(CODE_FAILURES_GATEWAY.window_sec)
    elif CODE_FAILURES_PER_USER.exhausted(call.user_id) or CODE_FAILURES_PER_IP.exhausted(call.ip):
        wait = int(CODE_FAILURES_PER_USER.window_sec)
    else:
        return
    call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id, reason="rate_limited")
    raise _Fail(429, "rate_limited", "Too many failed enrolment codes; try again later.", retry_after=wait)


def _record_code_failure(call: _Call) -> None:
    CODE_FAILURES_PER_USER.check(call.user_id)
    CODE_FAILURES_PER_IP.check(call.ip)
    if CODE_FAILURES_GATEWAY.check(_GATEWAY_KEY) is Verdict.ALLOWED and CODE_FAILURES_GATEWAY.exhausted(_GATEWAY_KEY):
        # The failure that used up the gateway-wide budget: redemptions are refused for the rest of the hour.
        _log.warning("passkey enrolment: %d failed code redemptions within an hour; refusing redemptions "
                     "until the window passes", CODE_FAILURES_GATEWAY.max_events)
        call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, reason="gateway_rate_limited")


def _register_finish(call: _Call, body: dict) -> Any:
    registration_id = _string(body, "registration_id", high=ID_MAX)
    code, grant_id = body.get("code"), body.get("grant_id")
    if (code is None) == (grant_id is None):
        raise _Fail(400, "bad_request", "Give exactly one of code (an enrolment code) or grant_id (a sign-in "
                                        "made again to add this passkey).")
    if code is not None and not isinstance(code, str):
        raise _Fail(400, "bad_request", "code must be a string (the enrolment code).")
    grant_secret: Optional[str] = None
    if grant_id is not None:
        grant_id = _grant_id(body)
        _refuse_self_enrol(call, AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id,
                           grant=grant_id[:8])
        grant_secret = _grant_secret(call, body)
    _refuse_if_code_failures_exhausted(call, registration_id)
    pending = call.store.pending(registration_id, kind="register", user_id=call.user_id)
    if pending is None:
        call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id, reason="expired")
        raise _Fail(410, "expired", "The registration is unknown, used or expired; start again.")
    verdict = verify_registration(call.ctx, pending.registration(), body)
    if not isinstance(verdict, RegistrationOk):
        call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id, rp_id=pending.rp_id,
                   base_url=pending.base_url, reason=verdict.reason)
        raise _Fail(422, "attestation_invalid", "The new passkey could not be verified.", reason=verdict.reason)
    with _REDEEM_LOCK:
        # Checked again under the lock: the check above only spares the attestation work of a caller who is
        # already refused; this one is what holds against a parallel burst.
        _refuse_if_code_failures_exhausted(call, registration_id)
        usable_from = None
        try:
            if grant_id is not None:
                # The client kind; the store checks the rest (the binding included) again as it spends it.
                _usable_grant(call, grant_id, grant_secret)
                cooling = call.settings.self_enrol.cooling_off_s
                usable_from = call.store.now() + cooling if cooling > 0 else None
            record = call.store.add_credential(user_id=call.user_id, registration=verdict, code=code,
                                               grant_id=grant_id, grant_secret=grant_secret,
                                               usable_from=usable_from, created_ip=call.ip)
        except PendingInvalid:
            call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id, reason="expired")
            raise _Fail(410, "expired", "The registration is unknown, used or expired; start again.") from None
        except GrantInvalid as exc:
            # Counted like a wrong code: the same limiters bound how often anyone may try an authority.
            _record_code_failure(call)
            raise _reauth_invalid(call, exc, str(grant_id), request_id=registration_id, rp_id=pending.rp_id,
                                  base_url=pending.base_url) from None
        except CodeInvalid:
            _record_code_failure(call)
            call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id, rp_id=pending.rp_id,
                       base_url=pending.base_url, reason="code_invalid")
            raise _Fail(403, "code_invalid", "The enrolment code is not valid.") from None
        except CredentialExists:
            # Counted like a wrong code: the store checks the code before the id, so a caller holding one valid
            # code could otherwise probe which credential ids exist for as long as the registration lives.
            _record_code_failure(call)
            call.audit(AuditEvent.PASSKEY_REGISTER_REFUSED, request_id=registration_id, rp_id=pending.rp_id,
                       credential=b64u(verdict.credential_id)[:16], reason="credential_exists")
            raise _Fail(409, "credential_exists", "This passkey is already registered.") from None
    extra: dict[str, Any] = {"grant": str(grant_id)[:8], "usable_from": record.usable_from} \
        if grant_id is not None else {}
    call.audit(AuditEvent.PASSKEY_REGISTERED, request_id=registration_id, rp_id=record.rp_id,
               base_url=pending.base_url, credential=record.id_b64u[:16], created_via=record.created_via, **extra)
    _announce(call, "added", record, via=record.created_via)
    answer = {"ok": True, "credential": _credential_view(record, call.store.now())}
    if grant_id is not None and call.client == "web":
        from hermes_cli.dashboard_auth.cookies import clear_reauth_cookie
        return _WithCookies(answer, clear_reauth_cookie)  # the grant is spent: its binding is done
    return answer


@router.post(f"{PREFIX}/register/finish", name="passkeys_register_finish")
async def passkeys_register_finish(request: Request):
    return await _run(request, _register_finish, write=True)


# ── step-ups ─────────────────────────────────────────────────────────────────────────────────────


def _stepup_begin(call: _Call, body: dict) -> dict:
    purpose = body.get("purpose")
    if purpose not in ("invite", "revoke"):
        raise _Fail(400, "bad_request", 'purpose must be "invite" or "revoke".')
    # The signers: credentials that may sign now. One in its cooling-off period cannot (it would mint a code
    # for an immediately usable second passkey), but it can be the subject of a revoke.
    signers = call.store.credentials(call.user_id, usable_only=True)
    if not signers:
        raise _Fail(400, "bad_request", "You have no passkey on this gateway.", reason="not_enrolled")
    if purpose == "invite":
        if not call.settings.user_invites:
            call.audit(AuditEvent.PASSKEY_INVITE_REFUSED, reason="user_invites_disabled")
            raise _Fail(403, "invites_disabled", "This gateway's operator mints every enrolment code.")
        if body.get("subject", "invite") != "invite":
            raise _Fail(400, "bad_request", 'The subject of an invite step-up is "invite".')
        subject = "invite"
    else:
        subject = _string(body, "subject", high=1400)  # base64url of up to 1,023 bytes
        # Only the caller's own active credentials; another user's id gets the same answer as an unknown one.
        if not any(c.id_b64u == subject for c in call.store.credentials(call.user_id)):
            raise _Fail(400, "bad_request", "subject is not one of your passkeys.", reason="unknown_credential")
    if STEPUP_BEGIN_PER_USER.check(call.user_id) is not Verdict.ALLOWED:
        call.audit(AuditEvent.PASSKEY_STEPUP_REFUSED, purpose=purpose, reason="rate_limited")
        raise _Fail(429, "rate_limited", "Too many step-ups; try again later.", retry_after=600)
    pending = call.store.open_pending(purpose, user_id=call.user_id, subject=subject)
    return {"stepup_id": pending.id, "purpose": purpose, "subject": subject, "nonce": b64u(pending.nonce),
            "expires_at": pending.expires_at, "credentials": _credentials_by_rp(signers)}


@router.post(f"{PREFIX}/stepup/begin", name="passkeys_stepup_begin")
async def passkeys_stepup_begin(request: Request):
    return await _run(request, _stepup_begin, write=True)


def _spend(call: _Call, stepup_id: str, purpose: str) -> None:
    try:
        call.store.take_pending(stepup_id, kind=purpose, user_id=call.user_id)
    except PendingInvalid:
        pass  # already taken or expired


def _stepup(call: _Call, body: dict, purpose: str, *, subject: Optional[str] = None) -> tuple[AssertionOk, bool]:
    """Verify and commit a step-up assertion (README §5 for ``invite`` / ``revoke``). A step-up is single
    use: an assertion refused by the verifier or at the store's commit spends it too. *subject*, when given,
    must be what the step-up was opened for."""
    stepup_id = _string(body, "stepup_id", high=ID_MAX)
    assertion = body.get("assertion")
    if not isinstance(assertion, dict):
        raise _Fail(400, "bad_request", "assertion must be an object.")
    if "base_url" in body and body["base_url"] != assertion.get("base_url"):
        raise _Fail(400, "bad_request", "base_url differs from the assertion's base_url.")
    pending = call.store.pending(stepup_id, kind=purpose, user_id=call.user_id)
    if pending is None or (subject is not None and pending.subject != subject):
        call.audit(AuditEvent.PASSKEY_STEPUP_REFUSED, purpose=purpose, request_id=stepup_id, reason="stepup_invalid")
        raise _Fail(403, "stepup_invalid", f"No open {purpose} step-up with this id for you; start again.")
    snapshot = call.store.snapshot(call.user_id)
    request = AssertionRequest(user_id=call.user_id, request_id=pending.id, nonce=pending.nonce, title="",
                               summary=pending.subject, detail="", session_id="", purpose=purpose)
    verdict = verify_assertion(call.ctx, request, snapshot,
                               {"decision": "confirmed", "method": "passkey", "passkey": assertion})
    if not isinstance(verdict, AssertionOk):
        _spend(call, pending.id, purpose)
        call.audit(AuditEvent.PASSKEY_STEPUP_REFUSED, purpose=purpose, request_id=stepup_id,
                   base_url=str(assertion.get("base_url", ""))[:512], reason=verdict.reason)
        raise _Fail(422, "assertion_invalid", "The passkey assertion was refused.", reason=verdict.reason)
    used = next(c for c in snapshot if c.credential_id == verdict.credential_id)
    try:
        committed = call.store.commit_assertion(verdict, user_id=call.user_id, snapshot=used, stepup_id=pending.id)
    except CommitRefused as exc:
        _spend(call, pending.id, purpose)  # the commit changed nothing, the step-up included
        call.audit(AuditEvent.PASSKEY_STEPUP_REFUSED, purpose=purpose, request_id=stepup_id,
                   credential=b64u(verdict.credential_id)[:16], reason=exc.reason)
        if exc.reason == "stepup_invalid":
            raise _Fail(403, "stepup_invalid", f"No open {purpose} step-up with this id for you; start again.") \
                from None
        raise _Fail(422, "assertion_invalid", "The passkey assertion was refused.", reason=exc.reason) from None
    return verdict, committed.counter_warning


def _invites(call: _Call, body: dict) -> dict:
    if not call.settings.user_invites:
        call.audit(AuditEvent.PASSKEY_INVITE_REFUSED, reason="user_invites_disabled")
        raise _Fail(403, "invites_disabled", "This gateway's operator mints every enrolment code.")
    verdict, counter_warning = _stepup(call, body, "invite")
    invite = call.store.mint_code(by=call.user_id)
    call.audit(AuditEvent.PASSKEY_INVITE_MINTED, by=call.user_id, request_id=verdict.request_id,
               credential=b64u(verdict.credential_id)[:16], rp_id=verdict.rp_id, base_url=verdict.base_url,
               expires_at=invite.expires_at, counter_warning=counter_warning)
    return {"code": invite.code, "expires_at": invite.expires_at}


@router.post(f"{PREFIX}/invites", name="passkeys_invites")
async def passkeys_invites(request: Request):
    return await _run(request, _invites, write=True)


def _revoke(call: _Call, body: dict) -> dict:
    credential_id = _string(body, "credential_id", high=1400)
    try:
        raw_id = b64u_decode(credential_id, 1, 1023)
    except ValueError:
        raise _Fail(400, "bad_request", "credential_id is not a base64url credential id.") from None
    verdict, counter_warning = _stepup(call, body, "revoke", subject=credential_id)
    revoked = call.store.revoke(raw_id, by=call.user_id, user_id=call.user_id)
    if revoked is None:  # revoked meanwhile (the operator, or a parallel request): nothing more to announce
        return {"ok": True}
    call.audit(AuditEvent.PASSKEY_REVOKED, by=call.user_id, request_id=verdict.request_id,
               credential=revoked.id_b64u[:16], rp_id=revoked.rp_id,
               signed_with=b64u(verdict.credential_id)[:16], counter_warning=counter_warning)
    _announce(call, "revoked", revoked, via="passkey")
    return {"ok": True}


@router.post(f"{PREFIX}/revoke", name="passkeys_revoke")
async def passkeys_revoke(request: Request):
    return await _run(request, _revoke, write=True)


def reset_for_tests() -> None:
    """Forget cached stores, prune times and rate-limit buckets."""
    with _stores_lock:
        _stores.clear()
    with _prune_lock:
        _last_prune.clear()
    for limiter in LIMITERS:
        limiter.reset()


__all__ = ["BODY_CAP", "HOOK_KWARGS", "PREFIX", "router"]
