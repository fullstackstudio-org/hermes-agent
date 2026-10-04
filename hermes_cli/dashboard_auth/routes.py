"""HTTP routes for the dashboard-auth OAuth round trip.

Mounted at root (no prefix) by ``web_server.py``; ``gated_auth_middleware``
allowlists the public ones.

  GET  /login                  server-rendered login page
  GET  /auth/login?provider=N  302 to IDP, sets PKCE cookie
  GET  /auth/native/authorize  RFC 8252 native-app (desktop) login start
  GET  /auth/callback          completes login, sets session cookies
  POST /auth/password-login    username/password login (JSON)
  POST /auth/logout            clears cookies, best-effort revoke
  POST /auth/native/token      loopback code -> bearer tokens
  POST /auth/native/refresh    desktop-held refresh token rotation
  POST /auth/native/revoke     a native client ends its own grant (best effort, always ok)
  GET  /api/auth/providers     list registered providers (login bootstrap)
  GET  /api/auth/me            current Session as JSON (auth-required)
  GET  /api/auth/picture?id=   a signed-in user's stored profile picture (auth-required)
  POST /api/auth/ws-ticket     single-use WS upgrade ticket (auth-required)

Fork (passkey self-enrolment, ``passkeys/reauth.py``): ``/auth/login`` and ``/auth/native/authorize``
take ``reauth=<grant id>``, checked before any redirect or cookie; the callback and the password login
complete a web grant, ``/auth/native/token`` a native one (and then hands out no tokens). Without
``reauth`` every route behaves exactly as before; the passkey package is imported only when it is present.
"""
from __future__ import annotations

import html
import json
import logging
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlparse, urlunparse

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from hermes_cli.dashboard_auth import (
    get_provider, list_providers, list_session_providers, native_flow, pictures)
from hermes_cli.dashboard_auth import origins as _origins
from hermes_cli.dashboard_auth import prefix as _prefix_mod
from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import (
    InvalidCodeError, InvalidCredentialsError, ProviderError, Session)
from hermes_cli.dashboard_auth.rate_limit import SlidingWindowLimiter, Verdict
from hermes_cli.dashboard_auth.cookies import (
    clear_pkce_cookie, clear_reauth_cookie, clear_session_cookies, clear_sso_attempt_cookie,
    detect_https, parse_pkce_payload, read_pkce_cookie, read_reauth_cookie, read_session_cookies,
    set_pkce_cookie, set_session_cookies)
from hermes_cli.dashboard_auth.login_page import (
    render_login_html, render_native_provider_choice_html)
from hermes_cli.dashboard_auth.refresh_singleflight import (
    refresh_session_coalesced, revoke_session_coalesced)
from hermes_cli.dashboard_auth.request_utils import (
    access_token_max_age, client_ip as _client_ip, is_safe_next_path)

_log = logging.getLogger(__name__)

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store, no-cache, must-revalidate"}
_NATIVE_EXPIRED_DETAIL = "Native login expired or unknown; restart sign-in."


def _http(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)


def _prefix(request: Request) -> str:
    """Normalised ``X-Forwarded-Prefix`` (cookie name/Path + redirect URLs)."""
    return _prefix_mod.prefix_from_request(request)


def _audit(request: Request, event: AuditEvent, **fields) -> None:
    audit_log(event, **fields, ip=_client_ip(request))


def _redirect_uri(request: Request) -> str:
    """Absolute ``/auth/callback`` URL handed to the IDP. An operator-declared public URL is the
    complete authority (``X-Forwarded-Prefix`` ignored so a baked-in prefix is not doubled):
    the listed URL of the origin this request came in on, else the primary (fork: several
    ``dashboard.public_urls``; see ``dashboard_auth.origins``), so the callback lands on the
    host that holds the PKCE cookie. The value is always a listed URL, never the request's own
    Host. Otherwise ``url_for`` (``X-Forwarded-Proto`` under uvicorn ``proxy_headers``) with
    the prefix prepended, which Starlette does not do."""
    public_url = _origins.public_base_url(request)
    if public_url:
        return f"{public_url}/auth/callback"
    base = str(request.url_for("auth_callback"))
    prefix = _prefix(request)
    if not prefix:
        return base
    parsed = urlparse(base)
    return urlunparse(parsed._replace(path=f"{prefix}{parsed.path}"))


def _redirect_uri_hint(request: Request, *idp_text: str) -> str:
    """When the IdP's own error text names the redirect URI, say which one this gateway sent and
    that it must be registered. With several public origins each has its own callback; an IdP
    that refuses one outright usually shows its own error page and never returns here."""
    if "redirect" not in " ".join(idp_text).lower():
        return ""
    return (f" -- the gateway sent redirect_uri {_redirect_uri(request)}; register it with the "
            "identity provider's client (every origin in dashboard.public_urls needs its own "
            "/auth/callback).")


def _provider_pkce_segments(cookie_payload: dict[str, str]) -> dict[str, str]:
    """Parse a provider's flat ``state=…;verifier=…`` PKCE string into a dict — the ONE place
    the flat form is parsed; :func:`set_pkce_cookie` encodes the dict."""
    flat = cookie_payload.get("hermes_session_pkce", "")
    return dict(seg.split("=", 1) for seg in flat.split(";") if "=" in seg)


def _validate_post_login_target(raw: str) -> str:
    """``raw`` (URL-decoded) if it is a safe same-origin path, else ``""``. Re-validated
    at every hop because a ``next=`` value can re-enter via a crafted URL."""
    decoded = unquote(raw) if raw else ""
    return decoded if decoded and is_safe_next_path(decoded) else ""


def _set_pkce(resp, request: Request, payload: dict[str, str]) -> None:
    set_pkce_cookie(resp, payload=payload, use_https=detect_https(request), prefix=_prefix(request))


def _set_session(resp, request: Request, session: Session) -> None:
    set_session_cookies(
        resp, access_token=session.access_token, refresh_token=session.refresh_token,
        access_token_expires_in=access_token_max_age(session), use_https=detect_https(request),
        prefix=_prefix(request), provider=session.provider)


def _bearer_payload(session: Session) -> dict[str, Any]:
    """JSON body for the native token/refresh endpoints (tokens in body, no cookie)."""
    return {
        "access_token": session.access_token, "refresh_token": session.refresh_token,
        "token_type": "Bearer", "expires_at": session.expires_at,
        "provider": session.provider, "user_id": session.user_id}


def _finish_native_login(
    request: Request, *, broker_state: str, session: Session, provider: str) -> str:
    """Mint the one-time loopback code and return the desktop's ``redirect_uri?code=…&state=…``.
    No session cookies on the native path — the desktop redeems at ``/auth/native/token``."""
    try:
        pending = native_flow.get_pending(broker_state)
        gw_code = native_flow.complete_pending(broker_state, session=session)
    except native_flow.NativeFlowError:
        _audit(request, AuditEvent.NATIVE_TOKEN_FAILURE, provider=provider,
               reason="pending_not_found")
        raise _http(400, _NATIVE_EXPIRED_DETAIL)
    sep = "&" if "?" in pending.redirect_uri else "?"
    query = urlencode({'code': gw_code, 'state': pending.client_state})
    _audit(request, AuditEvent.NATIVE_CODE_ISSUED, provider=provider, user_id=session.user_id)
    return f"{pending.redirect_uri}{sep}{query}"


def _login_failure(request: Request, provider: str, reason: str, **extra) -> None:
    _audit(request, AuditEvent.LOGIN_FAILURE, provider=provider, reason=reason, **extra)


def _login_success(request: Request, session: Session, provider: str) -> None:
    _audit(request, AuditEvent.LOGIN_SUCCESS, provider=provider, user_id=session.user_id,
           email=session.email, org_id=session.org_id)


async def _complete_login(request: Request, provider: str, session: Session, *, broker_state: str,
                          next_raw: str) -> tuple:
    """Shared tail of the callback + password routes after credentials verified: audit success,
    then either the native loopback redirect (no cookies) or the landing path, storing the profile
    picture this login brought. Returns ``(target_url, native)``.

    The picture is fetched here and nowhere else -- not in the provider's grant, which refresh
    shares -- so it happens once per sign-in, and only once the login is certain to complete: a
    native login whose pending authorization is gone fails first and leaves the stored picture
    alone. The login never waits for a fetch slot and waits for the fetch itself only so long (see
    ``pictures.store_login_picture``); it never raises."""
    _login_success(request, session, provider)
    if broker_state:
        target = _finish_native_login(
            request, broker_state=broker_state, session=session, provider=provider)
        await pictures.store_login_picture(session)
        return target, True
    await pictures.store_login_picture(session)
    return _validate_post_login_target(next_raw) or "/", False


def _start_upstream_login(request: Request, p, *, audit_failure: bool, extra_pkce: dict[str, str],
                          fresh: bool = False):
    """Run ``start_login`` and 302 to the IDP with the PKCE cookie set. That cookie is the only
    server-controlled channel surviving the round trip (IDPs echo back only code+state), so it
    carries the provider name plus ``extra_pkce``. ``fresh`` (a re-authentication, only for a
    provider that ``supports_reauth``) is the only case that passes the keyword at all."""
    try:
        if fresh:
            ls = p.start_login(redirect_uri=_redirect_uri(request), fresh=True)
        else:
            ls = p.start_login(redirect_uri=_redirect_uri(request))
    except ProviderError as e:
        if audit_failure:
            _login_failure(request, p.name, "provider_unreachable")
        raise _http(503, f"Provider unreachable: {e}")
    resp = RedirectResponse(url=ls.redirect_url, status_code=302)
    pkce = _provider_pkce_segments(ls.cookie_payload)
    pkce.setdefault("provider", p.name)
    pkce.update(extra_pkce)
    _set_pkce(resp, request, pkce)
    return resp


# --- Re-authentication grants (passkey self-enrolment) -----------------------
# One helper per route; each imports the passkey package only when a ``reauth`` value is present.

def _reauth_page(status_code: int, text: str, *, retry_after: int = 0) -> HTMLResponse:
    """A person-facing refusal: never a redirect, no cookie (the route is public). A 429 says when to
    retry (``Retry-After``, the seconds until the refusal budget frees a slot)."""
    body = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>Passkey set-up</title></head><body><main><p>"
            f"{html.escape(text)}</p></main></body></html>")
    headers = {**_NO_STORE, **({"Retry-After": str(retry_after)} if retry_after else {})}
    return HTMLResponse(body, status_code=status_code, headers=headers)


def _reauth_too_many(attempt) -> HTMLResponse:
    return _reauth_page(429, "Too many attempts. Try again shortly.", retry_after=attempt.retry_after)


async def _reauth_start_refusal(request: Request, p, grant_id: str, *, client: str):
    """``None`` when the sign-in may start for re-authentication grant ``grant_id``, else the answer
    (429 past the refusal budget, 400 for a dead, foreign or unbound grant). A web grant needs this
    browser's ``hermes_reauth`` cookie; a link to someone else's grant completes nothing."""
    from hermes_cli.dashboard_auth.passkeys import reauth
    ip = _client_ip(request)
    attempt = reauth.begin_attempt(ip, grant_id)  # reserved before anything is read
    if not attempt.allowed:
        return _reauth_too_many(attempt)
    secret = read_reauth_cookie(request) if client == "web" else None
    grant = await run_in_threadpool(
        reauth.grant_for_login, grant_id, provider=p, client=client, secret=secret, ip=ip)
    if grant is None:
        return _reauth_page(400, reauth.EXPIRED_TEXT)
    attempt.succeeded()
    return None


class _ReauthRefused(Exception):
    """Carries the refusal page out of :func:`_native_reauth_provider`."""

    def __init__(self, response):
        super().__init__("reauth refused")
        self.response = response


async def _native_reauth_provider(request: Request, provider: str, grant_id: str):
    """The provider a native re-authentication runs with: the named one when the grant is its own,
    or (no ``provider``) the one the grant names. Raises the refusal (429 / 400 / 404)."""
    from hermes_cli.dashboard_auth.passkeys import reauth
    if provider:
        p = get_provider(provider)
        if p is None:
            raise _http(404, f"Unknown provider: {provider!r}")
        refusal = await _reauth_start_refusal(request, p, grant_id, client="native")
    else:
        ip = _client_ip(request)
        attempt = reauth.begin_attempt(ip, grant_id)  # reserved before anything is read
        if not attempt.allowed:
            refusal = _reauth_too_many(attempt)
        else:
            p, _grant = await run_in_threadpool(
                reauth.native_grant_for_login, grant_id, providers=list_session_providers(), ip=ip)
            if p is None:
                refusal = _reauth_page(400, reauth.EXPIRED_TEXT)
            else:
                attempt.succeeded()
                refusal = None
    if refusal is not None:
        raise _ReauthRefused(refusal)
    return p


async def _finish_web_reauth(request: Request, resp, parts: dict[str, str], session: Session) -> bool:
    """After a web sign-in (callback or password login) whose PKCE cookie carries ``reauth``: complete
    that grant with this browser's cookie secret. The cookie stays whatever the outcome: it is the grant's
    use binding until ``register/finish`` spends it (or it expires, or the person signs out), and the
    passkey routes need it to tell this browser why a failed grant failed. The sign-in stands either way.
    ``False`` (nothing done) without ``reauth`` or on a native flow."""
    grant_id = parts.get("reauth", "")
    if not grant_id or parts.get("broker"):
        return False
    from hermes_cli.dashboard_auth.passkeys import reauth
    secret = read_reauth_cookie(request)
    await run_in_threadpool(
        reauth.complete, grant_id, session, client="web", secret=secret, ip=_client_ip(request))
    return True


async def _native_reauth_answer(request: Request, grant_id: str, session: Session) -> JSONResponse:
    """A native re-authentication code was redeemed: complete the grant (the PKCE verifier was the
    binding) and answer ``{"reauth": {...}}`` with NO tokens; the app's own token set is untouched. A fresh
    grant's answer carries its one-time ``use_secret``, which ``register/begin|finish`` require: only the
    holder of the PKCE verifier ever sees it. The session the sign-in minted is never handed out and is
    deliberately NOT revoked at the provider: on an IdP such as Keycloak or Auth0 revoking that refresh token
    can end the SSO session the app's own sign-in rides on, the token expires by itself, and a synchronous
    IdP call does not belong in the token route."""
    from hermes_cli.dashboard_auth.passkeys import reauth
    outcome = await run_in_threadpool(
        reauth.complete, grant_id, session, client="native", secret=None, ip=_client_ip(request))
    return JSONResponse({"reauth": outcome.body()}, headers=_NO_STORE)


# --- Public: login page + provider list ------------------------------------

@router.get("/login", name="login_page")
async def login_page(request: Request) -> HTMLResponse:
    # ``next=`` is set by the gate's redirect but /login is reachable directly.
    next_path = _validate_post_login_target(request.query_params.get("next", ""))
    return HTMLResponse(render_login_html(next_path=next_path), headers=_NO_STORE)


@router.get("/api/auth/providers", name="auth_providers")
async def api_auth_providers() -> Any:
    # Only interactive providers are sign-in options; fail closed on zero.
    providers = list_session_providers()
    if not providers:
        return JSONResponse({"detail": "no auth providers registered"}, status_code=503)
    return {"providers": [
        {"name": p.name, "display_name": p.display_name,
         "supports_password": bool(getattr(p, "supports_password", False))}
        for p in providers]}


# --- Public: OAuth round trip ----------------------------------------------

@router.get("/auth/login", name="auth_login")
async def auth_login(request: Request, provider: str, next: str = "", reauth: str = ""):
    p = get_provider(provider)
    if p is None:
        raise _http(404, f"Unknown provider: {provider!r}")
    if not getattr(p, "supports_session", True):
        raise _http(404, f"Provider does not support interactive login: {provider!r}")
    if reauth:
        refusal = await _reauth_start_refusal(request, p, reauth, client="web")
        if refusal is not None:
            return refusal
    safe_next = _validate_post_login_target(next)
    if getattr(p, "supports_password", False):
        login_url = f"{_prefix(request)}/login"
        if safe_next:
            login_url = f"{login_url}?next={quote(safe_next, safe='')}"
        resp = RedirectResponse(url=login_url, status_code=302)
        if reauth:  # the password login completes the grant named here
            _set_pkce(resp, request, {"provider": p.name, "reauth": reauth})
        return resp
    extra = {"next": safe_next} if safe_next else {}
    resp = _start_upstream_login(
        request, p, audit_failure=True, extra_pkce={**extra, **({"reauth": reauth} if reauth else {})},
        fresh=bool(reauth))
    _audit(request, AuditEvent.LOGIN_START, provider=provider)
    return resp


# --- Public: RFC 8252 native-app authorization (system browser + loopback + PKCE)

def _validate_loopback_redirect_uri(raw: str) -> str:
    """Accept only ``http://127.0.0.1[:port]/…`` / ``http://[::1][:port]/…``. Security boundary:
    the route is public, so a non-loopback host would make the callback an open redirect leaking
    a live code. ``localhost`` is rejected (RFC 8252 §8.3)."""
    if not raw:
        raise _http(400, "redirect_uri required")
    parsed = urlparse(raw)
    if parsed.scheme != "http":
        raise _http(400, "native redirect_uri must be http:// on the loopback interface")
    if (parsed.hostname or "").lower() not in ("127.0.0.1", "::1"):
        raise _http(400, "native redirect_uri host must be a loopback IP literal (127.0.0.1 / ::1)")
    return raw


def _select_native_provider(provider: str):
    """Resolve the provider for a native authorize request. An empty ``provider`` auto-selects
    the ONLY interactive session provider (password providers included — native sign-in brokers
    them via ``/login``); with several the caller renders a chooser instead of guessing."""
    if provider:
        return get_provider(provider)
    candidates = list_session_providers()
    return candidates[0] if len(candidates) == 1 else None


@router.get("/auth/native/authorize", name="auth_native_authorize")
async def auth_native_authorize(
    request: Request, provider: str = "", code_challenge: str = "",
    code_challenge_method: str = "", redirect_uri: str = "", state: str = "", reauth: str = ""):
    """Begin an RFC 8252 native-app login: stash a pending broker authorization keyed by an
    opaque ``broker_state`` riding in the gateway's own PKCE cookie (the desktop's
    challenge/state never touch it), then run the normal upstream round trip. Password providers
    go to the ``/login`` form instead."""
    if code_challenge_method.upper() != "S256":
        raise _http(400, "code_challenge_method must be S256")
    if not code_challenge:
        raise _http(400, "code_challenge required")
    _validate_loopback_redirect_uri(redirect_uri)
    if reauth:
        try:
            p = await _native_reauth_provider(request, provider, reauth)
        except _ReauthRefused as refused:
            return refused.response
    else:
        p = _select_native_provider(provider)
    if p is None and not provider:
        candidates = list_session_providers()
        if len(candidates) > 1:
            # Render the chooser BEFORE allocating broker state or setting a cookie: every link
            # re-enters this same validated route with an explicit provider.
            return HTMLResponse(
                render_native_provider_choice_html(
                    providers=candidates,
                    authorize_path=f"{_prefix(request)}/auth/native/authorize",
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    redirect_uri=redirect_uri, state=state),
                headers=_NO_STORE)
    if p is None:
        raise _http(404, f"Unknown provider: {provider!r}")
    if not getattr(p, "supports_session", True):
        raise _http(400, f"Provider does not support native login: {p.name!r}")
    try:
        broker_state = native_flow.register_pending(
            code_challenge=code_challenge, redirect_uri=redirect_uri, client_state=state,
            client_ip=_client_ip(request), reauth=reauth)
    except native_flow.NativeFlowError as e:
        raise _http(503, str(e))
    if getattr(p, "supports_password", False):
        _audit(request, AuditEvent.NATIVE_AUTHORIZE_START, provider=p.name)
        resp = RedirectResponse(url=f"{_prefix(request)}/login", status_code=302)
        _set_pkce(resp, request, {"provider": p.name, "broker": broker_state})
        return resp
    resp = _start_upstream_login(
        request, p, audit_failure=False, extra_pkce={"broker": broker_state}, fresh=bool(reauth))
    _audit(request, AuditEvent.NATIVE_AUTHORIZE_START, provider=p.name)
    return resp


@router.get("/auth/callback", name="auth_callback")
async def auth_callback(
    request: Request, code: str = "", state: str = "", error: str = "",
    error_description: str = ""):
    pkce_raw = read_pkce_cookie(request)
    if not pkce_raw:
        _audit(request, AuditEvent.LOGIN_FAILURE, reason="missing_pkce_cookie")
        raise _http(400, "Missing PKCE state cookie")
    # ``next`` and ``broker`` come from the server-set cookie ONLY: the IDP
    # echoes back just code+state, so any such query param is attacker controlled.
    parts = parse_pkce_payload(pkce_raw)
    provider_name = parts.get("provider", "")
    p = get_provider(provider_name)
    if p is None:
        raise _http(400, f"Unknown provider in cookie: {provider_name!r}")
    if error:
        _login_failure(request, provider_name, "idp_error", error=error)
        raise _http(400, f"OAuth error from provider: {error} ({error_description})"
                         f"{_redirect_uri_hint(request, error, error_description)}")
    if not state or state != parts.get("state", ""):
        _login_failure(request, provider_name, "state_mismatch")
        raise _http(400, "OAuth state mismatch (CSRF check failed)")
    try:
        session = p.complete_login(
            code=code, state=state, code_verifier=parts.get("verifier", ""),
            redirect_uri=_redirect_uri(request))
    except InvalidCodeError as e:
        _login_failure(request, provider_name, "invalid_code")
        raise _http(400, f"Invalid code: {e}{_redirect_uri_hint(request, str(e))}")
    except ProviderError as e:
        _login_failure(request, provider_name, "provider_unreachable")
        raise _http(503, f"Provider unreachable: {e}")
    target, native = await _complete_login(
        request, provider_name, session, broker_state=parts.get("broker", ""),
        next_raw=parts.get("next", ""))
    resp = RedirectResponse(url=target, status_code=302)
    if not native:
        _set_session(resp, request, session)
        await _finish_web_reauth(request, resp, parts, session)
    prefix = _prefix(request)
    clear_pkce_cookie(resp, use_https=detect_https(request), prefix=prefix)
    # Clear the one-shot auto-SSO loop-guard so it never suppresses a future silent attempt.
    clear_sso_attempt_cookie(resp, prefix=prefix)
    return resp


# --- Public: password (non-redirect) login ---------------------------------
# Brute-force throttle: a process-local sliding window per client IP. Best-effort
# defence-in-depth on top of the provider's constant-time verify (resets on restart; behind a
# proxy that is not in dashboard.trusted_proxies the IP is the proxy's; see client_ip).
_PW_RATE_MAX_ATTEMPTS = 10
_PW_RATE_WINDOW_SEC = 60.0
_pw_limiter = SlidingWindowLimiter(_PW_RATE_MAX_ATTEMPTS, _PW_RATE_WINDOW_SEC)


def _password_rate_limited(ip: str) -> bool:
    """True if ``ip`` exceeded the budget; records the attempt when allowed. An empty IP shares
    one bucket — fail-safe toward throttling."""
    return _pw_limiter.check(ip) is not Verdict.ALLOWED


def _reset_password_rate_limit() -> None:
    """Test-only: clear all rate-limit buckets."""
    _pw_limiter.reset()


class _PasswordLoginBody(BaseModel):
    provider: str
    username: str
    password: str
    next: str = ""


@router.post("/auth/password-login", name="auth_password_login")
async def auth_password_login(request: Request, body: _PasswordLoginBody):
    """Authenticate a username/password against a password provider.

    Returns ``{"ok": true, "next": <path>}`` (the form POSTs via fetch, which follows a 302
    opaquely) and sets the session cookies; with a native ``broker`` handle in the PKCE cookie,
    ``next`` is the desktop's loopback redirect and NO cookies are set. Failures are deliberately
    generic (no username/provider oracle): unknown/non-password provider 404, bad credentials
    401, store unreachable 503, rate limited 429.
    """
    if _password_rate_limited(_client_ip(request)):
        _login_failure(request, body.provider, "rate_limited")
        raise _http(429, "Too many login attempts. Try again shortly.")
    p = get_provider(body.provider)
    if p is None or not getattr(p, "supports_password", False):
        _login_failure(request, body.provider, "unknown_password_provider")
        raise _http(404, "Unknown provider")
    # The native broker handle also records WHICH provider the flow was started for. Enforce
    # equality BEFORE verifying credentials so a flow started for provider A cannot be completed
    # with provider B's credentials.
    pkce_raw = read_pkce_cookie(request)
    pkce_parts = parse_pkce_payload(pkce_raw) if pkce_raw else {}
    broker_state = pkce_parts.get("broker", "")
    if broker_state and pkce_parts.get("provider", "") != body.provider:
        _audit(request, AuditEvent.NATIVE_TOKEN_FAILURE, provider=body.provider,
               reason="provider_mismatch")
        raise _http(400, "This native sign-in was started for a different provider; "
                         "use that provider's form or restart sign-in.")
    try:
        session = p.complete_password_login(username=body.username, password=body.password)
    except InvalidCredentialsError:
        _login_failure(request, body.provider, "invalid_credentials")
        raise _http(401, "Invalid credentials")
    except NotImplementedError:
        # supports_password True but method not implemented: a provider bug.
        raise _http(500, "Provider misconfigured")
    except ProviderError as e:
        _login_failure(request, body.provider, "provider_unreachable")
        raise _http(503, f"Provider unreachable: {e}")
    target, native = await _complete_login(
        request, body.provider, session, broker_state=broker_state, next_raw=body.next)
    resp = JSONResponse({"ok": True, "next": target})
    if native:
        clear_pkce_cookie(resp, use_https=detect_https(request), prefix=_prefix(request))
    else:
        _set_session(resp, request, session)
        if await _finish_web_reauth(request, resp, pkce_parts, session):
            clear_pkce_cookie(resp, use_https=detect_https(request), prefix=_prefix(request))
    return resp


@router.post("/auth/logout", name="auth_logout")
async def auth_logout(request: Request):
    _at, rt = read_session_cookies(request)
    # Best-effort revoke on every provider; failures logged, never raised.
    for provider in list_providers() if rt else ():
        try:
            provider.revoke_session(refresh_token=rt)
        except Exception as e:  # noqa: BLE001 — best-effort
            _log.warning("dashboard-auth: revoke on %r failed: %s", provider.name, e)
    sess = getattr(request.state, "session", None)
    _audit(request, AuditEvent.LOGOUT, provider=(sess.provider if sess else "unknown"),
           user_id=(sess.user_id if sess else ""))
    prefix = _prefix(request)
    resp = RedirectResponse(url=f"{prefix}/login", status_code=302)
    clear_session_cookies(resp, prefix=prefix)
    clear_pkce_cookie(resp, use_https=detect_https(request), prefix=prefix)
    clear_reauth_cookie(resp)
    return resp


# --- Auth-required: identity probe + WS ticket for the SPA -----------------

def _require_session(request: Request):
    sess = getattr(request.state, "session", None)
    if sess is None:
        raise _http(401, "Unauthorized")
    return sess


@router.get("/api/auth/me", name="auth_me")
async def api_auth_me(request: Request):
    """Return the verified session as JSON. Auth-required (gate enforces).

    Everything here comes from the session the gateway verified, never from the request.
    ``picture_url`` is the gateway's own copy (see ``pictures``), present only while one is stored;
    the provider's URL is never handed out."""
    sess = _require_session(request)
    body = {
        "user_id": sess.user_id, "email": sess.email, "display_name": sess.display_name,
        "org_id": sess.org_id, "provider": sess.provider, "expires_at": sess.expires_at}
    identity = pictures.identity_id(sess.provider, sess.user_id)
    if pictures.has_picture(identity):
        body["picture_url"] = pictures.picture_path(identity)
    return body


@router.get(pictures.PICTURE_ENDPOINT, name="auth_picture")
async def api_auth_picture(request: Request, identity: str = Query("", alias="id")):
    """The stored profile picture of ``id`` (``<provider>:<user id>``, the author-stamp id) for any
    signed-in user of this gateway -- a colleague's included, which is deliberate.

    Every id without a stored picture gets the same 404 as an unknown route, so this cannot tell a
    caller which ids exist. The type is the one read from the stored bytes, ``nosniff`` keeps a
    browser from second-guessing it, and the sandboxing CSP keeps it inert if opened directly."""
    _require_session(request)
    found = await run_in_threadpool(pictures.read_picture, identity)
    if found is None:
        raise _http(404, "Not Found")
    data, kind = found
    return Response(content=data, media_type=kind, headers={
        "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-cache",
        "Content-Security-Policy": "default-src 'none'; sandbox"})


@router.post("/api/auth/ws-ticket", name="auth_ws_ticket")
async def api_auth_ws_ticket(request: Request):
    """Mint a 30s single-use ticket for a WS upgrade (browsers cannot set
    ``Authorization`` on the upgrade); one ticket per WS."""
    sess = _require_session(request)
    from hermes_cli.dashboard_auth.ws_tickets import TTL_SECONDS, mint_ticket
    # The display name rides along with the login it belongs to: this verified session is the only
    # place a human name for the user exists without asking the provider again, and the WS turn has
    # no way to ask (see ws_tickets.mint_ticket).
    # So does the person's profile (``Session.profile``), for the same reason: each turn tells the model
    # who it is for, and this session is the only verified source of it.
    ticket = mint_ticket(
        user_id=sess.user_id, provider=sess.provider, user_name=sess.display_name,
        profile=dict(getattr(sess, "profile", None) or {}))
    _audit(request, AuditEvent.WS_TICKET_MINTED, provider=sess.provider, user_id=sess.user_id)
    return {"ticket": ticket, "ttl_seconds": TTL_SECONDS}


# --- Public: RFC 8252 native-app token exchange + refresh ------------------

class _NativeTokenBody(BaseModel):
    code: str
    code_verifier: str


@router.post("/auth/native/token", name="auth_native_token")
async def auth_native_token(request: Request, body: _NativeTokenBody):
    """Exchange a loopback gateway code + PKCE verifier for bearer tokens. The code is consumed
    on every path (no verifier oracle, no replay); any failure is a generic 400. Tokens go in
    the JSON body; no cookie is set. A re-authentication code (fork) answers
    ``{"reauth": {"grant_id", "state", "reason"?, "expires_at"}}`` and no tokens."""
    try:
        redeemed = native_flow.redeem(code=body.code, code_verifier=body.code_verifier)
    except native_flow.CodeInvalid:
        _audit(request, AuditEvent.NATIVE_TOKEN_FAILURE, reason="invalid_code_or_pkce")
        raise _http(400, "Invalid or expired authorization code.")
    session = redeemed.session
    _audit(request, AuditEvent.NATIVE_TOKEN_SUCCESS, provider=session.provider,
           user_id=session.user_id, **({"reauth": True} if redeemed.reauth else {}))
    if redeemed.reauth:
        return await _native_reauth_answer(request, redeemed.reauth, session)
    return _bearer_payload(session)


class _NativeRefreshBody(BaseModel):
    refresh_token: str
    provider: str = ""


@router.post("/auth/native/refresh", name="auth_native_refresh")
async def auth_native_refresh(request: Request, body: _NativeRefreshBody):
    """Rotate a desktop-held refresh token (mirrors the gate's ``_attempt_refresh``): every
    provider rejecting the RT -> 401 ``session_expired`` (desktop re-logs); none rotated and one
    unreachable -> 503."""
    if not body.refresh_token:
        raise _http(400, "refresh_token required")
    try:
        # Off the event loop: the provider call is synchronous network I/O and a slow IdP
        # otherwise wedges every public endpoint (/api/status) behind it.
        refreshed = await run_in_threadpool(
            refresh_session_coalesced, body.refresh_token, body.provider,
            phase="native refresh", log=_log)
    except ProviderError as e:
        raise _http(503, f"Auth provider {str(e)!r} unreachable")
    if refreshed is not None:
        session = refreshed[0]
        _audit(request, AuditEvent.REFRESH_SUCCESS, provider=session.provider,
               user_id=session.user_id)
        return _bearer_payload(session)
    _audit(request, AuditEvent.REFRESH_FAILURE, reason="all_providers_rejected_rt")
    return JSONResponse(
        {"error": "session_expired",
         "detail": "Refresh token expired or invalid; start a new sign-in."}, status_code=401)


# --- Public: native-app revoke ----------------------------------------------
# A native client ending its own grant, the counterpart of ``/auth/logout`` for a client that holds
# its refresh token itself instead of in a cookie. The refresh token in the body is the whole
# authority: nothing ambient (cookie, session) is read, so a cross-site page that makes a browser
# POST here can revoke only a token it already holds. Every accepted request answers the same
# ``200 {"ok": true}`` whether the token was live, dead or never issued, so the route is no
# validity oracle; the provider's own answer is never read back.
_REVOKE_MAX_BODY_BYTES = 16 * 1024
_REVOKE_RATE_MAX = 30
_REVOKE_RATE_WINDOW_SEC = 60.0
# Per client address, like the password throttle. Each accepted revoke can cost an outbound call
# to the identity provider that holds a threadpool worker until it answers or times out, so an
# unauthenticated caller must not be able to turn this route into an unbounded request pump.
_revoke_limiter = SlidingWindowLimiter(_REVOKE_RATE_MAX, _REVOKE_RATE_WINDOW_SEC)


def _reset_native_revoke_rate_limit() -> None:
    """Test-only: clear all revoke rate-limit buckets."""
    _revoke_limiter.reset()


async def _read_small_json_object(request: Request, limit: int) -> dict:
    """The request body as a JSON object, refusing more than ``limit`` bytes before reading them
    (declared length) and while reading them (chunked bodies). 413 too large, 400 not an object."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        raise _http(400, "Invalid Content-Length")
    if declared > limit:
        raise _http(413, "Request body too large")
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > limit:
            raise _http(413, "Request body too large")
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError):  # RecursionError: deeply nested arrays or objects
        body = None
    if not isinstance(body, dict):
        raise _http(400, "Body must be a JSON object")
    return body


@router.post("/auth/native/revoke", name="auth_native_revoke")
async def auth_native_revoke(request: Request):
    """End a native client's grant: body ``{"refresh_token": "...", "provider": "<name>"}``.

    ``provider`` is required: the name ``/auth/native/token`` and ``/auth/native/refresh``
    returned with the token. It selects which provider the token is handed to (see
    ``refresh_singleflight.revoke_targets``): only that one when it names a registered session
    provider, each in turn when it names none. Revocation is the provider's: RFC 7009 at an OIDC
    provider that advertises a revocation endpoint, nothing at the stateless password provider or
    the Nous Portal, whose tokens run out on their own. Best effort and never an error once the
    request is well formed: ``200 {"ok": true}`` for every token. A missing token or provider
    (``null`` and ``""`` count as missing; whether they are missing never depends on the token)
    400, an oversized body 413, more than ``_REVOKE_RATE_MAX`` a minute from one address 429."""
    verdict = _revoke_limiter.check(_client_ip(request))
    if verdict is not Verdict.ALLOWED:
        if verdict is Verdict.REFUSED:  # one audit line per address per window, not per request
            _audit(request, AuditEvent.REVOKE, flow="native", reason="rate_limited")
        raise _http(429, "Too many revoke requests. Try again shortly.")
    body = await _read_small_json_object(request, _REVOKE_MAX_BODY_BYTES)
    token, hint = body.get("refresh_token"), body.get("provider")
    if not isinstance(token, str) or not token:
        raise _http(400, "refresh_token required")
    if hint is None or hint == "":
        raise _http(400, "provider required: send the provider name returned with the token")
    if not isinstance(hint, str):
        raise _http(400, "provider must be a string")
    # Off the event loop: an OIDC revoke is synchronous network I/O.
    targets = await run_in_threadpool(revoke_session_coalesced, token, hint, log=_log)
    # Only registered provider names are written, never the caller's hint as sent, and never the
    # token: there is no user id to record, because nothing here verified whose token it was.
    _audit(request, AuditEvent.REVOKE, flow="native", providers=[p.name for p in targets])
    return JSONResponse({"ok": True}, headers=_NO_STORE)
