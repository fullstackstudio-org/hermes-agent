"""E2E + unit tests for the RFC 8252 native-app (system-browser + loopback +
PKCE) dashboard-auth flow.

Covers:
  * ``native_flow`` broker unit behaviour — PKCE binding, single-use codes,
    expiry, capacity, replay resistance.
  * The full ``/auth/native/authorize`` → ``/auth/callback`` →
    ``/auth/native/token`` round trip in-process against ``StubAuthProvider``.
  * ``/api/status`` capability advertisement (``auth_flows``).
  * Cookieless bearer authentication of a gated route (the whole point of the
    feature — a desktop authenticates REST with ``Authorization: Bearer`` and
    sets/needs no cookie).
  * ``/auth/native/refresh`` token rotation and terminal-expiry semantics.
  * ``/auth/native/revoke``: which provider a token is handed to, the uniform
    answer, and what it leaves in the audit log.

Run: pytest tests/hermes_cli/test_dashboard_auth_native_flow.py
"""

from __future__ import annotations

import hashlib
import base64
import html
import json
import logging
import re
import secrets
import time
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import (
    clear_providers,
    register_provider,
)
from hermes_cli.dashboard_auth import native_flow
from hermes_cli.dashboard_auth.base import RefreshExpiredError, Session
from hermes_cli.dashboard_auth.routes import _reset_native_revoke_rate_limit
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider


# ---------------------------------------------------------------------------
# PKCE helpers (desktop side)
# ---------------------------------------------------------------------------


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_pkce() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` — the desktop's PKCE pair."""
    verifier = _b64url_no_pad(b"desktop-verifier-secret-material-0123456789abcd")
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class _PasswordOnlyProvider(StubAuthProvider):
    """Mirrors the bundled ``basic`` provider's flags: a session provider
    (``supports_session`` defaults True) that authenticates by username +
    password and can never be the target of the native OAuth broker flow.
    ``start_login`` raises to prove the route must reject it before ever
    attempting a redirect."""

    name = "pwonly"
    display_name = "Password Only (test)"
    supports_password = True

    def start_login(self, *, redirect_uri):
        raise AssertionError(
            "native authorize must reject a password provider before "
            "calling start_login"
        )


class _SecondStubProvider(StubAuthProvider):
    """A second brokerable OAuth provider, so tests can create an ambiguous
    multi-provider deployment."""

    name = "stub2"
    display_name = "Stub IdP Two (test only)"


# ---------------------------------------------------------------------------
# native_flow broker unit tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_broker():
    native_flow._reset_for_tests()
    _reset_native_revoke_rate_limit()
    # Snapshot the shared app.state auth fields + provider registry so a test
    # that flips auth_required / registers a stub provider can't leak into a
    # later test file (e.g. the MCP dashboard-oauth suite shares web_server.app).
    prev_required = getattr(web_server.app.state, "auth_required", None)
    prev_host = getattr(web_server.app.state, "bound_host", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    yield
    native_flow._reset_for_tests()
    clear_providers()
    web_server.app.state.auth_required = prev_required
    web_server.app.state.bound_host = prev_host
    web_server.app.state.bound_port = prev_port


def _stub_session(exp_offset: int = 3600) -> Session:
    now = int(time.time())
    return Session(
        user_id="u1",
        email="u1@example.test",
        display_name="U One",
        org_id="org1",
        provider="stub",
        expires_at=now + exp_offset,
        access_token="at-opaque",
        refresh_token="rt-opaque",
    )








# ---------------------------------------------------------------------------
# Route-level E2E against StubAuthProvider
# ---------------------------------------------------------------------------


@pytest.fixture
def gated_client():
    clear_providers()
    register_provider(StubAuthProvider())
    prev_host = getattr(web_server.app.state, "bound_host", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    # follow_redirects=False so we can inspect each 302 leg of the flow.
    client = TestClient(
        web_server.app, base_url="https://fly-app.fly.dev",
        follow_redirects=False,
    )
    yield client
    clear_providers()
    web_server.app.state.bound_host = prev_host
    web_server.app.state.bound_port = prev_port
    web_server.app.state.auth_required = prev_required


def _walk_native_login(client, *, redirect_uri, challenge, state="cli-state"):
    """Drive authorize → (stub redirects to callback) → loopback code.

    Returns the ``code`` + ``state`` the gateway put on the loopback redirect.
    """
    # 1. Desktop opens the system browser at /auth/native/authorize.
    r = client.get(
        "/auth/native/authorize",
        params={
            "provider": "stub",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": redirect_uri,
            "state": state,
        },
    )
    assert r.status_code == 302, r.text
    # Stub's start_login redirects straight to /auth/callback?code=stub_code.
    loc = r.headers["location"]
    parsed = urlparse(loc)
    cb_qs = parse_qs(parsed.query)
    # Carry the gateway PKCE cookie forward (holds broker_state + verifier).
    cookies = r.cookies
    # 2. Browser hits the gateway callback.
    r2 = client.get(
        "/auth/callback",
        params={"code": cb_qs["code"][0], "state": cb_qs["state"][0]},
        cookies=cookies,
    )
    assert r2.status_code == 302, r2.text
    # 3. The callback 302s to the desktop's loopback redirect_uri.
    loop = urlparse(r2.headers["location"])
    assert f"{loop.scheme}://{loop.netloc}" == redirect_uri.rsplit("/", 1)[0] or \
        loop.netloc in redirect_uri
    loop_qs = parse_qs(loop.query)
    # No session cookie must be set on the native callback response.
    set_cookie = r2.headers.get("set-cookie", "")
    assert "hermes_session_at" not in set_cookie, (
        f"native callback must NOT set a session cookie; got {set_cookie!r}"
    )
    return loop_qs["code"][0], loop_qs["state"][0]




def test_native_authorize_rejects_non_loopback_redirect(gated_client):
    _verifier, challenge = _make_pkce()
    r = gated_client.get(
        "/auth/native/authorize",
        params={
            "provider": "stub",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "https://evil.example.com/steal",
            "state": "s",
        },
    )
    assert r.status_code == 400
    assert "loopback" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Empty-provider auto-select (the desktop omits ``provider``; the gateway
# picks when there is exactly one brokerable candidate) — regression #78906
# ---------------------------------------------------------------------------


def _native_authorize_params(challenge, **overrides):
    params = {
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "redirect_uri": "http://127.0.0.1:53999/cb",
        "state": "s",
    }
    params.update(overrides)
    return params


def test_native_authorize_mixed_providers_offers_both_choices(gated_client):
    """SSO-with-password-fallback (one OAuth + the bundled password provider): the desktop
    sends no ``provider``, so BOTH configured methods must stay reachable. #78906's symptom
    (a misleading ``Unknown provider: ''`` 404) stays fixed; the password option is no longer
    silently dropped by auto-selecting OAuth."""
    register_provider(_PasswordOnlyProvider())
    _verifier, challenge = _make_pkce()
    r = gated_client.get(
        "/auth/native/authorize", params=_native_authorize_params(challenge))
    assert r.status_code == 200, r.text
    hrefs = re.findall(r'<a class="provider-btn" href="([^"]+)"', r.text)
    assert {parse_qs(urlparse(html.unescape(h)).query)["provider"][0] for h in hrefs} == {
        "stub", "pwonly"}
    # Each link carries the desktop's PKCE inputs unchanged, and the chooser itself
    # allocates no broker state / sets no cookie.
    q = parse_qs(urlparse(html.unescape(hrefs[0])).query)
    assert q["code_challenge"] == [challenge] and q["code_challenge_method"] == ["S256"]
    assert "set-cookie" not in r.headers


def test_native_authorize_chooser_link_completes_the_native_flow(gated_client):
    """The chooser is inside the flow, not beside it: following an OAuth link re-enters the
    same validated route and starts the normal broker round trip."""
    register_provider(_PasswordOnlyProvider())
    _verifier, challenge = _make_pkce()
    r = gated_client.get(
        "/auth/native/authorize", params=_native_authorize_params(challenge))
    href = next(html.unescape(h) for h in
                re.findall(r'<a class="provider-btn" href="([^"]+)"', r.text)
                if "provider=stub" in h)
    follow = gated_client.get(href)
    assert follow.status_code == 302, follow.text
    assert "code=stub_code" in follow.headers["location"]


def test_native_authorize_empty_provider_auto_selects_single_oauth(gated_client):
    """The common hosted case: exactly one brokerable provider; an empty
    ``provider`` auto-selects it (302), so the desktop needn't hardcode the
    name."""
    _verifier, challenge = _make_pkce()
    r = gated_client.get(
        "/auth/native/authorize",
        params=_native_authorize_params(challenge),
    )
    assert r.status_code == 302, r.text
    assert "code=stub_code" in r.headers["location"]


def test_native_authorize_empty_provider_multiple_oauth_offers_a_choice(gated_client):
    """Two brokerable providers: the empty-provider convenience cannot pick unambiguously, so
    the user chooses in the browser instead of the desktop eating a 404."""
    register_provider(_SecondStubProvider())
    _verifier, challenge = _make_pkce()
    r = gated_client.get(
        "/auth/native/authorize",
        params=_native_authorize_params(challenge),
    )
    assert r.status_code == 200, r.text
    assert r.text.count('class="provider-btn"') == 2


def test_native_authorize_empty_provider_password_only_brokers_to_login(
    gated_client,
):
    """Password-only deployment: an empty ``provider`` selects the lone
    session provider and — now that native sign-in brokers password
    providers through the system browser — 302s to ``/login`` with the
    broker in the PKCE cookie, rather than the old 400."""
    clear_providers()
    register_provider(_PasswordOnlyProvider())
    _verifier, challenge = _make_pkce()
    r = gated_client.get(
        "/auth/native/authorize",
        params=_native_authorize_params(challenge),
    )
    assert r.status_code == 302, r.text
    assert r.headers["location"].endswith("/login")
    set_cookie = r.headers.get("set-cookie", "")
    # The PKCE cookie value is URL-encoded on the wire; decode through
    # the real reader inverse before asserting the broker handle rides
    # in it.
    from hermes_cli.dashboard_auth.cookies import parse_pkce_payload
    wire_value = set_cookie.split("=", 1)[1].split(";", 1)[0]
    assert "broker" in parse_pkce_payload(wire_value)


# ---------------------------------------------------------------------------
# Cookieless bearer auth of a gated route — the core deliverable
# ---------------------------------------------------------------------------


def test_bearer_authenticates_gated_route_without_cookie(gated_client):
    """A desktop that redeemed tokens can call a gated route with only an
    ``Authorization: Bearer`` header — no cookie in the jar."""
    verifier, challenge = _make_pkce()
    code, _state = _walk_native_login(
        gated_client, redirect_uri="http://127.0.0.1:53999/cb",
        challenge=challenge,
    )
    tokens = gated_client.post(
        "/auth/native/token",
        json={"code": code, "code_verifier": verifier},
    ).json()
    at = tokens["access_token"]

    # /api/auth/me is gated; a cookieless request with the bearer must pass
    # and identify the user.
    r = gated_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {at}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["user_id"] == "stub-user-1"




# ---------------------------------------------------------------------------
# Capability advertisement on /api/status
# ---------------------------------------------------------------------------




def test_status_loopback_mode_has_no_auth_flows():
    clear_providers()
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.auth_required = False
    try:
        client = TestClient(web_server.app, base_url="http://127.0.0.1:8080")
        body = client.get("/api/status").json()
        assert body["auth_required"] is False
        assert body["auth_flows"] == []
    finally:
        web_server.app.state.auth_required = prev_required


# ---------------------------------------------------------------------------
# Native flow for password providers (system-browser autofill path)
# ---------------------------------------------------------------------------
#
# A password provider has no IDP round trip, but the native flow still buys
# the desktop the one thing an embedded webview can never have: the system
# browser's OS-password-manager autofill. /auth/native/authorize lands the
# browser on /login (broker_state in the PKCE cookie) and a successful
# /auth/password-login completes the pending authorization exactly like the
# OAuth callback does.


@pytest.fixture
def pw_gated_client():
    from hermes_cli.dashboard_auth.routes import _reset_password_rate_limit
    from tests.hermes_cli.test_dashboard_auth_password_login import (
        PasswordProvider,
    )

    clear_providers()
    register_provider(PasswordProvider())
    _reset_password_rate_limit()
    prev_host = getattr(web_server.app.state, "bound_host", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    client = TestClient(
        web_server.app, base_url="https://fly-app.fly.dev",
        follow_redirects=False,
    )
    yield client
    clear_providers()
    _reset_password_rate_limit()
    web_server.app.state.bound_host = prev_host
    web_server.app.state.bound_port = prev_port
    web_server.app.state.auth_required = prev_required


def test_status_advertises_native_pkce_for_password_only_gateway(
    pw_gated_client,
):
    body = pw_gated_client.get("/api/status").json()
    assert body["auth_required"] is True
    assert "cookie" in body["auth_flows"]
    assert "native_pkce" in body["auth_flows"]


def test_native_authorize_password_provider_redirects_to_login(
    pw_gated_client,
):
    """Empty ``provider`` auto-picks the single password provider and lands
    the system browser on /login with the broker in the PKCE cookie."""
    _verifier, challenge = _make_pkce()
    r = pw_gated_client.get(
        "/auth/native/authorize",
        params={
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "http://127.0.0.1:53999/cb",
            "state": "desk-state",
        },
    )
    assert r.status_code == 302, r.text
    assert r.headers["location"].endswith("/login")
    set_cookie = r.headers.get("set-cookie", "")
    assert "pkce" in set_cookie
    # Wire value is URL-encoded; decode through the reader inverse.
    from hermes_cli.dashboard_auth.cookies import parse_pkce_payload
    wire_value = set_cookie.split("=", 1)[1].split(";", 1)[0]
    assert "broker" in parse_pkce_payload(wire_value)


def _start_native_password_login(client, *, challenge, state="desk-state"):
    r = client.get(
        "/auth/native/authorize",
        params={
            "provider": "testpw",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "http://127.0.0.1:53999/cb",
            "state": state,
        },
    )
    assert r.status_code == 302, r.text
    return r.cookies


def test_native_password_login_full_roundtrip(pw_gated_client):
    """authorize → /login → password-login → loopback code → bearer tokens."""
    verifier, challenge = _make_pkce()
    cookies = _start_native_password_login(pw_gated_client, challenge=challenge)

    # The browser form POSTs the credentials; the PKCE cookie rides along.
    r = pw_gated_client.post(
        "/auth/password-login",
        json={"provider": "testpw", "username": "admin", "password": "hunter2"},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    # ``next`` is the desktop's loopback redirect carrying code + state —
    # NOT a dashboard path.
    assert body["next"].startswith("http://127.0.0.1:53999/cb?")
    qs = parse_qs(urlparse(body["next"]).query)
    assert qs["state"][0] == "desk-state"
    code = qs["code"][0]
    # No browser session on the native branch; the PKCE cookie is cleared.
    set_cookie = r.headers.get("set-cookie", "")
    assert "hermes_session_at" not in set_cookie, (
        f"native password login must NOT set a session cookie; got {set_cookie!r}"
    )
    assert "pkce" in set_cookie  # the clearing Set-Cookie

    # Desktop redeems the loopback code with its PKCE verifier.
    tokens = pw_gated_client.post(
        "/auth/native/token",
        json={"code": code, "code_verifier": verifier},
    ).json()
    assert tokens["provider"] == "testpw"
    assert tokens["user_id"] == "admin"

    # Cookieless bearer auth of a gated route — the point of the flow.
    r2 = pw_gated_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["user_id"] == "admin"


def test_native_password_login_wrong_password_keeps_pending(pw_gated_client):
    """A failed credential attempt must not consume the pending
    authorization — the user retypes and succeeds on the same broker."""
    verifier, challenge = _make_pkce()
    cookies = _start_native_password_login(pw_gated_client, challenge=challenge)

    r = pw_gated_client.post(
        "/auth/password-login",
        json={"provider": "testpw", "username": "admin", "password": "wrong"},
        cookies=cookies,
    )
    assert r.status_code == 401

    r2 = pw_gated_client.post(
        "/auth/password-login",
        json={"provider": "testpw", "username": "admin", "password": "hunter2"},
        cookies=cookies,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["next"].startswith("http://127.0.0.1:53999/cb?")


def test_native_password_login_expired_broker_returns_400(pw_gated_client):
    """A broker cookie whose pending entry lapsed (TTL) is a clean 400
    telling the user to restart sign-in — never a silent cookie login."""
    _verifier, challenge = _make_pkce()
    cookies = _start_native_password_login(pw_gated_client, challenge=challenge)

    native_flow._reset_for_tests()  # simulate the pending TTL lapsing

    r = pw_gated_client.post(
        "/auth/password-login",
        json={"provider": "testpw", "username": "admin", "password": "hunter2"},
        cookies=cookies,
    )
    assert r.status_code == 400
    assert "restart" in r.json()["detail"].lower()


def test_native_password_login_rejects_cross_provider_completion(
    pw_gated_client,
):
    """A native flow started for provider A must not be completable with
    provider B's credentials: /login renders every provider's form, and the
    pending authorization is bound to the provider recorded in the
    server-set PKCE cookie. The mismatch is rejected BEFORE credential
    verification and preserves the pending entry, so the user can still
    submit the form the flow was started for."""
    from tests.hermes_cli.test_dashboard_auth_password_login import (
        PasswordProvider,
    )

    class SecondPasswordProvider(PasswordProvider):
        name = "testpw2"
        display_name = "Test Password 2"

    register_provider(SecondPasswordProvider())

    verifier, challenge = _make_pkce()
    # Native flow initiated for provider A ("testpw").
    cookies = _start_native_password_login(pw_gated_client, challenge=challenge)

    # Valid credentials for provider B ("testpw2") must NOT complete A's
    # pending authorization.
    r = pw_gated_client.post(
        "/auth/password-login",
        json={
            "provider": "testpw2", "username": "admin", "password": "hunter2",
        },
        cookies=cookies,
    )
    assert r.status_code == 400, r.text
    assert "different provider" in r.json()["detail"]
    set_cookie = r.headers.get("set-cookie", "")
    assert "hermes_session_at" not in set_cookie

    # The pending entry survived — provider A completes normally.
    r2 = pw_gated_client.post(
        "/auth/password-login",
        json={
            "provider": "testpw", "username": "admin", "password": "hunter2",
        },
        cookies=cookies,
    )
    assert r2.status_code == 200, r2.text
    qs = parse_qs(urlparse(r2.json()["next"]).query)
    tokens = pw_gated_client.post(
        "/auth/native/token",
        json={"code": qs["code"][0], "code_verifier": verifier},
    ).json()
    assert tokens["provider"] == "testpw"


def test_password_login_without_broker_still_mints_cookies(pw_gated_client):
    """Guard: an ordinary browser password login (no native broker cookie)
    keeps the existing cookie-minting behaviour."""
    r = pw_gated_client.post(
        "/auth/password-login",
        json={"provider": "testpw", "username": "admin", "password": "hunter2"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["next"] == "/"
    set_cookie = r.headers.get("set-cookie", "")
    assert "hermes_session_at" in set_cookie


# ---------------------------------------------------------------------------
# Native refresh
# ---------------------------------------------------------------------------


def test_native_refresh_dead_token_returns_401(gated_client):
    r = gated_client.post(
        "/auth/native/refresh",
        json={"refresh_token": "garbage-not-a-real-rt", "provider": "stub"},
    )
    assert r.status_code == 401
    assert r.json()["error"] == "session_expired"


# ---------------------------------------------------------------------------
# Native revoke
# ---------------------------------------------------------------------------

_OIDC_ISSUER = "https://auth.example.com/application/o/hermes"


def _oidc_provider():
    """The bundled self-hosted OIDC provider with discovery pre-seeded (no network); its
    discovery advertises an RFC 7009 revocation endpoint."""
    import plugins.dashboard_auth.self_hosted as oidc_plugin

    p = oidc_plugin.SelfHostedOIDCProvider(issuer=_OIDC_ISSUER, client_id="hermes-dashboard")
    p._discovery = {
        "issuer": _OIDC_ISSUER,
        "authorization_endpoint": f"{_OIDC_ISSUER}/authorize",
        "token_endpoint": f"{_OIDC_ISSUER}/token",
        "jwks_uri": f"{_OIDC_ISSUER}/jwks",
        "revocation_endpoint": f"{_OIDC_ISSUER}/revoke",
    }
    p._discovery_fetched_at = time.time()
    return p


def _basic_provider():
    import plugins.dashboard_auth.basic as basic_plugin

    return basic_plugin.BasicAuthProvider(
        username="admin", password_hash=basic_plugin.hash_password("hunter2"),
        secret=secrets.token_bytes(32))


def _nous_provider():
    import plugins.dashboard_auth.nous as nous_plugin

    return nous_plugin.NousDashboardAuthProvider(
        client_id="agent:inst123", portal_url="https://portal.example.com")


@pytest.fixture
def outbound(monkeypatch):
    """Every outbound HTTP call a provider could make, recorded instead of sent."""
    calls = {"post": MagicMock(return_value=MagicMock(spec=httpx.Response, status_code=200)),
             "get": MagicMock(side_effect=AssertionError("no discovery fetch expected"))}
    monkeypatch.setattr(httpx, "post", calls["post"])
    monkeypatch.setattr(httpx, "get", calls["get"])
    return calls


def _gated(*providers) -> TestClient:
    """A gated app with exactly ``providers`` registered; ``_reset_broker`` restores state."""
    clear_providers()
    for provider in providers:
        register_provider(provider)
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    return TestClient(web_server.app, base_url="https://fly-app.fly.dev", follow_redirects=False)


def test_native_revoke_hands_the_token_to_the_oidc_revocation_endpoint_once(outbound):
    client = _gated(_basic_provider(), _oidc_provider())
    # No cookie and no bearer: the gate is engaged and turns this client away elsewhere.
    assert client.get("/api/auth/me").status_code == 401

    r = client.post("/auth/native/revoke",
                    json={"refresh_token": "oidc-rt-live", "provider": "self-hosted"})

    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True}
    outbound["post"].assert_called_once()
    args, kwargs = outbound["post"].call_args
    assert args[0] == f"{_OIDC_ISSUER}/revoke"
    assert kwargs["data"]["token"] == "oidc-rt-live"
    assert kwargs["data"]["token_type_hint"] == "refresh_token"
    assert kwargs["data"]["client_id"] == "hermes-dashboard"


@pytest.mark.parametrize("make_provider", [_basic_provider, _nous_provider],
                         ids=["basic", "nous"])
def test_native_revoke_at_a_provider_without_revocation_is_ok_and_sends_nothing(
        outbound, make_provider):
    """``basic`` (stateless) and Nous (no revocation grant) revoke nothing, and their token is
    not handed to the OIDC provider registered beside them: that would disclose a live
    credential to another identity provider."""
    provider = make_provider()
    client = _gated(_oidc_provider(), provider)

    r = client.post("/auth/native/revoke",
                    json={"refresh_token": f"{provider.name}-rt", "provider": provider.name})

    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True}
    outbound["post"].assert_not_called()


def test_native_revoke_answers_an_unknown_token_like_a_live_one(gated_client):
    verifier, challenge = _make_pkce()
    code, _state = _walk_native_login(
        gated_client, redirect_uri="http://127.0.0.1:53999/cb", challenge=challenge)
    live = gated_client.post(
        "/auth/native/token", json={"code": code, "code_verifier": verifier}).json()

    answers = [gated_client.post("/auth/native/revoke", json=body)
               for body in ({"refresh_token": live["refresh_token"], "provider": "stub"},
                            {"refresh_token": "never-issued", "provider": "stub"},
                            {"refresh_token": "never-issued", "provider": "no-such-provider"})]

    assert {(r.status_code, r.text) for r in answers} == {(200, json.dumps({"ok": True}, separators=(",", ":")))}


class _RevocableStub(StubAuthProvider):
    """A rotating identity provider with RFC 7009 revocation: a refresh token is spent by the
    refresh that rotates it, and a revoke ends it."""

    def __init__(self):
        super().__init__()
        self.revoked: set[str] = set()

    def refresh_session(self, *, refresh_token):
        if refresh_token in self.revoked:
            raise RefreshExpiredError("revoked")
        self.revoked.add(refresh_token)
        session = super().refresh_session(refresh_token=refresh_token)
        # The stub's tokens carry only second-resolution claims; make each rotation unique.
        import dataclasses
        return dataclasses.replace(session, refresh_token=f"{session.refresh_token}.{secrets.token_hex(4)}")

    def revoke_session(self, *, refresh_token):
        self.revoked.add(refresh_token)


def test_native_refresh_after_revoke_is_not_served_from_the_replay_cache():
    """A refresh is cached for its burst; a revoke must end that too, or the revoked token keeps
    minting sessions for the rest of the window."""
    client = _gated(_RevocableStub())
    verifier, challenge = _make_pkce()
    code, _state = _walk_native_login(
        client, redirect_uri="http://127.0.0.1:53999/cb", challenge=challenge)
    rt = client.post("/auth/native/token", json={"code": code, "code_verifier": verifier}
                     ).json()["refresh_token"]
    assert client.post("/auth/native/refresh",
                       json={"refresh_token": rt, "provider": "stub"}).status_code == 200

    assert client.post("/auth/native/revoke",
                       json={"refresh_token": rt, "provider": "stub"}).status_code == 200

    r = client.post("/auth/native/refresh", json={"refresh_token": rt, "provider": "stub"})
    assert r.status_code == 401, r.text
    assert r.json()["error"] == "session_expired"


def test_native_revoke_audit_and_log_never_carry_the_token(gated_client, caplog):
    import os
    from pathlib import Path

    token = "secret-refresh-token-value-0123456789"
    with caplog.at_level(logging.DEBUG):
        r = gated_client.post("/auth/native/revoke",
                              json={"refresh_token": token, "provider": "stub"})
    assert r.status_code == 200

    log_path = Path(os.environ["HERMES_HOME"]) / "logs" / "dashboard-auth.log"
    text = log_path.read_text()
    events = [json.loads(line) for line in text.splitlines()]
    assert [e for e in events if e["event"] == "revoke"] == [
        {**events[-1], "event": "revoke", "flow": "native", "providers": ["stub"]}]
    digest = hashlib.sha256(token.encode()).hexdigest()
    for haystack in (text, caplog.text):
        assert token not in haystack
        assert digest[:8] not in haystack


def test_native_revoke_refuses_oversized_bodies_and_other_methods(gated_client):
    big = {"refresh_token": "x" * (64 * 1024), "provider": "stub"}
    assert gated_client.post("/auth/native/revoke", json=big).status_code == 413
    # Chunked, so no Content-Length announces the size: refused while reading.
    chunked = gated_client.post(
        "/auth/native/revoke", headers={"Content-Type": "application/json"},
        content=iter([json.dumps(big).encode()[i:i + 4096] for i in range(0, 70 * 1024, 4096)]))
    assert chunked.status_code == 413
    # Only POST reaches the handler (a GET falls through to the SPA's 404, as for refresh).
    for method in ("get", "put", "delete"):
        assert getattr(gated_client, method)("/auth/native/revoke").status_code in (404, 405)
    assert gated_client.post("/auth/native/revoke", json={"provider": "stub"}).status_code == 400


@pytest.mark.parametrize("raw", [
    b"{not json", b"[]", b'"rt"', b"[" * 5000, b'{"a":' * 3000,
    b'{"refresh_token": "rt-x", "provider": 7}',
    b'{"refresh_token": "rt-x"}', b'{"refresh_token": "rt-x", "provider": null}',
    b'{"refresh_token": "rt-x", "provider": ""}',
], ids=["malformed", "array", "string", "deep-array", "deep-object", "provider-number",
        "provider-missing", "provider-null", "provider-empty"])
def test_native_revoke_answers_a_malformed_body_400(gated_client, raw):
    """Never a 500: an unhandled error would flip /api/status to degraded for anyone."""
    r = gated_client.post("/auth/native/revoke", content=raw,
                          headers={"Content-Type": "application/json"})
    assert r.status_code == 400, r.text


def test_native_revoke_with_an_unknown_provider_name_reaches_every_provider():
    class _Recording(StubAuthProvider):
        def __init__(self, name):
            super().__init__()
            self.name, self.seen = name, []

        def revoke_session(self, *, refresh_token):
            self.seen.append(refresh_token)

    first, second = _Recording("one"), _Recording("two")
    client = _gated(first, second)

    r = client.post("/auth/native/revoke", json={"refresh_token": "rt-u", "provider": "gone"})

    assert r.json() == {"ok": True}
    assert first.seen == second.seen == ["rt-u"]


def test_native_revoke_survives_a_provider_that_raises_and_logs_only_its_class(caplog):
    class _Exploding(StubAuthProvider):
        def revoke_session(self, *, refresh_token):
            raise RuntimeError(f"upstream said no to {refresh_token} body=<secret>")

    client = _gated(_Exploding())
    with caplog.at_level(logging.DEBUG):
        r = client.post("/auth/native/revoke", json={"refresh_token": "rt-boom", "provider": "stub"})

    assert r.status_code == 200 and r.json() == {"ok": True}
    assert "RuntimeError" in caplog.text
    assert "rt-boom" not in caplog.text and "<secret>" not in caplog.text


def test_native_revoke_drops_the_cached_burst_that_handed_out_the_revoked_token():
    """The client revokes its CURRENT token RT2. The burst cache keyed by the previous RT1 holds
    the session carrying RT2 and must not keep handing it out."""
    client = _gated(_RevocableStub())
    verifier, challenge = _make_pkce()
    code, _state = _walk_native_login(
        client, redirect_uri="http://127.0.0.1:53999/cb", challenge=challenge)
    rt1 = client.post("/auth/native/token", json={"code": code, "code_verifier": verifier}
                      ).json()["refresh_token"]
    rotated = client.post("/auth/native/refresh", json={"refresh_token": rt1, "provider": "stub"})
    rt2 = rotated.json()["refresh_token"]
    assert rt2 != rt1

    assert client.post("/auth/native/revoke",
                       json={"refresh_token": rt2, "provider": "stub"}).status_code == 200

    replay = client.post("/auth/native/refresh", json={"refresh_token": rt1, "provider": "stub"})
    assert replay.status_code == 401, replay.text


def test_native_revoke_from_a_foreign_web_origin_is_refused_when_the_check_is_on(monkeypatch):
    primary, other = "https://hermes.example.test", "https://app.example.test"
    monkeypatch.delenv("HERMES_DASHBOARD_PUBLIC_URL", raising=False)
    monkeypatch.setattr("hermes_cli.config.load_config",
                        lambda: {"dashboard": {"public_url": primary, "public_urls": [other]}})
    for name in ("trusted_public_hosts", "public_origins", "write_origin_check"):
        monkeypatch.setattr(web_server.app.state, name,
                            getattr(web_server.app.state, name, None), raising=False)
    clear_providers()
    register_provider(StubAuthProvider())
    web_server.app.state.bound_host = "127.0.0.1"
    web_server._configure_auth_gate("127.0.0.1", False, None, None)
    assert web_server.app.state.write_origin_check and web_server.app.state.auth_required
    client = TestClient(web_server.app, base_url=primary)
    body = {"refresh_token": "rt-o", "provider": "stub"}

    foreign = client.post("/auth/native/revoke", json=body,
                          headers={"Origin": "https://evil.example.test"})
    native = client.post("/auth/native/revoke", json=body)  # a native client sends no Origin

    assert foreign.status_code == 403
    assert native.status_code == 200 and native.json() == {"ok": True}


def test_paths_that_merely_start_like_the_revoke_route_expose_nothing(gated_client):
    """The gate's public list is prefix-matched; nothing may live behind the revoke prefix."""
    for path in ("/auth/native/revoke-x", "/auth/native/revoke/x", "/auth/native/revokeall"):
        assert gated_client.post(path, json={"refresh_token": "rt", "provider": "stub"}
                                 ).status_code in (404, 405), path
        r = gated_client.get(path)
        assert r.status_code == 404 or "refresh_token" not in r.text, path


def _behind_uvicorn(peer: str) -> TestClient:
    """The gated app as uvicorn serves it, with socket peer ``peer`` and loopback as the only
    trusted proxy (the default ``forwarded_allow_ips``)."""
    import uvicorn

    config = uvicorn.Config(web_server.app, proxy_headers=True, log_config=None,
                            forwarded_allow_ips=["127.0.0.1", "::1"])
    config.load()
    return TestClient(config.loaded_app, base_url="https://fly-app.fly.dev", client=(peer, 50000))


def _revoke_codes(client, count, **headers):
    body = {"refresh_token": "rt-burst", "provider": "stub"}
    return [client.post("/auth/native/revoke", json=body, headers=headers).status_code
            for _ in range(count)]


def test_native_revoke_is_rate_limited_per_address(gated_client, caplog):
    from hermes_cli.dashboard_auth.routes import _REVOKE_RATE_MAX

    codes = _revoke_codes(gated_client, _REVOKE_RATE_MAX + 3)

    assert set(codes[:_REVOKE_RATE_MAX]) == {200}
    assert set(codes[_REVOKE_RATE_MAX:]) == {429}
    import os
    from pathlib import Path
    events = [json.loads(line) for line in
              (Path(os.environ["HERMES_HOME"]) / "logs" / "dashboard-auth.log").read_text().splitlines()]
    assert len([e for e in events if e.get("reason") == "rate_limited"]) == 1


def test_a_forged_forwarded_for_neither_escapes_nor_spends_another_address_budget(gated_client):
    from hermes_cli.dashboard_auth.routes import _REVOKE_RATE_MAX

    attacker = _behind_uvicorn("203.0.113.66")
    # (a) a fresh X-Forwarded-For per request from an untrusted peer is ignored: one bucket.
    codes = [attacker.post("/auth/native/revoke",
                           json={"refresh_token": "rt-burst", "provider": "stub"},
                           headers={"X-Forwarded-For": f"10.0.{i // 250}.{i % 250}"}).status_code
             for i in range(_REVOKE_RATE_MAX + 1)]
    assert codes[-1] == 429
    # (c) naming the victim does not spend the victim's budget, directly or through the proxy,
    # which appends the attacker's real address that uvicorn then takes as the client.
    via_proxy = _behind_uvicorn("127.0.0.1")
    _revoke_codes(via_proxy, _REVOKE_RATE_MAX + 1, **{"X-Forwarded-For": "198.51.100.7, 203.0.113.77"})
    assert _revoke_codes(_behind_uvicorn("198.51.100.7"), 1) == [200]
    assert _revoke_codes(via_proxy, 1, **{"X-Forwarded-For": "198.51.100.7"}) == [200]


def test_status_advertises_native_revoke_only_when_gated(gated_client):
    assert "native_revoke" in gated_client.get("/api/status").json()["auth_flows"]
    web_server.app.state.auth_required = False
    assert "native_revoke" not in gated_client.get("/api/status").json()["auth_flows"]
