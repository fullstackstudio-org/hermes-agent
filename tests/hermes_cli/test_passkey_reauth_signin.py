"""Passkey self-enrolment, the sign-in side: ``reauth=`` on ``/auth/login`` and ``/auth/native/authorize``, the
callback and the password login completing a web grant, and ``/auth/native/token`` completing a native one
without handing out tokens (``hermes_cli/dashboard_auth/passkeys/reauth.py`` and ``routes.py``).

Pinned here: the grant check runs before any redirect or cookie; a web grant only starts and completes from
the browser holding its ``__Host-hermes_reauth`` cookie (a link to it completes nothing, a tossed weaker cookie
does not count); a native grant only through the native route, a web grant only through the web route; the
same-person, same-provider and freshness rules; a failed grant never undoes the sign-in; single use; the
refusal budget; nothing secret in the audit log; and every route without ``reauth`` exactly as before.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, native_flow, register_provider
from hermes_cli.dashboard_auth.base import DashboardAuthProvider, InvalidCredentialsError, LoginStart, Session
from hermes_cli.dashboard_auth.cookies import parse_pkce_payload
from hermes_cli.dashboard_auth.passkeys import reauth
from hermes_cli.dashboard_auth.passkeys import routes as passkey_routes
from hermes_cli.dashboard_auth.passkeys.store import REAUTH_SKEW, PasskeyStore
from hermes_cli.dashboard_auth.routes import _reset_password_rate_limit
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider, _sign, _unsign

BASE = "https://fly-app.fly.dev"
ALICE = "idp:alice"
HOST_COOKIE = "__Host-hermes_reauth"
LOOPBACK = "http://127.0.0.1:53999/cb"


# ── providers ────────────────────────────────────────────────────────────────────────────────────


class ReauthIdP(DashboardAuthProvider):
    """An OIDC-like provider that can re-authenticate: bounces straight back to the callback and reports
    whichever person and ``auth_time`` the test sets. Records how ``start_login`` was called."""

    name = "idp"
    display_name = "Reauth IdP"
    supports_reauth = True

    def __init__(self):
        self.user = "alice"
        self.auth_time: int | None = None  # None: now
        self.starts: list[bool] = []
        self.revoked: list[str] = []
        self._verifiers: dict[str, str] = {}

    def start_login(self, *, redirect_uri: str, fresh: bool = False) -> LoginStart:
        self.starts.append(fresh)
        state, verifier = secrets.token_urlsafe(16), secrets.token_urlsafe(32)
        self._verifiers[state] = verifier
        return LoginStart(redirect_url=f"{redirect_uri}?code=c&state={state}",
                          cookie_payload={"hermes_session_pkce": f"state={state};verifier={verifier}"})

    def complete_login(self, *, code, state, code_verifier, redirect_uri) -> Session:
        assert self._verifiers.pop(state) == code_verifier
        return self._session(int(time.time()) if self.auth_time is None else self.auth_time)

    def _session(self, auth_time: int) -> Session:
        exp = int(time.time()) + 3600
        return Session(user_id=self.user, email="", display_name=self.user.title(), org_id="", provider=self.name,
                       expires_at=exp, access_token=_sign({"sub": self.user, "email": "", "name": self.user,
                                                           "org_id": "", "exp": exp}),
                       refresh_token=_sign({"sub": self.user, "kind": "refresh", "exp": exp}), auth_time=auth_time)

    def verify_session(self, *, access_token: str):
        payload = _unsign(access_token)
        if payload is None or payload.get("exp", 0) <= int(time.time()):
            return None
        return self._session(0)

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError

    def revoke_session(self, *, refresh_token: str) -> None:
        self.revoked.append(refresh_token)


class ReauthPassword(DashboardAuthProvider):
    """A password provider (admin / hunter2) that, like ``basic``, reports the password check as the
    authentication time."""

    name = "pw"
    display_name = "Password"
    supports_password = True
    supports_reauth = True

    def start_login(self, *, redirect_uri: str, fresh: bool = False):
        raise AssertionError("a password provider is never sent to an IdP")

    def complete_login(self, **kwargs):
        raise NotImplementedError

    def complete_password_login(self, *, username: str, password: str) -> Session:
        if (username, password) != ("admin", "hunter2"):
            raise InvalidCredentialsError("bad")
        exp = int(time.time()) + 3600
        return Session(user_id="admin", email="", display_name="admin", org_id="", provider=self.name,
                       expires_at=exp, access_token=_sign({"sub": "admin", "exp": exp}), refresh_token="",
                       auth_time=int(time.time()))

    def verify_session(self, *, access_token: str):
        return None

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError

    def revoke_session(self, *, refresh_token: str) -> None:
        return None


# ── fixture ──────────────────────────────────────────────────────────────────────────────────────


class Gateway:
    def __init__(self, client: TestClient, store: PasskeyStore, idp: ReauthIdP, config: dict, clock):
        self.client, self.store, self.idp, self.config, self.clock = client, store, idp, config, clock

    def browser(self) -> TestClient:
        """A second, independent browser (its own cookie jar)."""
        return TestClient(web_server.app, base_url=BASE, follow_redirects=False)

    def open_web(self, user: str = ALICE, provider: str = "idp", client: TestClient | None = None) -> str:
        """What ``reauth/begin`` does for a cookie caller: open a web grant, set its cookie in *client*."""
        opened = reauth.open_grant(store=self.store, user_id=user, provider=provider, client="web", ip="t")
        (client or self.client).cookies.set(HOST_COOKIE, opened.secret)
        return opened.grant.id

    def open_native(self, user: str = ALICE, provider: str = "idp") -> str:
        return reauth.open_grant(store=self.store, user_id=user, provider=provider, client="native").grant.id

    def state(self, grant_id: str, user: str = ALICE):
        grant = self.store.grant(grant_id, user_id=user)
        return (grant.state, grant.failure) if grant else None

    def web_login(self, grant_id: str, client: TestClient | None = None, provider: str = "idp", next_: str = "/s"):
        c = client or self.client
        return c.get("/auth/login", params={"provider": provider, "reauth": grant_id, "next": next_})

    def callback(self, start, client: TestClient | None = None):
        q = parse_qs(urlparse(start.headers["location"]).query)
        return (client or self.client).get("/auth/callback", params={"code": q["code"][0], "state": q["state"][0]})


class Clock:
    def __init__(self):
        self.offset = 0.0

    def __call__(self) -> float:
        return time.time() + self.offset


@pytest.fixture
def gw(monkeypatch, tmp_path):
    clear_providers()
    idp = ReauthIdP()
    register_provider(idp)
    register_provider(ReauthPassword())
    register_provider(StubAuthProvider())  # "stub": no re-authentication, old start_login signature
    native_flow._reset_for_tests()
    reauth.reset_for_tests()
    _reset_password_rate_limit()
    config = {"confirm": {"passkey": {"enabled": True, "base_urls": [BASE]}}}
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: copy.deepcopy(config))
    for name in ("auth_required", "bound_host", "bound_port"):
        monkeypatch.setattr(web_server.app.state, name, getattr(web_server.app.state, name, None), raising=False)
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    clock = Clock()
    store = PasskeyStore(tmp_path / "dashboard_auth" / "passkeys.db", clock=clock)
    monkeypatch.setattr(passkey_routes, "_store", lambda: store)
    yield Gateway(TestClient(web_server.app, base_url=BASE, follow_redirects=False), store, idp, config, clock)
    native_flow._reset_for_tests()
    reauth.reset_for_tests()
    _reset_password_rate_limit()
    clear_providers()


def audit_lines(event: str | None = None) -> list[dict]:
    from hermes_constants import get_hermes_home

    path = get_hermes_home() / "logs" / "dashboard-auth.log"
    lines = [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
    return [x for x in lines if event is None or x["event"] == event]


def set_cookies(response) -> list[str]:
    return response.headers.get_list("set-cookie")


def pkce_of(response) -> dict:
    for header in set_cookies(response):
        name, _, rest = header.partition("=")
        if name.endswith("hermes_session_pkce") and rest.split(";", 1)[0]:
            return parse_pkce_payload(rest.split(";", 1)[0])
    return {}


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize(client: TestClient, challenge: str, **params):
    return client.get("/auth/native/authorize", params={
        "code_challenge": challenge, "code_challenge_method": "S256", "redirect_uri": LOOPBACK,
        "state": "app-state", **params})


def loopback_code(response) -> str:
    location = response.headers["location"] if response.status_code == 302 else response.json()["next"]
    assert location.startswith(LOOPBACK), location
    return parse_qs(urlparse(location).query)["code"][0]


# ── web, OIDC ────────────────────────────────────────────────────────────────────────────────────


def test_web_reauth_round_trip_completes_the_grant_and_the_login(gw):
    grant_id = gw.open_web()
    start = gw.web_login(grant_id, next_="/settings/passkeys")
    assert start.status_code == 302
    assert gw.idp.starts == [True]  # prompt=login / max_age=0 asked for
    pkce = pkce_of(start)
    assert pkce["reauth"] == grant_id and pkce["next"] == "/settings/passkeys" and "broker" not in pkce

    done = gw.callback(start)
    assert done.status_code == 302 and done.headers["location"] == "/settings/passkeys"
    cookies = set_cookies(done)
    assert any(c.startswith("__Host-hermes_session_at=") and "Max-Age=0" not in c for c in cookies)
    # A fresh grant keeps its cookie: it is the use binding until register/finish spends the grant.
    assert not [c for c in cookies if c.startswith(f"{HOST_COOKIE}=")]
    assert gw.client.cookies.get(HOST_COOKIE)
    assert gw.state(grant_id) == ("fresh", "")
    fresh = audit_lines("passkey_reauth_fresh")
    assert fresh[-1]["grant"] == grant_id[:8] and fresh[-1]["client"] == "web" and fresh[-1]["user_id"] == ALICE


def test_web_reauth_start_without_the_cookie_is_400_before_any_redirect_or_cookie(gw):
    grant_id = gw.open_web()  # opened in gw.client; the victim's browser below never had the cookie
    victim = gw.browser()
    r = gw.web_login(grant_id, client=victim)
    assert r.status_code == 400 and "location" not in r.headers
    assert set_cookies(r) == []
    assert "expired or was not started here" in r.text and r.headers["content-type"].startswith("text/html")
    assert gw.idp.starts == []
    assert gw.state(grant_id) == ("open", "")
    assert audit_lines("passkey_reauth_refused")[-1]["reason"] == "client_mismatch"


def test_web_reauth_start_with_another_grants_cookie_is_refused(gw):
    grant_id = gw.open_web()
    gw.open_web()  # a second grant overwrote the cookie in this browser
    r = gw.web_login(grant_id)
    assert r.status_code == 400 and gw.idp.starts == []


def test_a_tossed_weaker_cookie_does_not_stand_in_for_the_host_cookie(gw):
    opened = reauth.open_grant(store=gw.store, user_id=ALICE, provider="idp", client="web")
    for name in ("hermes_reauth", "__Secure-hermes_reauth"):
        browser = gw.browser()
        browser.cookies.set(name, opened.secret)
        assert gw.web_login(opened.grant.id, client=browser).status_code == 400
    assert gw.idp.starts == []


def test_link_attack_callback_without_the_reauth_cookie_completes_the_login_not_the_grant(gw):
    """Session A opened grant G (A's browser holds the cookie). The callback reaches the gateway from a
    browser without that cookie: the person is signed in, the grant is not completed (the store lets no
    one without the binding change it), and the refusal is audited as ``client_mismatch``."""
    grant_id = gw.open_web()
    start = gw.web_login(grant_id)
    assert start.status_code == 302
    gw.client.cookies.delete(HOST_COOKIE)
    done = gw.callback(start)
    assert done.status_code == 302 and done.headers["location"] == "/s"
    assert any(c.startswith("__Host-hermes_session_at=") for c in set_cookies(done))
    assert gw.state(grant_id) == ("open", "")
    refused = audit_lines("passkey_reauth_refused")[-1]
    assert refused["reason"] == "client_mismatch" and refused["at"] == "complete"
    with pytest.raises(Exception) as err:  # and the grant id alone uses nothing
        gw.store.fresh_grant(grant_id, user_id=ALICE, secret=None)
    assert getattr(err.value, "reason", "") == "unknown"


def test_a_sign_in_as_someone_else_fails_the_grant_but_signs_them_in(gw):
    grant_id = gw.open_web()
    gw.idp.user = "bob"
    done = gw.callback(gw.web_login(grant_id))
    assert done.status_code == 302 and any(c.startswith("__Host-hermes_session_at=") for c in set_cookies(done))
    assert gw.state(grant_id) == ("failed", "user_mismatch")
    # The cookie stays until it expires (or a sign-out): with it the browser can learn why the grant failed;
    # the grant itself can never be used.
    assert not any(c.startswith(f"{HOST_COOKIE}=") for c in set_cookies(done))


@pytest.mark.parametrize("offset, accept, expected", [
    (-3600, False, ("failed", "auth_not_fresh")),          # the IdP reused an old sign-in
    (-(REAUTH_SKEW + 5), False, ("failed", "auth_not_fresh")),
    (-(REAUTH_SKEW - 5), False, ("fresh", "")),             # inside the clock-skew allowance
    (None, False, ("failed", "auth_time_missing")),
    (None, True, ("fresh", "")),                            # the operator accepts a missing auth_time
])
def test_auth_time_rules(gw, offset, accept, expected):
    if accept:
        gw.config["confirm"]["passkey"]["self_enrol"] = {"accept_missing_auth_time": True}
    grant_id = gw.open_web()
    created = gw.store.grant(grant_id, user_id=ALICE).created_at
    gw.idp.auth_time = 0 if offset is None else created + offset
    done = gw.callback(gw.web_login(grant_id))
    assert done.status_code == 302
    assert gw.state(grant_id) == expected
    if accept:
        assert gw.store.grant(grant_id, user_id=ALICE).auth_time_assumed is True
        assert audit_lines("passkey_reauth_fresh")[-1]["auth_time_assumed"] is True


def test_a_native_grant_cannot_start_through_the_web_route(gw):
    grant_id = gw.open_native()
    assert gw.web_login(grant_id).status_code == 400  # no cookie, and the grant is not a web grant
    gw.client.cookies.set(HOST_COOKIE, "x" * 43)
    assert gw.web_login(grant_id).status_code == 400
    assert gw.idp.starts == [] and gw.state(grant_id) == ("open", "")


def test_a_grant_is_single_use_and_expires(gw):
    opened = reauth.open_grant(store=gw.store, user_id=ALICE, provider="idp", client="web")
    gw.client.cookies.set(HOST_COOKIE, opened.secret)
    gw.callback(gw.web_login(opened.grant.id))
    assert gw.state(opened.grant.id) == ("fresh", "")
    # The completion cleared the cookie; with it put back, a completed grant still starts nothing.
    gw.client.cookies.set(HOST_COOKIE, opened.secret)
    assert gw.web_login(opened.grant.id).status_code == 400
    late = gw.open_web()
    gw.clock.offset = 601
    assert gw.web_login(late).status_code == 400  # expired
    assert gw.idp.starts == [True]


def test_the_grant_must_be_for_the_provider_signed_in_with(gw):
    grant_id = gw.open_web(provider="pw", user="pw:admin")
    assert gw.web_login(grant_id, provider="idp").status_code == 400
    assert gw.idp.starts == []


@pytest.mark.parametrize("change", ["level_off", "self_enrol_off"])
def test_no_grant_starts_while_the_level_or_self_enrolment_is_off(gw, change):
    grant_id = gw.open_web()
    if change == "level_off":
        gw.config["confirm"]["passkey"]["enabled"] = False
    else:
        gw.config["confirm"]["passkey"]["self_enrol"] = {"enabled": False}
    assert gw.web_login(grant_id).status_code == 400
    assert gw.idp.starts == []


def test_a_provider_without_reauth_starts_no_grant(gw):
    grant_id = gw.open_web(provider="stub", user="stub:stub-user-1")
    r = gw.client.get("/auth/login", params={"provider": "stub", "reauth": grant_id})
    assert r.status_code == 400
    assert audit_lines("passkey_reauth_refused")[-1]["reason"] == "provider_no_reauth"


def test_refusals_are_rate_limited_per_address_and_grant_id(gw):
    for _ in range(reauth.REFUSALS_PER_GRANT.max_events):
        assert gw.web_login("A" * 22).status_code == 400
    assert gw.web_login("A" * 22).status_code == 429
    # A login without reauth is not affected.
    assert gw.client.get("/auth/login", params={"provider": "idp"}).status_code == 302
    # Nor somebody else's grant behind the same address (a shared proxy or NAT): that budget is per grant id.
    grant_id = gw.open_web()
    assert gw.web_login(grant_id).status_code == 302


def _spray_id(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(16, "big")).decode().rstrip("=")


@pytest.mark.parametrize("route", ["web", "native"])
def test_spraying_well_formed_ids_hits_the_per_address_ceiling(gw, monkeypatch, route):
    """Every refused id costs a config read, a store read and an audit line; random well-formed ids each have
    a fresh per-grant budget, so the per-address ceiling (checked first) is what stops a spray."""
    reads = []
    real = gw.store.grant_for_login
    monkeypatch.setattr(gw.store, "grant_for_login", lambda *a, **kw: reads.append(1) or real(*a, **kw))
    ceiling = reauth.REFUSALS_PER_ADDRESS.max_events
    gw.client.cookies.set(HOST_COOKIE, "x" * 43)  # with a cookie every web attempt reaches the store

    def attempt(n: int):
        if route == "web":
            return gw.web_login(_spray_id(n))
        _verifier, challenge = make_pkce()
        return authorize(gw.client, challenge, reauth=_spray_id(n), provider="idp")

    assert [attempt(n).status_code for n in range(ceiling)] == [400] * ceiling
    refused = len(audit_lines("passkey_reauth_refused"))
    statuses = [attempt(ceiling + n).status_code for n in range(5)]
    assert statuses == [429] * 5
    assert len(audit_lines("passkey_reauth_refused")) == refused  # no more log lines, no more reads
    assert len(reads) == ceiling
    assert gw.idp.starts == []


def test_malformed_ids_count_only_against_the_ceiling(gw):
    for _ in range(reauth.REFUSALS_PER_GRANT.max_events + 5):  # past the per-grant budget: still a plain 400
        assert gw.web_login("not a grant").status_code == 400


def test_with_the_level_off_a_spray_reads_no_store_and_still_hits_the_ceiling(gw, monkeypatch):
    gw.config["confirm"]["passkey"]["enabled"] = False
    monkeypatch.setattr(gw.store, "grant_for_login", lambda *a, **kw: pytest.fail("store read with the level off"))
    ceiling = reauth.REFUSALS_PER_ADDRESS.max_events
    assert all(gw.web_login(_spray_id(n)).status_code == 400 for n in range(ceiling))
    assert gw.web_login(_spray_id(ceiling)).status_code == 429


def test_without_reauth_the_web_login_is_unchanged(gw):
    """No ``fresh`` keyword (a provider with the old signature keeps working), no ``reauth`` segment, no
    reauth cookie touched, and the callback still lands the person."""
    gw.client.cookies.set(HOST_COOKIE, "stale")
    start = gw.client.get("/auth/login", params={"provider": "stub", "next": "/x"})
    assert start.status_code == 302 and "reauth" not in pkce_of(start)
    done = gw.callback(start)
    assert done.status_code == 302 and done.headers["location"] == "/x"
    assert not any("hermes_reauth" in c for c in set_cookies(done))
    start = gw.client.get("/auth/login", params={"provider": "idp"})
    assert gw.idp.starts == [False] and "reauth" not in pkce_of(start)
    assert gw.client.get("/auth/login", params={"provider": "pw"}).headers.get_list("set-cookie") == []


def test_logout_clears_the_reauth_cookie(gw):
    gw.open_web()
    r = gw.client.post("/auth/logout")
    assert any(c.startswith(f"{HOST_COOKIE}=") and "Max-Age=0" in c for c in set_cookies(r))


def test_audit_lines_carry_no_secret_code_or_token(gw):
    opened = reauth.open_grant(store=gw.store, user_id=ALICE, provider="idp", client="web")
    gw.client.cookies.set(HOST_COOKIE, opened.secret)
    gw.callback(gw.web_login(opened.grant.id))
    text = json.dumps(audit_lines())
    assert opened.secret not in text and opened.grant.id not in text
    assert audit_lines("passkey_reauth_opened")[-1]["grant"] == opened.grant.id[:8]


# ── web, password provider ───────────────────────────────────────────────────────────────────────


def test_password_reauth_sets_the_pkce_cookie_and_the_login_completes_the_grant(gw):
    grant_id = gw.open_web(provider="pw", user="pw:admin")
    start = gw.web_login(grant_id, provider="pw", next_="/settings")
    assert start.status_code == 302 and start.headers["location"] == "/login?next=%2Fsettings"
    assert pkce_of(start) == {"provider": "pw", "reauth": grant_id}

    wrong = gw.client.post("/auth/password-login", json={"provider": "pw", "username": "admin", "password": "no"})
    assert wrong.status_code == 401 and gw.state(grant_id, "pw:admin") == ("open", "")

    ok = gw.client.post("/auth/password-login",
                        json={"provider": "pw", "username": "admin", "password": "hunter2", "next": "/settings"})
    assert ok.status_code == 200 and ok.json() == {"ok": True, "next": "/settings"}
    cookies = set_cookies(ok)
    assert any(c.startswith("__Host-hermes_session_at=") for c in cookies)
    assert any(c.startswith("__Host-hermes_session_pkce=") and "Max-Age=0" in c for c in cookies)
    assert not any(c.startswith(f"{HOST_COOKIE}=") for c in cookies)  # kept: the grant is fresh, not spent
    assert gw.state(grant_id, "pw:admin") == ("fresh", "")


def test_password_login_without_reauth_is_unchanged(gw):
    ok = gw.client.post("/auth/password-login", json={"provider": "pw", "username": "admin", "password": "hunter2"})
    assert ok.status_code == 200
    assert not any("pkce" in c or "hermes_reauth" in c for c in set_cookies(ok))


# ── native ───────────────────────────────────────────────────────────────────────────────────────


def _native_round_trip(gw, grant_id: str, **params) -> tuple[str, str]:
    verifier, challenge = make_pkce()
    start = authorize(gw.client, challenge, reauth=grant_id, **params)
    assert start.status_code == 302, start.text
    return verifier, loopback_code(gw.callback(start))


def test_native_reauth_returns_the_grant_state_and_no_tokens(gw):
    grant_id = gw.open_native()
    verifier, code = _native_round_trip(gw, grant_id, provider="idp")
    assert gw.idp.starts == [True]
    r = gw.client.post("/auth/native/token", json={"code": code, "code_verifier": verifier})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"reauth"}
    use_secret = body["reauth"].pop("use_secret")
    assert body["reauth"] == {"grant_id": grant_id, "state": "fresh",
                              "expires_at": gw.store.grant(grant_id, user_id=ALICE).expires_at}
    assert "token" not in r.text and not set_cookies(r)
    assert gw.state(grant_id) == ("fresh", "")
    # The one-time use secret is the grant's binding from here to the spend; never logged.
    assert len(use_secret) == 43 and use_secret not in json.dumps(audit_lines())
    assert gw.store.fresh_grant(grant_id, user_id=ALICE, secret=use_secret).state == "fresh"
    with pytest.raises(Exception) as err:
        gw.store.fresh_grant(grant_id, user_id=ALICE, secret=None)
    assert getattr(err.value, "reason", "") == "unknown"
    # The session the re-sign-in minted is never handed out, and not revoked at the IdP either (that could end
    # the SSO session the app's own sign-in rides on).
    assert gw.idp.revoked == []
    # Single use: the code is gone.
    again = gw.client.post("/auth/native/token", json={"code": code, "code_verifier": verifier})
    assert again.status_code == 400


def test_native_reauth_without_a_provider_uses_the_grants_provider_and_no_chooser(gw):
    grant_id = gw.open_native()
    verifier, code = _native_round_trip(gw, grant_id)
    assert gw.client.post("/auth/native/token", json={"code": code, "code_verifier": verifier}
                          ).json()["reauth"]["state"] == "fresh"


def test_native_reauth_as_someone_else_reports_the_failure_and_no_tokens(gw):
    grant_id = gw.open_native()
    gw.idp.user = "bob"
    verifier, code = _native_round_trip(gw, grant_id, provider="idp")
    body = gw.client.post("/auth/native/token", json={"code": code, "code_verifier": verifier}).json()
    assert body == {"reauth": {"grant_id": grant_id, "state": "failed", "reason": "user_mismatch",
                               "expires_at": gw.store.grant(grant_id, user_id=ALICE).expires_at}}


def test_native_reauth_code_needs_the_apps_verifier(gw):
    """A link to someone else's native grant lands its code on their own loopback; without the opener's
    verifier it redeems nothing and leaves the grant open."""
    grant_id = gw.open_native()
    _verifier, code = _native_round_trip(gw, grant_id, provider="idp")
    other, _ = make_pkce()
    assert gw.client.post("/auth/native/token", json={"code": code, "code_verifier": other}).status_code == 400
    assert gw.state(grant_id) == ("open", "")


@pytest.mark.parametrize("which", ["web_grant", "unknown", "malformed", "other_provider"])
def test_native_authorize_refuses_a_bad_grant_before_any_pending_or_cookie(gw, which):
    grant_id = {"web_grant": lambda: gw.open_web(), "unknown": lambda: "B" * 22, "malformed": lambda: "x/y",
                "other_provider": lambda: gw.open_native(provider="pw", user="pw:admin")}[which]()
    _verifier, challenge = make_pkce()
    r = authorize(gw.browser(), challenge, reauth=grant_id, provider="idp")
    assert r.status_code == 400 and "location" not in r.headers and set_cookies(r) == []
    assert native_flow._pending == {} and gw.idp.starts == []


def test_native_password_reauth(gw):
    grant_id = gw.open_native(provider="pw", user="pw:admin")
    verifier, challenge = make_pkce()
    start = authorize(gw.client, challenge, reauth=grant_id)
    assert start.status_code == 302 and start.headers["location"] == "/login"
    login = gw.client.post("/auth/password-login",
                           json={"provider": "pw", "username": "admin", "password": "hunter2"})
    assert login.status_code == 200 and not any("hermes_session_at" in c for c in set_cookies(login))
    body = gw.client.post("/auth/native/token", json={"code": loopback_code(login), "code_verifier": verifier}).json()
    assert body["reauth"]["state"] == "fresh" and "access_token" not in body


def test_native_login_without_reauth_still_returns_tokens(gw):
    verifier, challenge = make_pkce()
    start = authorize(gw.client, challenge, provider="idp")
    body = gw.client.post("/auth/native/token",
                          json={"code": loopback_code(gw.callback(start)), "code_verifier": verifier}).json()
    assert body["access_token"] and body["user_id"] == "alice" and "reauth" not in body
    assert gw.idp.starts == [False]


def test_redeem_code_refuses_and_consumes_a_reauth_code():
    native_flow._reset_for_tests()
    verifier, challenge = make_pkce()
    state = native_flow.register_pending(code_challenge=challenge, redirect_uri=LOOPBACK, client_state="s",
                                         reauth="G" * 22)
    session = Session(user_id="u", email="", display_name="", org_id="", provider="idp", expires_at=0,
                      access_token="at", refresh_token="rt")
    code = native_flow.complete_pending(state, session=session)
    with pytest.raises(native_flow.CodeInvalid):
        native_flow.redeem_code(code=code, code_verifier=verifier)
    with pytest.raises(native_flow.CodeInvalid):
        native_flow.redeem(code=code, code_verifier=verifier)
    native_flow._reset_for_tests()


@pytest.mark.parametrize("self_enrol, usable", [
    ({"enabled": True}, True),
    ({"enabled": "yes"}, False),
    ({"cooling_off_s": "10m"}, False),  # an unreadable cooling-off: off here too, like the passkey routes
    (True, False),
    ({"accept_missing_auth_time": "true"}, True),
])
def test_the_policy_is_read_with_the_passkey_settings_parser(self_enrol, usable):
    cfg = {"confirm": {"passkey": {"enabled": True, "self_enrol": self_enrol}}}
    assert reauth.policy(cfg).usable is usable
    assert reauth.policy(cfg).accept_missing_auth_time is False
