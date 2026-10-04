"""The passkey routes (``hermes_cli/dashboard_auth/passkeys/routes.py``) end to end: the real gated
dashboard app, a stub sign-in provider for two users, the real store, and a software authenticator.

Pinned here: 404 for every route while the level is off; nothing is public; identity only from the
gate's session; enrolment needs a code or a fresh re-authentication grant every time; an invite needs a valid ``invite`` step-up and a
revoke a ``revoke`` step-up for that credential; one user never sees, adds to or revokes another's
credentials; a cookie write needs a listed ``Origin``; the 16 KiB body cap; the rate limits; the
``passkey.changed`` event and the ``on_passkey_change`` hook with their documented payloads; and no code,
assertion or token in the audit log.
"""

from __future__ import annotations

import copy
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.passkeys import routes
from hermes_cli.dashboard_auth.passkeys.challenge import b64u, b64u_decode
from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore, StoreError
from hermes_cli.dashboard_auth.passkeys.webauthn import AssertionRequest, PendingRegistration
from hermes_cli.dashboard_auth.rate_limit import SlidingWindowLimiter
from hermes_cli.plugins import VALID_HOOKS, get_plugin_manager
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider, _sign
from tests.hermes_cli.passkey_soft_authenticator import SoftAuthenticator, web_authenticator

BASE = "https://gw.example.com"
NATIVE_RP = "confirm.hermie.dev"
NATIVE_ORIGIN = "https://confirm.hermie.dev"
ALICE, BOB = "stub:alice", "stub:bob"
REPO = Path(__file__).resolve().parents[2]


class Clock:
    def __init__(self, t: float = 1_790_000_000):
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakeTransport:
    """A live WebSocket connection as ``tui_gateway.server`` tracks it: the minted login and the frames."""

    def __init__(self, user: str | None):
        provider, _, login = (user or "").partition(":")
        self.auth_identity = None if user is None else {"provider": provider, "user_id": login}
        self.frames: list[dict] = []

    def write(self, frame: dict) -> bool:
        self.frames.append(frame)
        return True

    def events(self, name: str = "passkey.changed") -> list[dict]:
        return [f["params"]["payload"] for f in self.frames if f["params"]["type"] == name]


class Gateway:
    def __init__(self, client: TestClient, store: PasskeyStore, clock: Clock, config: dict):
        self.client, self.store, self.clock, self.config = client, store, clock, config

    @staticmethod
    def bearer(user: str) -> dict:
        name = user.split(":", 1)[1]
        token = _sign({"sub": name, "email": "", "name": name.title(), "org_id": "",
                       "exp": int(time.time()) + 3600})
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def cookie(user: str, origin: str | None = None) -> dict:
        token = Gateway.bearer(user)["Authorization"].split(" ", 1)[1]
        headers = {"Cookie": f"hermes_session_at={token}"}
        if origin is not None:
            headers["Origin"] = origin
        return headers

    def get(self, user: str = ALICE, **kw):
        return self.client.get(routes.PREFIX, headers=kw.pop("headers", None) or self.bearer(user), **kw)

    def post(self, path: str, body, user: str = ALICE, headers: dict | None = None):
        return self.client.post(f"{routes.PREFIX}{path}", json=body, headers=headers or self.bearer(user))

    # ── ceremonies ──────────────────────────────────────────────────────────────────────────────

    def begin_registration(self, auth: SoftAuthenticator, user: str = ALICE, name: str = "Phone — gw.example.com",
                           headers: dict | None = None) -> dict:
        r = self.post("/register/begin", {"rp_id": auth.rp_id, "base_url": BASE, "name": name}, user, headers)
        assert r.status_code == 200, r.text
        return r.json()

    def finish_body(self, auth: SoftAuthenticator, begin: dict, code: str, user: str = ALICE) -> dict:
        pending = PendingRegistration(registration_id=begin["registration_id"], user_id=user, rp_id=auth.rp_id,
                                      base_url=begin["base_url"], name=begin["user"]["name"],
                                      nonce=b64u_decode(begin["nonce"]))
        body = auth.register(b64u_decode(begin["gateway_id"]), pending)
        body["code"] = code
        return body

    def enrol(self, auth: SoftAuthenticator, user: str = ALICE, code: str | None = None, **kw) -> dict:
        begin = self.begin_registration(auth, user, **kw)
        code = code if code is not None else self.store.mint_code(user_id=user).code
        r = self.post("/register/finish", self.finish_body(auth, begin, code, user), user, kw.get("headers"))
        assert r.status_code == 200, r.text
        return r.json()["credential"]

    def stepup(self, purpose: str, subject: str | None = None, user: str = ALICE) -> dict:
        body = {"purpose": purpose} | ({"subject": subject} if subject is not None else {})
        r = self.post("/stepup/begin", body, user)
        assert r.status_code == 200, r.text
        return r.json()

    def sign_stepup(self, auth: SoftAuthenticator, stepup: dict, user: str = ALICE, purpose: str | None = None,
                    subject: str | None = None) -> dict:
        request = AssertionRequest(user_id=user, request_id=stepup["stepup_id"], nonce=b64u_decode(stepup["nonce"]),
                                   title="", summary=subject if subject is not None else stepup["subject"],
                                   detail="", session_id="", purpose=purpose or stepup["purpose"])
        handle_key = self.store.identity()[1]
        return auth.assert_(self.store.gateway_id, handle_key, request, BASE)["passkey"]


def native(**kw) -> SoftAuthenticator:
    return SoftAuthenticator(rp_id=NATIVE_RP, client_origin=NATIVE_ORIGIN, **kw)


@pytest.fixture
def transports():
    from tui_gateway import server

    made: list[FakeTransport] = []

    def connect(user: str | None) -> FakeTransport:
        transport = FakeTransport(user)
        server.register_live_transport(transport)
        made.append(transport)
        return transport

    yield connect
    for transport in made:
        server.unregister_live_transport(transport)


@pytest.fixture
def hooks():
    manager = get_plugin_manager()
    saved = {k: list(v) for k, v in manager._hooks.items()}
    fired: list[dict] = []
    # The dispatcher adds its own envelope key (telemetry_schema_version); everything else is the route's.
    manager._hooks.setdefault("on_passkey_change", []).append(
        lambda **kw: fired.append({k: v for k, v in kw.items() if k != "telemetry_schema_version"}))
    yield fired
    manager._hooks = saved


@pytest.fixture
def make_gateway(monkeypatch, tmp_path):
    clear_providers()
    register_provider(StubAuthProvider())
    routes.reset_for_tests()

    def make(passkey: dict | None = None, *, gated: bool = True) -> Gateway:
        config = {"dashboard": {"public_url": BASE},
                  "confirm": {"passkey": {"enabled": True, "base_urls": [BASE]} | (passkey or {})}}
        monkeypatch.delenv("HERMES_DASHBOARD_PUBLIC_URL", raising=False)
        monkeypatch.setattr("hermes_cli.config.load_config", lambda: copy.deepcopy(config))
        for name in ("auth_required", "bound_host", "trusted_public_hosts", "public_origins", "write_origin_check"):
            monkeypatch.setattr(web_server.app.state, name, getattr(web_server.app.state, name, None), raising=False)
        web_server.app.state.bound_host = "127.0.0.1"
        web_server._configure_auth_gate("127.0.0.1", False, None, None)
        if not gated:
            web_server.app.state.auth_required = False
        assert web_server.app.state.auth_required is gated
        clock = Clock()
        store = PasskeyStore(tmp_path / "dashboard_auth" / "passkeys.db", clock=clock)
        monkeypatch.setattr(routes, "_store", lambda: store)
        return Gateway(TestClient(web_server.app, base_url=BASE), store, clock, config)

    yield make
    routes.reset_for_tests()
    clear_providers()


@pytest.fixture
def gw(make_gateway) -> Gateway:
    return make_gateway()


def audit_lines() -> list[dict]:
    from hermes_constants import get_hermes_home

    path = get_hermes_home() / "logs" / "dashboard-auth.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ── availability ─────────────────────────────────────────────────────────────────────────────────

ROUTES = [("GET", ""), ("POST", "/reauth/begin"), ("POST", "/register/begin"), ("POST", "/register/finish"),
          ("POST", "/stepup/begin"), ("POST", "/invites"), ("POST", "/revoke")]


@pytest.mark.parametrize("passkey", [{"enabled": False}, {"enabled": "yes"}])
def test_every_route_answers_like_an_unknown_path_while_the_level_is_off(make_gateway, passkey):
    gw = make_gateway(passkey)

    def answer(method: str, path: str) -> tuple:
        r = gw.client.request(method, path, headers=gw.bearer(ALICE), json={} if method == "POST" else None)
        return r.status_code, r.json(), r.headers.get("allow")

    for method, path in ROUTES:
        unknown = "/api/auth/passkeyz" + path  # what a gateway without these routes answers
        got, expected = answer(method, f"{routes.PREFIX}{path}"), answer(method, unknown)
        assert got[0] == expected[0] and got[2] == expected[2], (method, path)
        assert got[1] == {"detail": expected[1]["detail"].replace("/api/auth/passkeyz", routes.PREFIX)}
        assert got[0] == (404 if method == "GET" else 405)
    assert not gw.store.exists()  # nothing was even created


def test_no_route_is_public(gw):
    for method, path in ROUTES:
        r = gw.client.request(method, f"{routes.PREFIX}{path}", json={} if method == "POST" else None)
        assert r.status_code == 401, (method, path)


def test_a_connection_without_a_signed_in_user_has_no_passkeys(make_gateway):
    gw = make_gateway(gated=False)  # loopback / session-token mode: the shared token names nobody
    headers = {"X-Hermes-Session-Token": web_server._SESSION_TOKEN}
    r = gw.client.get(routes.PREFIX, headers=headers)
    assert (r.status_code, r.json()["error"]) == (403, "no_identity")
    r = gw.client.post(f"{routes.PREFIX}/register/begin", headers=headers,
                       json={"rp_id": NATIVE_RP, "base_url": BASE, "name": "x"})
    assert (r.status_code, r.json()["error"]) == (403, "no_identity")


def test_status_names_the_gateway_the_user_and_the_rps(gw):
    r = gw.get()
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["v"] == 1 and body["enabled"] is True and body["reason"] == ""
    assert body["gateway_id"] == b64u(gw.store.gateway_id)
    assert body["user"]["id"] == ALICE and len(b64u_decode(body["user"]["handle"])) == 32
    assert body["rp"] == {"native": [NATIVE_RP], "web": ["gw.example.com"]}
    assert body["base_urls"] == [BASE] and body["user_invites"] is True and body["credentials"] == []
    assert gw.get(BOB).json()["user"]["handle"] != body["user"]["handle"]


@pytest.mark.parametrize("passkey, reason", [
    ({"base_urls": []}, "no_base_url"),
    ({"base_urls": ["http://192.168.1.10:9119"]}, "private_origin")])
def test_status_is_not_enabled_while_the_level_has_no_usable_base_url(make_gateway, passkey, reason):
    body = make_gateway(passkey).get().json()
    assert (body["enabled"], body["reason"]) == (False, reason)  # contract §8: enabled exactly when reason is ""
    assert body["rp"] == {"native": [], "web": []} and body["base_urls"] == []


def test_store_failure_is_unavailable_not_a_crash(gw, monkeypatch):
    def broken():
        raise StoreError("disk")

    monkeypatch.setattr(routes, "_store", broken)
    r = gw.get()
    assert (r.status_code, r.json()["error"]) == (503, "unavailable")


# ── enrolment ────────────────────────────────────────────────────────────────────────────────────


def test_enrol_with_an_operator_code_and_announce_it(gw, transports, hooks):
    alice_app, alice_web, bob_app, anonymous = transports(ALICE), transports(ALICE), transports(BOB), transports(None)
    auth = native()
    begin = gw.begin_registration(auth)
    assert begin["rp"] == {"id": NATIVE_RP, "name": NATIVE_RP} and begin["user_verification"] == "required"
    assert begin["attestation"] == "none" and begin["pub_key_cred_params"] == [{"type": "public-key", "alg": -7}]
    assert begin["expires_at"] == int(gw.clock.t) + 300 and begin["exclude_credentials"] == []
    code = gw.store.mint_code().code  # the operator's `passkey invite`, not bound to a user
    r = gw.post("/register/finish", gw.finish_body(auth, begin, code))
    assert r.status_code == 200, r.text
    credential = r.json()["credential"]
    assert credential["id"] == b64u(auth.credential_id) and credential["rp_id"] == NATIVE_RP
    assert credential["created_via"] == "operator" and credential["name"] == "Phone — gw.example.com"
    assert [c["id"] for c in gw.get().json()["credentials"]] == [credential["id"]]

    expected = {"change": "added", "credential": {"id": credential["id"], "name": credential["name"],
                                                   "rp_id": NATIVE_RP}, "at": int(gw.clock.t)}
    assert alice_app.events() == [expected] and alice_web.events() == [expected]
    assert bob_app.frames == [] and anonymous.frames == []
    assert hooks == [{"change": "added", "user_id": ALICE, "credential": expected["credential"],
                      "at": int(gw.clock.t), "via": "operator"}]
    assert code not in json.dumps(hooks)
    # The excluded list of a new registration now names the enrolled credential (same RP only).
    assert [c["id"] for c in gw.begin_registration(native())["exclude_credentials"]] == [credential["id"]]
    assert gw.begin_registration(web_authenticator(BASE))["exclude_credentials"] == []


def test_a_second_enrolment_needs_a_code_of_its_own(gw):
    first_code = gw.store.mint_code(user_id=ALICE).code
    gw.enrol(native(), code=first_code)
    second = native()
    begin = gw.begin_registration(second)
    for code in ("", first_code, "not-a-code", "00000-00000-00000-00000"):
        r = gw.post("/register/finish", gw.finish_body(second, begin, code))
        assert (r.status_code, r.json()["error"]) == (403, "code_invalid"), code
    body = gw.finish_body(second, begin, "")
    del body["code"]
    assert gw.post("/register/finish", body).status_code == 400
    assert len(gw.get().json()["credentials"]) == 1
    # The registration stayed open: the right code still works.
    r = gw.post("/register/finish", gw.finish_body(second, begin, gw.store.mint_code(user_id=ALICE).code))
    assert r.status_code == 200 and len(gw.get().json()["credentials"]) == 2


def test_registration_refusals(gw):
    auth = native()
    assert gw.post("/register/begin", {"rp_id": "evil.example", "base_url": BASE, "name": "x"}).json()["reason"] \
        == "rp_not_accepted"
    assert gw.post("/register/begin", {"rp_id": NATIVE_RP, "base_url": "https://other.example", "name": "x"}) \
        .json()["reason"] == "base_url_not_accepted"
    assert gw.post("/register/begin", {"rp_id": NATIVE_RP, "base_url": BASE + "/", "name": "x"}) \
        .json()["reason"] == "base_url_not_accepted"  # never normalised
    assert gw.post("/register/begin", {"rp_id": NATIVE_RP, "base_url": BASE, "name": "a\nb"}).status_code == 400
    assert gw.post("/register/begin", {"rp_id": NATIVE_RP, "base_url": BASE, "name": ""}).status_code == 400

    begin = gw.begin_registration(auth)
    body = gw.finish_body(auth, begin, gw.store.mint_code(user_id=ALICE).code)
    tampered = copy.deepcopy(body)
    tampered["credential"]["client_data_json"] = b64u(b'{"type":"webauthn.create","challenge":"AA","origin":"x"}')
    r = gw.post("/register/finish", tampered)
    assert (r.status_code, r.json()["error"], r.json()["reason"]) == (422, "attestation_invalid", "bad_client_data")
    gw.clock.t += 301
    r = gw.post("/register/finish", body)
    assert (r.status_code, r.json()["error"]) == (410, "expired")
    assert gw.post("/register/finish", body | {"registration_id": "nope"}).status_code == 410


def test_the_same_passkey_cannot_be_enrolled_twice(gw):
    auth = native()
    gw.enrol(auth)
    begin = gw.begin_registration(native(credential_id=auth.credential_id, key=auth.key))
    r = gw.post("/register/finish", gw.finish_body(auth, begin, gw.store.mint_code(user_id=ALICE).code))
    assert (r.status_code, r.json()["error"]) == (409, "credential_exists")


def test_a_browser_enrols_for_its_own_host_with_a_cookie(gw):
    browser = web_authenticator(BASE, synced=False)
    headers = gw.cookie(ALICE, origin=BASE)
    credential = gw.enrol(browser, headers=headers)
    assert credential["rp_id"] == "gw.example.com" and credential["backup_eligible"] is False


# ── step-ups, invites and revocation ─────────────────────────────────────────────────────────────


def test_an_invite_needs_a_valid_invite_stepup(gw, hooks):
    phone = native()
    credential = gw.enrol(phone)
    # No step-up at all, or someone else's id.
    assertion = gw.sign_stepup(phone, {"stepup_id": "made-up", "nonce": b64u(b"\0" * 32), "subject": "invite",
                                       "purpose": "invite"})
    r = gw.post("/invites", {"stepup_id": "made-up", "assertion": assertion})
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    # A step-up signed by a key that is not enrolled is refused, and spends the step-up.
    stepup = gw.stepup("invite")
    assert stepup["credentials"] == [{"rp_id": NATIVE_RP, "ids": [credential["id"]]}]
    assert stepup["expires_at"] == int(gw.clock.t) + 120
    stranger = native()
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(stranger, stepup)})
    assert (r.status_code, r.json()["error"], r.json()["reason"]) == (422, "assertion_invalid", "unknown_credential")
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(phone, stepup)})
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    # A signature over other text (not "invite") is refused.
    stepup = gw.stepup("invite")
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"],
                             "assertion": gw.sign_stepup(phone, stepup, subject="something else")})
    assert r.json()["reason"] == "challenge_mismatch"
    # A valid one mints a code bound to the caller, which enrols a browser passkey.
    stepup = gw.stepup("invite")
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(phone, stepup)})
    assert r.status_code == 200, r.text
    code = r.json()["code"]
    assert re.fullmatch(r"[0-9A-Z]{5}(-[0-9A-Z]{5}){3}", code) and r.json()["expires_at"] == int(gw.clock.t) + 900
    # Replaying the same step-up is refused: single use.
    assert gw.post("/invites", {"stepup_id": stepup["stepup_id"],
                                "assertion": gw.sign_stepup(phone, stepup)}).status_code == 403
    # Bob cannot redeem Alice's code.
    bob_auth = native()
    begin = gw.begin_registration(bob_auth, BOB)
    assert gw.post("/register/finish", gw.finish_body(bob_auth, begin, code, BOB), BOB).json()["error"] \
        == "code_invalid"
    added = gw.enrol(web_authenticator(BASE), code=code)
    assert added["created_via"] == "passkey"
    assert [h["via"] for h in hooks] == ["operator", "passkey"]


def test_invites_can_be_switched_off_by_the_operator(make_gateway):
    gw = make_gateway({"user_invites": False})
    gw.enrol(native())
    assert gw.get().json()["user_invites"] is False
    r = gw.post("/stepup/begin", {"purpose": "invite"})
    assert (r.status_code, r.json()["error"]) == (403, "invites_disabled")


def test_a_stepup_for_invite_cannot_revoke(gw, transports):
    phone, laptop = native(), web_authenticator(BASE)
    phone_id = gw.enrol(phone)["id"]
    laptop_id = gw.enrol(laptop)["id"]
    stepup = gw.stepup("invite")
    assertion = gw.sign_stepup(phone, stepup)
    r = gw.post("/revoke", {"credential_id": phone_id, "stepup_id": stepup["stepup_id"], "assertion": assertion})
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    # Signed as if it were a revoke of the phone, still over the invite step-up's id and nonce: refused.
    r = gw.post("/revoke", {"credential_id": phone_id, "stepup_id": stepup["stepup_id"],
                            "assertion": gw.sign_stepup(phone, stepup, purpose="revoke", subject=phone_id)})
    assert r.status_code == 403
    # A revoke step-up for the laptop cannot revoke the phone.
    stepup = gw.stepup("revoke", laptop_id)
    r = gw.post("/revoke", {"credential_id": phone_id, "stepup_id": stepup["stepup_id"],
                            "assertion": gw.sign_stepup(phone, stepup)})
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    # And a revoke step-up is no invite.
    stepup = gw.stepup("revoke", phone_id)
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(phone, stepup)})
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    assert {c["id"] for c in gw.get().json()["credentials"]} == {phone_id, laptop_id}


def test_revoking_the_last_credential_works_and_is_announced(gw, transports, hooks):
    alice, bob = transports(ALICE), transports(BOB)
    phone = native()
    phone_id = gw.enrol(phone)["id"]
    stepup = gw.stepup("revoke", phone_id)
    assert stepup["subject"] == phone_id
    r = gw.post("/revoke", {"credential_id": phone_id, "stepup_id": stepup["stepup_id"], "base_url": BASE,
                            "assertion": gw.sign_stepup(phone, stepup)})
    assert (r.status_code, r.json()) == (200, {"ok": True})
    assert gw.get().json()["credentials"] == []
    assert [e["change"] for e in alice.events()] == ["added", "revoked"]
    assert alice.events()[-1]["credential"]["id"] == phone_id and bob.frames == []
    assert hooks[-1] == {"change": "revoked", "user_id": ALICE, "credential": alice.events()[-1]["credential"],
                         "at": int(gw.clock.t), "via": "passkey"}
    revoked = gw.store.credential(b64u_decode(phone_id))
    assert revoked is not None and revoked.revoked_by == ALICE
    # Nothing is left to step up with.
    assert gw.post("/stepup/begin", {"purpose": "invite"}).json()["reason"] == "not_enrolled"


def test_one_user_never_sees_adds_to_or_revokes_anothers(gw):
    alice_phone, bob_phone = native(), native()
    alice_id = gw.enrol(alice_phone)["id"]
    # Bob sees none of Alice's credentials, and has nothing to step up with.
    assert gw.get(BOB).json()["credentials"] == []
    assert gw.post("/stepup/begin", {"purpose": "revoke", "subject": alice_id}, BOB).json()["reason"] \
        == "not_enrolled"
    bob_id = gw.enrol(bob_phone, BOB)["id"]
    assert [c["id"] for c in gw.get(BOB).json()["credentials"]] == [bob_id]
    assert [c["id"] for c in gw.get(ALICE).json()["credentials"]] == [alice_id]
    # Bob cannot open a revoke step-up for Alice's credential (the same answer as an unknown id).
    r = gw.post("/stepup/begin", {"purpose": "revoke", "subject": alice_id}, BOB)
    assert (r.status_code, r.json()["reason"]) == (400, "unknown_credential")
    assert gw.post("/stepup/begin", {"purpose": "revoke", "subject": b64u(b"x" * 32)}, BOB).json() == r.json()
    # Bob cannot take Alice's step-up, nor Alice's registration.
    stepup = gw.stepup("revoke", alice_id)
    r = gw.post("/revoke", {"credential_id": alice_id, "stepup_id": stepup["stepup_id"],
                            "assertion": gw.sign_stepup(alice_phone, stepup)}, BOB)
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    begin = gw.begin_registration(native())
    r = gw.post("/register/finish", gw.finish_body(native(), begin, gw.store.mint_code().code, BOB), BOB)
    assert (r.status_code, r.json()["error"]) == (410, "expired")
    # Bob's own revoke step-up names his credential; Alice's credential id in the body does not match it.
    stepup = gw.stepup("revoke", bob_id, BOB)
    r = gw.post("/revoke", {"credential_id": alice_id, "stepup_id": stepup["stepup_id"],
                            "assertion": gw.sign_stepup(bob_phone, stepup, BOB)}, BOB)
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")
    # Alice's authenticator signing Bob's step-up is not one of Bob's credentials.
    stepup = gw.stepup("revoke", bob_id, BOB)
    r = gw.post("/revoke", {"credential_id": bob_id, "stepup_id": stepup["stepup_id"],
                            "assertion": gw.sign_stepup(alice_phone, stepup, BOB)}, BOB)
    assert r.json()["reason"] == "unknown_credential"
    assert [c["id"] for c in gw.get(ALICE).json()["credentials"]] == [alice_id]
    assert [c["id"] for c in gw.get(BOB).json()["credentials"]] == [bob_id]


# ── CSRF, body cap, rate limits ──────────────────────────────────────────────────────────────────


def test_a_cookie_write_needs_a_listed_origin(gw):
    body = {"rp_id": NATIVE_RP, "base_url": BASE, "name": "Phone"}
    for origin in (None, "https://evil.example", "http://gw.example.com", "null", BASE + ":8443"):
        r = gw.post("/register/begin", body, headers=gw.cookie(ALICE, origin))
        assert (r.status_code, r.json()["error"]) == (403, "origin_not_listed"), origin
    assert gw.post("/register/begin", body, headers=gw.cookie(ALICE, BASE)).status_code == 200
    # Reads need no Origin; a bearer caller (the native app) sends none.
    assert gw.get(headers=gw.cookie(ALICE)).status_code == 200
    assert gw.post("/register/begin", body).status_code == 200
    assert any(line.get("reason") == "origin_not_listed" for line in audit_lines())


def test_the_listed_origin_comes_from_the_passkey_list_not_the_dashboard(make_gateway):
    gw = make_gateway({"base_urls": ["https://other.example.com"]})
    body = {"rp_id": NATIVE_RP, "base_url": "https://other.example.com", "name": "Phone"}
    assert gw.post("/register/begin", body, headers=gw.cookie(ALICE, BASE)).status_code == 403
    assert gw.post("/register/begin", body, headers=gw.cookie(ALICE, "https://other.example.com")).status_code \
        == 200


def test_the_body_is_capped_at_16_kib(gw):
    big = {"rp_id": NATIVE_RP, "base_url": BASE, "name": "x", "pad": "a" * routes.BODY_CAP}
    r = gw.post("/register/begin", big)
    assert (r.status_code, r.json()["error"]) == (413, "body_too_large")
    r = gw.client.post(f"{routes.PREFIX}/register/begin", headers=gw.bearer(ALICE), content=b"[1, 2]")
    assert (r.status_code, r.json()["error"]) == (400, "bad_request")
    r = gw.client.post(f"{routes.PREFIX}/register/begin", headers=gw.bearer(ALICE), content=b"{not json")
    assert r.status_code == 400


def test_register_begin_is_limited_per_user(gw):
    body = {"rp_id": NATIVE_RP, "base_url": BASE, "name": "Phone"}
    assert [gw.post("/register/begin", body).status_code for _ in range(6)] == [200] * 5 + [429]
    assert gw.post("/register/begin", body).headers["retry-after"] == "600"


def test_failed_codes_are_limited_per_user_and_address(gw):
    auth = native()
    begin = gw.begin_registration(auth)
    statuses = [gw.post("/register/finish", gw.finish_body(auth, begin, "")).status_code for _ in range(6)]
    assert statuses == [403] * 5 + [429]
    # Even the right code is refused while the window lasts.
    r = gw.post("/register/finish", gw.finish_body(auth, begin, gw.store.mint_code(user_id=ALICE).code))
    assert (r.status_code, r.json()["error"]) == (429, "rate_limited")
    # The address is spent too (every test client shares one).
    bob = native()
    begin = gw.begin_registration(bob, BOB)
    assert gw.post("/register/finish", gw.finish_body(bob, begin, "", BOB), BOB).status_code == 429


def test_failed_codes_are_limited_gateway_wide(gw, monkeypatch, caplog):
    monkeypatch.setattr(routes, "CODE_FAILURES_PER_IP", SlidingWindowLimiter(1000, 600))
    for n in range(4):
        user = f"stub:user{n}"
        auth = native()
        begin = gw.begin_registration(auth, user)
        for _ in range(5):
            assert gw.post("/register/finish", gw.finish_body(auth, begin, "", user), user).status_code == 403
    auth = native()
    begin = gw.begin_registration(auth, BOB)
    r = gw.post("/register/finish", gw.finish_body(auth, begin, gw.store.mint_code().code, BOB), BOB)
    assert (r.status_code, r.headers["retry-after"]) == (429, "3600")
    assert "failed code redemptions" in caplog.text
    assert any(line.get("reason") == "gateway_rate_limited" for line in audit_lines())


def test_stepups_are_limited_per_user(gw):
    gw.enrol(native())
    assert [gw.post("/stepup/begin", {"purpose": "invite"}).status_code for _ in range(11)] == [200] * 10 + [429]


# ── what is written down ─────────────────────────────────────────────────────────────────────────


def test_no_code_assertion_or_token_reaches_the_audit_log(gw, caplog):
    phone = native()
    code = gw.store.mint_code(user_id=ALICE).code
    gw.enrol(phone, code=code)
    stepup = gw.stepup("invite")
    assertion = gw.sign_stepup(phone, stepup)
    minted = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": assertion}).json()["code"]
    text = json.dumps(audit_lines()) + caplog.text
    token = gw.bearer(ALICE)["Authorization"].split(" ", 1)[1]
    for secret in (code, minted, assertion["signature"], assertion["client_data_json"],
                   assertion["authenticator_data"], token):
        assert secret not in text
    events = {line["event"] for line in audit_lines()}
    assert {"passkey_registered", "passkey_invite_minted"} <= events
    registered = next(line for line in audit_lines() if line["event"] == "passkey_registered")
    assert registered["user_id"] == ALICE and registered["auth"] == "bearer" and registered["ip"]
    assert registered["credential"] == b64u(phone.credential_id)[:16]


def test_the_hook_is_registered_and_documented_with_its_payload():
    assert "on_passkey_change" in VALID_HOOKS
    hooks_md = (REPO / "website/docs/user-guide/features/hooks.md").read_text(encoding="utf-8")
    row = next(line for line in hooks_md.splitlines() if line.startswith("| `on_passkey_change` |"))
    documented = re.findall(r"`([a-z_]+)`", row.split("|")[4])
    assert tuple(documented) == routes.HOOK_KWARGS
    plugins_md = (REPO / "website/docs/user-guide/features/plugins.md").read_text(encoding="utf-8")
    assert "`on_passkey_change`" in plugins_md


def test_passkey_changed_has_a_contract():
    from tui_gateway.contracts import registry

    assert "passkey.changed" in registry.EVENTS
    with pytest.raises(ValidationError):
        registry.EVENTS["passkey.changed"].payload.model_validate({"change": "added", "at": 1})


def test_exhausted_asks_without_recording():
    limiter = SlidingWindowLimiter(2, 60)
    assert [limiter.exhausted("k") for _ in range(5)] == [False] * 5
    limiter.check("k")
    assert not limiter.exhausted("k")
    limiter.check("k")
    assert limiter.exhausted("k") and not limiter.exhausted("other")


def test_parallel_wrong_codes_cannot_outrun_the_failure_limit(gw, monkeypatch):
    """Check, redeem and count happen under one lock: a burst cannot pass the check before any failure is
    counted. The store is slowed down so the burst really overlaps."""
    from concurrent.futures import ThreadPoolExecutor

    reached: list[int] = []
    redeem = gw.store.add_credential

    def slow_redeem(**kw):
        reached.append(1)
        time.sleep(0.05)
        return redeem(**kw)

    monkeypatch.setattr(gw.store, "add_credential", slow_redeem)
    auth = native()
    body = gw.finish_body(auth, gw.begin_registration(auth), "00000-00000-00000-00000")

    def attempt(_):
        client = TestClient(web_server.app, base_url=BASE)
        return client.post(f"{routes.PREFIX}/register/finish", json=body, headers=gw.bearer(ALICE)).status_code

    with ThreadPoolExecutor(max_workers=12) as pool:
        statuses = sorted(pool.map(attempt, range(12)))
    assert statuses == [403] * 5 + [429] * 7
    assert len(reached) == 5


def test_a_duplicate_credential_counts_as_a_code_failure(gw):
    auth = native()
    gw.enrol(auth)
    code = gw.store.mint_code(user_id=ALICE).code  # one valid code, used to probe credential ids
    clone = native(credential_id=auth.credential_id, key=auth.key)
    begin = gw.begin_registration(clone)
    statuses = [gw.post("/register/finish", gw.finish_body(clone, begin, code)).status_code for _ in range(6)]
    assert statuses == [409] * 5 + [429]


def test_a_stepup_refused_at_commit_is_spent(gw, monkeypatch):
    from hermes_cli.dashboard_auth.passkeys.store import CommitRefused

    phone = native()
    gw.enrol(phone)
    stepup = gw.stepup("invite")

    def refuse(*_a, **_kw):
        raise CommitRefused("revoked")  # e.g. the operator revoked the credential between check and commit

    commit = gw.store.commit_assertion
    monkeypatch.setattr(gw.store, "commit_assertion", refuse)
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(phone, stepup)})
    assert (r.status_code, r.json()["error"], r.json()["reason"]) == (422, "assertion_invalid", "revoked")
    assert gw.store.pending(stepup["stepup_id"], kind="invite", user_id=ALICE) is None
    monkeypatch.setattr(gw.store, "commit_assertion", commit)
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(phone, stepup)})
    assert (r.status_code, r.json()["error"]) == (403, "stepup_invalid")


@pytest.mark.parametrize("misbehaviour", ["raises", "hangs"])
def test_a_misbehaving_hook_never_fails_or_holds_the_change(gw, transports, monkeypatch, misbehaviour):
    from hermes_cli.plugins_dispatch import _HOOK_TIMEOUT_BOUNDED_HOOKS

    assert "on_passkey_change" in _HOOK_TIMEOUT_BOUNDED_HOOKS
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.2)
    release = __import__("threading").Event()

    def bad(**_kw):
        if misbehaviour == "raises":
            raise RuntimeError("push service down")
        release.wait(10)

    manager = get_plugin_manager()
    saved = {k: list(v) for k, v in manager._hooks.items()}
    manager._hooks.setdefault("on_passkey_change", []).append(bad)
    alice = transports(ALICE)
    try:
        started = time.monotonic()
        credential = gw.enrol(native())
        assert time.monotonic() - started < 5
    finally:
        release.set()
        manager._hooks = saved
    assert [c["id"] for c in gw.get().json()["credentials"]] == [credential["id"]]
    assert [e["change"] for e in alice.events()] == ["added"]


# ── self-enrolment: a fresh sign-in instead of a code ────────────────────────────────────────────


class ReauthStubProvider(StubAuthProvider):
    """The stub provider able to force a fresh sign-in (like ``basic`` and ``self_hosted``). Its sign-in
    returns ``user`` authenticated at ``auth_time`` (the gateway clock's now when None)."""

    supports_reauth = True

    def __init__(self, clock: Clock):
        super().__init__()
        self.clock, self.user, self.auth_time = clock, "alice", None
        self.fresh: list[bool] = []

    def start_login(self, *, redirect_uri: str, fresh: bool = False):
        self.fresh.append(fresh)
        return super().start_login(redirect_uri=redirect_uri)

    def complete_login(self, **kwargs):
        import dataclasses

        session = super().complete_login(**kwargs)
        token = Gateway.bearer(f"stub:{self.user}")["Authorization"].split(" ", 1)[1]
        return dataclasses.replace(session, user_id=self.user, access_token=token,
                                   auth_time=int(self.clock.t) if self.auth_time is None else self.auth_time)


@pytest.fixture
def make_self_gateway(make_gateway):
    def make(passkey: dict | None = None) -> Gateway:
        gw = make_gateway(passkey)
        clear_providers()
        gw.provider = ReauthStubProvider(gw.clock)  # type: ignore[attr-defined]
        register_provider(gw.provider)  # type: ignore[attr-defined]
        return gw

    return make


@pytest.fixture
def sgw(make_self_gateway) -> Gateway:
    return make_self_gateway()


def open_grant(gw: Gateway, user: str = ALICE, headers: dict | None = None) -> dict:
    r = gw.post("/reauth/begin", {}, user, headers)
    assert r.status_code == 200, r.text
    return r.json()


def fresh(gw: Gateway, grant_id: str, user: str = ALICE, *, client: str = "native", secret: str | None = None,
          auth_time: int | None = None):
    """What the sign-in routes do when the re-sign-in comes back (SE-3): complete the grant."""
    return gw.store.complete_grant(grant_id, session_user=user, session_provider="stub",
                                   auth_time=int(gw.clock.t) if auth_time is None else auth_time, client=client,
                                   secret=secret)


def self_finish(gw: Gateway, auth: SoftAuthenticator, begin: dict, grant_id: str, user: str = ALICE) -> dict:
    body = gw.finish_body(auth, begin, "", user)
    del body["code"]
    return body | {"grant_id": grant_id}


def begin_with_grant(gw: Gateway, auth: SoftAuthenticator, grant_id: str, user: str = ALICE,
                     headers: dict | None = None):
    return gw.post("/register/begin", {"rp_id": auth.rp_id, "base_url": BASE, "name": "Laptop",
                                       "grant_id": grant_id}, user, headers)


def self_enrol(gw: Gateway, auth: SoftAuthenticator, user: str = ALICE) -> dict:
    grant = open_grant(gw, user)
    fresh(gw, grant["grant_id"], user)
    r = begin_with_grant(gw, auth, grant["grant_id"], user)
    assert r.status_code == 200, r.text
    r = gw.post("/register/finish", self_finish(gw, auth, r.json(), grant["grant_id"], user), user)
    assert r.status_code == 200, r.text
    return r.json()["credential"]


def test_status_says_whether_self_enrolment_is_available(make_gateway, make_self_gateway):
    body = make_self_gateway().get().json()
    assert body["self_enrol"] == {"available": True, "reason": "", "cooling_off_s": 0}
    body = make_self_gateway({"self_enrol": {"enabled": False, "cooling_off_s": 600}}).get().json()
    assert body["self_enrol"] == {"available": False, "reason": "disabled", "cooling_off_s": 600}
    # A provider that cannot force a fresh sign-in (like nous): only codes.
    gw = make_gateway()
    clear_providers()
    register_provider(StubAuthProvider())
    body = gw.get().json()
    assert body["self_enrol"] == {"available": False, "reason": "provider_no_reauth", "cooling_off_s": 0}


def test_a_bearer_caller_opens_a_native_grant_without_a_cookie(sgw):
    r = sgw.post("/reauth/begin", {})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert "set-cookie" not in r.headers
    body = r.json()
    assert set(body) == {"grant_id", "expires_at", "provider"}
    assert body["expires_at"] == int(sgw.clock.t) + 600 and body["provider"] == "stub"
    assert len(b64u_decode(body["grant_id"])) == 16
    grant = sgw.store.grant(body["grant_id"], user_id=ALICE)
    assert grant is not None and (grant.client, grant.state, grant.provider) == ("native", "open", "stub")
    opened = [line for line in audit_lines() if line["event"] == "passkey_reauth_opened"]
    assert len(opened) == 1 and opened[0]["grant"] == body["grant_id"][:8]
    assert (opened[0]["user_id"], opened[0]["client"], opened[0]["auth"]) == (ALICE, "native", "bearer")
    assert body["grant_id"] not in json.dumps(audit_lines())


def test_a_cookie_caller_gets_the_binding_cookie_and_a_login_path(sgw):
    r = sgw.post("/reauth/begin", {}, headers=sgw.cookie(ALICE, BASE))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["login_path"] == f"/auth/login?provider=stub&reauth={body['grant_id']}"
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("__Host-hermes_reauth=")
    for attribute in ("HttpOnly", "Max-Age=600", "Path=/", "SameSite=none", "Secure"):
        assert attribute.lower() in cookie.lower(), attribute
    secret = cookie.split(";", 1)[0].split("=", 1)[1]
    grant = sgw.store.grant(body["grant_id"], user_id=ALICE)
    assert grant is not None and grant.client == "web"
    # Only the browser holding the cookie can complete it.
    assert sgw.store.grant_for_login(body["grant_id"], "stub", secret) is not None
    assert sgw.store.grant_for_login(body["grant_id"], "stub", None) is None
    assert sgw.store.grant_for_login(body["grant_id"], "stub", "x" + secret[1:]) is None
    assert secret not in json.dumps(audit_lines())
    # A cookie write without a listed Origin opens nothing.
    r = sgw.post("/reauth/begin", {}, headers=sgw.cookie(ALICE))
    assert (r.status_code, r.json()["error"]) == (403, "origin_not_listed")
    assert any(line["event"] == "passkey_reauth_refused" and line["reason"] == "origin_not_listed"
               for line in audit_lines())


def test_the_login_path_keeps_the_proxy_prefix(sgw):
    headers = sgw.cookie(ALICE, BASE) | {"X-Forwarded-Prefix": "/hermes"}
    r = sgw.post("/reauth/begin", {}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["login_path"] == f"/hermes/auth/login?provider=stub&reauth={r.json()['grant_id']}"
    # ``__Host-`` forbids a path; under a prefix the cookie is ``__Secure-`` and scoped to it.
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("__Secure-hermes_reauth=") and "path=/hermes" in cookie.lower()


def test_reauth_begin_is_refused_when_off_or_without_a_capable_provider(make_gateway, make_self_gateway):
    gw = make_self_gateway({"self_enrol": {"enabled": False}})
    r = gw.post("/reauth/begin", {})
    assert (r.status_code, r.json()["error"]) == (403, "self_enrol_disabled")
    gw = make_gateway()
    clear_providers()
    register_provider(StubAuthProvider())
    r = gw.post("/reauth/begin", {})
    assert (r.status_code, r.json()["error"]) == (403, "provider_no_reauth")
    assert gw.store.counts()["open_grants"] == 0
    refused = [line["reason"] for line in audit_lines() if line["event"] == "passkey_reauth_refused"]
    assert refused == ["disabled", "provider_no_reauth"]


def test_reauth_begin_is_limited_per_user_and_per_address(sgw):
    assert [sgw.post("/reauth/begin", {}).status_code for _ in range(6)] == [200] * 5 + [429]
    assert sgw.post("/reauth/begin", {}).headers["retry-after"] == "600"
    # Every test client shares one address: Bob is refused too.
    assert sgw.post("/reauth/begin", {}, BOB).status_code == 429
    assert sgw.store.counts()["open_grants"] == 5


def test_reauth_begin_per_user_limit_does_not_spend_the_address(sgw, monkeypatch):
    monkeypatch.setattr(routes, "REAUTH_BEGIN_PER_IP", SlidingWindowLimiter(1000, 600))
    assert [sgw.post("/reauth/begin", {}).status_code for _ in range(6)] == [200] * 5 + [429]
    assert sgw.post("/reauth/begin", {}, BOB).status_code == 200


def test_a_fresh_sign_in_enrols_a_passkey_marked_self(sgw, transports, hooks):
    alice, bob = transports(ALICE), transports(BOB)
    laptop = native()
    grant = open_grant(sgw)
    assert fresh(sgw, grant["grant_id"]).state == "fresh"
    r = begin_with_grant(sgw, laptop, grant["grant_id"])
    assert r.status_code == 200, r.text
    begin = r.json()
    assert begin["grant"] == {"expires_at": grant["expires_at"]}
    r = sgw.post("/register/finish", self_finish(sgw, laptop, begin, grant["grant_id"]))
    assert r.status_code == 200, r.text
    credential = r.json()["credential"]
    assert credential["created_via"] == "self" and "usable_from" not in credential
    assert [c["created_via"] for c in sgw.get().json()["credentials"]] == ["self"]
    spent = sgw.store.grant(grant["grant_id"], user_id=ALICE)
    assert spent is not None and spent.state == "spent"
    ref = {"id": credential["id"], "name": credential["name"], "rp_id": NATIVE_RP}
    assert alice.events() == [{"change": "added", "credential": ref, "at": int(sgw.clock.t)}] and bob.frames == []
    assert hooks == [{"change": "added", "user_id": ALICE, "credential": ref, "at": int(sgw.clock.t),
                      "via": "self"}]
    registered = [line for line in audit_lines() if line["event"] == "passkey_registered"]
    assert registered[-1]["created_via"] == "self" and registered[-1]["grant"] == grant["grant_id"][:8]
    # Usable at once (no cooling-off): it can sign a step-up.
    assert sgw.stepup("invite")["credentials"] == [{"rp_id": NATIVE_RP, "ids": [credential["id"]]}]


def test_a_browser_enrols_with_its_own_web_grant(sgw):
    headers = sgw.cookie(ALICE, BASE)
    r = sgw.post("/reauth/begin", {}, headers=headers)
    secret = r.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    grant_id = r.json()["grant_id"]
    fresh(sgw, grant_id, client="web", secret=secret)
    browser = web_authenticator(BASE)
    r = begin_with_grant(sgw, browser, grant_id, headers=headers)
    assert r.status_code == 200, r.text
    r = sgw.post("/register/finish", self_finish(sgw, browser, r.json(), grant_id), headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["credential"]["created_via"] == "self"


def test_register_finish_takes_exactly_one_authority(sgw):
    laptop = native()
    grant = open_grant(sgw)
    fresh(sgw, grant["grant_id"])
    begin = begin_with_grant(sgw, laptop, grant["grant_id"]).json()
    body = self_finish(sgw, laptop, begin, grant["grant_id"])
    both = body | {"code": sgw.store.mint_code(user_id=ALICE).code}
    neither = {k: v for k, v in body.items() if k != "grant_id"}
    for bad in (both, neither, body | {"grant_id": 7}, body | {"grant_id": ""}, body | {"grant_id": "g" * 65}):
        r = sgw.post("/register/finish", bad)
        assert (r.status_code, r.json()["error"]) == (400, "bad_request"), bad.get("grant_id")
    assert sgw.get().json()["credentials"] == []
    assert sgw.post("/register/finish", body).status_code == 200


@pytest.mark.parametrize("case", ["open", "expired", "other_user", "spent", "failed", "other_client", "unknown"])
def test_a_grant_that_cannot_authorise_is_refused_at_begin_and_finish(sgw, case):
    laptop = native()
    caller = ALICE
    expected: tuple = ("unknown", None)
    if case == "unknown":
        grant_id = b64u(b"\x01" * 16)
    elif case == "other_client":
        r = sgw.post("/reauth/begin", {}, headers=sgw.cookie(ALICE, BASE))
        grant_id = r.json()["grant_id"]
        secret = r.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
        fresh(sgw, grant_id, client="web", secret=secret)  # a fresh browser grant, used by the app
    else:
        grant_id = open_grant(sgw)["grant_id"]
        if case == "open":
            expected = ("not_fresh", None)
        elif case == "failed":
            fresh(sgw, grant_id, user=BOB)  # the re-sign-in came back as someone else
            expected = ("failed", "user_mismatch")
        else:
            fresh(sgw, grant_id)
        if case == "expired":
            sgw.clock.t += 601
        elif case == "other_user":
            caller = BOB
        elif case == "spent":
            self_finish_ok = begin_with_grant(sgw, laptop, grant_id).json()
            assert sgw.post("/register/finish", self_finish(sgw, laptop, self_finish_ok, grant_id)).status_code == 200
            laptop = native()
            expected = ("spent", None)
    r = begin_with_grant(sgw, laptop, grant_id, caller)
    assert (r.status_code, r.json()["error"], r.json()["reason"], r.json().get("failure")) == (
        403, "reauth_invalid", *expected)
    # Finish re-checks it (a registration opened without the grant cannot borrow it either).
    begin = sgw.begin_registration(laptop, caller)
    r = sgw.post("/register/finish", self_finish(sgw, laptop, begin, grant_id, caller), caller)
    assert (r.status_code, r.json()["error"], r.json()["reason"], r.json().get("failure")) == (
        403, "reauth_invalid", *expected)
    assert len(sgw.get(caller).json()["credentials"]) == (1 if case == "spent" else 0)
    assert any(line.get("grant_reason") == expected[0] for line in audit_lines())


def test_failed_grants_count_like_failed_codes(sgw):
    laptop = native()
    begin = sgw.begin_registration(laptop)
    grant_id = open_grant(sgw)["grant_id"]  # never completed: not fresh
    statuses = [sgw.post("/register/finish", self_finish(sgw, laptop, begin, grant_id)).status_code
                for _ in range(6)]
    assert statuses == [403] * 5 + [429]


def test_self_enrolment_switched_off_refuses_a_grant_opened_before(make_self_gateway):
    gw = make_self_gateway()
    laptop = native()
    grant_id = open_grant(gw)["grant_id"]
    fresh(gw, grant_id)
    begin = gw.begin_registration(laptop)
    gw.config["confirm"]["passkey"]["self_enrol"] = {"enabled": False}
    r = begin_with_grant(gw, native(), grant_id)
    assert (r.status_code, r.json()["error"]) == (403, "self_enrol_disabled")
    r = gw.post("/register/finish", self_finish(gw, laptop, begin, grant_id))
    assert (r.status_code, r.json()["error"]) == (403, "self_enrol_disabled")
    assert gw.get().json()["credentials"] == []
    # Codes keep working.
    r = gw.post("/register/finish", gw.finish_body(laptop, begin, gw.store.mint_code(user_id=ALICE).code))
    assert r.status_code == 200 and r.json()["credential"]["created_via"] == "operator"


def test_a_cooling_off_passkey_is_listed_but_cannot_confirm_or_sign_and_can_be_revoked(make_self_gateway, hooks):
    gw = make_self_gateway({"self_enrol": {"enabled": True, "cooling_off_s": 600}})
    # With only a cooling-off passkey there is nothing to step up with.
    first = native()
    cooling = self_enrol(gw, first)
    assert cooling["usable_from"] == int(gw.clock.t) + 600
    listed = gw.get().json()["credentials"]
    assert [c["usable_from"] for c in listed] == [int(gw.clock.t) + 600]
    assert gw.store.snapshot(ALICE) == ()  # no `confirm` target
    assert gw.post("/stepup/begin", {"purpose": "invite"}).json()["reason"] == "not_enrolled"
    # An earlier, usable passkey (from a code) is the only signer.
    phone = native()
    phone_id = gw.enrol(phone)["id"]
    stepup = gw.stepup("invite")
    assert stepup["credentials"] == [{"rp_id": NATIVE_RP, "ids": [phone_id]}]
    assert [c.credential_id for c in gw.store.snapshot(ALICE)] == [phone.credential_id]
    # Signing an invite with the cooling-off passkey is refused: it cannot mint a code for a usable one.
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(first, stepup)})
    assert (r.status_code, r.json()["error"], r.json()["reason"]) == (422, "assertion_invalid", "unknown_credential")
    # But it can be revoked, with the usable one.
    stepup = gw.stepup("revoke", cooling["id"])
    r = gw.post("/revoke", {"credential_id": cooling["id"], "stepup_id": stepup["stepup_id"],
                            "assertion": gw.sign_stepup(phone, stepup)})
    assert r.status_code == 200, r.text
    assert [c["id"] for c in gw.get().json()["credentials"]] == [phone_id]
    assert [(h["change"], h["via"]) for h in hooks] == [("added", "self"), ("added", "operator"),
                                                        ("revoked", "passkey")]


def test_a_cooling_off_passkey_becomes_usable_when_the_period_ends(make_self_gateway):
    gw = make_self_gateway({"self_enrol": {"enabled": True, "cooling_off_s": 600}})
    laptop = native()
    credential = self_enrol(gw, laptop)
    gw.clock.t += 600
    assert "usable_from" not in gw.get().json()["credentials"][0]
    stepup = gw.stepup("invite")
    assert stepup["credentials"] == [{"rp_id": NATIVE_RP, "ids": [credential["id"]]}]
    r = gw.post("/invites", {"stepup_id": stepup["stepup_id"], "assertion": gw.sign_stepup(laptop, stepup)})
    assert r.status_code == 200, r.text


def test_no_grant_secret_or_id_reaches_the_audit_log(sgw, caplog):
    headers = sgw.cookie(ALICE, BASE)
    r = sgw.post("/reauth/begin", {}, headers=headers)
    secret = r.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    grant_id = r.json()["grant_id"]
    fresh(sgw, grant_id, client="web", secret=secret)
    browser = web_authenticator(BASE)
    begin = begin_with_grant(sgw, browser, grant_id, headers=headers).json()
    sgw.post("/register/finish", self_finish(sgw, browser, begin, grant_id), headers=headers)
    text = json.dumps(audit_lines()) + caplog.text
    assert secret not in text and grant_id not in text
    assert grant_id[:8] in text


def test_end_to_end_a_browser_signs_in_again_and_adds_a_self_passkey(sgw, transports, hooks):
    """Through the real sign-in routes: reauth/begin sets the binding cookie, /auth/login asks the provider
    for a fresh sign-in, the callback completes the grant, and the grant enrols one passkey."""
    alice = transports(ALICE)
    browser = TestClient(web_server.app, base_url=BASE, follow_redirects=False)
    browser.cookies.set("hermes_session_at", sgw.bearer(ALICE)["Authorization"].split(" ", 1)[1])
    origin = {"Origin": BASE}
    r = browser.post(f"{routes.PREFIX}/reauth/begin", json={}, headers=origin)
    assert r.status_code == 200, r.text
    grant_id, login_path = r.json()["grant_id"], r.json()["login_path"]
    r = browser.get(login_path + "&next=/settings")
    assert r.status_code in (302, 303, 307), r.text
    assert sgw.provider.fresh == [True]  # type: ignore[attr-defined]
    r = browser.get(r.headers["location"])  # the provider's redirect back to the callback
    assert r.status_code in (302, 303, 307), r.text
    grant = sgw.store.grant(grant_id, user_id=ALICE)
    assert grant is not None and grant.state == "fresh"
    laptop = web_authenticator(BASE)
    r = browser.post(f"{routes.PREFIX}/register/begin", headers=origin,
                     json={"rp_id": laptop.rp_id, "base_url": BASE, "name": "Laptop", "grant_id": grant_id})
    assert r.status_code == 200, r.text
    r = browser.post(f"{routes.PREFIX}/register/finish", headers=origin,
                     json=self_finish(sgw, laptop, r.json(), grant_id))
    assert r.status_code == 200, r.text
    assert r.json()["credential"]["created_via"] == "self"
    assert [e["change"] for e in alice.events()] == ["added"] and [h["via"] for h in hooks] == ["self"]
    events = [line["event"] for line in audit_lines()]
    assert events.index("passkey_reauth_opened") < events.index("passkey_reauth_fresh") \
        < events.index("passkey_registered")


def test_end_to_end_a_stale_sign_in_cannot_enrol(sgw):
    browser = TestClient(web_server.app, base_url=BASE, follow_redirects=False)
    browser.cookies.set("hermes_session_at", sgw.bearer(ALICE)["Authorization"].split(" ", 1)[1])
    r = browser.post(f"{routes.PREFIX}/reauth/begin", json={}, headers={"Origin": BASE})
    grant_id = r.json()["grant_id"]
    sgw.provider.auth_time = int(sgw.clock.t) - 3600  # type: ignore[attr-defined]  # the IdP reused an old sign-in
    r = browser.get(r.json()["login_path"])
    browser.get(r.headers["location"])
    r = begin_with_grant(sgw, web_authenticator(BASE), grant_id, headers=sgw.cookie(ALICE, BASE))
    assert (r.status_code, r.json()["reason"], r.json()["failure"]) == (403, "failed", "auth_not_fresh")
