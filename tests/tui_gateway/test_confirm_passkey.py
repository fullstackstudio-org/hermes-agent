"""``confirm`` at level ``passkey`` (``tui_gateway/confirm_passkey.py`` through ``confirm.request`` and
``server_requests.send_gated``), end to end with the real store, the real verifier, a software
authenticator and fake client connections.

Pinned here: the capability and the advertisement (contract §8); the bound user is the running turn's
submitter as the gateway resolved it, also on a tool thread and in a shared session; ``unavailable`` with
the right reason and nothing sent when the level cannot work; only connections signed in as the bound
user with an accepted, enrolled RP get the frame, may answer, or see it on reconnect; a valid assertion
confirms with ``verified: true``, commits once and writes a receipt; an assertion for another request,
session, base URL, text or user is refused (4034 with the reason) and the request stays open; five refused
answers settle it ``unavailable (verification_failed)``; a credential revoked while the request is open is
refused at commit; ``plain`` after a failed ``passkey`` is refused for the window; the validator is
memoised and never touches the store; the ``pre_confirm_request`` hook fires without the text.
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import copy
import json
import threading
import time

import pytest

from hermes_cli.dashboard_auth.passkeys import webauthn
from hermes_cli.dashboard_auth.passkeys.challenge import b64u, b64u_decode
from hermes_cli.dashboard_auth.passkeys.settings import gateway_context, settings_from_config
from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
from hermes_cli.dashboard_auth.passkeys.webauthn import AssertionRequest, RegistrationOk, verify_registration
from tests.hermes_cli.passkey_soft_authenticator import SoftAuthenticator, web_authenticator
from tests.tui_gateway.test_confirm_request import (  # noqa: F401 - fixtures are used by name
    _advertise, _as, _drain, _Peer, _session, _wait_open, audit_records, server)

BASE = "https://gw.example.com"
NATIVE_RP = "confirm.hermie.dev"
NATIVE_ORIGIN = "https://confirm.hermie.dev"
ALICE, BOB = "self_hosted:alice", "self_hosted:bob"
TEXT = {"title": "Pay invoice", "summary": "Pay 120.00 EUR to Example Plumbing for invoice 2026-114.",
        "detail": "IBAN NL00 TEST 0123 4567 89"}


def native(**kw) -> SoftAuthenticator:
    return SoftAuthenticator(rp_id=NATIVE_RP, client_origin=NATIVE_ORIGIN, **kw)


class Passkeys:
    """The gateway's passkey side for one test: config, store, enrolment."""

    def __init__(self, store: PasskeyStore, config: dict):
        self.store, self.config = store, config

    @property
    def ctx(self):
        return gateway_context(self.store.identity(), settings_from_config(self.config))

    def enrol(self, auth: SoftAuthenticator, user: str = ALICE, name: str = "Phone — gw.example.com") -> bytes:
        pending = self.store.open_pending("register", user_id=user, rp_id=auth.rp_id, base_url=BASE, subject=name)
        body = auth.register(self.store.gateway_id, pending.registration())
        verdict = verify_registration(self.ctx, pending.registration(), body)
        assert isinstance(verdict, RegistrationOk), verdict
        code = self.store.mint_code(user_id=user).code
        self.store.add_credential(user_id=user, code=code, registration=verdict)
        return auth.credential_id

    def answer(self, auth: SoftAuthenticator, frame: dict, *, base_url: str = BASE, with_user_handle: bool = True,
               **override) -> dict:
        """What *auth* answers for *frame* as dialed at *base_url*; ``override`` changes what it signs."""
        params, passkey = frame["params"], frame["params"]["passkey"]
        fields = dict(user_id=passkey["user"]["id"], request_id=frame["id"], nonce=b64u_decode(passkey["nonce"]),
                      title=params["title"], summary=params["summary"], detail=params.get("detail"),
                      session_id=params["session_id"], purpose="confirm")
        fields.update(override)
        handle_key = getattr(self, "handle_key", None) or self.store.identity()[1]
        return auth.assert_(b64u_decode(passkey["gateway_id"]), handle_key, AssertionRequest(**fields),
                            base_url, with_user_handle=with_user_handle)


@pytest.fixture
def passkeys(monkeypatch, tmp_path, server):
    from tui_gateway import confirm_passkey
    config = {"confirm": {"passkey": {"enabled": True, "base_urls": [BASE]}}}
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: copy.deepcopy(config))
    store = PasskeyStore(tmp_path / "dashboard_auth" / "passkeys.db")
    monkeypatch.setattr(confirm_passkey, "_store", lambda: store)
    confirm_passkey.reset_for_tests()
    yield Passkeys(store, config)
    confirm_passkey.reset_for_tests()


def _advertise_passkey(server, peer, *, kind="native", rp_id=NATIVE_RP, v=1):
    return _as(peer, server.handle_request, {"id": 1, "method": "client.capabilities", "params": {
        "server_requests": True, "confirm": ["plain", "passkey"], "confirm_passkey": {"v": v, "kind": kind,
                                                                                     "rp_id": rp_id}}})


def _turn(server, submitter):
    """Bind the running turn's submitter the way ``prompt_turn.run_body`` does (None: a turn nobody submitted)."""
    return server._turn_auth_user.set(submitter if submitter is not None else server._UNATTRIBUTED_TURN)


def _ask(server, sid, submitter=(ALICE, "Alice"), *, level="passkey", timeout=5, **text):
    """``confirm.request`` on a thread inside a turn submitted by *submitter*; returns (thread, box)."""
    from tui_gateway import confirm
    params = confirm.build_params(level=level, **(text or TEXT))
    box: dict = {}

    def run():
        token = _turn(server, submitter)
        try:
            box["r"] = confirm.request(sid, params, timeout=timeout)
        finally:
            server._turn_auth_user.reset(token)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def _ask_now(server, sid, submitter=(ALICE, "Alice"), **kw):
    thread, box = _ask(server, sid, submitter, **kw)
    thread.join(10)
    return box["r"]


def _answer_rpc(server, peer, rid, result, n=9):
    return _as(peer, server.handle_request, {"id": n, "method": "request.answer", "params": {"id": rid,
                                                                                            "result": result}})


def _frame(server, peer, sid="s1"):
    _wait_open()
    deadline = time.monotonic() + 5
    while not peer.requests() and time.monotonic() < deadline:
        time.sleep(0.005)
    return peer.requests()[-1]


def _alice_session(server, passkeys, *extra, auth=None):
    """Session s1 with Alice's phone (native, enrolled) attached and advertising; returns (phone, auth)."""
    auth = auth or native()
    passkeys.enrol(auth)
    phone = _Peer("phone", ALICE)
    _session(server, "s1", phone, *extra, creator=ALICE)
    assert _advertise_passkey(server, phone)["result"]["confirm"] == ["passkey", "plain"]
    return phone, auth


# ── capability ──────────────────────────────────────────────────────────────────────────────


def test_capability_and_advertisement(server, passkeys):
    from tui_gateway import server_requests
    phone, token_client = _Peer("phone", ALICE), _Peer("token")
    first = _advertise(server, phone)["result"]
    assert first["confirm_passkey"] == {"v": 1, "enabled": True, "reason": "", "gateway_id": b64u(
        passkeys.store.gateway_id), "rp": {"native": [NATIVE_RP], "web": ["gw.example.com"]}, "versions": [1, 2]}
    assert _advertise(server, token_client)["result"]["confirm_passkey"]["reason"] == "no_identity"
    # Accepted: a signed-in connection, an RP this gateway accepts for that kind.
    assert _advertise_passkey(server, phone)["result"]["confirm"] == ["passkey", "plain"]
    assert server_requests._confirm_details[phone] == {"passkey": {"kind": "native", "rp_id": NATIVE_RP, "v": 1}}
    assert _advertise_passkey(server, phone, kind="web", rp_id="gw.example.com")["result"]["confirm"] == [
        "passkey", "plain"]
    # Not accepted (plain still is, and the call never fails): no identity, unknown RP, wrong kind, other v.
    for peer, kw in ((token_client, {}), (phone, {"rp_id": "evil.example"}),
                     (phone, {"kind": "web", "rp_id": NATIVE_RP}), (phone, {"kind": "carrier-pigeon"}),
                     (phone, {"v": 3}), (phone, {"v": 0})):
        response = _advertise_passkey(server, peer, **kw)
        assert response["result"]["confirm"] == ["plain"], kw
    assert phone not in server_requests._confirm_details
    # A passkey listed without the detail object is ignored too.
    assert _advertise(server, phone, confirm=["plain", "passkey"])["result"]["confirm"] == ["plain"]
    # A later client's extra field is fine; wrong types only drop passkey, never fail the call (4000).
    def advertise(detail):
        return _as(phone, server.handle_request, {"id": 1, "method": "client.capabilities", "params": {
            "server_requests": True, "confirm": ["plain", "passkey"], "confirm_passkey": detail}})
    assert advertise({"v": 1, "kind": "native", "rp_id": NATIVE_RP, "attachment": "platform"})["result"][
        "confirm"] == ["passkey", "plain"]
    for wrong in ({"v": "1", "kind": "native", "rp_id": NATIVE_RP}, {"v": 1, "kind": 5, "rp_id": NATIVE_RP},
                  {"v": 1, "kind": "native", "rp_id": [NATIVE_RP]}, {"v": True, "kind": "native", "rp_id": NATIVE_RP},
                  {}):
        response = advertise(wrong)
        assert "error" not in response and response["result"]["confirm"] == ["plain"], wrong
    # The contract carries both objects.
    from tui_gateway.contracts import registry
    contract = registry.METHODS["client.capabilities"]
    contract.result.model_validate(first)
    contract.params.model_validate({"server_requests": True, "confirm": ["plain", "passkey"],
                                    "confirm_passkey": {"v": 1, "kind": "native", "rp_id": NATIVE_RP}})


def test_capability_reasons_follow_the_settings(server, passkeys):
    phone = _Peer("phone", ALICE)
    passkeys.config["confirm"]["passkey"]["base_urls"] = []
    assert _advertise(server, phone)["result"]["confirm_passkey"]["reason"] == "no_base_url"
    passkeys.config["confirm"]["passkey"]["base_urls"] = ["http://192.168.1.10:9119"]
    assert _advertise(server, phone)["result"]["confirm_passkey"]["reason"] == "private_origin"
    assert _advertise_passkey(server, phone)["result"]["confirm"] == ["plain"]
    passkeys.config["confirm"]["passkey"]["enabled"] = False
    cap = _advertise(server, phone)["result"]["confirm_passkey"]
    assert cap == {"v": 1, "enabled": False, "reason": "disabled", "gateway_id": "", "rp": {"native": [], "web": []},
                   "versions": [1, 2]}


# ── the happy path ──────────────────────────────────────────────────────────────────────────


def test_valid_native_assertion_confirms_verified_and_commits_once(server, passkeys, audit_records):
    from tui_gateway import server_requests
    from tui_gateway.contracts import registry
    desk = _Peer("desk", ALICE)
    phone, auth = _alice_session(server, passkeys, desk)
    assert _advertise_passkey(server, desk)["result"]["confirm"] == ["passkey", "plain"]
    before = int(time.time())
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    params = frame["params"]
    registry.SERVER_REQUESTS["confirm"].params.model_validate(params)
    assert {k: params[k] for k in ("title", "summary", "detail", "level")} == {**TEXT, "level": "passkey"}
    passkey = params["passkey"]
    assert passkey["v"] == 1 and passkey["base_url"] == BASE and passkey["user"] == {"id": ALICE, "name": "Alice"}
    assert passkey["gateway_id"] == b64u(passkeys.store.gateway_id)
    assert passkey["credentials"] == [{"rp_id": NATIVE_RP, "ids": [b64u(auth.credential_id)]}]
    assert len(b64u_decode(passkey["nonce"])) == 32 and before + 5 <= passkey["expires_at"] <= int(time.time()) + 6
    assert len(desk.requests()) == 1
    answer = passkeys.answer(auth, frame)
    assert _answer_rpc(server, phone, frame["id"], answer)["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "confirmed", "method": "passkey", "verified": True}
    # One receipt, for exactly this request; digests only.
    receipts = passkeys.store.receipts(user_id=ALICE)
    assert [(r.purpose, r.session_id, r.request_id, r.origin) for r in receipts] == [("confirm", "s1", frame["id"],
                                                                                       BASE)]
    assert {"id": frame["id"], "method": "confirm", "reason": "resolved"} in _drain(desk, 1)
    assert server_requests.open_requests("s1") == []
    events = [e for e, _ in audit_records]
    assert events == ["confirm_request", "confirm_passkey_verified", "confirm_outcome"]
    verified = dict(audit_records)["confirm_passkey_verified"]
    assert verified["user_id"] == ALICE and verified["credential"] == b64u(auth.credential_id)[:16]
    assert verified["counter_warning"] is False and verified["rp_id"] == NATIVE_RP
    outcome = dict(audit_records)["confirm_outcome"]
    assert outcome["verified"] is True and outcome["acting_user"] == ALICE and outcome["answered_by"] == ALICE
    dumped = json.dumps(audit_records)
    for secret in (*TEXT.values(), passkey["nonce"], answer["passkey"]["signature"]):
        assert secret not in dumped


def test_a_bare_response_frame_also_confirms(server, passkeys):
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": frame["id"], "result": passkeys.answer(auth, frame)}, phone)
    thread.join(5)
    assert box["r"].verified is True


def test_web_rp_device_bound_credential_confirms(server, passkeys):
    browser = web_authenticator(BASE, synced=False)
    passkeys.enrol(browser, name="Browser — gw.example.com")
    tab = _Peer("tab", ALICE)
    _session(server, "s1", tab, creator=ALICE)
    assert _advertise_passkey(server, tab, kind="web", rp_id="gw.example.com")["result"]["confirm"] == [
        "passkey", "plain"]
    for _ in range(2):  # the counter goes up each time
        thread, box = _ask(server, "s1")
        frame = _frame(server, tab)
        assert _answer_rpc(server, tab, frame["id"], passkeys.answer(browser, frame))["result"]["status"] == "ok"
        thread.join(5)
        assert box["r"].verified is True
    assert passkeys.store.credential(browser.credential_id).sign_count == 2


def test_decline_needs_no_assertion_and_is_not_verified(server, passkeys):
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    # A decline is exactly {decision: declined, method: tap}; anything else is a refused answer.
    refused = _answer_rpc(server, phone, frame["id"], {"decision": "declined", "method": "tap", "verified": False})
    assert refused["error"]["code"] == 4034 and refused["error"]["data"] == {"reason": "bad_shape"}
    assert _answer_rpc(server, phone, frame["id"], {"decision": "declined", "method": "tap"})["result"] == {
        "status": "ok"}
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "declined", "method": "tap", "verified": False}
    assert passkeys.store.receipts() == []


def test_a_client_that_cannot_run_the_ceremony_is_unavailable(server, passkeys):
    phone, _auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": frame["id"], "error": {
        "code": 4040, "message": "passkey ceremony unavailable", "data": {"reason": "no_credential"}}}, phone)
    thread.join(5)
    assert box["r"].outcome == "unavailable" and box["r"].reason == "error_response"


# ── refusals ────────────────────────────────────────────────────────────────────────────────


def test_assertions_for_anything_else_are_refused_and_the_request_stays_open(server, passkeys, audit_records):
    from tui_gateway import server_requests
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    nonce = b64u_decode(frame["params"]["passkey"]["nonce"])
    cases = [
        ("another request", {"request_id": "srq-000000000000"}, {}, "challenge_mismatch"),
        ("another session", {"session_id": "s2"}, {}, "challenge_mismatch"),
        ("another text", {"summary": "Pay 1,200.00 EUR to Example Plumbing."}, {}, "challenge_mismatch"),
        ("another user", {"user_id": BOB}, {"with_user_handle": False}, "challenge_mismatch"),
        ("another base URL claimed", {}, {"base_url": "https://evil.example"}, "base_url_not_accepted"),
    ]
    assert len(nonce) == 32
    for n, (label, override, kw, reason) in enumerate(cases[:4]):
        refused = _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame, **kw, **override), n=n)
        assert refused["error"] == {"code": 4034, "message": "answer refused", "data": {"reason": reason}}, label
        assert thread.is_alive() and frame["id"] in server_requests._open, label
    # The relay case: another gateway's base URL (signed for it) is not one this gateway listed.
    # It is also the fifth refusal: answered too_many_attempts, audited with its own reason.
    label, override, kw, reason = cases[4]
    refused = _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame, **kw, **override))
    assert refused["error"]["data"] == {"reason": "too_many_attempts"}
    refusals = [f for e, f in audit_records if e == "confirm_passkey_refused"]
    assert [f["reason"] for f in refusals] == [c[3] for c in cases] and refusals[-1]["refusals_exhausted"] is True
    assert refusals[-1]["base_url"] == "https://evil.example"
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "unavailable", "method": None, "verified": False,
                                  "reason": "verification_failed"}


def test_four_refusals_then_a_valid_answer_still_confirms(server, passkeys):
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    for n in range(4):
        bad = passkeys.answer(auth, frame, summary=f"other text {n}")
        assert _answer_rpc(server, phone, frame["id"], bad, n=n)["error"]["code"] == 4034
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"]["status"] == "ok"
    thread.join(5)
    assert box["r"].verified is True


def test_five_refusals_settle_the_request(server, passkeys, audit_records):
    """Bare frames count as well as ``request.answer``; client-sent ``verified`` and a plain-style tap are
    shapes the level refuses. The fifth is refused with ``too_many_attempts`` and every client is told."""
    desk = _Peer("desk", ALICE)
    phone, auth = _alice_session(server, passkeys, desk)
    _advertise_passkey(server, desk)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    good = passkeys.answer(auth, frame)
    bad = [{"decision": "confirmed", "method": "tap"}, {**good, "verified": True},
           passkeys.answer(auth, frame, title="Another title"), {**good, "passkey": {**good["passkey"], "v": 2}}]
    for n, result in enumerate(bad[:2]):
        assert _answer_rpc(server, phone, frame["id"], result, n=n)["error"]["data"] == {"reason": "bad_shape"}
    _as(desk, server.dispatch, {"jsonrpc": "2.0", "id": frame["id"], "result": bad[2]}, desk)  # counted, no reply
    assert _answer_rpc(server, phone, frame["id"], bad[3])["error"]["data"] == {"reason": "bad_shape"}
    assert thread.is_alive()
    last = _answer_rpc(server, desk, frame["id"], passkeys.answer(auth, frame, nonce=b"\x00" * 32))
    assert last["error"] == {"code": 4034, "message": "answer refused", "data": {"reason": "too_many_attempts"}}
    thread.join(5)
    assert box["r"].reason == "verification_failed"
    assert {"id": frame["id"], "method": "confirm", "reason": "too_many_attempts"} in _drain(desk, 1)
    # Nothing is open any more: the valid answer is too late.
    assert _answer_rpc(server, phone, frame["id"], good)["result"] == {"status": "expired"}
    assert [f["reason"] for e, f in audit_records if e == "confirm_passkey_refused"] == [
        "bad_shape", "bad_shape", "challenge_mismatch", "bad_shape", "challenge_mismatch"]
    assert passkeys.store.receipts() == []


# ── who sees and answers it ─────────────────────────────────────────────────────────────────


def test_a_connection_signed_in_as_someone_else_never_sees_it_and_gets_4033(server, passkeys):
    from tui_gateway import server_requests
    bob_auth = native()
    passkeys.enrol(bob_auth, user=BOB)
    bob = _Peer("bob", BOB)
    token = _Peer("token")  # no identity at all
    phone, auth = _alice_session(server, passkeys, bob, token)
    assert _advertise_passkey(server, bob)["result"]["confirm"] == ["passkey", "plain"]
    _advertise(server, token, confirm=["plain"])
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    assert bob.requests() == [] and token.requests() == []
    assert _as(bob, server._open_requests, "s1") == [] and _as(token, server._open_requests, "s1") == []
    # Bob answers with his own valid passkey for the frame he never got: refused before any check, not counted.
    stolen = passkeys.answer(bob_auth, frame, user_id=BOB)
    for n in range(6):
        assert _answer_rpc(server, bob, frame["id"], stolen, n=n)["error"]["code"] == 4033
        _as(bob, server.dispatch, {"jsonrpc": "2.0", "id": frame["id"], "result": stolen}, bob)
    assert _answer_rpc(server, token, frame["id"], passkeys.answer(auth, frame))["error"]["code"] == 4033
    with server_requests._lock:
        assert server_requests._open[frame["id"]].refusals == 0
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"]["status"] == "ok"
    thread.join(5)
    assert box["r"].verified is True


def test_a_connection_without_a_credential_for_its_rp_is_not_a_target(server, passkeys):
    """Alice is enrolled for the native RP only; her browser tab advertised the web RP: it is not asked."""
    tab = _Peer("tab", ALICE)
    phone, auth = _alice_session(server, passkeys, tab)
    _advertise_passkey(server, tab, kind="web", rp_id="gw.example.com")
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    assert tab.requests() == [] and _as(tab, server._open_requests, "s1") == []
    assert _answer_rpc(server, tab, frame["id"], passkeys.answer(auth, frame))["error"]["code"] == 4033
    _answer_rpc(server, phone, frame["id"], {"decision": "declined", "method": "tap"})
    thread.join(5)


def test_reconnect_gets_the_request_back_and_answers_it(server, passkeys):
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    # The phone's socket drops; a new one of the same person attaches and advertises again.
    server.unregister_live_transport(phone)
    server._detach_session_transport(server._sessions["s1"], phone)
    again = _Peer("phone-again", ALICE)
    assert _as(again, server._open_requests, "s1") == []  # not attached yet
    server._attach_session_transport(server._sessions["s1"], again)
    assert _as(again, server._open_requests, "s1") == []  # attached, but has not advertised passkey yet
    _advertise_passkey(server, again)
    listed = _as(again, server._open_requests, "s1")
    assert [entry["id"] for entry in listed] == [frame["id"]]
    assert listed[0]["params"]["passkey"] == frame["params"]["passkey"]
    # The challenge does not depend on the socket: the restored frame is enough.
    restored = {"id": listed[0]["id"], "params": listed[0]["params"]}
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, restored))["error"]["code"] == 4033
    assert _answer_rpc(server, again, frame["id"], passkeys.answer(auth, restored))["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].verified is True and again.requests() == []


def test_two_valid_answers_at_once_commit_once(server, passkeys):
    desk = _Peer("desk", ALICE)
    phone, auth = _alice_session(server, passkeys, desk)
    _advertise_passkey(server, desk)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    answers = [passkeys.answer(auth, frame), passkeys.answer(auth, frame)]
    statuses: list = []
    barrier = threading.Barrier(2)

    def answer(peer, result):
        barrier.wait()
        statuses.append(_answer_rpc(server, peer, frame["id"], result)["result"]["status"])

    workers = [threading.Thread(target=answer, args=(peer, result)) for peer, result in zip((phone, desk), answers)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(5)
    thread.join(5)
    assert sorted(statuses) == ["expired", "ok"] and box["r"].verified is True
    assert len(passkeys.store.receipts()) == 1


# ── commit ──────────────────────────────────────────────────────────────────────────────────


def test_a_credential_revoked_while_the_request_is_open_is_refused_at_commit(server, passkeys, audit_records):
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    assert passkeys.store.revoke(auth.credential_id, by="operator") is not None
    # The validator works on the snapshot taken when the request opened; the commit re-reads the store.
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"]["status"] == "ok"
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "unavailable", "method": None, "verified": False,
                                  "reason": "verification_failed"}
    refused = dict(audit_records)["confirm_passkey_refused"]
    assert refused["reason"] == "revoked" and refused["at_commit"] is True
    assert passkeys.store.receipts() == []
    # request.answer said "ok" (received and valid); the commit failed, so the answering app is told it did
    # not count.
    assert {"id": frame["id"], "method": "confirm", "reason": "verification_failed"} in _drain(phone, 2)


def test_a_store_failure_at_commit_is_never_consent(server, passkeys, monkeypatch):
    from hermes_cli.dashboard_auth.passkeys.store import StoreError
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)

    def broken(*a, **kw):
        raise StoreError("disk gone")

    monkeypatch.setattr(passkeys.store, "commit_assertion", broken)
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].outcome == "unavailable" and box["r"].reason == "verification_failed"
    assert [c["reason"] for c in _drain(phone, 2)] == ["resolved", "verification_failed"]


def test_the_validator_is_memoised_and_never_touches_the_store(server, passkeys, monkeypatch):
    phone, auth = _alice_session(server, passkeys)
    calls = {"verify": 0, "store": 0}
    real_verify = webauthn.verify_assertion

    def counting_verify(*a, **kw):
        calls["verify"] += 1
        return real_verify(*a, **kw)

    monkeypatch.setattr(webauthn, "verify_assertion", counting_verify)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    real_commit = passkeys.store.commit_assertion
    passkeys.store.identity()  # read once before the store's readers are replaced (the test signs with it)
    handle_key = passkeys.store.identity()[1]
    monkeypatch.setattr(Passkeys, "handle_key", handle_key, raising=False)
    commits: list = []
    for name in ("snapshot", "credentials", "credential", "identity", "receipts"):
        monkeypatch.setattr(passkeys.store, name, lambda *a, _n=name, **kw: calls.__setitem__("store", calls["store"] + 1))
    monkeypatch.setattr(passkeys.store, "commit_assertion", lambda *a, **kw: commits.append(1) or real_commit(*a, **kw))
    bad = passkeys.answer(auth, frame, summary="other")
    for n in range(2):  # the same refused answer twice: verified once
        assert _answer_rpc(server, phone, frame["id"], bad, n=n)["error"]["code"] == 4034
    good = passkeys.answer(auth, frame)
    assert _answer_rpc(server, phone, frame["id"], good)["result"]["status"] == "ok"  # validated twice, once
    thread.join(5)
    assert box["r"].verified is True
    assert calls == {"verify": 2, "store": 0} and commits == [1]


def test_prune_runs_after_a_verified_confirmation_at_most_hourly(server, passkeys, monkeypatch):
    phone, auth = _alice_session(server, passkeys)
    pruned: list = []
    monkeypatch.setattr(passkeys.store, "prune", lambda **kw: pruned.append(kw) or {})
    for _ in range(2):
        thread, box = _ask(server, "s1")
        frame = _frame(server, phone)
        _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))
        thread.join(5)
        assert box["r"].verified is True
    assert pruned == [{"receipts_days": 90}]


# ── unavailable before anything is sent ─────────────────────────────────────────────────────


@pytest.mark.parametrize("case, reason", [
    ("token_mode", "no_identity"),
    ("unattributed_turn", "no_acting_user"),
    ("no_turn", "no_acting_user"),
    ("shared_unattributed", "no_acting_user"),
    ("not_enrolled", "not_enrolled"),
    ("enrolled_for_an_rp_no_longer_accepted", "not_enrolled"),
    ("disabled", "disabled"),
    ("no_base_url", "no_base_url"),
    ("private_only", "private_origin"),
])
def test_unavailable_with_the_reason_and_nothing_sent(server, passkeys, case, reason):
    from tui_gateway import confirm, server_requests
    phone = _Peer("phone", ALICE)
    submitter = (ALICE, "Alice")
    if case == "token_mode":
        phone = _Peer("token")
        _session(server, "s1", phone)
        submitter = None  # a token connection's turn names nobody
    else:
        _session(server, "s1", phone, creator=ALICE)
        passkeys.enrol(native())
        _advertise_passkey(server, phone)
    if case == "unattributed_turn":
        submitter = None
    elif case == "shared_unattributed":
        bob = _Peer("bob", BOB)
        server._attach_session_transport(server._sessions["s1"], bob)
        submitter = None
    elif case == "not_enrolled":
        passkeys.store.revoke_user(ALICE, by="operator")
    elif case == "enrolled_for_an_rp_no_longer_accepted":
        passkeys.config["confirm"]["passkey"]["native_rps"] = {NATIVE_RP: []}
    elif case == "disabled":
        passkeys.config["confirm"]["passkey"]["enabled"] = False
    elif case == "no_base_url":
        passkeys.config["confirm"]["passkey"]["base_urls"] = []
    elif case == "private_only":
        passkeys.config["confirm"]["passkey"]["base_urls"] = ["http://192.168.1.10:9119"]
    if case == "no_turn":
        outcome = confirm.request("s1", confirm.build_params(level="passkey", **TEXT), timeout=5)
    else:
        outcome = _ask_now(server, "s1", submitter)
    assert outcome.as_dict() == {"outcome": "unavailable", "method": None, "verified": False, "reason": reason}
    assert phone.requests() == [] and not server_requests._open
    assert not confirm._sent  # nothing reached a person: the window is not charged
    # Nor is the no-downgrade window opened: plain stays available.
    assert not confirm._passkey_failed
    assert _ask_now(server, "s1", submitter, level="plain", timeout=0.05).reason != "downgrade_refused"


def test_no_capable_client_when_nobody_of_the_user_advertised(server, passkeys):
    passkeys.enrol(native())
    phone = _Peer("phone", ALICE)
    _session(server, "s1", phone, creator=ALICE)
    _advertise(server, phone, confirm=["plain"])
    assert _ask_now(server, "s1").reason == "no_capable_client" and phone.requests() == []
    # A third party can cause this one (detach the person's app): it opens the window.
    assert _ask_now(server, "s1", level="plain").reason == "downgrade_refused" and phone.requests() == []


def test_turn_isolation_still_fails_closed(server, passkeys, monkeypatch):
    from tui_gateway import confirm
    phone, _ = _alice_session(server, passkeys)
    monkeypatch.setenv("HERMES_COMPUTE_HOST_CHILD", "1")
    assert _ask_now(server, "s1").reason == "turn_isolation" and phone.requests() == []
    assert not confirm._passkey_failed


# ── the bound user ──────────────────────────────────────────────────────────────────────────


def test_the_tool_thread_binds_the_turns_submitter_even_in_a_shared_session(server, passkeys):
    """The value the tool thread reads is ``_acting_auth_user`` for the turn: the submitter, carried into the
    tool's worker thread the way ``agent/tool_executor.py`` runs tools, never the session's creator and
    never another person attached to it. Tool arguments cannot name anyone."""
    from gateway.session_context import clear_session_vars, set_session_vars
    from tools import confirm_tool
    from tools.thread_context import propagate_context_to_thread
    bob_auth = native()
    passkeys.enrol(bob_auth, user=BOB)
    passkeys.enrol(native())
    alice, bob = _Peer("alice", ALICE), _Peer("bob", BOB)
    _session(server, "s1", alice, bob, creator=ALICE)
    server._sessions["s1"]["auth_user_shared"] = True
    _advertise_passkey(server, alice)
    _advertise_passkey(server, bob)
    seen: dict = {}

    def turn():
        token = _turn(server, (BOB, "Bob"))  # Bob submitted this turn in Alice's session
        vars_token = set_session_vars(ui_session_id="s1", source="tui")
        try:
            seen["turn"] = server._acting_auth_user(server._sessions["s1"])
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(propagate_context_to_thread(lambda: confirm_tool.confirm_action_tool(
                    summary=TEXT["summary"], level="passkey", title=TEXT["title"])))
                seen["tool"] = future.result(10)
        finally:
            clear_session_vars(vars_token)
            server._turn_auth_user.reset(token)

    worker = threading.Thread(target=turn, daemon=True)
    worker.start()
    frame = _frame(server, bob)
    assert seen["turn"] == (BOB, "Bob")
    assert frame["params"]["passkey"]["user"] == {"id": BOB, "name": "Bob"} and alice.requests() == []
    assert _answer_rpc(server, alice, frame["id"], {"decision": "declined", "method": "tap"})["error"]["code"] == 4033
    _answer_rpc(server, bob, frame["id"], passkeys.answer(bob_auth, frame))
    worker.join(10)
    result = json.loads(seen["tool"])
    assert result["outcome"] == "confirmed" and result["verified"] is True and result["method"] == "passkey"
    assert result["message"].startswith("The person confirmed with a passkey and the gateway verified it")


def test_bound_user_must_equal_the_acting_user(server, passkeys, monkeypatch):
    from tui_gateway import confirm_passkey
    phone, _ = _alice_session(server, passkeys)
    monkeypatch.setattr(server, "_acting_auth_user", lambda session: (BOB, "Bob"))
    token = _turn(server, (ALICE, "Alice"))
    try:
        with pytest.raises(confirm_passkey.Unavailable) as refused:
            confirm_passkey.bound_user(server._sessions["s1"])
    finally:
        server._turn_auth_user.reset(token)
    assert refused.value.reason == "no_acting_user"


# ── no downgrade ────────────────────────────────────────────────────────────────────────────


def test_plain_after_a_failed_passkey_is_refused_for_the_window(server, passkeys, monkeypatch):
    from tui_gateway import confirm
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    _answer_rpc(server, phone, frame["id"], {"decision": "declined", "method": "tap"})
    thread.join(5)
    assert box["r"].outcome == "declined"
    sent = len(phone.requests())
    refused = _ask_now(server, "s1", level="plain")
    assert refused.as_dict() == {"outcome": "unavailable", "method": None, "verified": False,
                                 "reason": "downgrade_refused"}
    assert len(phone.requests()) == sent
    # Passkey itself is still allowed in the window.
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    assert frame["params"]["level"] == "passkey"
    _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))
    thread.join(5)
    assert box["r"].verified is True
    # A later success does not reopen plain early; the window passing does.
    assert _ask_now(server, "s1", level="plain").reason == "downgrade_refused"
    later = time.monotonic() + confirm.DOWNGRADE_WINDOW_SECONDS + 1
    monkeypatch.setattr(confirm.time, "monotonic", lambda: later)
    assert _ask_now(server, "s1", level="plain", timeout=0.05).outcome == "timeout"


def test_a_confirmed_passkey_does_not_block_plain(server, passkeys):
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))
    thread.join(5)
    assert box["r"].verified is True
    assert _ask_now(server, "s1", level="plain", timeout=0.05).outcome == "timeout"


def test_the_window_is_per_conversation(server, passkeys):
    passkeys.enrol(native())
    for sid in ("s1", "s2"):
        _session(server, sid, _Peer(f"p{sid}", ALICE), creator=ALICE)
    assert _ask_now(server, "s1").reason == "no_capable_client"
    assert _ask_now(server, "s1", level="plain").reason == "downgrade_refused"
    assert _ask_now(server, "s2", level="plain").reason == "no_capable_client"


@pytest.mark.parametrize("end, reason", [
    ("timeout", "timeout"), ("error", "error_response"), ("interrupt", "cancelled:interrupted"),
    ("refusals", "verification_failed"), ("revoked", "verification_failed")])
def test_every_post_send_failure_opens_the_window(server, passkeys, end, reason):
    from tui_gateway import confirm, server_requests
    phone, auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1", timeout=0.3 if end == "timeout" else 5)
    frame = _frame(server, phone)
    if end == "error":
        _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": frame["id"], "error": {"code": 4040, "message": "x"}},
            phone)
    elif end == "interrupt":
        server_requests.cancel("s1", reason="interrupted")
    elif end == "refusals":
        for n in range(5):
            _answer_rpc(server, phone, frame["id"], {"decision": "confirmed", "method": "tap"}, n=n)
    elif end == "revoked":
        passkeys.store.revoke(auth.credential_id, by="operator")
        _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))
    thread.join(5)
    assert (box["r"].reason or box["r"].outcome) == reason
    assert confirm.opens_downgrade_window(box["r"])
    assert _ask_now(server, "s1", level="plain").reason == "downgrade_refused"


# ── hook ────────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def hooks():
    from hermes_cli.plugins import get_plugin_manager
    manager = get_plugin_manager()
    saved = {k: list(v) for k, v in manager._hooks.items()}
    fired: list[dict] = []
    done = threading.Event()

    def record(**kw):
        fired.append({k: v for k, v in kw.items() if k != "telemetry_schema_version"})
        done.set()

    manager._hooks.setdefault("pre_confirm_request", []).append(record)
    yield fired, done
    manager._hooks = saved


def test_pre_confirm_request_fires_without_the_text(server, passkeys, hooks):
    from tui_gateway import confirm
    fired, done = hooks
    phone, _auth = _alice_session(server, passkeys)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    assert done.wait(5)
    assert fired == [{"session_id": "s1", "session_key": "key-s1", "request_id": frame["id"], "level": "passkey",
                      "user_id": ALICE, "expires_at": frame["params"]["passkey"]["expires_at"], "reached": 1}]
    assert tuple(fired[0]) == confirm.HOOK_KWARGS
    assert not any(text in json.dumps(fired) for text in TEXT.values())
    _answer_rpc(server, phone, frame["id"], {"decision": "declined", "method": "tap"})
    thread.join(5)


def test_pre_confirm_request_is_declared_bounded_and_documented():
    from pathlib import Path

    from hermes_cli.plugins import VALID_HOOKS
    from hermes_cli.plugins_dispatch import _HOOK_TIMEOUT_BOUNDED_HOOKS
    from tui_gateway import confirm
    assert "pre_confirm_request" in VALID_HOOKS and "pre_confirm_request" in _HOOK_TIMEOUT_BOUNDED_HOOKS
    root = Path(__file__).resolve().parents[2]
    hooks_md = (root / "website/docs/user-guide/features/hooks.md").read_text()
    row = next(line for line in hooks_md.splitlines() if line.startswith("| `pre_confirm_request` |"))
    assert all(f"`{name}`" in row for name in confirm.HOOK_KWARGS)
    assert "### `pre_confirm_request`" in hooks_md
    assert "`pre_confirm_request`" in (root / "website/docs/user-guide/features/plugins.md").read_text()


# ── the tool ────────────────────────────────────────────────────────────────────────────────


def test_tool_offers_passkey_only_while_enabled(passkeys):
    from tools import confirm_tool
    overrides = confirm_tool._schema_overrides()
    assert overrides["parameters"]["properties"]["level"]["enum"] == ["plain", "passkey"]
    assert "passkey" in overrides["description"] and "never ask again at 'plain'" in overrides["description"]
    assert confirm_tool.CONFIRM_ACTION_SCHEMA["parameters"]["properties"]["level"]["enum"] == ["plain"]
    passkeys.config["confirm"]["passkey"]["enabled"] = False
    assert confirm_tool._schema_overrides() is None


def test_tool_messages_for_passkey_outcomes():
    from tools import confirm_tool
    from tui_gateway import confirm
    not_consent = "This is not consent: do not perform the action."
    no_plain = "Do not ask again at level plain and do not reach the same effect another way."
    # The tool says "not plain instead" exactly where the gateway refuses plain.
    assert confirm_tool._POST_SEND_OUTCOMES == confirm.DOWNGRADE_OUTCOMES
    assert confirm_tool._POST_SEND_REASONS == confirm.DOWNGRADE_REASONS
    for reason in ("no_capable_client", "verification_failed", "error_response", "cancelled:interrupted"):
        sentence = confirm_tool._sentence({"outcome": "unavailable", "reason": reason}, "passkey")
        assert not_consent in sentence and no_plain in sentence and f"(reason: {reason})" in sentence, reason
    for reason in ("disabled", "no_base_url", "private_origin", "no_identity", "no_acting_user", "not_enrolled",
                   "store_unavailable", "settings_unavailable", "turn_isolation", "rate_limited", "already_pending",
                   "something_new"):
        sentence = confirm_tool._sentence({"outcome": "unavailable", "reason": reason}, "passkey")
        assert not_consent in sentence and f"(reason: {reason})" in sentence, reason
        assert "level plain" not in sentence or reason == "disabled", reason
        assert "do not ask again" not in sentence.lower(), reason
    disabled = confirm_tool._sentence({"outcome": "unavailable", "reason": "disabled"}, "passkey")
    assert "plain remains available" in disabled
    for outcome in ("declined", "timeout"):
        sentence = confirm_tool._sentence({"outcome": outcome}, "passkey")
        assert no_plain in sentence and "Do not perform" in sentence or not_consent in sentence
    assert "not_enrolled" not in confirm_tool._sentence({"outcome": "unavailable", "reason": "x"}, "plain")
    assert not_consent in confirm_tool._sentence({"outcome": "unavailable", "reason": "downgrade_refused"})
    # A confirmed answer is verified only when the gateway said so.
    assert confirm_tool._sentence({"outcome": "confirmed", "verified": False}, "passkey").startswith("Someone")
