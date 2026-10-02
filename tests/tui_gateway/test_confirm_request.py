"""The ``confirm`` server→client request (``tui_gateway/confirm.py`` over ``server_requests.send_gated``) and
the ``confirm_action`` tool (``tools/confirm_tool.py``).

What is pinned here: the frame reaches only connections that advertised the requested level; the four
outcomes stay apart (an error response or no capable client is ``unavailable``, never ``declined``); a
connection that did not advertise the level cannot settle the request on any path; the reserved
``passkey`` level is never sent and never advertisable; ``verified`` is the gateway's, not the client's;
restore lists the request only to a connection that may answer it; the tool's gating and rate limit; and
the existing request kinds see exactly what they saw before (``send`` wraps ``send_detailed``).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from unittest.mock import MagicMock, patch

import pytest


class _Peer:
    """A client connection: records frames, never answers on its own. *login* makes it a signed-in one."""

    def __init__(self, name: str, login: str | None = None, *, write_ok: bool = True):
        self.name = name
        self.frames: list[dict] = []
        self._closed = False
        self._peer = f"10.0.0.{len(name)}:5{len(name)}00"
        self.write_ok = write_ok
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id}

    def write(self, obj):
        self.frames.append(json.loads(json.dumps(obj)))
        return self.write_ok

    def close(self):
        self._closed = True

    def requests(self, method="confirm"):
        return [f for f in self.frames if f.get("method") == method]

    def cancels(self):
        return [f["params"]["payload"] for f in self.frames
                if f.get("method") == "event" and f["params"].get("type") == "request.cancel"]

    def __repr__(self):
        return f"<peer {self.name}>"


@pytest.fixture(autouse=True)
def audit_records(monkeypatch):
    """Capture the dashboard audit records instead of writing them to disk."""
    import tui_gateway.confirm as confirm_module
    records: list[tuple[str, dict]] = []
    monkeypatch.setattr(confirm_module, "_audit_sink", lambda event, **fields: records.append((event, fields)))
    return records


@pytest.fixture()
def server():
    # Same import discipline as test_protocol.py: everything the test touches by name is imported BEFORE
    # the sys.modules patch window, so the test and server.py share one module object each.
    import tui_gateway.server_requests  # noqa: F401
    import tui_gateway.transport  # noqa: F401
    import tui_gateway.confirm  # noqa: F401
    import tools.confirm_tool  # noqa: F401
    with patch.dict("sys.modules", {
        "hermes_constants": MagicMock(get_hermes_home=MagicMock(return_value="/tmp/hermes_test")),
        "hermes_cli.env_loader": MagicMock(),
        "hermes_cli.banner": MagicMock(),
        "hermes_state": MagicMock(),
    }):
        import importlib
        mod = importlib.import_module("tui_gateway.server")
    methods = dict(mod._methods)
    yield mod
    mod._methods.clear()
    mod._methods.update(methods)
    for sid in list(mod._sessions):
        mod._sessions.pop(sid, None)
    from tui_gateway import confirm, server_requests
    server_requests.reset_for_tests()
    confirm.reset_for_tests()


def _session(server, sid, *peers, creator=None):
    from tui_gateway.transport import FanoutTransport
    transport = peers[0] if len(peers) == 1 else FanoutTransport(*peers)
    server._sessions[sid] = {"session_key": f"key-{sid}", "transport": transport, "history": [],
                             "history_lock": threading.Lock(), "agent_ready": None, "auth_user_id": creator,
                             "auth_user_name": ""}
    return transport


def _as(peer, fn, *args, **kwargs):
    from tui_gateway.transport import bind_transport, reset_transport
    token = bind_transport(peer)
    try:
        return fn(*args, **kwargs)
    finally:
        reset_transport(token)


def _advertise(server, peer, confirm=None, server_requests=True):
    params = {"server_requests": server_requests}
    if confirm is not None:
        params["confirm"] = confirm
    return _as(peer, server.handle_request, {"id": 1, "method": "client.capabilities", "params": params})


def _answer(server, peer, rid, result=None, error=None):
    frame = {"jsonrpc": "2.0", "id": rid, **({"error": error} if error is not None else {"result": result})}
    return _as(peer, server.dispatch, frame, peer)


def _wait_open(timeout=10.0):
    from tui_gateway import server_requests
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with server_requests._lock:
            req = next((r for r in server_requests._open.values() if r.method == "confirm"), None)
        if req is not None:
            return req
        time.sleep(0.005)
    raise AssertionError("confirm request never opened")


def _ask(sid, **kwargs):
    """Run confirm.request in a thread; returns (thread, box)."""
    from tui_gateway import confirm
    params = confirm.build_params(summary=kwargs.pop("summary", "Pay 10 EUR to the plumber."),
                                  level=kwargs.pop("level", "plain"), **kwargs)
    box: dict = {}
    thread = threading.Thread(target=lambda: box.setdefault("r", confirm.request(sid, params, timeout=5)),
                              daemon=True)
    thread.start()
    return thread, box


def _drain(peer, count, timeout=5.0):
    """Fan-out writes are asynchronous: wait until *peer* holds *count* request.cancel events."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(peer.cancels()) < count:
        time.sleep(0.005)
    return peer.cancels()


CONFIRMED = {"decision": "confirmed", "method": "tap"}


# ── contract ────────────────────────────────────────────────────────────────────────────────


def test_contract_bounds_and_params():
    from pydantic import ValidationError
    from tui_gateway.contracts import registry
    contract = registry.SERVER_REQUESTS["confirm"]
    ok = {"session_id": "s", "title": "t", "summary": "s", "level": "plain"}
    contract.params.model_validate(ok)
    contract.params.model_validate({**ok, "level": "passkey"})  # reserved, but a contract value
    for bad in ({**ok, "title": "x" * 81}, {**ok, "summary": "x" * 501}, {**ok, "detail": "x" * 2001},
                {**ok, "level": "device_auth"}, {**ok, "summary": ""}, {**ok, "confirm_label": "Yes!"},
                {**ok, "allow_passcode": False}):
        with pytest.raises(ValidationError):
            contract.params.model_validate(bad)
    contract.result.model_validate(CONFIRMED)
    with pytest.raises(ValidationError):
        contract.result.model_validate({"decision": "maybe", "method": "tap"})
    with pytest.raises(ValidationError):
        contract.result.model_validate({"decision": "confirmed", "method": "biometric"})


def test_build_params_strips_controls_and_rejects_over_long_text():
    from tui_gateway import confirm
    params = confirm.build_params(
        summary="Delete‮ gpj.exe​ the\x00 backup\r\n\r\n\r\n\r\nof 3 files\x1b[31m",
        detail="rm -rf /srv/old\tbackup", title="  Delete\n backup  ", level="plain")
    assert params == {"title": "Delete backup", "summary": "Delete gpj.exe the backup\n\nof 3 files[31m",
                      "detail": "rm -rf /srv/old backup", "level": "plain"}
    assert confirm.build_params(summary="x")["title"] == confirm.DEFAULT_TITLE
    assert "detail" not in confirm.build_params(summary="x", detail="​")
    for kwargs in ({"summary": " ​ "}, {"summary": "x" * 501}, {"summary": "x", "detail": "y" * 2001},
                   {"summary": "x", "title": "t" * 81}, {"summary": "x", "level": "device_auth"}):
        with pytest.raises(confirm.ConfirmParamsError):
            confirm.build_params(**kwargs)


def test_plain_check_validates_shape_and_never_verifies():
    from tui_gateway import confirm
    plain = confirm.LEVELS["plain"]
    params = {"level": "plain"}
    assert plain.check(params, CONFIRMED) == (None, False)
    assert plain.check(params, {**CONFIRMED, "verified": True}) == (None, False)
    assert plain.check(params, {"decision": "declined", "method": "tap"}) == (None, False)
    assert plain.check(params, {"decision": "yes", "method": "tap"})[0]
    assert plain.check(params, {"decision": "confirmed", "method": "biometric"})[0]
    assert plain.challenge("s1", params) == {}


def test_advertisable_levels_match_and_passkey_is_reserved():
    from tui_gateway import confirm, server_requests
    from tui_gateway.contracts.server_requests import ConfirmLevel
    assert set(confirm.LEVELS) == {level.value for level in ConfirmLevel}
    assert set(server_requests.CONFIRM_LEVELS) == {n for n, lv in confirm.LEVELS.items() if lv.advertisable}
    assert confirm.LEVELS["passkey"].implemented is False and confirm.LEVELS["passkey"].advertisable is False


# ── capability ──────────────────────────────────────────────────────────────────────────────


def test_capabilities_echo_accepted_levels_and_old_clients_are_unaffected(server):
    from tui_gateway import server_requests
    app, old = _Peer("app"), _Peer("old")
    # The reserved passkey level and unknown levels are not accepted from a client.
    response = _advertise(server, app, confirm=["plain", "passkey", "device_auth"])
    assert response["result"]["confirm"] == ["plain"]
    assert "confirm" in response["result"]["server_requests"]
    assert server_requests.confirm_levels(app) == {"plain"}
    response = _advertise(server, old)
    assert response["result"]["confirm"] == []
    assert server_requests.answers_requests(old) and server_requests.confirm_levels(old) == frozenset()
    # Levels never count without server_requests, and a later advertisement replaces them.
    assert _advertise(server, app, confirm=["plain"], server_requests=False)["result"]["confirm"] == []
    assert server_requests.confirm_levels(app) == frozenset()
    _advertise(server, app, confirm=["plain"])
    server.unregister_live_transport(app)
    assert server_requests.confirm_levels(app) == frozenset()


def test_no_capable_client_is_unavailable_and_nothing_is_sent(server):
    from tui_gateway import confirm, server_requests
    old, other = _Peer("old"), _Peer("other")
    _session(server, "s1", old, other)
    _advertise(server, old)
    _advertise(server, other, confirm=["passkey"])
    t0 = time.monotonic()
    outcome = confirm.request("s1", confirm.build_params(summary="Pay."), timeout=5)
    assert time.monotonic() - t0 < 1
    assert outcome.as_dict() == {"outcome": "unavailable", "method": None, "verified": False,
                                 "reason": "no_capable_client"}
    assert old.requests() == [] and other.requests() == []
    assert server_requests.open_requests("s1") == []
    # No session at all (parked, unknown): the same.
    assert confirm.request("nope", confirm.build_params(summary="Pay."), timeout=5).outcome == "unavailable"


def test_passkey_is_not_implemented_unavailable_at_once_and_nothing_is_sent(server):
    from tui_gateway import confirm, server_requests
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain", "passkey"])
    for _ in range(10):  # never sent, so never counted against the window either
        outcome = confirm.request("s1", confirm.build_params(summary="Pay.", level="passkey"), timeout=5)
        assert outcome.as_dict() == {"outcome": "unavailable", "method": None, "verified": False,
                                     "reason": "level_not_implemented"}
    assert app.frames == [] and server_requests.open_requests("s1") == []
    assert confirm.request("s1", confirm.build_params(summary="Pay."), timeout=0.01).outcome == "timeout"


# ── the four outcomes ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("result, expected", [
    (CONFIRMED, {"outcome": "confirmed", "method": "tap", "verified": False}),
    # ``verified`` is the gateway's: a client claiming it changes nothing.
    ({"decision": "confirmed", "method": "tap", "verified": True},
     {"outcome": "confirmed", "method": "tap", "verified": False}),
    ({"decision": "declined", "method": "tap"}, {"outcome": "declined", "method": "tap", "verified": False}),
])
def test_answered_outcomes(server, result, expected):
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    thread, box = _ask("s1", title="Payment", detail="IBAN NL00 TEST 0000 0000 00")
    req = _wait_open()
    frame = app.requests()[-1]
    assert frame["id"] == req.id
    assert frame["params"] == {"session_id": "s1", "title": "Payment", "summary": "Pay 10 EUR to the plumber.",
                               "detail": "IBAN NL00 TEST 0000 0000 00", "level": "plain"}
    assert _answer(server, app, req.id, result) is None
    thread.join(5)
    assert box["r"].as_dict() == expected


def test_error_response_is_unavailable_not_declined(server):
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    thread, box = _ask("s1")
    req = _wait_open()
    _answer(server, app, req.id, error={"code": -32601, "message": "no handler"})
    thread.join(5)
    assert box["r"].outcome == "unavailable" and box["r"].reason == "error_response"


def test_timeout_emits_request_cancel(server, monkeypatch):
    from tui_gateway import confirm, server_requests
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    outcome = confirm.request("s1", confirm.build_params(summary="Pay.", level="plain"), timeout=0.05)
    assert outcome.as_dict() == {"outcome": "timeout", "method": None, "verified": False, "reason": "timeout"}
    rid = app.requests()[-1]["id"]
    assert app.cancels() == [{"id": rid, "method": "confirm", "reason": "timeout"}]
    assert server_requests.open_requests("s1") == []


def test_interrupt_is_unavailable(server):
    from tui_gateway import server_requests
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    thread, box = _ask("s1", level="plain")
    _wait_open()
    assert server_requests.cancel("s1", reason="interrupted") == 1
    thread.join(5)
    assert box["r"].outcome == "unavailable" and box["r"].reason == "cancelled:interrupted"


def test_default_timeout_is_120_seconds():
    from tui_gateway import confirm
    assert confirm.TIMEOUT_SECONDS == 120


# ── several clients ─────────────────────────────────────────────────────────────────────────


def test_only_advertising_clients_get_the_frame_and_others_cannot_settle_it(server):
    from tui_gateway import server_requests
    phone, web = _Peer("phone"), _Peer("web")
    _session(server, "s1", phone, web)
    _advertise(server, phone, confirm=["plain"])
    _advertise(server, web)  # answers server requests, but not confirm
    thread, box = _ask("s1")
    req = _wait_open()
    assert len(phone.requests()) == 1 and web.requests() == []
    # The other client answers by frame and by request.answer: both refused, the request stays open.
    assert _answer(server, web, req.id, CONFIRMED) is None
    refused = _as(web, server.handle_request, {"id": 9, "method": "request.answer",
                                               "params": {"id": req.id, "result": CONFIRMED}})
    assert refused["error"]["code"] == 4033
    # Its error frame is ignored too: it was never asked.
    _answer(server, web, req.id, error={"code": -32601})
    assert thread.is_alive() and req.id in server_requests._open
    # A malformed answer from the right client does not settle it either.
    bad = _as(phone, server.handle_request, {"id": 10, "method": "request.answer",
                                             "params": {"id": req.id, "result": {"decision": "confirmed",
                                                                                 "method": "biometric"}}})
    assert bad["error"]["code"] == 4034
    assert _answer(server, phone, req.id, {"decision": "yes", "method": "tap"}) is None
    assert req.id in server_requests._open
    _answer(server, phone, req.id, CONFIRMED)
    thread.join(5)
    assert box["r"].outcome == "confirmed"
    # Every connection is told the card is settled (the answering one ignores it).
    assert {"id": req.id, "method": "confirm", "reason": "resolved"} in _drain(web, 1)


def test_first_valid_answer_wins_and_one_client_error_leaves_the_other_asked(server):
    from tui_gateway import server_requests
    phone, desk = _Peer("phone"), _Peer("desk")
    _session(server, "s1", phone, desk)
    _advertise(server, phone, confirm=["plain"])
    _advertise(server, desk, confirm=["plain"])
    thread, box = _ask("s1", level="plain")
    req = _wait_open()
    assert len(phone.requests()) == 1 and len(desk.requests()) == 1
    _answer(server, desk, req.id, error={"code": -32001, "message": "cannot right now"})
    assert thread.is_alive() and req.id in server_requests._open
    _answer(server, phone, req.id, {"decision": "declined", "method": "tap", "verified": False})
    thread.join(5)
    assert box["r"].outcome == "declined"
    # A second, later answer finds nothing open.
    assert _as(desk, server.handle_request, {"id": 3, "method": "request.answer", "params": {
        "id": req.id, "result": CONFIRMED}})["result"] == {"status": "expired"}


# ── restore ─────────────────────────────────────────────────────────────────────────────────


def test_open_requests_lists_confirm_only_to_a_connection_with_the_level(server):
    from tui_gateway import server_requests
    phone, later, web = _Peer("phone"), _Peer("later"), _Peer("web")
    _session(server, "s1", phone)
    _advertise(server, phone, confirm=["plain"])
    _advertise(server, later, confirm=["plain"])
    _advertise(server, web)
    thread, box = _ask("s1")
    req = _wait_open()
    # Not attached yet (a reconnecting socket before its resume): the request is not listed, and its answer
    # is refused. After it reattaches (resume / activate), it is.
    assert _as(later, server._open_requests, "s1") == []
    assert _as(later, server.handle_request, {"id": 3, "method": "request.answer", "params": {
        "id": req.id, "result": CONFIRMED}})["error"]["code"] == 4033
    server._attach_session_transport(server._sessions["s1"], later)
    server._attach_session_transport(server._sessions["s1"], web)
    listed = _as(later, server._open_requests, "s1")
    assert [entry["id"] for entry in listed] == [req.id]
    assert listed[0]["method"] == "confirm" and listed[0]["params"]["level"] == "plain"
    assert _as(web, server._open_requests, "s1") == []
    assert server_requests.open_requests("s1") == []  # no calling connection: nothing gated is listed
    # The restoring connection did not get the original frame, but it advertised the level: it may settle.
    assert _as(web, server.handle_request, {"id": 5, "method": "request.answer", "params": {
        "id": req.id, "result": CONFIRMED}})["error"]["code"] == 4033
    ok = _as(later, server.handle_request, {"id": 4, "method": "request.answer",
                                            "params": {"id": req.id, "result": CONFIRMED}})
    assert ok["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].outcome == "confirmed" and later.requests() == []


# ── existing kinds ──────────────────────────────────────────────────────────────────────────


def test_send_detailed_tells_unavailable_from_cancelled_and_send_is_unchanged(server):
    from tui_gateway import server_requests
    box: dict = {}
    thread = threading.Thread(target=lambda: box.setdefault(
        "r", server_requests.send_detailed("sudo", "s9", {}, timeout=5)), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server_requests._open and time.monotonic() < deadline:
        time.sleep(0.005)
    rid = next(iter(server_requests._open))
    server_requests.resolve_response({"id": rid, "error": {"code": -32601}})
    thread.join(5)
    assert box["r"] == server_requests.RequestOutcome("unavailable", None, "error_response", rid)
    assert server_requests.send_detailed("sudo", "s9", {}, timeout=0).status == "timeout"
    assert server_requests.send("sudo", "s9", {}, timeout=0) is None
    batch = server_requests.send("clarify", "s9", {"questions": [{"qid": "q1", "question": "?"}]}, timeout=0,
                                 qids=["q1"])
    assert batch == {"answers": {}, "timed_out": True}


def test_ungated_requests_are_still_listed_and_answerable_by_anyone(server):
    from tui_gateway import server_requests
    req = server_requests.ServerRequest("s1", "sudo", {})
    with server_requests._lock:
        server_requests._open[req.id] = req
    assert [e["id"] for e in server_requests.open_requests("s1")] == [req.id]
    assert server_requests.answer_problem(req.id, {"value": "x"}) is None
    assert server_requests.resolve_response({"id": req.id, "result": {"value": "x"}})


# ── audit ───────────────────────────────────────────────────────────────────────────────────


def test_audit_records_who_was_asked_and_who_answered_never_the_text(server, caplog, audit_records):
    app = _Peer("app", "self_hosted:alice")
    _session(server, "s1", app, creator="self_hosted:alice")
    _advertise(server, app, confirm=["plain"])
    caplog.set_level(logging.INFO, logger="tui_gateway.confirm.audit")
    thread, box = _ask("s1", level="plain", summary="SECRET-SUMMARY", detail="SECRET-DETAIL", title="SECRET-T")
    req = _wait_open()
    _answer(server, app, req.id, {"decision": "confirmed", "method": "tap"})
    thread.join(5)
    assert audit_records == [
        ("confirm_request", {"session_id": "s1", "request_id": req.id, "level": "plain",
                             "acting_user": "self_hosted:alice", "reached": 1}),
        ("confirm_outcome", {"session_id": "s1", "request_id": req.id, "level": "plain",
                             "acting_user": "self_hosted:alice", "outcome": "confirmed", "method": "tap",
                             "reason": "", "verified": False, "answered_by": "self_hosted:alice",
                             "answered_from": app._peer}),
    ]
    assert not any("SECRET" in r.getMessage() for r in caplog.records)
    assert "SECRET" not in json.dumps(audit_records)


def test_audit_event_names_exist_in_the_dashboard_audit_log():
    from hermes_cli.dashboard_auth.audit import AuditEvent
    assert AuditEvent("confirm_request") and AuditEvent("confirm_outcome")


def test_clean_drops_invisible_letters_and_caps_combining_marks():
    from tui_gateway import confirm
    params = confirm.build_params(summary="Pay\u3164\u115f now e" + "\u0301" * 30 + ".", title="\uffa0T\u2800")
    assert params["summary"] == "Pay now e" + "\u0301" * confirm.MAX_COMBINING_MARKS + "."
    assert params["title"] == "T"
    with pytest.raises(confirm.ConfirmParamsError):
        confirm.build_params(summary="\u3164\u1160 \u2800")


# ── finding: answering needs attachment ─────────────────────────────────────────────────────


def test_a_connection_attached_elsewhere_cannot_see_or_answer_a_confirm(server):
    """A connection that advertised plain but is attached to ANOTHER session (or none) never sees the
    request and cannot settle it — even in token mode, where it may read the session's events."""
    alice, outsider = _Peer("alice"), _Peer("outsider")
    _session(server, "s1", alice)
    _session(server, "s2", outsider)
    _advertise(server, alice, confirm=["plain"])
    _advertise(server, outsider, confirm=["plain"])
    thread, box = _ask("s1")
    req = _wait_open()
    replay = _as(outsider, server.handle_request, {"id": 1, "method": "session.events.since",
                                                   "params": {"session_id": "s1", "last_seen": 0}})
    assert replay["result"]["open_requests"] == []
    assert _as(outsider, server.handle_request, {"id": 2, "method": "request.answer", "params": {
        "id": req.id, "result": CONFIRMED}})["error"]["code"] == 4033
    assert _answer(server, outsider, req.id, CONFIRMED) is None
    assert thread.is_alive()
    _answer(server, alice, req.id, {"decision": "declined", "method": "tap"})
    thread.join(5)
    assert box["r"].outcome == "declined"


def test_another_signed_in_person_cannot_replay_the_session(server):
    alice, bob = _Peer("alice", "self_hosted:alice"), _Peer("bob", "self_hosted:bob")
    _session(server, "s1", alice, creator="self_hosted:alice")
    _advertise(server, bob, confirm=["plain"])
    replay = _as(bob, server.handle_request, {"id": 1, "method": "session.events.since",
                                              "params": {"session_id": "s1", "last_seen": 0}})
    assert replay["error"]["code"] == 4001


# ── edge cases ──────────────────────────────────────────────────────────────────────────────


def test_readvertising_without_plain_then_answering_is_refused(server):
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    thread, box = _ask("s1")
    req = _wait_open()
    _advertise(server, app)  # the same connection now says it has no confirm levels
    assert _as(app, server.handle_request, {"id": 2, "method": "request.answer", "params": {
        "id": req.id, "result": CONFIRMED}})["error"]["code"] == 4033
    from tui_gateway import server_requests
    server_requests.cancel("s1")
    thread.join(5)


@pytest.mark.parametrize("end", ["timeout", "cancel"])
def test_late_answer_after_the_request_ended_is_expired(server, end):
    from tui_gateway import confirm, server_requests
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    if end == "timeout":
        confirm.request("s1", confirm.build_params(summary="Pay."), timeout=0.01)
    else:
        thread, _box = _ask("s1")
        _wait_open()
        server_requests.cancel("s1")
        thread.join(5)
    rid = app.requests()[-1]["id"]
    assert _as(app, server.handle_request, {"id": 2, "method": "request.answer", "params": {
        "id": rid, "result": CONFIRMED}})["result"] == {"status": "expired"}


def test_two_answers_at_once_settle_once(server):
    phone, desk = _Peer("phone"), _Peer("desk")
    _session(server, "s1", phone, desk)
    _advertise(server, phone, confirm=["plain"])
    _advertise(server, desk, confirm=["plain"])
    thread, box = _ask("s1")
    req = _wait_open()
    statuses: list = []
    barrier = threading.Barrier(2)

    def answer(peer, decision):
        barrier.wait()
        statuses.append(_as(peer, server.handle_request, {"id": 1, "method": "request.answer", "params": {
            "id": req.id, "result": {"decision": decision, "method": "tap"}}})["result"]["status"])

    workers = [threading.Thread(target=answer, args=(phone, "confirmed")),
               threading.Thread(target=answer, args=(desk, "declined"))]
    for w in workers:
        w.start()
    for w in workers:
        w.join(5)
    thread.join(5)
    assert sorted(statuses) == ["expired", "ok"]
    assert box["r"].outcome in ("confirmed", "declined")


def test_disconnect_forgets_the_advertisement(server):
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    thread, box = _ask("s1")
    req = _wait_open()
    server.unregister_live_transport(app)
    assert _as(app, server.handle_request, {"id": 2, "method": "request.answer", "params": {
        "id": req.id, "result": CONFIRMED}})["error"]["code"] == 4033
    from tui_gateway import server_requests
    server_requests.cancel("s1")
    thread.join(5)


def test_a_write_that_reaches_nobody_is_unavailable_and_leaves_nothing_open(server):
    from tui_gateway import confirm, server_requests
    app = _Peer("app", write_ok=False)
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    outcome = confirm.request("s1", confirm.build_params(summary="Pay."), timeout=5)
    assert outcome.reason == "write_failed" and not server_requests._open
    # Nothing reached a person, so the window is not charged.
    assert not confirm._sent


def test_parallel_tool_calls_send_one_request(server):
    from tui_gateway import confirm, server_requests
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    results: list = []
    barrier = threading.Barrier(5)

    def ask():
        barrier.wait()
        results.append(confirm.request("s1", confirm.build_params(summary="Pay."), timeout=1))

    workers = [threading.Thread(target=ask) for _ in range(5)]
    for w in workers:
        w.start()
    _wait_open()
    deadline = time.monotonic() + 5
    while len(results) < 4 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert [r.reason for r in results] == ["already_pending"] * 4 and len(app.requests()) == 1
    server_requests.cancel("s1")
    for w in workers:
        w.join(5)


# ── the tool ────────────────────────────────────────────────────────────────────────────────


def _bind_ui_session(sid):
    from gateway.session_context import clear_session_vars, set_session_vars
    tokens = set_session_vars(ui_session_id=sid, source="tui")
    return lambda: clear_session_vars(tokens)


def test_tool_is_withheld_without_the_gateway_bridge_and_off_by_default():
    from tools import confirm_tool
    from toolsets import TOOLSETS
    from hermes_cli.tools_config import _DEFAULT_OFF_TOOLSETS
    saved = confirm_tool._bridge
    try:
        confirm_tool.set_bridge(None)
        assert confirm_tool.available() is False
        result = json.loads(confirm_tool.confirm_action_tool(summary="Pay."))
        assert result["outcome"] == "unavailable" and result["reason"] == "no_session"
        assert result["message"].startswith("Confirmations are not available in this conversation")
    finally:
        confirm_tool.set_bridge(saved)
    assert TOOLSETS["confirm"]["tools"] == ["confirm_action"]
    assert "confirm" in _DEFAULT_OFF_TOOLSETS


def test_tool_platform_toolsets_keep_it_off_unless_named():
    from hermes_cli.tools_config import _get_platform_tools
    assert "confirm" not in _get_platform_tools({}, "cli")
    assert "confirm" not in _get_platform_tools({}, "telegram")
    assert "confirm" in _get_platform_tools({"platform_toolsets": {"cli": ["hermes-cli", "confirm"]}}, "cli")


def test_tool_without_an_interactive_session_sends_nothing(server):
    from tools import confirm_tool
    assert confirm_tool.available()  # the gateway import installed the bridge
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    # No HERMES_UI_SESSION_ID bound (cron, background, CLI): unavailable, nothing written.
    result = json.loads(confirm_tool.confirm_action_tool(summary="Pay."))
    assert result["outcome"] == "unavailable" and app.requests() == []
    # A messaging-platform turn, even with a UI session id somehow bound: the same.
    from gateway.session_context import clear_session_vars, set_session_vars
    tokens = set_session_vars(ui_session_id="s1", platform="telegram")
    try:
        assert json.loads(confirm_tool.confirm_action_tool(summary="Pay."))["outcome"] == "unavailable"
    finally:
        clear_session_vars(tokens)
    assert app.requests() == []


def test_tool_round_trip_and_messages(server):
    from tools import confirm_tool
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    release = _bind_ui_session("s1")
    try:
        assert "error" in json.loads(confirm_tool.confirm_action_tool(summary="x" * 501))
        assert app.requests() == []
        box: dict = {}
        import contextvars
        ctx = contextvars.copy_context()
        thread = threading.Thread(target=lambda: box.setdefault("r", ctx.run(
            confirm_tool.confirm_action_tool, summary="Delete the old backups.")), daemon=True)
        thread.start()
        req = _wait_open()
        _answer(server, app, req.id, CONFIRMED)
        thread.join(5)
    finally:
        release()
    result = json.loads(box["r"])
    assert result["outcome"] == "confirmed" and result["verified"] is False
    assert result["message"].startswith("Someone confirmed in a connected app")
    assert "error" in json.loads(confirm_tool.confirm_action_tool(summary="Pay.", level="passkey"))
    not_consent = "This is not consent: do not perform the action."
    assert confirm_tool._sentence({"outcome": "declined"}).startswith("Declined in a connected app.")
    assert not_consent in confirm_tool._sentence({"outcome": "timeout"})
    for reason in ("no_capable_client", "write_failed", "error_response", "no_session", "already_pending",
                   "rate_limited", "level_not_implemented", "turn_isolation", "cancelled:interrupted",
                   "cancelled:session_closed", "cancelled:shutdown", "something_new"):
        sentence = confirm_tool._sentence({"outcome": "unavailable", "reason": reason})
        assert not_consent in sentence, reason
    stopped = confirm_tool._sentence({"outcome": "unavailable", "reason": "cancelled:interrupted"})
    assert "stopped" in stopped and "open" not in stopped
    assert "open" not in confirm_tool._sentence({"outcome": "unavailable", "reason": "error_response"})


def test_rate_limit_one_pending_and_six_per_window(server, monkeypatch):
    from tui_gateway import confirm
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    thread, box = _ask("s1", level="plain")
    req = _wait_open()
    second = confirm.request("s1", confirm.build_params(summary="Again.", level="plain"), timeout=5)
    assert second.outcome == "unavailable" and second.reason == "already_pending"
    assert len(app.requests()) == 1
    _answer(server, app, req.id, {"decision": "declined", "method": "tap"})
    thread.join(5)
    for _ in range(5):
        assert confirm.request("s1", confirm.build_params(summary="Again.", level="plain"),
                               timeout=0.01).outcome == "timeout"
    limited = confirm.request("s1", confirm.build_params(summary="Again.", level="plain"), timeout=5)
    assert limited.as_dict()["reason"] == "rate_limited" and len(app.requests()) == 6
    # The window is per conversation, and it slides.
    clock = time.monotonic() + confirm.WINDOW_SECONDS + 1
    monkeypatch.setattr(confirm.time, "monotonic", lambda: clock)
    assert confirm.request("s1", confirm.build_params(summary="Later.", level="plain"),
                           timeout=0.01).outcome == "timeout"


def test_unavailable_requests_do_not_count_against_the_window(server):
    from tui_gateway import confirm
    _session(server, "s1", _Peer("nobody"))
    for _ in range(10):
        assert confirm.request("s1", confirm.build_params(summary="Pay."), timeout=1).reason == "no_capable_client"


def test_turn_isolation_child_fails_closed(server, monkeypatch):
    from tui_gateway import confirm
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    monkeypatch.setenv("HERMES_COMPUTE_HOST_CHILD", "1")
    outcome = confirm.request("s1", confirm.build_params(summary="Pay.", level="plain"), timeout=5)
    assert outcome.reason == "turn_isolation" and app.requests() == []
