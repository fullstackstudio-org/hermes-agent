"""The method gate and parking of ``server_requests.send_gated`` (plan ``request-types-v2``, task P1-F3).

An interactive request (``input.form``, ``input.file``, ``review.draft``) is gated on its METHOD: a connection
gets the frame, may answer it and sees it in ``open_requests`` only after it listed the method under
``client.capabilities {requests}``. ``acting_user_target`` narrows that to the login the turn acts for. With
``park_seconds`` a request that finds no capable connection waits (bounded) for one to attach instead of
declining at once, and settles ``unavailable (no_capable_client)`` WITHOUT a ``request.cancel`` when nobody came.
An agent acting through MCP never qualifies. ``confirm``'s level gate is untouched (its own suites pin it).
Every payload is a harmless marker.
"""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

ROBIN = "oidc:robin"
SAM = "oidc:sam"
AGENT = {"kind": "mcp", "client": "Claude Code", "grant": "grant-g1"}
DRAFT = {"v": 1, "title": "Marker title", "summary": "Marker summary.", "expires_at": 1_791_119_400,
         "optional": False, "kind": "mail", "text": "MARKER-DRAFT-TEXT"}
APPROVED = {"decision": "approved", "text": "MARKER-DRAFT-TEXT"}


class _WS:
    """A client connection; signed in as *login* when given, an agent acting for that login with *agent*."""

    def __init__(self, name: str, login: str | None = ROBIN, agent: dict | None = None):
        self.name = name
        self.frames: list[dict] = []
        self.fail_writes = False
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id, "user_name": name}
            if agent is not None:
                self.auth_identity["agent"] = agent

    def write(self, obj):
        if self.fail_writes:
            return False
        self.frames.append(json.loads(json.dumps(obj)))
        return True

    def close(self):
        return None

    def requests(self, method: str = "review.draft") -> list[dict]:
        return [f for f in self.frames if f.get("method") == method]

    def __repr__(self):
        return f"<_WS {self.name}>"


@pytest.fixture()
def server():
    import tui_gateway.server_requests  # noqa: F401
    import tui_gateway.transport  # noqa: F401
    with patch.dict("sys.modules", {
        "hermes_constants": MagicMock(get_hermes_home=MagicMock(return_value="/tmp/hermes_test")),
        "hermes_cli.env_loader": MagicMock(),
        "hermes_cli.banner": MagicMock(),
        "hermes_state": MagicMock(),
    }):
        import importlib
        mod = importlib.import_module("tui_gateway.server")
    yield mod
    for sid in list(mod._sessions):
        mod._sessions.pop(sid, None)
    from tui_gateway import server_requests
    server_requests.reset_for_tests()


@pytest.fixture()
def cancels(monkeypatch):
    """Every ``request.cancel`` the module emits, as ``(sid, payload)``."""
    from tui_gateway import server_requests
    seen: list[tuple[str, dict]] = []
    real = server_requests._emit

    def emit(event, sid, payload):
        if event == "request.cancel":
            seen.append((sid, dict(payload)))
        return real(event, sid, payload)

    monkeypatch.setattr(server_requests, "_emit", emit)
    return seen


def _session(server, sid, *peers, creator=ROBIN):
    session = {"session_key": f"key-{sid}", "transport": None, "history": [], "history_lock": threading.Lock(),
               "agent_ready": None, "auth_user_id": creator, "auth_user_name": "", "running": False}
    server._sessions[sid] = session
    for peer in peers:
        server._attach_session_transport(session, peer)
    return session


def _as(peer, fn, *args, **kwargs):
    from tui_gateway.transport import bind_transport, reset_transport
    token = bind_transport(peer)
    try:
        return fn(*args, **kwargs)
    finally:
        reset_transport(token)


def _rpc(server, peer, method, params):
    return _as(peer, server.handle_request, {"id": 1, "method": method, "params": params})


def _caps(server, peer, requests=("review.draft",), **extra):
    """The second ``client.capabilities`` of a connection that lists *requests*; the RPC result."""
    params = {"server_requests": True, **extra}
    if requests is not None:
        params["requests"] = list(requests)
    return _rpc(server, peer, "client.capabilities", params)["result"]


def _frame(server, peer, req_id, **body):
    return _as(peer, server.dispatch, {"jsonrpc": "2.0", "id": req_id, **body}, peer)


def _validate(result: dict) -> str | None:
    return None if result.get("decision") in ("approved", "rejected") else "bad_shape"


def _ask(sid="s1", *, timeout=10.0, park_seconds=0.0, target=None, on_open=None, max_refusals=None):
    """``send_gated`` on a thread, the way a turn asks; ``box["outcome"]`` once it returns."""
    from tui_gateway import server_requests
    box: dict = {"opened": threading.Event()}

    def opened(request_id, reached):
        box["open"] = (request_id, reached)
        box["opened"].set()
        if on_open is not None:
            on_open(request_id, reached)

    def run():
        try:
            box["outcome"] = server_requests.send_gated(
                "review.draft", sid, DRAFT, timeout=timeout, validate=_validate, target=target, on_open=opened,
                max_refusals=max_refusals, park_seconds=park_seconds)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    box["thread"] = thread
    return box


def _opened(box, timeout=5.0):
    assert box["opened"].wait(timeout), "on_open never ran"
    return box["open"]


def _done(box, timeout=5.0):
    box["thread"].join(timeout)
    assert not box["thread"].is_alive(), "send_gated did not return"
    assert "error" not in box, box.get("error")
    return box["outcome"]


def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("condition never held")


# ── advertisement ────────────────────────────────────────────────────────────────────────────


def test_advertised_interactive_methods_are_accepted_and_echoed(server):
    phone = _WS("phone")
    _session(server, "s1", phone)
    result = _caps(server, phone, requests=["review.draft", "input.form"])
    assert result["requests"] == ["input.form", "review.draft"]
    from tui_gateway import server_requests
    assert server_requests.handled_methods(phone) == ["input.form", "review.draft"]


def test_unknown_and_malformed_methods_are_ignored(server):
    from tui_gateway import server_requests
    phone = _WS("phone")
    result = _caps(server, phone, requests=["review.draft", "clarify", "confirm", "device.made_up", ""])
    assert result["requests"] == ["review.draft"]
    # Past the contract (a direct caller): non-strings and a non-list are dropped, never raised on.
    server_requests.advertise(phone, True, None, requests=["input.form", 7, None, {"x": 1}])
    assert server_requests.handled_methods(phone) == ["input.form"]
    server_requests.advertise(phone, True, None, requests="input.form")
    assert server_requests.handled_methods(phone) == []


def test_methods_count_only_together_with_server_requests(server):
    from tui_gateway import server_requests
    phone = _WS("phone")
    server_requests.advertise(phone, False, None, requests=["review.draft"])
    assert server_requests.handled_methods(phone) == []


def test_a_later_advertisement_without_requests_clears_them(server):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _caps(server, phone)
    assert _caps(server, phone, requests=None)["requests"] == []
    assert server_requests.handled_methods(phone) == []


def test_forget_clears_the_methods(server):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _caps(server, phone)
    server_requests.forget(phone)
    assert server_requests.handled_methods(phone) == []
    assert phone not in server_requests._handled


def test_confirm_levels_and_methods_are_recorded_side_by_side(server):
    phone = _WS("phone")
    result = _caps(server, phone, confirm=["plain"])
    assert result["confirm"] == ["plain"] and result["requests"] == ["review.draft"]


# ── the frame goes only to advertising connections ──────────────────────────────────────────


def test_the_frame_goes_only_to_connections_that_listed_the_method(server):
    phone, laptop, old = _WS("phone"), _WS("laptop"), _WS("old")
    _session(server, "s1", phone, laptop, old)
    _caps(server, phone)
    _caps(server, laptop, requests=["input.form"])
    _caps(server, old, requests=None)
    box = _ask()
    request_id, reached = _opened(box)
    assert reached == 1
    assert [f["id"] for f in phone.requests()] == [request_id]
    assert laptop.requests() == [] and old.requests() == []
    _frame(server, phone, request_id, result=APPROVED)
    outcome = _done(box)
    assert outcome.status == "answered" and outcome.result == APPROVED and outcome.answered_by is phone


def test_without_park_seconds_nobody_capable_declines_at_once(server, cancels):
    from tui_gateway import server_requests
    old = _WS("old")
    _session(server, "s1", old)
    _caps(server, old, requests=None)
    outcome = server_requests.send_gated("review.draft", "s1", DRAFT, timeout=10, validate=_validate)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert old.frames == [] and server_requests.open_request_count() == 0 and cancels == []


def test_a_connection_that_did_not_list_the_method_may_not_answer(server):
    phone, laptop = _WS("phone"), _WS("laptop")
    _session(server, "s1", phone, laptop)
    _caps(server, phone)
    _caps(server, laptop, requests=None)
    box = _ask()
    request_id, _ = _opened(box)
    refused = _rpc(server, laptop, "request.answer", {"id": request_id, "result": APPROVED})
    assert refused["error"]["code"] == 4033
    assert "review.draft" in refused["error"]["message"]
    from tui_gateway import server_requests
    assert server_requests.request_method(request_id) == "review.draft"
    ok = _rpc(server, phone, "request.answer", {"id": request_id, "result": APPROVED})
    assert ok["result"] == {"status": "ok"}
    assert _done(box).status == "answered"


def test_a_refused_answer_is_4034_and_the_request_stays_open(server):
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    box = _ask(max_refusals=2)
    request_id, _ = _opened(box)
    first = _rpc(server, phone, "request.answer", {"id": request_id, "result": {"decision": "maybe"}})
    assert first["error"]["code"] == 4034 and first["error"]["data"] == {"reason": "bad_shape"}
    second = _rpc(server, phone, "request.answer", {"id": request_id, "result": {"decision": "maybe"}})
    assert second["error"]["data"] == {"reason": "too_many_attempts"}
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "too_many_attempts")


def test_open_requests_lists_a_method_gated_request_only_to_advertisers(server):
    from tui_gateway import server_requests
    phone, laptop = _WS("phone"), _WS("laptop")
    _session(server, "s1", phone, laptop)
    _caps(server, phone)
    _caps(server, laptop, requests=None)
    box = _ask()
    request_id, _ = _opened(box)
    assert [r["id"] for r in _as(phone, server_requests.open_requests, "s1")] == [request_id]
    assert _as(laptop, server_requests.open_requests, "s1") == []
    server_requests.cancel("s1")
    assert _done(box).status == "cancelled"


# ── the acting user ──────────────────────────────────────────────────────────────────────────


def test_acting_user_target_admits_the_same_login_only(server, monkeypatch):
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: ROBIN)
    target = server_requests.acting_user_target("s1")
    assert target(_WS("robin's phone", ROBIN), None) is True
    assert target(_WS("sam's phone", SAM), None) is False
    assert target(_WS("token client", None), None) is False


def test_acting_user_target_admits_everyone_when_no_login_is_named(server, monkeypatch):
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: None)
    target = server_requests.acting_user_target("s1")
    assert target(_WS("robin", ROBIN), None) and target(_WS("sam", SAM), None) and target(_WS("anon", None), None)


def test_acting_user_target_fails_closed_when_the_login_cannot_be_read(server, monkeypatch):
    from tui_gateway import server_requests

    def broken(sid):
        raise RuntimeError("marker")

    monkeypatch.setattr(server_requests, "_acting_user", broken)
    assert server_requests.acting_user_target("s1")(_WS("robin", ROBIN), None) is False


def test_acting_user_target_resolves_the_login_before_the_call(server, monkeypatch):
    """The predicate closes over the login read when it was built: a later change does not move it."""
    from tui_gateway import server_requests
    acting = {"login": ROBIN}
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: acting["login"])
    target = server_requests.acting_user_target("s1")
    acting["login"] = SAM
    assert target(_WS("robin", ROBIN), None) and not target(_WS("sam", SAM), None)


def test_the_gateway_resolves_the_acting_user_of_a_session(server):
    """Bound to ``server._acting_auth_user``: a session only its creator is attached to acts for the creator."""
    from tui_gateway import server_requests
    robin = _WS("robin", ROBIN)
    _session(server, "s1", robin, creator=ROBIN)
    target = server_requests.acting_user_target("s1")
    assert target(robin, None) and not target(_WS("sam", SAM), None)


def test_with_the_acting_user_target_another_login_never_gets_or_answers_it(server, monkeypatch):
    from tui_gateway import server_requests
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _session(server, "s1", robin, sam)
    _caps(server, robin)
    _caps(server, sam)
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: ROBIN)
    box = _ask(target=server_requests.acting_user_target("s1"))
    request_id, reached = _opened(box)
    assert reached == 1 and sam.requests() == [] and len(robin.requests()) == 1
    assert _as(sam, server_requests.open_requests, "s1") == []
    assert _rpc(server, sam, "request.answer", {"id": request_id, "result": APPROVED})["error"]["code"] == 4033
    assert _rpc(server, robin, "request.answer", {"id": request_id, "result": APPROVED})["result"]["status"] == "ok"
    assert _done(box).answered_by is robin


# ── agents ──────────────────────────────────────────────────────────────────────────────────


def test_an_agent_never_gets_sees_or_answers_a_method_gated_request(server, cancels):
    """An agent acting through MCP: its advertisement is ignored, it is never a target, it does not see the
    request in ``open_requests``, and every answer path refuses it (frame, error frame, ``request.answer``)."""
    from tui_gateway import server_requests
    agent, phone = _WS("agent", ROBIN, AGENT), _WS("phone", ROBIN)
    _session(server, "s1", agent, phone)
    assert _caps(server, agent)["requests"] == []
    server_requests.advertise(agent, True, None, requests=["review.draft"])  # even advertised directly
    _caps(server, phone)
    box = _ask(park_seconds=5)
    request_id, reached = _opened(box)
    assert reached == 1 and agent.requests() == []
    with server_requests._lock:
        assert all(peer is not agent for peer in server_requests._open[request_id].targets)
    assert _as(agent, server_requests.open_requests, "s1") == []
    assert _rpc(server, agent, "request.answer", {"id": request_id, "result": APPROVED})["error"]["code"] == 4033
    _frame(server, agent, request_id, result=APPROVED)
    _frame(server, agent, request_id, error={"code": 4041, "message": "cannot_show"})
    assert server_requests.request_method(request_id) == "review.draft"
    _frame(server, phone, request_id, result=APPROVED)
    assert _done(box).answered_by is phone


def test_a_session_with_only_an_agent_attached_parks_and_the_agent_is_never_asked(server, cancels):
    from tui_gateway import server_requests
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    server_requests.advertise(agent, True, None, requests=["review.draft"])
    box = _ask(park_seconds=0.15, timeout=5)
    assert _opened(box)[1] == 0
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert agent.frames == [] and cancels == []


# ── parking ──────────────────────────────────────────────────────────────────────────────────


def test_a_parked_request_is_open_counted_and_named_while_nobody_is_attached(server):
    from tui_gateway import server_requests
    _session(server, "s1")
    box = _ask(park_seconds=5)
    request_id, reached = _opened(box)
    assert reached == 0
    assert server_requests.open_request_count() == 1
    assert server_requests.pending_kind("s1") == "review.draft"
    assert server_requests.request_session(request_id) == "s1"
    server_requests.cancel("s1")
    _done(box)
    assert server_requests.open_request_count() == 0 and server_requests.pending_kind("s1") == ""


def test_a_late_attach_and_advertise_gets_the_parked_request_and_its_answer_settles(server):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=5, timeout=10)
    request_id, reached = _opened(box)
    assert reached == 0
    phone = _WS("phone")
    _caps(server, phone)  # advertises first (not attached yet: nothing to deliver)
    assert phone.requests() == []
    server._attach_session_transport(session, phone)
    listed = _as(phone, server_requests.open_requests, "s1")
    assert [r["id"] for r in listed] == [request_id] and listed[0]["params"]["text"] == DRAFT["text"]
    with server_requests._lock:
        assert server_requests._open[request_id].targets == [phone]
    _as(phone, server_requests.open_requests, "s1")  # listed again (a poll): still one target
    with server_requests._lock:
        assert server_requests._open[request_id].targets == [phone]
    _frame(server, phone, request_id, result=APPROVED)
    outcome = _done(box)
    assert outcome.status == "answered" and outcome.answered_by is phone


def test_a_connection_that_advertises_after_attaching_gets_the_parked_frame_pushed(server):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=5, timeout=10)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    server._attach_session_transport(session, phone)
    assert _as(phone, server_requests.open_requests, "s1") == []  # not advertised yet: not listed
    _caps(server, phone)
    assert [f["id"] for f in phone.requests()] == [request_id]
    _caps(server, phone)  # advertising again does not deliver it twice
    assert len(phone.requests()) == 1
    _frame(server, phone, request_id, result=APPROVED)
    assert _done(box).status == "answered"


def test_nobody_within_park_seconds_is_unavailable_without_a_cancel(server, cancels):
    """Pinned choice: no ``request.cancel {reason: timeout}`` for a parked request nobody was shown."""
    from tui_gateway import server_requests
    _session(server, "s1")
    started = time.monotonic()
    box = _ask(park_seconds=0.2, timeout=30)
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert outcome.request_id == box["open"][0]
    assert time.monotonic() - started < 5  # bounded by park_seconds, not by the 30 s timeout
    assert cancels == [] and server_requests.open_request_count() == 0


def test_once_reached_the_parked_request_waits_past_park_seconds_for_the_answer(server):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=0.2, timeout=10)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    _caps(server, phone)
    server._attach_session_transport(session, phone)
    _as(phone, server_requests.open_requests, "s1")
    time.sleep(0.4)  # past park_seconds: the request is still open because somebody was reached
    assert server_requests.request_method(request_id) == "review.draft"
    _frame(server, phone, request_id, result=APPROVED)
    assert _done(box).status == "answered"


def test_a_reached_parked_request_that_runs_out_times_out_with_a_cancel(server, cancels):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=5, timeout=0.3)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    _caps(server, phone)
    server._attach_session_transport(session, phone)
    _as(phone, server_requests.open_requests, "s1")
    outcome = _done(box)
    assert outcome.status == "timeout"
    assert ("s1", {"id": request_id, "method": "review.draft", "reason": "timeout"}) in cancels


def test_an_error_from_the_late_peer_settles_error_response(server):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=5, timeout=10)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    _caps(server, phone)
    server._attach_session_transport(session, phone)
    _as(phone, server_requests.open_requests, "s1")
    _frame(server, phone, request_id, error={"code": 4041, "message": "cannot_show",
                                              "data": {"reason": "not_supported_on_device"}})
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "error_response")


def test_an_error_from_a_connection_it_never_reached_is_ignored(server):
    """A capable connection attached but never given the request (no listing, no push) is not a target."""
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=5, timeout=10)
    request_id, _ = _opened(box)
    stranger = _WS("stranger")
    server._attach_session_transport(session, stranger)
    _frame(server, stranger, request_id, error={"code": 4041, "message": "cannot_show"})
    assert server_requests.request_method(request_id) == "review.draft"
    server_requests.cancel("s1")
    assert _done(box).status == "cancelled"


def test_an_interrupt_withdraws_a_parked_request(server, cancels):
    from tui_gateway import server_requests
    _session(server, "s1")
    box = _ask(park_seconds=5, timeout=10)
    request_id, _ = _opened(box)
    assert server_requests.cancel("s1", reason="interrupted") == 1
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("cancelled", "interrupted")
    assert ("s1", {"id": request_id, "method": "review.draft", "reason": "interrupted"}) in cancels
    assert server_requests.open_request_count() == 0


def test_a_level_gated_request_never_parks(server):
    """``confirm``'s path: no capable connection is ``unavailable`` at once, whatever ``park_seconds`` says."""
    from tui_gateway import server_requests
    _session(server, "s1")
    outcome = server_requests.send_gated("confirm", "s1", {"title": "Marker", "summary": "Marker.",
                                                           "level": "plain"},
                                         level="plain", timeout=10, validate=lambda r: None, park_seconds=5)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert server_requests.open_request_count() == 0


def test_a_method_gated_send_needs_an_interactive_method_and_the_gate(server):
    from tui_gateway import server_requests
    _session(server, "s1")
    with pytest.raises(ValueError):
        server_requests.send_gated("review.draft", "s1", DRAFT, methods_gate=False, timeout=1, validate=_validate)
    with pytest.raises(ValueError):
        server_requests.send_gated("clarify", "s1", {"question": "marker"}, timeout=1, validate=_validate)
