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


@pytest.fixture()
def clock(monkeypatch):
    """The method-gated waits' clock (``server_requests._monotonic``), moved by hand: :meth:`advance` moves it and
    wakes every method-gated wait (under the module lock, as a lost target does), so no test sleeps through a park
    window or a deadline."""
    from tui_gateway import server_requests
    state = {"now": 1_000.0}
    monkeypatch.setattr(server_requests, "_monotonic", lambda: state["now"])

    class Clock:
        def advance(self, seconds: float) -> None:
            state["now"] += seconds
            with server_requests._lock:
                for req in server_requests._open.values():
                    if req.method_gated:
                        req.event.set()

    return Clock()


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
    return None if result.get("decision") in ("approved", "rejected") or result.get("status") == "answered" \
        else "bad_shape"


def _ask(sid="s1", *, timeout=10.0, park_seconds=0.0, target=None, on_open=None, max_refusals=None,
         method="review.draft", params=None):
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
                method, sid, DRAFT if params is None else params, timeout=timeout, validate=_validate, target=target, on_open=opened,
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

FORM = {"v": 1, "title": "Marker form", "summary": "Marker summary.", "expires_at": 1_791_119_400, "optional": True,
        "fields": [{"id": "name", "kind": "text", "label": "Marker"}]}


def test_acting_user_target_admits_the_same_login_only(server, monkeypatch):
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (ROBIN, False))
    target = server_requests.acting_user_target("s1", "review.draft")
    assert target.refusal is None and target.login == ROBIN
    assert target(_WS("robin's phone", ROBIN), None) is True
    assert target(_WS("sam's phone", SAM), None) is False
    assert target(_WS("token client", None), None) is False


@pytest.mark.parametrize("method", ["input.form", "review.draft"])
def test_with_no_auth_provider_everyone_capable_qualifies(server, monkeypatch, method):
    """One trust domain (nobody signed in, nothing ambiguous): every capable connection, for review.* too."""
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (None, False))
    target = server_requests.acting_user_target("s1", method)
    assert target.refusal is None
    assert target(_WS("robin", ROBIN), None) and target(_WS("sam", SAM), None) and target(_WS("anon", None), None)


def test_a_shared_session_naming_nobody_admits_everyone_for_input_and_nobody_for_review(server, monkeypatch):
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (None, True))
    form = server_requests.acting_user_target("s1", "input.form")
    assert form.refusal is None and form(_WS("robin", ROBIN), None) and form(_WS("sam", SAM), None)
    review = server_requests.acting_user_target("s1", "review.draft")
    assert review.refusal == server_requests.NO_ACTING_USER == "no_acting_user"
    assert not review(_WS("robin", ROBIN), None)


def test_acting_user_target_fails_closed_when_the_login_cannot_be_read(server, monkeypatch):
    from tui_gateway import server_requests

    def broken(sid):
        raise RuntimeError("marker")

    monkeypatch.setattr(server_requests, "_acting_user", broken)
    target = server_requests.acting_user_target("s1", "input.form")
    assert target.refusal == "no_acting_user" and target(_WS("robin", ROBIN), None) is False


def test_acting_user_target_resolves_the_login_before_the_call(server, monkeypatch):
    """The predicate closes over the login read when it was built: a later change does not move it."""
    from tui_gateway import server_requests
    acting = {"login": ROBIN}
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (acting["login"], False))
    target = server_requests.acting_user_target("s1", "review.draft")
    acting["login"] = SAM
    assert target(_WS("robin", ROBIN), None) and not target(_WS("sam", SAM), None)


def test_the_gateway_resolves_the_acting_user_of_a_session(server):
    """Bound to ``server._acting_auth_user``: a session only its creator is attached to acts for the creator."""
    from tui_gateway import server_requests
    robin = _WS("robin", ROBIN)
    _session(server, "s1", robin, creator=ROBIN)
    target = server_requests.acting_user_target("s1", "review.draft")
    assert target.login == ROBIN and target(robin, None) and not target(_WS("sam", SAM), None)


def test_a_review_in_a_shared_session_naming_nobody_is_unavailable_at_once(server, cancels):
    """Bound to the gateway: two people attached and the turn names nobody. ``review.draft`` goes to nobody and
    settles ``unavailable (no_acting_user)`` with nothing written or opened; ``input.form`` goes to both."""
    from tui_gateway import server_requests
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _session(server, "s1", robin, sam, creator=ROBIN)
    _caps(server, robin, requests=["review.draft", "input.form"])
    _caps(server, sam, requests=["review.draft", "input.form"])
    review = server_requests.acting_user_target("s1", "review.draft")
    outcome = server_requests.send_gated("review.draft", "s1", DRAFT, timeout=10, validate=_validate,
                                         target=review, park_seconds=60)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_acting_user")
    assert robin.frames == [] and sam.frames == [] and server_requests.open_request_count() == 0 and cancels == []
    box = _ask(method="input.form", params=FORM, target=server_requests.acting_user_target("s1", "input.form"))
    request_id, reached = _opened(box)
    assert reached == 2
    _frame(server, sam, request_id, result={"status": "answered", "values": {"name": "marker"}})
    assert _done(box).answered_by is sam


def test_a_review_in_a_session_with_no_sign_in_goes_to_every_capable_connection(server):
    from tui_gateway import server_requests
    tui, web = _WS("tui", None), _WS("web", None)
    _session(server, "s1", tui, web, creator=None)
    _caps(server, tui)
    _caps(server, web)
    box = _ask(target=server_requests.acting_user_target("s1", "review.draft"))
    assert _opened(box)[1] == 2
    _frame(server, web, box["open"][0], result=APPROVED)
    assert _done(box).status == "answered"


def test_with_the_acting_user_target_another_login_never_gets_or_answers_it(server, monkeypatch):
    from tui_gateway import server_requests
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _session(server, "s1", robin, sam)
    _caps(server, robin)
    _caps(server, sam)
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (ROBIN, True))
    box = _ask(target=server_requests.acting_user_target("s1", "review.draft"))
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
    box = _ask(park_seconds=60)
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


def test_a_session_with_only_an_agent_attached_parks_and_the_agent_is_never_asked(server, cancels, clock):
    from tui_gateway import server_requests
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    server_requests.advertise(agent, True, None, requests=["review.draft"])
    box = _ask(park_seconds=60, timeout=300)
    assert _opened(box)[1] == 0
    clock.advance(61)
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert agent.frames == [] and cancels == []


# ── parking ──────────────────────────────────────────────────────────────────────────────────


def test_a_parked_request_is_open_counted_and_named_while_nobody_is_attached(server):
    from tui_gateway import server_requests
    _session(server, "s1")
    box = _ask(park_seconds=60)
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
    box = _ask(park_seconds=60, timeout=300)
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
    box = _ask(park_seconds=60, timeout=300)
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


def test_a_request_pushed_and_then_listed_is_one_target_and_settles_once(server):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    server._attach_session_transport(session, phone)
    _caps(server, phone)  # pushed
    assert [r["id"] for r in _as(phone, server_requests.open_requests, "s1")] == [request_id]  # and listed
    with server_requests._lock:
        assert server_requests._open[request_id].targets == [phone]
    assert _rpc(server, phone, "request.answer", {"id": request_id, "result": APPROVED})["result"]["status"] == "ok"
    assert _rpc(server, phone, "request.answer", {"id": request_id, "result": APPROVED})["result"]["status"] == \
        "expired"
    outcome = _done(box)
    assert outcome.status == "answered" and outcome.answered_by is phone


def test_a_peer_attaching_between_the_scan_and_the_registration_still_gets_the_frame(server, monkeypatch):
    """The late scan of ``send_gated``: the first peer scan saw nobody, the phone was there by registration."""
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    real, calls = server_requests._peers, {"n": 0}

    def peers(sid):
        calls["n"] += 1
        return [] if calls["n"] == 1 else real(sid)

    monkeypatch.setattr(server_requests, "_peers", peers)
    box = _ask(park_seconds=60, timeout=300)
    request_id, reached = _opened(box)
    assert reached == 1 and [f["id"] for f in phone.requests()] == [request_id]
    _frame(server, phone, request_id, result=APPROVED)
    assert _done(box).answered_by is phone


def test_nobody_within_park_seconds_is_unavailable_without_a_cancel(server, cancels, clock):
    """Pinned choice: no ``request.cancel`` for a parked request nobody was shown."""
    from tui_gateway import server_requests
    _session(server, "s1")
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    clock.advance(59)
    assert server_requests.request_method(request_id) == "review.draft"  # still inside the window
    clock.advance(2)
    outcome = _done(box)
    assert (outcome.status, outcome.reason, outcome.request_id) == ("unavailable", "no_capable_client", request_id)
    assert cancels == [] and server_requests.open_request_count() == 0


def test_once_reached_the_parked_request_waits_past_park_seconds_for_the_answer(server, clock):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    _caps(server, phone)
    server._attach_session_transport(session, phone)
    _as(phone, server_requests.open_requests, "s1")
    clock.advance(120)  # past the park window: still open because somebody was reached
    assert server_requests.request_method(request_id) == "review.draft"
    _frame(server, phone, request_id, result=APPROVED)
    assert _done(box).status == "answered"


def test_a_reached_parked_request_that_runs_out_times_out_with_a_cancel(server, cancels, clock):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    phone = _WS("phone")
    _caps(server, phone)
    server._attach_session_transport(session, phone)
    _as(phone, server_requests.open_requests, "s1")
    clock.advance(301)
    outcome = _done(box)
    assert outcome.status == "timeout"
    assert ("s1", {"id": request_id, "method": "review.draft", "reason": "timeout"}) in cancels


def test_an_error_from_the_late_peer_settles_error_response(server):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=60, timeout=300)
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
    box = _ask(park_seconds=60, timeout=300)
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
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    assert server_requests.cancel("s1", reason="interrupted") == 1
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("cancelled", "interrupted")
    assert ("s1", {"id": request_id, "method": "review.draft", "reason": "interrupted"}) in cancels
    assert server_requests.open_request_count() == 0


# ── lost targets ─────────────────────────────────────────────────────────────────────────────


def test_a_failed_late_push_leaves_the_request_parked_and_unreached(server, cancels, clock):
    """The only "reach" was a write that failed: no target, so the park window decides (no timeout, no cancel)."""
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    dead = _WS("dead")
    dead.fail_writes = True
    server._attach_session_transport(session, dead)
    assert server_requests.handled_methods(dead) == [] and _caps(server, dead)["requests"] == ["review.draft"]
    with server_requests._lock:
        assert server_requests._open[request_id].targets == []
    clock.advance(61)
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert cancels == []


def test_a_target_that_disconnects_parks_the_request_again_for_its_replacement(server, clock):
    """A phone that reconnects as a new connection: the old one is forgotten, so the new one's 4041 settles."""
    from tui_gateway import server_requests
    session = _session(server, "s1")
    old = _WS("phone (old socket)")
    _caps(server, old)
    server._attach_session_transport(session, old)
    box = _ask(park_seconds=60, timeout=300)
    request_id, reached = _opened(box)
    assert reached == 1
    server._detach_session_transport(session, old)
    server_requests.forget(old)
    with server_requests._lock:
        assert server_requests._open[request_id].targets == []
    clock.advance(30)  # inside the park window: still waiting for a device
    assert server_requests.request_method(request_id) == "review.draft"
    new = _WS("phone (new socket)")
    _caps(server, new)
    server._attach_session_transport(session, new)
    assert [r["id"] for r in _as(new, server_requests.open_requests, "s1")] == [request_id]
    _frame(server, new, request_id, error={"code": 4041, "message": "cannot_show"})
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "error_response")


def test_a_shown_request_that_loses_its_device_gets_a_fresh_bounded_window(server, cancels, clock):
    """Lead decision: shown once, its last device gone after the first window, it parks again for
    ``park_seconds`` from then; nobody back in that window ends it ``no_capable_client`` with a cancel."""
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    clock.advance(90)
    server_requests.forget(phone)
    clock.advance(59)  # inside the fresh window (until t=150)
    assert server_requests.request_method(request_id) == "review.draft"
    clock.advance(2)
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert ("s1", {"id": request_id, "method": "review.draft", "reason": "timeout"}) in cancels


def test_a_backgrounded_phone_that_returns_in_its_fresh_window_answers(server, clock):
    """review.draft, park 120 / timeout 600: shown at t=5, the app backgrounded at t=150 (its socket forgotten),
    back at t=170 as a new connection: ``open_requests`` lists it again and the answer settles."""
    from tui_gateway import server_requests
    session = _session(server, "s1")
    box = _ask(park_seconds=120, timeout=600)
    request_id, _ = _opened(box)
    clock.advance(5)
    phone = _WS("phone")
    _caps(server, phone)
    server._attach_session_transport(session, phone)
    assert [r["id"] for r in _as(phone, server_requests.open_requests, "s1")] == [request_id]
    clock.advance(145)  # t=150
    server._detach_session_transport(session, phone)
    server_requests.forget(phone)
    with server_requests._lock:
        req = server_requests._open[request_id]
        assert req.targets == [] and req.park_until == pytest.approx(1_000.0 + 150 + 120)
    clock.advance(20)  # t=170
    back = _WS("phone (back)")
    _caps(server, back)
    server._attach_session_transport(session, back)
    assert [r["id"] for r in _as(back, server_requests.open_requests, "s1")] == [request_id]
    _frame(server, back, request_id, result=APPROVED)
    outcome = _done(box)
    assert outcome.status == "answered" and outcome.answered_by is back


def test_the_fresh_window_never_passes_the_timeout(server, cancels, clock):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    box = _ask(park_seconds=120, timeout=200)
    request_id, _ = _opened(box)
    clock.advance(150)
    server_requests.forget(phone)
    with server_requests._lock:
        assert server_requests._open[request_id].park_until == pytest.approx(1_000.0 + 200)
    clock.advance(51)
    assert (_done(box).reason) == "no_capable_client"


def test_a_connection_that_stops_advertising_the_method_is_dropped_like_a_disconnect(server, clock):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    _caps(server, phone, requests=["input.form"])  # no longer review.draft
    with server_requests._lock:
        assert server_requests._open[request_id].targets == []
    assert _rpc(server, phone, "request.answer", {"id": request_id, "result": APPROVED})["error"]["code"] == 4033
    clock.advance(61)
    assert _done(box).reason == "no_capable_client"


def test_server_requests_false_drops_it_too(server):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    box = _ask(park_seconds=60, timeout=300)
    request_id, _ = _opened(box)
    server_requests.advertise(phone, False)
    with server_requests._lock:
        assert server_requests._open[request_id].targets == []
    server_requests.cancel("s1")
    _done(box)


def test_a_connection_forgotten_between_the_peer_list_and_the_registration_is_no_target(server, monkeypatch):
    """Seam: ``_peers`` lists the phone, which disconnects before the choice is made under the lock."""
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    real = server_requests._peers

    def peers(sid):
        listed = real(sid)
        server_requests.forget(phone)
        return listed

    monkeypatch.setattr(server_requests, "_peers", peers)
    outcome = server_requests.send_gated("review.draft", "s1", DRAFT, timeout=300, validate=_validate)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert phone.frames == [] and server_requests.open_request_count() == 0


def test_without_parking_every_failed_first_write_settles_write_failed_silently(server, cancels, monkeypatch):
    from tui_gateway import request_hooks, server_requests
    announced = []
    monkeypatch.setattr(request_hooks, "opened", lambda *a, **k: announced.append(a))
    dead = _WS("dead")
    dead.fail_writes = True
    _session(server, "s1", dead)
    _caps(server, dead)
    opened = []
    outcome = server_requests.send_gated("review.draft", "s1", DRAFT, timeout=300, validate=_validate,
                                         on_open=lambda rid, n: opened.append(rid))
    assert (outcome.status, outcome.reason) == ("unavailable", "write_failed")
    assert opened == [] and announced == [] and cancels == [] and server_requests.open_request_count() == 0


def test_without_parking_a_lost_last_target_ends_it_at_once(server, cancels):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    _caps(server, phone)
    box = _ask(timeout=300)
    request_id, _ = _opened(box)
    server_requests.forget(phone)
    outcome = _done(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert ("s1", {"id": request_id, "method": "review.draft", "reason": "timeout"}) in cancels


def test_a_failed_first_write_parks_instead_of_failing(server, clock):
    from tui_gateway import server_requests
    session = _session(server, "s1")
    dead = _WS("dead")
    dead.fail_writes = True
    _caps(server, dead)
    server._attach_session_transport(session, dead)
    box = _ask(park_seconds=60, timeout=300)
    request_id, reached = _opened(box)
    assert reached == 0 and server_requests.request_method(request_id) == "review.draft"
    clock.advance(61)
    assert (_done(box).reason) == "no_capable_client"


def test_forget_leaves_a_confirm_requests_targets_alone(server):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", phone)
    req = server_requests.ServerRequest("s1", "confirm", {}, level="plain")
    req.targets = [phone]
    with server_requests._lock:
        server_requests._open[req.id] = req
    server_requests.forget(phone)
    assert req.targets == [phone] and not req.event.is_set()


# ── the owner's callback ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("attached", [False, True])
def test_an_on_open_that_raises_withdraws_the_request(server, cancels, attached):
    from tui_gateway import server_requests
    phone = _WS("phone")
    _session(server, "s1", *([phone] if attached else []))
    _caps(server, phone)

    def broken(request_id, reached):
        raise RuntimeError("marker audit failure")

    with pytest.raises(RuntimeError):
        server_requests.send_gated("review.draft", "s1", DRAFT, timeout=300, validate=_validate, on_open=broken,
                                   park_seconds=60)
    assert server_requests.open_request_count() == 0
    assert bool(cancels) is attached  # withdrawn where it was shown, silent where nobody saw it


# ── confirm and misuse ──────────────────────────────────────────────────────────────────────


def test_a_level_gated_request_never_parks(server):
    """``confirm``'s path: no capable connection is ``unavailable`` at once, whatever ``park_seconds`` says."""
    from tui_gateway import server_requests
    _session(server, "s1")
    outcome = server_requests.send_gated("confirm", "s1", {"title": "Marker", "summary": "Marker.", "level": "plain"},
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
