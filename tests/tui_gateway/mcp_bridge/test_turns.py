"""``TurnWatch``: a turn an agent submits through MCP, watched until it concludes (plan D8, D9).

The first half drives the real handlers (``prompt.submit``, ``request.answer``, ``session.events.since``,
``session.active_list``) with a scripted agent, through ``server.dispatch`` on a real ``AgentTransport``. The
second half feeds the watch frames directly to pin which turn it adopts and the process-wide limits. Every
payload is a harmless marker.
"""

from __future__ import annotations

import threading
import time

import pytest

from tui_gateway.mcp_bridge import rpc, turns
from tui_gateway.mcp_bridge.transport import AgentTransport
import tui_gateway.server as server

from .conftest import CLIENT, KEY, ROBIN, SAM, SID, identity

PREFIX = f"[Answered by the agent «{CLIENT}» through MCP, not by «Robin»] "


def _deadline(seconds=10.0):
    return time.monotonic() + seconds


def _until(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _start(gateway, text, **kw):
    transport = gateway.connect(**kw)
    return transport, turns.start_turn(transport, chat_id=KEY, session_id=SID, text=text)


def _app_request(gateway, method):
    """The request frame as the person's app got it (each attached connection drains on its own thread)."""
    assert _until(lambda: gateway.app.requests(method))
    return gateway.app.requests(method)


def _user_row(gateway, text):
    [row] = [r for r in gateway.db.get_messages(KEY, include_inactive=True)
             if r["role"] == "user" and r["content"] == text]
    return row.get("display_metadata") or {}


# ── the real handlers ───────────────────────────────────────────────────────────────────────


def test_a_prompt_is_done_with_the_reply_and_the_marker_on_its_row(gateway):
    transport, watch = _start(gateway, "marker reply")
    result = watch.wait(_deadline())

    assert result["status"] == "done"
    assert result["text"] == "marker reply done"
    assert result["requests"] == [] and result["submit_status"] == "streaming"
    assert result["turn_id"] == watch.turn_id and result["chat_id"] == KEY
    metadata = _user_row(gateway, "marker reply")
    assert result["gateway_turn_id"] == metadata["turn_id"]
    assert metadata["author"] == {"id": ROBIN[0], "name": ROBIN[1], "via": {"kind": "mcp", "client": CLIENT}}
    assert "grant-g1" not in str(metadata)
    # The person's app saw the same turn; the agent's connection joined the session, it did not replace it.
    assert server._session_transport_contains(gateway.session, gateway.app)
    assert server._session_transport_contains(gateway.session, transport)


def test_progress_carries_the_tail_of_the_partial_text_while_the_turn_runs(gateway):
    _transport, watch = _start(gateway, "marker gated")
    seen = []
    running = watch.wait(time.monotonic() + 1.5, on_progress=seen.append)

    assert running["status"] == "running"
    assert running["text"].startswith("marker partial tick")
    assert seen and seen[-1].endswith("tick ")
    gateway.agent.gate.set()
    assert watch.wait(_deadline())["status"] == "done"


def test_a_clarify_waits_for_a_person_and_the_agents_answer_reaches_the_tool_marked(gateway):
    _transport, watch = _start(gateway, "marker clarify")
    waiting = watch.wait(_deadline())

    assert waiting["status"] == "waiting_for_person"
    [request] = waiting["requests"]
    assert request["kind"] == "clarify" and request["answerable"] is True and request["batch"] is False
    assert request["questions"] == [{"id": "", "question": "Which marker?", "choices": ["one", "two"],
                                     "multi_select": False}]
    # Reported once: a second wait does not return early for the same open request.
    again = watch.wait(time.monotonic() + 0.3)
    assert again["status"] == "waiting_for_person"

    assert watch.answer_clarify(request["id"], "one") == "ok"
    done = watch.wait(_deadline())
    assert done["status"] == "done" and done["text"] == "marker clarified"
    # The gateway prefixed it; the bridge added nothing.
    assert gateway.agent.clarify_answers == [PREFIX + "one"]


def test_an_approval_waits_for_the_person_and_the_agent_cannot_answer_it(gateway):
    transport, watch = _start(gateway, "marker approval")
    waiting = watch.wait(_deadline())

    assert waiting["status"] == "waiting_for_person"
    [request] = waiting["requests"]
    assert request["kind"] == "approval" and request["answerable"] is False
    assert request["description"] == "marker approval" and request["command"] == "echo marker"
    with pytest.raises(turns.NotAnswerable) as refused:
        turns.answer_clarify(transport, request["id"], "once")
    assert refused.value.code == 4033
    # Still open, still the person's.
    assert watch.wait(time.monotonic() + 0.3)["status"] == "waiting_for_person"
    assert gateway.agent.approval_results == []

    # Robin answers from the app; the agent learns it from the gateway (no event says so).
    [frame] = _app_request(gateway, "approval")
    server.dispatch({"jsonrpc": "2.0", "id": frame["id"], "result": {"choice": "once"}}, gateway.app)
    done = watch.wait(_deadline())
    assert done["status"] == "done" and done["text"] == "marker approved"
    assert gateway.agent.approval_results == [{"choice": "once"}]


def test_a_request_the_person_answered_leaves_the_watch_while_the_turn_goes_on(gateway):
    _transport, watch = _start(gateway, "marker approval then gated")
    assert watch.wait(_deadline())["status"] == "waiting_for_person"
    [frame] = _app_request(gateway, "approval")
    server.dispatch({"jsonrpc": "2.0", "id": frame["id"], "result": {"choice": "deny"}}, gateway.app)

    running = watch.wait(time.monotonic() + 3)
    assert (running["status"], running["requests"]) == ("running", [])
    gateway.agent.gate.set()
    assert watch.wait(_deadline())["status"] == "done"


def test_another_persons_session_answers_4001_and_nothing_is_watched(gateway):
    sam = gateway.connect(SAM)
    with pytest.raises(rpc.RpcError) as refused:
        turns.start_turn(sam, chat_id=KEY, session_id=SID, text="marker reply")
    assert refused.value.code == 4001
    assert turns.watch_count() == 0
    assert not sam.has_event_sink
    with pytest.raises(rpc.RpcError) as replay:
        rpc.call(sam, "session.events.since", {"session_id": SID, "last_seen": 0})
    assert replay.value.code == 4001
    assert gateway.agent.texts == []


def test_a_watch_is_found_by_its_person_only(gateway):
    _transport, watch = _start(gateway, "marker reply")
    assert turns.get(KEY, watch.turn_id, identity=identity()) is watch
    assert turns.get(KEY, watch.turn_id, identity=identity(grant="grant-g2")) is watch
    assert turns.get(KEY, watch.turn_id, identity=identity(SAM)) is None
    assert turns.get(KEY, "unknown", identity=identity()) is None


def test_the_agent_detaches_after_the_turn_and_the_chat_stays_with_the_person(gateway, monkeypatch):
    monkeypatch.setattr(turns, "DETACH_AFTER_END_S", 0.05)
    transport, watch = _start(gateway, "marker reply")
    assert watch.wait(_deadline())["status"] == "done"

    assert _until(lambda: watch.detached)
    assert transport.closed and server._transport_is_dead(transport)
    assert not server._session_transport_contains(gateway.session, transport)
    assert server._session_transport_contains(gateway.session, gateway.app)
    assert server._sessions.get(SID) is gateway.session
    # The outcome outlives the attachment.
    assert turns.get(KEY, watch.turn_id, identity=identity()).snapshot()["text"] == "marker reply done"


def test_a_session_only_the_agent_was_attached_to_is_parked_after_the_detach(gateway, monkeypatch):
    monkeypatch.setattr(turns, "DETACH_AFTER_END_S", 0.05)
    monkeypatch.setattr(server, "_schedule_ws_orphan_reap", lambda sid: None)
    server._detach_session_transport(gateway.session, gateway.app)
    gateway.session["transport"] = server._detached_ws_transport
    transport, watch = _start(gateway, "marker reply")
    assert watch.wait(_deadline())["status"] == "done"

    assert _until(lambda: watch.detached)
    assert gateway.session["transport"] is server._detached_ws_transport
    assert server._sessions.get(SID) is gateway.session


def test_a_submit_while_the_gateway_restarts_is_gateway_restarting(gateway, monkeypatch):
    from tui_gateway import shutdown_drain
    monkeypatch.setattr(server, "_shutdown_drain_active", lambda: True)
    monkeypatch.setattr(shutdown_drain, "_shutdown_drain_active", lambda: True)
    monkeypatch.setattr(server, "_session_turn_admission", _refuse_admission)
    transport = gateway.connect()
    with pytest.raises(rpc.GatewayRestarting) as restarting:
        turns.start_turn(transport, chat_id=KEY, session_id=SID, text="marker reply")
    assert restarting.value.code == 5035 and restarting.value.kind == "gateway_restarting"
    assert restarting.value.retry_after_seconds == rpc.RESTART_RETRY_AFTER_S
    assert turns.watch_count() == 0


class _refuse_admission:
    def __init__(self, _session):
        pass

    def __enter__(self):
        return False

    def __exit__(self, *_exc):
        return False


def test_a_queued_prompt_behind_the_persons_queued_prompt_gets_its_own_turn(gateway):
    # The person's turn runs; the person queues a follow-up; then the agent's text queues behind it. The turn
    # after the running one is the PERSON's: the agent's watch must wait for its own.
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker person", "queued": True})[
        "result"]["status"] == "queued"
    transport = gateway.connect()
    watch = turns.start_turn(transport, chat_id=KEY, session_id=SID, text="marker reply", params={"queued": True})
    snap = watch.snapshot()
    assert (snap["status"], snap["queue_position"]) == ("queued", 2)
    gateway.agent.gate.set()
    done = watch.wait(_deadline())
    assert (done["status"], done["text"]) == ("done", "marker reply done"), done
    assert gateway.agent.texts[-2:] == ["marker person", "marker reply"]


def test_two_grants_under_one_client_name_each_get_their_own_queued_turn(gateway):
    """"This agent" is the grant (review X1b): two grants of one person under the same client name sending the
    same text are two turns, each matched to the connection that queued it, never one merged turn."""
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    first, second = gateway.connect(grant="grant-g1"), gateway.connect(grant="grant-g2")
    one = turns.start_turn(first, chat_id=KEY, session_id=SID, text="marker reply", params={"queued": True})
    two = turns.start_turn(second, chat_id=KEY, session_id=SID, text="marker reply", params={"queued": True})
    assert (one.snapshot()["queue_position"], two.snapshot()["queue_position"]) == (1, 2)
    gateway.agent.gate.set()
    done_one, done_two = one.wait(_deadline()), two.wait(_deadline())
    assert done_one["status"] == done_two["status"] == "done"
    assert done_one["gateway_turn_id"] != done_two["gateway_turn_id"]
    assert gateway.agent.texts[-2:] == ["marker reply", "marker reply"]


def test_a_queued_prompt_a_stop_dropped_ends_interrupted(gateway, monkeypatch):
    monkeypatch.setattr(turns, "_DROPPED_CONFIRM_S", 0.2)
    monkeypatch.setattr(turns, "RECONCILE_INTERVAL_S", 0.2)
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    transport = gateway.connect()
    watch = turns.start_turn(transport, chat_id=KEY, session_id=SID, text="marker reply", params={"queued": True})
    assert watch.snapshot()["queue_position"] == 1
    gateway.app.call("session.interrupt", {"session_id": SID})  # the person's Stop clears the queue
    gateway.agent.gate.set()
    ended = watch.wait(_deadline())
    assert (ended["status"], ended["error"]) == ("interrupted", turns.DROPPED_MESSAGE)
    assert "marker reply" not in gateway.agent.texts


def test_a_queued_prompt_a_stop_dropped_concludes_without_a_waiter(gateway, monkeypatch):
    """Regression (review X1b): the drop was noticed only inside a waiter's reconcile, so with no bot_wait the
    watch never concluded, held its slot and kept the agent's connection attached for hours."""
    from tui_gateway.mcp_bridge import limits

    monkeypatch.setattr(turns, "_DROPPED_CONFIRM_S", 0.2)
    monkeypatch.setattr(turns, "MONITOR_INTERVAL_S", 0.1)
    monkeypatch.setattr(turns, "DETACH_AFTER_END_S", 0.2)
    limits.reset_for_tests()
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    transport = gateway.connect()
    slot = limits.reserve_running(transport.grant, 3)
    watch = turns.start_turn(transport, chat_id=KEY, session_id=SID, text="marker reply", params={"queued": True},
                             slot=slot)
    assert watch.status == "queued" and limits.running_turns(transport.grant) == 1
    gateway.app.call("session.interrupt", {"session_id": SID})  # the person's Stop clears the queue
    gateway.agent.gate.set()
    # Nobody calls wait(): the watch concludes on its own, gives its slot back and detaches.
    assert _until(lambda: watch.concluded, 5)
    assert watch.snapshot()["error"] == turns.DROPPED_MESSAGE
    assert limits.running_turns(transport.grant) == 0
    assert _until(lambda: transport.closed and watch.detached, 5)
    limits.reset_for_tests()


@pytest.mark.parametrize("extra", [{"turn_agent": {"kind": "mcp", "client": "X"}},
                                   {"agent": {"kind": "mcp", "client": "X"}},
                                   {"_turn_agent": {"kind": "mcp", "client": "X"}}],
                         ids=["turn_agent", "agent", "_turn_agent"])
def test_no_request_parameter_puts_an_agent_marker_on_a_persons_turn(gateway, extra):
    """Review X1b: the marker comes from the connection only; a person's client cannot forge it."""
    response = gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker reply", **extra})
    if "result" in response:
        assert _until(lambda: not gateway.session.get("running"))
        assert "via" not in (_user_row(gateway, "marker reply").get("author") or {})
    else:
        assert response["error"]["code"] in (4000, -32602), response


# ── an agent's stop (review X1b) ──────────────────────────────────────────────────────────


def _running_turn_id(gateway):
    assert _until(lambda: gateway.session.get("running") and gateway.session.get("turn_id"))
    return gateway.session["turn_id"]


def test_an_agent_stops_a_turn_only_by_its_id_and_never_the_persons(gateway):
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    persons = _running_turn_id(gateway)
    transport = gateway.connect()
    # Without the id the bridge binds, an agent's session.interrupt is refused outright.
    with pytest.raises(rpc.RpcError) as refused:
        rpc.call(transport, "session.interrupt", {"session_id": SID})
    assert refused.value.code == 4033
    # The person's own turn, named by its id: not the agent's, so not stopped.
    assert rpc.interrupt_turn(transport, SID, persons) is False
    assert gateway.agent._interrupt_requested is False and gateway.session["running"] is True
    gateway.agent.gate.set()


def test_a_stop_checked_against_the_agents_turn_never_lands_on_the_next_one(gateway):
    """Regression (review X1b): the bridge checked the running turn, then interrupted the session; the agent's
    turn could end in between and the person's next turn be the one stopped."""
    transport, watch = _start(gateway, "marker gated")
    agents = _running_turn_id(gateway)
    assert _until(lambda: watch.gateway_turn_id == agents)
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker clarify", "queued": True})[
        "result"]["status"] == "queued"
    gateway.agent.gate.set()  # the agent's turn ends; the person's queued prompt starts and asks a question
    assert watch.wait(_deadline())["status"] == "done"
    [clarify] = _app_request(gateway, "clarify")
    assert _running_turn_id(gateway) != agents
    # The stop the agent asked for names its own (finished) turn: the person's turn goes on.
    assert rpc.interrupt_turn(gateway.connect(), SID, agents) is False
    assert gateway.agent._interrupt_requested is False and gateway.session["running"] is True
    from tui_gateway import server_requests
    assert server_requests.request_method(clarify["id"]) == "clarify"
    gateway.app.call("request.answer", {"id": clarify["id"], "result": {"answer": "one"}})


def test_an_agents_stop_keeps_the_prompts_others_queued(gateway):
    """Regression (review X1b): an agent's stop went through the person's Stop, which empties the queue."""
    transport, watch = _start(gateway, "marker gated")
    agents = _running_turn_id(gateway)
    assert _until(lambda: watch.gateway_turn_id == agents)
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker person", "queued": True})[
        "result"]["status"] == "queued"
    assert rpc.interrupt_turn(transport, SID, agents) is True
    assert gateway.session["queued_prompt"]["text"] == "marker person"
    gateway.agent.gate.set()
    assert watch.wait(_deadline())["status"] in ("interrupted", "done")
    assert _until(lambda: "marker person" in gateway.agent.texts)


def test_a_cancelled_wait_returns_without_stopping_the_turn(gateway):
    _transport, watch = _start(gateway, "marker gated")
    stop = threading.Event()
    stop.set()
    assert watch.wait(_deadline(), stop=stop)["status"] == "running"
    assert gateway.session["running"] is True
    gateway.agent.gate.set()
    assert watch.wait(_deadline())["status"] == "done"


# ── which turn is ours, from frames ─────────────────────────────────────────────────────────


def _watch(*, pre=(), **kw):
    transport = AgentTransport(identity())
    watch = turns.TurnWatch(transport, chat_id=KEY, session_id=SID, **kw)
    for frame in pre:
        watch._feed(frame)
    watch._arm()
    return watch


def _event(kind, tid=None, payload=None, sid=SID):
    params = {"type": kind, "session_id": sid}
    if tid:
        params["turn_id"] = tid
    if payload is not None:
        params["payload"] = payload
    return {"jsonrpc": "2.0", "method": "event", "params": params}


def _complete(tid, text="marker", status="complete", **extra):
    return _event("message.complete", tid, {"text": text, "status": status, **extra})


def _request(rid, method="clarify", **params):
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": {"session_id": SID, **params}}


@pytest.fixture(autouse=True)
def _clarify_on(monkeypatch):
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_agent_clarify_allowed", lambda: True)
    yield
    turns.reset_for_tests()


def test_frames_before_the_submit_answered_wait_for_its_status():
    watch = _watch()
    watch._feed(_event("message.start", "t-ours"))
    watch._feed(_event("message.delta", "t-ours", {"text": "marker "}))
    assert watch.snapshot()["text"] == ""
    watch._set_mode("streaming", None)
    watch._feed(_complete("t-ours", "marker final"))
    snap = watch.snapshot()
    assert (snap["status"], snap["text"], snap["gateway_turn_id"]) == ("done", "marker final", "t-ours")


def test_a_turn_that_ran_before_the_watch_armed_is_never_adopted():
    watch = _watch(pre=[_event("message.start", "t-old"), _event("message.delta", "t-old", {"text": "x"})])
    watch._feed(_complete("t-old", "the earlier reply"))  # a straggler delivered after arming
    watch._set_mode("streaming", None)
    assert watch.status == "running" and watch.snapshot()["text"] == ""
    watch._feed(_event("message.start", "t-ours"))
    watch._feed(_complete("t-ours", "marker ours"))
    assert watch.snapshot()["text"] == "marker ours"


def test_a_queued_prompt_adopts_only_the_turn_known_to_be_the_agents():
    # The queue holds someone else's envelope ahead of ours: position would pick the wrong turn.
    ours = {"t-ours"}
    watch = _watch(verify_start=lambda tid: tid in ours)
    watch._set_mode("queued", None)
    watch._feed(_event("message.delta", "t-running", {"text": "theirs"}))
    watch._feed(_complete("t-running", "their reply"))
    assert watch.status == "queued"
    watch._feed(_event("message.start", "t-person"))
    watch._feed(_event("message.delta", "t-person", {"text": "the person's words"}))
    watch._feed(_request("rq-person", question="Theirs?"))
    watch._feed(_complete("t-person", "the person's reply"))
    snap = watch.snapshot()
    assert (snap["status"], snap["text"], snap["requests"]) == ("queued", "", [])
    watch._feed(_event("message.start", "t-ours"))
    watch._feed(_complete("t-ours", "marker queued"))
    snap = watch.snapshot()
    assert (snap["status"], snap["text"], snap["gateway_turn_id"]) == ("done", "marker queued", "t-ours")


def test_a_queued_turn_that_cannot_be_told_at_its_start_is_told_by_its_stored_row():
    ends = []

    def verify_end(tid, row):
        ends.append((tid, row))
        return row == 7

    watch = _watch(verify_start=lambda tid: None, verify_end=verify_end)
    watch._set_mode("queued", None)
    watch._feed(_event("message.start", "t-a"))
    watch._feed(_event("message.delta", "t-a", {"text": "not ours"}))
    watch._feed(_complete("t-a", "theirs", persisted_turn={"user_row_id": 6}))
    watch._feed(_event("message.start", "t-b"))
    watch._feed(_request("rq-b", question="Which marker?"))
    watch._feed(_event("message.delta", "t-b", {"text": "marker "}))
    assert watch.wait(time.monotonic() + 1)["status"] == "queued"
    watch._feed(_complete("t-b", "marker ours", persisted_turn={"user_row_id": 7}))
    snap = watch.wait(time.monotonic() + 2)
    assert (snap["status"], snap["text"], snap["gateway_turn_id"]) == ("done", "marker ours", "t-b")
    assert ends == [("t-a", 6), ("t-b", 7)]


def test_a_queued_turn_is_adopted_mid_turn_with_its_open_request(monkeypatch):
    watch = _watch(verify_start=lambda tid: True)
    watch._set_mode("queued", None)
    watch._feed(_event("message.start", "t-ours"))
    watch._feed(_request("rq-1", question="Which marker?"))
    snap = watch.snapshot()
    assert snap["status"] == "waiting_for_person" and [r["id"] for r in snap["requests"]] == ["rq-1"]


def test_a_queued_prompt_reports_its_position_and_ends_when_dropped(monkeypatch):
    monkeypatch.setattr(turns, "_DROPPED_CONFIRM_S", 0.2)
    monkeypatch.setattr(turns, "RECONCILE_INTERVAL_S", 0.1)
    monkeypatch.setattr(turns, "_RECONCILE_MIN_GAP_S", 0.05)
    state = {"probe": (True, 2)}
    watch = _watch(verify_start=lambda tid: False, queue_probe=lambda: state["probe"])
    watch._set_mode("queued", None)
    watch._probe_queue()
    snap = watch.snapshot()
    assert (snap["status"], snap["queue_position"]) == ("queued", 2)
    # A Stop dropped the queue: idle, and no envelope holds the text.
    state["probe"] = (False, None)
    snap = watch.wait(time.monotonic() + 3)
    assert (snap["status"], snap["error"]) == ("interrupted", turns.DROPPED_MESSAGE)


def test_a_steer_joins_the_running_turn():
    watch = _watch(pre=[_event("message.start", "t-running")])
    watch._set_mode("steered", None)
    watch._feed(_event("message.delta", "t-running", {"text": "marker "}))
    watch._feed(_complete("t-running", "marker steered"))
    snap = watch.snapshot()
    assert (snap["status"], snap["gateway_turn_id"], snap["submit_status"]) == ("done", "t-running", "steered")


def test_a_terminal_frame_without_a_start_is_ours_when_the_user_row_says_so():
    watch = _watch()
    watch._set_mode("streaming", 41)
    watch._feed(_complete("t-old", "earlier", persisted_turn={"row_ids": [], "complete": True, "user_row_id": 40}))
    assert watch.status == "running"
    watch._feed(_complete("t-ours", "", status="error", error="marker failed",
                          persisted_turn={"row_ids": [], "complete": False, "user_row_id": 41}))
    snap = watch.snapshot()
    assert (snap["status"], snap["error"]) == ("error", "marker failed")


def test_a_held_terminal_frame_is_adopted_once_the_session_is_idle(monkeypatch):
    calls = []

    def fake_call(transport, method, params=None, *, timeout=None):
        calls.append(method)
        return {"sessions": [{"id": SID, "status": "idle"}]} if method == "session.active_list" else {}

    monkeypatch.setattr(rpc, "call", fake_call)
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("error", "t-ours", {"message": "marker refused"}))
    assert watch.status == "running"
    snap = watch.wait(_deadline(3))
    assert (snap["status"], snap["error"]) == ("error", "marker refused")
    assert "session.active_list" in calls


def test_a_held_terminal_frame_concludes_without_a_waiter(monkeypatch):
    monkeypatch.setattr(turns, "MONITOR_INTERVAL_S", 0.05)
    monkeypatch.setattr(rpc, "call", lambda *a, **k: {"sessions": [{"id": SID, "status": "idle"}]})
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("error", "t-ours", {"message": "marker refused"}))
    assert _until(lambda: watch.concluded, 3)
    assert watch.snapshot()["error"] == "marker refused"


def test_a_held_terminal_frame_is_dropped_when_the_turn_starts_after_all(monkeypatch):
    monkeypatch.setattr(rpc, "call", lambda *a, **k: {"sessions": [{"id": SID, "status": "working"}]})
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_complete("t-old", "earlier"))
    watch.wait(time.monotonic() + 0.7)
    assert watch.status == "running"
    watch._feed(_event("message.start", "t-ours"))
    watch._feed(_complete("t-ours", "marker ours"))
    assert watch.snapshot()["text"] == "marker ours"


@pytest.mark.parametrize("status,reason,expected", [
    ("interrupted", "", "interrupted"), ("interrupted", "shutdown", "restarted"), ("error", "", "error"),
])
def test_the_end_of_a_turn_names_how_it_ended(status, reason, expected):
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("message.start", "t"))
    watch._feed(_event("message.delta", "t", {"text": "marker partial"}))
    watch._feed(_complete("t", "", status=status, interrupt_reason=reason or None, error="x" if status == "error"
                          else None))
    snap = watch.snapshot()
    assert snap["status"] == expected
    assert snap["text"] == "marker partial"
    if expected == "restarted":
        assert snap["restarting"] is True and snap["retry_after_seconds"] == rpc.RESTART_RETRY_AFTER_S


def test_a_restart_notice_is_reported_while_the_turn_drains():
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("message.start", "t"))
    watch._feed(_event("status.update", None, {"kind": "restart", "text": "marker"}))
    snap = watch.snapshot()
    assert snap["status"] == "running" and snap["restarting"] is True


def test_a_stamped_error_inside_a_started_turn_does_not_end_it():
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("message.start", "t"))
    watch._feed(_event("error", "t", {"message": "marker hiccup"}))
    assert watch.status == "running"


def test_frames_of_another_session_are_ignored():
    watch = _watch()
    watch._set_mode("streaming", None)
    other = _complete("t", "theirs")
    other["params"]["session_id"] = "sid-other"
    watch._feed(_event("message.start", "t", sid="sid-other"))
    watch._feed(other)
    assert watch.status == "running"


def test_requests_open_and_close_and_secret_prompts_are_a_kind_only():
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_request("srq-early", question="before the start"))  # not ours until the turn starts
    watch._feed(_event("message.start", "t"))
    watch._feed(_request("srq-1", "secret", env_var="MARKER_VAR", prompt="marker secret prompt"))
    watch._feed(_request("srq-2", "sudo", command="marker"))
    watch._feed(_request("srq-3", "vault.code", site="marker.invalid", hint="marker hint"))
    snap = watch.snapshot()
    assert snap["status"] == "waiting_for_person"
    assert [r["id"] for r in snap["requests"]] == ["srq-1", "srq-2", "srq-3"]
    for summary in snap["requests"]:
        assert set(summary) == {"id", "kind", "answerable"} and summary["answerable"] is False
    assert "marker secret prompt" not in str(snap) and "MARKER_VAR" not in str(snap)
    for rid in ("srq-1", "srq-2", "srq-3"):
        watch._feed(_event("request.cancel", None, {"id": rid, "method": "x", "reason": "timeout"}))
    assert watch.status == "running"


def test_a_batch_clarify_summary_lists_its_questions():
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("message.start", "t"))
    watch._feed(_request("srq-b", questions=[{"qid": "q1", "question": "marker one?", "choices": ["a"]},
                                             {"qid": "q2", "question": "marker two?", "multi_select": True}],
                         answers={"q1": "a"}))
    [summary] = watch.snapshot()["requests"]
    assert summary["batch"] is True and summary["locked"] == ["q1"]
    assert [q["id"] for q in summary["questions"]] == ["q1", "q2"]
    assert summary["questions"][1]["multi_select"] is True


def test_the_reply_buffer_is_capped(monkeypatch):
    monkeypatch.setattr(turns, "TEXT_CAP_BYTES", 64)
    watch = _watch()
    watch._set_mode("streaming", None)
    watch._feed(_event("message.start", "t"))
    for _ in range(10):
        watch._feed(_event("message.delta", "t", {"text": "marker-é-"}))
    snap = watch.snapshot()
    assert snap["text_truncated"] is True and len(snap["text"].encode()) <= 64
    assert watch._tail.endswith("marker-é-")


def test_a_newer_wait_supersedes_the_older_one():
    watch = _watch()
    watch._set_mode("streaming", None)
    results = []
    first = threading.Thread(target=lambda: results.append(watch.wait(_deadline(5))))
    first.start()
    time.sleep(0.1)
    watch.wait(time.monotonic() + 0.05)
    first.join(timeout=2)
    assert not first.is_alive() and results[0]["status"] == "running"


# ── process-wide limits ─────────────────────────────────────────────────────────────────────


def _registered(n):
    watches = []
    for _ in range(n):
        watch = _watch()
        turns._register(watch)
        watches.append(watch)
    return watches


def test_at_most_max_watches_and_none_evicted_while_running(monkeypatch):
    monkeypatch.setattr(turns, "MAX_WATCHES", 3)
    _registered(3)
    with pytest.raises(turns.WatchLimitReached):
        _registered(1)


def test_a_concluded_watch_makes_room_oldest_first(monkeypatch):
    monkeypatch.setattr(turns, "MAX_WATCHES", 3)
    monkeypatch.setattr(turns, "DETACH_AFTER_END_S", 3600)
    first, second, _third = _registered(3)
    for watch in (second, first):
        watch._set_mode("none", None)  # concluded at once
    [newest] = _registered(1)
    assert turns.get(KEY, second.turn_id, identity=identity()) is None
    assert turns.get(KEY, first.turn_id, identity=identity()) is first
    assert second.detached and second._transport.closed
    assert turns.get(KEY, newest.turn_id, identity=identity()) is newest


def test_a_concluded_watch_is_evicted_an_hour_after_it_ended(monkeypatch):
    monkeypatch.setattr(turns, "DETACH_AFTER_END_S", 3600)
    [watch] = _registered(1)
    watch._set_mode("none", None)
    assert turns.get(KEY, watch.turn_id, identity=identity()) is watch
    watch.ended_at -= turns.RETAIN_AFTER_END_S
    assert turns.get(KEY, watch.turn_id, identity=identity()) is None
    assert watch.detached


def test_one_turn_per_transport():
    watch = _watch()
    with pytest.raises(rpc.DisallowedCall):
        turns.start_turn(watch._transport, chat_id=KEY, session_id=SID, text="marker")
