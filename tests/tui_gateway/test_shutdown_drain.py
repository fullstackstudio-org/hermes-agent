"""Restart-safe turns: a dashboard shutdown drains running turns before the sockets close, then
interrupts the rest so they resume after the restart (``tui_gateway/shutdown_drain.py``).

Pinned here, with fake agents and no real signals:

* a turn that finishes inside the drain window completes normally (real answer, marker retired);
* a turn still running when the window ends is interrupted with the shutdown reason, keeps its
  marker with attempts bumped, journals the prompts queued behind it, and says so on
  ``message.complete``; the next ``session.resume`` schedules the continuation and restores the queue;
* the closing row of a shutdown-interrupted tool tail is a hidden structured marker, never the
  "Operation interrupted" sentinel, and history replay shows nothing for it;
* a user /stop is unchanged (marker retired, sentinel closing row, no interrupt reason), and wins
  over a shutdown that is interrupting the same turn;
* new turns and continuations are refused while draining;
* the signal/atexit exit path interrupts with the same shutdown semantics.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
import types

import pytest

from tui_gateway import server
from tui_gateway.turn_marker import (
    mark_turn_shutdown_interrupted,
    read_turn_marker,
    record_turn_start,
    retire_turn_marker,
)

SENTINEL = "Operation interrupted: waiting for model response (1.2s elapsed)."


def _session(agent=None, **extra):
    return {
        "agent": agent if agent is not None else types.SimpleNamespace(),
        "session_key": "session-key",
        "history": [],
        "history_lock": threading.RLock(),
        "history_version": 0,
        "running": False,
        "attached_images": [],
        "image_counter": 0,
        "cols": 80,
        "slash_worker": None,
        "show_reasoning": False,
        "tool_progress_mode": "all",
        "inflight_turn": None,
        **extra,
    }


class _ModelWaitAgent:
    """An agent whose turn blocks in a "model wait" until released or interrupted.

    ``release`` set -> the model answered: a normal completion. A hard interrupt -> the turn
    returns the way the real loop does when a stop lands during the provider call."""

    def __init__(self):
        self.session_id = "session-key"
        self.release = threading.Event()
        self.entered = threading.Event()
        self.interrupts: list[tuple] = []
        self._interrupted = threading.Event()
        self.interim_assistant_callback = None

    def run_conversation(self, message, **kwargs):
        self.entered.set()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self.release.is_set():
                return {"final_response": "the real answer", "messages": []}
            if self._interrupted.is_set():
                return {"final_response": SENTINEL, "interrupted": True, "messages": []}
            time.sleep(0.01)
        raise AssertionError("fake turn was never released nor interrupted")

    def hard_interrupt(self, message=None, *, tool_reason=None):
        self.interrupts.append((message, tool_reason))
        self._interrupted.set()

    def interrupt(self, message=None):
        self.hard_interrupt(message)

    def clear_interrupt(self, **kwargs):
        return True


class _Emits(list):
    broadcasts: list


@pytest.fixture()
def emits(monkeypatch):
    captured = _Emits()
    monkeypatch.setattr(server, "_emit", lambda event, sid, payload=None: captured.append((event, sid, payload)))
    broadcasts: list = []
    monkeypatch.setattr(server, "_broadcast_global_event", lambda event, payload=None: broadcasts.append((event, payload)))
    captured.broadcasts = broadcasts
    return captured


@pytest.fixture()
def marker_home(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_hermes_home", tmp_path)
    return tmp_path


@pytest.fixture()
def turn_env(monkeypatch, tmp_path, marker_home):
    """Real turn threads; the turn pipeline's environment-heavy side paths neutralized."""
    monkeypatch.setattr(server, "_wire_callbacks", lambda sid: None)
    monkeypatch.setattr(server, "_sync_agent_model_with_config", lambda sid, session: None)
    monkeypatch.setattr(server, "_session_cwd", lambda session: str(tmp_path))
    monkeypatch.setattr(server, "_register_session_cwd", lambda session: None)
    monkeypatch.setattr(server, "_tts_stream_begin", lambda: None)
    monkeypatch.setattr(server, "_sync_session_key_after_compress", lambda *a, **k: None)
    monkeypatch.setattr(server, "_get_usage", lambda agent: {})
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda *a, **k: False)
    monkeypatch.setattr(server, "_clear_pending", lambda sid=None: None)
    monkeypatch.setattr(server, "_reopen_routed_session_row", lambda *a, **k: None)
    monkeypatch.setattr(server, "_routing_provenance_db", lambda session: contextlib.nullcontext(None))
    monkeypatch.setattr(server, "_run_post_turn_followups", lambda *a, **k: None)
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    from tools.environments import base as env_base
    monkeypatch.setattr(env_base, "kill_live_foreground_processes", lambda now=False: None)


@pytest.fixture(autouse=True)
def _fresh_drain_state():
    server._shutdown_draining.clear()
    registered = dict(server._sessions)
    yield
    server._shutdown_draining.clear()
    with server._sessions_lock:
        server._sessions.clear()
        server._sessions.update(registered)


def _register(sid, session):
    with server._sessions_lock:
        server._sessions[sid] = session
    return session


def _start_turn(sid, session, text="do the long thing"):
    session["running"] = True
    server._run_prompt_submit("rid", sid, session, text)
    assert session["agent"].entered.wait(5), "fake turn never started"


def _completes(emits, sid):
    return [p for e, s, p in emits if e == "message.complete" and s == sid]


def _wait_settled(session, timeout=5.0):
    thread = session.get("_run_thread")
    if thread is not None:
        thread.join(timeout)
    deadline = time.monotonic() + timeout
    while session.get("running") and time.monotonic() < deadline:
        time.sleep(0.01)


# ── Drain: a short turn finishes with its real answer ─────────────────


def test_drain_lets_a_short_turn_finish_normally(emits, turn_env, marker_home):
    agent = _ModelWaitAgent()
    session = _register("short", _session(agent=agent))
    _start_turn("short", session)
    # The model answers while the drain is waiting.
    threading.Timer(0.3, agent.release.set).start()

    outcome = asyncio.run(server.drain_turns_for_shutdown(timeout=5.0))

    _wait_settled(session)
    assert outcome["drained"] == 1 and outcome["interrupted"] == 0
    assert agent.interrupts == []
    (complete,) = _completes(emits, "short")
    assert complete["status"] == "complete"
    assert complete["text"] == "the real answer"
    assert "interrupt_reason" not in complete
    assert read_turn_marker(marker_home, "session-key") is None
    # Clients were told before the wait, while the turn was still running.
    assert ("gateway.restarting", {"drain_timeout_s": 5.0}) in emits.broadcasts
    restart_notice = [p for e, s, p in emits if e == "status.update" and s == "short"]
    assert restart_notice and restart_notice[0]["kind"] == "restart"
    assert emits.index(("status.update", "short", restart_notice[0])) < emits.index(
        ("message.complete", "short", complete))


# ── Drain timeout: interrupted with the shutdown reason, resumable ────


def test_long_turn_is_interrupted_for_shutdown_and_keeps_its_marker(emits, turn_env, marker_home):
    agent = _ModelWaitAgent()
    session = _register("long", _session(agent=agent))
    _start_turn("long", session)
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "and then this", "transport": object(),
                                    "turn_auth_user": ("oidc", "user-1")}

    outcome = asyncio.run(server.drain_turns_for_shutdown(timeout=0.2))

    _wait_settled(session)
    assert outcome["interrupted"] == 1
    assert agent.interrupts == [("Dashboard restarting", "dashboard shutdown")]
    (complete,) = _completes(emits, "long")
    assert complete["status"] == "interrupted"
    assert complete["interrupt_reason"] == "shutdown"
    assert complete["text"] == ""
    marker = read_turn_marker(marker_home, "session-key")
    assert marker is not None, "a shutdown-interrupted turn must stay resumable"
    assert marker["prompt"] == "do the long thing"
    assert marker["attempts"] == 1
    assert marker["interrupted_by"] == "shutdown"
    assert marker["queued"] == [{"text": "and then this", "turn_auth_user": ["oidc", "user-1"]}]


def test_next_resume_continues_the_turn_and_restores_its_queue(emits, turn_env, marker_home, monkeypatch):
    agent = _ModelWaitAgent()
    session = _register("long", _session(agent=agent))
    _start_turn("long", session)
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "and then this", "transport": object()}
    asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    _wait_settled(session)
    server._shutdown_draining.clear()  # the next process

    submitted: list = []
    monkeypatch.setattr(server, "_start_agent_build", lambda sid, s: None)
    monkeypatch.setattr(server, "_wait_agent", lambda s, rid, timeout=30.0: None)
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda sid, s: None)
    monkeypatch.setattr(server, "_run_prompt_submit",
                        lambda rid, sid, s, text, **kw: submitted.append((text, kw, s.get("queued_prompt"))))
    resumed = _session()

    descriptor = server._maybe_schedule_auto_continue("resumed", resumed, "session-key")
    deadline = time.monotonic() + 5
    while not submitted and time.monotonic() < deadline:
        time.sleep(0.01)

    assert descriptor["attempt"] == 2  # the shutdown counted as one attempt
    assert descriptor["interrupted_by"] == "shutdown"
    assert descriptor["queued_prompts"] == 1
    (text, kwargs, queued_at_dispatch), = submitted
    assert kwargs["display_kind"] == "auto_continue"
    assert "do the long thing" in text and "check the current state" in text
    assert queued_at_dispatch["text"] == "and then this"
    assert queued_at_dispatch["transport"] is None


def test_breaker_still_stops_a_turn_every_restart_interrupts(marker_home, monkeypatch):
    """Attempts are bumped per shutdown, so the default 2-attempt breaker gives up on a turn that
    every restart cuts off instead of resubmitting it forever."""
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    record_turn_start(marker_home, "session-key", "endless", attempts=1)
    mark_turn_shutdown_interrupted(marker_home, "session-key")

    assert server._maybe_schedule_auto_continue("sid", _session(), "session-key") is None
    assert read_turn_marker(marker_home, "session-key") is None


def test_freshness_counts_from_the_shutdown_not_the_turn_start(emits, marker_home, monkeypatch):
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    monkeypatch.setattr(server, "_start_agent_build", lambda sid, s: None)
    monkeypatch.setattr(server, "_wait_agent", lambda s, rid, timeout=30.0: None)
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda sid, s: None)
    submitted = threading.Event()
    monkeypatch.setattr(server, "_run_prompt_submit", lambda *a, **k: submitted.set())
    record_turn_start(marker_home, "session-key", "a forty minute task")
    path = marker_home / "desktop" / "interrupted_turns.json"
    import json
    entries = json.loads(path.read_text())
    entries["session-key"]["started_at"] = time.time() - 40 * 60
    path.write_text(json.dumps(entries))
    mark_turn_shutdown_interrupted(marker_home, "session-key")

    assert server._maybe_schedule_auto_continue("sid", _session(), "session-key") is not None
    # The kickoff thread must finish while this test's patches are still in place.
    assert submitted.wait(5)


# ── No sentinel as content ─────────────────────────────────────────────


def test_shutdown_closing_row_is_a_structured_marker_not_the_sentinel():
    from agent.message_sanitization import SHUTDOWN_CLOSING_API_CONTENT, close_interrupted_tool_sequence

    messages = [{"role": "assistant", "tool_calls": [{"id": "c1"}]},
                {"role": "tool", "tool_call_id": "c1", "content": "[interrupted: dashboard shutdown]"}]
    assert close_interrupted_tool_sequence(messages, SENTINEL, interrupt_reason="shutdown") is True
    closing = messages[-1]
    assert closing["role"] == "assistant"
    assert closing["content"] == ""
    assert SENTINEL not in str(closing)
    assert closing["display_kind"] == "hidden"
    assert closing["display_metadata"] == {"interrupt_reason": "shutdown"}
    assert closing["api_content"] == SHUTDOWN_CLOSING_API_CONTENT

    projected = server._history_to_messages([{"role": "user", "content": "go"}, *messages])
    assert all(SENTINEL not in str(m) for m in projected)
    assert all(m.get("role") != "assistant" or m.get("text") for m in projected)


def test_finalizer_closes_a_shutdown_interrupted_tail_with_the_marker():
    from agent.interrupt_compat import DASHBOARD_SHUTDOWN_TOOL_REASON
    from agent.turn_finalizer import _close_transcript_tail

    agent = types.SimpleNamespace(_tool_interrupt_reason=DASHBOARD_SHUTDOWN_TOOL_REASON)
    messages = [{"role": "tool", "tool_call_id": "c1", "content": "partial"}]
    _close_transcript_tail(agent, messages, SENTINEL, True, False)
    assert messages[-1]["display_metadata"] == {"interrupt_reason": "shutdown"}
    assert messages[-1]["content"] == ""


def test_user_stop_closing_row_is_unchanged():
    from agent.turn_finalizer import _close_transcript_tail

    agent = types.SimpleNamespace(_tool_interrupt_reason="explicit stop requested")
    messages = [{"role": "tool", "tool_call_id": "c1", "content": "partial"}]
    _close_transcript_tail(agent, messages, SENTINEL, True, False)
    assert messages[-1] == {"role": "assistant", "content": SENTINEL, "timestamp": messages[-1]["timestamp"]}


def test_real_hard_interrupt_is_read_back_as_a_shutdown():
    """The reason the gateway passes is the one the agent's real interrupt stores and the finalizer reads."""
    from agent.interrupt_compat import (
        DASHBOARD_SHUTDOWN_TOOL_REASON,
        request_hard_interrupt,
        shutdown_interrupt_reason,
    )
    from agent.interrupt_control import InterruptControlMixin

    class _Agent(InterruptControlMixin):
        quiet_mode = True
        _execution_thread_id = None

        def __init__(self):
            self._active_children_lock = threading.Lock()
            self._active_children = []

    agent = _Agent()
    assert request_hard_interrupt(agent, "Dashboard restarting", tool_reason=DASHBOARD_SHUTDOWN_TOOL_REASON)
    assert shutdown_interrupt_reason(agent) == "shutdown"
    agent.clear_interrupt()
    assert request_hard_interrupt(agent)
    assert shutdown_interrupt_reason(agent) is None


# ── User /stop is unchanged ────────────────────────────────────────────


def _patch_rpc_session(monkeypatch, session):
    monkeypatch.setattr(server, "_tts_stream_stop", lambda: None)
    monkeypatch.setattr(server, "_sess_nowait", lambda params, rid: (session, None))
    monkeypatch.setattr(server, "_sess", lambda params, rid: (session, None))


def test_user_stop_still_retires_the_marker(emits, turn_env, marker_home, monkeypatch):
    agent = _ModelWaitAgent()
    session = _register("stopped", _session(agent=agent))
    _start_turn("stopped", session)
    _patch_rpc_session(monkeypatch, session)

    response = server._methods["session.interrupt"]("stop", {"session_id": "stopped"})
    _wait_settled(session)

    assert response["result"]["status"] == "interrupted"
    assert agent.interrupts == [(None, None)]
    (complete,) = _completes(emits, "stopped")
    assert complete["status"] == "interrupted"
    assert "interrupt_reason" not in complete
    assert read_turn_marker(marker_home, "session-key") is None


def test_user_stop_during_a_shutdown_interrupt_wins(emits, turn_env, marker_home, monkeypatch):
    agent = _ModelWaitAgent()
    session = _register("both", _session(agent=agent))
    _start_turn("both", session)
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "queued", "transport": None}
    # The shutdown marks the session first; the stop arrives before the turn unwinds.
    assert server._shutdown_mark_session(session) is True
    assert read_turn_marker(marker_home, "session-key")["queued"]
    _patch_rpc_session(monkeypatch, session)

    server._methods["session.interrupt"]("stop", {"session_id": "both"})
    _wait_settled(session)

    assert read_turn_marker(marker_home, "session-key") is None
    (complete,) = _completes(emits, "both")
    assert "interrupt_reason" not in complete


# ── Admission while draining ───────────────────────────────────────────


def test_new_turns_are_refused_while_draining():
    session = _session()
    server._shutdown_draining.set()
    with server._session_turn_admission(session) as admitted:
        assert admitted is False
    err, _fields = server._lock_in_submit_turn("rid", "sid", session, "hello", {}, False, set(), None, None)
    assert err["error"]["code"] == 5035
    assert "restarting" in err["error"]["message"]
    assert session["running"] is False


def test_no_continuation_is_scheduled_while_draining(marker_home):
    record_turn_start(marker_home, "session-key", "left for the next process")
    server._shutdown_draining.set()
    assert server._maybe_schedule_auto_continue("sid", _session(), "session-key") is None
    assert read_turn_marker(marker_home, "session-key") is not None


def test_repeated_signal_cuts_the_drain_short(emits, turn_env, marker_home):
    agent = _ModelWaitAgent()
    session = _register("abort", _session(agent=agent))
    _start_turn("abort", session)

    started = time.monotonic()
    outcome = asyncio.run(server.drain_turns_for_shutdown(timeout=30.0, should_abort=lambda: True))
    _wait_settled(session)

    assert time.monotonic() - started < 10.0
    assert outcome["interrupted"] == 1
    assert read_turn_marker(marker_home, "session-key")["interrupted_by"] == "shutdown"


# ── Queues of sessions the drain left idle ─────────────────────────────


def test_idle_queue_is_journaled_and_drained_after_the_restart(emits, marker_home, monkeypatch):
    session = _register("idle", _session(queued_prompt={"text": "queued while draining", "transport": None}))
    asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    marker = read_turn_marker(marker_home, "session-key")
    assert marker["prompt"] == "" and marker["queued"] == [{"text": "queued while draining"}]
    assert marker["attempts"] == 0
    server._shutdown_draining.clear()

    drained: list = []
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    monkeypatch.setattr(server, "_start_agent_build", lambda sid, s: None)
    monkeypatch.setattr(server, "_wait_agent", lambda s, rid, timeout=30.0: None)
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda sid, s: None)
    monkeypatch.setattr(server, "_drain_queued_prompt",
                        lambda rid, sid, s: drained.append((sid, s.get("queued_prompt"))) or True)
    resumed = _session()

    descriptor = server._maybe_schedule_auto_continue("resumed", resumed, "session-key")
    deadline = time.monotonic() + 5
    while not drained and time.monotonic() < deadline:
        time.sleep(0.01)

    assert descriptor == {"attempt": 0, "interrupted_at": marker["interrupted_at"], "interrupted_by": "shutdown",
                          "queued_prompts": 1}
    assert drained == [("resumed", {"text": "queued while draining", "transport": None})]
    assert read_turn_marker(marker_home, "session-key") is None
    del session


def test_turn_that_finishes_after_the_shutdown_mark_keeps_only_its_queue(marker_home):
    record_turn_start(marker_home, "session-key", "finished anyway")
    mark_turn_shutdown_interrupted(marker_home, "session-key", [{"text": "next"}])

    retire_turn_marker(marker_home, "session-key")

    marker = read_turn_marker(marker_home, "session-key")
    assert marker["prompt"] == "" and marker["queued"] == [{"text": "next"}]


# ── The exit signal / atexit path uses the same semantics ──────────────


def test_exit_path_interrupts_with_the_shutdown_reason(emits, turn_env, marker_home):
    agent = _ModelWaitAgent()
    session = _register("exit", _session(agent=agent))
    _start_turn("exit", session)

    server._stop_turns_before_exit(budget_s=5.0)
    _wait_settled(session)

    assert agent.interrupts == [("Dashboard restarting", "dashboard shutdown")]
    marker = read_turn_marker(marker_home, "session-key")
    assert marker is not None and marker["attempts"] == 1


def test_drain_then_exit_path_counts_one_shutdown_once(emits, turn_env, marker_home, monkeypatch):
    """The drain interrupts, then the re-raised SIGTERM's handler runs ``_stop_turns_before_exit``:
    the marker must be bumped once, not twice (a second bump would trip the breaker on one restart)."""
    agent = _ModelWaitAgent()
    agent.hard_interrupt = lambda message=None, *, tool_reason=None: agent.interrupts.append((message, tool_reason))
    session = _register("twice", _session(agent=agent))
    _start_turn("twice", session)
    monkeypatch.setattr(server, "_SHUTDOWN_INTERRUPT_SETTLE_S", 0.2)  # this agent ignores the interrupt

    asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    server._stop_turns_before_exit(budget_s=0.1)

    assert read_turn_marker(marker_home, "session-key")["attempts"] == 1
    agent._interrupted.set()
    _wait_settled(session)


def test_handing_the_queue_back_never_drops_a_newer_turns_marker(marker_home):
    from tui_gateway.turn_marker import drop_journaled_queue

    mark_turn_shutdown_interrupted(marker_home, "session-key", [{"text": "queued"}])
    # A user turn in the new process replaced the queue-only entry with its own marker.
    record_turn_start(marker_home, "session-key", "typed after the restart")
    drop_journaled_queue(marker_home, "session-key")
    assert read_turn_marker(marker_home, "session-key")["prompt"] == "typed after the restart"

    record_turn_start(marker_home, "other", "x")
    mark_turn_shutdown_interrupted(marker_home, "idle-key", [{"text": "queued"}])
    drop_journaled_queue(marker_home, "idle-key")
    assert read_turn_marker(marker_home, "idle-key") is None
    assert read_turn_marker(marker_home, "other") is not None
