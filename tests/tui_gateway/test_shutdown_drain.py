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

    def __init__(self, *, honor_interrupt=True, interrupted_text=None):
        self.honor_interrupt = honor_interrupt
        self.interrupted_text = SENTINEL if interrupted_text is None else interrupted_text
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
            if self.release.is_set() and not self._interrupted.is_set():
                return {"final_response": "the real answer", "messages": []}
            if self._interrupted.is_set() and (self.honor_interrupt or self.release.is_set()):
                return {"final_response": self.interrupted_text, "interrupted": True, "messages": []}
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
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda sid, session: None)
    from tools.environments import base as env_base
    monkeypatch.setattr(env_base, "kill_live_foreground_processes", lambda now=False: None)


@pytest.fixture(autouse=True)
def _fresh_drain_state():
    """Every test starts in a dashboard-like process (restarts are resumable) that is not draining."""
    server._shutdown_draining.clear()
    server._resumable_shutdown.set()
    registered = dict(server._sessions)
    yield
    server._shutdown_draining.clear()
    server._resumable_shutdown.clear()
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
    assert session["agent"].entered.wait(5), f"fake turn never started: {session.get('running')} {session.get('_run_thread')}"


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
    assert marker["attempts"] == 0  # the continuation counts itself; the restart does not count twice
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

    assert descriptor["attempt"] == 1
    assert descriptor["interrupted_by"] == "shutdown"
    assert descriptor["queued_prompts"] == 1
    (text, kwargs, queued_at_dispatch), = submitted
    assert kwargs["display_kind"] == "auto_continue"
    assert "do the long thing" in text and "check the current state" in text
    assert queued_at_dispatch["text"] == "and then this"
    assert queued_at_dispatch["transport"] is None


def test_breaker_hands_the_queue_back_instead_of_dropping_it(emits, marker_home, monkeypatch):
    """The breaker still gives up on a turn every restart cuts off, but the prompts queued behind it go
    back in the session's queue (they run after the next turn) and the client is told."""
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    record_turn_start(marker_home, "session-key", "endless", attempts=2)
    mark_turn_shutdown_interrupted(marker_home, "session-key", [{"text": "then deploy"}], token="t")
    session = _session()

    assert server._maybe_schedule_auto_continue("sid", session, "session-key") is None

    assert read_turn_marker(marker_home, "session-key") is None
    assert session["queued_prompt"] == {"text": "then deploy", "transport": None}
    (notice,) = [p for e, s, p in emits if e == "status.update" and s == "sid"]
    assert notice["kind"] == "restart"
    assert "not resumed" in notice["text"] and "1 message(s)" in notice["text"]


def test_stale_marker_hands_the_queue_back(emits, marker_home, monkeypatch):
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    mark_turn_shutdown_interrupted(marker_home, "session-key", [{"text": "old follow-up"}], token="t")
    monkeypatch.setattr(server, "time", types.SimpleNamespace(time=lambda: time.time() + 3600,
                                                              monotonic=time.monotonic))
    session = _session()

    assert server._maybe_schedule_auto_continue("sid", session, "session-key") is None
    assert read_turn_marker(marker_home, "session-key") is None
    assert session["queued_prompt"]["text"] == "old follow-up"
    assert any(e == "status.update" and "queued before the restart" in p["text"] for e, _s, p in emits)


@pytest.mark.parametrize("extra, auto_continue", [({"source": "bot_room"}, True), ({}, False)])
def test_queue_behind_a_turn_auto_continue_never_owns_comes_back(emits, marker_home, monkeypatch, extra,
                                                               auto_continue):
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    record_turn_start(marker_home, "session-key", "room or mailbox turn", auto_continue=auto_continue)
    mark_turn_shutdown_interrupted(marker_home, "session-key", [{"text": "queued"}], token="t")
    session = _session(**extra)

    assert server._maybe_schedule_auto_continue("sid", session, "session-key") is None

    assert session["queued_prompt"]["text"] == "queued"
    marker = read_turn_marker(marker_home, "session-key")
    assert marker is not None and "queued" not in marker  # the owner's entry stays, the queue is handed back


def test_missing_attachments_are_dropped_with_a_notice(emits, marker_home, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    kept = tmp_path / "kept.png"
    kept.write_bytes(b"png")
    mark_turn_shutdown_interrupted(marker_home, "session-key", [
        {"text": "look", "image_paths": [str(kept), str(tmp_path / "gone.png")]},
        {"image_paths": [str(tmp_path / "also-gone.png")]},
    ], token="t")
    monkeypatch.setattr(server, "time", types.SimpleNamespace(time=lambda: time.time() + 3600,
                                                              monotonic=time.monotonic))
    session = _session()

    server._maybe_schedule_auto_continue("sid", session, "session-key")

    assert session["queued_prompt"] == {"text": "look", "image_paths": [str(kept)], "transport": None}
    assert not session.get("queued_prompts")  # the image-only envelope had nothing left
    assert any("2 attachment(s)" in p["text"] for e, _s, p in emits if e == "status.update")


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
    assert marker is not None and marker["attempts"] == 0 and marker["interrupted_by"] == "shutdown"


def test_drain_then_exit_path_marks_and_interrupts_once(emits, turn_env, marker_home, monkeypatch):
    """The drain interrupts, then the re-raised SIGTERM's handler runs ``_stop_turns_before_exit``: one
    mark (queue journaled once), one interrupt, one agent_loop_stopped hook."""
    from hermes_cli import plugins

    hooks: list = []
    monkeypatch.setattr(plugins, "invoke_hook", lambda name, **kw: hooks.append((name, kw.get("reason"))))
    agent = _ModelWaitAgent(honor_interrupt=False)  # still running when the exit path comes by
    session = _register("twice", _session(agent=agent))
    _start_turn("twice", session)
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "then deploy", "transport": None}
    monkeypatch.setattr(server, "_SHUTDOWN_INTERRUPT_SETTLE_S", 0.2)

    asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    server._stop_turns_before_exit(budget_s=0.1)

    marker = read_turn_marker(marker_home, "session-key")
    assert marker["attempts"] == 0
    assert marker["queued"] == [{"text": "then deploy"}]
    assert agent.interrupts == [("Dashboard restarting", "dashboard shutdown")]
    assert hooks == [("agent_loop_stopped", "shutdown")]
    agent.release.set()
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


# ── Review round: races, stop ordering, repeated restarts, replay ──────


def test_shutdown_landing_between_marker_write_and_flag_read_marks_once(emits, turn_env, marker_home, monkeypatch):
    """The turn writes its marker; the shutdown marks that entry; the turn then reads the flag and re-applies.
    Exactly one mark: attempts untouched, the queue journaled once (it used to come out doubled)."""
    agent = _ModelWaitAgent()
    session = _register("race", _session(agent=agent))
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "then deploy", "transport": None}
    real_record = server.record_turn_start

    def record_then_shutdown(home, key, prompt, **kwargs):
        real_record(home, key, prompt, **kwargs)
        assert server._shutdown_mark_session(session) is True

    monkeypatch.setattr(server, "record_turn_start", record_then_shutdown)
    _start_turn("race", session)
    agent._interrupted.set()
    _wait_settled(session)

    marker = read_turn_marker(marker_home, "session-key")
    assert marker["attempts"] == 0
    assert marker["queued"] == [{"text": "then deploy"}]


def test_shutdown_before_the_marker_write_is_reapplied_to_the_new_entry(emits, turn_env, marker_home,
                                                                        monkeypatch):
    agent = _ModelWaitAgent()
    session = _register("early", _session(agent=agent))
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "queued", "transport": None}
    real_record = server.record_turn_start
    marked: list = []

    def shutdown_then_record(home, key, prompt, **kwargs):
        if not marked:
            marked.append(server._shutdown_mark_session(session))
        real_record(home, key, prompt, **kwargs)  # replaces the entry the shutdown marked

    monkeypatch.setattr(server, "record_turn_start", shutdown_then_record)
    _start_turn("early", session)
    agent._interrupted.set()
    _wait_settled(session)

    marker = read_turn_marker(marker_home, "session-key")
    assert marked == [True]
    assert marker["prompt"] == "do the long thing" and marker["interrupted_by"] == "shutdown"
    assert marker["queued"] == [{"text": "queued"}]


def _stop_payload(emits, sid):
    (complete,) = _completes(emits, sid)
    return {k: v for k, v in complete.items() if k != "usage"}


@pytest.mark.parametrize("exit_path", ["drain", "signal"])
def test_user_stop_first_then_shutdown_leaves_the_stop_untouched(emits, turn_env, marker_home, monkeypatch,
                                                                 exit_path):
    """/stop lands first; the turn is still unwinding when the shutdown comes by. The shutdown must not
    mark it, re-interrupt it or change its reason: same frame, marker retired, as a plain /stop."""
    # Baseline: a plain /stop.
    baseline_agent = _ModelWaitAgent()
    baseline = _register("baseline", _session(agent=baseline_agent))
    _start_turn("baseline", baseline)
    _patch_rpc_session(monkeypatch, baseline)
    server._methods["session.interrupt"]("stop", {"session_id": "baseline"})
    _wait_settled(baseline)
    expected = _stop_payload(emits, "baseline")

    agent = _ModelWaitAgent(honor_interrupt=False)
    session = _register("stopped", _session(agent=agent))
    _start_turn("stopped", session)
    _patch_rpc_session(monkeypatch, session)
    server._methods["session.interrupt"]("stop", {"session_id": "stopped"})
    monkeypatch.setattr(server, "_SHUTDOWN_INTERRUPT_SETTLE_S", 0.2)
    if exit_path == "drain":
        asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    else:
        server._stop_turns_before_exit(budget_s=0.1)
    agent.release.set()
    _wait_settled(session)

    assert agent.interrupts == [(None, None)]
    assert "_shutdown_interrupt" not in session
    assert read_turn_marker(marker_home, "session-key") is None
    assert _stop_payload(emits, "stopped") == expected
    assert "interrupt_reason" not in expected


def test_second_restart_during_the_continuation_keeps_the_queue_and_the_breaker_holds(
        emits, turn_env, marker_home, monkeypatch):
    """Restart 1 interrupts a turn with a queue; the continuation runs (queue restored in memory) and
    restart 2 interrupts it too. The queue is journaled again -- once -- and the breaker still ends the
    loop: continuation attempts 1, 2, then the queue is handed back instead of a third continuation."""
    first = _ModelWaitAgent()
    session = _register("one", _session(agent=first))
    _start_turn("one", session)
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "then deploy", "transport": None}
    asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    _wait_settled(session)

    monkeypatch.setattr(server, "_wait_agent", lambda s, rid, timeout=30.0: None)
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda sid, s: None)

    def restart_and_resume(sid, expected_attempt):
        server._shutdown_draining.clear()  # the next process
        agent = _ModelWaitAgent()
        resumed = _register(sid, _session())
        monkeypatch.setattr(server, "_start_agent_build", lambda s_id, s: s.update(agent=agent))
        descriptor = server._maybe_schedule_auto_continue(sid, resumed, "session-key")
        assert descriptor["attempt"] == expected_attempt
        assert agent.entered.wait(5), "continuation never ran"
        assert resumed["queued_prompt"]["text"] == "then deploy"
        asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))  # the restart during the continuation
        _wait_settled(resumed)
        marker = read_turn_marker(marker_home, "session-key")
        assert marker["attempts"] == expected_attempt
        assert marker["queued"] == [{"text": "then deploy"}]
        return resumed

    restart_and_resume("two", 1)
    restart_and_resume("three", 2)

    server._shutdown_draining.clear()
    last = _session()
    assert server._maybe_schedule_auto_continue("four", last, "session-key") is None
    assert read_turn_marker(marker_home, "session-key") is None
    assert last["queued_prompt"]["text"] == "then deploy"


def test_shutdown_closing_row_round_trips_through_the_store_and_replay(tmp_path):
    """Persist a shutdown-interrupted tool block, read it back, canonicalize it for replay and build the
    request: the hidden row sends its neutral api_content, the call/result pairing is intact, and the
    side-effecting interrupted result is still rewritten to the UNKNOWN orphan notice."""
    import json

    from agent.message_sanitization import SHUTDOWN_CLOSING_API_CONTENT, close_interrupted_tool_sequence
    from agent.replay_cleanup import canonicalize_replay_history
    from agent.turn_context import build_api_messages
    from hermes_state import SessionDB

    call = {"id": "c1", "type": "function", "function": {"name": "terminal", "arguments": '{"command": "make deploy"}'}}
    interrupted = json.dumps({"output": "deploying...\n[Command interrupted]", "exit_code": 130})
    messages = [{"role": "user", "content": "deploy it"},
                {"role": "assistant", "content": "", "tool_calls": [call]},
                {"role": "tool", "tool_call_id": "c1", "content": interrupted}]
    close_interrupted_tool_sequence(messages, SENTINEL, interrupt_reason="shutdown")

    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session(session_id="s1", source="tui")
    for m in messages:
        db.append_message("s1", role=m["role"], content=m.get("content"), tool_calls=m.get("tool_calls"),
                          tool_call_id=m.get("tool_call_id"), api_content=m.get("api_content"),
                          display_kind=m.get("display_kind"), display_metadata=m.get("display_metadata"),
                          timestamp=9_000.0)
    stored = db.get_messages_as_conversation("s1")
    assert all(SENTINEL not in str(m) for m in stored)
    closing = stored[-1]
    assert closing["role"] == "assistant" and closing["display_kind"] == "hidden"
    assert closing["api_content"] == SHUTDOWN_CLOSING_API_CONTENT
    assert closing["display_metadata"] == {"interrupt_reason": "shutdown"}

    replay = canonicalize_replay_history(stored, now=10_000.0)
    tool_result = next(m for m in replay if m.get("role") == "tool")
    assert tool_result["effect_disposition"] == "unknown" and "UNKNOWN" in tool_result["content"]

    class _SendAgent:
        api_mode = "chat_completions"
        ephemeral_system_prompt = None
        _compression_warning = None
        _current_turn_timestamp = 10_000.0

        @staticmethod
        def _copy_reasoning_content_for_api(_source, _target):
            return None

        @staticmethod
        def _should_sanitize_tool_calls():
            return False

    history = [*stored, {"role": "user", "content": "[System note: Your previous turn was interrupted]"}]
    request, _ = build_api_messages(
        _SendAgent(), history, current_turn_user_idx=len(history) - 1, ext_prefetch_cache="",
        plugin_user_context="", moa_config=None, active_system_prompt="")
    roles = [m["role"] for m in request]
    assert roles == ["user", "assistant", "tool", "assistant", "user"]
    assert request[1]["tool_calls"][0]["id"] == request[2]["tool_call_id"] == "c1"
    assert "UNKNOWN" in request[2]["content"]
    assert request[3]["content"] == SHUTDOWN_CLOSING_API_CONTENT
    assert all("display_" not in key for m in request for key in m)


def test_non_resumable_exit_stops_turns_the_old_way(emits, turn_env, marker_home):
    """stdio TUI quit / Desktop quit: no resumable switch. The turn is stopped as before and its marker is
    retired, so quitting to stop a runaway turn does not bring it back."""
    server._resumable_shutdown.clear()
    agent = _ModelWaitAgent()
    session = _register("quit", _session(agent=agent))
    _start_turn("quit", session)
    with session["history_lock"]:
        session["queued_prompt"] = {"text": "queued", "transport": None}

    server._stop_turns_before_exit(budget_s=5.0)
    _wait_settled(session)

    assert agent.interrupts == [(None, None)]
    assert read_turn_marker(marker_home, "session-key") is None
    (complete,) = _completes(emits, "quit")
    assert "interrupt_reason" not in complete


def test_shutdown_keeps_text_the_model_already_streamed(emits, turn_env, marker_home):
    agent = _ModelWaitAgent(interrupted_text="Here is the first half of")
    session = _register("partial", _session(agent=agent))
    _start_turn("partial", session)

    asyncio.run(server.drain_turns_for_shutdown(timeout=0.0))
    _wait_settled(session)

    (complete,) = _completes(emits, "partial")
    assert complete["interrupt_reason"] == "shutdown"
    assert complete["text"] == "Here is the first half of"


def test_repeated_signal_also_cuts_the_settle_short(emits, turn_env, marker_home):
    agent = _ModelWaitAgent(honor_interrupt=False)
    session = _register("stuck", _session(agent=agent))
    _start_turn("stuck", session)

    started = time.monotonic()
    asyncio.run(server.drain_turns_for_shutdown(timeout=30.0, should_abort=lambda: True))
    assert time.monotonic() - started < 2.0  # neither the 30 s drain nor the 5 s settle
    agent.release.set()
    _wait_settled(session)


def test_a_new_turn_drops_the_previous_turns_shutdown_mark():
    session = _session(_shutdown_interrupt=True, _shutdown_queued=[{"text": "x"}], _shutdown_token="t",
                       _turn_cancel_requested=True)
    err, _fields = server._lock_in_submit_turn("rid", "sid", session, "hello", {}, False, set(), None, None)
    assert err is None
    assert not any(k in session for k in ("_shutdown_interrupt", "_shutdown_queued", "_shutdown_token"))
    assert session["_turn_cancel_requested"] is False
