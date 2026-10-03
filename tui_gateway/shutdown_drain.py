"""Restart-safe turns: drain running turns before the dashboard's WebSockets close, then interrupt the
rest with a shutdown reason that keeps them resumable.

``systemctl restart`` (SIGTERM) used to interrupt every running turn the way a user /stop does: the
interrupted turn concluded, retired its crash marker (``turn_marker.py``), and the auto-continue that
``session.resume`` runs for a marker never fired. The closing row carried the "Operation interrupted"
sentinel as if the assistant had said it. The order is now (driven from ``hermes_cli.web_server``'s
serve coroutine, between uvicorn's main loop and its ``shutdown()``, so clients are still attached):

1. :func:`drain_turns_for_shutdown` raises the drain fence -- ``_session_turn_admission`` refuses every
   new turn (prompt.submit, queued drains, goal continuations, notification and bot-delivery turns) and
   ``_maybe_schedule_auto_continue`` schedules nothing -- and tells live clients the gateway is
   restarting (``gateway.restarting`` to every client, ``status.update`` kind ``restart`` to each
   session with a running turn).
2. It waits up to ``dashboard.shutdown_drain_timeout`` (default 20 s) for running turns to finish on
   their own, so clients receive the real answer. A second Ctrl+C (uvicorn's ``force_exit``) or a
   repeated signal ends the wait early.
3. Turns still running are interrupted by :func:`_shutdown_interrupt_turns` with reason "Dashboard
   restarting" / ``tool_reason="dashboard shutdown"``. Such a turn keeps its marker (``attempts``
   unchanged, ``interrupted_by: "shutdown"``), the prompts queued behind it are journaled next to it, and
   its closing row is a hidden structured marker instead of the sentinel. Up to
   :data:`_SHUTDOWN_INTERRUPT_SETTLE_S` is given for those turns to persist and send ``message.complete``
   while the socket is still open (a repeated signal cuts that short too).

A user /stop wins in both orders: a turn already stopped is left alone, and a stop landing after the
shutdown marked the turn clears the mark (``session.interrupt``).

Resumable shutdowns are for restarts only: the dashboard / ``serve`` backend turns them on at boot
(:func:`enable_resumable_shutdown`), except a Desktop-owned backend. Everywhere else -- the stdio TUI,
a Desktop quitting its backend -- the exit paths stop running turns the old way and retire their
markers, so quitting to stop a runaway turn does not bring it back on the next resume. The signal and
atexit paths (``_stop_turns_before_exit``) follow the same switch as the drain.

The process retirement fence (``hermes_cli.backend_retirement``) is not reused for step 1: it closes
admission for EVERY RPC (history reads, ``session.interrupt``) and only commits once the process is
already idle, while a drain must keep serving the clients it is draining for. Turn threads are not
asyncio tasks, so the waits here poll on the event loop instead of joining threads on it.
"""

from __future__ import annotations

import json
import os
import threading
import uuid

from .method_ctx import bind_module

_SHUTDOWN_DRAIN_TIMEOUT_DEFAULT_S = 20.0
# Interrupted turns get this long to unwind (closing row persisted, message.complete sent) before
# uvicorn closes the sockets. A foreground command still alive halfway through ignored the interrupt's
# SIGTERM and is SIGKILLed then, as in ``_stop_turns_before_exit``.
_SHUTDOWN_INTERRUPT_SETTLE_S = 5.0
_SHUTDOWN_POLL_S = 0.1
SHUTDOWN_INTERRUPT_MESSAGE = "Dashboard restarting"
# English on the wire; clients localise from ``kind``.
SHUTDOWN_NOTICE_TEXT = "The gateway is restarting; this turn continues after the restart."
# Process-wide and one-way: nothing reopens admission in a process that is on its way out.
_shutdown_draining = threading.Event()
# Set once at boot by a backend whose stops are restarts (see the module docstring).
_resumable_shutdown = threading.Event()
# The JSON-safe part of a queued-prompt envelope (``_enqueue_prompt``). The transport is a live socket
# and is re-pinned to whoever resumes the session.
_JOURNALED_QUEUE_KEYS = ("text", "image_paths", "turn_author", "turn_auth_user", "row_metadata", "origin",
                         "contributors")


def enable_resumable_shutdown() -> None:
    """This process's SIGTERM/SIGINT is a restart: interrupted turns resume afterwards."""
    _resumable_shutdown.set()


def _shutdown_drain_timeout() -> float:
    """``dashboard.shutdown_drain_timeout`` in seconds (default 20; 0 = interrupt at once). Raw loader:
    a missing key, a non-number or a negative value all mean the default / 0."""
    try:
        dashboard = (_load_cfg() or {}).get("dashboard")
        raw = dashboard.get("shutdown_drain_timeout") if isinstance(dashboard, dict) else None
        return _SHUTDOWN_DRAIN_TIMEOUT_DEFAULT_S if raw is None else max(0.0, float(raw))
    except (TypeError, ValueError):
        return _SHUTDOWN_DRAIN_TIMEOUT_DEFAULT_S
    except Exception:
        logger.debug("shutdown drain timeout unreadable; using the default", exc_info=True)
        return _SHUTDOWN_DRAIN_TIMEOUT_DEFAULT_S


def _shutdown_drain_active() -> bool:
    return _shutdown_draining.is_set()


def _running_turn_sessions() -> list[tuple[str, dict]]:
    with _sessions_lock:
        return [(sid, s) for sid, s in _sessions.items() if isinstance(s, dict) and s.get("running")]


def _journal_queue_envelope(envelope) -> dict | None:
    """``envelope`` as it is written next to the marker, or None when it cannot be (logged)."""
    if not isinstance(envelope, dict):
        return None
    out = {key: envelope[key] for key in _JOURNALED_QUEUE_KEYS if envelope.get(key) is not None}
    if isinstance(out.get("turn_auth_user"), tuple):
        out["turn_auth_user"] = list(out["turn_auth_user"])
    if out.get("text") in (None, "") and not out.get("image_paths"):
        return None
    try:
        json.dumps(out)
    except (TypeError, ValueError):
        logger.warning("queued prompt could not be kept across the restart (not serializable); dropped")
        return None
    return out


def _restore_journaled_queue(entries) -> tuple[list[dict], int]:
    """``(envelopes, dropped_attachments)``: the inverse of :func:`_journal_queue_envelope`, with no
    transport pin. Attachments are often temp files a restart removed: a missing one is dropped (and
    counted, so the caller can say so), and an envelope left with neither text nor attachments goes."""
    envelopes, dropped = [], 0
    for entry in entries or ():
        if not isinstance(entry, dict):
            continue
        envelope = {key: entry[key] for key in _JOURNALED_QUEUE_KEYS if key in entry}
        envelope["transport"] = None
        if isinstance(envelope.get("turn_auth_user"), list):
            envelope["turn_auth_user"] = tuple(envelope["turn_auth_user"])
        if isinstance(paths := envelope.get("image_paths"), list):
            kept = [p for p in paths if isinstance(p, str) and os.path.exists(p)]
            dropped += len(paths) - len(kept)
            if kept:
                envelope["image_paths"] = kept
            else:
                envelope.pop("image_paths")
        if envelope.get("text") in (None, "") and not envelope.get("image_paths"):
            continue
        envelopes.append(envelope)
    return envelopes, dropped


def _take_session_queue(session: dict) -> list[dict]:
    """Journal-ready copies of the session's queued prompts. Caller holds ``history_lock``; the
    in-memory queue is left alone (the interrupt that follows clears it, as a /stop would)."""
    entries = [session.get("queued_prompt"), *(session.get("queued_prompts") or [])]
    return [j for e in entries if e and (j := _journal_queue_envelope(e)) is not None]


def _shutdown_mark_session(session: dict) -> bool:
    """Flag ``session``'s running turn as shutdown-interrupted and write that onto its marker (queue
    journaled). Once per turn: the drain and the exit signal path may both get here. A turn a person
    already stopped (``_turn_cancel_requested`` without a shutdown mark) is theirs: it is left alone.
    Returns whether this call did the marking -- the caller interrupts only then."""
    with session["history_lock"]:
        if session.get("_shutdown_interrupt") or session.get("_turn_cancel_requested"):
            return False
        token = uuid.uuid4().hex
        session["_shutdown_interrupt"], session["_shutdown_token"] = True, token
        queued = _take_session_queue(session)
        # Kept for _record_turn_marker: a turn that had not written its marker yet overwrites the entry
        # when it does, and re-applies this then (the token makes a second application a no-op).
        session["_shutdown_queued"] = queued
        key = str(session.get("_active_turn_marker_key") or session.get("session_key") or "")
    mark_turn_shutdown_interrupted(_session_home(session), key, queued, token=token)
    return True


def _shutdown_journal_idle_queue(session: dict) -> None:
    """An idle session still holding a queue (its turn ended during the drain, and the drain refused
    the follow-up) keeps that queue as a queue-only marker entry."""
    with session["history_lock"]:
        if session.get("running") or session.get("_shutdown_interrupt"):
            return
        queued = _take_session_queue(session)
        if not queued:
            return
        token = uuid.uuid4().hex
        session["_shutdown_interrupt"], session["_shutdown_token"] = True, token
        key = str(session.get("session_key") or "")
    mark_turn_shutdown_interrupted(_session_home(session), key, queued, token=token)


def _stop_session_turn_for_exit(sid: str, session: dict) -> None:
    """A non-resumable exit (stdio TUI quit, Desktop quitting its backend): stop the turn as a /stop
    would and retire its marker now, so the next resume does not bring it back."""
    _interrupt_session_turn(sid, session)
    with session["history_lock"]:
        active_marker_key = str(session.pop("_active_turn_marker_key", "") or "")
    _retire_turn_marker(session, active_marker_key, keep_queued=False)


def _shutdown_interrupt_turns(resumable: bool | None = None) -> list:
    """Interrupt every running turn on the way out; returns the turn threads to settle. ``resumable``
    (default: :func:`enable_resumable_shutdown` was called) keeps markers and journals queues, idle
    sessions' queues included; otherwise turns stop the old way. Blocking (an interrupt may wait out a
    compression commit), so the async drain runs it off the event loop. It does not raise the drain
    fence itself: the exit paths that also call it run in a process that is already dying."""
    resumable = _resumable_shutdown.is_set() if resumable is None else resumable
    with _sessions_lock:
        sessions = [(sid, s) for sid, s in _sessions.items() if isinstance(s, dict)]
    threads = []
    for sid, session in sessions:
        if not session.get("running"):
            if resumable:
                with contextlib.suppress(Exception):
                    _shutdown_journal_idle_queue(session)
            continue
        if resumable:
            first = False
            with contextlib.suppress(Exception):
                first = _shutdown_mark_session(session)
            if first:  # once per turn: the agent_loop_stopped hook and the agent's reason are set once
                with contextlib.suppress(Exception):
                    _interrupt_session_turn(sid, session, reason="shutdown")
        else:
            with contextlib.suppress(Exception):
                _stop_session_turn_for_exit(sid, session)
        if (t := session.get("_run_thread")) is not None and t is not threading.current_thread():
            threads.append(t)
    return threads


def _announce_shutdown_drain(timeout: float) -> None:
    """Tell every connected client the gateway is going down, and each running turn's clients that the
    turn will continue afterwards. Best-effort: a dead socket must not stall the drain."""
    with contextlib.suppress(Exception):
        _broadcast_global_event("gateway.restarting", {"drain_timeout_s": float(timeout)})
    for sid, _session in _running_turn_sessions():
        with contextlib.suppress(Exception):
            _emit("status.update", sid, {"kind": "restart", "text": SHUTDOWN_NOTICE_TEXT})


def _poll_abort(should_abort) -> bool:
    if should_abort is None:
        return False
    try:
        return bool(should_abort())
    except Exception:
        return False


async def _settle_turn_threads(threads: list, budget: float, should_abort=None) -> None:
    import asyncio  # local: bound bodies resolve globals in server.py, which has no asyncio
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, budget)
    killed = False
    while any(t.is_alive() for t in threads) and loop.time() < deadline and not _poll_abort(should_abort):
        if not killed and loop.time() >= deadline - budget / 2:
            killed = True
            from tools.environments.base import kill_live_foreground_processes
            with contextlib.suppress(Exception):
                await asyncio.to_thread(kill_live_foreground_processes, now=True)
        await asyncio.sleep(_SHUTDOWN_POLL_S)


async def drain_turns_for_shutdown(timeout: float | None = None, should_abort=None,
                                   resumable: bool | None = None) -> dict:
    """Steps 1-3 of the module docstring, on the serving event loop, BEFORE uvicorn closes the sockets.
    ``timeout`` overrides ``dashboard.shutdown_drain_timeout``; ``should_abort()`` is polled to cut the
    wait and the settle short; ``resumable`` overrides the process switch. Returns
    ``{"drained": n, "interrupted": n, "waited_s": s}`` for the log line."""
    import asyncio  # local: bound bodies resolve globals in server.py, which has no asyncio
    loop = asyncio.get_running_loop()
    timeout = _shutdown_drain_timeout() if timeout is None else max(0.0, float(timeout))
    _shutdown_draining.set()
    started = loop.time()
    running_at_start = len(_running_turn_sessions())
    if running_at_start:
        logger.info("Dashboard shutting down: draining %d running turn(s) for up to %.0fs",
                    running_at_start, timeout)
    await asyncio.to_thread(_announce_shutdown_drain, timeout)
    deadline = started + timeout
    while _running_turn_sessions() and loop.time() < deadline:
        if _poll_abort(should_abort):
            logger.info("Shutdown drain cut short by a repeated signal")
            break
        await asyncio.sleep(_SHUTDOWN_POLL_S)
    still_running = len(_running_turn_sessions())
    threads = await asyncio.to_thread(_shutdown_interrupt_turns, resumable)
    if threads:
        await _settle_turn_threads(threads, _SHUTDOWN_INTERRUPT_SETTLE_S, should_abort)
    waited = loop.time() - started
    if running_at_start or still_running:
        logger.info("Shutdown drain finished in %.1fs: %d turn(s) finished, %d interrupted", waited,
                    max(0, running_at_start - still_running), still_running)
    return {"drained": max(0, running_at_start - still_running), "interrupted": still_running,
            "waited_s": waited}


def register(server) -> None:
    bind_module(globals(), server)
