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
   restarting" / ``tool_reason="dashboard shutdown"``. Such a turn keeps its marker (attempts bumped,
   ``interrupted_by: "shutdown"``), the prompts queued behind it are journaled next to it, and its
   closing row is a hidden structured marker instead of the sentinel. Up to
   :data:`_SHUTDOWN_INTERRUPT_SETTLE_S` is given for those turns to persist and send ``message.complete``
   while the socket is still open.

The signal / atexit exit paths (``_stop_turns_before_exit``) interrupt with the same shutdown semantics,
so a SIGTERM outside uvicorn's serve window, or a stdio TUI exit, leaves the same resumable state.

The process retirement fence (``hermes_cli.backend_retirement``) is not reused for step 1: it closes
admission for EVERY RPC (history reads, ``session.interrupt``) and only commits once the process is
already idle, while a drain must keep serving the clients it is draining for. Turn threads are not
asyncio tasks, so the waits here poll on the event loop instead of joining threads on it.
"""

from __future__ import annotations

import json
import threading

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
# The JSON-safe part of a queued-prompt envelope (``_enqueue_prompt``). The transport is a live socket
# and is re-pinned to whoever resumes the session.
_JOURNALED_QUEUE_KEYS = ("text", "image_paths", "turn_author", "turn_auth_user", "row_metadata", "origin",
                         "contributors")


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


def _restore_queue_envelope(entry: dict) -> dict:
    """The inverse of :func:`_journal_queue_envelope`: a queue envelope with no transport pin."""
    envelope = {key: entry[key] for key in _JOURNALED_QUEUE_KEYS if key in entry}
    envelope["transport"] = None
    if isinstance(envelope.get("turn_auth_user"), list):
        envelope["turn_auth_user"] = tuple(envelope["turn_auth_user"])
    return envelope


def _take_session_queue(session: dict) -> list[dict]:
    """Journal-ready copies of the session's queued prompts. Caller holds ``history_lock``; the
    in-memory queue is left alone (the interrupt that follows clears it, as a /stop would)."""
    entries = [session.get("queued_prompt"), *(session.get("queued_prompts") or [])]
    return [j for e in entries if e and (j := _journal_queue_envelope(e)) is not None]


def _shutdown_mark_session(session: dict) -> bool:
    """Flag ``session``'s running turn as shutdown-interrupted and write that onto its marker (attempts
    bumped, queue journaled). Idempotent: the drain and the exit signal path may both get here, and the
    breaker must count one shutdown once. Returns whether this call did the marking."""
    with session["history_lock"]:
        if session.get("_shutdown_interrupt"):
            return False
        session["_shutdown_interrupt"] = True
        queued = _take_session_queue(session)
        # Kept for _record_turn_marker: a turn that had not written its marker yet overwrites the entry
        # when it does, and re-applies this then.
        session["_shutdown_queued"] = queued
        key = str(session.get("_active_turn_marker_key") or session.get("session_key") or "")
    mark_turn_shutdown_interrupted(_session_home(session), key, queued)
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
        session["_shutdown_interrupt"] = True
        key = str(session.get("session_key") or "")
    mark_turn_shutdown_interrupted(_session_home(session), key, queued, bump_attempts=False)


def _shutdown_interrupt_turns() -> list:
    """Interrupt every running turn for shutdown (marker kept, queue journaled) and journal the queues of
    idle sessions; returns the turn threads to settle. Blocking (an interrupt may wait out a compression
    commit), so the async drain runs it off the event loop. It does not raise the drain fence itself: the exit
    paths that also call it (``_stop_turns_before_exit``) run in a process that is already dying."""
    with _sessions_lock:
        sessions = [(sid, s) for sid, s in _sessions.items() if isinstance(s, dict)]
    threads = []
    for sid, session in sessions:
        if not session.get("running"):
            with contextlib.suppress(Exception):
                _shutdown_journal_idle_queue(session)
            continue
        with contextlib.suppress(Exception):
            _shutdown_mark_session(session)
        with contextlib.suppress(Exception):
            _interrupt_session_turn(sid, session, reason="shutdown")
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


async def _settle_turn_threads(threads: list, budget: float) -> None:
    import asyncio  # local: bound bodies resolve globals in server.py, which has no asyncio
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, budget)
    killed = False
    while any(t.is_alive() for t in threads) and loop.time() < deadline:
        if not killed and loop.time() >= deadline - budget / 2:
            killed = True
            from tools.environments.base import kill_live_foreground_processes
            with contextlib.suppress(Exception):
                await asyncio.to_thread(kill_live_foreground_processes, now=True)
        await asyncio.sleep(_SHUTDOWN_POLL_S)


async def drain_turns_for_shutdown(timeout: float | None = None, should_abort=None) -> dict:
    """Steps 1-3 of the module docstring, on the serving event loop, BEFORE uvicorn closes the sockets.
    ``timeout`` overrides ``dashboard.shutdown_drain_timeout``; ``should_abort()`` is polled to cut the
    wait short. Returns ``{"drained": n, "interrupted": n, "waited_s": s}`` for the log line."""
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
        if should_abort is not None:
            with contextlib.suppress(Exception):
                if should_abort():
                    logger.info("Shutdown drain cut short by a repeated signal")
                    break
        await asyncio.sleep(_SHUTDOWN_POLL_S)
    still_running = len(_running_turn_sessions())
    threads = await asyncio.to_thread(_shutdown_interrupt_turns)
    if threads:
        await _settle_turn_threads(threads, _SHUTDOWN_INTERRUPT_SETTLE_S)
    waited = loop.time() - started
    if running_at_start or still_running:
        logger.info("Shutdown drain finished in %.1fs: %d turn(s) finished, %d interrupted to resume after "
                    "the restart", waited, max(0, running_at_start - still_running), still_running)
    return {"drained": max(0, running_at_start - still_running), "interrupted": still_running,
            "waited_s": waited}


def register(server) -> None:
    bind_module(globals(), server)
