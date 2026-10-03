"""Durable interrupted-turn markers for the desktop/TUI auto-continue path. A running turn's progress
lives only in process memory (the agent flushes to SQLite at turn end), so a marker is written at turn
start and cleared on any conclusion — only a process death leaves one behind, and ``session.resume``
reads it (``_maybe_schedule_auto_continue``). Stored per ``HERMES_HOME`` (profile-aware); writes prune
entries older than ``_MAX_AGE_SECS`` and cap the count so a crash streak can't grow the file. Every
function is best-effort — marker bookkeeping must never break a turn — so I/O errors degrade to "no
marker" instead of raising.

A shutdown (``tui_gateway.shutdown_drain``) is the one deliberate exception to "cleared on any
conclusion": a turn the process interrupts on its way out keeps its marker, with ``attempts`` bumped
and ``interrupted_by: "shutdown"``, so the next ``session.resume`` continues it. Prompts queued behind
that turn ride along as ``queued`` (the envelope minus its transport), and a session that was idle with
a queue at exit gets a queue-only entry (``prompt`` empty). ``retire_turn_marker`` keeps such a queue
when the turn concludes after all; ``clear_turn_marker`` drops everything."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any
from utils import atomic_json_write

logger = logging.getLogger(__name__)

_MAX_AGE_SECS = 24 * 3600
_MAX_ENTRIES = 32
# Enough to re-submit any realistic prompt; guards against a multi-megabyte paste being journaled.
_MAX_PROMPT_CHARS = 64_000

_lock = threading.Lock()


def _marker_path(home: Path | str) -> Path:
    return Path(home) / "desktop" / "interrupted_turns.json"


def _started_at(entry: dict) -> float:
    return float(entry.get("started_at") or 0)


def _load(path: Path) -> dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        logger.debug("unreadable turn-marker file %s; starting fresh", path, exc_info=True)
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}


def _prune(entries: dict[str, dict], now: float) -> dict[str, dict]:
    fresh = {k: e for k, e in entries.items() if now - _started_at(e) <= _MAX_AGE_SECS}
    if len(fresh) <= _MAX_ENTRIES:
        return fresh
    return dict(sorted(fresh.items(), key=lambda item: _started_at(item[1]), reverse=True)[:_MAX_ENTRIES])


def _store(path: Path, entries: dict[str, dict]) -> None:
    if not entries:
        path.unlink(missing_ok=True)
        return
    atomic_json_write(path, entries, indent=None, mode=0o600)


def _update(home: Path | str, session_key: str, mutate, what: str) -> None:
    """Load → ``mutate(entries)`` → store under the lock; ``mutate`` returns None to skip the write."""
    try:
        with _lock:
            path = _marker_path(home)
            entries = mutate(_load(path))
            if entries is not None:
                _store(path, entries)
    except Exception:
        logger.debug("failed to %s turn marker for %s", what, session_key, exc_info=True)


def record_turn_start(home: Path | str, session_key: str, prompt: str, *, attempts: int = 0,
                      auto_continue: bool = True, notification_category: str | None = None) -> None:
    """Persist the marker for a turn that is about to run. ``attempts`` = how many auto-continues led to
    this run (0 for a user-initiated turn); the crash-loop breaker reads it back on the next resume."""
    if not session_key or not prompt:
        return
    now = time.time()
    entry = {"attempts": max(0, int(attempts)), "prompt": prompt[:_MAX_PROMPT_CHARS], "started_at": now,
             "auto_continue": bool(auto_continue)}
    if notification_category == "diagnostic":
        entry["notification_category"] = notification_category
    _update(home, session_key, lambda entries: {**_prune(entries, now), session_key: entry}, "record")


def clear_turn_marker(home: Path | str, session_key: str) -> None:
    """Remove the marker once its turn concluded (any outcome the client saw)."""
    if session_key:
        _update(home, session_key, lambda e: {k: v for k, v in e.items() if k != session_key} if session_key in e else None, "clear")


def _queued_envelopes(entry: dict) -> list[dict]:
    queued = entry.get("queued")
    return [e for e in queued if isinstance(e, dict)] if isinstance(queued, list) else []


def read_turn_marker(home: Path | str, session_key: str) -> dict[str, Any] | None:
    """The marker left by a turn that never concluded (or a shutdown's queue-only entry), or None."""
    if not session_key:
        return None
    try:
        with _lock:
            entry = _load(_marker_path(home)).get(session_key)
        prompt = str(entry.get("prompt") or "") if isinstance(entry, dict) else ""
        queued = _queued_envelopes(entry) if isinstance(entry, dict) else []
        if not prompt.strip() and not queued:
            return None
        return {"attempts": max(0, int(entry.get("attempts") or 0)), "prompt": prompt, "started_at": _started_at(entry),
                "auto_continue": bool(entry.get("auto_continue", True)),
                **({"notification_category": "diagnostic"}
                   if entry.get("notification_category") == "diagnostic" else {}),
                **({"interrupted_by": "shutdown", "interrupted_at": float(entry.get("interrupted_at") or 0)
                    or _started_at(entry)} if entry.get("interrupted_by") == "shutdown" else {}),
                **({"queued": queued} if queued else {})}
    except Exception:
        return None


def retire_turn_marker(home: Path | str, session_key: str) -> None:
    """A turn concluded: drop its marker, but keep prompts a shutdown queued behind it (they never ran)
    as a queue-only entry. Identical to :func:`clear_turn_marker` for every entry no shutdown touched."""
    if not session_key:
        return

    def mutate(entries: dict[str, dict]) -> dict[str, dict] | None:
        entry = entries.get(session_key)
        if entry is None:
            return None
        rest = {k: v for k, v in entries.items() if k != session_key}
        if queued := _queued_envelopes(entry):
            at = float(entry.get("interrupted_at") or 0) or time.time()
            rest[session_key] = {"attempts": 0, "prompt": "", "started_at": at, "interrupted_at": at,
                                 "auto_continue": bool(entry.get("auto_continue", True)),
                                 "interrupted_by": "shutdown", "queued": queued}
        return rest

    _update(home, session_key, mutate, "retire")


def drop_journaled_queue(home: Path | str, session_key: str) -> None:
    """The journaled queue was handed back to the live session: remove it from the entry, and remove a
    queue-only entry altogether. A turn's own marker (one that replaced the entry meanwhile) is kept."""
    if not session_key:
        return

    def mutate(entries: dict[str, dict]) -> dict[str, dict] | None:
        entry = entries.get(session_key)
        if entry is None or "queued" not in entry:
            return None
        rest = {k: v for k, v in entries.items() if k != session_key}
        if str(entry.get("prompt") or "").strip():
            rest[session_key] = {k: v for k, v in entry.items() if k != "queued"}
        return rest

    _update(home, session_key, mutate, "drop the queue of")


def mark_turn_shutdown_interrupted(home: Path | str, session_key: str, queued: list[dict] | None = None, *,
                                   bump_attempts: bool = True) -> None:
    """The process is stopping this session's turn on its way out: keep the marker so the next resume
    continues it, count the interruption against the crash-loop breaker (``bump_attempts``), and journal
    ``queued`` -- JSON-safe envelopes of the prompts waiting behind it. With no marker (an idle session,
    or a turn that had not written one yet) and a non-empty queue, a queue-only entry is written."""
    if not session_key:
        return
    queued = [e for e in (queued or []) if isinstance(e, dict)]
    now = time.time()

    def mutate(entries: dict[str, dict]) -> dict[str, dict] | None:
        entry = entries.get(session_key)
        if entry is None:
            if not queued:
                return None
            entry = {"attempts": 0, "prompt": "", "started_at": now, "auto_continue": True}
        else:
            entry = dict(entry)
            if bump_attempts and str(entry.get("prompt") or "").strip():
                entry["attempts"] = max(0, int(entry.get("attempts") or 0)) + 1
        # Freshness counts from the interruption, not from the turn's start: a turn that ran for
        # twenty minutes before a restart is still fresh the moment the restart ends.
        entry["interrupted_by"], entry["interrupted_at"] = "shutdown", now
        if queued:
            entry["queued"] = [*_queued_envelopes(entry), *queued]
        return {**_prune(entries, now), session_key: entry}

    _update(home, session_key, mutate, "mark shutdown on")
