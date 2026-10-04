"""The approved text of a reviewed draft, kept by the gateway (plan ``request-types-v2`` D7).

``review.draft`` settles with the FINAL text (edited or not). :func:`put` stores it under a ``draft_id``
(``drf-<12 hex>``) for the conversation; a later ``confirm_action(draft_id=...)`` builds its detail FROM HERE,
never from what the agent says it will send, so a confirmation commits to the text the person approved.

Memory only, never written to disk or logged: a conversation key maps to at most :data:`MAX_PER_KEY` entries (the
oldest goes first), each valid for :data:`TTL_SECONDS`; :func:`clear` drops a conversation's entries when its
session ends. The text is the person's and may be private: nothing here logs it, and a lookup by another
conversation's key finds nothing. Time is passed in (monotonic seconds) so a test moves the clock by hand.
"""

from __future__ import annotations

import collections
import hashlib
import threading
import time
import uuid
from dataclasses import dataclass

TTL_SECONDS = 3_600.0
MAX_PER_KEY = 20
#: Conversations the register keeps entries for at once; beyond it the one idle longest is dropped (a gateway that
#: hosts many conversations must not grow without bound).
MAX_KEYS = 256


@dataclass(frozen=True)
class Draft:
    draft_id: str
    text: str
    sha256: str
    edited: bool
    created_at: float


_lock = threading.Lock()
# conversation key → drafts, oldest first.
_drafts: "collections.OrderedDict[str, list[Draft]]" = collections.OrderedDict()


def _live(entries: list[Draft], now: float) -> list[Draft]:
    return [d for d in entries if now - d.created_at < TTL_SECONDS]


def put(key: str, text: str, *, edited: bool = False, now: float | None = None) -> Draft:
    """Store *text* for conversation *key*; the entry (with its ``draft_id`` and ``sha256``) comes back."""
    now = time.monotonic() if now is None else now
    entry = Draft(f"drf-{uuid.uuid4().hex[:12]}", text, hashlib.sha256(text.encode("utf-8")).hexdigest(),
                  bool(edited), now)
    with _lock:
        entries = _live(_drafts.pop(key, []), now)
        entries.append(entry)
        del entries[:-MAX_PER_KEY]
        _drafts[key] = entries
        while len(_drafts) > MAX_KEYS:
            _drafts.popitem(last=False)
    return entry


def get(key: str, draft_id: str, *, now: float | None = None) -> Draft | None:
    """The live draft *draft_id* of conversation *key*, or None (unknown, expired, or another conversation's)."""
    now = time.monotonic() if now is None else now
    with _lock:
        entries = _live(_drafts.get(key, []), now)
        if entries:
            _drafts[key] = entries
        else:
            _drafts.pop(key, None)
        return next((d for d in entries if d.draft_id == draft_id), None)


def clear(key: str | None) -> None:
    """Forget every draft of conversation *key* (its session ended)."""
    if key:
        with _lock:
            _drafts.pop(str(key), None)


def count(key: str, *, now: float | None = None) -> int:
    now = time.monotonic() if now is None else now
    with _lock:
        return len(_live(_drafts.get(key, []), now))


def reset_for_tests() -> None:
    with _lock:
        _drafts.clear()
