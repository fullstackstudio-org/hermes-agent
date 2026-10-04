"""Per-key rate limiting for the requests the gateway asks of a person.

A :class:`Limiter` keeps, per key (a conversation, or a conversation under a prefix of its own such as
``forced:<conversation>``), how many requests are open and when the last ones were sent. Two limits:

- ``max_pending`` requests open at the same time (:data:`ALREADY_PENDING` when taken);
- ``max_per_window`` requests sent within ``window_seconds`` (:data:`RATE_LIMITED` when used up).

Keys are independent: one key's slots and history never touch another's. Time is passed in (monotonic
seconds), never read here, so a test drives the window with a plain number.

A request that was reserved but never reached anybody is released with ``sent_at=None`` and does not count
against the window. The limiter owns one lock that guards only its own state and calls nothing while holding
it, so it can be used under or beside any other lock without an ordering hazard.
"""

from __future__ import annotations

import collections
import threading

ALREADY_PENDING = "already_pending"
RATE_LIMITED = "rate_limited"


class Limiter:
    def __init__(self, max_pending: int, max_per_window: int, window_seconds: float) -> None:
        self.max_pending = max_pending
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        #: key → open requests. Exposed (not copied) so a module can alias its state; mutate under no one's lock
        #: only in tests.
        self.pending: dict[str, int] = {}
        #: key → send times (monotonic seconds) still inside the window, oldest first.
        self.sent: dict[str, collections.deque] = {}

    def reserve(self, key: str, now: float) -> str:
        """Take one open slot for *key*; "" on success, else the reason it is refused
        (:data:`ALREADY_PENDING`, :data:`RATE_LIMITED`). A refusal changes nothing but expired history."""
        with self._lock:
            history = self.sent.get(key)
            if history is not None:
                while history and now - history[0] >= self.window_seconds:
                    history.popleft()
                if not history:
                    self.sent.pop(key, None)
                    history = None
            if self.pending.get(key, 0) >= self.max_pending:
                return ALREADY_PENDING
            if history is not None and len(history) >= self.max_per_window:
                return RATE_LIMITED
            self.pending[key] = self.pending.get(key, 0) + 1
            return ""

    def release(self, key: str, *, sent_at: float | None) -> None:
        """Give back a slot taken by :meth:`reserve`. *sent_at* is when the request went out, or None when
        nothing reached a person (the window is not charged)."""
        with self._lock:
            left = self.pending.get(key, 0) - 1
            if left > 0:
                self.pending[key] = left
            else:
                self.pending.pop(key, None)
            if sent_at is not None:
                self.sent.setdefault(key, collections.deque()).append(sent_at)

    def reset(self) -> None:
        """Forget every key (tests)."""
        with self._lock:
            self.pending.clear()
            self.sent.clear()
