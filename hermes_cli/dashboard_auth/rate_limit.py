"""Per-key sliding-window throttle for the public auth routes (password login, native revoke).

Process-local and best effort: it resets on restart and is no substitute for the provider's own
defences. The key is the client address from ``request_utils.client_ip``, which a caller cannot
choose (see there).

Memory is bounded. A key's bucket is dropped once its window has passed with no event, and the
table never holds more than ``max_keys`` buckets: the least recently active one goes first. A
flood of distinct addresses can therefore evict an idle bucket early, which only ever loosens
the throttle for that address, never tightens it for anybody else.
"""
from __future__ import annotations

import enum
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque


class Verdict(enum.Enum):
    ALLOWED = "allowed"
    REFUSED = "refused"              # the first refusal of this key in the current window
    REFUSED_AGAIN = "refused_again"  # refused again before that window ran out


@dataclass
class _Bucket:
    events: Deque[float] = field(default_factory=deque)
    noted_until: float = 0.0  # a refusal before this moment is REFUSED_AGAIN


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_sec: float, *, max_keys: int = 10_000) -> None:
        self.max_events = max_events
        self.window_sec = window_sec
        self.max_keys = max_keys
        # Ordered by last activity, oldest first, so expired buckets sit at the front.
        self._buckets: "OrderedDict[str, _Bucket]" = OrderedDict()
        self._lock = threading.Lock()

    def check(self, key: str) -> Verdict:
        """Record an event for ``key`` when it is within budget. An empty key shares one bucket,
        failing toward throttling."""
        key = key or "_unknown_"
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            self._sweep(cutoff, now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = _Bucket()
            while bucket.events and bucket.events[0] < cutoff:
                bucket.events.popleft()
            if len(bucket.events) >= self.max_events:
                if now < bucket.noted_until:
                    return Verdict.REFUSED_AGAIN
                bucket.noted_until = now + self.window_sec
                return Verdict.REFUSED
            bucket.events.append(now)
            self._buckets.move_to_end(key)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return Verdict.ALLOWED

    def exhausted(self, key: str) -> bool:
        """True when ``key`` has no budget left in the current window. Records nothing: a throttle
        that counts failures asks this first and records a failure with :meth:`check` afterwards."""
        key = key or "_unknown_"
        cutoff = time.monotonic() - self.window_sec
        with self._lock:
            bucket = self._buckets.get(key)
            return bucket is not None and sum(1 for t in bucket.events if t >= cutoff) >= self.max_events

    def reserve(self, key: str) -> "float | None":
        """Check and record in one step: the stamp of the event recorded for ``key``, or None when its
        budget is used up (nothing recorded). A caller that turns out not to need the slot gives it back
        with :meth:`release`, so a burst of concurrent callers can never overshoot the budget."""
        key = key or "_unknown_"
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            self._sweep(cutoff, now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = _Bucket()
            while bucket.events and bucket.events[0] < cutoff:
                bucket.events.popleft()
            if len(bucket.events) >= self.max_events:
                return None
            bucket.events.append(now)
            self._buckets.move_to_end(key)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return now

    def release(self, key: str, stamp: float) -> None:
        """Give back the slot :meth:`reserve` recorded as *stamp* for ``key`` (no-op when it is gone)."""
        key = key or "_unknown_"
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None:
                try:
                    bucket.events.remove(stamp)
                except ValueError:
                    pass

    def retry_after(self, key: str) -> int:
        """Whole seconds until ``key`` has budget again (0 when it has some now)."""
        key = key or "_unknown_"
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            bucket = self._buckets.get(key)
            live = sorted(t for t in bucket.events if t >= cutoff) if bucket is not None else []
            if len(live) < self.max_events:
                return 0
            # The slot frees when the event that leaves the window first does.
            oldest = live[len(live) - self.max_events]
            return max(1, int(oldest + self.window_sec - now + 0.999))

    def _sweep(self, cutoff: float, now: float) -> None:
        """Drop buckets from the front whose last event left the window and that hold no note."""
        while self._buckets:
            key, bucket = next(iter(self._buckets.items()))
            last = bucket.events[-1] if bucket.events else float("-inf")
            if last >= cutoff or bucket.noted_until > now:
                return
            del self._buckets[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
