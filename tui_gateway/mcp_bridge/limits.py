"""The per-grant limits of the MCP endpoint (plan D11), keyed on the grant id the verified token names, never
on anything a client chooses.

* every tool call: :data:`TOOL_CALLS_PER_MINUTE` a minute;
* ``bot_prompt``: :data:`PROMPTS_PER_WINDOW` in :data:`PROMPT_WINDOW_S`;
* turns that have not concluded: ``dashboard.mcp.max_running_turns_per_grant`` (default 3), counted from the
  grant's watches (:mod:`.turns`), so a turn that ends frees its slot without bookkeeping here;
* one waiter per turn: :meth:`~tui_gateway.mcp_bridge.turns.TurnWatch.wait` hands a turn to the newest
  waiter and returns the older one at once.

Process-local and reset by a restart, like the dashboard's other throttles. Pure apart from the clock.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable, Deque

TOOL_CALLS_PER_MINUTE = 60
PROMPTS_PER_WINDOW = 20
PROMPT_WINDOW_S = 600.0
_MAX_KEYS = 10_000


@dataclass(frozen=True)
class Refusal:
    """A limit was reached: the tool error ``rate_limited`` (or ``busy``), with when to try again."""
    code: str
    message: str
    retry_after_seconds: int


class WindowLimiter:
    """At most *max_events* per key in any *window_s*; a refusal says when the oldest event leaves the window."""

    def __init__(self, max_events: int, window_s: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_events = max_events
        self.window_s = window_s
        self._clock = clock
        self._lock = threading.Lock()
        self._events: OrderedDict[str, Deque[float]] = OrderedDict()

    def take(self, key: str) -> float | None:
        """Record one event for *key*; None when admitted, else the seconds until one would be."""
        now = self._clock()
        with self._lock:
            events = self._events.get(key)
            if events is None:
                events = self._events[key] = deque()
            while events and events[0] <= now - self.window_s:
                events.popleft()
            if len(events) >= self.max_events:
                return max(0.0, events[0] + self.window_s - now)
            events.append(now)
            self._events.move_to_end(key)
            while len(self._events) > _MAX_KEYS:
                self._events.popitem(last=False)
            return None

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


TOOL_CALLS = WindowLimiter(TOOL_CALLS_PER_MINUTE, 60.0)
PROMPTS = WindowLimiter(PROMPTS_PER_WINDOW, PROMPT_WINDOW_S)


def _retry(seconds: float) -> int:
    return max(1, math.ceil(seconds))


def check_tool_call(grant_id: str) -> Refusal | None:
    wait = TOOL_CALLS.take(grant_id)
    if wait is None:
        return None
    return Refusal("rate_limited", f"more than {TOOL_CALLS_PER_MINUTE} tool calls a minute on this connection",
                   _retry(wait))


def check_prompt(grant_id: str) -> Refusal | None:
    wait = PROMPTS.take(grant_id)
    if wait is None:
        return None
    return Refusal("rate_limited", f"more than {PROMPTS_PER_WINDOW} prompts in {int(PROMPT_WINDOW_S // 60)} minutes "
                   "on this connection", _retry(wait))


def running_turns(grant_id: str) -> int:
    """Turns this grant submitted that have not concluded (queued ones included)."""
    from tui_gateway.mcp_bridge import turns

    return sum(1 for watch in turns.watches() if watch.grant == grant_id and not watch.concluded)


def check_running(grant_id: str, maximum: int) -> Refusal | None:
    if running_turns(grant_id) < maximum:
        return None
    return Refusal("busy", f"{maximum} turns started through this connection have not finished; wait for one "
                   "(bot_wait) or stop it (bot_interrupt)", 5)


def reset_for_tests() -> None:
    TOOL_CALLS.reset()
    PROMPTS.reset()
