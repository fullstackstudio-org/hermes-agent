"""Which persisted assistant row a tool call belongs to, and at which position in that row.

A provider's ``tool_call_id`` is not unique: llama.cpp answers every call with one constant id and other
backends restart at ``call_0`` each turn, so a client that pairs a live ``tool.start`` / ``tool.complete``
with a stored tool row by that id alone merges two different calls into one card. The assistant row that
holds the ``tool_calls`` is unique, and so is a call's position inside it. ``(call_row_id, call_index)`` is
the identity the gateway puts on every tool frame and on every history tool row.

``CallRow`` is the executor's side of it: ``run_tool_round`` builds one right after it flushed the assistant
row, ``_parse_tool_call`` claims an index per call (in call order, on the thread that parses, before any
worker runs) and every ref, callback and frame of that call carries the same pair.

``ToolRowPairing`` is the read side: the same pairing rule applied to stored rows, used by
``tui_gateway.row_identity.annotate_tool_rows`` for ``session.history`` and the REST routes.
"""

from __future__ import annotations

import threading
from typing import Any, Iterable

from agent.message_sanitization import coalesce_tool_call_id


def positive_row_id(value: Any) -> int | None:
    """``value`` when it is a durable ``messages.id`` (a positive int, never a bool), else ``None``."""
    return value if type(value) is int and value > 0 else None


class ToolRowPairing:
    """Pairs tool result rows with the entries of ONE assistant row's ``tool_calls``, in order.

    A tool row takes the first entry of its ``tool_call_id`` nobody took before it, so two calls that share
    an id inside one message come out as index 0 and 1, and a row whose id the message never held gets
    nothing."""

    def __init__(self, row_id: int, ids: Iterable[str]) -> None:
        self.row_id = row_id
        self.ids = list(ids)
        self._taken: set[int] = set()

    def take(self, pairing_id: str) -> int | None:
        if not pairing_id:
            return None
        for index, candidate in enumerate(self.ids):
            if index not in self._taken and candidate == pairing_id:
                self._taken.add(index)
                return index
        return None


class CallRow(ToolRowPairing):
    """The live round's pairing: ``claim(tool_call)`` answers ``(call_row_id, call_index)`` for a call object.

    The persisted ``tool_calls`` list and the call objects it was built from share their order, so a call's
    index is its position in the list the row was staged from; that also holds for a call whose provider id
    was blank (the row carries a derived one). A call object the row was not staged from (a caller outside
    the round) falls back to the id rule of ``ToolRowPairing``. Claims are remembered per object: the same
    call parsed twice (a prepared terminal batch, then the sequential loop) keeps one index."""

    def __init__(self, row_id: int, ids: Iterable[str], staged_calls: Iterable[Any] = ()) -> None:
        super().__init__(row_id, ids)
        staged = list(staged_calls)
        self._position = {id(tc): i for i, tc in enumerate(staged)} if len(staged) == len(self.ids) else {}
        self._keepalive = staged  # an id() is only a key while its object lives
        self._claims: dict[int, tuple[int, int | None]] = {}
        self._lock = threading.Lock()

    def claim(self, tool_call: Any) -> tuple[int, int | None]:
        with self._lock:
            key = id(tool_call)
            if key not in self._claims:
                index = self._position.get(key)
                if index is not None:
                    self._taken.add(index)
                else:
                    index = self.take(coalesce_tool_call_id(tool_call))
                self._claims[key] = (self.row_id, index)
                self._keepalive.append(tool_call)
            return self._claims[key]


def call_row_for(assistant_msg: dict, staged_calls: Iterable[Any] = ()) -> CallRow | None:
    """The ``CallRow`` of a committed assistant row holding ``tool_calls``; ``None`` when the row was never
    committed (a projection no flush wrote names no row) or carries no calls."""
    from agent.context_compressor import _DB_PERSISTED_MARKER

    row_id = positive_row_id(assistant_msg.get("_row_id")) if assistant_msg.get(_DB_PERSISTED_MARKER) else None
    calls = assistant_msg.get("tool_calls")
    if row_id is None or not isinstance(calls, list) or not calls:
        return None
    return CallRow(row_id, [coalesce_tool_call_id(tc) for tc in calls], staged_calls)


def claim_call_identity(agent: Any, tool_call: Any) -> tuple[int | None, int | None]:
    """``(call_row_id, call_index)`` of ``tool_call`` in the round ``agent`` is running; ``(None, None)``
    outside a round, and never an index without a row."""
    call_row = getattr(agent, "_current_call_row", None)
    if not isinstance(call_row, CallRow):
        return None, None
    row_id, index = call_row.claim(tool_call)
    return (row_id, index) if index is not None else (None, None)


def callback_identity_kwargs(callback: Any, **values: Any) -> dict[str, Any]:
    """The subset of ``values`` worth handing ``callback``: not ``None``, and only when the callback takes the
    keyword (a bare ``(tool_call_id, name, args)`` callback keeps working)."""
    from agent.interrupt_control import accepts_keyword

    if not callback:
        return {}
    return {name: value for name, value in values.items() if value is not None and accepts_keyword(callback, name)}
