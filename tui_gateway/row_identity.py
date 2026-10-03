"""Which turn a live frame belongs to, so a client can pair it with the row the turn persisted.

A client cannot tell from a streamed frame which stored row it will become: ``message.delta`` has no
id, ``message.start`` carries no payload, and a chat reopened from a cache saved mid-turn replays the
same frames again over rows it already holds. Matching by words or by position guesses; a stable id
does not. So the gateway mints one ``turn_id`` per turn and writes it in two places that survive
different journeys:

* on the envelope (``params.turn_id``) of every turn-stream frame, which the replay ring stores with
  the frame, so a replayed frame names its turn exactly as the live one did;
* on the turn's user row, in ``display_metadata`` beside the author, which crosses SQLite,
  ``session.history``, the REST read and ``session.resume`` with no schema or wire-contract change.

A leaf module on purpose, for the reason ``row_author.py`` gives: the gateway's split modules have
their bodies re-created against ``server.py``'s globals, so callers import from here inside the
function that needs it.
"""

import uuid

#: Advertised through ``gateway.capabilities``. A module constant beside the code that stamps, the
#: ``PER_MESSAGE_AUTHOR`` pattern: it answers for the RUNNING process, so a gateway carrying this
#: file on disk but not yet restarted answers without the key, which is the honest answer. Advisory:
#: a client decides per frame on whether the field is present.
TRANSCRIPT_ROW_IDENTITY = True

#: The events that belong to one turn's stream, and so carry its ``turn_id``. Everything else on the
#: wire (``session.info``, ``sessions.changed``, ``status.update``, requests, ...) is session chrome
#: that can fire with no turn running and names no turn.
TURN_STREAM_EVENTS = frozenset({
    "message.start",
    "message.delta",
    "message.interim",
    "message.complete",
    "reasoning.delta",
    "reasoning.available",
    "thinking.delta",
    "tool.generating",
    "tool.start",
    "tool.complete",
    "tool.output_risk",
    "error",
})


def mint_turn_id() -> str:
    """A fresh, opaque turn id (uuid4 hex)."""
    return uuid.uuid4().hex


def begin_turn_id(session: dict) -> str:
    """Mint this turn's id onto ``session`` for a caller that emits ``message.start`` BEFORE it calls
    ``_run_prompt_submit`` (which adopts it), so that first frame is stamped too. The caller holds the
    session's ``running`` claim, so no other turn can be reading ``session["turn_id"]``."""
    turn_id = mint_turn_id()
    session["turn_id"] = turn_id
    return turn_id


def with_turn_id(display_metadata: dict | None, turn_id: str) -> dict:
    """``display_metadata`` with ``turn_id`` merged in. Every other key is kept, and ``turn_id`` is
    ALWAYS overwritten: the gateway mints it, so a value that arrived from anywhere else is never
    trusted."""
    return {**(display_metadata or {}), "turn_id": turn_id}


def turn_id_of(display_metadata) -> str | None:
    """The turn id a row's ``display_metadata`` carries, or None."""
    if not isinstance(display_metadata, dict):
        return None
    value = display_metadata.get("turn_id")
    return value if isinstance(value, str) and value else None


def annotate_tool_rows(messages) -> list:
    """``messages`` with every tool row that can be tied to its call carrying ``call_row_id`` and
    ``call_index``: the assistant row that holds the ``tool_calls`` and the position of the call in it.

    ``tool_call_id`` cannot say which call a row answers (llama.cpp sends one constant id, other backends
    restart at ``call_0`` each turn); the assistant row and the index can. Works on the stored shape
    (``_row_id`` on a message from ``get_messages_as_conversation``, ``id`` on a REST row) and so
    serves ``session.history`` and the REST routes alike. A tool row takes the first call of its id
    that no earlier tool row took, among the calls of the NEAREST preceding assistant row with calls; a
    later assistant row ends the earlier one's claim, so a call that never got a result cannot absorb the
    next turn's row. Rows with no such assistant row, or whose id that row never held, are returned as
    they came. The same list length and order; annotated tool rows are copies, nothing is mutated."""
    from agent.message_sanitization import coalesce_tool_call_id
    from agent.tool_call_identity import ToolRowPairing, positive_row_id

    annotated: list = []
    active: ToolRowPairing | None = None
    for message in messages or ():
        if not isinstance(message, dict):
            annotated.append(message)
            continue
        role = message.get("role")
        if role == "assistant":
            calls = message.get("tool_calls")
            row_id = positive_row_id(message.get("_row_id")) or positive_row_id(message.get("id"))
            active = (ToolRowPairing(row_id, [coalesce_tool_call_id(tc) for tc in calls])
                      if row_id is not None and isinstance(calls, list) and calls else None)
        elif role == "tool" and active is not None:
            raw_id = message.get("tool_call_id")
            pairing_id = raw_id.split("|", 1)[0].strip() if isinstance(raw_id, str) else ""
            index = active.take(pairing_id)
            if index is not None:
                message = {**message, "call_row_id": active.row_id, "call_index": index}
        annotated.append(message)
    return annotated
