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
