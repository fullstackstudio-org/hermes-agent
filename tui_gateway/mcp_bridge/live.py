"""What the bridge reads of a live session in process, beyond what the RPCs answer: which turn is the one a
queued prompt became, and where that prompt sits in the queue.

``prompt.submit`` answers ``queued`` without naming the turn the text will become, and no frame says whose
turn starts next; a FIFO with other people's envelopes in it (or a Stop that drops the queue) makes "the
turn after the running one" a guess. The gateway itself knows: the turn's in-flight record carries the
row metadata it was admitted with (``display_metadata.turn_id`` and ``author`` with ``via``) and the text,
and the queue holds the envelopes. This module reads exactly that, and only of a session the agent's
connection may act on (``_transport_may_access_session``, the rule every session-scoped RPC applies).

Two kinds of readers:

* :func:`turn_verdict_from_inflight` runs on the EMITTING thread of ``message.start`` (from the watch's
  frame sink): it takes no lock and calls nothing. A dict read is atomic in CPython; the in-flight record
  of the turn being started is set before its ``message.start`` (``_admit_prompt_turn``).
* everything else runs on the waiter's thread and may take the session's ``history_lock`` or open its store.

A verdict is ``True`` (the agent's own turn: this person, through a client of this name, with this text in
it), ``False`` (somebody else's) or ``None`` (cannot tell from here).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: How many of a chat's latest stored rows the end-of-turn check looks through for the turn's user row.
_ROW_SCAN = 50


def session_record(transport: Any, session_id: str) -> dict | None:
    """The live record of *session_id* when *transport* may act on it; None otherwise (or when gone)."""
    from tui_gateway import server

    session = server._sessions.get(str(session_id))
    if not isinstance(session, dict):
        return None
    try:
        allowed = server._transport_may_access_session(session, transport, sid=str(session_id))
    except Exception:  # noqa: BLE001 - an access check that fails is a refusal
        logger.debug("mcp bridge: access check failed for %s", session_id, exc_info=True)
        return None
    return session if allowed else None


def _agent_of(transport: Any) -> tuple[str | None, dict | None]:
    from tui_gateway.mcp_bridge.transport import login_of
    from tui_gateway.row_author import agent_marker

    identity = getattr(transport, "auth_identity", None)
    agent = agent_marker(identity.get("agent")) if isinstance(identity, dict) else None
    return login_of(identity), agent


def _author_is(author: Any, login: str | None, agent: dict | None) -> bool:
    from tui_gateway.row_author import agent_from_row_author

    if not isinstance(author, dict) or login is None or agent is None:
        return False
    return author.get("id") == login and agent_from_row_author(author) == agent


def _contains(haystack: Any, text: str) -> bool:
    needle = (text or "").strip()
    return isinstance(haystack, str) and bool(needle) and needle in haystack


def turn_verdict(metadata: Any, content: Any, *, tid: str, transport: Any, text: str) -> bool | None:
    """Whether the turn *tid* whose user row (or in-flight record) carries *metadata* and *content* is the
    agent's own. None when *metadata* does not name *tid* (another turn's record)."""
    if not isinstance(metadata, dict) or metadata.get("turn_id") != tid:
        return None
    login, agent = _agent_of(transport)
    return _author_is(metadata.get("author"), login, agent) and _contains(content, text)


def turn_verdict_from_inflight(transport: Any, session_id: str, tid: str, text: str) -> bool | None:
    """Lock-free: the verdict from the session's in-flight record (see the module docstring)."""
    try:
        session = session_record(transport, session_id)
        inflight = session.get("inflight_turn") if session is not None else None
        if not isinstance(inflight, dict):
            return None
        return turn_verdict(inflight.get("display_metadata"), inflight.get("user"), tid=tid, transport=transport,
                            text=text)
    except Exception:  # noqa: BLE001 - a verdict that cannot be read is "cannot tell"
        logger.debug("mcp bridge: in-flight verdict failed", exc_info=True)
        return None


def turn_verdict_from_store(transport: Any, session_id: str, tid: str, text: str,
                            user_row_id: int | None) -> bool | None:
    """The verdict from the stored user row of *tid* (by *user_row_id* when the turn's end named it, else among
    the chat's latest rows). Waiter thread only: it opens the session's store."""
    from tui_gateway import server

    session = session_record(transport, session_id)
    if session is None:
        return None
    key = str(session.get("session_key") or "")
    if not key:
        return None
    try:
        with server._session_db(session) as db:
            if db is None:
                return None
            rows = db.get_messages(key, limit=_ROW_SCAN, latest=True)
    except Exception:  # noqa: BLE001 - an unreadable store is "cannot tell"
        logger.debug("mcp bridge: stored verdict failed", exc_info=True)
        return None
    for row in reversed(rows):
        if row.get("role") != "user":
            continue
        if user_row_id is not None and row.get("id") != user_row_id:
            continue
        verdict = turn_verdict(row.get("display_metadata"), row.get("content"), tid=tid, transport=transport,
                               text=text)
        if verdict is not None:
            return verdict
    return None


def queue_position(transport: Any, session_id: str, text: str) -> tuple[bool, int | None]:
    """``(running, position)`` of the agent's queued prompt in *session_id*: whether a turn runs now, and the
    1-based place of the envelope that holds the agent's text (its own, or the one of the same person and
    client it merged into), None when no envelope holds it (it ran, or a Stop dropped it). Waiter thread."""
    session = session_record(transport, session_id)
    if session is None:
        return False, None
    login, agent = _agent_of(transport)
    lock = session.get("history_lock")
    try:
        if lock is not None:
            lock.acquire()
        try:
            running = bool(session.get("running"))
            envelopes = [session.get("queued_prompt"), *(session.get("queued_prompts") or [])]
        finally:
            if lock is not None:
                lock.release()
    except Exception:  # noqa: BLE001
        logger.debug("mcp bridge: queue read failed", exc_info=True)
        return False, None
    position = 0
    for envelope in envelopes:
        if not isinstance(envelope, dict):
            continue
        position += 1
        user = envelope.get("turn_auth_user")
        sender = f"{user[0]}" if isinstance(user, (tuple, list)) and user else None
        from tui_gateway.row_author import agent_marker
        if (envelope.get("transport") is transport
                or (sender == login and agent_marker(envelope.get("turn_agent")) == agent
                    and _contains(envelope.get("text"), text))):
            return running, position
    return running, None

