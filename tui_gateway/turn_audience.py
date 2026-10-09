"""The gateway's answer to ``hermes_cli.turn_audience.turn_audience`` (fork; see FORK.md).

Registered by ``tui_gateway.server`` at import, so the parent gateway and a compute-host child both answer.
A leaf module: the server is imported inside the function, the way the split modules reach it.

Who takes part in a session, as this gateway knows it:

- the person the turn acts for (``server._acting_auth_user``: the submitter carried into the turn, else
  the connection handling the request, else the record's stamp where no second person could be behind it);
- the login the session record was created under (the owner, shared or not);
- the logins attached to the session right now;
- the authors stamped on the session's stored rows (``display_metadata.author.id``).

The live record is found by the turn's ``HERMES_UI_SESSION_ID`` when it names the session asked about,
else by stored key or agent session id. A session with no live record (a cron run, a messaging platform's
chat) answers from its rows alone.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

#: How many row authors are read for one answer. A chat with more writers than this is not a chat whose
#: notifications are anybody's privacy question; the limit only bounds the read.
MAX_ROW_AUTHORS = 32


def _record_ids(record: dict) -> set:
    agent = record.get("agent")
    return {str(value) for value in (record.get("session_key"), getattr(agent, "session_id", None)) if value}


def _find_record(server: Any, session_id: str, session_key: str) -> Optional[dict]:
    wanted = {value for value in (session_id, session_key) if value}
    try:
        from gateway.session_context import get_session_env
        sid = get_session_env("HERMES_UI_SESSION_ID", "")
    except Exception:
        sid = ""
    sessions = getattr(server, "_sessions", None) or {}
    candidate = sessions.get(sid) if sid else None
    if isinstance(candidate, dict) and (not wanted or wanted & _record_ids(candidate)):
        return candidate
    if not wanted:
        return None
    for record in list(sessions.values()):
        if isinstance(record, dict) and wanted & _record_ids(record):
            return record
    return None


def _row_authors(stored_id: str) -> List[str]:
    if not stored_id:
        return []
    try:
        from hermes_state_registry import acquire, release_or_close
    except Exception:
        return []
    try:
        database = acquire()
    except Exception:
        logger.debug("turn audience: session database unavailable", exc_info=True)
        return []
    try:
        return list(database.get_session_author_ids(stored_id, MAX_ROW_AUTHORS))
    except Exception:
        logger.debug("turn audience: row authors unreadable", exc_info=True)
        return []
    finally:
        try:
            release_or_close(database)
        except Exception:
            pass


def provide(session_id: str, session_key: str) -> Optional[Dict[str, Any]]:
    """``{"acting_user_id", "user_ids"}`` for the session a hook is about. See the module docstring."""
    from tui_gateway import server

    record = _find_record(server, session_id, session_key)
    acting = ""
    people: List[str] = []

    def add(user_id: Any) -> None:
        if isinstance(user_id, str) and user_id and user_id not in people:
            people.append(user_id)

    if record is not None:
        try:
            acting = server._acting_auth_user(record)[0] or ""
        except Exception:
            logger.debug("turn audience: acting user unresolved", exc_info=True)
        add(acting)
        try:
            add(server._session_auth_user_id(record))
        except Exception:
            logger.debug("turn audience: owner unresolved", exc_info=True)
        try:
            for login in sorted(server._session_auth_logins(record)):
                add(login)
        except Exception:
            logger.debug("turn audience: attached logins unresolved", exc_info=True)
    stored = str((record or {}).get("session_key") or session_key or session_id or "")
    for author in _row_authors(stored):
        add(author)
    return {"acting_user_id": acting, "user_ids": people}
