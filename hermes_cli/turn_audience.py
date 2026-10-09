"""Who a notification about a session's turn may go to (fork; see FORK.md).

A plugin that notifies people about a turn (a push after a bot replies, a clarify question, the turn
ending) has to know whose turn it is, or it notifies every person the gateway knows. The turn hooks do
not say: ``post_llm_call``, ``on_session_end``, ``pre_approval_request`` and the clarify ``pre_tool_call``
are fired from agent core, which knows nothing about signed-in people. The gateway that runs the turn does.

So the gateway registers a provider here and a plugin asks, from inside the hook (the turn's own
context), only when it is about to notify::

    from hermes_cli.turn_audience import turn_audience
    audience = turn_audience(session_id=kwargs.get("session_id", ""))

A function rather than hook kwargs on purpose: working the answer out reads the session's rows, and
``pre_tool_call`` fires for every tool call of every turn, while a plugin needs it for a handful of them.

The answer is ``None`` when this process cannot say (no gateway registered a provider: the CLI, a
messaging gateway, an upstream build), else a dict:

- ``acting_user_id``: the person this turn acts for, as the gateway attributes work (``<provider>:<id>``),
  ``""`` when it attributes the turn to nobody (a cron run, a relayed bot message on a shared chat);
- ``user_ids``: everyone the gateway knows takes part in the session, acting person first: the acting
  person, the login the session was created under (unless the session is shared and the stamp no longer
  proves anything), the logins attached to it right now, and the authors stamped on its rows. Empty when
  the gateway knows nobody.

It never raises; a provider that fails answers ``None``.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

TurnAudienceProvider = Callable[[str, str], Optional[Dict[str, Any]]]

_provider: Optional[TurnAudienceProvider] = None


def set_turn_audience_provider(provider: Optional[TurnAudienceProvider]) -> None:
    """Install (or, with ``None``, remove) the process's provider. The gateway calls this at import."""
    global _provider
    _provider = provider


def turn_audience(*, session_id: str = "", session_key: str = "") -> Optional[Dict[str, Any]]:
    """The audience of the session a hook is about; see the module docstring. Never raises."""
    provider = _provider
    if provider is None:
        return None
    try:
        answer = provider(str(session_id or ""), str(session_key or ""))
    except Exception:
        logger.debug("turn audience provider failed", exc_info=True)
        return None
    if not isinstance(answer, dict):
        return None
    acting = answer.get("acting_user_id")
    user_ids = answer.get("user_ids")
    return {
        "acting_user_id": acting if isinstance(acting, str) else "",
        "user_ids": [uid for uid in (user_ids or []) if isinstance(uid, str) and uid],
    }
