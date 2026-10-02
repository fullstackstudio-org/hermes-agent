"""``confirm_action``: ask the person to confirm one sensitive action on their own device before doing it.

The request travels as the ``confirm`` server→client request to the connected apps of the turn's
interactive session (``tui_gateway/confirm.py``). The gateway installs the bridge with :func:`set_bridge`;
anywhere else (CLI, messaging platforms, cron, a process without the gateway) the tool is withheld from
the schema, and a call that still arrives is ``unavailable`` with nothing sent.

Off by default: the ``confirm`` toolset is in ``hermes_cli/tools_config.py::_DEFAULT_OFF_TOOLSETS`` and
is turned on per platform with ``hermes tools`` (or ``platform_toolsets``).
"""

from __future__ import annotations

import json
from typing import Callable, Optional

from gateway.session_context import get_session_env, session_is_messaging_surface
from tools.registry import registry, tool_error

# Levels the model may ask for. ``passkey`` (a verified level) is reserved and not offered yet; the gateway
# answers it ``unavailable`` without sending anything.
LEVELS = ("plain",)

# (sid, summary=, detail=, title=, level=) -> an object with ``as_dict()`` (tui_gateway.confirm.ConfirmOutcome).
_bridge: Optional[Callable] = None


def set_bridge(fn: Optional[Callable]) -> None:
    """Install (or clear) the gateway bridge. Called once by ``tui_gateway/server.py`` at import."""
    global _bridge
    _bridge = fn


def available() -> bool:
    return _bridge is not None


_NOT_CONSENT = "This is not consent: do not perform the action."

# One sentence per outcome and reason, each saying only what is known. A ``plain`` confirmation proves that
# someone tapped Confirm in an app attached to this conversation; not who, and not that they read it.
_OUTCOME_SENTENCES = {
    "confirmed": "Someone confirmed in a connected app (level plain: not verified, and not proof of who it was).",
    "declined": "Declined in a connected app. Do not perform the action.",
    "timeout": f"No answer within 120 seconds. {_NOT_CONSENT} Tell the person it is waiting for their "
               "confirmation; do not ask again unless they want you to.",
}
_REASON_SENTENCES = {
    "no_capable_client": f"No app attached to this conversation can answer a confirmation right now. {_NOT_CONSENT} "
                         "Tell the person a confirmation is needed; they can open an app that supports it and "
                         "ask you again.",
    "write_failed": f"The confirmation could not be delivered to any connected app. {_NOT_CONSENT} Tell the person.",
    "error_response": f"The connected app could not show the confirmation. {_NOT_CONSENT} Tell the person.",
    "no_session": f"Confirmations are not available in this conversation (no interactive app session). "
                  f"{_NOT_CONSENT}",
    "already_pending": f"Another confirmation is still open in this conversation. {_NOT_CONSENT} Wait for it to "
                       "end before asking again.",
    "rate_limited": f"Too many confirmations in this conversation; wait several minutes. {_NOT_CONSENT}",
    "level_not_implemented": f"That confirmation level is not available yet. {_NOT_CONSENT}",
    "turn_isolation": f"Confirmations are not available on this gateway while turns run isolated. {_NOT_CONSENT}",
    "cancelled:interrupted": f"The confirmation was withdrawn because the turn was stopped. {_NOT_CONSENT} Do not "
                             "ask again unless the person asks you to.",
    "cancelled:session_closed": f"The confirmation was withdrawn because the conversation was closed. {_NOT_CONSENT}",
    "cancelled:shutdown": f"The confirmation was withdrawn because the gateway is shutting down. {_NOT_CONSENT}",
}
_UNAVAILABLE = f"No confirmation was obtained. {_NOT_CONSENT}"


def _sentence(result: dict) -> str:
    outcome = str(result.get("outcome") or "")
    if outcome in _OUTCOME_SENTENCES:
        return _OUTCOME_SENTENCES[outcome]
    return _REASON_SENTENCES.get(str(result.get("reason") or ""), _UNAVAILABLE)


def _reply(result: dict) -> str:
    return json.dumps({**result, "message": _sentence(result)}, ensure_ascii=False)


def confirm_action_tool(summary: str, detail: str | None = None, level: str = "plain",
                        title: str | None = None) -> str:
    if level not in LEVELS:
        return tool_error(f"level must be one of: {', '.join(LEVELS)}.")
    sid = get_session_env("HERMES_UI_SESSION_ID", "")
    if _bridge is None or not sid or session_is_messaging_surface():
        # No interactive session for this turn (CLI, messaging, cron, background work): nothing is sent.
        return _reply({"outcome": "unavailable", "method": None, "verified": False, "reason": "no_session"})
    try:
        outcome = _bridge(sid, summary=summary, detail=detail, title=title, level=level)
    except ValueError as exc:  # text the agent must fix (empty / too long); nothing was sent
        return tool_error(str(exc))
    return _reply(outcome.as_dict())


CONFIRM_ACTION_SCHEMA = {
    "name": "confirm_action",
    "description": (
        "Ask for a confirmation of ONE sensitive action in the connected app before you do it (spending "
        "money, deleting data, sending something on someone's behalf, changing access). It only helps when "
        "you ask: nothing forces this tool. Blocks for up to 120 seconds. Write title, summary and detail as "
        "plain, factual text saying exactly what will happen; the app shows your words verbatim, marked as "
        "coming from you, with its own Confirm / Decline buttons. Never word it as a system or security "
        "message. "
        "What a 'confirmed' proves (level 'plain', the only one today): someone tapped Confirm in an app "
        "attached to this conversation. Not who it was (in a shared conversation it can be any participant), "
        "not that they read the text; verified is always false. "
        "Outcomes: 'confirmed' — do exactly what you described, nothing more; 'declined' — do not do it; "
        "'unavailable' or 'timeout' — NOT consent: do not do the action, do not reach the same effect another "
        "way, tell the person, and follow the message. One confirmation at a time, a few per conversation; do "
        "not ask for routine steps."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Plain text, at most 500 characters: exactly what will happen if confirmed.",
            },
            "detail": {
                "type": "string",
                "description": "Optional plain text, at most 2,000 characters (shown monospace): the "
                               "command, amounts, recipients.",
            },
            "level": {
                "type": "string",
                "enum": list(LEVELS),
                "description": "'plain' (default, the only level today): a tap in a connected app.",
            },
            "title": {
                "type": "string",
                "description": "Optional short heading, at most 80 characters.",
            },
        },
        "required": ["summary"],
    },
}


registry.register(
    name="confirm_action", toolset="confirm", schema=CONFIRM_ACTION_SCHEMA, check_fn=available,
    handler=lambda args, **kw: confirm_action_tool(
        summary=args.get("summary", ""), detail=args.get("detail"),
        level=args.get("level") or "plain", title=args.get("title")),
    emoji="🔐")
