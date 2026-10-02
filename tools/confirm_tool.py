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


_SENTENCES = {
    ("confirmed", "tap"): "The person tapped Confirm in a connected app.",
}
_UNAVAILABLE = ("No connected app can confirm this right now — ask the person to open their app, or proceed "
                "without the action.")
_REASON_SENTENCES = {
    "already_pending": "Another confirmation is still waiting for an answer; do not ask again until it ends.",
    "rate_limited": "Too many confirmation requests in this conversation; wait several minutes before asking again.",
}


def _sentence(result: dict) -> str:
    outcome = result.get("outcome")
    if outcome == "confirmed":
        return _SENTENCES.get(("confirmed", str(result.get("method"))), "The person confirmed.")
    if outcome == "declined":
        return "The person declined."
    if outcome == "timeout":
        return "No answer within 120 seconds."
    reason = _REASON_SENTENCES.get(str(result.get("reason") or ""))
    return f"{_UNAVAILABLE} {reason}" if reason else _UNAVAILABLE


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
        "Ask the person to confirm ONE sensitive action in their connected app before you do it (spending "
        "money, deleting data, sending something on their behalf, changing access). Blocks for up to 120 "
        "seconds. Describe exactly what will happen in summary, in plain text; the person sees your words "
        "verbatim with fixed Confirm / Decline buttons. "
        "What it proves (level 'plain', the only one today): someone tapped Confirm in a connected app, "
        "nothing more — not who tapped it, not that it was the account owner; verified is always false. "
        "Outcomes: 'confirmed' — go ahead with exactly what you described, nothing more; 'declined' — "
        "do not do it; 'unavailable' or 'timeout' — NOT consent: do not do the action, tell the person, "
        "and do not keep asking. One confirmation at a time, a few per conversation; do not ask for "
        "routine steps."
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
