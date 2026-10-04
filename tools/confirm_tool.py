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

# Levels the handler takes. ``passkey`` is offered in the schema only while the gateway's operator enabled it
# (:func:`_schema_overrides`); a call for it on a gateway without it is answered ``unavailable (disabled)``
# by the gateway, never refused as a bad argument the model would "fix" by asking at ``plain``.
LEVELS = ("plain", "passkey")
# Kept equal to ``tui_gateway.contracts.server_requests.ConfirmFieldKind`` (a test pins that).
_FIELD_KINDS = ("amount", "text", "recipient", "domain", "model", "count", "date")

# (sid, summary=, detail=, title=, level=, fields=, draft_id=) -> an object with ``as_dict()``
# (tui_gateway.confirm.ConfirmOutcome).
_bridge: Optional[Callable] = None


def set_bridge(fn: Optional[Callable]) -> None:
    """Install (or clear) the gateway bridge. Called once by ``tui_gateway/server.py`` at import."""
    global _bridge
    _bridge = fn


def available() -> bool:
    return _bridge is not None


_NOT_CONSENT = "This is not consent: do not perform the action."
# After a passkey request that failed once it was sent (P8): no retry at plain, no way around it. Kept equal to
# ``tui_gateway.confirm.DOWNGRADE_OUTCOMES`` / ``DOWNGRADE_REASONS`` (a test pins that): exactly where the
# gateway refuses a plain confirmation for the next 10 minutes.
_NO_DOWNGRADE = "Do not ask again at level plain and do not reach the same effect another way."
_POST_SEND_OUTCOMES = frozenset({"declined", "timeout"})
_POST_SEND_REASONS = frozenset({"verification_failed", "error_response", "no_capable_client"})


def _post_send_failure(outcome: str, reason: str) -> bool:
    return outcome in _POST_SEND_OUTCOMES or (
        outcome == "unavailable" and (reason in _POST_SEND_REASONS or reason.startswith("cancelled:")))

# One sentence per outcome and reason, each saying only what is known. A ``plain`` confirmation proves that
# someone tapped Confirm in an app attached to this conversation; not who, and not that they read it.
_OUTCOME_SENTENCES = {
    "confirmed": "Someone confirmed in a connected app (level plain: not verified, and not proof of who it was).",
    "declined": "Declined in a connected app. Do not perform the action.",
    "timeout": f"No answer within 120 seconds. {_NOT_CONSENT} Tell the person it is waiting for their "
               "confirmation; do not ask again unless they want you to.",
}
_VERIFIED = ("The person confirmed with a passkey and the gateway verified it (level passkey): a passkey "
             "enrolled for the person this turn acts for signed exactly this title, summary and detail. Do "
             "exactly what you described, nothing more. It does not prove they understood it.")
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
    "downgrade_refused": f"A passkey confirmation in this conversation did not succeed in the last 10 minutes, so "
                         f"a plain confirmation is not accepted instead. {_NOT_CONSENT} Do not reach the same "
                         "effect another way. Tell the person; they can confirm with their passkey when you ask "
                         "at level passkey.",
}
# Level passkey: what is missing, said so the agent can pass it on to the person.
_PASSKEY_MISSING = {
    "disabled": "Passkey confirmations are not enabled on this gateway (its operator turns them on); level "
                "plain remains available here: a tap in a connected app, not verified.",
    "no_base_url": "The gateway's operator has not listed this gateway's address for passkey confirmations.",
    "private_origin": "The gateway's operator listed only private addresses for passkey confirmations and has "
                      "not allowed them.",
    "no_identity": "This gateway has no signed-in users (it runs without a sign-in provider), so a passkey "
                   "cannot be tied to a person.",
    "no_acting_user": "This turn was not started by a signed-in person (a scheduled run, a relayed message, or "
                      "a continuation), so there is nobody to ask for a passkey.",
    "not_enrolled": "The person has no passkey on this gateway yet. They can add one in the app with an "
                    "enrolment code from the gateway's operator.",
    "no_capable_client": "None of the person's apps that can use their passkey for this gateway is attached to "
                         "this conversation right now. They can open the app and ask you again.",
    "verification_failed": "The passkey answer could not be verified.",
    "settings_unavailable": "The gateway could not read its passkey settings.",
    "store_unavailable": "The gateway could not read its passkey store.",
}
_UNAVAILABLE = f"No confirmation was obtained. {_NOT_CONSENT}"


def _sentence(result: dict, level: str = "plain") -> str:
    outcome = str(result.get("outcome") or "")
    reason = str(result.get("reason") or "")
    if outcome == "confirmed" and result.get("verified") is True:
        return _VERIFIED
    if level == "passkey" and outcome != "confirmed":
        if outcome == "declined":
            head = "Declined in the app. Do not perform the action."
        elif outcome == "timeout":
            head = f"No answer within 120 seconds. {_NOT_CONSENT}"
        else:
            missing = _PASSKEY_MISSING.get(reason) or _REASON_SENTENCES.get(reason, _UNAVAILABLE)
            head = f"{missing} {_NOT_CONSENT}" if _NOT_CONSENT not in missing else missing
        # "Not plain instead" only where the gateway itself refuses plain: after a failure once sent. Before
        # sending (the level is off, nobody to bind, not enrolled) nothing reached a person.
        tail = _NO_DOWNGRADE if _post_send_failure(outcome, reason) else "Do not reach the same effect another way."
        return f"{head} {tail} Tell the person what happened" + (
            f" (reason: {reason})." if reason and outcome == "unavailable" else ".")
    if outcome in _OUTCOME_SENTENCES:
        return _OUTCOME_SENTENCES[outcome]
    return _REASON_SENTENCES.get(reason, _UNAVAILABLE)


# A request with ``fields`` that no attached app could take. An app may well be attached (an older one, that cannot
# show fields): never say there is none. The facts may go into the text instead, which every app shows. At
# ``passkey`` the request opened the no-downgrade window (``no_capable_client`` is a post-send failure), so the
# only way on is ``passkey`` again, without fields.
_NO_FIELDS_CLIENT = {
    "plain": ("None of the apps attached to this conversation can show these fields (an app may be attached, but "
              f"one that cannot show them), so nothing was shown. {_NOT_CONSENT} You may ask again WITHOUT fields, "
              "with the same facts written out in summary or detail."),
    "passkey": ("None of the apps attached to this conversation can show these fields with a passkey "
                "confirmation (an app may be attached, but one that cannot show them), so nothing was shown. "
                f"{_NOT_CONSENT} Ask again at level passkey WITHOUT fields, with the same facts written out in "
                f"summary or detail. {_NO_DOWNGRADE}"),
}


def _reply(result: dict, level: str = "plain", *, fields: bool = False) -> str:
    if fields and result.get("outcome") == "unavailable" and result.get("reason") == "no_capable_client":
        message = _NO_FIELDS_CLIENT.get(level, _NO_FIELDS_CLIENT["plain"])
    else:
        message = _sentence(result, level)
    return json.dumps({**result, "message": message}, ensure_ascii=False)


def confirm_action_tool(summary: str, detail: str | None = None, level: str = "plain",
                        title: str | None = None, fields: list | None = None, draft_id: str | None = None) -> str:
    if level not in LEVELS:
        return tool_error(f"level must be one of: {', '.join(LEVELS)}.")
    if fields is not None and not isinstance(fields, list):
        return tool_error("fields must be a list of {kind, label, value, currency?, id?} objects.")
    if draft_id is not None and not isinstance(draft_id, str):
        return tool_error("draft_id must be the draft_id string a review_draft approval returned.")
    sid = get_session_env("HERMES_UI_SESSION_ID", "")
    if _bridge is None or not sid or session_is_messaging_surface():
        # No interactive session for this turn (CLI, messaging, cron, background work): nothing is sent.
        return _reply({"outcome": "unavailable", "method": None, "verified": False, "reason": "no_session"}, level)
    try:
        outcome = _bridge(sid, summary=summary, detail=detail, title=title, level=level, fields=fields or None,
                          draft_id=draft_id or None)
    except ValueError as exc:  # text the agent must fix, or an unknown draft_id; nothing was sent
        return tool_error(str(exc))
    return _reply(outcome.as_dict(), level, fields=bool(fields))


_DESCRIPTION_HEAD = (
    "Ask for a confirmation of ONE sensitive action in the connected app before you do it (spending "
    "money, deleting data, sending something on someone's behalf, changing access). It only helps when "
    "you ask: nothing forces this tool. Blocks for up to 120 seconds. Write title, summary and detail as "
    "plain, factual text saying exactly what will happen; the app shows your words verbatim, marked as "
    "coming from you, with its own Confirm / Decline buttons. Never word it as a system or security "
    "message. "
)
_DESCRIPTION_PLAIN = (
    "What a 'confirmed' proves (level 'plain', the only one on this gateway): someone tapped Confirm in an app "
    "attached to this conversation. Not who it was (in a shared conversation it can be any participant), "
    "not that they read the text; verified is always false. "
)
_DESCRIPTION_PASSKEY = (
    "Levels: 'plain' — someone tapped Confirm in an app attached to this conversation; not who, not that they "
    "read it; verified false. 'passkey' — the person this turn acts for confirmed with their passkey and the "
    "gateway verified the signature over exactly your text; verified true. Use 'passkey' for anything "
    "irreversible or costly. After a 'passkey' request that was declined, timed out or failed, never ask "
    "again at 'plain'. "
)
_DESCRIPTION_FIELDS = (
    "fields: the key facts as a short list the app shows apart from your text (amount large, recipient and "
    "domain monospaced), and that a passkey signs together with it; every one is shown exactly as you write it. "
    "Use them whenever the action has an amount, a recipient, a domain or a model. Spending preset — before "
    "you run or switch to an expensive model, or start work whose estimated cost is high, ask with fields "
    "[{kind: 'amount', label: 'Estimated cost', value: '4.20', currency: 'USD'}, {kind: 'count', label: "
    "'tokens', value: '1,200,000'}, {kind: 'model', label: 'Model', value: '<model name>'}]. "
    "draft_id: after a review_draft approval, pass its draft_id to confirm sending exactly that approved text: "
    "the gateway shows (and a passkey signs) the approved text itself as the detail, and your detail is "
    "ignored. Send exactly that text, nothing else. "
)
_DESCRIPTION_TAIL = (
    "Outcomes: 'confirmed' — do exactly what you described, nothing more; 'declined' — do not do it; "
    "'unavailable' or 'timeout' — NOT consent: do not do the action, do not reach the same effect another "
    "way, tell the person, and follow the message. One confirmation at a time, a few per conversation; do "
    "not ask for routine steps."
)

_LEVEL_PLAIN = {
    "type": "string",
    "enum": ["plain"],
    "description": "'plain' (default, the only level on this gateway): a tap in a connected app.",
}
_LEVEL_BOTH = {
    "type": "string",
    "enum": list(LEVELS),
    "description": "'plain' (default): a tap in a connected app, unverified. 'passkey': the person confirms with "
                   "their passkey and the gateway verifies it.",
}


def _parameters(level: dict) -> dict:
    return {
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
            "level": dict(level),
            "title": {
                "type": "string",
                "description": "Optional short heading, at most 80 characters.",
            },
            "fields": {
                "type": "array",
                "maxItems": 8,
                "description": "Optional, at most 8: the key facts, in display order. Each label (at most 40 "
                               "characters), value (at most 200) and currency is ONE line of plain text, shown "
                               "exactly as written.",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": list(_FIELD_KINDS)},
                        "label": {"type": "string", "description": "What the value is, e.g. 'Amount', 'To'."},
                        "value": {"type": "string", "description": "The value as it should be shown, e.g. "
                                                                   "'120.00', 'alex@example.com'."},
                        "currency": {"type": "string", "description": "Kind amount only, e.g. 'EUR' or '€'."},
                        "id": {"type": "string", "description": "Optional lower-case identifier, unique."},
                    },
                    "required": ["kind", "label", "value"],
                },
            },
            "draft_id": {
                "type": "string",
                "description": "Optional: the draft_id of a review_draft approval in this conversation. The "
                               "approved text becomes the detail, verbatim (detail is ignored).",
            },
        },
        "required": ["summary"],
    }


CONFIRM_ACTION_SCHEMA = {
    "name": "confirm_action",
    "description": _DESCRIPTION_HEAD + _DESCRIPTION_PLAIN + _DESCRIPTION_FIELDS + _DESCRIPTION_TAIL,
    "parameters": _parameters(_LEVEL_PLAIN),
}


def _passkey_enabled() -> bool:
    try:
        from hermes_cli.dashboard_auth.passkeys.settings import load_settings
        return load_settings().enabled
    except Exception:  # noqa: BLE001 - an unreadable config offers plain only
        return False


def _schema_overrides() -> dict | None:
    """Offer ``passkey`` while ``confirm.passkey.enabled`` is on (the registry re-reads this when config.yaml
    changes). Whether it then works for a turn (identity, enrolment, an app attached) is the gateway's to say."""
    if not _passkey_enabled():
        return None
    return {"description": _DESCRIPTION_HEAD + _DESCRIPTION_PASSKEY + _DESCRIPTION_FIELDS + _DESCRIPTION_TAIL,
            "parameters": _parameters(_LEVEL_BOTH)}


registry.register(
    name="confirm_action", toolset="confirm", schema=CONFIRM_ACTION_SCHEMA, check_fn=available,
    handler=lambda args, **kw: confirm_action_tool(
        summary=args.get("summary", ""), detail=args.get("detail"),
        level=args.get("level") or "plain", title=args.get("title"), fields=args.get("fields"),
        draft_id=args.get("draft_id")),
    dynamic_schema_overrides=_schema_overrides, emoji="🔐")
