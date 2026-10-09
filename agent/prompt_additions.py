"""What is added to the cached system prompt at API time only: the session's ``ephemeral_system_prompt`` and,
for one turn, a note the gateway staged for it.

``ephemeral_system_prompt`` belongs to the personality config (``/personality`` and ``/model`` rewrite it), so
a per-turn addition cannot ride in it. A gateway that wants the model told something for exactly one turn
(``tui_gateway/hermie_markup.py``: the blocks the submitting app draws) stages it with
:func:`stage_turn_system_addition` at the turn's start, "" included, and clears it when the turn ends. Every
place that joins the cached prompt with its additions for one request goes through
:func:`with_system_additions`, so the system message of each request, a failover's rewrite of it and the
iteration summary agree. The Codex runtime keeps its thread's developer instructions to the session's part
(:func:`with_session_additions`) and hands the turn's addition in with the turn's input
(:func:`with_turn_input_addition`), so a turn addition that changes never retires the thread. Nothing here is ever written into ``_cached_system_prompt``, the session store or a
transcript.

Without a staged addition the result is byte-identical to the cached prompt joined with
``ephemeral_system_prompt`` as before.
"""

from __future__ import annotations

from typing import Any

_TURN_ADDITION_ATTR = "_turn_system_addition"


def stage_turn_system_addition(agent: Any, text: str) -> None:
    """Stage *text* (or "" for nothing) as this turn's API-time system addition on *agent*."""
    try:
        setattr(agent, _TURN_ADDITION_ATTR, text if isinstance(text, str) else "")
    except Exception:  # an agent stand-in without attributes simply gets no addition
        pass


def turn_system_addition(agent: Any) -> str:
    """The addition staged for the running turn ("" when none)."""
    text = getattr(agent, _TURN_ADDITION_ATTR, None)
    return text if isinstance(text, str) else ""


def with_session_additions(base: str, agent: Any) -> str:
    """*base* with ``ephemeral_system_prompt`` only, as the sites composed it before the turn addition existed.
    For a composition that identifies something longer-lived than one turn (the Codex thread)."""
    ephemeral = getattr(agent, "ephemeral_system_prompt", None)
    return (base + "\n\n" + ephemeral).strip() if isinstance(ephemeral, str) and ephemeral else base


#: How the turn addition opens when it rides in a turn's input instead of a system message (Codex).
TURN_INPUT_HEADER = "[Instructions for this reply from the app, not from the person]"


def with_turn_input_addition(user_input: Any, agent: Any) -> Any:
    """*user_input* with the staged turn addition appended as a final text block, for a runtime whose system
    instructions live on a long-lived thread (Codex): a per-turn change must not restart that thread. Unchanged
    when nothing is staged. A list input (text and image parts) gains one text part."""
    addition = turn_system_addition(agent)
    if not addition:
        return user_input
    block = f"{TURN_INPUT_HEADER}\n{addition}"
    if isinstance(user_input, list):
        return [*user_input, {"type": "text", "text": block}]
    text = "" if user_input is None else str(user_input)
    return f"{text}\n\n{block}" if text else block


def system_prompt_additions(agent: Any) -> str:
    """``ephemeral_system_prompt`` and the staged turn addition, joined by a blank line ("" when neither)."""
    parts = [getattr(agent, "ephemeral_system_prompt", None), getattr(agent, _TURN_ADDITION_ATTR, None)]
    return "\n\n".join(part for part in parts if isinstance(part, str) and part)


def with_system_additions(base: str, agent: Any) -> str:
    """*base* (the cached system prompt) with :func:`system_prompt_additions` appended, as every API-time site
    composes it: ``(base + "\\n\\n" + additions).strip()``, or *base* unchanged when there are none."""
    additions = system_prompt_additions(agent)
    return (base + "\n\n" + additions).strip() if additions else base
