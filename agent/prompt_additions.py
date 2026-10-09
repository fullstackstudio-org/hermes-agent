"""What is added to the cached system prompt at API time only: the session's ``ephemeral_system_prompt`` and,
for one turn, a note the gateway staged for it.

``ephemeral_system_prompt`` belongs to the personality config (``/personality`` and ``/model`` rewrite it), so
a per-turn addition cannot ride in it. A gateway that wants the model told something for exactly one turn
(``tui_gateway/hermie_markup.py``: the blocks the submitting app draws) stages it with
:func:`stage_turn_system_addition` at the turn's start, "" included, and clears it when the turn ends. Every
place that joins the cached prompt with its additions for one request goes through
:func:`with_system_additions`, so the system message of each request, a failover's rewrite of it and the
iteration summary agree. The Codex runtime keeps its thread's developer instructions to the session's part
(:func:`with_session_additions`) and hands the turn's addition in with a turn's input, once per change
(:func:`with_changed_turn_input_addition`), so a turn addition that changes never retires the thread and the
thread does not collect a copy per turn. Nothing here is ever written into ``_cached_system_prompt``, the
session store or a transcript.

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


#: How the turn addition opens when it rides in a turn's input instead of a system message (Codex). It is a
#: label for the model, not a credential: text in a turn's input carries no authority of its own, and nothing may
#: ever trust a block because it begins with this header (a person can type the same line).
TURN_INPUT_HEADER = "[Instructions for this reply from the app, not from the person]"
#: Sent once, in place of a block, when the addition a thread was last given is withdrawn.
TURN_INPUT_WITHDRAWN = "[The app no longer draws the blocks described earlier; write plain Markdown.]"


def _with_input_block(user_input: Any, block: str) -> Any:
    if isinstance(user_input, list):
        return [*user_input, {"type": "text", "text": block}]
    text = "" if user_input is None else str(user_input)
    return f"{text}\n\n{block}" if text else block


def with_changed_turn_input_addition(user_input: Any, agent: Any, last_sent: str | None) -> tuple[Any, str]:
    """For a runtime whose thread keeps every input (Codex): *user_input* with the staged addition appended only
    when it differs from *last_sent* (what this thread was last given; ``None`` or "" for nothing, as on a new
    or compacted thread), or with :data:`TURN_INPUT_WITHDRAWN` once when it was withdrawn. Returns the input and
    what the thread has been given after it, so a thread carries one copy per change and not one per turn."""
    addition = turn_system_addition(agent)
    if addition == (last_sent or ""):
        return user_input, addition
    block = f"{TURN_INPUT_HEADER}\n{addition}" if addition else TURN_INPUT_WITHDRAWN
    return _with_input_block(user_input, block), addition


def system_prompt_additions(agent: Any) -> str:
    """``ephemeral_system_prompt`` and the staged turn addition, joined by a blank line ("" when neither)."""
    parts = [getattr(agent, "ephemeral_system_prompt", None), getattr(agent, _TURN_ADDITION_ATTR, None)]
    return "\n\n".join(part for part in parts if isinstance(part, str) and part)


def with_system_additions(base: str, agent: Any) -> str:
    """*base* (the cached system prompt) with :func:`system_prompt_additions` appended, as every API-time site
    composes it: ``(base + "\\n\\n" + additions).strip()``, or *base* unchanged when there are none."""
    additions = system_prompt_additions(agent)
    return (base + "\n\n" + additions).strip() if additions else base
