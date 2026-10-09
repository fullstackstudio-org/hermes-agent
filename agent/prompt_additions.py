"""What is added to the cached system prompt at API time only: the session's ``ephemeral_system_prompt`` and,
for one turn, a note the gateway staged for it.

``ephemeral_system_prompt`` belongs to the personality config (``/personality`` and ``/model`` rewrite it), so
a per-turn addition cannot ride in it. A gateway that wants the model told something for exactly one turn
(``tui_gateway/hermie_markup.py``: the blocks the submitting app draws) stages it with
:func:`stage_turn_system_addition` at the turn's start, "" included, and clears it when the turn ends. Every
place that joins the cached prompt with its additions goes through :func:`with_system_additions`, so the
system message of each request, a failover's rewrite of it, the iteration summary and the Codex developer
instructions agree. Nothing here is ever written into ``_cached_system_prompt``, the session store or a
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


def system_prompt_additions(agent: Any) -> str:
    """``ephemeral_system_prompt`` and the staged turn addition, joined by a blank line ("" when neither)."""
    parts = [getattr(agent, "ephemeral_system_prompt", None), getattr(agent, _TURN_ADDITION_ATTR, None)]
    return "\n\n".join(part for part in parts if isinstance(part, str) and part)


def with_system_additions(base: str, agent: Any) -> str:
    """*base* (the cached system prompt) with :func:`system_prompt_additions` appended, as every API-time site
    composes it: ``(base + "\\n\\n" + additions).strip()``, or *base* unchanged when there are none."""
    additions = system_prompt_additions(agent)
    return (base + "\n\n" + additions).strip() if additions else base
