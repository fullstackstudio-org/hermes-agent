"""What the gateway itself refuses or narrows for a connection of an agent acting for its person through MCP.

The MCP bridge only ever dispatches an allowlist of methods, but these rules do not rest on that list: an
agent's connection (a transport whose ``auth_identity`` carries ``agent``, minted by the bridge from a verified
grant, never from a request) is held to them in the handlers, whatever reaches them.

* :data:`INTERRUPT_TURN`: an agent's ``session.interrupt`` stops only the turn it names. The id is not a
  request parameter (a client could send one); the bridge binds it in the fresh ``contextvars.Context`` it
  dispatches the call in, and ``session.interrupt`` reads it only when the calling connection IS an agent.
* :func:`turn_start_fence`: the per-session lock a turn's start (``_admit_prompt_turn``, the compute-host
  hand-off) and an agent's bound interrupt both take, so the interrupt checked against one turn cannot land on
  the next.

A leaf on purpose (see ``row_author``): the gateway's split modules are re-created against ``server.py``'s
globals, so callers import from here inside the function that needs it.
"""

from __future__ import annotations

import contextvars
import threading
from typing import Any

#: The gateway turn id an agent's ``session.interrupt`` may stop, bound by the MCP bridge around that one call
#: (``mcp_bridge.rpc.interrupt_turn``). Never read for a connection that is not an agent's.
INTERRUPT_TURN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "hermes_gateway_agent_interrupt_turn", default=None)


def agent_identity(transport: Any) -> dict | None:
    """``transport``'s identity when it is an agent's (it carries ``agent`` at all, whatever its shape)."""
    identity = getattr(transport, "auth_identity", None)
    return identity if isinstance(identity, dict) and identity.get("agent") is not None else None


def grant_of(transport: Any) -> str:
    """The grant id of an agent's connection ("" for anyone else). A registry key: never written to a row."""
    identity = agent_identity(transport)
    agent = identity.get("agent") if identity is not None else None
    grant = agent.get("grant") if isinstance(agent, dict) else None
    return grant.strip() if isinstance(grant, str) else ""


def turn_start_fence(session: dict) -> threading.Lock:
    """The session's turn-start fence (created on first use). Lock order: the fence, then ``history_lock``."""
    fence = session.get("_turn_start_fence")
    if fence is None:
        fence = session.setdefault("_turn_start_fence", threading.Lock())
    return fence
