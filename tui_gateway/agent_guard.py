"""What the gateway itself refuses or narrows for a connection of an agent acting for its person through MCP.

The MCP bridge only ever dispatches an allowlist of methods, but these rules do not rest on that list: an
agent's connection (a transport whose ``auth_identity`` carries ``agent``, minted by the bridge from a verified
grant, never from a request) is held to them in the handlers, whatever reaches them.

* :func:`refusal`: the handlers that approve, unlock, provide a secret, run a command or change a setting
  answer an agent 4033 (Security 1 of the MCP plan: a token acts as the person for prompts and reading,
  nothing more).
* :data:`AGENT_PARAMS` / :func:`param_refusal`: the methods an agent may call and, for each, the only keys it
  may send (an allowlist). The bridge sends nothing else (``mcp_bridge.rpc``); the handlers whose other
  parameters would act as the person refuse them from an agent's connection (``session.create``: seeded
  messages, hidden, a parent, room plumbing, a model; ``session.resume``: close-on-disconnect, an eager build;
  ``client.capabilities``: confirm levels; ``prompt.submit``: :data:`AGENT_SUBMIT_PARAMS`).
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

#: Every method an agent's connection is meant to call, and the only parameter keys it may send to each: exactly
#: what the MCP bridge sends (``mcp_bridge.rpc.ALLOWED_METHODS`` is these methods, ``check_call`` these keys). A
#: plain new chat (a bot, a title), a resume of one without its transcript, an answer, a stop of its own turn,
#: its text; never a seeded, hidden, branched or plumbing chat, another model, a close-on-disconnect, a confirm.
AGENT_PARAMS: dict[str, frozenset[str]] = {
    "gateway.capabilities": frozenset(),
    "client.capabilities": frozenset({"server_requests"}),
    "profiles.list": frozenset({"include_sessions"}),
    "session.create": frozenset({"profile", "title"}),
    "session.resume": frozenset({"session_id", "profile", "omit_messages"}),
    "session.active_list": frozenset(),
    "session.events.since": frozenset({"session_id", "last_seen"}),
    "prompt.submit": frozenset({"session_id", "text", "queued"}),
    "session.interrupt": frozenset({"session_id"}),
    "request.answer": frozenset({"id", "result"}),
}

#: Every key an agent's ``prompt.submit`` may carry: its text, queued behind a running turn. ``methods_prompt``
#: refuses an agent's submit with any other key (4033); the MCP bridge never sends one
#: (``mcp_bridge.rpc.PROMPT_SUBMIT_PARAMS`` is this set).
AGENT_SUBMIT_PARAMS: frozenset[str] = AGENT_PARAMS["prompt.submit"]

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


def refusal(rid: Any, action: str) -> dict | None:
    """The 4033 answer for an agent's connection calling a handler that *action*s (approves, unlocks, ...); None
    for every other connection. Reads the connection the request arrived on (``current_transport``)."""
    from tui_gateway.transport import current_transport

    if agent_identity(current_transport()) is None:
        return None
    return {"jsonrpc": "2.0", "id": rid, "error": {
        "code": 4033, "message": f"an agent connected through MCP cannot {action}; the person does that in their own app"}}


def param_refusal(rid: Any, method: str, params: dict) -> dict | None:
    """The 4033 answer for an agent's connection calling *method* with a key outside :data:`AGENT_PARAMS`
    (a method not listed there allows none); None for every other connection and for the gateway's own dispatch
    on an agent's thread (``_INTERNAL_DISPATCH``: a relayed bot message, a hosted room)."""
    from tui_gateway.session_transports import _INTERNAL_DISPATCH
    from tui_gateway.transport import current_transport

    if agent_identity(current_transport()) is None or _INTERNAL_DISPATCH.get():
        return None
    extra = set(params) - AGENT_PARAMS.get(method, frozenset())
    if not extra:
        return None
    return refusal(rid, f"send {', '.join(sorted(extra))} with {method}")


def turn_start_fence(session: dict) -> threading.Lock:
    """The session's turn-start fence (created on first use). Lock order: the fence, then ``history_lock``."""
    fence = session.get("_turn_start_fence")
    if fence is None:
        fence = session.setdefault("_turn_start_fence", threading.Lock())
    return fence
