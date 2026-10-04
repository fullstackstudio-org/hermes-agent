"""The bridge's only way into the gateway: ``server.dispatch(req, transport)`` with an
:class:`~tui_gateway.mcp_bridge.transport.AgentTransport` bound, for an allowlist of methods (plan D6).

Through ``dispatch`` the agent's connection gets exactly what a WebSocket client gets: the method contracts
(unknown param keys answer 4000), the retirement fence (5035), the access rules
(``_transport_may_access_session``: another person's session answers 4001 like an unknown one) and the
agent's own limits in ``server_requests``. Never ``_internal_dispatch()`` (it bypasses the access rules),
never a handler called directly. Each call runs in a FRESH ``contextvars.Context``, so nothing the calling
thread happens to have bound (an internal-dispatch flag, another transport, a turn's identity) can leak
into the request.

What is refused here, before anything is dispatched (:class:`DisallowedCall`, always a bridge bug):

* a method outside :data:`ALLOWED_METHODS`;
* any parameter key starting with ``_`` at any depth (``prompt.submit`` treats ``_turn_author``,
  ``_replayed_turn``, ``_hosted_task`` as in-process objects; a wire client cannot send objects, and
  neither may the bridge -- params are also round-tripped through JSON for that reason);
* ``client.capabilities`` advertising anything but ``server_requests`` (an agent never performs a
  ``confirm`` level);
* ``request.answer`` with a result that is not a clarify answer (``{answer}`` or ``{answers}``). The
  gateway refuses every other method from an agent anyway (4033); this keeps the bridge from even trying.

Blocking: :func:`call` waits on the calling thread (a pooled handler answers from an RPC worker). Run it
from a worker thread, never on an event loop.
"""

from __future__ import annotations

import contextvars
import json
import logging
import uuid
from typing import Any

from tui_gateway.mcp_bridge.transport import AgentTransport

logger = logging.getLogger(__name__)

#: Plan D6. ``request.answer`` is clarify-only (checked below and, authoritatively, by the gateway); history is
#: read through the stored read the REST route uses, not over RPC. ``profiles.describe`` is left out: its
#: editor snapshot carries the profile's SOUL, skills and MCP servers, and the agent gets a bot's read fields
#: from ``profiles.list`` (name, display name, description, model). Never: ``session.close/delete/title/
#: set_hidden``, ``config.*``, ``profiles.describe/configure/create/set_asset``, ``slash.exec``,
#: ``approval.respond``, ``clarify.lock``, ``fs.*``, console, ``prompt.background``.
ALLOWED_METHODS = frozenset({
    "gateway.capabilities",
    "client.capabilities",
    "profiles.list",
    "session.create",
    "session.resume",
    "session.active_list",
    "session.events.since",
    "prompt.submit",
    "session.interrupt",
    "request.answer",
})

DEFAULT_TIMEOUT_S = 30.0
#: What a ``gateway_restarting`` error tells the agent to wait before trying again: the default drain
#: (``dashboard.shutdown_drain_timeout``, 20 s) plus a restart. The wire carries no figure of its own.
RESTART_RETRY_AFTER_S = 30
#: The JSON-RPC error code of the retirement fence and of the restart drain's turn admission.
RESTARTING_CODE = 5035


class BridgeError(Exception):
    """Base of everything the bridge raises."""


class DisallowedCall(BridgeError):
    """The bridge tried a call outside its allowlist or with a forbidden parameter: a bug in the bridge."""


class TransportClosed(BridgeError):
    """The agent's connection closed before the call was answered."""


class RpcTimeout(BridgeError):
    """No response within the call's timeout. The handler may still finish; its response is dropped."""


class RpcError(BridgeError):
    """The gateway answered a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class GatewayRestarting(RpcError):
    """5035: the gateway is retiring or draining for a restart. The tool error ``gateway_restarting``."""

    kind = "gateway_restarting"

    def __init__(self, message: str, data: Any = None,
                 retry_after_seconds: int = RESTART_RETRY_AFTER_S) -> None:
        super().__init__(RESTARTING_CODE, message, data)
        self.retry_after_seconds = retry_after_seconds


def _underscore_key(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.startswith("_"):
                return key
            if (found := _underscore_key(item)) is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            if (found := _underscore_key(item)) is not None:
                return found
    return None


def _clarify_result(result: Any) -> bool:
    if not isinstance(result, dict) or not result or set(result) - {"answer", "answers"}:
        return False
    if "answer" in result and not isinstance(result["answer"], str):
        return False
    answers = result.get("answers")
    return answers is None or (isinstance(answers, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in answers.items()))


def check_call(method: str, params: Any) -> dict:
    """The params *method* may be dispatched with, as plain JSON; :class:`DisallowedCall` otherwise."""
    if method not in ALLOWED_METHODS:
        raise DisallowedCall(f"the MCP bridge may not call {method!r}")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise DisallowedCall(f"{method}: params must be an object")
    try:
        params = json.loads(json.dumps(params))
    except (TypeError, ValueError) as exc:
        raise DisallowedCall(f"{method}: params must be plain JSON") from exc
    if (key := _underscore_key(params)) is not None:
        raise DisallowedCall(f"{method}: parameter {key!r} is in-process only")
    if method == "client.capabilities" and params != {"server_requests": True}:
        raise DisallowedCall("client.capabilities: an agent advertises {server_requests: true} and nothing else")
    if method == "request.answer" and (set(params) - {"id", "result"} or not _clarify_result(params.get("result"))):
        raise DisallowedCall("request.answer: an agent answers clarify only ({answer} or {answers})")
    return params


def _raise_for(method: str, response: dict) -> None:
    error = response.get("error")
    if not isinstance(error, dict):
        error = {"code": -32603, "message": str(error)}
    code = error.get("code")
    message = str(error.get("message") or "")
    if code == RESTARTING_CODE:
        raise GatewayRestarting(message, error.get("data"))
    raise RpcError(code if isinstance(code, int) else -32603, message, error.get("data"))


def _dispatch(transport: AgentTransport, method: str, params: dict, timeout: float | None,
              bind: dict | None = None) -> dict:
    """*bind*: ``{ContextVar: value}`` set in the call's fresh context before dispatch (an in-process value the
    gateway reads for an agent's connection only, never a parameter: see :func:`interrupt_turn`)."""
    from tui_gateway import server

    rid = f"mcp-{uuid.uuid4().hex[:16]}"
    try:
        pending = transport.expect(rid)
    except ConnectionError as exc:
        raise TransportClosed(str(exc)) from exc
    request = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
    try:
        # A fresh context: the request sees only what dispatch binds (this transport), never the caller's
        # ContextVars. A pooled handler copies THIS context, so it inherits the same clean slate.
        response = contextvars.Context().run(_dispatch_bound, server.dispatch, request, transport, bind or {})
        if response is None:
            settled, response = pending.wait(timeout)
            if not settled:
                raise RpcTimeout(f"{method}: no response within {timeout}s")
            if response is None:
                raise TransportClosed(f"{method}: the agent transport closed")
    finally:
        transport.forget(rid)
    if not isinstance(response, dict):
        raise RpcError(-32603, f"{method}: malformed response")
    if "error" in response:
        _raise_for(method, response)
    result = response.get("result")
    return result if isinstance(result, dict) else {}


def _dispatch_bound(dispatch, request: dict, transport: AgentTransport, bind: dict) -> Any:
    for var, value in bind.items():
        var.set(value)
    return dispatch(request, transport)


def ensure_capabilities(transport: AgentTransport, *, timeout: float | None = DEFAULT_TIMEOUT_S) -> None:
    """Send ``client.capabilities {server_requests: true}`` once per connection: the agent receives the
    session's server requests (read-only, except clarify) and advertises no ``confirm`` level."""
    if transport.advertised:
        return
    with transport.advertise_lock:
        if transport.advertised:
            return
        _dispatch(transport, "client.capabilities", {"server_requests": True}, timeout)
        transport.advertised = True


def call(transport: AgentTransport, method: str, params: dict | None = None, *,
         timeout: float | None = DEFAULT_TIMEOUT_S) -> dict:
    """Dispatch *method* on the agent's connection and return its ``result``.

    Raises :class:`DisallowedCall` (bridge bug, nothing dispatched), :class:`GatewayRestarting` (5035),
    :class:`RpcError` (any other error, ``code`` as the gateway answered it), :class:`RpcTimeout`, or
    :class:`TransportClosed`."""
    if not isinstance(transport, AgentTransport):
        raise DisallowedCall("the MCP bridge dispatches on an AgentTransport only")
    params = check_call(method, params)
    if transport.closed:
        raise TransportClosed(f"{method}: the agent transport is closed")
    if method == "client.capabilities":
        with transport.advertise_lock:
            result = _dispatch(transport, method, params, timeout)
            transport.advertised = True
        return result
    ensure_capabilities(transport, timeout=timeout)
    return _dispatch(transport, method, params, timeout)


def interrupt_turn(transport: AgentTransport, session_id: str, gateway_turn_id: str, *,
                   timeout: float | None = DEFAULT_TIMEOUT_S) -> bool:
    """``session.interrupt`` of the one turn *gateway_turn_id* in *session_id*: True when the gateway stopped it.

    The gateway stops an agent's turn only by its id, and only when that turn is the agent's own and still
    running (``session_lifecycle._interrupt_agent_turn``); the id goes in ``agent_guard.INTERRUPT_TURN``,
    bound in the call's fresh context, because no request parameter may carry it (a WebSocket client could send
    one). Raises like :func:`call`."""
    from tui_gateway.agent_guard import INTERRUPT_TURN

    if not isinstance(transport, AgentTransport):
        raise DisallowedCall("the MCP bridge dispatches on an AgentTransport only")
    if not isinstance(gateway_turn_id, str) or not gateway_turn_id:
        raise DisallowedCall("session.interrupt: an agent names the turn it stops")
    params = check_call("session.interrupt", {"session_id": str(session_id)})
    if transport.closed:
        raise TransportClosed("session.interrupt: the agent transport is closed")
    ensure_capabilities(transport, timeout=timeout)
    result = _dispatch(transport, "session.interrupt", params, timeout, bind={INTERRUPT_TURN: gateway_turn_id})
    return result.get("status") == "interrupted"
