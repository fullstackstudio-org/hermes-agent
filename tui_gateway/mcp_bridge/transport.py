"""The connection object of an agent acting for its signed-in person through MCP.

The gateway sees an :class:`AgentTransport` exactly as it sees a WebSocket client's transport: a peer that
``write()`` frames go to and that dies when ``_closed`` is set (``session_reaper._transport_is_dead``). Its
``auth_identity`` carries the person -- so ``_transport_auth_user``, the access rules, the row author, the
note, the tool variables and the audit apply unchanged -- plus ``agent``, the marker that makes the turn
the agent's on the person's behalf (``server._transport_agent``) and lets it answer ``clarify`` only
(``server_requests.agent_answer_refusal``).

``write()`` is called from whatever thread emits: a turn thread (sometimes under the session's
``history_lock``), a fan-out drain thread, an RPC pool worker writing its response, the server-request
sink. It therefore never blocks and never calls back into the gateway: a response frame resolves the
waiting :func:`tui_gateway.mcp_bridge.rpc.call`, any other frame goes to the ``on_event`` sink (the
:class:`~tui_gateway.mcp_bridge.turns.TurnWatch`), which only records it.

Lifetime: :meth:`AgentTransport.close` marks the peer gone (later writes answer False, so a fan-out prunes
it) and fails pending calls; :meth:`AgentTransport.release` also runs the gateway's own disconnect teardown
(``_close_sessions_for_transport``, as ``ws.py`` does when a socket goes), so every session it was attached
to follows the ordinary detached/reaper path. ``release`` may block (a session teardown); never call it
on an event loop.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

#: The ``kind`` of the only agent marker the gateway knows (``row_author.AGENT_KIND``).
AGENT_KIND = "mcp"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def validate_identity(identity: Any) -> dict:
    """A JSON-plain copy of *identity* when it names a person AND an MCP agent with its grant; ValueError
    otherwise. An agent transport without the marker would make the agent's words the person's own, so
    there is no such thing: the shape is checked here, before any frame can be dispatched."""
    if not isinstance(identity, dict):
        raise ValueError("an agent identity is a dict")
    try:
        copy = json.loads(json.dumps(identity))
    except (TypeError, ValueError) as exc:
        raise ValueError("an agent identity must be plain JSON") from exc
    if not _text(copy.get("provider")) or not _text(copy.get("user_id")):
        raise ValueError("an agent identity names its person (provider and user_id)")
    agent = copy.get("agent")
    if not isinstance(agent, dict) or agent.get("kind") != AGENT_KIND:
        raise ValueError("an agent identity carries agent {kind: 'mcp', client, grant}")
    if not _text(agent.get("grant")):
        raise ValueError("an agent identity names the grant it was minted from")
    if not isinstance(agent.get("client"), str):
        raise ValueError("an agent identity names its client")
    return copy


def login_of(identity: dict | None) -> str | None:
    """``<provider>:<user id>`` as ``server._transport_auth_user`` spells it, or None."""
    if not isinstance(identity, dict):
        return None
    provider, user_id = _text(identity.get("provider")), _text(identity.get("user_id"))
    return f"{provider}:{user_id}" if provider and user_id else None


def is_response_frame(obj: Any) -> bool:
    """A JSON-RPC response: an ``id`` with ``result`` or ``error`` and no ``method`` (the same test as
    ``server_requests.is_response_frame``)."""
    return isinstance(obj, dict) and "method" not in obj and "id" in obj and ("result" in obj or "error" in obj)


class _Pending:
    """One in-flight RPC: the response frame, or None when the transport closed first."""

    __slots__ = ("event", "response")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.response: dict | None = None

    def settle(self, response: dict | None) -> None:
        self.response = response
        self.event.set()

    def wait(self, timeout: float | None) -> tuple[bool, dict | None]:
        """``(settled, response)``."""
        settled = self.event.wait(timeout)
        return settled, self.response


class AgentTransport:
    """An agent's in-process connection to the gateway (see the module docstring)."""

    def __init__(self, identity: dict, on_event: Callable[[dict], None] | None = None, *,
                 peer: str = "mcp") -> None:
        #: Read by the gateway exactly like ``WSTransport.auth_identity``; minted by the bridge from a verified
        #: grant. A copy: nothing the caller holds can change who this connection is afterwards.
        self.auth_identity = validate_identity(identity)
        #: The address the audit lines name (``session_transports._session_audit`` reads ``_peer``).
        self._peer = str(peer or "mcp")
        #: The liveness flag the gateway's helpers read (``_transport_is_dead``: ``_closed is True``).
        self._closed = False
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._on_event = on_event
        self._released = False
        #: ``client.capabilities`` goes out once per connection, before its first other call (``rpc.call``).
        self.advertise_lock = threading.Lock()
        self.advertised = False

    # ── what the gateway calls ────────────────────────────────────────────────────────────────

    def write(self, obj: dict) -> bool:
        """Take one frame. Never blocks, never raises, never calls into the gateway. False once closed."""
        if self._closed:
            return False
        if is_response_frame(obj):
            rid = obj.get("id")
            with self._lock:
                pending = self._pending.pop(rid, None) if isinstance(rid, str) else None
            if pending is not None:
                pending.settle(obj)
            else:
                logger.debug("agent transport: response for no pending call id=%r", rid)
            return True
        sink = self._on_event
        if sink is not None and isinstance(obj, dict):
            try:
                sink(obj)
            except Exception:  # noqa: BLE001 - a broken sink must not break the emitting turn
                logger.exception("agent transport: event sink failed")
        return not self._closed

    def close(self) -> None:
        """Mark the peer gone and fail every pending call. Idempotent; never blocks."""
        with self._lock:
            self._closed = True
            pending, self._pending = list(self._pending.values()), {}
        for call in pending:
            call.settle(None)

    # ── what the bridge calls ─────────────────────────────────────────────────────────────────

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def login(self) -> str | None:
        return login_of(self.auth_identity)

    @property
    def grant(self) -> str:
        return _text((self.auth_identity.get("agent") or {}).get("grant"))

    @property
    def has_event_sink(self) -> bool:
        return self._on_event is not None

    def set_event_sink(self, on_event: Callable[[dict], None] | None) -> None:
        """Route every non-response frame to *on_event* from now on (called on the emitting thread)."""
        self._on_event = on_event

    def expect(self, rid: str) -> _Pending:
        """Register an in-flight call under *rid* before it is dispatched. Raises once closed."""
        with self._lock:
            if self._closed:
                raise ConnectionError("the agent transport is closed")
            pending = self._pending[rid] = _Pending()
            return pending

    def forget(self, rid: str) -> None:
        with self._lock:
            self._pending.pop(rid, None)

    def release(self) -> tuple[int, int]:
        """Close and leave every session this connection is attached to, through the gateway's own
        disconnect teardown (``_close_sessions_for_transport``): a session another client still shows keeps
        streaming to it, one left clientless is parked for the grace-windowed reap (or torn down when it was
        opened ``close_on_disconnect``). Returns ``(reaped, detached)``. Idempotent. May block."""
        with self._lock:
            if self._released:
                return 0, 0
            self._released = True
        self.close()
        from tui_gateway import server

        server.unregister_live_transport(self)  # also drops the server-request advertisement
        try:
            # The teardown a socket's disconnect runs; "ws_disconnect" is its automatic-cleanup reason.
            return server._close_sessions_for_transport(self, end_reason="ws_disconnect")
        except Exception:  # noqa: BLE001 - a failed teardown leaves a dead peer the reaper handles
            logger.exception("agent transport: session teardown failed")
            return 0, 0
