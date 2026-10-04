"""Events for one signed-in person: written to every live connection whose minted login is that user.

``_broadcast_global_event`` reaches every connected client, which is wrong for anything about one
person's account: another login on the same gateway must not learn that this person's passkeys changed,
or what they are called. The login of a connection is the identity minted at the WebSocket upgrade
(``server._transport_auth_user_id``); a connection without one (legacy token, stdio, the compute-host
pipe) never receives a user event.

Delivery is per process, like every broadcast: the dashboard process owns the WebSocket connections and
is where the passkey routes run.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _deliver(user_id: str, frame: dict) -> int:
    from tui_gateway import server

    with server._live_transports_lock:
        targets = list(server._live_transports)
    delivered = 0
    for transport in targets:
        if server._transport_auth_user_id(transport) != user_id:
            continue
        try:
            transport.write(frame)
            delivered += 1
        except Exception:  # one wedged peer must not stall the rest; disconnect teardown unregisters it
            logger.debug("user event write failed type=%s", frame["params"]["type"], exc_info=True)
    return delivered


def announce_passkey_changed(user_id: str, payload: dict) -> int:
    """``passkey.changed`` to *user_id*'s live connections; returns how many were written to."""
    if not user_id:
        return 0
    from tui_gateway.contracts import registry

    registry.check_payload("passkey.changed", payload)
    frame = {"jsonrpc": "2.0", "method": "event", "params": {"type": "passkey.changed", "session_id": "",
                                                              "payload": payload}}
    return _deliver(user_id, frame)


def announce_mcp_changed(user_id: str, payload: dict) -> int:
    """``mcp.changed`` to *user_id*'s live connections; returns how many were written to."""
    if not user_id:
        return 0
    from tui_gateway.contracts import registry

    registry.check_payload("mcp.changed", payload)
    frame = {"jsonrpc": "2.0", "method": "event", "params": {"type": "mcp.changed", "session_id": "",
                                                              "payload": payload}}
    return _deliver(user_id, frame)
