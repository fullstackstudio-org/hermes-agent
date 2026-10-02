"""Transport liveness + build capability probes (``methods_voice.py`` hosts them)."""

from __future__ import annotations

from pydantic import Field

from .base import Params, Result
from .registry import method
from .server_requests import ConfirmLevel


class PingParams(Params):
    pass


class PingResult(Result):
    pong: bool


method("ping", params=PingParams, result=PingResult,
       doc="Cheapest liveness probe; answered on the WS reader thread even while every agent is mid-turn.")


class GatewayCapabilitiesResult(Result):
    per_session_exclusive_submit: bool


method("gateway.capabilities", params=PingParams, result=GatewayCapabilitiesResult,
       doc="What THIS build enforces (a client withholds a feature unless advertised).")


class ClientCapabilitiesParams(Params):
    #: The client answers server→client requests (clarify, approval, sudo, …) — with a result or a -32601
    #: error for methods it has no handler for. A WebSocket client that never says so is treated as a
    #: build older than server→client requests and every such request fails fast for it.
    server_requests: bool = False
    #: The ``confirm`` levels this connection can answer (today only ``"plain"``). Optional and additive:
    #: absent means none, and the gateway never sends ``confirm`` to this connection. Only read together
    #: with ``server_requests: true``. Levels this backend does not accept from clients (unknown ones, and
    #: the reserved ``passkey``) are ignored. Send it in a SECOND call, after the first one's result lists
    #: ``confirm``: a backend older than ``confirm`` rejects the unknown key (4000) and the whole call.
    confirm: list[str] | None = None


class ClientCapabilitiesResult(Result):
    #: Server→client request methods this backend may send.
    server_requests: list[str]
    #: The ``confirm`` levels this backend accepted from this connection's advertisement (``[]`` when none).
    confirm: list[ConfirmLevel] = Field(default_factory=list)


method("client.capabilities", params=ClientCapabilitiesParams, result=ClientCapabilitiesResult,
       doc="What the calling client handles, sent once per connection (after gateway.ready); returns the "
           "server→client request methods this backend may send.")
