"""Transport liveness + build capability probes (``methods_voice.py`` hosts them)."""

from __future__ import annotations

from pydantic import Field

from .base import JsonValue, Params, Result
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
    per_message_author: bool | None = None
    #: The gateway may stamp ``via`` on a row's ``author`` / ``replayed_by`` (an agent sent it through MCP).
    per_message_author_via: bool | None = None
    transcript_row_identity: bool | None = None


method("gateway.capabilities", params=PingParams, result=GatewayCapabilitiesResult,
       doc="What THIS build enforces (a client withholds a feature unless advertised).")


class ConfirmPasskeyAdvertisement(Params):
    """Second ``client.capabilities`` call, with ``passkey`` in ``confirm``: how this client runs the
    ceremony, ``{v, kind, rp_id}``. ``v``: ``1``, or ``2`` from a client that also computes the version-2 text
    digest of a request with ``fields`` (contract §4.1; send it only when the result's
    ``confirm_passkey.versions`` lists 2). A ``v: 2`` client takes ``v: 1`` and ``v: 2`` frames; a ``v: 1``
    client is never sent a ``v: 2`` frame. ``kind``: ``native`` (an app under a native RP) or ``web`` (a browser;
    ``rp_id`` is its host). Deliberately permissive here (any value, extra keys allowed) and checked in code
    (``confirm_passkey.accept_advertisement``): a shape this gateway does not accept, including a later
    client's extra field, only drops ``passkey`` and never fails the call (and ``plain`` with it)."""

    model_config = Params.model_config | {"extra": "allow"}

    #: ``1`` or ``2``.
    v: JsonValue = None
    #: ``"native"`` or ``"web"``.
    kind: JsonValue = None
    #: The RP id the client asserts under.
    rp_id: JsonValue = None


class ClientCapabilitiesParams(Params):
    #: The client answers server→client requests (clarify, approval, sudo, …) — with a result or a -32601
    #: error for methods it has no handler for. A WebSocket client that never says so is treated as a
    #: build older than server→client requests and every such request fails fast for it.
    server_requests: bool = False
    #: The ``confirm`` levels this connection can answer (``"plain"``, ``"passkey"``). Optional and additive:
    #: absent means none, and the gateway never sends ``confirm`` to this connection. Only read together
    #: with ``server_requests: true``. Levels this backend does not accept are ignored: unknown ones, and
    #: ``passkey`` without an accepted ``confirm_passkey`` or from a connection with no signed-in user. Send
    #: it in a SECOND call, after the first one's result lists ``confirm``: a backend older than ``confirm``
    #: rejects the unknown key (4000) and the whole call.
    confirm: list[str] | None = None
    #: Required for ``passkey`` to be accepted (contract §8). Send it only after a result carried
    #: ``confirm_passkey`` with ``enabled: true``.
    confirm_passkey: ConfirmPasskeyAdvertisement | None = None
    #: This connection shows a ``confirm``'s structured ``fields`` (every ``ConfirmFieldKind``). Optional and
    #: additive: absent or false means a ``confirm`` with fields is never sent to it. Only read together with
    #: ``server_requests: true`` and at least one accepted ``confirm`` level. Send it only after a result
    #: carried the key ``confirm_fields`` (a backend that knows it always sends it): an older one rejects
    #: the unknown key (4000) and the whole call. Deliberately permissive here, like ``confirm_passkey``: any
    #: value is taken, only exactly ``true`` counts (``server_requests.advertise``), and anything else only
    #: leaves the fields off and never fails the call (and the levels with it).
    confirm_fields: JsonValue = None
    #: The interactive request methods (``input.form``, ``input.file``, ``review.draft``, …) this connection
    #: can SHOW on this device; it lists nothing it cannot do. Optional and additive: absent means none, and
    #: the gateway never sends such a method to this connection. Only read together with
    #: ``server_requests: true``; methods this backend does not know are ignored. Send it in a SECOND call,
    #: only after the first result's ``server_requests`` lists one of them: a backend older than the key
    #: rejects it (4000) and the whole call, ``confirm`` levels included.
    requests: list[str] | None = Field(default=None, max_length=32)


class ConfirmPasskeyRps(Result):
    #: Accepted native RP ids (``confirm.passkey.native_rps``) and web RP ids (hosts of accepted base URLs).
    native: list[str]
    web: list[str]


class ConfirmPasskeyCapability(Result):
    """Whether this connection may advertise ``passkey`` (contract §8). ``reason`` is ``""`` exactly when
    ``enabled``; otherwise ``disabled``, ``no_base_url``, ``private_origin``, ``no_identity`` (this connection
    has no signed-in user) or ``store_unavailable``. ``gateway_id`` (base64url, 16 bytes) is ``""`` while the
    level is disabled."""

    v: int
    enabled: bool
    reason: str
    gateway_id: str
    rp: ConfirmPasskeyRps
    #: The ``confirm_passkey.v`` values this backend accepts in an advertisement (``[1, 2]``); absent from a
    #: backend that knows version 1 only (send ``v: 1`` to it).
    versions: list[int] | None = None


class ClientCapabilitiesResult(Result):
    #: Server→client request methods this backend may send.
    server_requests: list[str]
    #: The ``confirm`` levels this backend accepted from this connection's advertisement (``[]`` when none).
    confirm: list[ConfirmLevel] = Field(default_factory=list)
    #: The level ``passkey`` as this connection sees it (a build that knows the level always sends it).
    confirm_passkey: ConfirmPasskeyCapability | None = None
    #: Whether this backend accepted this connection's ``confirm_fields: true`` (false until it did). A backend
    #: that knows the key always sends it; one that does not omits it.
    confirm_fields: bool | None = None
    #: The interactive request methods this backend accepted from this connection's ``requests`` (``[]``
    #: when none, or from a backend older than the key).
    requests: list[str] = Field(default_factory=list)


method("client.capabilities", params=ClientCapabilitiesParams, result=ClientCapabilitiesResult,
       doc="What the calling client handles, sent once per connection (after gateway.ready); returns the "
           "server→client request methods this backend may send.")
