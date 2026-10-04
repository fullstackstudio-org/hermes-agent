"""The gateway's MCP endpoint, in process: an agent acting for its signed-in person speaks the same
JSON-RPC protocol a WebSocket client speaks, through the same handlers and the same access rules.

* :mod:`.transport` -- :class:`~.transport.AgentTransport`, the connection object. Its ``auth_identity`` is
  the person plus the agent marker (``{"provider", "user_id", "user_name", ["profile"], "agent": {"kind":
  "mcp", "client", "grant"}}``), minted by the bridge from a verified grant and never from RPC params; the
  gateway treats it as that person's signed-in client with the marker beside them.
* :mod:`.rpc` -- :func:`~.rpc.call`, the only way the bridge talks to the gateway: ``server.dispatch(req,
  transport)`` for the methods of an allowlist, never ``_internal_dispatch`` and never a handler directly.
* :mod:`.turns` -- :class:`~.turns.TurnWatch`, one per turn the agent submitted: it keeps the transport
  attached for the turn, buffers what the turn streams and answers ``wait()`` with the turn's status.

None of these modules imports the ``mcp`` SDK (an optional extra); only the server module of the endpoint
does. Leaf idiom as in the rest of ``tui_gateway``: the gateway's own modules are imported inside the
functions that need them.
"""
