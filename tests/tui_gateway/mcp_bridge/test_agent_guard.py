"""The gateway's own refusals for an agent acting for its person through MCP (``tui_gateway/agent_guard.py``).

The bridge never dispatches these methods (its allowlist, ``mcp_bridge/rpc.py``), but the handlers do not rest
on that: each one that approves, unlocks, provides or removes a secret, runs a command, or changes a setting,
a permission or billing answers an agent's connection 4033 before it does anything. Dispatched here directly
on an ``AgentTransport`` (``server.dispatch``, past the bridge), with params the method's contract accepts.
Every payload is a harmless marker, and the billing calls are stubbed so a missing refusal fails fast instead
of starting a device flow.
"""

from __future__ import annotations

import pytest

import tui_gateway.server as server

from .conftest import SID

#: method -> params its contract accepts. Each would act if it reached its body as the person.
GUARDED = {
    "approval.respond": {"session_id": SID, "choice": "once"},
    "vault.unlock": {"name": "marker", "password": "marker-passphrase"},
    "vault.add": {"kind": "login", "label": "marker", "secret": {"password": "marker-secret"}},
    "vault.remove": {"id": "marker"},
    "vault.lock": {},
    "vault.source.set": {"name": "marker", "enabled": False},
    "connection.respond": {"owner": {"type": "session", "session_id": SID}, "op_id": "marker", "result": {}},
    "connectors.connect": {"owner": {"type": "session", "session_id": SID}, "connectors": ["marker"]},
    "connectors.policy.set": {"change": {"type": "tools", "connector": "marker", "disabled_tools": []},
                              "expected_revision": "0" * 26},
    "connectors.accounts.remove": {"connection_id": "marker"},
    "slash.exec": {"session_id": SID, "command": "/yolo"},
    "command.dispatch": {"session_id": SID, "name": "yolo", "arg": ""},
    "cli.exec": {"argv": ["--version"]},
    "shell.exec": {"command": "echo marker"},
    "config.set": {"session_id": SID, "key": "yolo", "value": "on"},
    "model.save_key": {"slug": "marker", "api_key": "marker-key"},
    "model.disconnect": {"slug": "marker"},
    "profiles.create": {"name": "marker"},
    "billing.step_up": {},
    "billing.charge": {"amount_usd": 1},
    "subscription.change": {"subscription_type_id": "marker"},
}


def _dispatch(transport, method, params):
    rid = f"guard-{method}"
    pending = transport.expect(rid)
    response = server.dispatch({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, transport)
    if response is None:
        settled, response = pending.wait(10)
        assert settled, f"no answer to {method}"
    transport.forget(rid)
    return response


@pytest.mark.parametrize("method", sorted(GUARDED))
def test_an_agent_is_refused_by_the_handler_itself(gateway, monkeypatch, method):
    import tools.connectors as connectors
    from tui_gateway import server_requests

    monkeypatch.setattr(connectors, "connectors_available", lambda: True)  # past the feature gate, to the handler
    monkeypatch.setattr(server, "_billing_call", lambda rid, _call, extra=None: {
        "jsonrpc": "2.0", "id": rid, "result": {"reached": "the billing call"}})
    transport = gateway.connect()
    server_requests.advertise(transport, True)
    response = _dispatch(transport, method, GUARDED[method])
    assert "error" in response, response
    assert response["error"]["code"] == 4033, response
    assert "agent connected through MCP" in response["error"]["message"]


@pytest.mark.parametrize("method", ["vault.lock", "config.set"])
def test_the_person_is_not_refused(gateway, method):
    response = gateway.app.call(method, GUARDED[method])
    assert "agent connected through MCP" not in str(response)
