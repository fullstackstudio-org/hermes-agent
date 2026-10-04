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

from .conftest import KEY, SID

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
    # Plan "Agent prompts": what would let an agent act as the person beside a prompt of its own.
    "prompt.background": {"session_id": SID, "text": "marker"},
    "prompt.btw": {"session_id": SID, "text": "marker"},
    "session.steer": {"session_id": SID, "text": "marker"},
    "session.redirect": {"session_id": SID, "text": "marker"},
    "session.delete": {"session_id": "marker-other"},
    "session.close": {"session_id": SID},
    "profiles.configure": {"name": "marker", "description": "marker"},
    "profiles.set_asset": {"name": "marker", "asset": "avatar", "clear": True},
    "free_tier.provision": {},
    "onboarding.reset_setup_profile": {},
    # What would rewrite, shrink, hide, rename or fork the person's chat.
    "session.undo": {"session_id": SID},
    "session.compress": {"session_id": SID},
    "session.set_hidden": {"session_id": SID, "hidden": True},
    "session.title": {"session_id": SID, "title": "marker"},
    "session.branch": {"session_id": SID},
    "session.branch_whole": {"session_id": SID},
    "session.branch_stored": {"parent_session_id": KEY},
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


@pytest.mark.parametrize("method", ["vault.lock", "config.set", "session.title", "session.set_hidden"])
def test_the_person_is_not_refused(gateway, method):
    response = gateway.app.call(method, GUARDED[method])
    assert "agent connected through MCP" not in str(response)


def test_an_agent_may_still_read_a_chats_title(gateway):
    """Only the rename is refused: reading the title acts on nothing."""
    from tui_gateway import server_requests

    transport = gateway.connect()
    server_requests.advertise(transport, True)
    response = _dispatch(transport, "session.title", {"session_id": SID})
    assert "result" in response, response


# ── an agent's prompt.submit (plan: "Agent prompts") ───────────────────────────────────────────────


def _agent(gateway):
    from tui_gateway import server_requests

    transport = gateway.connect()
    server_requests.advertise(transport, True)
    return transport


def _until(predicate, seconds=5.0):
    import time

    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.mark.parametrize("mode", ["interrupt", "steer"])
def test_an_agents_submit_without_queued_never_stops_or_steers_the_persons_turn(gateway, monkeypatch, mode):
    """Past the bridge (which always sends ``queued``): the handler queues an agent's text whatever the busy mode,
    so it neither hard-stops the person's running turn nor steers into it."""
    steered: list = []
    monkeypatch.setattr(server, "_load_busy_input_mode", lambda: mode)
    monkeypatch.setattr(gateway.agent, "steer", lambda text, *_a, **_k: steered.append(text) or True, raising=False)
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    response = _dispatch(_agent(gateway), "prompt.submit", {"session_id": SID, "text": "marker reply"})
    assert response.get("result", {}).get("status") == "queued", response
    assert gateway.agent._interrupt_requested is False
    assert steered == []
    assert gateway.session["queued_prompt"]["text"] == "marker reply"
    gateway.agent.gate.set()
    assert _until(lambda: "marker reply" in gateway.agent.texts)


@pytest.mark.parametrize("extra", [
    {"truncate_before_row_id": 1, "confirm_truncate": True},
    {"truncate_before_user_ordinal": 0, "confirm_truncate": True},
    {"truncate_before_message_id": "marker", "confirm_truncate": True},
    {"confirm_truncate": True},
    {"confirm_empty_truncate": True},
    {"rebind_survivor_row_ids": [1]},
], ids=["row_id", "ordinal", "message_id", "confirm_truncate", "confirm_empty_truncate", "rebind"])
def test_an_agents_submit_may_not_rewind_the_chat(gateway, extra):
    gateway.db.append_message(KEY, "user", "marker person row")
    before = len(gateway.db.get_messages(KEY, include_inactive=True))
    response = _dispatch(_agent(gateway), "prompt.submit", {"session_id": SID, "text": "marker reply", **extra})
    assert response.get("error", {}).get("code") == 4033, response
    assert "agent connected through MCP" in response["error"]["message"]
    assert gateway.session.get("running") is False and gateway.agent.texts == []
    assert len(gateway.db.get_messages(KEY, include_inactive=True)) == before


def test_the_person_may_still_send_without_queued(gateway, monkeypatch):
    monkeypatch.setattr(server, "_load_busy_input_mode", lambda: "interrupt")
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker person"})["result"]["status"] \
        == "queued"
    assert gateway.agent._interrupt_requested is True  # the person's own busy mode still applies to her
    gateway.agent.gate.set()


def test_the_bridge_allowlist_is_pinned():
    """Any method added to what the MCP bridge may dispatch is a security decision: change this list with a
    review of what the method lets an agent do as the person (plan D6, "Agent prompts")."""
    from tui_gateway.mcp_bridge import rpc

    assert rpc.ALLOWED_METHODS == frozenset({
        "gateway.capabilities", "client.capabilities", "profiles.list", "session.create", "session.resume",
        "session.active_list", "session.events.since", "prompt.submit", "session.interrupt", "request.answer"})
    assert rpc.PROMPT_SUBMIT_PARAMS == frozenset({"session_id", "text", "queued"})
