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
    # The bot relay: its live-chat delivery is the gateway's own dispatch (``_INTERNAL_DISPATCH``).
    "bot_relay.deliver": {"profile": "marker", "message": "marker relayed"},
    "bot_relay.outbox.drain": {},
    "bot_relay.reply": {"id": "marker", "reply": "marker"},
    "bot_relay.roster.sync": {"agents": []},
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


@pytest.mark.parametrize("extra", [
    {"display_kind": "hidden"},
    {"surface": "hud"},
    {"voice_context": "marker spoken"},
    {"title_preview": "marker preview"},
    {"interrupted": True},
    {"_turn_author": {"user_id": "marker"}},
    {"_replayed_turn": {"author": "marker"}},
    {"truncate_before_row_id": None},
], ids=["display_kind", "surface", "voice_context", "title_preview", "interrupted", "turn_author", "replayed_turn",
        "null_rewind"])
def test_an_agents_submit_carries_nothing_but_its_text(gateway, extra):
    """An allowlist (``agent_guard.AGENT_SUBMIT_PARAMS``), not a list of what is refused: any other key is 4033,
    whatever its value, and nothing runs."""
    before = len(gateway.db.get_messages(KEY, include_inactive=True))
    response = _dispatch(_agent(gateway), "prompt.submit", {"session_id": SID, "text": "marker reply", **extra})
    assert response.get("error", {}).get("code") == 4033, response
    assert "agent connected through MCP" in response["error"]["message"]
    assert gateway.session.get("running") is False and gateway.agent.texts == []
    assert len(gateway.db.get_messages(KEY, include_inactive=True)) == before


def test_the_gateways_own_dispatch_on_an_agents_connection_is_not_the_agents_submit(gateway):
    """``_INTERNAL_DISPATCH`` (a relayed bot DM, a hosted room) still carries its in-process keys on a thread whose
    current connection is an agent's."""
    from tui_gateway.session_transports import _internal_dispatch
    from tui_gateway.transport import bind_transport, reset_transport

    token = bind_transport(_agent(gateway))
    try:
        with _internal_dispatch():
            response = server._methods["prompt.submit"](
                "internal", {"session_id": SID, "text": "marker internal", "title_preview": "marker"})
    finally:
        reset_transport(token)
    assert response.get("result", {}).get("status") == "streaming", response
    gateway.agent.gate.set()
    assert _until(lambda: "marker internal" in gateway.agent.texts)


def test_a_relay_into_a_live_bot_chat_on_an_agents_connection_queues_unattributed(gateway):
    """The relay's own submit into a live Bot Chat (``methods_bot_relay``: ``queued``, a ``DeliveryAuthor``, under
    ``_internal_dispatch``) with an agent's connection current: still the gateway's, so it queues behind the running
    turn as the relayed bot's, names neither the agent nor its person, and pins no connection."""
    from tools.bot_relay import DeliveryAuthor
    from tui_gateway.session_transports import _internal_dispatch
    from tui_gateway.transport import bind_transport, reset_transport

    bot = {"id": "bot:marker", "name": "marker", "is_bot": True}
    assert gateway.app.call("prompt.submit", {"session_id": SID, "text": "marker gated"})["result"]["status"] \
        == "streaming"
    agent = _agent(gateway)
    assert _dispatch(agent, "bot_relay.deliver", {"profile": "marker", "message": "marker relayed"})["error"][
        "code"] == 4033
    token = bind_transport(agent)
    try:
        with _internal_dispatch():
            response = server._methods["prompt.submit"]("relay", {
                "session_id": SID, "text": "marker relayed", "queued": True, "_turn_author": DeliveryAuthor(bot)})
    finally:
        reset_transport(token)
    assert response.get("result", {}).get("status") == "queued", response
    queued = gateway.session["queued_prompt"]
    assert queued["text"] == "marker relayed" and queued["turn_author"] == bot
    assert "turn_agent" not in queued and "turn_auth_user" not in queued
    assert queued["transport"] is not agent
    gateway.agent.gate.set()
    assert _until(lambda: "marker relayed" in gateway.agent.texts)


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


def test_what_an_agent_may_send_to_each_method_is_pinned():
    """The keys an agent may send to each allowed method (``agent_guard.AGENT_PARAMS``): exactly what the bridge
    sends. Widening one is a security decision, like adding a method."""
    from tui_gateway.agent_guard import AGENT_PARAMS
    from tui_gateway.mcp_bridge import rpc

    assert AGENT_PARAMS == {
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
    assert rpc.ALLOWED_METHODS == frozenset(AGENT_PARAMS)


@pytest.mark.parametrize("method, params", [
    ("session.create", {"profile": "default", "messages": [{"role": "user", "content": "marker seeded"}]}),
    ("session.create", {"profile": "default", "hidden": True}),
    ("session.create", {"profile": "default", "parent_session_id": KEY}),
    ("session.create", {"profile": "default", "room_plumbing": True}),
    ("session.create", {"profile": "default", "model": "marker/model", "provider": "marker"}),
    ("session.create", {"profile": "default", "close_on_disconnect": True}),
    ("session.create", {"profile": "default", "follow_profile_config": True}),
    ("session.resume", {"session_id": KEY, "profile": "default", "close_on_disconnect": True}),
    ("session.resume", {"session_id": KEY, "eager_build": True}),
    ("session.resume", {"session_id": KEY, "source": "marker"}),
    ("client.capabilities", {"server_requests": True, "confirm": ["plain"]}),
], ids=["messages", "hidden", "parent", "room_plumbing", "model", "create_close_on_disconnect",
        "follow_profile_config", "resume_close_on_disconnect", "eager_build", "source", "confirm"])
def test_an_agent_may_send_only_what_the_bridge_sends(gateway, monkeypatch, method, params):
    """Past the bridge: the handler itself refuses an agent any key outside ``AGENT_PARAMS`` (4033), before it
    creates, resumes or records anything."""
    from tui_gateway import server_requests

    created: list = []
    monkeypatch.setattr(server, "_create_session", lambda rid, p, **_k: created.append(p) or {"result": {}})
    sessions_before = dict(server._sessions)
    advertised: list = []
    real_advertise = server_requests.advertise
    monkeypatch.setattr(server_requests, "advertise",
                        lambda *a, **k: advertised.append(a) or real_advertise(*a, **k))
    response = _dispatch(gateway.connect(), method, params)
    assert response.get("error", {}).get("code") == 4033, response
    assert "agent connected through MCP" in response["error"]["message"]
    assert created == [] and advertised == [] and server._sessions == sessions_before


def test_the_person_may_still_create_with_every_parameter(gateway, monkeypatch):
    created: list = []
    monkeypatch.setattr(server, "_create_session", lambda rid, p, **_k: created.append(p) or {
        "jsonrpc": "2.0", "id": rid, "result": {"marker": True}})
    from tui_gateway.transport import bind_transport, reset_transport

    token = bind_transport(gateway.app)
    try:
        server._methods["session.create"]("person", {"profile": "default", "hidden": True, "title": "marker"})
    finally:
        reset_transport(token)
    assert created == [{"profile": "default", "hidden": True, "title": "marker"}]


def test_the_gateways_own_create_on_an_agents_connection_is_not_the_agents(gateway, monkeypatch):
    """A hosted room's ``session.create`` (hidden, room plumbing) under ``_internal_dispatch`` is the gateway's."""
    from tui_gateway.session_transports import _internal_dispatch
    from tui_gateway.transport import bind_transport, reset_transport

    created: list = []
    monkeypatch.setattr(server, "_create_session", lambda rid, p, **_k: created.append(p) or {
        "jsonrpc": "2.0", "id": rid, "result": {"marker": True}})
    token = bind_transport(_agent(gateway))
    try:
        with _internal_dispatch():
            server._methods["session.create"]("internal", {"profile": "default", "hidden": True, "room_plumbing": True})
    finally:
        reset_transport(token)
    assert created == [{"profile": "default", "hidden": True, "room_plumbing": True}]
