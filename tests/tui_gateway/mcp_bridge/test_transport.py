"""``AgentTransport`` and ``rpc.call``: an agent's connection is a signed-in client with the agent marker,
and the bridge reaches the gateway only through ``server.dispatch`` with an allowlist (plan D5, D6, D9).
Every payload is a harmless marker."""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time

import pytest

from tui_gateway.mcp_bridge import rpc
from tui_gateway.mcp_bridge.transport import AgentTransport, validate_identity
import tui_gateway.server as server

from .conftest import CLIENT, ROBIN, SAM, SID, identity


@pytest.fixture()
def dispatched(monkeypatch):
    """Every request ``server.dispatch`` is handed, in order."""
    seen: list[dict] = []
    real = server.dispatch

    def spy(req, transport=None):
        seen.append(req)
        return real(req, transport)

    monkeypatch.setattr(server, "dispatch", spy)
    return seen


# ── the identity ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("broken", [
    None, {}, {"provider": "oidc", "user_id": "user-a"},
    {"provider": "oidc", "user_id": "user-a", "agent": {"kind": "mcp", "client": CLIENT}},
    {"provider": "oidc", "user_id": "user-a", "agent": {"kind": "other", "client": CLIENT, "grant": "g"}},
    {"provider": "", "user_id": "user-a", "agent": {"kind": "mcp", "client": CLIENT, "grant": "g"}},
    {"provider": "oidc", "user_id": "user-a", "agent": {"kind": "mcp", "client": object(), "grant": "g"}},
])
def test_an_agent_transport_without_a_person_or_a_marker_does_not_exist(broken):
    with pytest.raises(ValueError):
        AgentTransport(broken)


def test_the_gateway_sees_the_person_with_the_marker_beside_them():
    source = identity()
    transport = AgentTransport(source)
    source["agent"]["client"] = "changed afterwards"
    assert transport.auth_identity == validate_identity(identity())
    assert server._transport_auth_user(transport) == ROBIN
    assert server._transport_agent(transport) == {"kind": "mcp", "client": CLIENT}
    assert transport.login == ROBIN[0] and transport.grant == "grant-g1"


def test_liveness_is_what_the_gateways_helpers_read():
    transport = AgentTransport(identity())
    assert server._transport_is_live_peer(transport) and not server._transport_is_dead(transport)
    transport.close()
    assert server._transport_is_dead(transport) and not server._transport_is_live_peer(transport)
    assert transport.write({"jsonrpc": "2.0", "method": "event", "params": {}}) is False


# ── write() ─────────────────────────────────────────────────────────────────────────────────


def test_responses_go_to_their_call_and_everything_else_to_the_sink():
    events = []
    transport = AgentTransport(identity(), events.append)
    pending = transport.expect("mcp-1")
    assert transport.write({"jsonrpc": "2.0", "id": "mcp-1", "result": {"marker": True}}) is True
    assert pending.wait(0) == (True, {"jsonrpc": "2.0", "id": "mcp-1", "result": {"marker": True}})
    # A response nobody waits for is dropped; it is never mistaken for an event.
    assert transport.write({"jsonrpc": "2.0", "id": "mcp-2", "result": {}}) is True
    request = {"jsonrpc": "2.0", "id": "srq-1", "method": "clarify", "params": {"session_id": SID}}
    event = {"jsonrpc": "2.0", "method": "event", "params": {"type": "message.start", "session_id": SID}}
    transport.write(request)
    transport.write(event)
    assert events == [request, event]


def test_a_broken_sink_never_breaks_the_emitting_thread():
    def boom(_frame):
        raise RuntimeError("marker")

    transport = AgentTransport(identity(), boom)
    assert transport.write({"jsonrpc": "2.0", "method": "event", "params": {}}) is True


def test_close_fails_every_pending_call():
    transport = AgentTransport(identity())
    pending = transport.expect("mcp-1")
    transport.close()
    assert pending.wait(0) == (True, None)
    with pytest.raises(ConnectionError):
        transport.expect("mcp-2")


# ── rpc.call ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", [
    "session.close", "session.delete", "session.title", "session.set_hidden", "config.set", "profiles.configure",
    "profiles.create", "profiles.set_asset", "slash.exec", "approval.respond", "clarify.lock", "fs.read",
    "prompt.background", "session.history", "unknown.method"])
def test_a_method_outside_the_allowlist_is_refused_before_dispatch(method, dispatched):
    transport = AgentTransport(identity())
    with pytest.raises(rpc.DisallowedCall):
        rpc.call(transport, method, {"session_id": SID})
    assert dispatched == []


@pytest.mark.parametrize("method,params", [
    ("prompt.submit", {"session_id": SID, "text": "marker", "_turn_author": {"id": "x"}}),
    ("prompt.submit", {"session_id": SID, "text": "marker", "_replayed_turn": None}),
    ("session.create", {"cols": 80, "meta": {"_hosted_task": {}}}),
    ("session.events.since", {"session_id": SID, "list": [{"_x": 1}]}),
    ("client.capabilities", {"server_requests": True, "confirm": ["plain"]}),
    ("client.capabilities", {"server_requests": False}),
    ("request.answer", {"id": "srq-1", "result": {"choice": "once"}}),
    ("request.answer", {"id": "srq-1", "result": {"value": "marker"}}),
    ("request.answer", {"id": "srq-1", "result": {}}),
    ("request.answer", {"id": "srq-1", "result": {"answers": {"q1": 1}}}),
    ("prompt.submit", {"session_id": SID, "text": object()}),
])
def test_forbidden_parameters_are_refused_before_dispatch(method, params, dispatched):
    transport = AgentTransport(identity())
    with pytest.raises(rpc.DisallowedCall):
        rpc.call(transport, method, params)
    assert dispatched == []


def test_only_an_agent_transport_is_dispatched_on(dispatched):
    from .conftest import AppPeer
    with pytest.raises(rpc.DisallowedCall):
        rpc.call(AppPeer(), "gateway.capabilities")
    assert dispatched == []


def test_capabilities_go_out_once_with_server_requests_and_no_confirm_level(gateway, dispatched):
    from tui_gateway import server_requests
    transport = gateway.connect()
    assert rpc.call(transport, "gateway.capabilities")["per_message_author_via"] is True
    rpc.call(transport, "gateway.capabilities")
    rpc.call(transport, "session.events.since", {"session_id": SID, "last_seen": 0})
    methods = [req["method"] for req in dispatched]
    assert methods == ["client.capabilities", "gateway.capabilities", "gateway.capabilities", "session.events.since"]
    assert dispatched[0]["params"] == {"server_requests": True}
    assert server_requests.answers_requests(transport)
    assert server_requests.confirm_levels(transport) == frozenset()


def test_a_pooled_handler_answers_through_the_transport(gateway):
    transport = gateway.connect()
    assert "session.active_list" in server._LONG_HANDLERS
    server._attach_session_transport(gateway.session, transport)
    rows = rpc.call(transport, "session.active_list", {})["sessions"]
    assert [(row["id"], row["status"]) for row in rows] == [(SID, "idle")]


def test_a_slow_handler_times_out_and_its_late_answer_is_dropped(gateway, monkeypatch):
    release = threading.Event()
    real = server._methods["session.active_list"]

    def slow(rid, params):
        release.wait(5)
        return real(rid, params)

    monkeypatch.setitem(server._methods, "session.active_list", slow)
    transport = gateway.connect()
    rpc.ensure_capabilities(transport)
    with pytest.raises(rpc.RpcTimeout):
        rpc.call(transport, "session.active_list", {}, timeout=0.05)
    release.set()
    time.sleep(0.2)
    assert transport._pending == {}


def test_another_persons_live_session_answers_4001_like_an_unknown_one(gateway):
    sam = gateway.connect(SAM)
    for method, params in (("session.events.since", {"session_id": SID, "last_seen": 0}),
                           ("session.interrupt", {"session_id": SID}),
                           ("prompt.submit", {"session_id": SID, "text": "marker"})):
        with pytest.raises(rpc.RpcError) as refused:
            rpc.call(sam, method, params)
        assert (refused.value.code, refused.value.message) == (4001, "session not found")
    assert gateway.agent.texts == []


def test_nothing_the_calling_thread_bound_leaks_into_the_request(gateway):
    """An internal-dispatch flag (or any other ContextVar) on the caller's thread would bypass the access
    rules; every call runs in a fresh context."""
    sam = gateway.connect(SAM)
    with server._internal_dispatch():
        with pytest.raises(rpc.RpcError) as refused:
            rpc.call(sam, "session.events.since", {"session_id": SID, "last_seen": 0})
    assert refused.value.code == 4001


def test_a_retiring_gateway_is_gateway_restarting(gateway, monkeypatch):
    from hermes_cli.backend_retirement import retirement

    @contextlib.contextmanager
    def refused():
        yield False

    monkeypatch.setattr(retirement, "work", refused)
    transport = gateway.connect()
    with pytest.raises(rpc.GatewayRestarting) as restarting:
        rpc.call(transport, "gateway.capabilities")
    assert restarting.value.retry_after_seconds == rpc.RESTART_RETRY_AFTER_S


def test_release_leaves_every_session_and_closes(gateway):
    transport = gateway.connect()
    server._attach_session_transport(gateway.session, transport)
    assert server._session_transport_contains(gateway.session, transport)
    transport.release()
    assert transport.closed
    assert not server._session_transport_contains(gateway.session, transport)
    assert server._session_transport_contains(gateway.session, gateway.app)
    with pytest.raises(rpc.TransportClosed):
        rpc.call(transport, "gateway.capabilities")
    assert transport.release() == (0, 0)


# ── liveness: the agent's connection is a client that answers server requests ────────────────


def test_an_agent_that_advertised_counts_as_a_client_that_answers(gateway):
    from tui_gateway.ws import WSTransport
    loop = asyncio.new_event_loop()
    try:
        old_app = WSTransport(object(), loop, peer="old-app",
                              auth_identity={"provider": "oidc", "user_id": "user-a", "user_name": "Robin"})
        server._detach_session_transport(gateway.session, gateway.app)
        server._attach_session_transport(gateway.session, old_app)
        # A WebSocket client that never advertised: the request fails fast (#112548) ...
        assert server._session_client_answers_requests(SID) is False
        transport = gateway.connect()
        server._attach_session_transport(gateway.session, transport)
        rpc.ensure_capabilities(transport)
        # ... unless an agent that answers (clarify) is attached too.
        assert server._session_client_answers_requests(SID) is True
        transport.close()
        assert server._session_client_answers_requests(SID) is False
    finally:
        loop.close()
