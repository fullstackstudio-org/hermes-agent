"""The embedded Chat tab's PTY credential (``ws_tickets.mint_pty_credential``).

On a gated dashboard each ``/api/pty`` gets a credential of its own, carrying the login that opened it, so
the PTY child's gateway connection is that person (and the gateway's access rules, throttle and audit
apply). It is revoked when the PTY ends; a kept-alive PTY is never shared between logins; session-token
mode is unchanged.
"""

from __future__ import annotations

import asyncio

import pytest

from hermes_cli import web_server
import hermes_cli.web_server_chat as _web_server_chat
from hermes_cli.dashboard_auth.ws_tickets import (
    TicketInvalid, _reset_for_tests, consume_pty_credential, mint_pty_credential)


class FakeBridge:
    def __init__(self):
        self.written = bytearray()
        self.alive = True

    def read(self, timeout):
        return b""

    async def write(self, data):
        self.written.extend(data)
        return True

    def resize(self, cols, rows):
        pass

    def close(self):
        self.alive = False


@pytest.fixture
def harness(monkeypatch):
    """/api/pty with a fake PTY. ``?as=<provider>:<id>`` signs the browser socket in as that login."""
    _reset_for_tests()
    seen: list[dict] = []
    bridges: list[FakeBridge] = []

    def fake_spawn(argv, cwd=None, env=None):
        bridges.append(FakeBridge())
        return bridges[-1]

    def fake_auth(ws):
        login = ws.query_params.get("as", "")
        if login:
            provider, user_id = login.split(":", 1)
            ws._hermes_auth_identity = {"user_id": user_id, "provider": provider}
        return None, "test"

    async def fake_argv(**kw):
        seen.append(kw)
        return (["x"], "/tmp", {})

    monkeypatch.setattr(_web_server_chat.PtyBridge, "spawn", staticmethod(fake_spawn))
    monkeypatch.setattr(_web_server_chat, "_ws_auth_reason", fake_auth)
    monkeypatch.setattr(_web_server_chat, "_ws_host_origin_reason", lambda ws: None)
    monkeypatch.setattr(_web_server_chat, "_ws_client_reason", lambda ws: None)
    monkeypatch.setattr(_web_server_chat, "_resolve_chat_argv_async", fake_argv)
    prev = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.auth_required = True
    try:
        yield seen, bridges
    finally:
        web_server.app.state.auth_required = prev
        _web_server_chat.PTY_REGISTRY._sessions.clear()
        _reset_for_tests()


def _client():
    from starlette.testclient import TestClient
    return TestClient(web_server.app)


def test_a_one_shot_pty_carries_its_login_and_the_credential_dies_with_it(harness):
    seen, _bridges = harness
    with _client().websocket_connect("/api/pty?as=stub:alice") as ws:
        ws.send_bytes(b"hi")
        credential = seen[-1]["pty_credential"]
        assert consume_pty_credential(credential) == {"user_id": "alice", "provider": "stub"}
    with pytest.raises(TicketInvalid):
        consume_pty_credential(credential)


@pytest.mark.asyncio
async def test_a_kept_alive_pty_is_one_logins_and_its_credential_ends_with_it(harness):
    seen, bridges = harness
    client = _client()
    with client.websocket_connect("/api/pty?as=stub:alice&attach=TOK1") as ws:
        ws.send_bytes(b"a")
    alice = seen[-1]["pty_credential"]
    # The same attach token from another login is another PTY, with that login's credential.
    with client.websocket_connect("/api/pty?as=stub:bob&attach=TOK1") as ws:
        ws.send_bytes(b"b")
    bob = seen[-1]["pty_credential"]
    assert len(bridges) == 2
    assert consume_pty_credential(bob)["user_id"] == "bob"
    # Alice reattaching reuses her PTY; the credential minted for the reattach is dropped at once.
    with client.websocket_connect("/api/pty?as=stub:alice&attach=TOK1") as ws:
        ws.send_bytes(b"c")
    reattach = seen[-1]["pty_credential"]
    assert len(bridges) == 2 and bytes(bridges[0].written) == b"a\x0cc"
    assert consume_pty_credential(alice)["user_id"] == "alice"
    with pytest.raises(TicketInvalid):
        consume_pty_credential(reattach)
    # The PTY ends (reaped, shut down): its credential ends with it.
    await _web_server_chat.PTY_REGISTRY.close_all()
    for credential in (alice, bob):
        with pytest.raises(TicketInvalid):
            consume_pty_credential(credential)


@pytest.mark.asyncio
async def test_a_pty_whose_child_exits_revokes_its_credential():
    from hermes_cli.pty_session import PtySession
    from hermes_cli.dashboard_auth.ws_tickets import revoke_pty_credential

    class ExitedBridge(FakeBridge):
        def read(self, timeout):
            return None  # EOF: the child exited

    credential = mint_pty_credential(user_id="alice", provider="stub")
    session = PtySession("k", ExitedBridge(), buffer_cap=1024, read_timeout=0.01)
    session.on_end.append(lambda: revoke_pty_credential(credential))
    await session.start()
    await asyncio.wait_for(session._drain_task, 5)
    with pytest.raises(TicketInvalid):
        consume_pty_credential(credential)


def test_a_credential_read_from_one_pty_cannot_claim_another_login(harness):
    seen, _bridges = harness
    with _client().websocket_connect("/api/pty?as=stub:alice") as ws:
        ws.send_bytes(b"x")
        credential = seen[-1]["pty_credential"]
        # Whoever holds the value IS alice, never anybody else, and only while the PTY runs.
        assert consume_pty_credential(credential) == {"user_id": "alice", "provider": "stub"}
    with pytest.raises(TicketInvalid):
        consume_pty_credential(credential)


def test_session_token_mode_is_unchanged(harness):
    seen, _bridges = harness
    web_server.app.state.auth_required = False
    with _client().websocket_connect("/api/pty?as=stub:alice") as ws:
        ws.send_bytes(b"x")
    assert "pty_credential" not in seen[-1]


def test_gated_without_a_login_hands_out_no_gateway_url(harness):
    seen, _bridges = harness
    with _client().websocket_connect("/api/pty") as ws:
        ws.send_bytes(b"x")
    assert "pty_credential" not in seen[-1]
    assert _web_server_chat._build_gateway_ws_url(None) is None
