"""The dashboard drains running turns BEFORE uvicorn closes its connections.

A real ``uvicorn.Server`` on a loopback ephemeral port runs ``_serve_with_drain``; the exit is requested
through ``server.handle_exit`` -- the function uvicorn installs as its SIGTERM handler -- called directly,
so no signal is sent to anything. The drain (faked here; its behaviour is pinned in
``tests/tui_gateway/test_shutdown_drain.py``) must observe the listener still serving and a client
connection still open, i.e. run before ``server.shutdown()``.
"""

from __future__ import annotations

import asyncio
import signal
import socket

import pytest


async def _app(scope, receive, send):  # minimal ASGI app: lifespan + a plain HTTP 200
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _server():
    import uvicorn

    config = uvicorn.Config(_app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
    return config, uvicorn.Server(config)


def test_drain_runs_while_clients_are_still_connected(monkeypatch):
    from hermes_cli import web_server
    import tui_gateway.server as gateway

    config, server = _server()
    seen: dict = {}

    async def fake_drain(timeout=None, should_abort=None):
        seen["listening"] = any(s.is_serving() for s in server.servers)
        seen["connections"] = len(server.server_state.connections)
        seen["timeout"] = timeout
        seen["abort_now"] = should_abort()
        return {"drained": 0, "interrupted": 0, "waited_s": 0.0}

    monkeypatch.setattr(gateway, "drain_turns_for_shutdown", fake_drain)
    monkeypatch.setattr(web_server, "is_desktop_owned_backend", lambda: False)
    client: list[socket.socket] = []

    def on_started():
        port = server.servers[0].sockets[0].getsockname()[1]
        client.append(socket.create_connection(("127.0.0.1", port)))
        # What SIGTERM does under capture_signals(), without a signal.
        asyncio.get_running_loop().call_later(0.3, server.handle_exit, signal.SIGTERM, None)

    try:
        asyncio.run(asyncio.wait_for(web_server._serve_with_drain(server, config, on_started), 20))
    finally:
        for sock in client:
            sock.close()

    assert seen["listening"] is True, "the drain ran after uvicorn stopped listening"
    assert seen["connections"] >= 1, "the drain ran after uvicorn closed the client connections"
    assert seen["timeout"] is None  # dashboard.shutdown_drain_timeout decides
    assert seen["abort_now"] is False  # one SIGTERM does not cut the drain short
    assert not any(s.is_serving() for s in server.servers)  # ...and shutdown still ran afterwards


def test_desktop_owned_backend_does_not_wait(monkeypatch):
    from hermes_cli import web_server
    import tui_gateway.server as gateway

    calls: list = []

    async def fake_drain(timeout=None, should_abort=None):
        calls.append(timeout)

    monkeypatch.setattr(gateway, "drain_turns_for_shutdown", fake_drain)
    monkeypatch.setattr(web_server, "is_desktop_owned_backend", lambda: True)
    asyncio.run(web_server._drain_turns_before_shutdown(object()))
    assert calls == [0.0]


@pytest.mark.parametrize("state, expected", [
    ({"force_exit": False, "_captured_signals": [signal.SIGTERM]}, False),
    ({"force_exit": True, "_captured_signals": [signal.SIGINT, signal.SIGINT]}, True),
    ({"force_exit": False, "_captured_signals": [signal.SIGTERM, signal.SIGTERM]}, True),
])
def test_repeated_signal_aborts_the_drain(state, expected):
    from types import SimpleNamespace

    from hermes_cli.web_server import _shutdown_drain_should_abort

    assert _shutdown_drain_should_abort(SimpleNamespace(**state)) is expected


def test_failed_drain_does_not_stop_the_shutdown(monkeypatch):
    from hermes_cli import web_server
    import tui_gateway.server as gateway

    async def broken(timeout=None, should_abort=None):
        raise RuntimeError("drain exploded")

    monkeypatch.setattr(gateway, "drain_turns_for_shutdown", broken)
    monkeypatch.setattr(web_server, "is_desktop_owned_backend", lambda: False)
    asyncio.run(web_server._drain_turns_before_shutdown(object()))  # logged, not raised


def test_stop_grace_reads_the_backends_own_home(monkeypatch, tmp_path):
    """``hermes update`` / ``dashboard --stop`` may run from another profile than the backend it stops:
    the drain budget comes from the backend's own config.yaml, the longest one when several stop."""
    from hermes_cli import dashboard_procs

    quick, slow = tmp_path / "quick", tmp_path / "slow"
    for home, drain in ((quick, 0), (slow, 60)):
        home.mkdir()
        (home / "config.yaml").write_text(f"dashboard:\n  shutdown_drain_timeout: {drain}\n", encoding="utf-8")
    homes = {101: str(quick), 102: str(slow), 103: None}
    monkeypatch.setattr(dashboard_procs, "_hermes_home_for_pid", lambda pid: homes[pid])
    floor, settle = dashboard_procs._POSIX_TERM_GRACE_SECONDS, dashboard_procs._SHUTDOWN_DRAIN_SETTLE_SECONDS

    assert dashboard_procs._posix_term_grace_seconds([101]) == floor + settle
    assert dashboard_procs._posix_term_grace_seconds([101, 102]) == floor + 60 + settle
    assert dashboard_procs._posix_term_grace_seconds([103]) == floor + 20 + settle  # unreadable: the default


def test_only_a_non_desktop_backend_makes_its_stops_resumable(monkeypatch):
    from hermes_cli import web_server
    import tui_gateway.server as gateway

    gateway._resumable_shutdown.clear()
    try:
        monkeypatch.setattr(web_server, "is_desktop_owned_backend", lambda: True)
        web_server._enable_resumable_shutdown_unless_desktop()
        assert not gateway._resumable_shutdown.is_set()
        monkeypatch.setattr(web_server, "is_desktop_owned_backend", lambda: False)
        web_server._enable_resumable_shutdown_unless_desktop()
        assert gateway._resumable_shutdown.is_set()
    finally:
        gateway._resumable_shutdown.clear()
