"""A turn-isolation child loads the gateway home's plugins, so gateway-scope hooks reach isolated turns.

The child builds every routed turn's agent under that profile's HERMES_HOME override, so without an
explicit discovery the gateway home's plugin manager never exists in the child and a gateway-scope
plugin (Hermie's push) never hears an isolated bot turn (fork; FORK.md).
"""

from __future__ import annotations

import io
import os
import sys
import threading
import types
from pathlib import Path

import pytest
import yaml

import hermes_cli.plugins as plugins_mod
from tui_gateway import compute_host, server
from tui_gateway.compute_host import ComputeHost

RECORDER = "gw_child_recorder"


@pytest.fixture
def homes(tmp_path, monkeypatch):
    gateway = tmp_path / ".hermes"
    profile = gateway / "profiles" / "scout"
    profile.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(gateway))
    monkeypatch.setenv("HERMES_COMPUTE_HOST_HEARTBEAT_SECS", "0")
    (gateway / "config.yaml").write_text(yaml.safe_dump({"plugins": {"enabled": ["gwp"]}}), encoding="utf-8")
    (profile / "config.yaml").write_text(yaml.safe_dump({"plugins": {"enabled": []}}), encoding="utf-8")
    plugin = gateway / "plugins" / "gwp"
    plugin.mkdir(parents=True)
    (plugin / "plugin.yaml").write_text(yaml.safe_dump({"name": "gwp", "scope": "gateway"}), encoding="utf-8")
    (plugin / "__init__.py").write_text(
        f"import {RECORDER} as rec\n"
        "def register(ctx):\n"
        "    ctx.register_hook('post_llm_call', lambda **kw: rec.calls.append((ctx.profile_name, kw.get('session_id'))))\n",
        encoding="utf-8")
    recorder = types.ModuleType(RECORDER)
    recorder.calls = []
    monkeypatch.setitem(sys.modules, RECORDER, recorder)
    plugins_mod._reset_plugin_managers_for_tests()
    yield gateway, profile, recorder
    plugins_mod._reset_plugin_managers_for_tests()


def _run_child_until_closed() -> None:
    """``run_host`` on a pipe that closes at once: hello, discovery, then the reader sees EOF."""
    child_stdout = io.StringIO()
    stdin_r, stdin_w = os.pipe()
    os.close(stdin_w)
    child = threading.Thread(target=compute_host.run_host,
                             kwargs={"stdin": os.fdopen(stdin_r), "stdout": child_stdout}, daemon=True)
    child.start()
    child.join(timeout=60)
    assert not child.is_alive()


def _routed_isolated_turn(monkeypatch, profile: Path) -> None:
    """The child's own build path for a routed session, with an agent that fires the turn's hook."""
    host = ComputeHost(stdout=io.StringIO(), heartbeat_secs=0)

    def fake_make_agent(sid, key, **kwargs):
        plugins_mod.invoke_hook("post_llm_call", session_id=key)
        return types.SimpleNamespace(session_id=key)

    monkeypatch.setattr(server, "_make_agent", fake_make_agent)
    monkeypatch.setattr(server, "_transfer_db_to_agent", lambda agent, db: False)
    monkeypatch.setattr(server, "_init_session", lambda sid, key, agent, history, **kw: monkeypatch.setitem(
        server._sessions, sid, {"agent": agent, "session_key": key}))
    try:
        host._build_server_session(
            server, {"sid": "s-1", "session_key": "k-1", "history": [], "profile_home": str(profile)}, "s-1")
    finally:
        host.close()


def test_an_isolated_routed_turn_fires_the_gateway_scope_hook_once(homes, monkeypatch):
    gateway, profile, recorder = homes
    _run_child_until_closed()
    manager = plugins_mod._plugin_managers_by_home.get(gateway.resolve())
    assert manager is not None and manager._sweep_complete and "gwp" in manager._plugins

    _routed_isolated_turn(monkeypatch, profile)

    assert recorder.calls == [("scout", "k-1")]


def test_without_the_childs_discovery_the_hook_is_never_heard(homes, monkeypatch):
    """The failure the discovery fixes: the profile's manager is the only one the child builds."""
    _, profile, recorder = homes
    monkeypatch.setattr(compute_host, "_discover_gateway_home_plugins", lambda: None)
    _run_child_until_closed()

    _routed_isolated_turn(monkeypatch, profile)

    assert recorder.calls == []
