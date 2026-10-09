"""Gateway-scope plugins: hooks of a plugin enabled at the gateway's own home fire for routed profile turns.

A routed bot turn runs under its profile's HERMES_HOME override, so ``invoke_hook`` reaches that
profile's plugin manager and nothing else. A plugin that serves the whole gateway (push for every bot,
say) declares ``scope: gateway`` in its plugin.yaml; its hooks, and only its hooks, then also run for
turns routed to other profiles. See FORK.md.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest
import yaml

import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins_manifest import parse_manifest_file
from hermes_constants import get_hermes_home, reset_hermes_home_override, set_hermes_home_override


RECORDER = "gw_scope_recorder"


@pytest.fixture
def recorder(monkeypatch):
    module = types.ModuleType(RECORDER)
    module.calls = []
    monkeypatch.setitem(sys.modules, RECORDER, module)
    return module


@pytest.fixture
def homes(tmp_path, monkeypatch):
    """A gateway home (the default profile) and one bot profile under it, neither discovered yet."""
    gateway = tmp_path / ".hermes"
    profile = gateway / "profiles" / "scout"
    profile.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(gateway))
    _write_config(gateway, {"plugins": {"enabled": []}})
    _write_config(profile, {"plugins": {"enabled": []}})
    plugins_mod._reset_plugin_managers_for_tests()
    yield gateway, profile
    plugins_mod._reset_plugin_managers_for_tests()


def _write_config(home: Path, data: dict) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")


def _enable(home: Path, name: str) -> None:
    path = home / "config.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.setdefault("plugins", {}).setdefault("enabled", []).append(name)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _plugin(home: Path, name: str, body: str, *, scope: str | None = "gateway") -> None:
    """A plugin under ``<home>/plugins/<name>`` whose register(ctx) runs *body* (indented 4)."""
    directory = home / "plugins" / name
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "version": "0.1.0", "description": f"test plugin {name}"}
    if scope is not None:
        manifest["scope"] = scope
    (directory / "plugin.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    lines = "\n".join("    " + line for line in body.strip().splitlines())
    (directory / "__init__.py").write_text(
        "from hermes_constants import get_hermes_home\n"
        f"import {RECORDER} as rec\n\n"
        "def register(ctx):\n"
        f"{lines}\n",
        encoding="utf-8",
    )
    _enable(home, name)


RECORDING_HOOK = """
def on_hook(**kwargs):
    rec.calls.append((ctx.plugin_id, ctx.profile_name, str(get_hermes_home()), kwargs.get("session_id")))
    return ctx.plugin_id
ctx.register_hook("post_llm_call", on_hook)
"""


def _discover(home: Path | None):
    """Discover the manager of *home* (None: the process's own home) and return it."""
    token = set_hermes_home_override(str(home)) if home is not None else None
    try:
        manager = plugins_mod.get_plugin_manager()
        manager.discover_and_load()
        return manager
    finally:
        if token is not None:
            reset_hermes_home_override(token)


class _InProfile:
    def __init__(self, home: Path):
        self.home = home

    def __enter__(self):
        self.token = set_hermes_home_override(str(self.home))
        return self

    def __exit__(self, *exc):
        reset_hermes_home_override(self.token)


def _ids(calls):
    return [call[0] for call in calls]


# ── manifest ───────────────────────────────────────────────────────────────


def test_manifest_scope_is_parsed_and_defaults_to_profile(tmp_path, caplog):
    def parse(extra):
        directory = tmp_path / f"p{len(list(tmp_path.iterdir()))}"
        directory.mkdir()
        (directory / "plugin.yaml").write_text(yaml.safe_dump({"name": "p", **extra}), encoding="utf-8")
        return parse_manifest_file(directory / "plugin.yaml", directory, "user", "")

    assert parse({}).scope == "profile"
    assert parse({"scope": "gateway"}).scope == "gateway"
    assert parse({"scope": " Gateway "}).scope == "gateway"
    assert parse({"scope": "profile"}).scope == "profile"
    with caplog.at_level("WARNING", logger="hermes_cli.plugins"):
        assert parse({"scope": "everywhere"}).scope == "profile"
    assert "scope" in caplog.text


def test_validate_reports_the_scope():
    from hermes_cli.plugin_validate import ValidationReport, _check_scope

    def check(manifest):
        report = ValidationReport()
        _check_scope(report, manifest)
        return [(name, ok) for name, ok, _ in report.checks]

    assert check({}) == [("scope", True)]
    assert check({"scope": "gateway"}) == [("scope", True)]
    assert check({"scope": "everywhere"}) == [("scope", False)]
    assert check({"scope": 3}) == [("scope", False)]


# ── routing ────────────────────────────────────────────────────────────────


def test_routed_profile_turn_fires_gateway_scope_hook_with_the_profile_identity(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK + "\nrec.ctx = ctx")
    _discover(None)
    with _InProfile(profile):
        results = plugins_mod.invoke_hook("post_llm_call", session_id="s1")
        profile_home = recorder.ctx.profile_home

    assert recorder.calls == [("gwp", "scout", str(profile), "s1")]
    assert results == ["gwp"]
    assert Path(profile_home) == profile


def test_default_home_turn_fires_once(homes, recorder):
    gateway, _ = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _discover(None)

    results = plugins_mod.invoke_hook("post_llm_call", session_id="s1")

    assert recorder.calls == [("gwp", "default", str(gateway), "s1")]
    assert results == ["gwp"]


def test_plugin_without_gateway_scope_stays_in_its_own_home(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "plain", RECORDING_HOOK, scope=None)
    _plugin(gateway, "explicit", RECORDING_HOOK, scope="profile")
    _discover(None)
    with _InProfile(profile):
        assert plugins_mod.invoke_hook("post_llm_call", session_id="s1") == []
        assert plugins_mod.has_hook("post_llm_call") is False
    assert recorder.calls == []


def test_profile_plugins_run_first_then_gateway_scope(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _plugin(profile, "own", RECORDING_HOOK, scope=None)
    _discover(None)
    _discover(profile)
    with _InProfile(profile):
        results = plugins_mod.invoke_hook("post_llm_call", session_id="s1")

    assert results == ["own", "gwp"]
    assert _ids(recorder.calls) == ["own", "gwp"]


def test_profile_with_its_own_copy_of_the_plugin_is_not_fired_twice(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _plugin(profile, "gwp", RECORDING_HOOK)
    _discover(None)
    _discover(profile)
    with _InProfile(profile):
        plugins_mod.invoke_hook("post_llm_call", session_id="s1")

    assert recorder.calls == [("gwp", "scout", str(profile), "s1")]


def test_profile_copy_that_is_disabled_still_opts_the_profile_out(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _plugin(profile, "gwp", RECORDING_HOOK)
    _write_config(profile, {"plugins": {"enabled": [], "disabled": ["gwp"]}})
    _discover(None)
    _discover(profile)
    with _InProfile(profile):
        plugins_mod.invoke_hook("post_llm_call", session_id="s1")

    assert recorder.calls == []


def test_has_hook_and_iter_hook_callbacks_see_gateway_scope_hooks(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _discover(None)
    _discover(profile)
    with _InProfile(profile):
        assert plugins_mod.has_hook("post_llm_call") is True
        assert plugins_mod.has_hook("pre_llm_call") is False
        callbacks = plugins_mod.iter_hook_callbacks("post_llm_call")
    assert len(callbacks) == 1
    assert callbacks[0].__name__ == "on_hook"


def test_lifecycle_dispatch_reaches_gateway_scope_hooks(homes, recorder):
    from hermes_cli import lifecycle

    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _discover(None)
    with _InProfile(profile):
        assert lifecycle.has_hook("post_llm_call") is True
        lifecycle.invoke_hook("post_llm_call", session_id="s2")
    assert recorder.calls == [("gwp", "scout", str(profile), "s2")]


def test_ainvoke_hook_fans_out_too(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", """
async def on_hook(**kwargs):
    rec.calls.append((ctx.plugin_id, ctx.profile_name))
    return "async-gwp"
ctx.register_hook("post_llm_call", on_hook)
""")
    _plugin(profile, "own", RECORDING_HOOK, scope=None)
    _discover(None)
    _discover(profile)

    async def run():
        with _InProfile(profile):
            return await plugins_mod.ainvoke_hook("post_llm_call", session_id="s1")

    assert asyncio.run(run()) == ["own", "async-gwp"]
    assert recorder.calls[-1] == ("gwp", "scout")


def test_every_turn_hook_the_plugin_registers_fans_out(homes, recorder):
    gateway, profile = homes
    hooks = ["pre_llm_call", "post_llm_call", "pre_tool_call", "post_tool_call", "on_session_end",
             "pre_approval_request", "post_approval_response", "pre_confirm_request",
             "pre_server_request", "post_server_request", "on_background_complete"]
    _plugin(gateway, "gwp", f"""
for name in {hooks!r}:
    def on_hook(_name=name, **kwargs):
        rec.calls.append((_name, ctx.profile_name))
    ctx.register_hook(name, on_hook)
""")
    _discover(None)
    with _InProfile(profile):
        for name in hooks:
            plugins_mod.invoke_hook(name, session_id="s1")
    assert recorder.calls == [(name, "scout") for name in hooks]


# ── isolation ──────────────────────────────────────────────────────────────


def test_a_raising_gateway_scope_hook_does_not_break_the_profile_turn(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", """
def boom(**kwargs):
    raise RuntimeError("gateway plugin failed")
ctx.register_hook("post_llm_call", boom)
ctx.register_hook("pre_tool_call", boom)
""")
    _plugin(profile, "own", RECORDING_HOOK, scope=None)
    _discover(None)
    _discover(profile)
    with _InProfile(profile):
        assert plugins_mod.invoke_hook("post_llm_call", session_id="s1") == ["own"]
        # pre_tool_call fails closed for a profile's own guard; a gateway-scope observer that raises
        # must not veto the routed profile's tool call.
        block, _ = plugins_mod._dispatch_pre_tool_call_hooks("read_file", {"path": "x"})
    assert block is None
    assert _ids(recorder.calls) == ["own"]


def test_a_profile_guard_that_raises_still_fails_closed(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    _plugin(profile, "guard", """
def boom(**kwargs):
    raise RuntimeError("guard failed")
ctx.register_hook("pre_tool_call", boom)
""", scope=None)
    _discover(None)
    _discover(profile)
    with _InProfile(profile):
        block, _ = plugins_mod._dispatch_pre_tool_call_hooks("read_file", {"path": "x"})
    assert block


def test_only_hooks_leak_into_profiles(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", """
ctx.register_hook("post_llm_call", lambda **kw: None)
ctx.register_command("gwonly", lambda raw: "hi", description="gateway only")
ctx.register_middleware("llm_request", lambda **kw: None)
ctx.register_system_prompt_section("gwsection", "from the gateway")
ctx.register_tool(
    name="gw_only_tool", toolset="gwp", schema={"name": "gw_only_tool", "description": "x",
    "parameters": {"type": "object", "properties": {}}}, handler=lambda args, **kw: "{}")
""")
    gateway_manager = _discover(None)
    assert "gwonly" in gateway_manager._plugin_commands
    assert gateway_manager.has_middleware("llm_request")
    profile_manager = _discover(profile)
    from tools.registry import registry

    with _InProfile(profile):
        assert plugins_mod.has_hook("post_llm_call") is True
        assert "gwonly" not in plugins_mod.get_plugin_commands()
        assert plugins_mod.has_middleware("llm_request") is False
        assert plugins_mod.render_system_prompt_sections({}) == []
        assert registry.get_entry("gw_only_tool", scope=profile_manager.scope_key) is None
        assert all(ts != "gwp" for ts, _, _ in plugins_mod.get_plugin_toolsets())


def test_config_and_state_stay_in_the_gateway_home_during_a_routed_turn(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", """
def on_hook(**kwargs):
    rec.calls.append((ctx.get_config("flag", "unset"), str(ctx.state.data_dir), ctx.profile_name))
    ctx.state.set("seen", kwargs.get("session_id"))
ctx.register_hook("post_llm_call", on_hook)
""")
    config = yaml.safe_load((gateway / "config.yaml").read_text(encoding="utf-8"))
    config["plugins"]["entries"] = {"gwp": {"settings": {"flag": "gateway-value"}}}
    (gateway / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    _discover(None)
    with _InProfile(profile):
        plugins_mod.invoke_hook("post_llm_call", session_id="s9")

    flag, data_dir, name = recorder.calls[0]
    assert (flag, name) == ("gateway-value", "scout")
    assert Path(data_dir).parent.resolve() == (gateway / "plugin-data").resolve()
    stored = json.loads((Path(data_dir) / "state.json").read_text(encoding="utf-8"))
    assert stored["seen"] == "s9"
    assert not (profile / "plugin-data").exists()


def test_set_config_during_a_routed_turn_writes_the_gateway_config(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", """
ctx.register_hook("post_llm_call", lambda **kw: ctx.set_config("last", kw.get("session_id")))
""")
    _discover(None)
    with _InProfile(profile):
        plugins_mod.invoke_hook("post_llm_call", session_id="s3")

    gateway_cfg = yaml.safe_load((gateway / "config.yaml").read_text(encoding="utf-8"))
    profile_cfg = yaml.safe_load((profile / "config.yaml").read_text(encoding="utf-8"))
    assert gateway_cfg["plugins"]["entries"]["gwp"]["settings"]["last"] == "s3"
    assert "entries" not in (profile_cfg.get("plugins") or {})


# ── lifecycle ──────────────────────────────────────────────────────────────


def test_disposed_hook_and_unloaded_gateway_no_longer_fan_out(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", """
rec.handle = ctx.register_hook("post_llm_call", lambda **kw: rec.calls.append("first"))
ctx.register_hook("post_llm_call", lambda **kw: rec.calls.append("second"))
""")
    gateway_manager = _discover(None)
    recorder.handle.dispose()
    with _InProfile(profile):
        plugins_mod.invoke_hook("post_llm_call", session_id="s1")
    assert recorder.calls == ["second"]

    gateway_manager.unload()
    assert gateway_manager._gateway_scope_hooks == {}
    with _InProfile(profile):
        plugins_mod.invoke_hook("post_llm_call", session_id="s1")
        assert plugins_mod.has_hook("post_llm_call") is False
    assert recorder.calls == ["second"]


def test_undiscovered_gateway_manager_is_not_discovered_from_a_profile_turn(homes, recorder):
    gateway, profile = homes
    _plugin(gateway, "gwp", RECORDING_HOOK)
    with _InProfile(profile):
        assert plugins_mod.invoke_hook("post_llm_call", session_id="s1") == []
    assert recorder.calls == []
    gateway_key = Path(get_hermes_home()).resolve()
    manager = plugins_mod._plugin_managers_by_home.get(gateway_key)
    assert manager is None or not manager._discovered
