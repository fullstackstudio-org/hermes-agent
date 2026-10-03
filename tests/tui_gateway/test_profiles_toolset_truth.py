"""The toolset switches ``profiles.describe`` shows are the toolsets a bot's next app chat gets.

Invariant: for a profile, ``profiles.describe``'s ``toolsets[].enabled`` equals what the gateway builds the
agent from for an app / web chat (``_load_enabled_toolsets`` -> ``AIAgent(enabled_toolsets=...)``), checked
on the tools the model actually receives. Before, ``_describe_toolsets`` read the raw ``platform_toolsets.cli``
list, so a composite pin (``[hermes-cli]``, the shape ``hermes setup`` writes and the one on every profile of a
long-lived gateway) showed every switch off on a bot that had every tool, and a toolset named in
``agent.disabled_toolsets`` showed on while the model never saw it.

Also pinned: with the skills toolset off the model has no skill tools and no skill index in its system
prompt, which is the whole of what the switch controls; the slash command and the per-skill list are separate.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import tui_gateway.server as server

SKILL_TOOLS = {"skills_list", "skill_view", "skill_manage"}


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    """A temp HERMES_HOME root holding one named profile, ``bot``, with one installed skill."""
    root = tmp_path / "hermes_home"
    skill = root / "profiles" / "bot" / "skills" / "demo" / "truth-probe"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: truth-probe\ndescription: Probe skill used by the toolset truth test\n---\n\nBody.\n",
        encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.delenv("HERMES_TUI_TOOLSETS", raising=False)
    return root / "profiles" / "bot"


def _write_config(profile: Path, cli, *, agent: dict | None = None) -> None:
    cfg: dict = {"platform_toolsets": {} if cli is None else {"cli": cli}}
    if agent:
        cfg["agent"] = agent
    (profile / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")


def _described(profile: Path) -> dict[str, bool]:
    resp = server._methods["profiles.describe"](1, {"name": profile.name})
    assert "error" not in resp, resp.get("error")
    return {row["name"]: row["enabled"] for row in resp["result"]["toolsets"]}


BRIDGE_TOOLS = {"tool_search", "tool_describe", "tool_call"}


def _raw_tools(toolsets) -> set[str]:
    """Every tool *toolsets* puts in reach of the model after availability checks, uncollapsed: tools the
    tool_search bridge defers are still callable through it."""
    import model_tools

    return {t["function"]["name"] for t in model_tools.get_tool_definitions(
        enabled_toolsets=toolsets, quiet_mode=True, skip_tool_search_assembly=True)}


def _app_chat_agent(profile: Path):
    """The agent an app chat on this profile gets: the profile's home bound, toolsets from the gateway's own
    resolver, the surface the app's sessions run on (``tui``). Returns ``(tools in reach, prompt)``."""
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    from run_agent import AIAgent

    token = set_hermes_home_override(str(profile))
    try:
        enabled = server._load_enabled_toolsets("tui")
        agent = AIAgent(
            model="test-model", api_key="test-key", base_url="https://example.invalid/v1", quiet_mode=True,
            skip_context_files=True, skip_background_review=True, save_trajectories=False, platform="tui",
            session_id="truth", enabled_toolsets=enabled)
        from agent.system_prompt import build_system_prompt
        in_reach = _raw_tools(enabled)
        assert set(agent.valid_tool_names) - BRIDGE_TOOLS <= in_reach, "the agent holds tools its toolsets do not name"
        return in_reach, build_system_prompt(agent)
    finally:
        reset_hermes_home_override(token)


def _tools_of(toolset: str) -> set[str]:
    """The tools *toolset* alone puts in reach of a model."""
    return _raw_tools([toolset])


SHAPES = {
    "no pin": (None, None),
    "explicit pin without skills": (["web", "file", "terminal", "memory"], None),
    "explicit pin with skills": (["web", "skills"], None),
    "composite pin": (["hermes-cli"], None),
    "composite pin plus one toolset": (["hermes-cli", "spotify"], None),
    "composite pin, skills disabled globally": (["hermes-cli"], {"disabled_toolsets": ["skills"]}),
    "explicit pin, skills disabled globally": (["web", "skills"], {"disabled_toolsets": ["skills"]}),
    # An explicit empty list resolves to nothing, which the gateway hands the agent as "every toolset"
    # (``_load_enabled_toolsets`` returns None): describe tells that, it does not paper over it.
    "explicit empty list": ([], None),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_describe_enabled_is_what_the_model_receives(home, shape):
    cli, agent_cfg = SHAPES[shape]
    _write_config(home, cli, agent=agent_cfg)

    described = _described(home)
    received, _prompt = _app_chat_agent(home)

    assert described, "describe listed no toolsets"
    wrong = {}
    for name, enabled in described.items():
        tools = _tools_of(name)
        if not tools:  # nothing to receive either way (a check_fn keeps it out, or it is runtime-provided)
            continue
        got = bool(tools & received)
        if got != enabled:
            wrong[name] = {"describe_enabled": enabled, "model_has_its_tools": got}
    assert not wrong, f"{shape}: the settings screen and the agent disagree on {wrong}"


def test_a_composite_pin_does_not_read_as_everything_off(home):
    """The live shape: ``platform_toolsets.cli: [hermes-cli]``. Every switch must show on, and
    ``toolsets_pinned`` stays true (there IS a list; it just names a composite)."""
    _write_config(home, ["hermes-cli"])
    resp = server._methods["profiles.describe"](1, {"name": "bot"})["result"]
    assert resp["toolsets_pinned"] is True
    assert {"skills", "file", "terminal", "web"} <= {row["name"] for row in resp["toolsets"] if row["enabled"]}


def test_skills_switch_off_means_no_skill_tools_and_no_skill_index(home):
    _write_config(home, ["web", "file", "terminal"])
    assert _described(home)["skills"] is False
    received, prompt = _app_chat_agent(home)
    assert not (received & SKILL_TOOLS)
    assert "truth-probe" not in prompt, "an installed skill's name reached the prompt with the skills toolset off"


def test_skills_switch_on_means_skill_tools_and_the_skill_index(home):
    _write_config(home, ["web", "skills"])
    assert _described(home)["skills"] is True
    received, prompt = _app_chat_agent(home)
    assert SKILL_TOOLS <= received
    assert "truth-probe" in prompt


def test_config_only_capabilities_are_not_listed_as_toolsets(home):
    """``stt`` has its own switch (``stt.enabled``) and no tools; a row for it never changed anything."""
    _write_config(home, ["hermes-cli"])
    assert "stt" not in _described(home)


def test_what_the_editor_saves_is_what_the_next_chat_gets(home):
    """Round trip through the writer: save a pin from the checklist, then describe and the agent agree."""
    _write_config(home, ["hermes-cli"])
    saved = ["web", "file", "memory"]
    resp = server._methods["profiles.configure"](1, {"name": "bot", "enabled_toolsets": saved})
    assert resp["result"]["applied"]["toolsets"] is True
    described = _described(home)
    assert {name for name, on in described.items() if on} == set(saved)
    received, _prompt = _app_chat_agent(home)
    assert not (received & SKILL_TOOLS)
    assert {"read_file", "memory"} <= received


def test_a_skill_still_loads_by_slash_command_with_the_skills_toolset_off(home):
    """What the switch does NOT govern: ``/skill-name`` expands the skill into the user's turn whatever the
    toolsets say, so "skills off" and "this bot used a skill" can both be true. Per-skill ``disabled_skills``
    is the control that removes the skill from that path too."""
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    _write_config(home, ["web", "file"])
    assert _described(home)["skills"] is False

    token = set_hermes_home_override(str(home))
    try:
        from agent.skill_commands import scan_skill_commands

        scan_skill_commands()
        resp = server._dispatch_skill(1, {}, None, "truth-probe", "")
        assert resp is not None and resp["result"]["type"] == "skill"
        assert "Body." in resp["result"]["message"]

        server._methods["profiles.configure"](1, {"name": "bot", "disabled_skills": ["truth-probe"]})
        scan_skill_commands()
        assert server._dispatch_skill(1, {}, None, "truth-probe", "") is None
    finally:
        reset_hermes_home_override(token)
