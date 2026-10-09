"""API-time system additions (plan rich-answers T2): ``ephemeral_system_prompt`` plus one turn's staged addition.

Pinned here: with nothing staged every site composes exactly what it composed before (cached prompt, then
``ephemeral_system_prompt``), so a Telegram, Slack or desktop request is byte-identical; a staged addition
follows the personality prompt on the system message of each site (the request, a failover's rewrite, the
iteration summary, the Codex developer instructions) and never touches ``_cached_system_prompt`` or
``ephemeral_system_prompt``. Also the static ``hermie`` platform hint (D8).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.prompt_additions import stage_turn_system_addition, system_prompt_additions, with_system_additions
from agent.prompt_builder import HERMIE_FILES_HINT, HERMIE_PLATFORM_HINT, PLATFORM_HINTS
from tests.agent.test_platform_hint_desktop import _make_agent, _stable_prompt


def _old(base, ephemeral):
    """The composition every site used before the helper."""
    return (base + "\n\n" + ephemeral).strip() if ephemeral else base


@pytest.mark.parametrize("base", ["", "CACHED", "  CACHED  "])
@pytest.mark.parametrize("ephemeral", [None, "", "PERSONA", " PERSONA \n"])
def test_nothing_staged_is_byte_identical_to_before(base, ephemeral):
    agent = SimpleNamespace(ephemeral_system_prompt=ephemeral)
    assert with_system_additions(base, agent) == _old(base, ephemeral)
    stage_turn_system_addition(agent, "")
    assert with_system_additions(base, agent) == _old(base, ephemeral)


def test_a_staged_addition_follows_the_personality_prompt():
    agent = SimpleNamespace(ephemeral_system_prompt="PERSONA", _cached_system_prompt="CACHED")
    stage_turn_system_addition(agent, "MARKER GUIDE")
    assert system_prompt_additions(agent) == "PERSONA\n\nMARKER GUIDE"
    assert with_system_additions("CACHED", agent) == "CACHED\n\nPERSONA\n\nMARKER GUIDE"
    assert agent.ephemeral_system_prompt == "PERSONA" and agent._cached_system_prompt == "CACHED"
    agent.ephemeral_system_prompt = None
    assert with_system_additions("CACHED", agent) == "CACHED\n\nMARKER GUIDE"
    stage_turn_system_addition(agent, "")
    assert with_system_additions("CACHED", agent) == "CACHED"


def test_a_stand_in_without_the_attributes_gets_nothing():
    class Locked:
        __slots__ = ()
    stage_turn_system_addition(Locked(), "MARKER")
    assert system_prompt_additions(Locked()) == ""
    assert system_prompt_additions(SimpleNamespace(ephemeral_system_prompt=object(),
                                                   _turn_system_addition=3)) == ""


def _staged(**extra):
    agent = SimpleNamespace(ephemeral_system_prompt="PERSONA", _cached_system_prompt="CACHED", **extra)
    stage_turn_system_addition(agent, "MARKER GUIDE")
    return agent


def test_the_codex_developer_instructions_carry_it():
    from agent.codex_runtime import _codex_developer_instructions
    assert _codex_developer_instructions(_staged()) == "CACHED\n\nPERSONA\n\nMARKER GUIDE"
    plain = SimpleNamespace(ephemeral_system_prompt=None, _cached_system_prompt="CACHED")
    assert _codex_developer_instructions(plain) == "CACHED"


def test_a_failover_rewrite_keeps_it():
    from agent.conversation_loop import _sync_failover_system_message
    agent = _staged()
    api_messages = [{"role": "system", "content": "stale"}, {"role": "user", "content": "marker"}]
    assert _sync_failover_system_message(agent, api_messages, "stale") == "CACHED"
    assert api_messages[0]["content"] == "CACHED\n\nPERSONA\n\nMARKER GUIDE"


def test_the_iteration_summary_carries_it():
    from agent.chat_completion_helpers import _iteration_summary_api_messages
    same = lambda messages: messages  # noqa: E731 - the sanitizers this stub does not exercise
    agent = _staged(prefill_messages=None, model="m", provider="p", _should_sanitize_tool_calls=lambda: False,
                    _sanitize_api_messages=same, _drop_thinking_only_and_merge_users=same,
                    _image_rejecting_models=set())
    api_messages = _iteration_summary_api_messages(agent, [])
    assert api_messages[0] == {"role": "system", "content": "CACHED\n\nPERSONA\n\nMARKER GUIDE"}


def test_the_background_review_fork_inherits_the_same_system_bytes():
    from agent.background_review import _same_model_parity_kwargs
    assert _same_model_parity_kwargs(_staged())["ephemeral_system_prompt"] == "PERSONA\n\nMARKER GUIDE"
    plain = SimpleNamespace(ephemeral_system_prompt="PERSONA")
    assert _same_model_parity_kwargs(plain)["ephemeral_system_prompt"] == "PERSONA"
    assert _same_model_parity_kwargs(SimpleNamespace())["ephemeral_system_prompt"] is None


# ── the hermie platform hint (D8) ───────────────────────────────────────────────────────────────


def test_a_hermie_session_gets_its_platform_hint():
    with patch("agent.system_prompt._hermie_outbox_serves_files", return_value=True):
        stable = _stable_prompt(_make_agent(platform="hermie"))
    assert PLATFORM_HINTS["hermie"] in stable
    for claim in ("task lists, tables", "$...$ inline", "$$...$$ on lines of its own",
                  "flowcharts (without subgraphs or styling) and pie charts only", "Raw HTML and ::preview",
                  "never loaded", "MEDIA:/absolute/path/to/file"):
        assert claim in PLATFORM_HINTS["hermie"], claim
    # Version-dependent blocks are told per turn, never in the session's cached prompt.
    assert "hermie-chart" not in stable and "hermie-cards" not in stable and "[!NOTE]" not in stable


def test_without_the_outbox_the_files_sentence_goes():
    with patch("agent.system_prompt._hermie_outbox_serves_files", return_value=False):
        stable = _stable_prompt(_make_agent(platform="hermie"))
    assert HERMIE_PLATFORM_HINT in stable and HERMIE_FILES_HINT not in stable


def test_the_outbox_default_serves_hermie(monkeypatch):
    from agent.system_prompt import _hermie_outbox_serves_files
    monkeypatch.setattr("tui_gateway.outbox.load_settings",
                        lambda: __import__("tui_gateway.outbox", fromlist=["x"]).settings_from({}))
    assert _hermie_outbox_serves_files() is True
    monkeypatch.setattr("tui_gateway.outbox.load_settings",
                        lambda: __import__("tui_gateway.outbox", fromlist=["x"]).settings_from(
                            {"files": {"outbox_sources": ["desktop"]}}))
    assert _hermie_outbox_serves_files() is False


def test_the_config_override_still_reaches_the_hermie_hint():
    agent = _make_agent(platform="hermie", _platform_hint_overrides={"hermie": {"append": "MARKER APPEND"}})
    with patch("agent.system_prompt._hermie_outbox_serves_files", return_value=True):
        stable = _stable_prompt(agent)
    assert PLATFORM_HINTS["hermie"] in stable and "MARKER APPEND" in stable


@pytest.mark.parametrize("platform", ["telegram", "desktop", "slack", "tui", "cli"])
def test_other_platforms_never_hear_of_hermie(platform):
    stable = _stable_prompt(_make_agent(platform=platform))
    assert HERMIE_PLATFORM_HINT not in stable and "Hermie" not in stable
    assert PLATFORM_HINTS[platform] in stable or platform == "tui"
