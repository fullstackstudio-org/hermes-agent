"""Which turn identities count as a human messaging channel (``session_is_messaging_surface``).

The interactive tools (``confirm_action``, ``ask_form``, ``ask_file``, ``review_draft``) answer ``no_session`` on a
messaging surface, and ``verify_on_stop: auto`` stays off there. An unknown identity is messaging (default-deny).
"""

from __future__ import annotations

import pytest

from gateway.session_context import clear_session_vars, session_is_messaging_surface, set_session_vars


@pytest.fixture(autouse=True)
def _no_process_platform(monkeypatch):
    monkeypatch.delenv("HERMES_PLATFORM", raising=False)
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    monkeypatch.delenv("HERMES_SESSION_SOURCE", raising=False)


def _surface(**vars) -> bool:
    tokens = set_session_vars(**vars)
    try:
        return session_is_messaging_surface()
    finally:
        clear_session_vars(tokens)


@pytest.mark.parametrize("source", ["hermie", "Hermie", "tui", "desktop", "cli"])
def test_an_app_or_local_source_is_not_messaging(source):
    assert _surface(source=source, ui_session_id="s1") is False


@pytest.mark.parametrize("source", ["telegram", "discord", "bot_room", "something_new"])
def test_a_platform_or_unknown_source_is_messaging(source):
    assert _surface(source=source, ui_session_id="s1") is True


def test_a_messaging_platform_wins_over_an_app_source():
    assert _surface(platform="telegram", source="hermie", ui_session_id="s1") is True
