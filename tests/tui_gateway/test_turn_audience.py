"""Who takes part in a session, as the gateway answers ``hermes_cli.turn_audience`` (fork; FORK.md).

A plugin notifying people about a turn asks this from inside the hook, so a push about one person's chat
is not sent to everybody else on the gateway.
"""

from __future__ import annotations

import pytest

import hermes_cli.turn_audience as turn_audience_mod
from hermes_cli.turn_audience import turn_audience
from hermes_state_registry import acquire, release_or_close
from tui_gateway import server


OWNER = "oidc:owner"
LLOYD = "oidc:lloyd"


@pytest.fixture
def sessions(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    table: dict = {}
    monkeypatch.setattr(server, "_sessions", table)
    return table


def _rows(session_id: str, *authors: str | None) -> None:
    database = acquire()
    try:
        database.create_session(session_id, "tui")
        for author in authors:
            metadata = {"author": {"id": author}} if author else None
            database.append_message(session_id, "user", "hi", display_metadata=metadata)
            database.append_message(session_id, "assistant", "hello")
    finally:
        release_or_close(database)


def test_the_gateway_registers_its_provider_at_import():
    assert turn_audience_mod._provider is not None


def test_no_provider_answers_none(monkeypatch):
    monkeypatch.setattr(turn_audience_mod, "_provider", None)
    assert turn_audience(session_id="k1") is None


def test_a_failing_provider_answers_none(monkeypatch):
    def boom(session_id, session_key):
        raise RuntimeError("no")
    monkeypatch.setattr(turn_audience_mod, "_provider", boom)
    assert turn_audience(session_id="k1") is None


def test_an_own_chat_names_its_owner_only(sessions):
    sessions["sid-1"] = {"session_key": "k1", "auth_user_id": OWNER, "transport": None}
    _rows("k1", OWNER, None)
    assert turn_audience(session_id="k1") == {"acting_user_id": OWNER, "user_ids": [OWNER]}


def test_a_shared_chat_names_everyone_who_wrote_in_it(sessions):
    sessions["sid-1"] = {"session_key": "k1", "auth_user_id": OWNER, "auth_user_shared": True, "transport": None}
    _rows("k1", OWNER, LLOYD)
    answer = turn_audience(session_key="k1")
    # Shared: the record's stamp proves nobody acted, so no acting person outside a turn.
    assert answer["acting_user_id"] == ""
    assert answer["user_ids"] == [OWNER, LLOYD]


def test_the_turns_submitter_comes_first(sessions):
    sessions["sid-1"] = {"session_key": "k1", "auth_user_id": OWNER, "auth_user_shared": True, "transport": None}
    _rows("k1", OWNER)
    token = server._turn_auth_user.set((LLOYD, "Lloyd"))
    try:
        answer = turn_audience(session_id="k1")
    finally:
        server._turn_auth_user.reset(token)
    assert answer == {"acting_user_id": LLOYD, "user_ids": [LLOYD, OWNER]}


def test_an_unattributed_turn_in_an_own_chat_is_the_owners(sessions):
    """A wake-up or a cron continuation in the owner's own chat: nobody submitted it."""
    sessions["sid-1"] = {"session_key": "k1", "auth_user_id": OWNER, "transport": None}
    token = server._turn_auth_user.set(server._UNATTRIBUTED_TURN)
    try:
        answer = turn_audience(session_id="k1")
    finally:
        server._turn_auth_user.reset(token)
    assert answer == {"acting_user_id": OWNER, "user_ids": [OWNER]}


def test_the_turns_own_ui_session_id_finds_its_record(sessions):
    import contextvars

    from gateway.session_context import set_session_vars

    sessions["sid-9"] = {"session_key": "stored-9", "auth_user_id": OWNER, "transport": None}

    def in_turn():
        set_session_vars(ui_session_id="sid-9")
        return turn_audience()

    # A context of its own: the session variables stay out of every other test.
    answer = contextvars.copy_context().run(in_turn)
    assert answer["user_ids"] == [OWNER]


def test_a_session_without_a_live_record_answers_from_its_rows(sessions):
    _rows("cron_job_1", None)
    assert turn_audience(session_id="cron_job_1") == {"acting_user_id": "", "user_ids": []}
    _rows("k2", LLOYD)
    assert turn_audience(session_id="k2") == {"acting_user_id": "", "user_ids": [LLOYD]}
