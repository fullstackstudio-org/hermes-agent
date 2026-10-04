"""History clients read never carries an inline (base64) image: an attached image shows as the
``@image:<path>`` reference clients render, and a legacy row's data URL becomes ``[image]``."""

from __future__ import annotations

import json

from agent.context_references import format_reference_value
from tui_gateway import server

_DATA = "data:image/png;base64," + "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB" * 4


def _user_text(history):
    messages = server._history_to_messages(history)
    return next(m["text"] for m in messages if m["role"] == "user")


def test_a_live_native_turn_shows_the_reference_not_the_data_url(tmp_path):
    path = str(tmp_path / "images" / "upload_20261004_120000_1.png")
    live = [{"role": "user", "content": [
        {"type": "text", "text": f"what is this?\n\n[Image attached at: {path}]"},
        {"type": "image_url", "image_url": {"url": _DATA}}]},
        {"role": "assistant", "content": "a cat"}]

    text = _user_text(live)

    assert "base64" not in text
    assert text == f"what is this?\n\n@image:{format_reference_value(path)}"


def test_a_stored_row_with_a_legacy_data_url_shows_a_note():
    stored_parts = [{"role": "user", "content": [
        {"type": "text", "text": "look"}, {"type": "image_url", "image_url": {"url": _DATA}}]}]
    flattened = [{"role": "user", "content": f"look\n{_DATA}"}]

    for history in (stored_parts, flattened):
        text = _user_text(history)
        assert "base64" not in text and "[image]" in text and text.startswith("look")


def test_remote_image_urls_still_show_inline():
    remote = [{"role": "user", "content": [
        {"type": "text", "text": "this one"}, {"type": "image_url", "image_url": {"url": "https://e.x/a.png"}}]}]
    assert "https://e.x/a.png" in _user_text(remote)


def test_assistant_text_quoting_a_handle_is_left_as_written():
    reply = "The marker looks like [Image attached at: /tmp/x.png]"
    messages = server._history_to_messages([{"role": "assistant", "content": reply}])
    assert json.dumps(messages).count("[Image attached at: /tmp/x.png]") == 1


def _legacy_db(tmp_path, monkeypatch, path):
    """A state.db whose user row was stored before inline images were dropped on write (raw SQL: the
    current writer would strip it)."""
    from pathlib import Path

    from hermes_state import SessionDB

    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr("hermes_state.DEFAULT_DB_PATH", home / "state.db")
    db = SessionDB(db_path=home / "state.db")
    db.create_session(session_id="legacy", source="tui")
    db.append_message("legacy", role="user", content="placeholder")
    db.append_message("legacy", role="assistant", content="a cat")
    legacy = [{"type": "text", "text": f"what is this?\n\n[Image attached at: {path}]"},
              {"type": "image_url", "image_url": {"url": _DATA}}]
    db._conn.execute("UPDATE messages SET content = ? WHERE session_id = 'legacy' AND role = 'user'",
                     (db._CONTENT_JSON_PREFIX + json.dumps(legacy),))
    db._conn.commit()
    return db


def test_legacy_rows_reach_no_client_with_their_data_url(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    path = str(tmp_path / "images" / "upload_1.png")
    db = _legacy_db(tmp_path, monkeypatch, path)
    try:
        rows = db.get_messages_as_conversation("legacy")
        assert "base64" in json.dumps(rows)  # the row really is legacy
        # session.history / session.resume projection
        assert "base64" not in json.dumps(server._history_to_messages(rows))
        # what a resumed session replays to the model
        from agent.replay_cleanup import canonicalize_replay_history
        replay = canonicalize_replay_history(rows)
        assert "base64" not in json.dumps(replay) and f"[Image attached at: {path}]" in json.dumps(replay)
    finally:
        db.close()

    # the dashboard REST page and export
    from hermes_cli.web_routers.sessions import manage_router

    app = FastAPI()
    app.include_router(manage_router)
    with TestClient(app) as client:
        page = client.get("/api/sessions/legacy/messages")
        export = client.get("/api/sessions/legacy/export")
    assert page.status_code == 200 and export.status_code == 200
    assert "base64" not in page.text and "base64" not in export.text
    assert "[Image attached at:" in page.text


def test_a_named_and_an_unnamed_inline_image_show_as_reference_and_note(tmp_path):
    path = str(tmp_path / "images" / "upload_1.png")
    history = [{"role": "user", "content": [
        {"type": "text", "text": f"two\n\n[Image attached at: {path}]"},
        {"type": "image_url", "image_url": {"url": _DATA}},
        {"type": "image_url", "image_url": {"url": _DATA}}]}]
    assert _user_text(history) == f"two\n\n@image:{format_reference_value(path)}\n[image]"


def test_the_export_keeps_an_unnamed_inline_image(tmp_path, monkeypatch):
    """An export is the stored form: a named image is dropped, an unnamed one (the only copy) stays."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    db = _legacy_db(tmp_path, monkeypatch, str(tmp_path / "images" / "upload_1.png"))
    try:
        db.append_message("legacy", role="user", content=[
            {"type": "text", "text": "api client"}, {"type": "image_url", "image_url": {"url": _DATA}}])
    finally:
        db.close()
    from hermes_cli.web_routers.sessions import manage_router

    app = FastAPI()
    app.include_router(manage_router)
    with TestClient(app) as client:
        exported = client.get("/api/sessions/legacy/export").json()["messages"]
        page = client.get("/api/sessions/legacy/messages").text
    users = [m["content"] for m in exported if m["role"] == "user"]
    assert "base64" not in json.dumps(users[0])  # the named legacy image
    assert _DATA in json.dumps(users[1])  # the unnamed one
    assert "base64" not in page
