"""History tool rows carry the identity of their call, ``(call_row_id, call_index)``, and their own ``row_id``.

``tool_call_id`` alone cannot pair a stored tool row with the live card of its call: llama.cpp answers every
call with one constant id and other backends restart at ``call_0`` each turn. The assistant row holding the
``tool_calls`` and the call's position in it can, and ``session.history`` and the REST routes both say so."""
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import tui_gateway.server as server
from hermes_state import SessionDB
from tui_gateway.row_identity import annotate_tool_rows


def _calls(*ids):
    return [{"id": i, "type": "function", "function": {"name": "web_search", "arguments": "{}"}} for i in ids]


def _assistant(row_id, *ids, content=""):
    return {"role": "assistant", "content": content, "tool_calls": _calls(*ids), "_row_id": row_id}


def _tool(row_id, call_id):
    return {"role": "tool", "tool_call_id": call_id, "content": f"result {row_id}", "_row_id": row_id}


def _identity(row):
    return row.get("call_row_id"), row.get("call_index")


def test_two_turns_reusing_call_0_pair_each_tool_row_with_its_own_assistant_row():
    rows = [
        {"role": "user", "content": "one", "_row_id": 1},
        _assistant(2, "call_0"), _tool(3, "call_0"),
        {"role": "assistant", "content": "done one", "_row_id": 4},
        {"role": "user", "content": "two", "_row_id": 5},
        _assistant(6, "call_0"), _tool(7, "call_0"),
    ]
    out = annotate_tool_rows(rows)

    assert [_identity(r) for r in out if r["role"] == "tool"] == [(2, 0), (6, 0)]
    # Nothing is mutated: the input rows stay as the store gave them.
    assert all("call_row_id" not in r for r in rows)
    assert len(out) == len(rows)


def test_two_calls_sharing_one_id_in_one_message_get_index_0_and_1_in_result_order():
    rows = [_assistant(10, "same", "same", "other"), _tool(11, "same"), _tool(12, "same"), _tool(13, "other")]
    out = annotate_tool_rows(rows)
    assert [_identity(r) for r in out[1:]] == [(10, 0), (10, 1), (10, 2)]


def test_a_tool_row_with_no_preceding_assistant_row_stays_unannotated():
    orphan = _tool(5, "call_0")
    out = annotate_tool_rows([{"role": "user", "content": "hi", "_row_id": 4}, orphan])
    assert out[1] is orphan and _identity(out[1]) == (None, None)


def test_a_tool_row_whose_id_the_message_never_held_stays_unannotated():
    out = annotate_tool_rows([_assistant(2, "call_0"), _tool(3, "call_9")])
    assert _identity(out[1]) == (None, None)


def test_a_call_that_never_got_a_result_cannot_absorb_the_next_turns_row():
    rows = [_assistant(2, "call_0"), {"role": "user", "content": "again", "_row_id": 3},
            _assistant(4, "call_0"), _tool(5, "call_0")]
    out = annotate_tool_rows(rows)
    assert _identity(out[3]) == (4, 0)


def test_rest_rows_name_their_row_by_id_and_unusable_entries_pass_through():
    rest = [{"id": 8, "role": "assistant", "tool_calls": _calls("call_0|fc_1")},
            {"id": 9, "role": "tool", "tool_call_id": "call_0"}, "stray", None]
    out = annotate_tool_rows(rest)
    assert _identity(out[1]) == (8, 0)
    assert out[2:] == ["stray", None]
    assert annotate_tool_rows(None) == []


def test_session_history_tool_rows_carry_row_id_and_call_identity_from_the_store(tmp_path):
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("room", source="desktop")
        db.append_messages_batch("room", [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "", "tool_calls": _calls("call_0")},
            {"role": "tool", "tool_call_id": "call_0", "content": "found it"},
            {"role": "assistant", "content": "done"},
            {"role": "user", "content": "second"},
            {"role": "assistant", "content": "", "tool_calls": _calls("call_0")},
            {"role": "tool", "tool_call_id": "call_0", "content": "found it again"},
        ])
        stored = db.get_messages_as_conversation("room", include_row_ids=True)
    finally:
        db.close()

    projected = server._history_to_messages(stored)
    tools = [row for row in projected if row["role"] == "tool"]
    by_role_ids = {i: r["_row_id"] for i, r in enumerate(stored)}
    assert [row["row_id"] for row in tools] == [by_role_ids[2], by_role_ids[6]]
    # The assistant rows project to nothing (no text), yet their ids are the call identity.
    assert [_identity(row) for row in tools] == [(by_role_ids[1], 0), (by_role_ids[5], 0)]
    assert all(row["tool_call_id"] == "call_0" for row in tools)


def test_rest_route_tool_rows_carry_the_call_identity(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr("hermes_state.DEFAULT_DB_PATH", home / "state.db")
    db = SessionDB(db_path=home / "state.db")
    try:
        db.create_session(session_id="s", source="desktop")
        db.append_messages_batch("s", [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": _calls("call_0", "call_1")},
            {"role": "tool", "tool_call_id": "call_0", "content": "a"},
            {"role": "tool", "tool_call_id": "call_1", "content": "b"},
            {"role": "assistant", "content": "all done"},
        ])
    finally:
        db.close()

    from hermes_cli.web_routers.sessions import manage_router

    app = FastAPI()
    app.include_router(manage_router)
    with TestClient(app) as client:
        rows = client.get("/api/sessions/s/messages?order=oldest&limit=50").json()["messages"]

    assistant = next(r for r in rows if r["role"] == "assistant" and r.get("tool_calls"))
    tools = [r for r in rows if r["role"] == "tool"]
    assert [_identity(r) for r in tools] == [(assistant["id"], 0), (assistant["id"], 1)]
    # A page that begins after the assistant row cannot tie its tool rows to one: they come back plain.
    with TestClient(app) as client:
        tail = client.get("/api/sessions/s/messages?order=oldest&limit=50&offset=2").json()["messages"]
    assert all(_identity(r) == (None, None) for r in tail if r["role"] == "tool")


@pytest.mark.parametrize("bad", [True, 0, -3, "7", 2.0, None])
def test_an_unusable_row_id_names_no_call(bad):
    out = annotate_tool_rows([{"role": "assistant", "tool_calls": _calls("call_0"), "_row_id": bad}, _tool(3, "call_0")])
    assert _identity(out[1]) == (None, None)
