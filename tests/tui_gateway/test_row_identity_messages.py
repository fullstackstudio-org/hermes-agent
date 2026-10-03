"""``message.interim`` / ``message.complete`` name the persisted rows they become, and a resuming client is
told which part of the streamed text no sealed note shows yet (``inflight.assistant_unsealed``)."""
import threading
from types import SimpleNamespace

import pytest

import tui_gateway.server as server
from hermes_state import SessionDB
from run_agent import AIAgent
from tui_gateway import event_replay
from tui_gateway.prompt_turn import _TurnRun
from tui_gateway.transport import bind_transport, reset_transport


def _flush_agent(db, key):
    """Agent shell owning the real flush, so rows get their ``_row_id`` and committed marker from SQLite."""
    agent = SimpleNamespace(
        _session_db=db, _session_db_created=True, _persist_disabled=False, session_id=key,
        _session_persist_lock=None, _flushed_db_message_ids=set(), _flushed_db_message_session_id=None,
        _last_flushed_db_idx=0, _persist_user_message_idx=None, _persist_user_message_override=None,
        _persist_user_message_timestamp=None, _pending_cli_user_message=None)
    agent._ensure_db_session = lambda: None
    agent._flush_messages_to_session_db = AIAgent._flush_messages_to_session_db.__get__(agent, AIAgent)
    agent._flush_messages_to_session_db_unlocked = AIAgent._flush_messages_to_session_db_unlocked.__get__(agent, AIAgent)
    return agent


def _tool_round_turn():
    return [
        {"role": "user", "content": "inspect the repository"},
        {"role": "assistant", "content": "I'll look.",
         "tool_calls": [{"id": "call_0", "type": "function", "function": {"name": "web_search", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "call_0", "content": "found it"},
        {"role": "assistant", "content": "All done."},
    ]


@pytest.fixture()
def turn(tmp_path):
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("room", source="desktop")
    agent = _flush_agent(db, "room")
    messages = _tool_round_turn()
    agent._persist_user_message_idx = 0
    agent.context_compressor = SimpleNamespace(compression_count=0)
    agent._flush_messages_to_session_db(messages, [])
    session = {"history_lock": threading.Lock(), "inflight_turn": None, "session_key": "room"}
    yield db, agent, messages, session
    db.close()


def _payload(session, agent, messages, *, final="All done.", status_result=None):
    st = _TurnRun(agent, None, None, False, history=[], compression_count=0,
                  result={"messages": messages, "final_response": final, **(status_result or {})})
    payload, _raw, _status = server._complete_turn_payload(session, st, None, 80)
    return payload


def test_message_complete_names_the_final_assistant_row(turn, monkeypatch):
    db, agent, messages, session = turn
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")

    payload = _payload(session, agent, messages)

    rows = db.get_messages_as_conversation("room", include_row_ids=True)
    assert [r["role"] for r in rows] == ["user", "assistant", "tool", "assistant"]
    assert payload["row_id"] == rows[-1]["_row_id"]
    assert payload["persisted_turn"]["final_assistant_row_id"] == payload["row_id"]


def test_message_complete_names_no_row_that_is_not_the_committed_final_answer(turn, monkeypatch):
    db, agent, messages, session = turn
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")

    # The final row's body changed after the commit: the row address says nothing about the new text.
    messages[-1].pop("_db_persisted")
    messages[-1]["content"] = "not flushed"
    payload = _payload(session, agent, messages, final="not flushed")
    assert "row_id" not in payload
    assert "final_assistant_row_id" not in payload["persisted_turn"]

    # A failed turn names no final row either.
    messages[-1]["content"] = "All done."
    agent._flush_messages_to_session_db(messages, [])
    failed = _payload(session, agent, messages, status_result={"failed": True, "error": "boom"})
    assert "row_id" not in failed


def _interim_agent():
    """Streams a note, seals it with ``already_streamed``, streams more, and reports what a resuming
    client would be told at each point."""
    snapshots = {}

    class Agent:
        def __init__(self):
            self._session_messages = []
            self._last_flushed_db_idx = 0
            self._db_flush_scan_prefix = []
            self.session_id = "room"
            self.interim_assistant_callback = None

        def clear_interrupt(self):
            return None

        def run_conversation(self, prompt, conversation_history=None, stream_callback=None, **_kw):
            session = server._sessions["sid"]
            stream_callback("Looking at it.")
            snapshots["before_note"] = server._inflight_snapshot(session)
            self.interim_assistant_callback("Looking at it.", already_streamed=True, row_id=7)
            snapshots["after_note"] = server._inflight_snapshot(session)
            stream_callback("\n\nNow the second part.")
            snapshots["after_more"] = server._inflight_snapshot(session)
            # Codex commentary and promoted finals are not text this stream showed: they seal nothing.
            self.interim_assistant_callback("Commentary the stream never showed.", already_streamed=False)
            snapshots["after_unstreamed"] = server._inflight_snapshot(session)
            return {"final_response": "done"}

    return Agent(), snapshots


class _Peer:
    def __init__(self):
        self.frames = []

    def write(self, obj):
        self.frames.append(obj)
        return True

    def close(self):
        return None


class _InlineThread:
    def __init__(self, target=None, daemon=None, args=(), kwargs=None, name=None):
        self._run = lambda: target(*args, **(kwargs or {}))

    def start(self):
        self._run()

    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None


def test_resume_snapshot_leaves_out_the_text_a_sealed_note_already_shows(tmp_path, monkeypatch):
    event_replay.reset_replay_state()
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("room", source="desktop")
    agent, snapshots = _interim_agent()
    peer = _Peer()
    session = {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path), "history": [],
        "history_lock": threading.Lock(), "history_version": 0, "inflight_turn": None, "running": False,
        "session_key": "room", "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": peer}
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    token = bind_transport(peer)
    try:
        server._methods["prompt.submit"]("rid", {"session_id": "sid", "text": "hello"})
    finally:
        reset_transport(token)
        db.close()

    # No sealed note yet: nothing to leave out, so the field is absent and ``assistant`` is the whole text.
    assert "assistant_unsealed" not in snapshots["before_note"]
    # The note is sealed: ``assistant`` (what upstream desktop reads) keeps it, the unsealed text has none.
    assert snapshots["after_note"]["assistant"] == "Looking at it."
    assert snapshots["after_note"]["assistant_unsealed"] == ""
    assert snapshots["after_more"]["assistant"] == "Looking at it.\n\nNow the second part."
    assert snapshots["after_more"]["assistant_unsealed"] == "Now the second part."
    assert snapshots["after_unstreamed"]["assistant_unsealed"] == "Now the second part."

    interim = [e for e in event_replay.events_since("sid", 0) if e["type"] == "message.interim"]
    assert [e["payload"] for e in interim] == [
        {"text": "Looking at it.", "already_streamed": True, "row_id": 7},
        {"text": "Commentary the stream never showed.", "already_streamed": False}]
    event_replay.reset_replay_state()
