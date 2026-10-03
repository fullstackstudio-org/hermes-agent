"""Contract test: every turn has one ``turn_id``, on its user row and on every frame it streams.

A live frame cannot say which stored row it becomes, and a chat reopened from a cache saved mid-turn
replays the same frames over rows it already holds. The gateway therefore mints one id per turn and
writes it where it survives each journey: ``display_metadata.turn_id`` on the user row (SQLite,
``session.history``, REST, ``session.resume``) and ``params.turn_id`` on the envelope of every
turn-stream frame (the replay ring stores ``params``, so a replayed frame keeps it).
"""
import threading

import pytest

import tui_gateway.server as server
from hermes_state import SessionDB
from tui_gateway import event_replay, row_identity
from tui_gateway.transport import bind_transport, reset_transport


class _Peer:
    auth_identity = {"provider": "oidc", "user_id": "user-a", "user_name": "Robin"}

    def __init__(self):
        self.frames = []

    def write(self, obj):
        self.frames.append(obj)
        return True

    def close(self):
        return None


class _StreamingAgent:
    """Streams through the real ``_emit`` like a live turn does, then answers."""

    def __init__(self, session_key):
        self._session_messages = []
        self._last_flushed_db_idx = 0
        self._db_flush_scan_prefix = []
        self.session_id = session_key
        self.persisted_metadata = "not called"

    def clear_interrupt(self):
        return None

    def run_conversation(self, prompt, conversation_history=None, stream_callback=None,
                         persist_user_display_metadata=None, **_kw):
        self.persisted_metadata = persist_user_display_metadata
        server._emit("reasoning.delta", "sid", {"text": "thinking"})
        server._emit("message.delta", "sid", {"text": "hello"})
        server._emit("message.interim", "sid", {"text": "hello", "already_streamed": True})
        return {"final_response": "done"}


class _InlineThread:
    def __init__(self, target=None, daemon=None, args=(), kwargs=None, name=None):
        self._run = lambda: target(*args, **(kwargs or {}))

    def start(self):
        self._run()

    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None


def _session(tmp_path, key, transport, agent=None):
    return {
        "agent": agent or _StreamingAgent(key), "attached_images": [], "cols": 80, "cwd": str(tmp_path),
        "history": [], "history_lock": threading.Lock(), "history_version": 0,
        "inflight_turn": None, "running": False, "session_key": key,
        "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": transport,
    }


@pytest.fixture(autouse=True)
def _fresh_ring():
    event_replay.reset_replay_state()
    yield
    event_replay.reset_replay_state()


@pytest.fixture()
def room(tmp_path, monkeypatch):
    """A live session wired for a real ``prompt.submit`` -> turn run against a real store, with the
    real ``_emit`` so frames land in the replay ring."""
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("room", source="desktop")
    peer = _Peer()
    session = _session(tmp_path, "room", peer)
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)

    def submit(text="hello", **params):
        token = bind_transport(peer)
        try:
            return server._methods["prompt.submit"]("rid", {"session_id": "sid", "text": text, **params})
        finally:
            reset_transport(token)

    def user_rows():
        return [row for row in db.get_messages_as_conversation("room", include_inactive=True)
                if row.get("role") == "user"]

    yield submit, user_rows, session, peer
    db.close()


def _ring():
    return event_replay.events_since("sid", 0)


def _turn_stream(ring):
    return [e for e in ring if e["type"] in row_identity.TURN_STREAM_EVENTS]


def test_a_submitted_turn_stamps_its_row_and_every_frame_with_one_id(room):
    submit, user_rows, session, _peer_ = room

    assert submit()["result"]["status"] == "streaming"

    (row,) = user_rows()
    turn_id = row["display_metadata"]["turn_id"]
    assert isinstance(turn_id, str) and len(turn_id) == 32

    stream = _turn_stream(_ring())
    assert [e["type"] for e in stream] == [
        "message.start", "reasoning.delta", "message.delta", "message.interim", "message.complete"]
    assert {e.get("turn_id") for e in stream} == {turn_id}
    # Cleared when the turn ended: the next frame of the session belongs to no turn.
    assert "turn_id" not in session


def test_the_row_read_back_through_session_history_carries_the_id(room):
    submit, _user_rows, _session, _peer_ = room
    submit()

    history = server._methods["session.history"]("rid", {"session_id": "sid"})["result"]["messages"]
    (user,) = [m for m in history if m["role"] == "user"]
    stream = _turn_stream(_ring())

    assert user["display_metadata"]["turn_id"] == stream[0]["turn_id"]


def test_session_chrome_frames_carry_no_turn_id(room):
    submit, _user_rows, _session, _peer_ = room
    submit()
    chrome = [e for e in _ring() if e["type"] not in row_identity.TURN_STREAM_EVENTS]

    assert chrome, "the turn epilogue emits session.info"
    assert all("turn_id" not in e for e in chrome)


def test_every_frame_of_a_turn_keeps_its_id_in_the_replay_ring(room):
    """The ring stores ``params``; ``session.events.since`` hands the same dicts back."""
    submit, _user_rows, _session, _peer_ = room
    submit()

    replayed = server._methods["session.events.since"]("rid", {"session_id": "sid", "last_seen": 0})["result"]
    stream = [e for e in replayed["events"] if e["type"] in row_identity.TURN_STREAM_EVENTS]

    assert stream and len({e["turn_id"] for e in stream}) == 1


def test_a_second_turn_gets_a_different_id(room):
    submit, user_rows, _session, _peer_ = room
    submit("first")
    submit("second")

    ids = [r["display_metadata"]["turn_id"] for r in user_rows()]
    assert len(ids) == 2 and ids[0] != ids[1]
    by_turn = {}
    for e in _turn_stream(_ring()):
        by_turn.setdefault(e["turn_id"], []).append(e["type"])
    assert set(by_turn) == set(ids)
    assert all(types[0] == "message.start" and types[-1] == "message.complete" for types in by_turn.values())


def test_a_client_supplied_turn_id_is_never_the_id(room):
    submit, user_rows, _session, _peer_ = room
    submit(display_metadata={"turn_id": "client-says-so"}, turn_id="client-says-so",
           title_preview="a widget intent")

    (row,) = user_rows()
    assert row["display_metadata"]["turn_id"] != "client-says-so"
    assert row["display_metadata"]["title_preview"] == "a widget intent"
    assert {e["turn_id"] for e in _turn_stream(_ring())} == {row["display_metadata"]["turn_id"]}


def test_the_replayed_or_rewritten_row_gets_a_fresh_id():
    stamped = row_identity.with_turn_id({"turn_id": "old", "author": {"id": "oidc:a"}}, "new")
    assert stamped == {"turn_id": "new", "author": {"id": "oidc:a"}}


# ---------------------------------------------------------------------------
# _event_frame
# ---------------------------------------------------------------------------

def test_a_frame_with_no_running_turn_has_no_turn_id(monkeypatch):
    monkeypatch.setattr(server, "_sessions", {"sid": {}}, raising=False)
    frame = server._event_frame("message.delta", "sid", {"text": "x"})
    assert "turn_id" not in frame["params"]
    # And a session the gateway does not know at all.
    assert "turn_id" not in server._event_frame("message.delta", "ghost", {"text": "x"})["params"]


def test_only_turn_stream_events_are_stamped(monkeypatch):
    monkeypatch.setattr(server, "_sessions", {"sid": {"turn_id": "abc"}}, raising=False)

    assert server._event_frame("message.delta", "sid", {"text": "x"})["params"]["turn_id"] == "abc"
    assert server._event_frame("message.start", "sid")["params"]["turn_id"] == "abc"
    assert "payload" not in server._event_frame("message.start", "sid")["params"]
    assert "turn_id" not in server._event_frame("status.update", "sid", {"kind": "process", "text": "x"})["params"]


def test_an_empty_turn_id_on_the_session_is_not_stamped(monkeypatch):
    monkeypatch.setattr(server, "_sessions", {"sid": {"turn_id": ""}}, raising=False)
    assert "turn_id" not in server._event_frame("message.delta", "sid", {"text": "x"})["params"]


# ---------------------------------------------------------------------------
# Turns the gateway starts itself
# ---------------------------------------------------------------------------

@pytest.fixture()
def turn_room(tmp_path, monkeypatch):
    """``_run_prompt_submit`` straight into the streaming agent, the way a queued drain, a continuation
    or an auto-continue enters it."""
    peer = _Peer()
    agent = _StreamingAgent("turn-room")
    session = _session(tmp_path, "turn-room", peer, agent)
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(server, "_ensure_session_db_row", lambda _session: True)
    monkeypatch.setattr(server, "_record_turn_marker", lambda *_a, **_k: "turn-room")
    return session, agent


def test_a_turn_entering_directly_mints_its_own_id(turn_room):
    session, agent = turn_room
    session["running"] = True

    server._run_prompt_submit("rid", "sid", session, "later")

    turn_id = row_identity.turn_id_of(agent.persisted_metadata)
    assert turn_id
    stream = _turn_stream(_ring())
    assert stream[0]["type"] == "message.start" and {e["turn_id"] for e in stream} == {turn_id}
    assert "turn_id" not in session


def test_a_continuation_stamps_message_start_too(turn_room):
    """``_dispatch_followup_turn`` emits ``message.start`` before it calls in: the id must already exist."""
    session, agent = turn_room
    session["running"] = True

    server._dispatch_followup_turn("rid", "sid", session, "keep going", "goal continuation dispatch")

    stream = _turn_stream(_ring())
    assert stream[0]["type"] == "message.start"
    assert {e["turn_id"] for e in stream} == {row_identity.turn_id_of(agent.persisted_metadata)}
    assert "turn_id" not in session


def test_a_queued_turn_keeps_the_metadata_it_was_sent_with(turn_room):
    session, agent = turn_room
    session["running"] = True

    server._run_prompt_submit("rid", "sid", session, "later", display_metadata={"title_preview": "x"},
                              row_auth_user=("oidc:user-b", "Sam"))

    meta = agent.persisted_metadata
    assert meta["title_preview"] == "x" and meta["author"] == {"id": "oidc:user-b", "name": "Sam"}
    assert row_identity.turn_id_of(meta)


def test_a_failed_followup_leaves_no_id_behind(turn_room, monkeypatch):
    session, _agent = turn_room
    session["running"] = True

    def refuse(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(server, "_run_prompt_submit", refuse)
    server._dispatch_followup_turn("rid", "sid", session, "keep going", "goal continuation dispatch")

    assert "turn_id" not in session and session["running"] is False


# ---------------------------------------------------------------------------
# Advert
# ---------------------------------------------------------------------------

def test_the_build_advertises_transcript_row_identity(monkeypatch):
    assert server._methods["gateway.capabilities"]("rid", {})["result"]["transcript_row_identity"] is True

    monkeypatch.setattr(row_identity, "TRANSCRIPT_ROW_IDENTITY", False)
    assert server._methods["gateway.capabilities"]("rid", {})["result"]["transcript_row_identity"] is False
