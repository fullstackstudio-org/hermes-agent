"""Where a turn's id comes from and where it ends: the hand-off to ``_run_prompt_submit``, every place
``running`` is force-released, the id a late frame wears, and the compute-host journey.

``test_turn_identity.py`` pins the stamp itself (one id on the user row and on every frame). These pin the
lifecycle around it: a turn must never adopt an id it was not handed, a force-released turn must not leave
one behind for the next drain or heartbeat, and a frame names the turn that emitted it."""
import io
import json
import threading
import time
import types

import pytest

import tui_gateway.server as server
from tui_gateway import event_replay, row_identity
from tui_gateway.compute_host import ComputeHost
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


class _Agent:
    """Answers one turn, recording the display metadata its user row would be persisted with."""

    def __init__(self, session_key="room", *, during=None):
        self._session_messages = []
        self._last_flushed_db_idx = 0
        self._db_flush_scan_prefix = []
        self.session_id = session_key
        self.persisted = []
        self.during = during

    def clear_interrupt(self):
        return None

    def run_conversation(self, prompt, conversation_history=None, stream_callback=None,
                         persist_user_display_metadata=None, **_kw):
        self.persisted.append(persist_user_display_metadata)
        server._emit("message.delta", "sid", {"text": "hello"})
        if self.during is not None:
            self.during()
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


class _DeadThread:
    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None


def _session(tmp_path, agent, transport):
    return {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path), "history": [],
        "history_lock": threading.Lock(), "history_version": 0, "inflight_turn": None, "running": False,
        "session_key": "room", "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": transport}


@pytest.fixture(autouse=True)
def _fresh_ring():
    event_replay.reset_replay_state()
    yield
    event_replay.reset_replay_state()


@pytest.fixture()
def room(tmp_path, monkeypatch):
    """A live session whose turns run inline through the real ``_run_prompt_submit`` and the real ``_emit``."""
    peer = _Peer()
    agent = _Agent()
    session = _session(tmp_path, agent, peer)
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(server, "_ensure_session_db_row", lambda _session: True)
    monkeypatch.setattr(server, "_record_turn_marker", lambda *_a, **_k: "room")
    monkeypatch.setattr(server, "_hermes_home", tmp_path)
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    return types.SimpleNamespace(session=session, agent=agent, peer=peer)


def _ring():
    return event_replay.events_since("sid", 0)


def _stream():
    return [e for e in _ring() if e["type"] in row_identity.TURN_STREAM_EVENTS]


def _ids_of_the_turn(room):
    """The one id the turn's row and every frame it streamed agree on."""
    (metadata,) = room.agent.persisted
    turn_id = row_identity.turn_id_of(metadata)
    assert turn_id
    stream = _stream()
    assert stream and stream[0]["type"] == "message.start"
    assert {e.get("turn_id") for e in stream} == {turn_id}
    return turn_id


# ---------------------------------------------------------------------------
# One hand-off, never a leftover
# ---------------------------------------------------------------------------

def test_a_leftover_session_turn_id_is_never_adopted(room):
    """``session["turn_id"]`` is what frames are stamped with, not a hand-off: whatever a force-released turn
    left in it belongs to a turn that is over."""
    room.session.update(running=True, turn_id="a-dead-turns-id")

    server._run_prompt_submit("rid", "sid", room.session, "later")

    turn_id = _ids_of_the_turn(room)
    assert turn_id != "a-dead-turns-id"
    assert "turn_id" not in room.session


def test_only_an_explicitly_pre_minted_id_is_adopted(room):
    room.session["running"] = True
    minted = row_identity.begin_turn_id(room.session)
    assert room.session["_pending_turn_id"] == minted == room.session["turn_id"]

    server._run_prompt_submit("rid", "sid", room.session, "later")

    assert _ids_of_the_turn(room) == minted
    assert "_pending_turn_id" not in room.session and "turn_id" not in room.session


def test_the_hand_off_is_consumed_even_when_the_row_already_names_the_turn(room):
    """prompt.submit stamps the id into the row's metadata; a stray pending id must not outlive that turn."""
    room.session.update(running=True, _pending_turn_id="stray")

    server._run_prompt_submit("rid", "sid", room.session, "later",
                              display_metadata=row_identity.with_turn_id({}, "from-the-row"))

    assert _ids_of_the_turn(room) == "from-the-row"
    assert "_pending_turn_id" not in room.session


def test_stop_on_a_dead_run_thread_then_a_queued_drain_gets_a_new_id(room):
    """The reviewed bug: Stop on a turn whose run thread is already gone clears ``running`` and the inflight
    turn but used to leave ``turn_id``, which the next drain adopted: two turns, one id."""
    inflight = {"assistant": "half an answer", "streaming": True, "user": "first"}
    room.session.update(running=True, turn_id="dead-turn", inflight_turn=inflight, _run_thread=_DeadThread())

    server._interrupt_session_turn("sid", room.session)

    assert room.session["running"] is False
    assert "turn_id" not in room.session and "_pending_turn_id" not in room.session
    with room.session["history_lock"]:
        server._enqueue_prompt(room.session, "queued while it ran", room.peer)
    assert server._drain_queued_prompt("rid", "sid", room.session) is True

    new_id = _ids_of_the_turn(room)
    assert new_id != "dead-turn"
    assert "dead-turn" not in {e.get("turn_id") for e in _ring()}


def test_a_generation_bump_cancelling_a_drain_leaves_no_id(room, monkeypatch):
    """Stop lands between the drain's claim and its dispatch: the claim is handed back and nothing runs."""
    room.session.update(turn_id="stale", _pending_turn_id="stale")
    with room.session["history_lock"]:
        server._enqueue_prompt(room.session, "queued", room.peer)
    set_queue = server._ac_set_queue

    def set_queue_then_stop(session, queue):
        set_queue(session, queue)
        session["_queued_prompt_generation"] = int(session.get("_queued_prompt_generation", 0)) + 1

    monkeypatch.setattr(server, "_ac_set_queue", set_queue_then_stop)

    server._drain_queued_prompt("rid", "sid", room.session)

    assert room.session["running"] is False and not room.agent.persisted
    assert "turn_id" not in room.session and "_pending_turn_id" not in room.session


def test_a_replayed_row_never_carries_its_old_turn_id_into_the_new_turn():
    from tui_gateway.row_author import replayed_row_metadata

    stored = {"turn_id": "the-first-turn", "title_preview": "keep me",
              "author": {"id": "oidc:robin", "name": "Robin"}}

    replayed = replayed_row_metadata(stored, ("oidc:robin", "Robin"), ("oidc:sam", "Sam"))

    assert "turn_id" not in replayed
    assert replayed["title_preview"] == "keep me" and replayed["replayed_by"]["id"] == "oidc:sam"


def test_a_retry_queued_while_busy_runs_as_a_new_turn_with_a_new_id(room):
    """``/retry`` on a busy session queues the replayed row's metadata. Whatever turn id that metadata still
    names is the first turn's, and the drained turn must not adopt it: one id, one turn."""
    stored_metadata = {"turn_id": "the-first-turn", "author": {"id": "oidc:robin", "name": "Robin"}}
    room.session.update(running=True, turn_id="the-first-turn")
    with room.session["history_lock"]:
        server._enqueue_prompt(room.session, "what about Q3?", room.peer, row_metadata=stored_metadata,
                               turn_auth_user=("oidc:sam", "Sam"))
    room.session.pop("turn_id")  # the first turn ended
    room.session["running"] = False

    assert server._drain_queued_prompt("rid", "sid", room.session) is True

    (metadata,) = room.agent.persisted
    new_id = _ids_of_the_turn(room)
    assert new_id != "the-first-turn"
    assert metadata["author"] == {"id": "oidc:robin", "name": "Robin"}  # the row still says who wrote it
    assert "the-first-turn" not in {e.get("turn_id") for e in _ring()}


def test_a_refused_turn_leaves_no_id(room, monkeypatch):
    room.session["running"] = True
    row_identity.begin_turn_id(room.session)
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda *_a, **_k: types.SimpleNamespace(reason="busy"))

    assert server._run_prompt_submit("rid", "sid", room.session, "later") is False

    assert room.session["running"] is False
    assert "turn_id" not in room.session and "_pending_turn_id" not in room.session


def test_a_failed_hand_off_releases_both_ids(room, monkeypatch):
    room.session["running"] = True

    def refuse(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(server, "_run_prompt_submit", refuse)
    with pytest.raises(RuntimeError, match="boom"):  # logged, released, then re-raised to the caller
        server._notif_submit("rid", "sid", room.session, "wake up", "wake-up dispatch")

    assert room.session["running"] is False
    assert "turn_id" not in room.session and "_pending_turn_id" not in room.session


# ---------------------------------------------------------------------------
# Callers that emit message.start before _run_prompt_submit
# ---------------------------------------------------------------------------

def test_a_notification_turn_stamps_message_start_with_the_id_its_row_gets(room):
    room.session["running"] = True

    server._notif_submit("rid", "sid", room.session, "a build finished", "completion notification")

    _ids_of_the_turn(room)
    assert "turn_id" not in room.session


def test_a_drained_queued_prompt_names_its_own_turn_on_the_row_and_every_frame(room):
    with room.session["history_lock"]:
        server._enqueue_prompt(room.session, "queued while it ran", room.peer)

    assert server._drain_queued_prompt("rid", "sid", room.session) is True

    _ids_of_the_turn(room)
    assert room.session["running"] is False and "turn_id" not in room.session


def test_a_loop_tick_stamps_message_start_with_the_id_its_row_gets(room, monkeypatch):
    import hermes_cli.loops as loops

    class _Manager:
        state = None

        def __init__(self, session_id):
            pass

        def is_due(self):
            return True

        def fire_tick(self):
            return "check the queue again"

        def abandon_tick(self):
            return None

    monkeypatch.setattr(loops, "LoopManager", _Manager)
    monkeypatch.setattr(loops, "goal_blocks_loop_tick", lambda _key: False)

    server._maybe_fire_tui_loop_tick("sid", room.session)

    _ids_of_the_turn(room)
    assert room.session["running"] is False and "turn_id" not in room.session


def test_an_auto_continue_stamps_message_start_with_the_id_its_row_gets(room, monkeypatch, tmp_path):
    from tui_gateway.turn_marker import record_turn_start

    record_turn_start(tmp_path, "room", "fix the flaky test")
    monkeypatch.setattr(server, "_start_agent_build", lambda _sid, _session: None)
    monkeypatch.setattr(server, "_wait_agent", lambda _session, _rid, timeout=30.0: None)

    assert server._maybe_schedule_auto_continue("sid", room.session, "room") is not None

    _ids_of_the_turn(room)
    assert room.session["running"] is False and "turn_id" not in room.session


# ---------------------------------------------------------------------------
# A turn that never reaches _run_prompt_submit
# ---------------------------------------------------------------------------

def test_the_terminal_frame_of_a_failed_agent_build_names_the_turn(room, monkeypatch):
    """The user row was persisted at submit with the turn's id, so the ``status: error`` ``message.complete``
    that ends the turn when the build fails belongs to that turn, though ``_run_prompt_submit`` never ran."""
    room.session["running"] = True
    monkeypatch.setattr(server, "_wait_agent_for_prompt", lambda *_a, **_k: {"error": {"message": "no key"}})

    server._run_after_agent_ready(
        "rid", "sid", room.session, "hi", None, row_identity.with_turn_id({}, "t-submit"), None)

    (complete,) = [e for e in _ring() if e["type"] == "message.complete"]
    assert complete["payload"]["status"] == "error" and complete["turn_id"] == "t-submit"
    assert room.session["running"] is False and "turn_id" not in room.session


def test_the_error_frame_of_a_turn_cancelled_before_the_agent_was_ready_names_the_turn(room, monkeypatch):
    room.session.update(running=True, _turn_cancel_requested=True)
    monkeypatch.setattr(server, "_wait_agent_for_prompt", lambda *_a, **_k: None)

    server._run_after_agent_ready(
        "rid", "sid", room.session, "hi", None, row_identity.with_turn_id({}, "t-submit"), None)

    (error,) = [e for e in _ring() if e["type"] == "error"]
    assert error["turn_id"] == "t-submit"
    assert room.session["running"] is False and "turn_id" not in room.session


# ---------------------------------------------------------------------------
# Which turn a frame belongs to
# ---------------------------------------------------------------------------

def test_a_frame_names_the_turn_that_emitted_it_not_the_one_the_session_moved_on_to(monkeypatch):
    monkeypatch.setattr(server, "_sessions", {"sid": {"turn_id": "next-turn"}, "other": {"turn_id": "o"}},
                        raising=False)

    token = row_identity.bind_emitting_turn("sid", "this-turn")
    try:
        assert server._event_frame("message.delta", "sid", {"text": "x"})["params"]["turn_id"] == "this-turn"
        assert server._event_frame("tool.start", "sid", {"tool_id": "t", "name": "n"})["params"]["turn_id"] == "this-turn"
        # Another session's frame is that session's own: the binding is per session.
        assert server._event_frame("message.delta", "other", {"text": "x"})["params"]["turn_id"] == "o"
        # Chrome is never stamped, bound or not.
        assert "turn_id" not in server._event_frame("status.update", "sid", {"kind": "process", "text": "x"})["params"]
        # A thread that never bound it (a tool pool worker) falls back to the session's current turn.
        seen = []
        worker = threading.Thread(
            target=lambda: seen.append(server._event_frame("message.delta", "sid", {"text": "x"})["params"]["turn_id"]))
        worker.start()
        worker.join()
        assert seen == ["next-turn"]
    finally:
        row_identity.unbind_emitting_turn(token)

    assert server._event_frame("message.delta", "sid", {"text": "x"})["params"]["turn_id"] == "next-turn"


def test_a_late_frame_of_a_released_turn_does_not_take_the_next_turns_id(room):
    """Stop released the session and the next turn took the slot while the old turn's thread was still
    emitting: its late frame keeps its own id."""
    def a_new_turn_takes_the_session():
        room.session["turn_id"] = "the-next-turn"
        server._emit("message.delta", "sid", {"text": "late"})

    room.agent.during = a_new_turn_takes_the_session
    room.session["running"] = True

    server._run_prompt_submit("rid", "sid", room.session, "first")

    (metadata,) = room.agent.persisted
    own = row_identity.turn_id_of(metadata)
    deltas = [e for e in _ring() if e["type"] == "message.delta"]
    assert [d["turn_id"] for d in deltas] == [own, own]
    assert own != "the-next-turn"
    # The binding ended with the turn: the thread's next frame is whatever the session says.
    assert row_identity.frame_turn_id("sid", {"turn_id": "x"}) == "x"
    assert row_identity.frame_turn_id("sid", {}) is None


# ---------------------------------------------------------------------------
# Compute host: minted by the parent, adopted by the child
# ---------------------------------------------------------------------------

def _frames(out):
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def _wait(out, predicate, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for frame in _frames(out):
            if predicate(frame):
                return frame
        time.sleep(0.01)
    raise AssertionError(f"timed out; saw={_frames(out)}")


def test_an_isolated_turn_adopts_the_parents_id_on_its_frames_and_its_row(tmp_path, monkeypatch):
    """The parent mints the id and puts it in the turn frame's ``display_metadata`` (``prompt.submit``). The
    child's ``_run_prompt_submit`` adopts it: its row persists with it, and every turn-stream frame the child
    writes carries it, still carrying it after ``_relay_compute_host_rpc`` hands it to the parent's clients.
    The frame's own ``turn_id`` is the dispatch token, a different thing, and never stamps a frame."""
    for name, value in (
        ("_wire_callbacks", lambda sid: None), ("_sync_agent_model_with_config", lambda sid, session: None),
        ("_session_cwd", lambda session: str(tmp_path)), ("_register_session_cwd", lambda session: None),
        ("_tts_stream_begin", lambda: None), ("_sync_session_key_after_compress", lambda *a, **k: None),
        ("_get_usage", lambda agent: {}),
    ):
        monkeypatch.setattr(server, name, value)
    persisted = []

    def run_conversation(prompt, *, conversation_history=None, stream_callback=None,
                         persist_user_display_metadata=None, **_kw):
        persisted.append(persist_user_display_metadata)
        stream_callback("a ")
        stream_callback("b ")
        return {"final_response": "a b ", "messages": [{"role": "user", "content": prompt},
                                                       {"role": "assistant", "content": "a b "}]}

    agent = types.SimpleNamespace(session_id="s1-key", run_conversation=run_conversation,
                                  clear_interrupt=lambda: None, hard_interrupt=lambda *a, **k: None)
    sid = "s1"
    server._sessions[sid] = {
        "agent": agent, "session_key": "s1-key", "history": [], "history_lock": threading.Lock(),
        "history_version": 0, "running": False, "attached_images": [], "image_counter": 0, "cols": 80,
        "slash_worker": None, "show_reasoning": False, "tool_progress_mode": "all", "inflight_turn": None,
        "active_session_lease": object()}
    parent_minted = row_identity.mint_turn_id()
    out = io.StringIO()
    host = ComputeHost(stdout=out, heartbeat_secs=0)
    try:
        host.handle_frame({
            "type": "turn.start", "sid": sid, "request_id": "dispatch-token", "turn_id": "dispatch-token",
            "prompt": "hello", "display_metadata": row_identity.with_turn_id({"author": {"id": "oidc:a"}}, parent_minted)})
        _wait(out, lambda f: f["type"] == "turn.end")
    finally:
        server._sessions.pop(sid, None)
        host.close()

    # The row the child persists: the parent's id, beside the author the parent stamped.
    (metadata,) = persisted
    assert metadata["turn_id"] == parent_minted and metadata["author"] == {"id": "oidc:a"}

    rpc = [f["message"] for f in _frames(out) if f["type"] == "rpc"]
    events = [m for m in rpc if m.get("method") == "event"]
    stream = [m for m in events if m["params"]["type"] in row_identity.TURN_STREAM_EVENTS]
    assert [m["params"]["type"] for m in stream] == ["message.start", "message.delta", "message.delta", "message.complete"]
    assert {m["params"]["turn_id"] for m in stream} == {parent_minted}
    assert not [m for m in events if m["params"]["type"] not in row_identity.TURN_STREAM_EVENTS
                and "turn_id" in m["params"]]

    # The parent relays each frame to its clients untouched, the id included.
    relayed = []
    monkeypatch.setattr(server, "write_json", lambda obj: relayed.append(obj) or True)
    for message in rpc:
        assert server._relay_compute_host_rpc(message) is True
    assert relayed == rpc
    assert {m["params"]["turn_id"] for m in relayed
            if m.get("method") == "event" and m["params"]["type"] in row_identity.TURN_STREAM_EVENTS} == {parent_minted}
