"""End-to-end contract: what a client may rely on to tell which stored row a live frame becomes.

One real turn goes through ``prompt.submit`` into a real ``AIAgent`` over a real ``SessionDB``, with a mocked
model and the gateway's own callback wiring: a note and a tool call, a second note and a second tool call, then
the final answer. Everything a client sees is read back the way a client reads it (the frames the transport
wrote, ``session.events.since``, ``session.resume``, ``session.history``) and pinned against the rows:

- a turn has ONE ``turn_id``: on the envelope of every frame it streams and on its user row's
  ``display_metadata``;
- ``message.interim`` and ``message.complete`` name their assistant row (``row_id``);
- ``tool.start`` / ``tool.complete`` name their call as ``(call_row_id, call_index)``, and ``tool.complete``
  names the tool RESULT row (``row_id``); history tool rows carry the same three numbers;
- the replay ring returns the same frames, ids included;
- a ``session.resume`` mid-turn says which streamed text no stored row shows yet (``assistant_unsealed``), the
  same with interim notes on or off.

It runs twice: with ``display.interim_assistant_messages`` on and off. Off, no ``message.interim`` exists and the
call still names the assistant row, which is the row the note would have been.
"""
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import tui_gateway.server as server
from hermes_state import SessionDB
from run_agent import AIAgent
from tui_gateway import event_replay, row_identity
from tui_gateway.transport import bind_transport, reset_transport

SID = "sid"
KEY = "room"
PROMPT = "look around the repository"
NOTE_1 = "Let me look at the layout first."
NOTE_2 = "Now the tests."
FINAL = "Everything checks out."


class _Peer:
    """A signed-in client connection that keeps every frame it is sent."""

    auth_identity = {"provider": "oidc", "user_id": "user-a", "user_name": "Robin"}

    def __init__(self):
        self.frames = []

    def write(self, obj):
        self.frames.append(obj)
        return True

    def close(self):
        return None

    @property
    def events(self):
        return [f["params"] for f in self.frames if f.get("method") == "event"]


_RealThread = threading.Thread


class _InlineThread:
    def __init__(self, target=None, args=(), kwargs=None):
        self._run = lambda: target(*args, **(kwargs or {}))

    def start(self):
        self._run()

    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None


def _inline_submit_thread(target=None, daemon=None, args=(), kwargs=None, name=None):
    """``prompt.submit`` hands the turn to a worker thread. The submit thread is only a trampoline, so it runs
    inline (the turn's own ``prompt-turn-<sid>`` thread stays real, as every tool of the turn runs in a pool
    that must not wait on a lock the submitting caller still holds)."""
    if name is None:
        return _InlineThread(target=target, args=args, kwargs=kwargs)
    return _RealThread(target=target, daemon=daemon, args=args, kwargs=kwargs or {}, name=name)


def _tool_defs():
    return [{"type": "function", "function": {"name": "web_search", "description": "search",
                                                "parameters": {"type": "object", "properties": {}}}}]


def _agent():
    hermes_home = Path(tempfile.mkdtemp(prefix="hermes-test-home-"))
    (hermes_home / "logs").mkdir(parents=True, exist_ok=True)
    with (
        patch("model_tools.get_tool_definitions", return_value=_tool_defs()),
        patch("model_tools.check_toolset_requirements", return_value={}),
        patch("agent.process_bootstrap.OpenAI"),
        patch("run_agent._hermes_home", hermes_home),
        patch("agent.model_metadata.fetch_model_metadata", return_value={}),
    ):
        agent = AIAgent(api_key="test-key", base_url="https://openrouter.ai/api/v1", quiet_mode=True,
                        skip_context_files=True, skip_memory=True)
    agent.client = MagicMock()
    agent._cached_system_prompt = "You are helpful."
    agent._use_prompt_caching = False
    agent.compression_enabled = False
    agent.save_trajectories = False
    # The mocked model is not a stream iterator; it feeds the stream callback itself (see ``_model_step``).
    agent._disable_streaming = True
    return agent


def _call(call_id):
    return SimpleNamespace(id=call_id, type="function",
                           function=SimpleNamespace(name="web_search", arguments=json.dumps({"query": call_id})))


def _model_step(agent, text, *, call_id=None):
    """One model answer. The text reaches the stream callback first, as a streaming provider delivers it."""
    tool_calls = [_call(call_id)] if call_id else None
    message = SimpleNamespace(content=text, tool_calls=tool_calls)
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls" if call_id else "stop")],
        model="test/model", usage=None)

    def answer(**_kwargs):
        agent._fire_stream_delta(text)
        return response
    return answer


def _script(agent, *steps):
    """The model answers with ``steps`` in order (a ``side_effect`` list would return them uncalled)."""
    queue = iter(steps)
    agent.client.chat.completions.create.side_effect = lambda **kwargs: next(queue)(**kwargs)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("agent.title_generator.maybe_auto_title", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "agent.tool_executor.maybe_persist_tool_result", lambda **kwargs: kwargs["content"])


@pytest.fixture(params=[True, False], ids=["interim_on", "interim_off"])
def interim_on(request):
    return request.param


@pytest.fixture()
def world(tmp_path, monkeypatch, interim_on):
    """One gateway session over a real SQLite store; every turn runs inline on the submitting thread."""
    event_replay.reset_replay_state()
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session(session_id=KEY, source="desktop", model="test/model")
    peer = _Peer()
    agent = _agent()
    agent._session_db = db
    agent._session_db_created = True
    agent.session_id = KEY
    agent._last_flushed_db_idx = 0
    agent._flushed_db_message_ids = set()
    agent._flushed_db_message_session_id = None
    agent._persist_disabled = False
    session = {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path), "history": [],
        "history_lock": threading.Lock(), "history_version": 0, "inflight_turn": None, "running": False,
        "session_key": KEY, "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": peer}
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {SID: session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _inline_submit_thread)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(
        server, "_load_cfg", lambda: {"display": {"interim_assistant_messages": interim_on}})
    # The gateway's own callbacks (what ``session.create`` hands the agent it builds).
    for key, callback in server._agent_cbs(SID).items():
        setattr(agent, key, callback)
    token = bind_transport(peer)
    try:
        yield SimpleNamespace(agent=agent, db=db, peer=peer, session=session, resumes=[])
    finally:
        reset_transport(token)
        event_replay.reset_replay_state()
        db.close()


def _rpc(method, **params):
    response = server._methods[method]("rid", {"session_id": SID, **params})
    assert "error" not in response, response
    return response["result"]


def _submit(world, text):
    assert _rpc("prompt.submit", text=text)["status"] == "streaming"
    world.session["_run_thread"].join()
    assert world.session["running"] is False


def _run_turn(world):
    """The one scenario: note + tool call, note + tool call, final answer. A resume is taken inside each tool
    run, i.e. after the round's note was sealed and before the next model answer streams anything."""
    agent = world.agent
    _script(agent, _model_step(agent, NOTE_1, call_id="call_0"), _model_step(agent, NOTE_2, call_id="call_0"),
            _model_step(agent, FINAL))

    def run_tool(*_args, **_kwargs):
        # Raw answers: an assertion failing on the tool's thread would only surface as a tool error.
        world.resumes.append(server._methods["session.resume"]("rid", {"session_id": KEY}))
        return "a plain result"

    with (
        patch("model_tools.handle_function_call", side_effect=run_tool),
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        _submit(world, PROMPT)


def _history(world):
    """``session.history`` as a client reads it. The handler falls back to the live list when the store read
    fails, so the stored rows are checked first: an empty answer must not pass for a different reason."""
    stored = world.db.get_messages_as_conversation(KEY, include_ancestors=True, include_row_ids=True)
    messages = _rpc("session.history")["messages"]
    assert stored and messages, (stored, messages)
    return messages


def _of(frames, *types):
    return [f for f in frames if f["type"] in types]


def test_the_whole_contract_from_prompt_submit_to_session_history(world, interim_on):
    _run_turn(world)

    frames = world.peer.events
    history = _history(world)
    users = [m for m in history if m["role"] == "user"]
    assistants = [m for m in history if m["role"] == "assistant"]
    tools = [m for m in history if m["role"] == "tool"]
    assert [m["role"] for m in history] == ["user", "assistant", "tool", "assistant", "tool", "assistant"]
    stored = world.db.get_messages_as_conversation(KEY, include_row_ids=True)
    assert [bool(m.get("tool_calls")) for m in stored if m["role"] == "assistant"] == [True, True, False]

    # One turn, one id: the user row and every frame of the turn name it.
    (user,) = users
    turn_id = user["display_metadata"]["turn_id"]
    assert isinstance(turn_id, str) and len(turn_id) == 32
    turn_frames = [f for f in frames if f["type"] in row_identity.TURN_STREAM_EVENTS]
    assert _of(turn_frames, "message.start", "message.delta", "tool.start", "tool.complete", "message.complete")
    assert {f["turn_id"] for f in turn_frames} == {turn_id}
    # What is not part of the turn's stream carries no turn.
    assert not [f for f in frames if f["type"] not in row_identity.TURN_STREAM_EVENTS and "turn_id" in f]

    # message.interim names the assistant row that holds the note, with the same text.
    interims = _of(frames, "message.interim")
    if interim_on:
        assert [i["payload"]["text"] for i in interims] == [NOTE_1, NOTE_2]
        assert all(i["payload"]["already_streamed"] is True for i in interims)
        by_id = {m["row_id"]: m for m in assistants}
        for interim in interims:
            assert by_id[interim["payload"]["row_id"]]["text"] == interim["payload"]["text"]
        assert [i["payload"]["row_id"] for i in interims] == [m["row_id"] for m in assistants[:2]]
    else:
        assert interims == []

    # tool.start names the assistant row that listed the call (the interim's row when there is one), position 0.
    starts = [f["payload"] for f in _of(frames, "tool.start")]
    completes = [f["payload"] for f in _of(frames, "tool.complete")]
    assert [(s["call_row_id"], s["call_index"]) for s in starts] == [(m["row_id"], 0) for m in assistants[:2]]
    assert all("row_id" not in s for s in starts)
    if interim_on:
        assert [s["call_row_id"] for s in starts] == [i["payload"]["row_id"] for i in interims]
    # Both calls carry the provider's id "call_0": the pair is what tells them apart.
    assert [s["tool_id"] for s in starts] == ["call_0", "call_0"]

    # tool.complete names its call and the tool RESULT row; the history tool row carries the same three numbers.
    assert [(c["call_row_id"], c["call_index"]) for c in completes] == [
        (s["call_row_id"], s["call_index"]) for s in starts]
    assert [c["row_id"] for c in completes] == [t["row_id"] for t in tools]
    for complete, tool in zip(completes, tools):
        assert (tool["call_row_id"], tool["call_index"]) == (complete["call_row_id"], complete["call_index"])
        assert tool["tool_call_id"] == complete["tool_id"]

    # message.complete names the last assistant row, the one carrying the final answer.
    (complete_frame,) = _of(frames, "message.complete")
    assert complete_frame["payload"]["row_id"] == assistants[-1]["row_id"]
    assert assistants[-1]["text"] == FINAL == complete_frame["payload"]["text"]
    assert complete_frame["payload"]["persisted_turn"]["final_assistant_row_id"] == assistants[-1]["row_id"]

    # The replay ring hands a reconnecting client the same frames, ids included.
    replay = _rpc("session.events.since", last_seen=0)
    assert replay["truncated"] is False
    assert replay["events"] == frames
    assert [f["turn_id"] for f in _of(replay["events"], "message.start")] == [turn_id]
    assert [f["payload"].get("row_id") for f in _of(replay["events"], "message.interim", "message.complete")] == (
        [i["payload"]["row_id"] for i in interims] + [complete_frame["payload"]["row_id"]])


def test_a_resume_mid_turn_paints_only_what_no_sealed_note_shows(world, interim_on):
    _run_turn(world)

    assert len(world.resumes) == 2 and all("error" not in r for r in world.resumes), world.resumes
    inflight_1, inflight_2 = (r["result"]["inflight"] for r in world.resumes)
    # The prompt is identified by the turn, so a client holding the user row by id does not paint it twice.
    turn_id = _history(world)[0]["display_metadata"]["turn_id"]
    assert inflight_1["display_metadata"]["turn_id"] == inflight_2["display_metadata"]["turn_id"] == turn_id
    assert inflight_1["user"] == PROMPT

    # ``assistant`` (what upstream desktop reads) keeps every streamed note, sealed or not.
    assert NOTE_1 in inflight_1["assistant"]
    assert NOTE_1 in inflight_2["assistant"] and NOTE_2 in inflight_2["assistant"]
    # ``assistant_unsealed`` leaves out the notes the history rows already show. The round's assistant row is
    # durable and named by ``tool.start.call_row_id`` whether or not interim notes are on, so the answer is the
    # same both ways: with interims off no ``message.interim`` ever sealed it, and a resume used to paint the
    # round's whole text again beside the history row.
    for inflight in (inflight_1, inflight_2):
        assert inflight["assistant_unsealed"] == ""
    assert NOTE_1 not in inflight_1["assistant_unsealed"]
    assert NOTE_2 not in inflight_2["assistant_unsealed"]

    # Once the turn is over nothing is in flight.
    assert _rpc("session.resume", session_id=KEY).get("inflight") is None


def test_a_second_turn_gets_its_own_turn_id(world):
    _run_turn(world)
    agent = world.agent
    _script(agent, _model_step(agent, "Second answer."))
    with (
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        _submit(world, "and once more")

    users = [m for m in _history(world) if m["role"] == "user"]
    first, second = (u["display_metadata"]["turn_id"] for u in users)
    assert first != second
    starts = _of(world.peer.events, "message.start")
    assert [f["turn_id"] for f in starts] == [first, second]
