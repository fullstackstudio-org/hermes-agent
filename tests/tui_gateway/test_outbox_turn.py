"""End to end: a bot's file reaches the person in the Hermie apps as an attachment, never as a server path.

One real turn goes through ``prompt.submit`` into a real ``AIAgent`` over a real ``SessionDB`` with a mocked model.
The model calls ``text_to_speech`` (its result names ``<home>/cache/audio/tts_*.mp3`` with ``MEDIA:`` and says
``voice_compatible: false``, the ElevenLabs case) and answers with a chart of its own (``MEDIA:<path>``). What a
client sees is read back the way it reads it: the frames, ``session.history`` and the dashboard's
``/api/sessions/{id}/messages`` projection. A session of another surface (``desktop``) is left as it was.
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
from tui_gateway import event_replay, outbox, upload_dirs
from tui_gateway.transport import bind_transport, reset_transport

pytestmark = pytest.mark.skipif(not upload_dirs.supported(), reason="needs O_NOFOLLOW and dir_fd")

SID = "sid"
KEY = "room"
_MP3 = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x55" * 200
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class _Peer:
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
    if name is None:
        return _InlineThread(target=target, args=args, kwargs=kwargs)
    return _RealThread(target=target, daemon=daemon, args=args, kwargs=kwargs or {}, name=name)


def _tool_defs():
    return [{"type": "function", "function": {"name": "text_to_speech", "description": "speak",
                                                "parameters": {"type": "object", "properties": {}}}}]


def _agent(home: Path):
    (home / "logs").mkdir(parents=True, exist_ok=True)
    with (
        patch("model_tools.get_tool_definitions", return_value=_tool_defs()),
        patch("model_tools.check_toolset_requirements", return_value={}),
        patch("agent.process_bootstrap.OpenAI"),
        patch("run_agent._hermes_home", home),
        patch("agent.model_metadata.fetch_model_metadata", return_value={}),
    ):
        agent = AIAgent(api_key="test-key", base_url="https://openrouter.ai/api/v1", quiet_mode=True,
                        skip_context_files=True, skip_memory=True)
    agent.client = MagicMock()
    agent._cached_system_prompt = "You are helpful."
    agent._use_prompt_caching = False
    agent.compression_enabled = False
    agent.save_trajectories = False
    agent._disable_streaming = True
    return agent


def _model_step(agent, text, *, call=False):
    tool_calls = [SimpleNamespace(id="call_tts", type="function", function=SimpleNamespace(
        name="text_to_speech", arguments=json.dumps({"text": "hello"})))] if call else None
    message = SimpleNamespace(content=text, tool_calls=tool_calls)
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls" if call else "stop")],
        model="test/model", usage=None)

    def answer(**_kwargs):
        agent._fire_stream_delta(text)
        return response
    return answer


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("agent.title_generator.maybe_auto_title", lambda *args, **kwargs: None)
    monkeypatch.setattr("agent.tool_executor.maybe_persist_tool_result", lambda **kwargs: kwargs["content"])


def _world(tmp_path, monkeypatch, source):
    event_replay.reset_replay_state()
    home = Path(tempfile.mkdtemp(prefix="hermes-outbox-home-", dir=tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_MEDIA_DELIVERY_STRICT", raising=False)
    (home / "cache" / "audio").mkdir(parents=True)
    clip = home / "cache" / "audio" / "tts_20261004_225730_989324.mp3"
    clip.write_bytes(_MP3)
    chart = tmp_path / "chart.png"
    chart.write_bytes(_PNG)
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session(session_id=KEY, source=source, model="test/model")
    peer = _Peer()
    agent = _agent(home)
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
        "session_key": KEY, "show_reasoning": False, "slash_worker": None, "source": source,
        "tool_progress_mode": "all", "transport": peer,
        "auth_user_id": "oidc:user-a", "auth_user_name": "Robin"}
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {SID: session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _inline_submit_thread)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    for key, callback in server._agent_cbs(SID).items():
        setattr(agent, key, callback)
    return SimpleNamespace(agent=agent, db=db, peer=peer, session=session, home=home, clip=clip, chart=chart)


@pytest.fixture()
def hermie(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch, "hermie")
    token = bind_transport(world.peer)
    try:
        yield world
    finally:
        reset_transport(token)
        event_replay.reset_replay_state()
        world.db.close()


@pytest.fixture()
def desktop(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch, "desktop")
    token = bind_transport(world.peer)
    try:
        yield world
    finally:
        reset_transport(token)
        event_replay.reset_replay_state()
        world.db.close()


def _rpc(method, **params):
    response = server._methods[method]("rid", {"session_id": SID, **params})
    assert "error" not in response, response
    return response["result"]


def _run_tts_turn(world):
    agent = world.agent
    final = f"Here is your audio, and the chart:\nMEDIA:{world.chart}"
    steps = iter([_model_step(agent, "Let me record that.", call=True), _model_step(agent, final)])
    agent.client.chat.completions.create.side_effect = lambda **kwargs: next(steps)(**kwargs)
    tts_result = json.dumps({
        "success": True, "file_path": str(world.clip), "media_tag": f"MEDIA:{world.clip}",
        "provider": "elevenlabs", "voice_compatible": False})
    with (
        patch("model_tools.handle_function_call", return_value=tts_result),
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        assert _rpc("prompt.submit", text="read it to me")["status"] == "streaming"
        world.session["_run_thread"].join()
    assert world.session["running"] is False
    return final


def _complete(world):
    (frame,) = [f for f in world.peer.events if f["type"] == "message.complete"]
    return frame["payload"]


def test_the_tts_file_and_the_reply_file_arrive_as_attachments(hermie):
    _run_tts_turn(hermie)
    payload = _complete(hermie)

    attachments = payload["attachments"]
    assert [(a["name"], a["kind"], a["mime"]) for a in attachments] == [
        ("chart.png", "image", "image/png"),
        ("tts_20261004_225730_989324.mp3", "audio", "audio/mpeg"),  # voice_compatible: false is still audio
    ]
    for attachment in attachments:
        assert set(attachment) == set(outbox.ATTACHMENT_KEYS)
        assert attachment["url"] == f"/api/files/outbox/{attachment['id']}/{attachment['name']}"
        shared = outbox.open_shared(hermie.home, attachment["id"], attachment["name"])
        assert shared is not None and shared.record["logins"] == ["oidc:user-a"]
        shared.close()
    assert (hermie.home / "outbox" / attachments[1]["id"] / "blob").read_bytes() == _MP3
    assert hermie.clip.read_bytes() == _MP3  # the agent's own file is untouched

    # No message frame of the turn shows a path: not the deltas, not the final text. (Tool activity frames
    # carry the tool's own result, as they do for every tool.)
    frames = json.dumps([f for f in hermie.peer.events if f["type"].startswith("message.")])
    assert "MEDIA:" not in frames and str(hermie.clip) not in frames and str(hermie.chart) not in frames
    assert payload["text"] == "Here is your audio, and the chart:"


def test_history_shows_the_attachments_and_the_model_keeps_its_text(hermie):
    final = _run_tts_turn(hermie)
    attachments = _complete(hermie)["attachments"]

    history = _rpc("session.history")["messages"]
    last = history[-1]
    assert last["role"] == "assistant" and last["attachments"] == attachments
    assert last["text"] == "Here is your audio, and the chart:"
    assert "MEDIA:" not in json.dumps(history) and str(hermie.home) not in json.dumps(history)
    assert "attachments" not in (last.get("display_metadata") or {})

    # The stored row keeps what the agent wrote (the model's next turn sees it unchanged).
    stored = hermie.db.get_messages_as_conversation(KEY, include_row_ids=True)
    assert stored[-1]["content"] == final
    assert stored[-1]["display_metadata"]["attachments"] == attachments

    # The dashboard's paged history shows the same.
    from hermes_cli.web_routers.sessions import _project_for_display
    rows = _project_for_display(hermie.db.get_messages(KEY))
    assert rows[-1]["attachments"] == attachments and rows[-1]["content"] == "Here is your audio, and the chart:"
    assert "MEDIA:" not in json.dumps([r.get("content") for r in rows if r["role"] == "assistant"])


def test_another_surface_is_left_exactly_as_it_was(desktop):
    final = _run_tts_turn(desktop)
    payload = _complete(desktop)
    assert "attachments" not in payload and payload["text"] == final
    assert not (desktop.home / "outbox").exists()
    assert "attachments" not in _rpc("session.history")["messages"][-1]


def test_without_a_persisted_receipt_the_row_still_records_its_attachments(hermie, monkeypatch):
    """Compaction or a redirect can leave the turn without a receipt: the reply's row is found by its content,
    so a reload shows the attachments and not the path."""
    monkeypatch.setattr(server, "_persisted_turn_receipt", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_final_assistant_row_id", lambda *_a, **_k: None)  # found by content alone
    final = _run_tts_turn(hermie)
    attachments = _complete(hermie)["attachments"]
    assert "row_id" not in _complete(hermie)
    stored = hermie.db.get_messages_as_conversation(KEY, include_row_ids=True)
    assert stored[-1]["content"] == final and stored[-1]["display_metadata"]["attachments"] == attachments
    # A fresh read (what a reload does) shows the attachments.
    hermie.session["history"] = []
    last = _rpc("session.history")["messages"][-1]
    assert last["attachments"] == attachments and "MEDIA:" not in last["text"]


def test_a_refused_file_shows_a_note_and_never_its_path(hermie):
    (hermie.home / "auth.json").write_text("{}")
    agent = hermie.agent
    final = f"Here are the credentials.\nMEDIA:{hermie.home}/auth.json"
    steps = iter([_model_step(agent, final)])
    agent.client.chat.completions.create.side_effect = lambda **kwargs: next(steps)(**kwargs)
    with (
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        _rpc("prompt.submit", text="send me the file")
        hermie.session["_run_thread"].join()
    payload = _complete(hermie)
    assert payload["attachments"] == []
    assert payload["text"] == "Here are the credentials.\n\n(1 file could not be shared.)"
    frames = json.dumps([f for f in hermie.peer.events if f["type"].startswith("message.")])
    assert "auth.json" not in frames and "MEDIA:" not in frames
    last = _rpc("session.history")["messages"][-1]
    assert last["text"] == payload["text"] and last["attachments"] == []
    assert not (hermie.home / "outbox").exists() or not [
        n for n in (hermie.home / "outbox").iterdir() if n.name != outbox.LOCK_NAME]
