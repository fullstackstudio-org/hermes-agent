"""End to end (plan rich-answers T2, T3): one real turn through ``prompt.submit`` into a real ``AIAgent`` over a real
``SessionDB`` with a mocked model.

* The guide: a turn submitted by a connection that advertised ``markup`` sends the guide for exactly those
  blocks on the system message of its requests, and nowhere else: not in the cached system prompt, not in the
  stored session, not in a turn the next (older) client submits in the same chat, not in a session of another
  surface.
* The sources: the model calls ``web_search`` and ``web_extract``; ``message.complete.sources``, the live
  history, ``session.history`` and the stored row carry the same list. A turn without web tools carries none.

Every payload is a harmless marker; no request leaves the test.
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
from tui_gateway import client_markup, event_replay, hermie_markup
from tui_gateway.transport import bind_transport, reset_transport

SID = "sid"
KEY = "room"
SEARCH = {"success": True, "data": {"web": [
    {"title": "Marker result one", "url": "https://one.example/", "description": "never sent", "position": 1},
    {"title": "Marker result two", "url": "https://two.example/a", "description": "never sent", "position": 2},
]}}
EXTRACT = {"results": [
    {"url": "https://two.example/a", "title": "Marker two, as read", "content": "never sent", "error": None},
    {"url": "https://three.example/", "title": "", "content": "", "error": "403 Forbidden"},
]}
SOURCES = [
    {"url": "https://two.example/a", "title": "Marker two, as read", "via": "read"},
    {"url": "https://one.example/", "title": "Marker result one", "via": "found"},
]


class _Peer:
    def __init__(self, user_id="user-a"):
        self.auth_identity = {"provider": "oidc", "user_id": user_id, "user_name": "Robin"}
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
    params = {"type": "object", "properties": {}}
    return [{"type": "function", "function": {"name": name, "description": name, "parameters": params}}
            for name in ("web_search", "web_extract")]


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


def _step(agent, text, calls=()):
    tool_calls = [SimpleNamespace(id=f"call_{name}", type="function", function=SimpleNamespace(
        name=name, arguments=json.dumps({"marker": True}))) for name in calls] or None
    message = SimpleNamespace(content=text, tool_calls=tool_calls)
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls" if calls else "stop")],
        model="test/model", usage=None)

    def answer(**_kwargs):
        agent._fire_stream_delta(text)
        return response
    return answer


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("agent.title_generator.maybe_auto_title", lambda *args, **kwargs: None)
    monkeypatch.setattr("agent.tool_executor.maybe_persist_tool_result", lambda **kwargs: kwargs["content"])
    with client_markup._lock:
        client_markup._accepted.clear()
    yield
    with client_markup._lock:
        client_markup._accepted.clear()


def _world(tmp_path, monkeypatch, source):
    event_replay.reset_replay_state()
    home = Path(tempfile.mkdtemp(prefix="hermes-rich-home-", dir=tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(home))
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session(session_id=KEY, source=source, model="test/model", system_prompt="You are helpful.")
    phone, laptop = _Peer(), _Peer()
    client_markup.advertise(phone, ["cards", "chart"])  # a new build; the laptop runs an older one
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
        "tool_progress_mode": "all", "transport": phone,
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
    world = SimpleNamespace(agent=agent, db=db, phone=phone, laptop=laptop, session=session, systems=[])
    yield world
    event_replay.reset_replay_state()
    db.close()


@pytest.fixture()
def hermie(tmp_path, monkeypatch):
    yield from _world(tmp_path, monkeypatch, "hermie")


@pytest.fixture()
def desktop(tmp_path, monkeypatch):
    yield from _world(tmp_path, monkeypatch, "desktop")


def _turn(world, peer, text, *, web=True, final="Marker answer."):
    agent = world.agent
    steps = [_step(agent, "Searching.", ("web_search",)), _step(agent, "Reading.", ("web_extract",))] if web else []
    steps = iter([*steps, _step(agent, final)])

    def create(**kwargs):
        world.systems.append(next(m["content"] for m in kwargs["messages"] if m["role"] == "system"))
        return next(steps)(**kwargs)

    def tool(name, *_a, **_k):
        return json.dumps(SEARCH if name == "web_search" else EXTRACT)

    agent.client.chat.completions.create.side_effect = create
    token = bind_transport(peer)
    try:
        with (
            patch("model_tools.handle_function_call", side_effect=tool),
            patch.object(agent, "_save_trajectory"),
            patch.object(agent, "_cleanup_task_resources"),
        ):
            response = server._methods["prompt.submit"]("rid", {"session_id": SID, "text": text})
            assert "error" not in response, response
            world.session["_run_thread"].join()
    finally:
        reset_transport(token)
    assert world.session["running"] is False
    return final


def _completes(peer):
    return [f["payload"] for f in peer.events if f["type"] == "message.complete"]


# ── the guide ──────────────────────────────────────────────────────────────────────────────────


def test_the_capable_submitter_gets_exactly_its_blocks_on_every_request_of_its_turn(hermie):
    _turn(hermie, hermie.phone, "marker question")
    assert len(hermie.systems) == 3
    for system in hermie.systems:
        assert system.startswith("You are helpful.")
        assert hermie_markup.INTRO in system
        assert hermie_markup.GUIDE["cards"] in system and hermie_markup.GUIDE["chart"] in system
        assert hermie_markup.GUIDE["alerts"] not in system


def test_the_guide_is_never_cached_stored_or_left_staged(hermie):
    _turn(hermie, hermie.phone, "marker question")
    assert hermie_markup.INTRO not in (hermie.agent._cached_system_prompt or "")
    stored = hermie.db.get_session(KEY)
    assert hermie_markup.INTRO not in json.dumps(stored)
    assert hermie_markup.INTRO not in json.dumps(hermie.db.get_messages(KEY))
    assert getattr(hermie.agent, "_turn_system_addition", "") == ""
    assert client_markup.TURN_MARKUP.get() == frozenset()


def test_a_shared_chat_gives_the_guide_only_to_the_capable_submitters_turns(hermie):
    _turn(hermie, hermie.phone, "marker from phone", web=False)
    phone_systems, hermie.systems[:] = list(hermie.systems), []
    _turn(hermie, hermie.laptop, "marker from laptop", web=False)
    assert all(hermie_markup.INTRO in s for s in phone_systems)
    assert hermie.systems and all(hermie_markup.INTRO not in s for s in hermie.systems)
    assert hermie.systems[0].startswith("You are helpful.")
    hermie.systems[:] = []
    _turn(hermie, hermie.phone, "marker from phone again", web=False)
    assert all(hermie_markup.INTRO in s for s in hermie.systems)


def test_a_session_of_another_surface_never_hears_of_it(desktop):
    _turn(desktop, desktop.phone, "marker question", web=False)
    assert desktop.systems and all(hermie_markup.INTRO not in s for s in desktop.systems)
    assert desktop.systems[0] == "You are helpful."


# ── the sources ────────────────────────────────────────────────────────────────────────────────


def test_message_complete_carries_the_pages_read_and_found(hermie):
    _turn(hermie, hermie.phone, "marker question")
    [payload] = _completes(hermie.phone)
    assert payload["sources"] == SOURCES
    assert "never sent" not in json.dumps(payload)
    from tui_gateway.contracts.events import MessageCompletePayload
    MessageCompletePayload.model_validate(payload)


def test_the_history_and_the_stored_row_carry_the_same_list(hermie):
    final = _turn(hermie, hermie.phone, "marker question")
    [payload] = _completes(hermie.phone)
    stored = hermie.db.get_messages_as_conversation(KEY, include_row_ids=True)
    assert stored[-1]["content"] == final and stored[-1]["display_metadata"]["sources"] == SOURCES
    token = bind_transport(hermie.phone)
    try:
        live = server._methods["session.history"]("rid", {"session_id": SID})["result"]["messages"][-1]
        hermie.session["history"] = []  # what a reload reads: the store
        reloaded = server._methods["session.history"]("rid", {"session_id": SID})["result"]["messages"][-1]
    finally:
        reset_transport(token)
    for row in (live, reloaded):
        assert row["role"] == "assistant" and row["display_metadata"]["sources"] == SOURCES
        assert row.get("row_id") == payload.get("row_id")
    from hermes_cli.web_routers.sessions import _project_for_display
    rows = _project_for_display(hermie.db.get_messages(KEY))
    assert rows[-1]["display_metadata"]["sources"] == SOURCES


def test_a_turn_without_web_tools_has_no_key(hermie):
    _turn(hermie, hermie.phone, "marker plain", web=False)
    [payload] = _completes(hermie.phone)
    assert "sources" not in payload
    stored = hermie.db.get_messages_as_conversation(KEY, include_row_ids=True)
    assert "sources" not in (stored[-1].get("display_metadata") or {})


def test_a_later_turn_does_not_inherit_the_earlier_ones_sources(hermie):
    _turn(hermie, hermie.phone, "marker one")
    _turn(hermie, hermie.phone, "marker two", web=False, final="Marker second answer.")
    first, second = _completes(hermie.phone)
    assert first["sources"] == SOURCES and "sources" not in second
    assert "_turn_sources" not in hermie.session
