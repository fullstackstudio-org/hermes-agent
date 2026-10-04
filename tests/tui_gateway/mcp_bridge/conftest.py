"""A live chat of Robin's, served by the real gateway handlers, with a scripted agent behind it.

The chat is a real session record in ``server._sessions`` over a real ``SessionDB``; Robin's own app is
attached to it (a signed-in connection that keeps its frames and answers server requests). The agent's
connection is a real :class:`~tui_gateway.mcp_bridge.transport.AgentTransport` and everything it does goes
through ``server.dispatch``. Turn threads are real threads, so a turn can block on a clarify or an approval
while the test answers it. The scripted agent picks its behaviour from the prompt; every payload is a
harmless marker.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from hermes_state import SessionDB
from tui_gateway.mcp_bridge.transport import AgentTransport
import tui_gateway.server as server

SID = "sid-room"
KEY = "room"
ROBIN = ("oidc:user-a", "Robin")
SAM = ("oidc:user-b", "Sam")
CLIENT = "Claude Code"


def identity(user=ROBIN, *, grant="grant-g1", client=CLIENT) -> dict:
    provider, user_id = user[0].split(":", 1)
    return {"provider": provider, "user_id": user_id, "user_name": user[1],
            "agent": {"kind": "mcp", "client": client, "grant": grant}}


class AppPeer:
    """A person's own signed-in app connection: keeps every frame."""

    def __init__(self, user=ROBIN):
        provider, user_id = user[0].split(":", 1)
        self.auth_identity = {"provider": provider, "user_id": user_id, "user_name": user[1]}
        self.frames: list[dict] = []
        self._lock = threading.Lock()

    def write(self, obj):
        with self._lock:
            self.frames.append(obj)
        return True

    def close(self):
        return None

    def call(self, method, params, rid=None, timeout=10.0):
        """Dispatch as this connection and return the response (a pooled handler answers through write)."""
        rid = rid or f"app-{time.monotonic_ns()}"
        response = server.dispatch({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, self)
        deadline = time.monotonic() + timeout
        while response is None and time.monotonic() < deadline:
            with self._lock:
                response = next((f for f in self.frames if f.get("id") == rid and "method" not in f), None)
            if response is None:
                time.sleep(0.01)
        assert response is not None, f"no answer to {method}"
        return response

    def requests(self, method):
        with self._lock:
            return [f for f in self.frames if f.get("method") == method and isinstance(f.get("id"), str)]


class ScriptedAgent:
    """Stands in for ``AIAgent``: the prompt names what the turn does."""

    def __init__(self, sid):
        self.sid = sid
        self.session_id = KEY
        self._session_messages = []
        self._last_flushed_db_idx = 0
        self._pending_steer = None
        self._pending_steer_lock = threading.Lock()
        self._interrupt_requested = False
        self._current_streamed_assistant_text = ""
        self.session = None
        self.clarify_answers: list[str] = []
        self.approval_results: list = []
        self.gate = threading.Event()
        self.texts: list[str] = []

    def _strip_think_blocks(self, text):
        return text

    def clear_interrupt(self, *_a, **_k):
        self._interrupt_requested = False
        return True

    def interrupt(self, *_a, **_k):
        self._interrupt_requested = True
        return True

    def run_conversation(self, message, conversation_history=None, stream_callback=None, **_kw):
        from tui_gateway import server_requests
        self.texts.append(message)
        if stream_callback is not None:
            stream_callback("marker partial ")
        if "marker clarify" in message:
            self.clarify_answers.append(server._clarify_block(self.sid, "Which marker?", ["one", "two"]))
            return {"final_response": "marker clarified"}
        if "marker approval" in message:
            self.approval_results.append(server_requests.send(
                "approval", self.sid, {"request_id": "ap-1", "command": "echo marker",
                                       "description": "marker approval", "choices": ["once", "deny"]},
                timeout=30))
            if "then gated" in message:
                self.gate.wait(30)
            return {"final_response": "marker approved"}
        if "marker person" in message:
            return {"final_response": "marker person reply"}
        if "marker gated" in message:
            for _ in range(3):
                stream_callback("tick ")
                time.sleep(0.05)
            self.gate.wait(30)
            return {"final_response": "marker gated done"}
        return {"final_response": "marker reply done"}


@pytest.fixture()
def gateway(tmp_path, monkeypatch):
    from tui_gateway import event_replay, server_requests
    from tui_gateway.mcp_bridge import turns

    event_replay.reset_replay_state()
    server_requests.reset_for_tests()
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session(KEY, source="desktop")
    app = AppPeer()
    agent = ScriptedAgent(SID)
    session = {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path),
        "history": [], "history_lock": threading.Lock(), "history_version": 0,
        "inflight_turn": None, "running": False, "session_key": KEY,
        "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": app,
        "auth_user_id": ROBIN[0], "auth_user_name": ROBIN[1],
    }
    agent.session = session
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {SID: session}, raising=False)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    # ``dashboard.mcp.answer_clarify`` at its default (on).
    monkeypatch.setattr(server_requests, "_agent_clarify_allowed", lambda: True)
    server_requests.advertise(app, True)
    transports: list[AgentTransport] = []

    def connect(user=ROBIN, **kw) -> AgentTransport:
        transport = AgentTransport(identity(user, **kw), peer="203.0.113.7")
        transports.append(transport)
        return transport

    yield SimpleNamespace(db=db, app=app, agent=agent, session=session, connect=connect)
    agent.gate.set()
    deadline = time.monotonic() + 5
    while session.get("running") and time.monotonic() < deadline:
        time.sleep(0.01)
    turns.reset_for_tests()
    for transport in transports:
        transport.close()
    server_requests.reset_for_tests()
    event_replay.reset_replay_state()
    db.close()


class BuiltAgent(ScriptedAgent):
    """A :class:`ScriptedAgent` the gateway builds for a session it creates or resumes; a stop releases a
    gated turn, which then reports itself interrupted (as ``AIAgent`` does)."""

    def __init__(self, sid, key):
        super().__init__(sid)
        self.session_id = key
        self.model = "test/model"

    def interrupt(self, *_a, **_k):
        self._interrupt_requested = True
        self.gate.set()
        return True

    def run_conversation(self, message, conversation_history=None, stream_callback=None, **kw):
        result = super().run_conversation(message, conversation_history, stream_callback, **kw)
        if self._interrupt_requested:
            return {"final_response": "", "interrupted": True}
        return result


@pytest.fixture()
def live_gateway(monkeypatch):
    """The real session handlers over a state.db in the test's HERMES_HOME: ``session.create`` and
    ``session.resume`` build a :class:`BuiltAgent` (``agents[stored id]``)."""
    from hermes_constants import get_hermes_home
    from tui_gateway import event_replay, server_requests
    from tui_gateway.mcp_bridge import turns

    event_replay.reset_replay_state()
    server_requests.reset_for_tests()
    db = SessionDB(db_path=get_hermes_home() / "state.db")
    sessions: dict = {}
    agents: dict = {}

    def make_agent(sid, key, session_id=None, session_db=None, **_kw):
        agent = agents[session_id or key] = BuiltAgent(sid, session_id or key)
        agent.session = sessions.get(sid)
        return agent

    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", sessions, raising=False)
    monkeypatch.setattr(server, "_make_agent", make_agent)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(server_requests, "_agent_clarify_allowed", lambda: True)

    def session_of(key):
        return next(((sid, s) for sid, s in sessions.items() if s.get("session_key") == key), (None, None))

    def agent_of(key, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sid, session = session_of(key)
            agent = session.get("agent") if session else None
            if isinstance(agent, BuiltAgent):
                agent.session = session
                return agent
            time.sleep(0.01)
        raise AssertionError(f"no agent was built for {key}")

    yield SimpleNamespace(db=db, sessions=sessions, agents=agents, session_of=session_of, agent_of=agent_of)
    for agent in list(agents.values()):
        agent.gate.set()
    deadline = time.monotonic() + 5
    while any(s.get("running") for s in sessions.values()) and time.monotonic() < deadline:
        time.sleep(0.01)
    turns.reset_for_tests()
    server_requests.reset_for_tests()
    event_replay.reset_replay_state()
    db.close()
