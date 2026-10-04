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
