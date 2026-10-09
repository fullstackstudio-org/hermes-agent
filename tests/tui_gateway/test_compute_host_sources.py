"""Sources and the guide on an isolated turn (plan rich-answers T2, T3): the compute-host child runs the turn.

The child (``ComputeHost`` driven in-process over a string pipe, the harness of
``test_compute_host_turn_protocol``) receives the names the gateway resolved in its ``turn.start`` frame and stages
their guide; its agent's web tools report through the child's own ``_on_tool_complete``; the child builds
``message.complete`` with ``sources`` and writes them on the reply's row in the session store it shares with the
gateway; the parent hands the frame to its clients unchanged (``_relay_compute_host_rpc``). The real subprocess
and pipe are not started here: what crosses them is the JSON frame this test reads. Every payload is a marker.
"""

from __future__ import annotations

import io
import json
import threading
import time
import types

import pytest

from agent.prompt_additions import turn_system_addition
from hermes_state import SessionDB
from tui_gateway import hermie_markup, server
from tui_gateway.compute_host import ComputeHost
from tests.tui_gateway.test_compute_host_turn_protocol import turn_env  # noqa: F401 - fixture used by name

SEARCH = {"success": True, "data": {"web": [{"title": "Marker one", "url": "https://One.example/",
                                             "description": "never sent", "position": 1}]}}
EXTRACT = {"results": [{"url": "https://two.example/a", "title": "Marker two", "content": "never sent",
                        "error": None}]}
SOURCES = [{"url": "https://two.example/a", "title": "Marker two", "via": "read"},
           {"url": "https://one.example/", "title": "Marker one", "via": "found"}]


def _frames(out: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def _wait_end(out: io.StringIO, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(f["type"] == "turn.end" for f in _frames(out)):
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out; saw={_frames(out)}")


@pytest.fixture()
def child(turn_env, tmp_path):  # noqa: F811 - the imported fixture
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session(session_id="s1-key", source="hermie", model="test/model")
    seen: dict = {}

    def run_conversation(prompt, *, conversation_history=None, stream_callback=None, **_kw):
        seen["guide"] = turn_system_addition(agent)
        # What the child's tool executor reports for this turn's web tools.
        server._on_tool_complete("s1", "call_search", "web_search", {"query": "marker"}, json.dumps(SEARCH))
        server._on_tool_complete("s1", "call_extract", "web_extract", {"urls": ["x"]}, json.dumps(EXTRACT))
        final = "Marker answer."
        db.append_message("s1-key", "user", prompt)
        db.append_message("s1-key", "assistant", final)
        return {"final_response": final, "messages": [
            *(conversation_history or []), {"role": "user", "content": prompt},
            {"role": "assistant", "content": final}]}

    agent = types.SimpleNamespace(session_id="s1-key", run_conversation=run_conversation,
                                  clear_interrupt=lambda: None, hard_interrupt=lambda *a, **k: None,
                                  _session_db=db)
    session = {
        "agent": agent, "session_key": "s1-key", "history": [], "history_lock": threading.Lock(),
        "history_version": 0, "running": False, "attached_images": [], "image_counter": 0, "cols": 80,
        "slash_worker": None, "show_reasoning": False, "tool_progress_mode": "all", "inflight_turn": None,
        "active_session_lease": object(), "source": "hermie",
    }
    server._sessions["s1"] = session
    out = io.StringIO()
    host = ComputeHost(stdout=out, heartbeat_secs=0)
    try:
        yield types.SimpleNamespace(host=host, out=out, db=db, seen=seen, session=session)
    finally:
        server._sessions.pop("s1", None)
        host.close()
        db.close()


def _complete(out: io.StringIO) -> dict:
    [frame] = [f for f in _frames(out) if f["type"] == "rpc" and f["message"].get("method") == "event"
               and f["message"]["params"]["type"] == "message.complete"]
    return frame


def test_the_child_collects_sends_and_stores_the_sources(child, monkeypatch):
    child.host.handle_frame({"type": "turn.start", "sid": "s1", "request_id": "turn", "prompt": "marker",
                             "turn_auth_user_id": "", "turn_markup": ["cards"]})
    _wait_end(child.out)
    frame = _complete(child.out)
    assert frame["message"]["params"]["payload"]["sources"] == SOURCES
    assert "never sent" not in json.dumps(frame)
    # The child staged the guide the frame named, and only for the turn.
    assert child.seen["guide"] == hermie_markup.guide_for(["cards"])
    assert turn_system_addition(child.session["agent"]) == ""
    # The reply's row in the shared store carries them (the child wrote it).
    [row] = [m for m in child.db.get_messages("s1-key") if m["role"] == "assistant"]
    assert (row.get("display_metadata") or {}).get("sources") == SOURCES
    # The parent forwards the frame to its clients unchanged.
    written = []
    monkeypatch.setattr(server, "write_json", lambda message: written.append(message) or True)
    server._relay_compute_host_rpc(frame["message"])
    assert written == [frame["message"]]
    assert written[0]["params"]["payload"]["sources"] == SOURCES


def test_a_frame_without_names_stages_nothing(child):
    child.host.handle_frame({"type": "turn.start", "sid": "s1", "request_id": "turn", "prompt": "marker"})
    _wait_end(child.out)
    assert child.seen["guide"] == ""
    assert _complete(child.out)["message"]["params"]["payload"]["sources"] == SOURCES
