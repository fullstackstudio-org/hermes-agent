"""The agent marker rides with the person through every carrier of a turn (plan D5, D12).

A connection whose ``auth_identity`` carries ``agent`` is an agent acting for its signed-in person through
MCP. The turn stays the person's -- scope, memory, limits, ``_acting_auth_user`` -- and the marker is carried
beside them wherever they are carried, so that

* the user row's ``author`` gains ``via: {kind: "mcp", client}`` (never the grant id),
* the stored gateway note names the agent,
* ``HERMES_SESSION_AGENT`` is ``mcp:<client>`` for the turn's tools,

on the inline path, through the busy queue (and its restart journal), in the isolated child's frame, for a
steer or redirect, a leftover steer, a ``/goal`` continuation and ``/retry``. A person's own turn in the same
chat carries none of it, and a junk marker is no marker. Every payload is a harmless marker.
"""

from __future__ import annotations

import threading

import pytest

from agent.agent_runtime_helpers import apply_pending_steer_to_tool_results
from agent.conversation_loop import _apply_active_turn_redirect
from agent.interrupt_control import InterruptControlMixin
from agent.turn_finalizer import hand_back_leftover_steer
from agent.turn_iteration_prep import apply_pending_redirect
from gateway.session_context import get_session_env
from hermes_state import SessionDB
from tui_gateway.transport import bind_transport, reset_transport
import tui_gateway.server as server

ROBIN = ("oidc:user-a", "Robin")
SAM = ("oidc:user-b", "Sam")
AUTHOR_ROBIN = {"id": "oidc:user-a", "name": "Robin"}
AUTHOR_SAM = {"id": "oidc:user-b", "name": "Sam"}
VIA = {"kind": "mcp", "client": "Claude Code"}
AUTHOR_ROBIN_VIA = {**AUTHOR_ROBIN, "via": VIA}
AGENT_IDENTITY = {"kind": "mcp", "client": "Claude Code", "grant": "grant-g1"}
AGENT_SENTENCE = ("This message was sent by an agent, «Claude Code», through MCP on «Robin»'s behalf; "
                  "the gateway verified «Robin»'s sign-in and the agent's token.")


class _Peer:
    def __init__(self, user, agent=None):
        self.auth_identity = (
            {"provider": "oidc", "user_id": user[0].split(":", 1)[1], "user_name": user[1]} if user else None)
        if user and agent is not None:
            self.auth_identity["agent"] = agent

    def write(self, obj):
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


class _Agent(InterruptControlMixin):
    """The real steer / redirect slots with a scripted turn; each turn records what it was told."""

    def __init__(self, session_key):
        self.session_id = session_key
        self._session_messages = []
        self._last_flushed_db_idx = 0
        self._db_flush_scan_prefix = []
        self._pending_steer = None
        self._pending_steer_lock = threading.Lock()
        self._pending_redirect = None
        self._pending_redirect_lock = threading.Lock()
        self._interrupt_requested = False
        self._interrupt_message = None
        self._tool_interrupt_reason = None
        self._execution_thread_id = None
        self._model_request_active = threading.Event()
        self._supports_active_turn_redirect = False
        self._current_streamed_assistant_text = ""
        self.turns = []
        self.rows = []
        self.script = []
        self.session = None

    def _strip_think_blocks(self, text):
        return text

    def clear_interrupt(self, *_a, **_k):
        self._interrupt_requested = False
        return True

    def interrupt(self, *_a, **_k):
        self._interrupt_requested = True
        return True

    def run_conversation(self, message, conversation_history=None, stream_callback=None,
                         persist_user_display_metadata=None, **_kw):
        self.turns.append({
            "text": message,
            "author": (persist_user_display_metadata or {}).get("author"),
            "replayed_by": (persist_user_display_metadata or {}).get("replayed_by"),
            "scope": server._acting_auth_user(self.session),
            "agent": server._acting_agent(self.session),
            "note": getattr(self, "_turn_sender_note", ""),
            "env": get_session_env("HERMES_SESSION_AGENT"),
        })
        if self.script:
            self.script.pop(0)()
        result = {"final_response": "done"}
        hand_back_leftover_steer(self, result)
        return result

    def deliver_mid_turn(self):
        messages = [{"role": "assistant", "content": "", "tool_calls": []},
                    {"role": "tool", "tool_call_id": "t1", "content": "ok"}]
        apply_pending_steer_to_tool_results(self, messages, 1)
        apply_pending_redirect(self, messages, _apply_active_turn_redirect)
        self.rows += [m for m in messages[2:] if m.get("role") == "user"]


@pytest.fixture()
def room(tmp_path, monkeypatch):
    """Robin's chat with Robin's own app, Robin's agent (through MCP) and Sam attached."""
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("room", source="desktop")
    peers = {"robin": _Peer(ROBIN), "agent": _Peer(ROBIN, AGENT_IDENTITY), "sam": _Peer(SAM)}
    agent = _Agent("room")
    session = {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path),
        "history": [], "history_lock": threading.Lock(), "history_version": 0,
        "inflight_turn": None, "running": False, "session_key": "room",
        "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": peers["robin"],
        "auth_user_id": ROBIN[0], "auth_user_name": ROBIN[1],
    }
    agent.session = session
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_emit", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    server._attach_session_transport(session, peers["agent"])
    server._attach_session_transport(session, peers["sam"])

    def call(who, method, **params):
        token = bind_transport(peers[who])
        try:
            return server._methods[method]("rid", {"session_id": "sid", **params})
        finally:
            reset_transport(token)

    agent.db = db
    yield agent, call, peers
    db.close()


def _turn(agent, text):
    [turn] = [t for t in agent.turns if t["text"] == text]
    return turn


def _stored_author(agent, text):
    [row] = [r for r in agent.db.get_messages("room", include_inactive=True)
             if r["role"] == "user" and r["content"] == text]
    return (row.get("display_metadata") or {}).get("author")


# ── the identity helpers ────────────────────────────────────────────────────────────────────


def test_the_person_half_is_unchanged_and_the_marker_sits_beside_it():
    agent_peer = _Peer(ROBIN, AGENT_IDENTITY)
    assert server._transport_auth_user(agent_peer) == ROBIN
    assert server._transport_auth_user(_Peer(ROBIN)) == ROBIN
    assert server._transport_agent(agent_peer) == VIA  # no grant id
    assert server._transport_agent(_Peer(ROBIN)) is None
    token = bind_transport(agent_peer)
    try:
        assert server._acting_auth_user({}) == ROBIN
        assert server._acting_agent({}) == VIA
    finally:
        reset_transport(token)


@pytest.mark.parametrize("entry", [{"kind": "other", "client": "x"}, {"kind": "mcp", "client": "​‮"},
                                   "mcp", {"kind": "mcp"}])
def test_a_transport_with_a_malformed_agent_entry_is_still_marked(entry):
    """Failing to "no marker" would show the agent's words as the person's own."""
    assert server._transport_agent(_Peer(ROBIN, entry)) == {"kind": "mcp", "client": "MCP client"}


# ── the inline turn ─────────────────────────────────────────────────────────────────────────


def test_an_agents_turn_is_the_persons_with_the_marker_on_row_note_and_tools(room):
    agent, call, _peers = room
    assert call("agent", "prompt.submit", text="marker one")["result"]["status"] == "streaming"

    turn = _turn(agent, "marker one")
    assert turn["scope"] == ROBIN
    assert turn["author"] == AUTHOR_ROBIN_VIA
    assert _stored_author(agent, "marker one") == AUTHOR_ROBIN_VIA
    assert turn["agent"] == VIA
    assert AGENT_SENTENCE in turn["note"]
    assert "cannot approve commands, confirm with a passkey or provide secrets" in turn["note"]
    assert turn["env"] == "mcp:Claude Code"
    assert "grant-g1" not in str(turn)
    # Bound for the turn only.
    assert server._turn_agent.get() is None


def test_the_persons_own_turn_in_the_same_chat_carries_nothing(room):
    agent, call, _peers = room
    call("agent", "prompt.submit", text="marker one")
    call("robin", "prompt.submit", text="marker two")
    call("sam", "prompt.submit", text="marker three")

    for text, author in (("marker two", AUTHOR_ROBIN), ("marker three", AUTHOR_SAM)):
        turn = _turn(agent, text)
        assert turn["author"] == author and turn["agent"] is None and turn["env"] == ""
        assert "agent" not in turn["note"]


@pytest.mark.parametrize("junk", [{"kind": "other", "client": "x"}, {"kind": "mcp", "client": ""}, "mcp:x",
                                  object()])
def test_a_junk_marker_reaching_the_turn_writes_and_says_nothing(room, junk):
    agent, _call, _peers = room
    server._run_prompt_submit("rid", "sid", agent.session, "marker junk", turn_auth_user=ROBIN,
                              row_auth_user=ROBIN, turn_agent=junk, row_agent=junk)
    turn = _turn(agent, "marker junk")
    assert turn["author"] == AUTHOR_ROBIN and turn["agent"] is None and turn["env"] == ""


def test_a_marker_without_a_person_is_nothing(room):
    agent, _call, _peers = room
    server._run_prompt_submit("rid", "sid", agent.session, "marker nobody", turn_agent=VIA, row_agent=VIA)
    turn = _turn(agent, "marker nobody")
    assert turn["author"] is None and turn["agent"] is None and turn["env"] == ""


# ── the busy queue and its restart journal ──────────────────────────────────────────────────


def test_an_agents_queued_message_keeps_the_marker_and_never_merges_with_the_persons(room, monkeypatch):
    monkeypatch.setattr(server, "_load_busy_input_mode", lambda: "queue")
    agent, call, _peers = room

    def both_queue():
        assert call("agent", "prompt.submit", text="marker from agent")["result"]["status"] == "queued"
        assert call("robin", "prompt.submit", text="marker from robin")["result"]["status"] == "queued"

    agent.script = [both_queue]
    call("robin", "prompt.submit", text="marker first")

    queued = _turn(agent, "marker from agent")
    assert (queued["author"], queued["agent"], queued["env"]) == (AUTHOR_ROBIN_VIA, VIA, "mcp:Claude Code")
    assert AGENT_SENTENCE in queued["note"]
    own = _turn(agent, "marker from robin")
    assert (own["author"], own["agent"]) == (AUTHOR_ROBIN, None)


def test_the_restart_journal_keeps_the_marker_with_its_person():
    from tui_gateway.shutdown_drain import _journal_queue_envelope, _restore_journaled_queue
    entry = _journal_queue_envelope({"text": "marker", "transport": object(), "turn_auth_user": ROBIN,
                                     "turn_agent": VIA})
    assert entry == {"text": "marker", "turn_auth_user": list(ROBIN), "turn_agent": VIA}
    [restored], _dropped = _restore_journaled_queue([entry])
    assert restored["turn_agent"] == VIA and restored["turn_auth_user"] == ROBIN


def test_a_journaled_agent_prompt_drains_as_the_agents(room):
    agent, _call, _peers = room
    agent.session["queued_prompt"] = {"text": "marker journaled", "transport": None,
                                      "turn_auth_user": ROBIN, "turn_agent": VIA}
    assert server._drain_queued_prompt("rid", "sid", agent.session) is True
    turn = _turn(agent, "marker journaled")
    assert (turn["author"], turn["agent"]) == (AUTHOR_ROBIN_VIA, VIA)


# ── the isolated child ──────────────────────────────────────────────────────────────────────


def test_the_compute_host_frame_carries_the_marker_beside_the_submitter(room):
    from tui_gateway.compute_host import _frame_turn_agent
    agent, _call, _peers = room
    frame = server._compute_host_turn_frame("rid", "sid", agent.session, "marker", turn_auth_user=ROBIN,
                                            turn_agent=VIA)
    assert frame["turn_agent"] == VIA and frame["turn_auth_user_id"] == ROBIN[0]
    assert _frame_turn_agent(frame) == VIA
    plain = server._compute_host_turn_frame("rid", "sid", agent.session, "marker", turn_auth_user=ROBIN)
    assert "turn_agent" not in plain and _frame_turn_agent(plain) is None
    nobody = server._compute_host_turn_frame("rid", "sid", agent.session, "marker", turn_agent=VIA)
    assert "turn_agent" not in nobody
    assert _frame_turn_agent({"turn_auth_user_id": ROBIN[0], "turn_agent": {"kind": "x"}}) is None
    assert _frame_turn_agent({"turn_agent": VIA}) is None  # a parent that names nobody


def test_an_isolated_agent_submit_sends_the_marker_and_a_stamped_row(room, monkeypatch):
    agent, call, _peers = room
    sent = []
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda *_a, **_k: True)
    monkeypatch.setattr(server, "_submit_prompt_to_compute_host",
                        lambda _rid, _sid, _session, text, **kw: sent.append((text, kw)) or {"result": {}})
    call("agent", "prompt.submit", text="marker isolated")
    [(text, kw)] = sent
    assert kw["turn_agent"] == VIA and kw["turn_auth_user"] == ROBIN
    assert kw["display_metadata"]["author"] == AUTHOR_ROBIN_VIA


def test_the_child_binds_what_the_frame_says(room):
    """What ``compute_host`` hands ``_run_prompt_submit`` from a frame: the same note and row as inline."""
    from tui_gateway.compute_host import _frame_turn_agent, _frame_turn_auth_user
    agent, _call, _peers = room
    frame = server._compute_host_turn_frame("rid", "sid", agent.session, "marker child", turn_auth_user=ROBIN,
                                            turn_agent=VIA, display_metadata={"author": AUTHOR_ROBIN_VIA})
    server._run_prompt_submit("rid", "sid", agent.session, "marker child",
                              display_metadata=frame["display_metadata"],
                              turn_auth_user=_frame_turn_auth_user(frame), turn_agent=_frame_turn_agent(frame))
    turn = _turn(agent, "marker child")
    assert (turn["author"], turn["agent"], turn["env"]) == (AUTHOR_ROBIN_VIA, VIA, "mcp:Claude Code")
    assert AGENT_SENTENCE in turn["note"]


# ── steer, redirect, leftover steer, continuation ───────────────────────────────────────────


def test_an_agents_mid_turn_steer_row_and_clause_say_it_was_the_agent(room):
    """The carrier itself, in-process: ``session.steer`` refuses an agent's connection (4033), but a steer handed
    in with the marker still lands as the agent's row and clause."""
    from tui_gateway.row_author import deliver_correction
    agent, call, _peers = room

    def steer():
        assert call("agent", "session.steer", text="marker steer")["error"]["code"] == 4033
        assert deliver_correction(agent, "steer", "marker steer", ROBIN, VIA)
        agent.deliver_mid_turn()

    agent.script = [steer]
    call("robin", "prompt.submit", text="marker first")

    [row] = agent.rows
    assert row["display_metadata"]["author"] == AUTHOR_ROBIN_VIA
    assert row["content"].endswith("marker steer\n[/OUT-OF-BAND USER MESSAGE]")  # what was typed
    assert "Sent by an agent, «Claude Code», through MCP on «Robin»'s behalf" in row["api_content"]


def test_an_agents_redirect_row_carries_the_marker(room):
    """The carrier itself, in-process: an agent's connection can no longer redirect (its text is queued), but a
    redirect handed in with the marker still lands as the agent's row."""
    from tui_gateway.row_author import deliver_correction
    agent, _call, _peers = room
    agent._supports_active_turn_redirect = True
    agent._model_request_active.set()

    def redirect():
        assert deliver_correction(agent, "redirect", "marker redirect", ROBIN, VIA)
        agent.deliver_mid_turn()

    agent.script = [redirect]
    _call("robin", "prompt.submit", text="marker first")
    [row] = agent.rows
    assert row["display_metadata"]["author"] == AUTHOR_ROBIN_VIA


def test_an_agents_submit_mid_turn_is_queued_never_a_redirect(room, monkeypatch):
    """Plan "Agent prompts": whatever the busy mode, an agent's text waits for a turn of its own."""
    monkeypatch.setattr(server, "_load_busy_input_mode", lambda: "interrupt")
    agent, call, _peers = room
    agent._supports_active_turn_redirect = True
    agent._model_request_active.set()
    answers = []
    agent.script = [lambda: answers.append(call("agent", "prompt.submit", text="marker redirect"))]
    call("robin", "prompt.submit", text="marker first")
    assert answers[0]["result"]["status"] == "queued", answers
    assert agent.rows == [] and agent._interrupt_requested is False
    turn = _turn(agent, "marker redirect")
    assert (turn["author"], turn["agent"]) == (AUTHOR_ROBIN_VIA, VIA)


def test_the_person_steering_an_agents_turn_is_named_as_in_person(room):
    agent, call, _peers = room

    def steer():
        call("robin", "session.steer", text="marker own steer")
        agent.deliver_mid_turn()

    agent.script = [steer]
    call("agent", "prompt.submit", text="marker first")
    [row] = agent.rows
    assert row["display_metadata"]["author"] == AUTHOR_ROBIN
    assert "Sent by «Robin» in person, not by the agent «Claude Code»" in row["api_content"]


def test_an_agents_leftover_steer_runs_as_the_agents(room):
    from tui_gateway.row_author import deliver_correction
    agent, call, _peers = room
    agent.script = [lambda: deliver_correction(agent, "steer", "marker leftover", ROBIN, VIA)]
    call("robin", "prompt.submit", text="marker first")

    turn = _turn(agent, "marker leftover")
    assert (turn["author"], turn["agent"], turn["scope"]) == (AUTHOR_ROBIN_VIA, VIA, ROBIN)


def test_the_goal_continuation_of_an_agents_turn_keeps_the_marker_but_no_author(room, monkeypatch):
    agent, call, _peers = room
    monkeypatch.setattr(
        server, "_goal_followup_after_turn",
        lambda _sid, _session, _result, _status, _raw: "marker continue" if len(agent.turns) == 1 else None)
    call("agent", "prompt.submit", text="marker goal")

    turn = _turn(agent, "marker continue")
    assert (turn["author"], turn["agent"], turn["scope"]) == (None, VIA, ROBIN)
    assert "an agent, «Claude Code», asked for through MCP" in turn["note"]


# ── retry, regenerate, edit ─────────────────────────────────────────────────────────────────


def _stored_exchange(agent, question, author):
    db, session = agent.db, agent.session
    db.append_message("room", "user", "marker hello", display_metadata={"author": AUTHOR_ROBIN})
    db.append_message("room", "assistant", "hello")
    db.append_message("room", "user", question, display_metadata={"author": author} if author else None)
    db.append_message("room", "assistant", "an answer")
    session["history"] = db.get_messages_as_conversation("room", include_row_ids=True)


def test_a_retry_an_agent_presses_marks_replayed_by_with_via(room):
    agent, call, peers = room
    _stored_exchange(agent, "marker question", AUTHOR_ROBIN)

    # command.dispatch refuses an agent's connection (``agent_guard``); the carrier is still pinned, for a
    # retry reached on an agent's connection by any other path.
    assert call("agent", "command.dispatch", name="retry", arg="")["error"]["code"] == 4033
    token = bind_transport(peers["agent"])
    try:
        pressed = server._SLASH_BUILTINS["retry"]("rid", {"session_id": "sid"}, agent.session, "retry", "")
    finally:
        reset_transport(token)
    assert pressed["result"]["type"] == "exec"

    turn = _turn(agent, "marker question")
    assert (turn["author"], turn["replayed_by"], turn["agent"]) == (AUTHOR_ROBIN, AUTHOR_ROBIN_VIA, VIA)
    assert "an agent, «Claude Code», asked through MCP for this message to run again" in turn["note"]


def test_the_person_retrying_their_agents_message_keeps_its_via(room):
    agent, call, _peers = room
    _stored_exchange(agent, "marker question", AUTHOR_ROBIN_VIA)

    call("robin", "command.dispatch", name="retry", arg="")

    turn = _turn(agent, "marker question")
    assert (turn["author"], turn["replayed_by"], turn["agent"]) == (AUTHOR_ROBIN_VIA, None, None)
    # The words were the agent's, and the model is told so; the turn is the person's own.
    assert "sent by an agent, «Claude Code», through MCP" in turn["note"]
    assert "This message was sent by an agent" not in turn["note"]


def test_an_agent_cannot_regenerate_or_edit_a_row(room):
    """Plan "Agent prompts": a rewind from an agent's connection is refused before anything is cut."""
    agent, call, _peers = room
    _stored_exchange(agent, "marker question", AUTHOR_ROBIN)
    row_id = next(row["_row_id"] for row in agent.session["history"] if row["content"] == "marker question")
    before = len(agent.db.get_messages("room", include_inactive=True))

    response = call("agent", "prompt.submit", text="marker edited", truncate_before_row_id=row_id,
                    confirm_truncate=True)
    assert response["error"]["code"] == 4033, response
    assert agent.turns == [] and len(agent.db.get_messages("room", include_inactive=True)) == before


@pytest.mark.parametrize("who, text, original, expected", [
    ("robin", "marker edited", AUTHOR_ROBIN_VIA, AUTHOR_ROBIN),
    ("robin", "marker question", AUTHOR_ROBIN_VIA, AUTHOR_ROBIN_VIA),
], ids=["robin_edits_the_agents_row", "robin_regenerates_the_agents_row"])
def test_a_truncating_resubmit_keeps_whose_words_and_how_they_were_sent(room, who, text, original, expected):
    agent, call, _peers = room
    _stored_exchange(agent, "marker question", original)
    row_id = next(row["_row_id"] for row in agent.session["history"] if row["content"] == "marker question")

    response = call(who, "prompt.submit", text=text, truncate_before_row_id=row_id, confirm_truncate=True)
    assert response.get("result", {}).get("status") == "streaming", response
    turn = _turn(agent, text)
    assert turn["author"] == expected and turn["agent"] == (VIA if who == "agent" else None)


# ── what a client reads ─────────────────────────────────────────────────────────────────────


def test_gateway_capabilities_advertise_via():
    result = server._methods["gateway.capabilities"]("rid", {})["result"]
    assert result["per_message_author_via"] is True and result["per_message_author"] is True
