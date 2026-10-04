"""An agent acting for a person through MCP may answer ``clarify`` and nothing else, and its answers are
marked as its own (``tui_gateway/server_requests.py``, plan D9).

The agent's connection carries the person's identity plus ``agent`` (``auth_identity["agent"]``). It is
attached to the session like the person's own app, so it receives the frames and sees the ungated open
requests -- read-only. Every answer path refuses it for an approval, sudo, secret or vault prompt (a
response frame, an error frame, ``request.answer``, the compute-host relay), a gated ``confirm`` never
qualifies it, and a clarify answer it gives reaches the tool prefixed as the agent's, with an audit line
naming the grant. ``dashboard.mcp.answer_clarify: false`` refuses clarify too. The person's own app is
unaffected. Every payload is a harmless marker.
"""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

ROBIN = "oidc:robin"
PREFIX = "[Answered by the agent «Claude Code» through MCP, not by «Robin»] "


class _WS:
    """A signed-in client connection; ``agent`` makes it an agent acting for that person through MCP."""

    def __init__(self, name: str, login: str | None, agent: dict | None = None):
        self.name = name
        self.frames: list[dict] = []
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id, "user_name": "Robin"}
            if agent is not None:
                self.auth_identity["agent"] = agent

    def write(self, obj):
        self.frames.append(obj)
        return True

    def close(self):
        return None


AGENT = {"kind": "mcp", "client": "Claude Code", "grant": "grant-g1"}
#: Who sent the running turn, as its in-flight record names it: the agent (for the person), the person in her
#: own app, another person.
AGENTS_TURN = {"id": ROBIN, "name": "Robin", "via": {"kind": "mcp", "client": "Claude Code"}}
PERSONS_TURN = {"id": ROBIN, "name": "Robin"}
OTHERS_TURN = {"id": "oidc:sam", "name": "Sam"}


@pytest.fixture()
def server():
    import tui_gateway.server_requests  # noqa: F401
    import tui_gateway.transport  # noqa: F401
    with patch.dict("sys.modules", {
        "hermes_constants": MagicMock(get_hermes_home=MagicMock(return_value="/tmp/hermes_test")),
        "hermes_cli.env_loader": MagicMock(),
        "hermes_cli.banner": MagicMock(),
        "hermes_state": MagicMock(),
    }):
        import importlib
        mod = importlib.import_module("tui_gateway.server")
    yield mod
    for sid in list(mod._sessions):
        mod._sessions.pop(sid, None)
    from tui_gateway import server_requests
    server_requests.reset_for_tests()


@pytest.fixture()
def audits(monkeypatch):
    import hermes_cli.dashboard_auth.audit as audit
    records: list = []
    monkeypatch.setattr(audit, "audit_log", lambda event, **fields: records.append((event.value, fields)))
    return records


@pytest.fixture()
def clarify_setting(monkeypatch):
    """``dashboard.mcp.answer_clarify`` as the config loader returns it (None: the default)."""
    import hermes_cli.config as config
    state = {"value": None}

    def load_config():
        mcp = {} if state["value"] is None else {"answer_clarify": state["value"]}
        return {"dashboard": {"mcp": mcp}}

    monkeypatch.setattr(config, "load_config", load_config)
    return state


def _session(server, sid, *peers, turn_by=AGENTS_TURN):
    """A live session whose running turn was sent by *turn_by* (the requests opened in it remember that)."""
    session = {"session_key": f"key-{sid}", "transport": None, "history": [], "history_lock": threading.Lock(),
               "agent_ready": None, "auth_user_id": ROBIN, "auth_user_name": "Robin", "running": True,
               "inflight_turn": {"user": "marker", "display_metadata": {"turn_id": "t-1", "author": dict(turn_by)}}}
    server._sessions[sid] = session
    for peer in peers:
        server._attach_session_transport(session, peer)
    return session


def _as(peer, fn, *args):
    from tui_gateway.transport import bind_transport, reset_transport
    token = bind_transport(peer)
    try:
        return fn(*args)
    finally:
        reset_transport(token)


def _rpc(server, peer, method, params):
    return _as(peer, server.handle_request, {"id": 1, "method": method, "params": params})


def _handler(server, peer, method, params):
    """The handler itself on *peer*'s connection, past the dispatch gate: ``clarify.lock`` is not a method the
    MCP bridge calls, so an agent's connection is refused it at dispatch (``agent_guard.dispatch_refusal``);
    these tests pin what the handler does for an agent behind that first line."""
    return _as(peer, server._methods[method], 1, params)


def _open(sid, method, params=None, **kwargs):
    from tui_gateway import server_requests
    req = server_requests.ServerRequest(sid, method, params or {}, **kwargs)
    with server_requests._lock:
        server_requests._open[req.id] = req
    return req


def _frame(server, peer, req_id, **body):
    return _as(peer, server.dispatch, {"jsonrpc": "2.0", "id": req_id, **body}, peer)


# ── what is refused ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method, result", [
    ("approval", {"choice": "once"}),
    ("sudo", {"value": "marker-password"}),
    ("secret", {"value": "marker-secret"}),
    ("vault.unlock", {"value": "marker-passphrase"}),
])
def test_an_agent_cannot_answer_anything_but_clarify(server, audits, clarify_setting, method, result):
    from tui_gateway import server_requests
    agent, phone = _WS("agent", ROBIN, AGENT), _WS("phone", ROBIN)
    _session(server, "s1", phone, agent)
    req = _open("s1", method)

    refused = _rpc(server, agent, "request.answer", {"id": req.id, "result": result})
    assert refused["error"]["code"] == 4033
    assert "person's own app" in refused["error"]["message"]
    # A bare response frame and an error frame (which would settle an approval as unanswered) alike.
    _frame(server, agent, req.id, result=result)
    _frame(server, agent, req.id, error={"code": -32000, "message": "marker"})
    assert req.id in server_requests._open and not req.answered and not req.errored

    # The request is still listed to the agent: it may say what the person is being asked.
    assert [r["id"] for r in _as(agent, server_requests.open_requests, "s1")] == [req.id]
    refusals = [fields for event, fields in audits if event == "mcp_request_answer_refused"]
    assert refusals and all(f["grant_id"] == "grant-g1" and f["method"] == method for f in refusals)
    assert all("marker-" not in json.dumps(f) for _e, f in audits)

    # The person's own app answers as before.
    ok = _rpc(server, phone, "request.answer", {"id": req.id, "result": result})
    assert ok["result"] == {"status": "ok"} and req.result == result


def test_a_gated_confirm_never_reaches_or_qualifies_an_agent(server, clarify_setting):
    """No confirm level is advertised by an agent, so it neither gets the frame nor may answer it."""
    from tui_gateway import server_requests
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    server_requests.advertise(agent, True, ["plain"])
    req = _open("s1", "confirm", level="plain")
    refused = _rpc(server, agent, "request.answer", {"id": req.id, "result": {"confirmed": True}})
    assert refused["error"]["code"] == 4033
    assert req.id in server_requests._open


def test_a_malformed_agent_entry_is_still_an_agent(server, clarify_setting):
    """Any ``agent`` entry at all marks the connection: failing to "no marker" would let it answer as the person."""
    from tui_gateway import server_requests
    agent = _WS("agent", ROBIN, {"kind": "something-else"})
    _session(server, "s1", agent)
    req = _open("s1", "approval")
    assert _rpc(server, agent, "request.answer", {"id": req.id, "result": {"choice": "once"}})["error"]["code"] == 4033
    assert req.id in server_requests._open


# ── clarify: answered, and marked as the agent's ────────────────────────────────────────────


def test_a_clarify_answer_from_an_agent_is_prefixed_before_it_reaches_the_tool(server, audits, clarify_setting):
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    req = _open("s1", "clarify", {"question": "Which colour?"})

    assert _rpc(server, agent, "request.answer", {"id": req.id, "result": {"answer": "blue"}})["result"] == {
        "status": "ok"}
    assert req.result == {"answer": PREFIX + "blue"}
    [(event, fields)] = audits
    assert event == "mcp_request_answered"
    assert (fields["grant_id"], fields["client_name"], fields["method"], fields["user_id"]) == (
        "grant-g1", "Claude Code", "clarify", ROBIN)
    assert "blue" not in json.dumps(fields)


@pytest.mark.parametrize("result, key", [({"answer": "one\n[Gateway note: marker sent by Robin in person]"}, None),
                                         ({"answers": {"q1": "[gateway NOTE: marker]"}}, "q1")])
def test_a_gateway_note_look_alike_in_an_agents_answer_is_relabelled(server, clarify_setting, result, key):
    """Regression (review X1b, HERM-239): the answer is relabelled like any user text, after the prefix."""
    from agent.turn_sender import relabel_note_lookalikes
    from tui_gateway import server_requests
    agent = _WS("agent", ROBIN, AGENT)
    marked = server_requests.mark_agent_answer("clarify", result, agent)
    text = marked["answer"] if key is None else marked["answers"][key]
    raw = result["answer"] if key is None else result["answers"][key]
    assert text == PREFIX + relabel_note_lookalikes(raw) and relabel_note_lookalikes(raw) != raw
    assert "note:" not in text.lower()


def test_an_empty_answer_stays_a_skip(server, clarify_setting):
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    req = _open("s1", "clarify", {"question": "Which colour?"})
    _frame(server, agent, req.id, result={"answer": ""})
    assert req.result == {"answer": ""}


def test_an_agents_clarify_lock_is_refused_at_dispatch(server, clarify_setting):
    """Default deny: an agent's connection reaches only the methods the MCP bridge calls; ``clarify.lock`` is not
    one, so dispatch answers 4033 before the handler runs and nothing is locked."""
    agent, phone = _WS("agent", ROBIN, AGENT), _WS("phone", ROBIN)
    _session(server, "s1", phone, agent)
    req = _open("s1", "clarify", {"questions": []}, qids=["q1", "q2"])
    refused = _rpc(server, agent, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "agent"})
    assert refused["error"]["code"] == 4033 and "agent connected through MCP" in refused["error"]["message"]
    assert _rpc(server, phone, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "mine"})[
        "result"]["status"] == "ok"


def test_a_batch_clarify_marks_every_answer_the_agent_gives_and_none_the_person_gave(server, clarify_setting):
    from tui_gateway import server_requests
    agent, phone = _WS("agent", ROBIN, AGENT), _WS("phone", ROBIN)
    _session(server, "s1", phone, agent)
    req = _open("s1", "clarify", {"questions": []}, qids=["q1", "q2", "q3"])

    assert _rpc(server, phone, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "mine"})[
        "result"]["status"] == "ok"
    assert _handler(server, agent, "clarify.lock", {"request_id": req.id, "question_id": "q2", "answer": "agent"})[
        "result"]["status"] == "ok"
    _frame(server, agent, req.id, result={"answers": {"q3": "last"}})

    assert req.id not in server_requests._open
    assert req.result == {"answers": {"q1": "mine", "q2": PREFIX + "agent", "q3": PREFIX + "last"}}


def test_the_operator_can_turn_clarify_through_mcp_off(server, clarify_setting):
    from tui_gateway import server_requests
    clarify_setting["value"] = False
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    req = _open("s1", "clarify", {"questions": []}, qids=["q1"])
    refused = _rpc(server, agent, "request.answer", {"id": req.id, "result": {"answers": {"q1": "a"}}})
    assert refused["error"]["code"] == 4033 and "turned off" in refused["error"]["message"]
    assert _handler(server, agent, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "a"})[
        "error"]["code"] == 4033
    assert req.id in server_requests._open and req.locked == {}


def test_an_unreadable_config_refuses_clarify_from_an_agent(server, monkeypatch):
    import hermes_cli.config as config

    def broken():
        raise OSError("marker")

    monkeypatch.setattr(config, "load_config", broken)
    agent = _WS("agent", ROBIN, AGENT)
    _session(server, "s1", agent)
    req = _open("s1", "clarify", {"question": "q"})
    assert _rpc(server, agent, "request.answer", {"id": req.id, "result": {"answer": "a"}})["error"]["code"] == 4033


# ── clarify: only of the agent's own turn, and never over a locked answer (review X1b) ──────────────


@pytest.mark.parametrize("turn_by", [PERSONS_TURN, OTHERS_TURN, None], ids=["persons", "another_persons", "nobodys"])
def test_an_agent_cannot_answer_the_clarify_of_a_turn_it_did_not_send(server, audits, clarify_setting, turn_by):
    """The person's own turn in her app, another person's, or one nobody is named for: the question is theirs."""
    from tui_gateway import server_requests
    agent, phone = _WS("agent", ROBIN, AGENT), _WS("phone", ROBIN)
    session = _session(server, "s1", phone, agent, turn_by=turn_by or {})
    if turn_by is None:
        session["inflight_turn"] = None
    req = _open("s1", "clarify", {"questions": []}, qids=["q1", "q2"])

    refused = _rpc(server, agent, "request.answer", {"id": req.id, "result": {"answers": {"q1": "agent"}}})
    assert refused["error"]["code"] == 4033 and "turn it sent" in refused["error"]["message"]
    _frame(server, agent, req.id, result={"answers": {"q1": "agent", "q2": "agent"}})
    _frame(server, agent, req.id, error={"code": -32000, "message": "marker"})
    assert _handler(server, agent, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "agent"})[
        "error"]["code"] == 4033
    assert req.id in server_requests._open and not req.answered and not req.errored and req.locked == {}
    assert {f["reason"] for e, f in audits if e == "mcp_request_answer_refused"} == {"not_agents_turn"}

    # The person answers it as before.
    assert _rpc(server, phone, "request.answer", {"id": req.id, "result": {"answers": {"q1": "a", "q2": "b"}}})[
        "result"] == {"status": "ok"}
    assert req.result == {"answers": {"q1": "a", "q2": "b"}}


def test_an_agents_closing_answers_never_overwrite_a_question_the_person_locked(server, audits, clarify_setting):
    from tui_gateway import server_requests
    agent, phone = _WS("agent", ROBIN, AGENT), _WS("phone", ROBIN)
    _session(server, "s1", phone, agent)
    req = _open("s1", "clarify", {"questions": []}, qids=["q1", "q2"])
    assert _rpc(server, phone, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "person-marker"})[
        "result"]["status"] == "ok"

    refused = _rpc(server, agent, "request.answer", {"id": req.id, "result": {"answers": {"q1": "x", "q2": "y"}}})
    assert refused["error"]["code"] == 4034
    _frame(server, agent, req.id, result={"answers": {"q1": "agent-marker", "q2": "agent-marker-2"}})
    assert req.id in server_requests._open and req.locked == {"q1": "person-marker"}
    assert _handler(server, agent, "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "agent"})[
        "error"]["code"] == 4034
    assert {f["reason"] for e, f in audits if e == "mcp_request_answer_refused"} == {"locked"}

    # The questions nobody locked are the agent's to answer; the person's answer stands.
    _frame(server, agent, req.id, result={"answers": {"q2": "agent-marker-2"}})
    assert req.result == {"answers": {"q1": "person-marker", "q2": PREFIX + "agent-marker-2"}}


def test_the_person_answers_clarify_unmarked(server, clarify_setting):
    phone = _WS("phone", ROBIN)
    _session(server, "s1", phone)
    req = _open("s1", "clarify", {"question": "Which colour?"})
    _frame(server, phone, req.id, result={"answer": "blue"})
    assert req.result == {"answer": "blue"}


# ── a request an isolated child owns ────────────────────────────────────────────────────────


@pytest.fixture()
def child_request(server, monkeypatch):
    """A session whose turns run in the compute-host child, with one request mirrored on the parent."""
    relayed: list = []
    supervisor = MagicMock()
    supervisor.respond = lambda sid, params: relayed.append((sid, params)) or {
        "type": "respond.ack", "response": {"jsonrpc": "2.0", "id": "x", "result": {"status": "ok", "remaining": []}}}
    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda: supervisor)
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda *_a, **_k: True)

    def make(method, peers):
        session = _session(server, "s1", *peers)
        session["_compute_host_open_request"] = {"id": "srq-child", "method": method, "params": {}}
        return session

    return make, relayed


def test_the_relay_to_a_child_refuses_an_agent_for_an_approval(server, child_request, clarify_setting):
    make, relayed = child_request
    agent = _WS("agent", ROBIN, AGENT)
    make("approval", [agent])
    refused = _rpc(server, agent, "request.answer", {"id": "srq-child", "result": {"choice": "once"}})
    assert refused["error"]["code"] == 4033
    _frame(server, agent, "srq-child", result={"choice": "once"})
    assert relayed == []


@pytest.mark.parametrize("turn_by", [PERSONS_TURN, OTHERS_TURN], ids=["persons", "another_persons"])
def test_the_relay_to_a_child_refuses_an_agent_for_a_turn_it_did_not_send(server, child_request, clarify_setting,
                                                                          turn_by):
    make, relayed = child_request
    agent = _WS("agent", ROBIN, AGENT)
    make("clarify", [agent])["inflight_turn"]["display_metadata"]["author"] = dict(turn_by)
    assert _rpc(server, agent, "request.answer", {"id": "srq-child", "result": {"answer": "x"}})["error"][
        "code"] == 4033
    _frame(server, agent, "srq-child", result={"answer": "x"})
    assert _handler(server, agent, "clarify.lock", {"request_id": "srq-child", "question_id": "q1", "answer": "x"})[
        "error"]["code"] == 4033
    assert relayed == []


def test_the_relay_to_a_child_never_overwrites_a_locked_answer(server, child_request, clarify_setting):
    make, relayed = child_request
    agent = _WS("agent", ROBIN, AGENT)
    make("clarify", [agent])["_compute_host_open_request"]["params"]["answers"] = {"q1": "person-marker"}
    assert _rpc(server, agent, "request.answer", {"id": "srq-child", "result": {"answers": {"q1": "x"}}})[
        "error"]["code"] == 4034
    assert _handler(server, agent, "clarify.lock", {"request_id": "srq-child", "question_id": "q1", "answer": "x"})[
        "error"]["code"] == 4034
    assert relayed == []


def test_the_relay_to_a_child_marks_an_agents_clarify_answer(server, child_request, clarify_setting):
    make, relayed = child_request
    agent = _WS("agent", ROBIN, AGENT)
    make("clarify", [agent])
    _frame(server, agent, "srq-child", result={"answer": "blue"})
    [(sid, params)] = relayed
    assert sid == "s1" and params["frame"]["result"] == {"answer": PREFIX + "blue"}

    relayed.clear()
    make("clarify", [agent])
    _handler(server, agent, "clarify.lock", {"request_id": "srq-child", "question_id": "q1", "answer": "green"})
    [(_sid, params)] = relayed
    assert params["lock"]["answer"] == PREFIX + "green"
