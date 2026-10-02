"""Who may read a session's event ring and settle its server→client requests
(``session_transports.py::_transport_may_access_session``).

A signed-in connection that is not attached to a session and whose login neither created it nor ever
attached to it must not replay its events (``session.events.since``) nor answer its requests
(``request.answer``, a bare response frame, ``clarify.lock``, ``approval.respond`` / ``pending`` /
``received``). The legitimate flows stay open: the creator's other device and a reconnecting socket
(replay before resume), a person who took part in a shared chat, attached peers, and connections without a
per-person identity (session-token mode, stdio, the server-internal credential).
"""

from __future__ import annotations

import contextlib
import threading
from unittest.mock import MagicMock, patch

import pytest


class _WS:
    """A signed-in (or anonymous) client connection."""

    def __init__(self, name: str, login: str | None):
        self.name = name
        self.frames: list[dict] = []
        self._closed = False
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id}

    def write(self, obj):
        self.frames.append(obj)
        return True

    def close(self):
        self._closed = True

    def __repr__(self):
        return f"<ws {self.name}>"


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


ALICE, BOB = "self_hosted:alice", "self_hosted:bob"


def _session(server, sid, *peers, creator=ALICE):
    session = {"session_key": f"key-{sid}", "transport": None, "history": [], "history_lock": threading.Lock(),
               "agent_ready": None, "auth_user_id": creator, "auth_user_name": ""}
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


def _open_sudo(sid):
    from tui_gateway import server_requests
    req = server_requests.ServerRequest(sid, "sudo", {})
    with server_requests._lock:
        server_requests._open[req.id] = req
    return req


# ── the rule ────────────────────────────────────────────────────────────────────────────────


def test_rule(server):
    phone, laptop, bob, anon = _WS("phone", ALICE), _WS("laptop", ALICE), _WS("bob", BOB), _WS("anon", None)
    session = _session(server, "s1", phone)
    allowed = lambda t: server._transport_may_access_session(session, t, sid="s1")  # noqa: E731
    assert allowed(phone)                       # attached
    assert allowed(laptop)                      # the creator's login, not attached (reconnect before resume)
    assert allowed(anon)                        # no per-person identity: token mode / stdio / internal
    assert allowed(None)                        # in-process
    assert not allowed(bob)                     # another person who never attached
    server._attach_session_transport(session, bob)   # Bob joins (logged, session marked shared)
    assert session["auth_user_shared"] is True
    server._detach_session_transport(session, bob)
    assert allowed(_WS("bob-again", BOB))       # a participant may reconnect
    assert server._transport_may_access_session(None, bob, sid="gone") is False
    assert server._transport_may_access_session(None, anon, sid="gone") is True
    assert server._transport_may_access_session(None, bob, sid="") is True   # app-level requests


# ── reads ───────────────────────────────────────────────────────────────────────────────────


def test_events_since_refuses_another_person_and_serves_the_owner_before_resume(server):
    from tui_gateway import event_replay
    phone = _WS("phone", ALICE)
    _session(server, "s1", phone)
    _open_sudo("s1")
    event_replay.reset_replay_state()
    event_replay._stamp_event({"jsonrpc": "2.0", "method": "event",
                               "params": {"type": "message.delta", "session_id": "s1", "payload": {"text": "x"}}})
    refused = _rpc(server, _WS("bob", BOB), "session.events.since", {"session_id": "s1", "last_seen": 0})
    assert refused["error"]["code"] == 4001
    # Alice's new socket replays before it resumes; Bob's attempt left nothing behind.
    ok = _rpc(server, _WS("phone-reconnected", ALICE), "session.events.since", {"session_id": "s1", "last_seen": 0})
    assert [r["method"] for r in ok["result"]["open_requests"]] == ["sudo"]
    assert [e["type"] for e in ok["result"]["events"]] == ["message.delta"]
    anon = _rpc(server, _WS("token-mode", None), "session.events.since", {"session_id": "s1", "last_seen": 0})
    assert len(anon["result"]["events"]) == 1


def test_approval_rpcs_refuse_another_person(server, monkeypatch):
    import tools.approval as approval
    resolved: list = []
    monkeypatch.setattr(approval, "resolve_gateway_approval", lambda *a, **k: resolved.append(a) or 1)
    monkeypatch.setattr(approval, "list_gateway_approvals", lambda key: [{"request_id": "ap-1"}])
    monkeypatch.setattr(server, "_wait_agent", lambda session, rid: None)
    _session(server, "s1", _WS("phone", ALICE))
    bob = _WS("bob", BOB)
    for method, params in (("approval.respond", {"session_id": "s1", "choice": "once", "request_id": "ap-1"}),
                           ("approval.respond", {"session_id": "stale", "choice": "once", "request_id": "ap-1"}),
                           ("approval.pending", {"session_id": "s1"}),
                           ("approval.received", {"session_id": "s1", "request_id": "ap-1"})):
        assert _rpc(server, bob, method, params)["error"]["code"] == 4001, (method, params)
    assert resolved == []
    ok = _rpc(server, _WS("laptop", ALICE), "approval.respond", {"session_id": "s1", "choice": "once",
                                                                  "request_id": "ap-1"})
    assert ok["result"]["resolved"] == 1 and len(resolved) == 1


# ── settling requests ───────────────────────────────────────────────────────────────────────


def test_request_answer_and_response_frames_from_another_person_are_refused(server):
    from tui_gateway import server_requests
    phone, bob = _WS("phone", ALICE), _WS("bob", BOB)
    _session(server, "s1", phone)
    req = _open_sudo("s1")
    refused = _rpc(server, bob, "request.answer", {"id": req.id, "result": {"value": "hunter2"}})
    assert refused["error"]["code"] == 4033
    assert _as(bob, server.dispatch, {"jsonrpc": "2.0", "id": req.id, "result": {"value": "hunter2"}}, bob) is None
    assert req.id in server_requests._open and not req.answered
    ok = _rpc(server, _WS("laptop", ALICE), "request.answer", {"id": req.id, "result": {"value": "pw"}})
    assert ok["result"] == {"status": "ok"} and req.result == {"value": "pw"}


def test_request_answer_with_a_profile_parameter_keeps_working(server):
    phone = _WS("phone", ALICE)
    _session(server, "s1", phone)
    req = _open_sudo("s1")
    ok = _rpc(server, phone, "request.answer", {"id": req.id, "result": {"value": "pw"}, "profile": None})
    assert ok["result"] == {"status": "ok"}


def test_clarify_lock_from_another_person_is_refused(server):
    from tui_gateway import server_requests
    _session(server, "s1", _WS("phone", ALICE))
    req = server_requests.ServerRequest("s1", "clarify", {"questions": []}, qids=["q1"])
    with server_requests._lock:
        server_requests._open[req.id] = req
    refused = _rpc(server, _WS("bob", BOB), "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "a"})
    assert refused["error"]["code"] == 4033 and req.locked == {}
    ok = _rpc(server, _WS("phone2", ALICE), "clarify.lock", {"request_id": req.id, "question_id": "q1", "answer": "a"})
    assert ok["result"] == {"status": "ok", "remaining": []}


def test_shared_chat_participants_and_attached_peers_may_answer(server):
    alice, bob = _WS("alice", ALICE), _WS("bob", BOB)
    _session(server, "s1", alice, bob)          # a shared chat: both attached
    req = _open_sudo("s1")
    assert _rpc(server, bob, "request.answer", {"id": req.id, "result": {"value": "x"}})["result"] == {"status": "ok"}


def test_two_devices_of_one_person_and_token_mode(server):
    phone, desk = _WS("phone", ALICE), _WS("desk", ALICE)
    _session(server, "s1", phone, desk)
    req = _open_sudo("s1")
    assert _rpc(server, desk, "request.answer", {"id": req.id, "result": {"value": "x"}})["result"]["status"] == "ok"
    _session(server, "s2", _WS("tok-a", None), creator=None)
    req2 = _open_sudo("s2")
    assert _rpc(server, _WS("tok-b", None), "request.answer",
                {"id": req2.id, "result": {"value": "x"}})["result"]["status"] == "ok"


def test_reconnect_resume_then_answer(server):
    """A socket that reconnected and reattached (the resume path) answers through request.answer."""
    phone = _WS("phone", ALICE)
    session = _session(server, "s1", phone)
    req = _open_sudo("s1")
    server._detach_session_transport(session, phone)
    reconnected = _WS("phone-2", ALICE)
    with session["history_lock"]:
        server._rebind_live_transport("s1", session, reconnected)
    assert [r["id"] for r in _as(reconnected, server._open_requests, "s1")] == [req.id]
    assert _rpc(server, reconnected, "request.answer", {"id": req.id, "result": {"value": "x"}})["result"]["status"] == "ok"


# ── every session-scoped RPC ────────────────────────────────────────────────────────────────

GUARDED = [
    ("session.history", {}), ("session.usage", {}), ("session.status", {}), ("session.interrupt", {}),
    ("session.steer", {"text": "x"}), ("session.redirect", {"text": "x"}), ("session.title", {"title": "x"}),
    ("session.activate", {}), ("session.undo", {}), ("session.compress", {}), ("session.branch", {}),
    ("session.save", {}), ("session.context_breakdown", {}), ("session.cwd.set", {"cwd": "/tmp"}),
    ("session.set_hidden", {"hidden": True}), ("prompt.submit", {"text": "hi"}), ("prompt.btw", {"text": "hi"}),
    ("slash.exec", {"command": "/help"}), ("image.attach", {"path": "/tmp/x.png"}), ("clipboard.paste", {}),
    ("input.detect_drop", {"text": "x"}), ("terminal.resize", {"cols": 80}),
    ("message.react", {"emoji": "x", "newest_role": "user"}), ("approval.pending", {}),
    ("approval.received", {"request_id": "r"}), ("approval.respond", {"choice": "deny"}),
    ("handoff.fail", {}), ("session.control.read", {}), ("subagent.steer", {"subagent_id": "a", "text": "x"}),
]


@pytest.mark.parametrize("method, params", GUARDED, ids=[m for m, _ in GUARDED])
def test_every_session_scoped_rpc_refuses_another_person_like_an_unknown_session(server, method, params):
    _session(server, "s1", _WS("phone", ALICE))
    refused = _rpc(server, _WS("bob", BOB), method, {"session_id": "s1", **params})
    unknown = _rpc(server, _WS("bob", BOB), method, {"session_id": "no-such-session", **params})
    assert refused.get("error", {}).get("code") == 4001, refused
    assert refused["error"] == unknown["error"]  # no oracle
    # Control: the owner's same call gets past the session lookup (whatever it answers next), so the 4001
    # above is the access rule and not a session the handler cannot see.
    try:
        owner = _rpc(server, _WS("laptop", ALICE), method, {"session_id": "s1", **params})
    except (AttributeError, KeyError, TypeError):
        return  # the handler body ran on the stub session: it got past the lookup
    assert owner.get("error", {}).get("code") != 4001, owner


def test_sess_nowait_serves_the_owner_and_token_mode(server):
    session = _session(server, "s1", _WS("phone", ALICE))
    for transport in (_WS("laptop", ALICE), _WS("token-mode", None)):
        assert _as(transport, server._sess_nowait, {"session_id": "s1"}, 1) == (session, None)


def test_session_close_of_another_persons_session_closes_nothing(server):
    _session(server, "s1", _WS("phone", ALICE))
    assert _rpc(server, _WS("bob", BOB), "session.close", {"session_id": "s1"})["result"] == {"closed": False}
    assert "s1" in server._sessions


def test_lookups_that_fall_back_treat_another_persons_session_as_absent(server):
    session = _session(server, "s1", _WS("phone", ALICE))
    assert _as(_WS("bob", BOB), server._caller_live_session, "s1") is None
    assert _as(_WS("laptop", ALICE), server._caller_live_session, "s1") is session
    assert _as(_WS("token", None), server._caller_live_session, "s1") is session


# ── listings ────────────────────────────────────────────────────────────────────────────────


def test_active_list_shows_full_rows_only_for_accessible_sessions(server, monkeypatch):
    monkeypatch.setattr(server, "_session_live_status", lambda sid, session: session.get("_status", "idle"))
    _session(server, "mine", _WS("phone", ALICE))
    _session(server, "bobs-idle", _WS("bob-phone", BOB), creator=BOB)
    busy = _session(server, "bobs-busy", _WS("bob-desk", BOB), creator=BOB)
    busy.update(_status="working", session_key="20261002_101010_abcdef")
    rows = _rpc(server, _WS("laptop", ALICE), "session.active_list", {})["result"]["sessions"]
    by_key = {row["session_key"]: row for row in rows}
    assert set(by_key) == {"key-mine", "20261002_101010_abcdef"}
    assert by_key["key-mine"]["id"] == "mine"
    bare = by_key["20261002_101010_abcdef"]
    assert bare["status"] == "working" and bare["id"] == "" and bare["title"] == "" and bare["preview"] == ""
    # Token mode keeps seeing everything, as before.
    assert len(_rpc(server, _WS("token", None), "session.active_list", {})["result"]["sessions"]) == 3


def test_agents_list_hides_another_persons_background_processes(server, monkeypatch):
    registry = server._tools_mod("tools.process_registry")  # the module object the handler itself resolves
    _session(server, "s1", _WS("phone", ALICE))
    monkeypatch.setattr(registry.process_registry, "list_sessions", lambda: [
        {"session_id": "key-s1", "command": "make", "status": "running", "uptime_seconds": 1},
        {"session_id": "someone-elses", "command": "secret --token x", "status": "running", "uptime_seconds": 1}])
    # The table builder, through this module object (the fixture re-imports the server per test, and the
    # registered handler keeps the first import's table).
    build = server._SIMPLE_RPCS["agents.list"][1]
    sessions = build.__globals__["_sessions"]
    sessions["s1"] = server._sessions["s1"]
    alice = _as(_WS("laptop", ALICE), build, {})["processes"]
    bob = _as(_WS("bob", BOB), build, {})["processes"]
    token = _as(_WS("token", None), build, {})["processes"]
    sessions.pop("s1", None)
    assert [p["session_id"] for p in alice] == ["key-s1"] and bob == [] and len(token) == 2


# ── in-process dispatch: bot relay and hosted rooms ─────────────────────────────────────────


def test_a_signed_in_relay_into_a_live_bot_chat_reaches_it(server, monkeypatch, tmp_path):
    """End to end through bot_relay.deliver: Bob's desktop relays a bot DM into a Bot Chat this gateway hosts
    live and Bob never attached. The relay is authorized as a relay; its submit is the gateway's own."""
    seen: list = []
    real_submit = server._methods["prompt.submit"]

    def submit(rid, params):  # the access check as the real prompt.submit runs it, then stop
        _session_obj, err = server._sess_nowait(params, rid)
        seen.append(err)
        return err or server._ok(rid, {"status": "queued"})

    monkeypatch.setitem(server._methods, "prompt.submit", submit)
    home = tmp_path / ".hermes"
    (home / "profiles" / "ops").mkdir(parents=True)
    (home / "profiles" / "ops" / "config.yaml").write_text("{}\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(server, "_profile_home", lambda name: home / "profiles" / name)
    bot_chat = _session(server, "live-ops", _WS("bot-chat-peer", None), creator=None)
    bot_chat.update(profile_home=str(home / "profiles" / "ops"), pending_title="Bot Chat")
    out = _rpc(server, _WS("bob-desktop", BOB), "bot_relay.deliver", {"profile": "ops", "message": "ping"})
    assert "result" in out, out
    assert seen == [None]
    # Outside the relay, the same connection may not act on that Bot Chat.
    monkeypatch.setitem(server._methods, "prompt.submit", real_submit)
    assert _rpc(server, _WS("bob-desktop", BOB), "prompt.submit",
                {"session_id": "live-ops", "text": "hi"})["error"]["code"] == 4001


def test_internal_dispatch_cannot_be_claimed_with_underscore_params(server):
    _session(server, "s1", _WS("phone", ALICE))
    refused = _rpc(server, _WS("bob", BOB), "prompt.submit", {"session_id": "s1", "text": "hi", "_hosted_task": {}})
    assert refused["error"]["code"] in (4000, 4001)


def test_bot_room_window_answers_a_members_prompt_from_another_socket(server, monkeypatch):
    """The desktop room window answers a member's prompt over a socket that is not the member session's own:
    request.answer, clarify.lock and approval.respond, same person (signed in) or token mode."""
    import tools.approval as approval
    from tui_gateway import server_requests
    monkeypatch.setattr(approval, "resolve_gateway_approval", lambda *a, **k: 1)
    monkeypatch.setattr(server, "_wait_agent", lambda session, rid: None)
    for login in (ALICE, None):
        server._sessions.clear()
        server_requests.reset_for_tests()
        _session(server, "member", _WS("member-socket", login), creator=login)
        window = _WS("room-window", login)
        sudo = _open_sudo("member")
        clarify = server_requests.ServerRequest("member", "clarify", {"questions": []}, qids=["q1"])
        with server_requests._lock:
            server_requests._open[clarify.id] = clarify
        assert _rpc(server, window, "request.answer", {"id": sudo.id, "result": {"value": "x"}})["result"] == {"status": "ok"}
        assert _rpc(server, window, "clarify.lock", {"request_id": clarify.id, "question_id": "q1", "answer": "a"})["result"]["status"] == "ok"
        assert _rpc(server, window, "approval.respond", {"session_id": "member", "choice": "once",
                                                         "request_id": "ap-1"})["result"]["resolved"] == 1


# ── resume: guessing throttle and the foreign-attach audit ──────────────────────────────────


@pytest.fixture()
def audits(monkeypatch):
    import hermes_cli.dashboard_auth.audit as audit
    records: list = []
    monkeypatch.setattr(audit, "audit_log", lambda event, **fields: records.append((event.value, fields)))
    return records


def test_failed_resumes_throttle_every_resume_by_that_login(server, monkeypatch, audits):
    monkeypatch.setattr(server, "RESUME_FAILURE_LIMIT", 3)
    server._resume_failures.clear()
    bob = _WS("bob", BOB)
    for _ in range(3):
        assert _rpc(server, bob, "session.resume", {"session_id": "20261002_000000_000000"})["error"]["code"] == 4007
    # Now refused for any id, a hit included, and audited; another login is unaffected.
    assert _rpc(server, bob, "session.resume", {"session_id": "anything"})["error"]["code"] == 4029
    assert [e for e, _ in audits] == ["session_resume_throttled"]
    assert audits[0][1]["login"] == BOB
    assert _rpc(server, _WS("alice", ALICE), "session.resume", {"session_id": "x"})["error"]["code"] == 4007
    # Token mode is never throttled.
    for _ in range(5):
        assert _rpc(server, _WS("token", None), "session.resume", {"session_id": "y"})["error"]["code"] == 4007
    server._resume_failures.clear()


def test_a_foreign_attach_is_audited(server, audits):
    session = _session(server, "s1", _WS("phone", ALICE))
    server._attach_session_transport(session, _WS("bob", BOB))
    assert audits and audits[0][0] == "session_foreign_attach"
    assert audits[0][1]["login"] == BOB and audits[0][1]["owner"] == ALICE and audits[0][1]["how"] == "attach"


def test_reopening_a_parked_conversation_keeps_its_owner_a_participant(server, audits):
    session = _session(server, "s9", _WS("bob", BOB), creator=BOB)  # the new record, stamped with Bob

    class Ctx:
        target, found = "20261002_101010_abcdef", {"user_id": ALICE}

    server._resume_note_stored_owner(Ctx, {"result": {"session_id": "s9"}}, _WS("bob", BOB), BOB)
    assert ALICE in session["attached_logins"] and session["auth_user_shared"] is True
    assert audits[-1][0] == "session_foreign_attach" and audits[-1][1]["how"] == "resume"
    assert server._transport_may_access_session(session, _WS("alice-phone", ALICE), sid="s9")


# ── the dashboard Chat tab carries its login ────────────────────────────────────────────────


def test_the_chat_tab_of_another_login_cannot_act_on_a_live_session_without_an_audited_attach(server, audits):
    """The Chat tab's PTY child authenticates with a per-PTY credential carrying the login that opened it
    (hermes_cli/dashboard_auth/ws_tickets.py), not with an identity that names nobody: rule B no longer
    covers it, so Bob's tab is refused on Alice's session and joining it is audited."""
    from hermes_cli.dashboard_auth.ws_tickets import consume_pty_credential, mint_pty_credential
    session = _session(server, "s1", _WS("alice-phone", ALICE))
    bob_tab = _WS("bob-chat-tab", None)
    bob_tab.auth_identity = consume_pty_credential(mint_pty_credential(user_id="bob", provider="self_hosted"))
    assert server._transport_auth_user_id(bob_tab) == BOB
    assert _rpc(server, bob_tab, "session.events.since", {"session_id": "s1", "last_seen": 0})["error"]["code"] == 4001
    req = _open_sudo("s1")
    assert _rpc(server, bob_tab, "request.answer", {"id": req.id, "result": {"value": "x"}})["error"]["code"] == 4033
    server._attach_session_transport(session, bob_tab)  # what resuming Alice's chat from Bob's tab does
    assert audits[-1][0] == "session_foreign_attach" and audits[-1][1]["login"] == BOB


# ── in-process dispatch never attaches the connection it runs on ────────────────────────────


def _relayed_submit(server, transport, sid):
    """The real prompt.submit, as bot_relay.deliver makes it: in process, on the relaying connection."""
    from tools.bot_relay import DeliveryAuthor
    with server._internal_dispatch():
        return _as(transport, server._methods["prompt.submit"], "r",
                   {"session_id": sid, "text": "ping", "queued": True,
                    "_turn_author": DeliveryAuthor({"id": "bot:ops", "name": "ops", "is_bot": True})})


def test_a_relayed_dm_does_not_attach_the_relaying_connection(server, audits):
    from tui_gateway import event_replay
    bot_chat = _session(server, "live-ops", _WS("alice-phone", ALICE))
    bot_chat.update(running=True, agent=None)  # mid-turn: the relayed DM is queued
    bob = _WS("bob-desktop", BOB)
    out = _relayed_submit(server, bob, "live-ops")
    assert "error" not in out, out
    assert not server._session_transport_contains(bot_chat, bob)
    assert not any(v is bob for v in (bot_chat.get("viewers") or {}))
    assert BOB not in (bot_chat.get("attached_logins") or set())
    assert not [a for a in audits if a[0] == "session_foreign_attach"]
    # Afterwards Bob's connection still may not read, receive or answer anything of that session.
    event_replay.reset_replay_state()
    server._emit("message.delta", "live-ops", {"text": "secret"})
    assert bob.frames == []
    assert _rpc(server, bob, "session.events.since", {"session_id": "live-ops", "last_seen": 0})["error"]["code"] == 4001
    req = _open_sudo("live-ops")
    assert _rpc(server, bob, "request.answer", {"id": req.id, "result": {"value": "x"}})["error"]["code"] == 4033


def test_the_hosted_room_adapter_does_not_attach_the_connection_it_runs_on(server, monkeypatch):
    """HostedRoomServerRPC._call (resume, then a local approval) on a thread bound to a client connection."""
    from tui_gateway.hosted_room_server_rpc import HostedRoomServerRPC
    import tools.approval as approval
    monkeypatch.setattr(approval, "resolve_gateway_approval", lambda *a, **k: 1)
    monkeypatch.setattr(server, "_wait_agent", lambda session, rid: None)
    member = _session(server, "member", _WS("alice-phone", ALICE))
    bob = _WS("bob-desktop", BOB)
    adapter = HostedRoomServerRPC(server)
    result = _as(bob, adapter._call, "approval.respond", {"session_id": "member", "choice": "once",
                                                          "request_id": "ap-1"})
    assert result == {"resolved": 1}
    with member["history_lock"]:
        with server._internal_dispatch():
            _as(bob, server._rebind_live_transport, "member", member, bob)
    assert not server._session_transport_contains(member, bob)
    assert BOB not in (member.get("attached_logins") or set())


# ── after the live record is gone ───────────────────────────────────────────────────────────


def test_replay_after_the_record_is_gone_serves_its_people_only(server):
    from tui_gateway import event_replay
    session = _session(server, "gone", _WS("alice-phone", ALICE))
    server._attach_session_transport(session, _WS("bob-phone", BOB))  # Bob took part
    event_replay.reset_replay_state()
    server._emit("message.delta", "gone", {"text": "x"})
    server._pop_session_by_id("gone")  # closed / reaped
    assert "gone" not in server._sessions
    for who in (ALICE, BOB):
        replay = _rpc(server, _WS("reconnected", who), "session.events.since", {"session_id": "gone", "last_seen": 0})
        assert [e["type"] for e in replay["result"]["events"]] == ["message.delta"], who
        assert replay["result"]["epoch"] == event_replay.replay_epoch()
    stranger = _rpc(server, _WS("carol", "self_hosted:carol"), "session.events.since",
                    {"session_id": "gone", "last_seen": 0})
    assert stranger["error"]["code"] == 4001
    assert "result" in _rpc(server, _WS("token", None), "session.events.since", {"session_id": "gone", "last_seen": 0})


# ── handlers that treat an inaccessible session as absent ───────────────────────────────────


def test_session_scoped_config_set_for_another_persons_session_is_refused(server):
    session = _session(server, "s1", _WS("alice-phone", ALICE))
    session["reasoning_effort"] = "low"
    out = _rpc(server, _WS("bob", BOB), "config.set", {"session_id": "s1", "key": "reasoning", "value": "high"})
    assert out.get("error", {}).get("code") == 4001, out
    assert session["reasoning_effort"] == "low"


@pytest.mark.parametrize("method, params", [
    ("command.dispatch", {"name": "retry"}), ("command.dispatch", {"name": "undo"}),
    ("complete.slash", {"text": "/re"}), ("complete.path", {"word": "./"}),
    ("reload.mcp", {}), ("llm.oneshot", {"prompt": "hi"}),
])
def test_fallback_handlers_never_scope_to_another_persons_session(server, monkeypatch, method, params):
    """These handlers treat "no live session" as normal; another person's session must look absent, so it
    never lends its profile home, cwd, model or history to the caller."""
    alice = _session(server, "s1", _WS("alice-phone", ALICE))
    alice.update(profile_home="/profiles/alice", cwd="/home/alice/secret-project", history=[{"role": "user"}])
    seen: list = []
    real_scope = server._session_home_scope
    monkeypatch.setattr(server, "_session_home_scope",
                        lambda session=None, *a, **k: seen.append(session) or real_scope(None, *a, **k))
    monkeypatch.setattr(server, "_session_profile_runtime_scope",
                        lambda session: seen.append(session) or contextlib.nullcontext(), raising=False)
    try:
        _rpc(server, _WS("bob", BOB), method, {"session_id": "s1", **params})
    except Exception:
        pass  # whatever the handler does next with no session, it must not have used Alice's
    assert all(s is not alice for s in seen)
    assert alice["history"] == [{"role": "user"}]
    assert _as(_WS("bob", BOB), server._caller_live_session, "s1") is None


# ── real session.resume through the handler ────────────────────────────────────────────────


@pytest.fixture()
def store(server, monkeypatch, tmp_path):
    from hermes_state import SessionDB
    db = SessionDB(db_path=tmp_path / "state.db")
    monkeypatch.setattr(server, "_profile_session_db", lambda profile_home: (db, False))
    monkeypatch.setattr(server, "_get_db", lambda: db)
    yield db
    db.close()


def test_resume_of_a_live_session_by_another_person_attaches_and_is_audited(server, store, audits):
    store.create_session("20261002_101010_abcdef", source="hermie", user_id=ALICE)
    live = _session(server, "rt1", _WS("alice-phone", ALICE))
    live["session_key"] = "20261002_101010_abcdef"
    bob = _WS("bob", BOB)
    out = _rpc(server, bob, "session.resume", {"session_id": "20261002_101010_abcdef", "omit_messages": True})
    assert out.get("result", {}).get("session_id") == "rt1", out
    assert server._session_transport_contains(live, bob)
    assert [a for a in audits if a[0] == "session_foreign_attach" and a[1]["how"] == "attach"]


def test_cold_reopen_of_a_stored_conversation_keeps_its_owner(server, store, audits):
    store.create_session("20261002_111111_aaaaaa", source="hermie", user_id=ALICE)
    out = _rpc(server, _WS("bob", BOB), "session.resume", {"session_id": "20261002_111111_aaaaaa", "lazy": True})
    sid = out.get("result", {}).get("session_id")
    assert sid in server._sessions, out
    record = server._sessions[sid]
    assert record.get("stored_owner") == ALICE and ALICE in record["attached_logins"]
    assert [a for a in audits if a[0] == "session_foreign_attach" and a[1]["how"] == "resume"]
    # Alice's own reconnecting client may replay it before resuming, and joining it is not "foreign".
    assert "result" in _rpc(server, _WS("alice-new", ALICE), "session.events.since", {"session_id": sid, "last_seen": 0})
    before = len(audits)
    server._attach_session_transport(record, _WS("alice-again", ALICE))
    assert not [a for a in audits[before:] if a[0] == "session_foreign_attach"]


def test_a_messaging_platform_owner_is_not_a_person_joined_by_a_reopen(server, store, audits):
    store.create_session("20261002_121212_bbbbbb", source="matrix", user_id="@someone:example.org")
    out = _rpc(server, _WS("bob", BOB), "session.resume", {"session_id": "20261002_121212_bbbbbb", "lazy": True})
    assert "result" in out, out
    assert not [a for a in audits if a[0] == "session_foreign_attach"]


def test_the_retry_answer_is_not_counted_and_the_throttle_audits_once(server, store, monkeypatch, audits):
    monkeypatch.setattr(server, "RESUME_FAILURE_LIMIT", 2)
    server._resume_failures.clear()
    server._resume_throttle_noted.clear()
    store.create_session("20261002_131313_cccccc", source="hermie", user_id=ALICE)
    live = _session(server, "rt2", _WS("alice-phone", ALICE))
    live["session_key"] = "20261002_131313_cccccc"
    monkeypatch.setattr(server, "_reattach_refusal",
                        lambda rid, sid, session: server._err(rid, 4007, "session no longer live; retry resume"))
    alice = _WS("alice-laptop", ALICE)
    for _ in range(5):
        assert _rpc(server, alice, "session.resume", {"session_id": "20261002_131313_cccccc"})["error"]["code"] == 4007
    assert not server._resume_throttled(ALICE)[0]
    for _ in range(2):
        _rpc(server, alice, "session.resume", {"session_id": "20261002_000000_000000"})
    for _ in range(3):
        assert _rpc(server, alice, "session.resume", {"session_id": "x"})["error"]["code"] == 4029
    assert [e for e, _ in audits].count("session_resume_throttled") == 1
    server._resume_failures.clear()
    server._resume_throttle_noted.clear()


def test_the_hosted_room_adapter_resumes_without_attaching_its_thread_connection(server, store):
    from tui_gateway.hosted_room_server_rpc import HostedRoomServerRPC
    store.create_session("20261002_141414_dddddd", source="room", user_id=ALICE)
    live = _session(server, "rt3", _WS("alice-phone", ALICE))
    live["session_key"] = "20261002_141414_dddddd"
    bob = _WS("bob-desktop", BOB)
    adapter = HostedRoomServerRPC(server)
    result = _as(bob, lambda: adapter.resume(profile=None, session_id="20261002_141414_dddddd", source="room"))
    assert result.get("session_id") == "rt3"
    assert not server._session_transport_contains(live, bob)


def test_delegation_status_lists_only_children_of_accessible_sessions(server, monkeypatch):
    import tools.delegate_tool_registry as registry
    _session(server, "s1", _WS("alice-phone", ALICE))
    monkeypatch.setattr(registry, "_active_subagents", {
        "a": {"subagent_id": "a", "goal": "alice's task", "owner_session_id": "s1"},
        "b": {"subagent_id": "b", "goal": "someone else's task", "owner_session_id": "elsewhere"}})
    alice = _rpc(server, _WS("alice-laptop", ALICE), "delegation.status", {})["result"]["active"]
    bob = _rpc(server, _WS("bob", BOB), "delegation.status", {})["result"]["active"]
    token = _rpc(server, _WS("token", None), "delegation.status", {})["result"]["active"]
    assert [r["subagent_id"] for r in alice] == ["a"] and bob == [] and len(token) == 2
    assert all("owner_session_id" not in r for r in alice + token)


def test_wake_start_never_routes_into_another_persons_session(server, monkeypatch):
    import tools.wake_word as wake
    captured: list = []
    monkeypatch.setattr(server, "_wake_detect_handler", lambda transport, sid, *a: captured.append(sid) or (lambda: None))
    monkeypatch.setattr(server, "_wake_probe", lambda cfg, params, surface: (
        "server", {"available": True, "phrase": "hey hermes", "provider": "test"}))
    monkeypatch.setattr(server, "_wake_owner_snapshot", lambda: (None, ""))
    monkeypatch.setattr(wake, "load_wake_word_config", lambda: {"enabled": True, "phrase": "hey hermes"})
    monkeypatch.setattr(wake, "wake_phrase", lambda cfg: "hey hermes")
    monkeypatch.setattr(wake, "wake_surface_enabled", lambda surface, cfg=None: True)
    monkeypatch.setattr(wake, "start_listening", lambda *a, **k: None)
    _session(server, "s1", _WS("alice-phone", ALICE))
    for transport, expected in ((_WS("bob", BOB), ""), (_WS("alice-laptop", ALICE), "s1")):
        captured.clear()
        _rpc(server, transport, "wake.start", {"surface": "gui", "session_id": "s1"})
        assert captured == [expected], (transport, captured)


def test_a_relayed_dm_into_a_busy_chat_never_attaches_the_relayer_when_the_queue_drains(server, audits, monkeypatch):
    bot_chat = _session(server, "live-ops", _WS("alice-phone", ALICE))
    bot_chat.update(running=True, agent=None)
    bob = _WS("bob-desktop", BOB)
    assert "error" not in _relayed_submit(server, bob, "live-ops")
    queued = bot_chat.get("queued_prompt") or {}
    assert queued and queued.get("transport") is not bob
    # The running turn ends; its epilogue drains the queue (the turn itself is stubbed out).
    bot_chat["running"] = False
    monkeypatch.setattr(server, "_run_prompt_submit", lambda *a, **k: None, raising=False)
    try:
        server._drain_queued_prompt("r", "live-ops", bot_chat)
    except Exception:
        pass  # only the attach decision before the stubbed turn matters here
    assert not server._session_transport_contains(bot_chat, bob)
    assert BOB not in (bot_chat.get("attached_logins") or set())
    assert not [a for a in audits if a[0] == "session_foreign_attach"]
    fresh = _WS("bob-new", BOB)
    assert _rpc(server, fresh, "session.events.since", {"session_id": "live-ops", "last_seen": 0})["error"]["code"] == 4001
    req = _open_sudo("live-ops")
    assert _rpc(server, fresh, "request.answer", {"id": req.id, "result": {"value": "x"}})["error"]["code"] == 4033


def test_a_reused_runtime_id_does_not_let_an_earlier_sessions_people_replay(server):
    from tui_gateway import event_replay
    first = _session(server, "reused", _WS("alice-phone", ALICE))
    server._attach_session_transport(first, _WS("bob-phone", BOB))
    server._pop_session_by_id("reused")
    # The id comes back for someone else's session (token mode: nobody signed in), which is then dropped too.
    _session(server, "reused", _WS("token-peer", None), creator=None)
    event_replay.reset_replay_state()
    server._emit("message.delta", "reused", {"text": "new session"})
    server._pop_session_by_id("reused")
    for who in (ALICE, BOB):
        replay = _rpc(server, _WS("old", who), "session.events.since", {"session_id": "reused", "last_seen": 0})
        assert replay["error"]["code"] == 4001, who


def test_a_runtime_id_coming_back_live_forgets_its_earlier_people(server):
    first = _session(server, "again", _WS("alice-phone", ALICE))
    server._pop_session_by_id("again")
    assert "result" in _rpc(server, _WS("alice-new", ALICE), "session.events.since", {"session_id": "again", "last_seen": 0})
    server._forget_dropped_session("again")  # what every live registration does
    assert _rpc(server, _WS("alice-new", ALICE), "session.events.since",
                {"session_id": "again", "last_seen": 0})["error"]["code"] == 4001
    assert first
