"""``session.interrupt_all``: stop every running turn the caller's login may stop, in one call.

Same per-session authorisation as ``session.interrupt`` (``_transport_may_access_session``), plus: a signed-in
connection stops only turns that are its own login's. Idle sessions are counted, other people's busy ones are
``not_allowed`` and never touched, cron runs live outside the registry and are left alone.
"""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import tui_gateway.server as server
from tui_gateway.transport import bind_transport, reset_transport

ALICE, BOB = "self_hosted:alice", "self_hosted:bob"


class _WS:
    def __init__(self, name: str, login: str | None, agent: dict | None = None):
        self.name = name
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id, **({"agent": agent} if agent else {})}

    def write(self, obj):
        return True

    def close(self):
        pass


@pytest.fixture
def homes(tmp_path, monkeypatch):
    launch, work = tmp_path / ".hermes", tmp_path / ".hermes" / "profiles" / "work"
    other = tmp_path / ".hermes" / "profiles" / "other"
    for home in (launch, work, other):
        home.mkdir(parents=True)
    names = {str(work): "work", str(other): "other"}
    monkeypatch.setattr(server, "_hermes_home", launch)
    monkeypatch.setattr(server, "_profile_home", lambda name: {"work": work, "other": other}.get((name or "").strip()))
    monkeypatch.setattr(server, "profile_name_for_home", lambda home: names.get(str(home)) if home else None)
    monkeypatch.setattr(server, "_current_profile_name", lambda: "default")
    monkeypatch.setattr(server, "_tts_stream_stop", lambda *a, **k: None)
    monkeypatch.setattr(server, "_clear_pending", lambda sid: None)
    yield SimpleHomes(launch, work, other)
    for sid in list(server._sessions):
        server._sessions.pop(sid, None)


class SimpleHomes:
    def __init__(self, launch: Path, work: Path, other: Path):
        self.launch, self.work, self.other = launch, work, other


def _session(sid, *, creator=ALICE, running=True, home=None, peers=(), source="hermie", turn_author=None, shared=False,
             title=None, turn_id=None):
    agent = MagicMock()
    agent.session_id = f"key-{sid}"
    session = {"session_key": f"key-{sid}", "transport": None, "history": [], "history_lock": threading.Lock(),
               "agent_ready": None, "auth_user_id": creator, "auth_user_name": "", "running": running,
               "agent": agent, "_run_thread": None, "queued_prompt": None, "source": source,
               "profile_home": str(home) if home else None, "pending_title": title,
               "created_at": 1.0, "last_active": 1.0}
    if turn_author or turn_id:
        metadata = {**({"author": {"id": turn_author, "name": ""}} if turn_author else {}),
                    **({"turn_id": turn_id} if turn_id else {})}
        session["inflight_turn"] = {"display_metadata": metadata}
    if turn_id:
        session["turn_id"] = turn_id
    if shared:
        session["auth_user_shared"] = True
    server._sessions[sid] = session
    for peer in peers:
        server._attach_session_transport(session, peer)
    return session


def _call(transport, params=None, method="session.interrupt_all"):
    token = bind_transport(transport)
    try:
        return server.handle_request({"id": 1, "method": method, "params": params or {}})
    finally:
        reset_transport(token)


def _stopped(session) -> bool:
    return bool(session.get("_turn_cancel_requested"))


def _ids(result):
    return sorted(row["session_id"] for row in result["stopped"])


# ── own turns, across profiles and clients ──────────────────────────────────────────────────────


def test_stops_every_own_turn_across_profiles_and_clients(homes):
    phone = _WS("phone", ALICE)
    here = _session("here", peers=(phone,), title="Here")
    work = _session("worked", home=homes.work, source="cron-ish", title="Work thing")   # started elsewhere, never attached here
    other = _session("elsewhere", home=homes.other)
    idle = _session("idle", running=False)
    response = _call(_WS("laptop", ALICE))
    assert "error" not in response, response
    result = response["result"]
    assert _ids(result) == ["elsewhere", "here", "worked"]
    assert result["already_idle"] == 1 and result["not_allowed"] == 0 and result["failed"] == 0
    rows = {row["session_id"]: row for row in result["stopped"]}
    assert rows["here"] == {"session_id": "here", "session_key": "key-here", "profile": "default", "title": "Here",
                            "source": "hermie"}
    assert rows["worked"]["profile"] == "work" and rows["worked"]["title"] == "Work thing"
    assert rows["worked"]["source"] == "cron-ish"
    assert rows["elsewhere"]["profile"] == "other" and rows["elsewhere"]["title"] is None
    assert all(_stopped(s) for s in (here, work, other)) and not _stopped(idle)
    assert not here["running"] and not work["running"]                       # the turn is released like a /stop
    assert here["agent"].method_calls                                       # the agent itself was told to stop


def test_the_profile_parameter_limits_the_stop(homes):
    mine, work, other = _session("mine"), _session("worked", home=homes.work), _session("elsewhere", home=homes.other)
    idle_work = _session("work-idle", home=homes.work, running=False)
    result = _call(_WS("laptop", ALICE), {"profile": "work"})["result"]
    assert _ids(result) == ["worked"] and result["already_idle"] == 1
    assert not _stopped(mine) and not _stopped(other) and not _stopped(idle_work)
    # The launch profile is a profile too: naming it stops the sessions that live in the launch home.
    assert _ids(_call(_WS("laptop", ALICE), {"profile": "default"})["result"]) == ["mine"]


def test_an_unknown_profile_stops_nothing(homes):
    session = _session("mine")
    monkey = server._profile_home

    def unknown(name):
        raise server.ProfileUnavailableError(f"Profile '{name}' does not exist.")
    server._profile_home = unknown
    try:
        assert _call(_WS("laptop", ALICE), {"profile": "ghost"})["error"]["code"] == 4064
    finally:
        server._profile_home = monkey
    assert not _stopped(session)


# ── never another person's ──────────────────────────────────────────────────────────────────────


def test_never_another_persons_turns(homes):
    mine = _session("mine", peers=(_WS("phone", ALICE),))
    bobs = _session("bobs", creator=BOB, peers=(_WS("bob-phone", BOB),))
    bobs_other_profile = _session("bobs-work", creator=BOB, home=homes.work)
    bobs_idle = _session("bobs-idle", creator=BOB, running=False)
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["mine"]
    assert result["not_allowed"] == 2                  # busy ones only: an idle session of Bob's tells Alice nothing
    assert result["already_idle"] == 0
    for session in (bobs, bobs_other_profile, bobs_idle):
        assert not _stopped(session) and "_turn_cancel_requested" not in session
        assert not session["agent"].method_calls
    # Bob stops his own in the same call shape; Alice's turn was already stopped and is not touched twice.
    assert _ids(_call(_WS("bob-laptop", BOB))["result"]) == ["bobs", "bobs-work"]
    assert _stopped(mine)


def test_in_a_shared_chat_each_person_stops_only_their_own_turn(homes):
    alice, bob = _WS("alice", ALICE), _WS("bob", BOB)
    alices_turn = _session("alices-turn", peers=(alice, bob), turn_author=ALICE, shared=True)
    bobs_turn = _session("bobs-turn", peers=(alice, bob), turn_author=BOB, shared=True)
    nobodys = _session("nobodys-turn", peers=(alice, bob), shared=True)       # a wake-up in a shared chat
    result = _call(_WS("alice-laptop", ALICE))["result"]
    assert _ids(result) == ["alices-turn"] and result["not_allowed"] == 2
    assert _stopped(alices_turn) and not _stopped(bobs_turn) and not _stopped(nobodys)
    assert _ids(_call(_WS("bob-laptop", BOB))["result"]) == ["bobs-turn"]


def test_a_turn_nobody_signed_in_sent_is_its_owners_in_an_unshared_session(homes):
    wake_up = _session("wake-up")                                                # crash continuation / wake-up
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["wake-up"] and _stopped(wake_up)


def test_a_connection_without_a_person_keeps_the_trust_domain_of_session_interrupt(homes):
    """Session-token mode and stdio carry no login: they reach every session, as ``session.interrupt`` lets them."""
    mine, bobs = _session("mine"), _session("bobs", creator=BOB)
    assert _ids(_call(_WS("token", None))["result"]) == ["bobs", "mine"]
    assert _stopped(mine) and _stopped(bobs)


def test_the_per_session_authorisation_is_the_one_session_interrupt_uses(homes, monkeypatch):
    """The rule is ``_transport_may_access_session`` itself, asked per session: refuse one there and it is not stopped."""
    asked: list[str] = []
    real = server._transport_may_access_session

    def spy(session, transport, *, sid=""):
        asked.append(sid)
        return sid != "denied" and real(session, transport, sid=sid)
    monkeypatch.setattr(server, "_transport_may_access_session", spy)
    fine, denied = _session("fine"), _session("denied")
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["fine"] and result["not_allowed"] == 1
    assert sorted(set(asked)) == ["denied", "fine"] and not _stopped(denied) and _stopped(fine)
    # And the single-session door agrees about who is shut out, for the same connection.
    other = _call(_WS("bob", BOB), {"session_id": "fine"}, method="session.interrupt")
    assert other["error"]["code"] == 4001


def test_an_mcp_agent_may_not_stop_everything(homes):
    session = _session("mine")
    agent = _WS("agent", ALICE, agent={"kind": "mcp", "client": "tool"})
    assert _call(agent)["error"]["code"] == 4033
    assert not _stopped(session)


# ── idle, races, isolation, failures ────────────────────────────────────────────────────────────


def test_idle_sessions_are_counted_and_untouched(homes):
    idle_a, idle_b = _session("a", running=False), _session("b", running=False, home=homes.work)
    result = _call(_WS("laptop", ALICE))["result"]
    assert result == {"stopped": [], "already_idle": 2, "not_allowed": 0, "failed": 0}
    assert "_turn_cancel_requested" not in idle_a and "_turn_cancel_requested" not in idle_b


def test_a_turn_that_ended_during_the_call_is_counted_idle(homes, monkeypatch):
    racer, steady = _session("racer"), _session("steady")

    def stop_tts(*a, **k):                       # runs after the registry pass, before the stops
        racer["running"] = False
    monkeypatch.setattr(server, "_tts_stream_stop", stop_tts)
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["steady"] and result["already_idle"] == 1
    assert "_turn_cancel_requested" not in racer and _stopped(steady)


def test_finalized_sessions_are_ignored(homes):
    gone = _session("gone")
    gone["_finalized"] = True
    assert _call(_WS("laptop", ALICE))["result"] == {"stopped": [], "already_idle": 0, "not_allowed": 0, "failed": 0}
    assert not _stopped(gone)


def test_a_stop_that_raises_is_counted_and_the_rest_still_stop(homes, monkeypatch):
    bad, good = _session("bad"), _session("good")
    real = server._interrupt_session_turn

    def flaky(sid, session, **kw):
        if sid == "bad":
            raise RuntimeError("compute host went away")
        return real(sid, session, **kw)
    monkeypatch.setattr(server, "_interrupt_session_turn", flaky)
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["good"] and result["failed"] == 1 and _stopped(good)


def test_an_isolated_turn_is_stopped_through_the_compute_host(homes, monkeypatch):
    isolated = _session("isolated", running=False)
    isolated["_compute_host_turn_id"] = "turn-1"                  # the turn runs in the child, the parent lags
    calls: list = []
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda session, cfg=None: session is isolated)
    monkeypatch.setattr(server, "_interrupt_session_turn", lambda sid, session, **kw: calls.append((sid, kw)))
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["isolated"]
    assert calls == [("isolated", {"request_id": "interrupt-all-1-isolated"})]


def test_the_stopped_turns_crash_marker_is_retired_like_a_stop(homes, monkeypatch):
    retired: list = []
    monkeypatch.setattr(server, "_retire_turn_marker", lambda session, *keys, keep_queued=True: retired.append(
        (session["session_key"], keys, keep_queued)))
    session = _session("marked")
    session["_active_turn_marker_key"] = "rotated-key"
    session["_shutdown_interrupt"] = True
    _call(_WS("laptop", ALICE))
    assert retired == [("key-marked", ("rotated-key",), False)] and "_shutdown_interrupt" not in session


# ── the turn that was checked is the turn that is stopped ───────────────────────────────────────


def _switch_turn(session, *, author, turn_id):
    """What the run thread does when one turn ends and the queued next one starts: a new in-flight record."""
    session["turn_id"] = turn_id
    session["inflight_turn"] = {"display_metadata": {"author": {"id": author, "name": ""}, "turn_id": turn_id}}


def test_a_turn_that_changed_owner_between_the_check_and_the_stop_is_not_stopped(homes, monkeypatch):
    """Alice's turn in the shared chat ends after the registry pass; Bob's queued prompt starts as the next turn.
    The stop was decided for Alice's turn, so Bob's is left alone."""
    alice, bob = _WS("alice", ALICE), _WS("bob", BOB)
    chat = _session("chat", peers=(alice, bob), turn_author=ALICE, shared=True, turn_id="turn-alice")
    monkeypatch.setattr(server, "_tts_stream_stop", lambda *a, **k: _switch_turn(chat, author=BOB, turn_id="turn-bob"))
    result = _call(_WS("alice-laptop", ALICE))["result"]
    assert result["stopped"] == [] and result["already_idle"] == 1 and result["failed"] == 0
    assert "_turn_cancel_requested" not in chat and chat["running"] is True
    assert not chat["agent"].method_calls                                   # Bob's agent loop was never told to stop


def test_the_callers_next_turn_is_not_the_one_that_was_checked(homes, monkeypatch):
    """Same owner, but another turn: the stop names the turn it decided on, not whatever runs by then."""
    chat = _session("chat", turn_author=ALICE, turn_id="turn-1")
    monkeypatch.setattr(server, "_tts_stream_stop", lambda *a, **k: _switch_turn(chat, author=ALICE, turn_id="turn-2"))
    result = _call(_WS("laptop", ALICE))["result"]
    assert result["stopped"] == [] and result["already_idle"] == 1 and "_turn_cancel_requested" not in chat


def test_the_check_and_the_stop_hold_the_turn_start_fence(homes, monkeypatch):
    """A turn start takes the fence before it clears the agent's interrupt flag, so the stop must hold it from its
    check to its interrupt, as an agent's bound ``session.interrupt`` does."""
    from tui_gateway.agent_guard import turn_start_fence
    chat = _session("chat", turn_author=ALICE, turn_id="turn-1")
    held: list[bool] = []
    real = server._interrupt_session_turn

    def spy(sid, session, **kw):
        held.append(turn_start_fence(session).locked())
        return real(sid, session, **kw)
    monkeypatch.setattr(server, "_interrupt_session_turn", spy)
    assert _ids(_call(_WS("laptop", ALICE))["result"]) == ["chat"]
    assert held == [True] and not turn_start_fence(chat).locked()


# ── a shared chat is stopped narrowly, the caller's own fully ───────────────────────────────────


@pytest.fixture
def delegations(monkeypatch):
    import tools.async_delegation as async_delegation
    ended: list = []
    monkeypatch.setattr(async_delegation, "interrupt_for_session", lambda **kw: ended.append(kw))
    return ended


def test_in_a_shared_chat_the_stop_keeps_the_others_queue_and_the_delegations(homes, delegations):
    alice, bob = _WS("alice", ALICE), _WS("bob", BOB)
    chat = _session("chat", peers=(alice, bob), turn_author=ALICE, shared=True, turn_id="turn-alice")
    alices_next = {"text": "alice-marker-next", "transport": alice}
    bobs_next = {"text": "bob-marker-next", "transport": bob}
    chat["queued_prompt"], chat["queued_prompts"] = alices_next, [bobs_next]
    chat["_queued_prompt_generation"] = 7
    result = _call(_WS("alice-laptop", ALICE))["result"]
    assert _ids(result) == ["chat"] and _stopped(chat)
    assert chat["queued_prompt"] is bobs_next and "queued_prompts" not in chat   # Bob's message still runs next
    assert chat["_queued_prompt_generation"] == 7                                # a drain in progress is not cancelled
    assert delegations == []                                                    # background work keeps running
    assert chat["agent"].method_calls                                           # Alice's turn itself was stopped


def test_in_the_callers_own_chat_the_stop_is_the_full_stop(homes, delegations):
    chat = _session("chat", turn_author=ALICE, turn_id="turn-1")
    chat["queued_prompt"] = {"text": "own-marker-next", "transport": _WS("phone", ALICE)}
    chat["queued_prompts"] = [{"text": "own-marker-later", "transport": None}]
    chat["_queued_prompt_generation"] = 7
    result = _call(_WS("laptop", ALICE))["result"]
    assert _ids(result) == ["chat"] and _stopped(chat)
    assert chat["queued_prompt"] is None and "queued_prompts" not in chat
    assert chat["_queued_prompt_generation"] == 8
    assert [call["origin_ui_session_id"] for call in delegations] == ["chat"]


# ── cron ────────────────────────────────────────────────────────────────────────────────────────


def test_cron_runs_are_outside_the_registry_and_left_alone(homes, monkeypatch):
    """A cron run executes in the scheduler's own pool and no job names the login that owns it: nothing to prove
    ownership with, so interrupt_all neither stops nor counts it."""
    import cron.scheduler as scheduler
    monkeypatch.setattr(scheduler, "mark_running_jobs_interrupted",
                        lambda *a, **k: pytest.fail("a cron run was interrupted"))
    assert scheduler.try_register_running_job("usage-test-job")
    try:
        session = _session("mine")
        result = _call(_WS("laptop", ALICE))["result"]
        assert _ids(result) == ["mine"] and _stopped(session)
        assert scheduler.is_job_running("usage-test-job")
    finally:
        scheduler.release_running_job("usage-test-job")


def test_the_method_is_in_the_contract(homes):
    assert _call(_WS("laptop", ALICE), {"surprise": 1})["error"]["code"] == 4000


def test_the_method_does_not_wait_behind_a_full_rpc_pool(homes, monkeypatch):
    """Every ``_pool`` worker busy with a slow handler: the stop still runs at once, on its own executor, and
    never on the socket reader (``dispatch`` returns None and the worker writes the answer)."""
    import queue
    from concurrent.futures import ThreadPoolExecutor
    from hermes_cli import backend_retirement

    assert "session.interrupt_all" in server._STOP_HANDLERS and "session.interrupt_all" not in server._LONG_HANDLERS
    monkeypatch.setattr(backend_retirement, "retirement", backend_retirement.RetirementFence())
    session = _session("mine")
    frames: queue.Queue = queue.Queue()
    laptop = _WS("laptop", ALICE)
    laptop.write = lambda frame: frames.put(frame) or True
    release = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as full:
        monkeypatch.setattr(server, "_pool", full)
        blocked = full.submit(release.wait, 10)
        try:
            assert server.dispatch({"jsonrpc": "2.0", "id": 9, "method": "session.interrupt_all", "params": {}},
                                   laptop) is None
            answer = frames.get(timeout=5)
            assert _ids(answer["result"]) == ["mine"] and _stopped(session) and not blocked.done()
        finally:
            release.set()


def test_a_turn_still_starting_up_is_stopped_once_its_ids_are_filled_in(homes, monkeypatch):
    # prompt.submit stamped the in-flight record (turn id T); the run thread sets session["turn_id"] only later,
    # here between the registry pass and the stop.
    chat = _session("chat", turn_author=ALICE)
    chat["inflight_turn"]["display_metadata"]["turn_id"] = "marker-turn"
    chat.pop("turn_id", None)
    monkeypatch.setattr(server, "_tts_stream_stop", lambda *a, **k: chat.__setitem__("turn_id", "marker-turn"))

    assert _ids(_call(_WS("laptop", ALICE))["result"]) == ["chat"]


def test_a_part_of_the_token_that_was_set_must_not_change():
    from tui_gateway.methods_session import _same_turn

    assert _same_turn(("t1", None, "t1"), (None, None, "t1"))
    assert not _same_turn(("t2", None, "t2"), ("t1", None, "t1"))
    assert not _same_turn((None, None, "t2"), (None, None, "t1"))
