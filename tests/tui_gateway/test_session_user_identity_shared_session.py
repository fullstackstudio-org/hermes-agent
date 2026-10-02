"""Contract test: a session two people share must not assert either of them.

``auth_user_id`` names the login the session record was CREATED under. Nothing
re-stamps it when a second window attaches — ``_note_foreign_login`` only logs,
and the transport slot becomes a FanoutTransport, which names no login at all.
So on a shared session the stamp is not an answer to "who is acting now": it is
whoever opened the conversation, and every reader of HERMES_SESSION_USER_ID /
_USER_NAME (kanban attribution, send_message, cron job args, the
terminal_tool_background watcher fields, per-person authorisation limits) takes
it as one anyway.

Empty is a state all of those already handle — an ungated gateway binds it on
every turn. Wrong is not. So the ambiguous session binds nothing.

One person with two windows is NOT ambiguous and must keep working.
"""
import threading
import types

import pytest

from gateway.session_context import (
    _UNSET,
    _VAR_MAP,
    get_session_env,
)
from tui_gateway.transport import FanoutTransport
import tui_gateway.server as server


@pytest.fixture(autouse=True)
def _reset_contextvars():
    """Reset all session contextvars to _UNSET between tests (see
    test_session_id_injection.py: tests share one thread context)."""
    yield
    for var in _VAR_MAP.values():
        var.set(_UNSET)


class _FakeAgent:
    def __init__(self, session_id):
        self.session_id = session_id


class _Peer:
    """A live client peer carrying a server-minted WS identity. Identity-hashed
    like the real WSTransport: the session keeps its peers in a viewers dict."""

    def __init__(self, auth_identity):
        self.auth_identity = auth_identity

    def write(self, obj):
        return True

    def close(self):
        return None


def _peer(provider, user_id, user_name=None):
    identity = {"provider": provider, "user_id": user_id}
    if user_name is not None:
        identity["user_name"] = user_name
    return _Peer(identity)


def _install_session(monkeypatch, *, session_key, transport=None, **extra):
    sess = {
        "session_key": session_key,
        "source": "desktop",
        "agent": _FakeAgent("20260921_cafebabe"),
        "cwd": "/home/user",
        **extra,
    }
    if transport is not None:
        sess["transport"] = transport
    monkeypatch.setattr(server, "_sessions", {session_key: sess}, raising=False)
    return sess


def _bound(session_key):
    tokens = server._set_session_context(session_key)
    try:
        return (
            get_session_env("HERMES_SESSION_USER_ID"),
            get_session_env("HERMES_SESSION_USER_ID_ALT"),
            get_session_env("HERMES_SESSION_USER_NAME"),
        )
    finally:
        server._clear_session_context(tokens)


def test_two_signed_in_members_on_one_session_bind_nothing(monkeypatch):
    """The reported failure. Two people are attached; the stamp names the one
    who opened the conversation, and a turn the other submitted would be
    attributed to them. Neither may be asserted."""
    creator, joiner = _peer("oidc", "user-a", "Robin"), _peer("oidc", "user-b", "Sam")
    _install_session(
        monkeypatch, session_key="skey-shared",
        transport=FanoutTransport(creator, joiner),
        auth_user_id="oidc:user-a", auth_user_name="Robin",
    )

    assert _bound("skey-shared") == ("", "", "")


def test_a_second_login_that_has_left_still_binds_nothing(monkeypatch):
    """Sticky: the second person leaving does not turn the creator's stamp back
    into proof of who acted, and the slot alone can no longer tell us apart."""
    creator = _peer("oidc", "user-a", "Robin")
    sess = _install_session(
        monkeypatch, session_key="skey-was-shared", transport=creator,
        auth_user_id="oidc:user-a", auth_user_name="Robin",
    )
    server._attach_session_transport(sess, _peer("oidc", "user-b", "Sam"))
    assert sess.get("auth_user_shared") is True
    server._detach_session_transport(sess, sess["transport"].transports()[1])

    assert _bound("skey-was-shared") == ("", "", "")


def test_one_person_in_two_windows_still_binds(monkeypatch):
    """A second window of the SAME login is not two people: the pop-out, the
    HUD and the phone all attach as the same person and attribution must keep
    working. This is the case the fanout arm used to break on."""
    first, second = _peer("oidc", "user-a", "Robin"), _peer("oidc", "user-a", "Robin")
    sess = _install_session(
        monkeypatch, session_key="skey-two-windows", transport=first,
        auth_user_id="oidc:user-a", auth_user_name="Robin",
    )
    server._attach_session_transport(sess, second)
    assert isinstance(sess["transport"], FanoutTransport)
    assert not sess.get("auth_user_shared")

    assert _bound("skey-two-windows") == ("oidc:user-a", "", "Robin")


def test_a_slot_that_names_no_login_still_binds_the_stamp(monkeypatch):
    """A parked session, and the compute-host child whose only peer is the host
    pipe, have no competing person attached — the stamp is the one identity in
    play and stays bindable. Fail closed means "when two could have acted", not
    "whenever no socket corroborates"."""
    _install_session(
        monkeypatch, session_key="skey-relayed", transport=types.SimpleNamespace(),
        auth_user_id="oidc:user-a", auth_user_name="Robin",
    )

    assert _bound("skey-relayed") == ("oidc:user-a", "", "Robin")


def test_a_foreign_login_attaching_marks_the_record(monkeypatch, caplog):
    """The mark is set where the foreign login is already noticed, so no attach
    path can share a session without recording that it is shared."""
    sess = _install_session(
        monkeypatch, session_key="skey-mark", transport=_peer("oidc", "user-a"),
        auth_user_id="oidc:user-a", auth_user_name="Robin",
    )

    with caplog.at_level("WARNING"):
        server._attach_session_transport(sess, _peer("basic", "user-b"))

    assert sess["auth_user_shared"] is True
    assert "a client logged in as" in caplog.text


def test_an_unattributable_slot_login_binds_nothing(monkeypatch):
    """Defence in depth for a peer that reached the slot without passing the
    attach path: a login attached that the stamp does not name is unresolved,
    whatever set the slot."""
    _install_session(
        monkeypatch, session_key="skey-unmarked",
        transport=FanoutTransport(_peer("oidc", "user-b", "Sam")),
        auth_user_id="oidc:user-a", auth_user_name="Robin",
    )

    assert _bound("skey-unmarked") == ("", "", "")


# ---------------------------------------------------------------------------
# Who submitted this turn
# ---------------------------------------------------------------------------
#
# Failing closed keeps a shared session from naming the wrong person, but it
# names nobody. The answer the gateway does have is the connection the prompt
# arrived on: WSTransport.auth_identity is minted at the WS upgrade from a
# verified ticket and no RPC param can reach it. prompt.submit runs on that
# connection's own context, so the identity is read there and carried into the
# turn -- the turn thread itself sees only session["transport"], which on a
# shared session is a FanoutTransport naming nobody.


class _RecordingAgent:
    """Fake agent that reads the bound identity from inside the running turn."""

    def __init__(self, seen: list):
        self._seen = seen
        self._session_messages = []
        self._last_flushed_db_idx = 0
        self._db_flush_scan_prefix = []
        self.session_id = "20260921_cafebabe"

    def clear_interrupt(self):
        return None

    def run_conversation(self, prompt, conversation_history=None, stream_callback=None, **_kw):
        self._seen.append((
            get_session_env("HERMES_SESSION_USER_ID"),
            get_session_env("HERMES_SESSION_USER_ID_ALT"),
            get_session_env("HERMES_SESSION_USER_NAME"),
        ))
        return {"final_response": "done"}


class _InlineThread:
    def __init__(self, target=None, daemon=None, args=(), kwargs=None, name=None):
        self._run = lambda: target(*args, **(kwargs or {}))

    def start(self):
        self._run()

    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None


@pytest.fixture()
def live_room(tmp_path, monkeypatch):
    """Factory for a live session wired for a real prompt.submit -> turn run: the
    agent records the identity bound inside the turn. Returns a ``build`` taking
    the record's own stamp and the peer that created it."""
    from hermes_state import SessionDB
    from tui_gateway.transport import bind_transport, reset_transport

    db = SessionDB(db_path=tmp_path / "state.db")
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_emit", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)

    def build(*, key, transport, auth_user_id, auth_user_name=""):
        db.create_session(key, source="desktop")
        seen: list = []
        session = {
            "agent": _RecordingAgent(seen), "attached_images": [], "cols": 80, "cwd": str(tmp_path),
            "history": [], "history_lock": threading.Lock(), "history_version": 0,
            "inflight_turn": None, "running": False, "session_key": key,
            "show_reasoning": False, "slash_worker": None, "source": "desktop",
            "tool_progress_mode": "all", "transport": transport,
            "auth_user_id": auth_user_id, "auth_user_name": auth_user_name,
        }
        monkeypatch.setattr(server, "_sessions", {key: session}, raising=False)

        def submit(peer, **params):
            token = bind_transport(peer)
            try:
                return server._methods["prompt.submit"](
                    "rid", {"session_id": key, "text": "who am i", **params})
            finally:
                reset_transport(token)

        return submit, session, seen

    yield build
    db.close()


@pytest.fixture()
def shared_room(live_room):
    """A live session two signed-in people are attached to."""
    creator, joiner = _peer("oidc", "user-a", "Robin"), _peer("oidc", "user-b", "Sam")
    submit, session, seen = live_room(
        key="shared-room", transport=creator,
        auth_user_id="oidc:user-a", auth_user_name="Robin")
    # The joiner opens the same conversation: the slot becomes a fanout naming nobody.
    server._attach_session_transport(session, joiner)
    assert session["auth_user_shared"] is True
    return submit, session, creator, joiner, seen


def test_the_turn_names_the_member_who_submitted_it(shared_room):
    """The reported scenario, end to end: both are attached, the JOINER sends
    the prompt, and the turn runs as the joiner -- not as whoever opened the
    conversation and not as nobody."""
    submit, _session, _creator, joiner, seen = shared_room

    assert submit(joiner)["result"]["status"] == "streaming"
    assert seen == [("oidc:user-b", "", "Sam")]


def test_the_creator_submitting_the_same_session_is_still_the_creator(shared_room):
    """It follows the submitting connection, not the newest one: the same shared
    session, a prompt from the person who opened it, runs as them."""
    submit, _session, creator, _joiner, seen = shared_room

    submit(creator)
    assert seen == [("oidc:user-a", "", "Robin")]


def test_a_client_cannot_name_itself_in_the_prompt(shared_room):
    """Server-minted end to end. The identity comes from the connection's own
    upgrade credential; params are the client's words and reach nothing."""
    submit, _session, _creator, joiner, seen = shared_room

    submit(joiner, user_id="oidc:user-a", user_name="Robin",
           auth_user_id="oidc:user-a", auth_user_name="Robin")
    assert seen == [("oidc:user-b", "", "Sam")]


def test_a_submitter_with_no_login_falls_back_to_the_record(shared_room):
    """stdio, the legacy token and the PTY child's internal credential name no
    person. They must not clear a single-user session's identity, and on this
    shared one there is still nothing to assert."""
    submit, _session, _creator, _joiner, seen = shared_room

    submit(None)
    assert seen == [("", "", "")]


def test_a_queued_prompt_keeps_its_own_submitter(monkeypatch):
    """A prompt sent while the session is busy runs a turn of its own later. It
    carries the connection that sent it, the way it already carries the socket
    the reply streams to -- the drain must not attribute it to whoever the
    session was last used by."""
    session = {"queued_prompt": None, "queued_prompts": []}
    server._enqueue_prompt(session, "later", _peer("oidc", "user-b"),
                           turn_auth_user=("oidc:user-b", "Sam"))

    assert session["queued_prompt"]["turn_auth_user"] == ("oidc:user-b", "Sam")


def test_two_members_queued_prompts_are_not_merged(monkeypatch):
    """Consecutive text-only prompts share one envelope so the model reads them
    as one message. Two PEOPLE's prompts may not: the merged turn could only be
    attributed to one of them."""
    session = {"queued_prompt": None, "queued_prompts": []}
    server._enqueue_prompt(session, "mine", _peer("oidc", "user-a"),
                           turn_auth_user=("oidc:user-a", "Robin"))
    server._enqueue_prompt(session, "and mine", _peer("oidc", "user-b"),
                           turn_auth_user=("oidc:user-b", "Sam"))

    assert session["queued_prompt"]["text"] == "mine"
    assert [q["text"] for q in session["queued_prompts"]] == ["and mine"]




# ---------------------------------------------------------------------------
# A turn the gateway itself dispatched asks for nobody
# ---------------------------------------------------------------------------
#
# prompt.submit is also the composer's choke point for turns no human typed: a
# bot DM relayed into somebody's open Bot Chat (methods_bot_relay) and a hosted
# room turn (hosted_room_server_rpc) both call it in process. Those requests
# arrive on whatever socket carried the RPC -- a person's open desktop, relaying
# somebody else's message -- so the connection is evidence of who RELAYED, never
# of who asked. Two lines before the identity is read, the handler already
# refuses to let a client name an author; taking the login off that same socket
# would put the relayer's name on the turn instead.


def test_a_relayed_turn_is_not_attributed_to_the_relaying_socket(live_room):
    """A bot DM relayed through one person's desktop into a Bot Chat runs as the
    bot author the gateway stamped -- and as no human at all."""
    from tools.bot_relay import DeliveryAuthor

    bot_chat = _Peer(None)  # a Bot Chat's own peer names no login
    submit, session, seen = live_room(
        key="bot-chat", transport=bot_chat, auth_user_id=None)
    relayer = _peer("oidc", "user-a", "Robin")

    # bot_relay.deliver makes this submit as the gateway's own in-process dispatch.
    with server._internal_dispatch():
        response = submit(relayer, _turn_author=DeliveryAuthor({"id": "bot:coder", "name": "coder", "is_bot": True}))

    assert "error" not in response
    assert seen == [("", "", "")]


def test_a_relayed_turn_into_a_shared_chat_names_nobody_either(shared_room):
    """The same on a chat two people already share: the relay must not resolve
    the ambiguity in favour of whichever of them happened to relay."""
    from tools.bot_relay import DeliveryAuthor

    submit, _session, _creator, joiner, seen = shared_room

    submit(joiner, _turn_author=DeliveryAuthor({"id": "bot:coder", "name": "coder", "is_bot": True}))
    assert seen == [("", "", "")]


def test_every_in_process_param_withholds_the_socket_identity(monkeypatch):
    """Structural, not a list to maintain: the in-process params are declared in
    the wire contract under an underscore alias, so the prefix is what is tested.
    A future internal caller inherits this the day it declares its param."""
    from tui_gateway.transport import bind_transport, reset_transport

    token = bind_transport(_peer("oidc", "user-a", "Robin"))
    try:
        # A person typing is attributed to their connection.
        assert server._submit_auth_user({"session_id": "s", "text": "hi"}) == ("oidc:user-a", "Robin")
        # Every param the gateway injects in process withholds it.
        for name in ("_turn_author", "_hosted_task", "_hosted_terminal_callback", "_some_future_internal"):
            assert server._submit_auth_user({"session_id": "s", "text": "hi", name: object()}) is None
        # A key that is merely absent or None is not an internal dispatch.
        assert server._submit_auth_user({"session_id": "s", "_turn_author": None}) == ("oidc:user-a", "Robin")
    finally:
        reset_transport(token)


def test_a_turn_nobody_submitted_is_not_attributed_to_a_watching_peer(live_room):
    """The mirror of the sentinel. A crash continuation, a wake-up or a cron run
    enters the turn path directly with no submitter. The session's own slot must
    not stand in for one: an attached peer is proof somebody is watching, never
    proof they asked."""
    watcher = _peer("oidc", "user-a", "Robin")
    _submit, session, seen = live_room(
        key="unattributed", transport=watcher, auth_user_id=None)

    server._run_prompt_submit("rid", "unattributed", session, "a turn nobody asked for")

    assert seen == [("", "", "")]


def test_a_drained_prompt_reaches_the_turn_as_its_own_submitter(live_room):
    """End to end for the queue: a prompt sent while the session was busy runs a
    turn of its own later, and the envelope's identity is what that turn binds --
    not the record's stamp and not whoever the session was last used by."""
    creator, joiner = _peer("oidc", "user-a", "Robin"), _peer("oidc", "user-b", "Sam")
    _submit, session, seen = live_room(
        key="drained", transport=creator, auth_user_id="oidc:user-a", auth_user_name="Robin")
    server._attach_session_transport(session, joiner)
    server._enqueue_prompt(session, "mine to run", joiner, turn_auth_user=("oidc:user-b", "Sam"))

    assert server._drain_queued_prompt("rid", "drained", session) is True
    assert seen == [("oidc:user-b", "", "Sam")]


def test_the_turn_identity_does_not_outlive_the_turn(live_room, monkeypatch):
    """Whatever the turn bound is gone by the time anything else runs in its
    context -- the follow-up dispatch and the notification drain both do."""
    after: list = []
    monkeypatch.setattr(server, "_run_post_turn_followups",
                        lambda *_a, **_k: after.append(server._turn_auth_user.get()))
    creator = _peer("oidc", "user-a", "Robin")
    _submit, session, seen = live_room(
        key="cleared", transport=creator, auth_user_id="oidc:user-a", auth_user_name="Robin")

    server._run_prompt_submit("rid", "cleared", session, "hi", turn_auth_user=("oidc:user-a", "Robin"))

    assert seen == [("oidc:user-a", "", "Robin")]
    assert after == [None]


def test_a_failure_before_the_turn_leaves_nothing_bound(live_room, monkeypatch):
    """The marker write touches the filesystem and can raise, and this thread goes
    on to drain notifications and dispatch follow-ups. Nothing the turn binds may
    survive it -- least of all the transport, which ``_acting_auth_user`` reads
    when no turn is in scope, so a leaked one silently names that socket's owner
    for every later piece of work.

    Observed with the per-turn context copy removed (``_start_session_work``
    normally runs the turn under ``ctx_bound``, which confines a leak to that
    copy): that copy is what keeps this from being a live bug today, and it is one
    patch away from not being there."""
    from tui_gateway.transport import current_transport

    monkeypatch.setattr(server, "_start_session_work",
                        lambda target, *, name, session=None: target() or True)
    monkeypatch.setattr(server, "_record_turn_marker",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("marker store is read-only")))
    creator = _peer("oidc", "user-a", "Robin")
    _submit, session, _seen = live_room(
        key="raising", transport=creator, auth_user_id="oidc:user-a", auth_user_name="Robin")

    with pytest.raises(OSError):
        server._run_prompt_submit("rid", "raising", session, "hi", turn_auth_user=("oidc:user-a", "Robin"))

    assert server._turn_auth_user.get() is None
    assert current_transport() is None
    assert server._current_runtime_session_record.get() is None


# ---------------------------------------------------------------------------
# An isolated turn reaches the same two answers
# ---------------------------------------------------------------------------
#
# With process isolation on, the turn runs in a child built from the frame alone.
# The child cannot resolve either question itself: its only peer is the host
# pipe, and its copy of the record reads as one unshared login whatever the
# gateway saw. So the frame carries both -- the conversation's own login, which
# the child builds the agent with (memory), and who asked for this one turn
# (attribution) -- and they are deliberately different fields.


def _isolated_session(monkeypatch, **extra):
    return _install_session(
        monkeypatch, session_key="skey-isolated",
        transport=FanoutTransport(_peer("oidc", "user-a"), _peer("oidc", "user-b")),
        auth_user_id="oidc:user-a", auth_user_name="Robin", auth_user_shared=True,
        history=[], history_version=0, history_lock=threading.Lock(), cols=80, **extra)


def test_the_frame_separates_the_conversation_from_who_asked(monkeypatch):
    """The record's stamp stays ``auth_user_id`` so the child scopes memory where
    an inline turn scopes it; the submitter travels beside it."""
    sess = _isolated_session(monkeypatch)

    frame = server._compute_host_turn_frame(
        "rid", "sid", sess, "who am i", turn_auth_user=("oidc:user-b", "Sam"))

    assert (frame["auth_user_id"], frame["auth_user_name"]) == ("oidc:user-a", "Robin")
    assert (frame["turn_auth_user_id"], frame["turn_auth_user_name"]) == ("oidc:user-b", "Sam")


def test_the_frame_resolves_who_asked_on_the_gateway_not_in_the_child(monkeypatch):
    """Without a submitter the gateway resolves it HERE, where the record is known
    to be shared, and ships the empty answer. The child must not re-derive it: its
    own copy of the record would read as an unshared login and name the creator."""
    sess = _isolated_session(monkeypatch)

    frame = server._compute_host_turn_frame("rid", "sid", sess, "who am i")

    assert (frame["auth_user_id"], frame["auth_user_name"]) == ("oidc:user-a", "Robin")
    assert frame["turn_auth_user_id"] == ""


def test_the_child_binds_the_answer_the_frame_carries():
    """The child's turn is attributed to the frame's resolved answer -- including
    the empty one -- while a frame that predates the keys keeps the old behaviour
    of falling back to the record."""
    from tui_gateway import compute_host

    assert compute_host._frame_turn_auth_user({"turn_auth_user_id": "oidc:user-b",
                                              "turn_auth_user_name": "Sam"}) == ("oidc:user-b", "Sam")
    # Present but empty: "nobody", which must bind empty rather than consult the record.
    assert compute_host._frame_turn_auth_user({"turn_auth_user_id": "", "turn_auth_user_name": ""}) == (None, "")
    # Absent: an older parent, and the child keeps its previous behaviour.
    assert compute_host._frame_turn_auth_user({"auth_user_id": "oidc:user-a"}) is None
