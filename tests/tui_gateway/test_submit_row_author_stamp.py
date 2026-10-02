"""Contract test: the user row a submitted turn persists says who wrote it.

``messages`` has no author column and the live path has no author field — ``message.start`` is
contracted as an empty payload, and two clients on one session share a FanoutTransport, so a
client learns nothing about a turn it did not send. The one place an author can ride without a
schema or contract change is ``display_metadata``, the free-form JSON dict every row already has
and both the REST read and the WS history projection already forward.

So the row gets ``{"author": {"id": "<provider>:<user id>", "name": ...}}``, and only where the
gateway can prove it: the identity is the submitting connection's own WS-upgrade credential, the
same value the turn is attributed with. A turn nobody submitted — a crash continuation, a wake-up,
a cron run, a bot delivery — and a transport that names no login write nothing at all. An absent
author is a state every reader already handles; a guessed one is the defect being fixed, because a
client that assumes an unmarked row is its own paints a colleague's sentence as the reader's.
"""
import threading

import pytest

from hermes_state import SessionDB
from tui_gateway import row_author
from tui_gateway.transport import FanoutTransport, bind_transport, reset_transport
import tui_gateway.server as server


class _Peer:
    """A live client peer carrying a server-minted WS identity (see
    test_session_user_identity_shared_session.py)."""

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


class _StubAgent:
    """Its ``session_id`` is the session key: the turn epilogue re-syncs the key from the agent
    (compression rotates it), so a stub naming a different id would send a second turn's row to a
    session of its own."""

    def __init__(self, session_key):
        self._session_messages = []
        self._last_flushed_db_idx = 0
        self._db_flush_scan_prefix = []
        self.session_id = session_key

    def clear_interrupt(self):
        return None

    def run_conversation(self, prompt, conversation_history=None, stream_callback=None, **_kw):
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
def room(tmp_path, monkeypatch):
    """A live session wired for a real ``prompt.submit`` -> turn run against a real store.
    Returns ``(submit, user_rows, session)``; ``submit(peer, **params)`` sends as that connection."""
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("room", source="desktop")
    creator = _peer("oidc", "user-a", "Robin")
    session = {
        "agent": _StubAgent("room"), "attached_images": [], "cols": 80, "cwd": str(tmp_path),
        "history": [], "history_lock": threading.Lock(), "history_version": 0,
        "inflight_turn": None, "running": False, "session_key": "room",
        "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": creator,
        "auth_user_id": "oidc:user-a", "auth_user_name": "Robin",
    }
    monkeypatch.setattr(server, "_db", db, raising=False)
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_emit", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)

    def submit(peer, text="who am i", **params):
        token = bind_transport(peer)
        try:
            return server._methods["prompt.submit"](
                "rid", {"session_id": "sid", "text": text, **params})
        finally:
            reset_transport(token)

    def user_rows():
        return [
            row for row in db.get_messages_as_conversation("room", include_inactive=True)
            if row.get("role") == "user"
        ]

    yield submit, user_rows, session, creator
    db.close()


def _authors(user_rows):
    return [(row.get("display_metadata") or {}).get("author") for row in user_rows()]


# ---------------------------------------------------------------------------
# What is stamped
# ---------------------------------------------------------------------------

def test_a_signed_in_submit_stamps_the_submitting_connection(room):
    """The whole point: the row carries the id the gateway minted for that socket, plus the
    provider's verified display name as a convenience for a client with no directory of its own."""
    submit, user_rows, _session, creator = room

    assert submit(creator)["result"]["status"] == "streaming"
    assert _authors(user_rows) == [{"id": "oidc:user-a", "name": "Robin"}]


def test_the_id_keeps_the_provider_apart_from_the_login(room):
    """One spelling, ``<provider>:<user id>``, so a basic-auth ``user-a`` and an OIDC ``user-a``
    are two people to every reader."""
    submit, user_rows, session, _creator = room
    peer = _peer("basic", "user-a", "Robin")
    server._attach_session_transport(session, peer)  # another login must attach before it may submit

    submit(peer)
    assert _authors(user_rows) == [{"id": "basic:user-a", "name": "Robin"}]


def test_a_credential_without_a_name_stamps_the_id_alone(room):
    """``name`` is omitted rather than empty: a client falls back to its own directory or to the
    id, and an empty string would read as a person with no name."""
    submit, user_rows, session, _creator = room
    peer = _peer("oidc", "user-c")
    server._attach_session_transport(session, peer)

    submit(peer)
    assert _authors(user_rows) == [{"id": "oidc:user-c"}]


def test_the_second_person_on_a_shared_session_is_stamped_as_themselves(room):
    """The case the feature exists for. Both are attached, so the record's stamp names whoever
    opened the conversation and the slot is a fanout naming nobody — but the SUBMITTING socket
    still answers "who wrote this", which is why the turn is attributed to the joiner too."""
    submit, user_rows, session, creator = room
    joiner = _peer("oidc", "user-b", "Sam")
    server._attach_session_transport(session, joiner)
    assert session["auth_user_shared"] is True

    assert submit(joiner, text="mine")["result"]["status"] == "streaming"
    assert submit(creator, text="and mine")["result"]["status"] == "streaming"

    assert _authors(user_rows) == [
        {"id": "oidc:user-b", "name": "Sam"}, {"id": "oidc:user-a", "name": "Robin"}]


def test_an_existing_display_metadata_key_survives_the_merge(room):
    """Merged, never replaced: the author joins whatever the gateway already put on the row."""
    submit, user_rows, _session, creator = room

    submit(creator, display_kind="hidden", title_preview="a widget intent")
    row = user_rows()[0]
    assert row["display_metadata"]["title_preview"] == "a widget intent"
    assert row["display_metadata"]["author"] == {"id": "oidc:user-a", "name": "Robin"}


# ---------------------------------------------------------------------------
# What is not stamped
# ---------------------------------------------------------------------------

def test_a_transport_that_names_no_login_stamps_nothing(room):
    """stdio, the legacy token and the PTY child's server-internal credential name no person.
    The record's own stamp is not evidence that its owner typed this: nothing is written."""
    submit, user_rows, _session, _creator = room

    submit(None)
    assert _authors(user_rows) == [None]


def test_a_client_cannot_name_itself(room):
    """Server-minted end to end. ``display_metadata`` is not an accepted ``prompt.submit``
    parameter, and neither is an author under any other spelling."""
    submit, user_rows, session, _creator = room
    joiner = _peer("oidc", "user-b", "Sam")
    server._attach_session_transport(session, joiner)

    submit(joiner,
           display_metadata={"author": {"id": "oidc:user-a", "name": "Robin"}},
           author={"id": "oidc:user-a"}, user_id="oidc:user-a", user_name="Robin",
           auth_user_id="oidc:user-a", auth_user_name="Robin")

    assert _authors(user_rows) == [{"id": "oidc:user-b", "name": "Sam"}]


def test_a_turn_nobody_submitted_stamps_nothing(tmp_path, monkeypatch):
    """A crash continuation, a wake-up, a cron run and a bot delivery enter the turn directly with
    no submitter. They bind the unattributed sentinel, and an attached peer is proof someone is
    watching, never proof they asked — so such a turn's row names nobody."""
    assert row_author.with_row_author(None, None) is None
    # The sentinel needs no special case: it names no login, which is the only test there is.
    assert row_author.with_row_author(None, server._UNATTRIBUTED_TURN) is None
    assert row_author.with_row_author({"notification_category": "diagnostic"}, None) == {
        "notification_category": "diagnostic"}
    assert row_author.with_row_author(None, (None, "Robin")) is None
    assert row_author.with_row_author(None, ("", "Robin")) is None


def test_an_ambiguous_session_with_no_submitter_stamps_nothing(room):
    """The fork's fail-closed rule, unchanged: with two logins attached and a submitter that names
    none of them, there is nothing the record can prove either."""
    submit, user_rows, session, _creator = room
    server._attach_session_transport(session, _peer("oidc", "user-b", "Sam"))
    assert isinstance(session["transport"], FanoutTransport)

    submit(None)
    assert _authors(user_rows) == [None]


# ---------------------------------------------------------------------------
# What a client reads back
# ---------------------------------------------------------------------------

def test_the_author_survives_a_cold_read_of_the_transcript(room):
    """A re-hydration is the case a client cannot repair for itself: a locally inferred marker is
    gone after a reload, so the author has to come back off the row. It does, unchanged."""
    submit, user_rows, _session, creator = room

    submit(creator)
    assert _authors(user_rows) == [{"id": "oidc:user-a", "name": "Robin"}]
    # Second read of the same store: nothing in the projection strips it.
    assert _authors(user_rows) == [{"id": "oidc:user-a", "name": "Robin"}]


# ---------------------------------------------------------------------------
# The turn that writes its own row
# ---------------------------------------------------------------------------
#
# prompt.submit's row is the one a client reads, but two turns write their own instead: a prompt
# queued while the session was busy (it drains into _run_prompt_submit directly, with the
# submitter in its envelope), and a submit whose submit-time write failed. Both reach the durable
# row through ``persist_user_display_metadata``, so the author has to travel that way too.


class _MetadataSpyAgent(_StubAgent):
    def __init__(self, session_key):
        super().__init__(session_key)
        self.persisted_metadata = "not called"

    def run_conversation(self, prompt, conversation_history=None, stream_callback=None,
                         persist_user_message=None, persist_user_display_kind=None,
                         persist_user_display_metadata=None, **_kw):
        self.persisted_metadata = persist_user_display_metadata
        return {"final_response": "done"}


@pytest.fixture()
def turn_room(tmp_path, monkeypatch):
    """``_run_prompt_submit`` straight into a spy agent, the way a queued prompt drains."""
    agent = _MetadataSpyAgent("turn-room")
    session = {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path),
        "history": [], "history_lock": threading.Lock(), "history_version": 0,
        "inflight_turn": None, "running": False, "session_key": "turn-room",
        "show_reasoning": False, "slash_worker": None, "source": "desktop",
        "tool_progress_mode": "all", "transport": None,
    }
    monkeypatch.setattr(server, "_sessions", {"sid": session}, raising=False)
    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_emit", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_get_usage", lambda _agent: {})
    monkeypatch.setattr(server, "render_message", lambda *_a: "")
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(server, "_ensure_session_db_row", lambda _session: True)
    monkeypatch.setattr(server, "_record_turn_marker", lambda *_a, **_k: "turn-room")
    return session, agent


def test_a_turn_writing_its_own_row_carries_its_submitter(turn_room):
    """A drained queued prompt is attributed to the person who sent it, not to whoever the session
    was last used by. The drain passes the envelope's submitter as the row's author explicitly: the
    turn's scope identity alone authors nothing (test_replayed_turn_author.py)."""
    session, agent = turn_room

    assert server._run_prompt_submit(
        "rid", "sid", session, "later", turn_auth_user=("oidc:user-b", "Sam"),
        row_auth_user=("oidc:user-b", "Sam")) is not False
    assert agent.persisted_metadata == {"author": {"id": "oidc:user-b", "name": "Sam"}}


def test_a_turn_nobody_submitted_writes_no_author_on_its_own_row_either(turn_room):
    """An auto-continue, a wake-up, a cron run and a bot delivery arrive with no submitter."""
    session, agent = turn_room

    server._run_prompt_submit(
        "rid", "sid", session, "resume", display_kind="auto_continue",
        display_metadata={"notification_category": "diagnostic"})
    assert agent.persisted_metadata == {"notification_category": "diagnostic"}


# ---------------------------------------------------------------------------
# Does this gateway attribute at all
# ---------------------------------------------------------------------------
#
# The per-row rule above answers "who wrote THIS message". It cannot answer "does this gateway
# attribute messages at all", and a client needs that before it draws anything: it decides whether
# the transcript is laid out with room for a sender's name or exactly as it always was. Inferring
# it from the rows would be wrong in both directions -- false on an empty or pre-stamp
# conversation, and it would make the layout shift as authored rows arrived.


def test_the_build_advertises_that_it_attributes_messages():
    """``gateway.capabilities`` is where a client asks what this build enforces, and it gains one
    additive key. A client against a gateway without it reads no key and behaves as it does today."""
    capabilities = server._methods["gateway.capabilities"]("rid", {})["result"]

    assert capabilities["per_message_author"] is True
    assert capabilities["per_session_exclusive_submit"] is True  # the key beside it is untouched


def test_the_advertisement_is_sourced_from_the_module_that_writes_the_author(monkeypatch):
    """Not a literal in the handler and not config: the constant lives beside ``_with_row_author``,
    the one function every submitted turn goes through, so the advertisement cannot drift from the
    behaviour without that file changing. Answered by the RUNNING process, which is why a gateway
    carrying this code but not yet restarted answers without the key at all."""
    monkeypatch.setattr(row_author, "PER_MESSAGE_AUTHOR", False)

    assert server._methods["gateway.capabilities"]("rid", {})["result"]["per_message_author"] is False
