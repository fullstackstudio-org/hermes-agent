"""The per-turn guide for the Hermie blocks (plan rich-answers T2).

* The text: one paragraph per block in a fixed order, under 2,500 characters for all of them, and every number
  it states is the one in ``contract/markup`` (read from the schemas here, never retyped).
* The carriers: the guide follows the SUBMITTING connection's ``markup`` through every way a turn starts -- the
  inline turn, the busy queue (and its restart journal), the compute-host frame and child, a redirect queued in
  the build window -- and is staged for that turn only. A connection that advertised nothing, an internal dispatch
  (a relayed bot DM), a ``/goal`` continuation and a session of another surface get none.

Every payload is a harmless marker.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

import pytest

from agent.interrupt_control import InterruptControlMixin
from agent.prompt_additions import with_system_additions
from hermes_state import SessionDB
from tui_gateway import client_markup, hermie_markup
from tui_gateway.transport import bind_transport, reset_transport
import tui_gateway.server as server

MARKUP = Path(__file__).resolve().parents[2] / "contract" / "markup"
ROBIN = ("oidc:user-a", "Robin")
SAM = ("oidc:user-b", "Sam")
CARDS = hermie_markup.GUIDE["cards"]
CHART = hermie_markup.GUIDE["chart"]
ALERTS = hermie_markup.GUIDE["alerts"]


# ── the text ────────────────────────────────────────────────────────────────────────────────────


def test_one_paragraph_per_name_in_a_fixed_order():
    assert hermie_markup.guide_for([]) == ""
    assert hermie_markup.guide_for(["timeline", "facts"]) == ""
    assert hermie_markup.guide_for(["cards"]) == f"{hermie_markup.INTRO}\n\n{CARDS}"
    assert hermie_markup.guide_for(["alerts", "cards", "chart"]) == "\n\n".join(
        [hermie_markup.INTRO, CHART, CARDS, ALERTS])


def test_the_whole_guide_stays_bounded():
    assert len(hermie_markup.guide_for(client_markup.VOCABULARY)) <= hermie_markup.MAX_GUIDE_CHARS == 2_500


def test_only_a_hermie_chat_carries_it():
    assert hermie_markup.turn_guide("hermie", ["cards"]) == hermie_markup.guide_for(["cards"])
    for source in ("telegram", "desktop", "tui", "slack", "", None):
        assert hermie_markup.turn_guide(source, ["cards", "chart", "alerts"]) == ""


def test_every_paragraph_says_to_say_it_in_words_and_names_its_fence():
    assert "say in words what it shows too; not every reader sees it drawn" in hermie_markup.INTRO
    assert "language hermie-chart" in CHART and "language hermie-cards" in CARDS


def _schema(name):
    return json.loads((MARKUP / name).read_text(encoding="utf-8"))


def test_the_chart_numbers_are_the_schemas():
    schema = _schema("chart.schema.json")
    props = schema["properties"]
    [pie_rule] = [rule for rule in schema["allOf"] if rule["if"]["properties"]["type"] == {"const": "pie"}]
    pie = pie_rule["then"]["properties"]
    series = schema["$defs"]["series"]["properties"]
    assert f"At most {props['series']['maxItems']} series and {props['x']['maxItems']} points" in CHART
    assert pie["series"]["maxItems"] == 1
    assert f"a pie has one series and at most {pie['x']['maxItems']} slices" in CHART
    [label] = {props["x"]["items"]["anyOf"][0]["maxLength"], series["name"]["maxLength"]}
    assert f"Names at most {label} characters" in CHART
    assert f"title at most {props['title']['maxLength']}, unit at most {props['unit']['maxLength']}" in CHART
    assert all(f'"{kind}"' in CHART for kind in props["type"]["enum"])
    values = series["values"]["items"]
    assert -values["minimum"] == values["maximum"] == float("1e15") and "numbers within \u00b11e15" in CHART
    assert props["x"]["uniqueItems"] is True and "categories and series names are unique once trimmed" in CHART
    assert "A pie's values are not negative and at least one is above zero" in CHART
    assert set(props) == {"type", "title", "unit", "x", "series"} and set(series) == {"name", "values"}
    assert all(f'"{key}"' in CHART for key in (*props, *series))


def test_the_cards_numbers_are_the_schemas():
    schema = _schema("cards.schema.json")
    props = schema["properties"]
    card = schema["$defs"]["card"]["properties"]
    tags = card["tags"]
    assert f"{props['cards']['minItems']} to {props['cards']['maxItems']} cards" in CARDS
    assert f"Card title {card['title']['minLength']} to {card['title']['maxLength']} characters" in CARDS
    assert f"subtitle at most {card['subtitle']['maxLength']}" in CARDS
    assert f"block title at most {props['title']['maxLength']}" in CARDS
    assert tags["uniqueItems"] is True
    assert (f"at most {tags['maxItems']} different tags of {tags['items']['minLength']} to "
            f"{tags['items']['maxLength']} characters") in CARDS
    assert f"next at most {card['next']['maxLength']}" in CARDS
    for value in (*props["layout"]["enum"], *props["connector"]["enum"]):
        assert value is None or f'"{value}"' in CARDS
    # With a grid there is no connector and no label on one (the schema's grid branch).
    grid = schema["then"]["properties"]
    assert schema["if"]["properties"]["layout"] == {"const": "grid"}
    assert grid["connector"] == {"type": "null"} and grid["cards"]["items"]["properties"]["next"]["maxLength"] == 0
    assert "connector and next only in a stack" in CARDS
    assert set(props) == {"title", "layout", "connector", "cards"}
    assert set(card) == {"title", "subtitle", "icon", "tags", "highlight", "next"}
    assert all(f'"{key}"' in CARDS for key in (*props, *card))


def test_the_examples_limits_are_the_schemas_and_the_guides():
    """``examples.json`` states the caps once more for the client validators: the three must agree."""
    limits = _schema("examples.json")["limits"]
    schema = _schema("cards.schema.json")
    props, card = schema["properties"], schema["$defs"]["card"]["properties"]
    assert limits == {
        "maxSourceBytes": 16384,
        "minCards": props["cards"]["minItems"], "maxCards": props["cards"]["maxItems"],
        "maxTitleLength": props["title"]["maxLength"], "maxCardTitleLength": card["title"]["maxLength"],
        "maxSubtitleLength": card["subtitle"]["maxLength"], "maxTags": card["tags"]["maxItems"],
        "maxTagLength": card["tags"]["items"]["maxLength"], "maxNextLength": card["next"]["maxLength"],
        "maxIconLength": card["icon"]["maxLength"],
    }
    assert "16384 bytes" in schema["description"] and "16384 bytes" in _schema("chart.schema.json")["description"]


def test_the_guides_icons_come_from_the_vocabulary():
    icons = _schema("icons.json")
    vocabulary = {entry["name"] for entry in icons["icons"]}
    match = re.search(r"icon is one word such as ([a-z, ]+?) or ([a-z]+); another word draws a plain glyph", CARDS)
    assert match, CARDS
    named = [name.strip() for name in match.group(1).split(",")] + [match.group(2)]
    assert set(named) <= vocabulary and 5 <= len(named) <= 12, named
    assert icons["generic"]["name"] == "generic" and "generic" not in vocabulary


def test_every_number_in_the_guide_comes_from_a_schema():
    numbers = set()
    for name in ("chart.schema.json", "cards.schema.json"):
        text = (MARKUP / name).read_text(encoding="utf-8")
        numbers |= {int(n) for n in re.findall(r'"(?:minItems|maxItems|minLength|maxLength)": (\d+)', text)}
    stated = {int(n) for n in re.findall(r"\b\d+\b", hermie_markup.guide_for(client_markup.VOCABULARY))}
    assert stated <= numbers, stated - numbers


def test_the_markup_contract_is_pinned():
    import hashlib
    lines = (MARKUP / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert {line.split("  ", 1)[1] for line in lines} == {
        "README.md", "cards.schema.json", "chart.schema.json", "examples.json", "icons.json"}
    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((MARKUP / name).read_bytes()).hexdigest() == digest, name


def test_the_alert_markers_in_the_guide_are_the_contracts():
    alerts = _schema("examples.json")["alerts"]
    kinds = {case["alert"] for case in alerts if case.get("alert")}
    assert kinds == {"note", "tip", "important", "warning", "caution"}
    assert all(f"[!{kind.upper()}]" in ALERTS for kind in kinds)


# ── the carriers ────────────────────────────────────────────────────────────────────────────────


class _Peer:
    def __init__(self, user, markup=None):
        self.auth_identity = {"provider": "oidc", "user_id": user[0].split(":", 1)[1], "user_name": user[1]}
        if markup is not None:
            client_markup.advertise(self, markup)

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
    """A scripted turn that records the system message its request would carry."""

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
        self.ephemeral_system_prompt = None
        self.turns = []
        self.script = []

    def _strip_think_blocks(self, text):
        return text

    def clear_interrupt(self, *_a, **_k):
        self._interrupt_requested = False
        return True

    def interrupt(self, *_a, **_k):
        self._interrupt_requested = True
        return True

    def run_conversation(self, message, conversation_history=None, stream_callback=None, **_kw):
        self.turns.append({"text": message, "system": with_system_additions("CACHED", self),
                           "markup": client_markup.TURN_MARKUP.get()})
        if self.script:
            self.script.pop(0)()
        return {"final_response": "done"}


def _room(tmp_path, monkeypatch, source="hermie"):
    db = SessionDB(db_path=tmp_path / "state.db")
    db.create_session("room", source=source)
    peers = {"phone": _Peer(ROBIN, ["cards"]), "laptop": _Peer(ROBIN), "sam": _Peer(SAM, ["chart", "alerts"])}
    agent = _Agent("room")
    session = {
        "agent": agent, "attached_images": [], "cols": 80, "cwd": str(tmp_path),
        "history": [], "history_lock": threading.Lock(), "history_version": 0,
        "inflight_turn": None, "running": False, "session_key": "room",
        "show_reasoning": False, "slash_worker": None, "source": source,
        "tool_progress_mode": "all", "transport": peers["phone"],
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
    server._attach_session_transport(session, peers["laptop"])
    server._attach_session_transport(session, peers["sam"])

    def call(who, method, **params):
        token = bind_transport(peers[who])
        try:
            return server._methods[method]("rid", {"session_id": "sid", **params})
        finally:
            reset_transport(token)

    return agent, call, peers, db


@pytest.fixture()
def room(tmp_path, monkeypatch):
    with client_markup._lock:
        client_markup._accepted.clear()
    agent, call, peers, db = _room(tmp_path, monkeypatch)
    yield agent, call, peers
    db.close()
    with client_markup._lock:
        client_markup._accepted.clear()


def _turn(agent, text):
    [turn] = [t for t in agent.turns if t["text"] == text]
    return turn


def test_a_cards_client_gets_the_cards_paragraph_and_not_the_charts(room):
    agent, call, _peers = room
    assert call("phone", "prompt.submit", text="marker one")["result"]["status"] == "streaming"
    turn = _turn(agent, "marker one")
    assert turn["markup"] == frozenset({"cards"})
    assert turn["system"] == "CACHED\n\n" + hermie_markup.guide_for(["cards"])
    assert CHART not in turn["system"]
    # Staged for the turn only.
    assert getattr(agent, "_turn_system_addition") == "" and client_markup.TURN_MARKUP.get() == frozenset()


def test_a_connection_that_advertised_nothing_gets_nothing(room):
    agent, call, _peers = room
    call("laptop", "prompt.submit", text="marker old build")
    assert _turn(agent, "marker old build")["system"] == "CACHED"


def test_each_submitter_in_a_shared_chat_gets_its_own_set(room):
    agent, call, _peers = room
    call("phone", "prompt.submit", text="marker phone")
    call("laptop", "prompt.submit", text="marker laptop")
    call("sam", "prompt.submit", text="marker sam")
    assert _turn(agent, "marker phone")["markup"] == frozenset({"cards"})
    assert _turn(agent, "marker laptop")["system"] == "CACHED"
    sam = _turn(agent, "marker sam")["system"]
    assert CHART in sam and ALERTS in sam and CARDS not in sam


def test_the_personality_prompt_stays_first_and_untouched(room):
    agent, call, _peers = room
    agent.ephemeral_system_prompt = "MARKER PERSONA"
    call("phone", "prompt.submit", text="marker persona")
    assert _turn(agent, "marker persona")["system"] == "CACHED\n\nMARKER PERSONA\n\n" + hermie_markup.guide_for(
        ["cards"])
    assert agent.ephemeral_system_prompt == "MARKER PERSONA"


def test_a_queued_prompt_keeps_its_senders_set_and_never_merges_with_anothers(room, monkeypatch):
    monkeypatch.setattr(server, "_load_busy_input_mode", lambda: "queue")
    agent, call, _peers = room

    def queue_three():
        for who, text in (("phone", "marker queued phone"), ("phone", "marker queued phone two"),
                          ("laptop", "marker queued laptop")):
            assert call(who, "prompt.submit", text=text)["result"]["status"] == "queued"

    agent.script = [queue_three]
    call("laptop", "prompt.submit", text="marker first")
    assert [t["text"] for t in agent.turns] == [
        "marker first", "marker queued phone\n\nmarker queued phone two", "marker queued laptop"]
    merged = _turn(agent, "marker queued phone\n\nmarker queued phone two")
    assert merged["markup"] == frozenset({"cards"}) and CARDS in merged["system"]
    assert _turn(agent, "marker queued laptop")["system"] == "CACHED"


def test_the_restart_journal_keeps_the_set():
    from tui_gateway.shutdown_drain import _journal_queue_envelope, _restore_journaled_queue
    entry = _journal_queue_envelope({"text": "marker", "transport": object(), "turn_auth_user": ROBIN,
                                     "turn_markup": ["cards"]})
    assert entry == {"text": "marker", "turn_auth_user": list(ROBIN), "turn_markup": ["cards"]}
    [restored], _dropped = _restore_journaled_queue([json.loads(json.dumps(entry))])
    assert restored["turn_markup"] == ["cards"]


def test_a_journaled_prompt_drains_with_its_set_rechecked(room):
    agent, _call, _peers = room
    agent.session["queued_prompt"] = {"text": "marker journaled", "transport": None, "turn_auth_user": ROBIN,
                                      "turn_markup": ["cards", "bogus"]}
    assert server._drain_queued_prompt("rid", "sid", agent.session) is True
    assert _turn(agent, "marker journaled")["markup"] == frozenset({"cards"})
    agent.session["queued_prompt"] = {"text": "marker junk", "transport": None, "turn_markup": "cards"}
    server._drain_queued_prompt("rid", "sid", agent.session)
    assert _turn(agent, "marker junk")["system"] == "CACHED"


def test_the_compute_host_frame_carries_the_set_and_the_child_binds_it(room):
    from tui_gateway.compute_host import _frame_turn_markup
    agent, _call, _peers = room
    frame = server._compute_host_turn_frame("rid", "sid", agent.session, "marker child", turn_auth_user=ROBIN,
                                            turn_markup=frozenset({"cards", "chart"}))
    assert frame["turn_markup"] == ["cards", "chart"]
    assert _frame_turn_markup(frame) == frozenset({"cards", "chart"})
    assert "turn_markup" not in server._compute_host_turn_frame("rid", "sid", agent.session, "marker")
    assert _frame_turn_markup({"turn_markup": "cards"}) == frozenset()
    assert _frame_turn_markup({}) == frozenset()
    server._run_prompt_submit("rid", "sid", agent.session, "marker child", turn_auth_user=ROBIN,
                              turn_markup=_frame_turn_markup(frame))
    assert CARDS in _turn(agent, "marker child")["system"]


def test_an_isolated_submit_hands_the_set_to_the_compute_host(room, monkeypatch):
    agent, call, _peers = room
    sent = []
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda *_a, **_k: True)
    monkeypatch.setattr(server, "_submit_prompt_to_compute_host",
                        lambda _rid, _sid, _session, text, **kw: sent.append((text, kw)) or {"result": {}})
    call("phone", "prompt.submit", text="marker isolated")
    [(text, kw)] = sent
    assert kw["turn_markup"] == frozenset({"cards"})


def test_an_internal_dispatch_names_no_set(room):
    """A relayed bot DM reaches prompt.submit on whatever socket carried it (here the phone's): it is not the
    phone's submit, so it gets no guide."""
    from tools.bot_relay import DeliveryAuthor
    agent, call, _peers = room
    call("phone", "prompt.submit", text="marker relayed",
         _turn_author=DeliveryAuthor({"id": "bot:marker", "name": "marker", "is_bot": True}))
    assert _turn(agent, "marker relayed")["system"] == "CACHED"


def _goal_once(monkeypatch, agent, after):
    """A ``/goal`` continuation after the turn whose text is *after*, once."""
    fired = []

    def followup(_sid, _session, _result, _status, _raw):
        if agent.turns[-1]["text"] == after and not fired:
            fired.append(after)
            return f"marker continue {after}"
        return None
    monkeypatch.setattr(server, "_goal_followup_after_turn", followup)


def test_a_goal_continuation_keeps_its_persons_guide_so_the_system_message_never_flips(room, monkeypatch):
    agent, call, _peers = room
    _goal_once(monkeypatch, agent, "marker goal")
    call("phone", "prompt.submit", text="marker goal")
    call("phone", "prompt.submit", text="marker after")
    person, continuation, again = (_turn(agent, t)["system"]
                                   for t in ("marker goal", "marker continue marker goal", "marker after"))
    assert CARDS in person and person == continuation == again


def test_a_continuation_follows_the_connection_live(room, monkeypatch):
    agent, call, peers = room
    session = agent.session
    call("phone", "prompt.submit", text="marker first")
    server._run_prompt_submit("rid", "sid", session, "marker wake one")  # nobody submitted it
    assert CARDS in _turn(agent, "marker wake one")["system"]
    client_markup.advertise(peers["phone"], ["chart"])  # the app now advertises another set
    server._run_prompt_submit("rid", "sid", session, "marker wake two")
    assert CHART in _turn(agent, "marker wake two")["system"] and CARDS not in _turn(agent, "marker wake two")["system"]
    client_markup.forget(peers["phone"])  # it disconnected
    server._run_prompt_submit("rid", "sid", session, "marker wake three")
    assert _turn(agent, "marker wake three")["system"] == "CACHED"


def test_a_continuation_after_an_old_clients_turn_carries_nothing(room):
    agent, call, _peers = room
    call("phone", "prompt.submit", text="marker phone")
    call("laptop", "prompt.submit", text="marker laptop")
    server._run_prompt_submit("rid", "sid", agent.session, "marker wake")
    assert _turn(agent, "marker wake")["system"] == "CACHED"


def test_an_mcp_agents_turn_and_its_continuation_carry_nothing(room, monkeypatch):
    """Accepted cost (lead decision): an agent's turn in the person's chat is told nothing about blocks, nor is
    what continues it, even though the person's phone that advertised cards is attached."""
    agent, call, peers = room
    bridge = _Peer(ROBIN)
    bridge.auth_identity["agent"] = {"kind": "mcp", "client": "Marker agent", "grant": "grant-g1"}
    server._attach_session_transport(agent.session, bridge)
    token = bind_transport(bridge)
    try:
        assert server._methods["prompt.submit"]("rid", {"session_id": "sid", "text": "marker agent"})[
            "result"]["status"] == "streaming"
    finally:
        reset_transport(token)
    assert _turn(agent, "marker agent")["system"] == "CACHED"
    server._run_prompt_submit("rid", "sid", agent.session, "marker agent continue")
    assert _turn(agent, "marker agent continue")["system"] == "CACHED"


def test_a_relayed_prompt_and_its_continuation_carry_nothing_but_the_persons_keep_theirs(room, monkeypatch):
    from tools.bot_relay import DeliveryAuthor
    agent, call, _peers = room
    call("phone", "prompt.submit", text="marker phone")
    _goal_once(monkeypatch, agent, "marker relayed")
    call("phone", "prompt.submit", text="marker relayed",
         _turn_author=DeliveryAuthor({"id": "bot:marker", "name": "marker", "is_bot": True}))
    assert _turn(agent, "marker relayed")["system"] == "CACHED"
    assert _turn(agent, "marker continue marker relayed")["system"] == "CACHED"
    # The person's own unsubmitted turn afterwards (a wake-up) follows their connection again.
    server._run_prompt_submit("rid", "sid", agent.session, "marker wake")
    assert CARDS in _turn(agent, "marker wake")["system"]


def test_a_bot_dm_delivered_to_the_live_session_carries_no_guide(room, monkeypatch, tmp_path):
    """``session_notifications._poll_bot_live_delivery_once``: person turn, then a bot's DM answered back to the
    bot (no guide: its reply would be raw JSON there), its /goal continuation (none), then the person's own next
    continuation (the guide again)."""
    import types
    import tools.bot_live_delivery as mailbox
    agent, call, _peers = room
    session = agent.session
    session["active_session_lease"] = types.SimpleNamespace(lease_id="lease", released=False)
    owner = {"lease_id": "lease", "live_session_id": "sid", "session_id": "room"}
    pending = [{"id": "dm-1", "message": "marker dm", "author": {"id": "bot:coder", "name": "coder", "is_bot": True}}]
    receipts = []
    monkeypatch.setattr(mailbox, "has_mailbox", lambda home: True)
    monkeypatch.setattr(mailbox, "find_canonical_live_owner", lambda home: owner)
    monkeypatch.setattr(mailbox, "claim_pending_delivery", lambda home, pinned: pending.pop(0) if pending else None)
    monkeypatch.setattr(mailbox, "complete_delivery", lambda *a, **k: receipts.append(k))
    monkeypatch.setattr(server, "_session_home", lambda _session: tmp_path)
    call("phone", "prompt.submit", text="marker phone")
    _goal_once(monkeypatch, agent, "marker dm")
    assert server._poll_bot_live_delivery_once("sid", session) is True
    assert receipts and receipts[0]["status"] == "settled"
    assert _turn(agent, "marker dm")["system"] == "CACHED"
    assert _turn(agent, "marker continue marker dm")["system"] == "CACHED"
    server._run_prompt_submit("rid", "sid", session, "marker wake after dm")
    assert CARDS in _turn(agent, "marker wake after dm")["system"]


def test_an_isolated_relayed_turn_is_unguided_and_leaves_the_childs_names_alone(room):
    from tui_gateway.compute_host import _frame_turn_markup
    agent, call, _peers = room
    call("phone", "prompt.submit", text="marker phone")
    relay = server._compute_host_turn_frame("rid", "sid", agent.session, "marker relay",
                                            turn_markup=client_markup.UNGUIDED)
    assert relay.get("turn_unguided") is True and "turn_markup" not in relay
    person = server._compute_host_turn_frame("rid", "sid", agent.session, "marker person")
    assert "turn_unguided" not in person and person["turn_markup"] == ["cards"]
    child = dict(agent.session)
    client_markup.remember_frame_names(child, _frame_turn_markup(person))
    # The child keeps these names through an unguided frame (test_compute_host_sources).
    assert client_markup.resolve_turn_markup(child, None) == frozenset({"cards"})


def test_a_relayed_prompt_queued_behind_a_turn_stays_unguided(room, monkeypatch):
    agent, _call, _peers = room
    agent.session["queued_prompt"] = {"text": "marker queued relay", "transport": None,
                                      "turn_author": {"id": "bot:marker", "name": "marker"},
                                      "turn_markup": ["cards"]}
    client_markup.remember_source(agent.session, _peers["phone"])
    assert server._drain_queued_prompt("rid", "sid", agent.session) is True
    assert _turn(agent, "marker queued relay")["system"] == "CACHED"
    assert agent.session["_markup_source"] is _peers["phone"]


def test_an_isolated_continuation_is_resolved_by_the_gateway_and_kept_by_the_child(room):
    from tui_gateway.compute_host import _frame_turn_markup
    agent, call, _peers = room
    call("phone", "prompt.submit", text="marker phone")
    frame = server._compute_host_turn_frame("rid", "sid", agent.session, "marker child")  # nobody submitted it
    assert frame["turn_markup"] == ["cards"]
    child = dict(agent.session)
    client_markup.remember_frame_names(child, _frame_turn_markup(frame))
    assert client_markup.resolve_turn_markup(child, None) == frozenset({"cards"})
    assert client_markup.resolve_turn_markup(child, frozenset()) == frozenset()


def test_a_redirect_queued_in_the_build_window_keeps_the_set(room):
    agent, call, _peers = room
    agent.session["running"] = True
    agent.session["agent"] = None
    try:
        assert call("phone", "session.redirect", text="marker redirect")["result"]["status"] == "queued"
    finally:
        agent.session["agent"] = agent
        agent.session["running"] = False
    assert agent.session["queued_prompt"]["turn_markup"] == ["cards"]


def test_a_telegram_or_desktop_session_gets_nothing(tmp_path, monkeypatch):
    with client_markup._lock:
        client_markup._accepted.clear()
    for source in ("telegram", "desktop"):
        directory = tmp_path / source
        directory.mkdir()
        agent, call, _peers, db = _room(directory, monkeypatch, source=source)
        call("phone", "prompt.submit", text=f"marker {source}")
        assert _turn(agent, f"marker {source}")["system"] == "CACHED"
        db.close()
    with client_markup._lock:
        client_markup._accepted.clear()
