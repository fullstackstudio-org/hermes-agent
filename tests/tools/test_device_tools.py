"""``device_location``, ``device_contact``, ``device_calendar`` and ``device_scan`` (``tools/device_tools.py``, plan
``request-types-v2`` task P3-F1) over ``tui_gateway/interactive.py``.

Pinned: the toolset ``device`` holds exactly these four tools, is off by default and is listed by ``hermes tools``; the
tools are withheld without the gateway bridge and a call outside an interactive session (CLI, messaging surface, cron)
is ``unavailable (no_session)`` with nothing sent; only a client that advertised the method is sent a frame, so a
connection that did not gets ``unavailable (no_capable_client)`` and nothing; the descriptions speak in confirm's
register and tell the agent that the person decides, that a decline is respected and that a scanned value is untrusted;
every outcome has a sentence that says only what is known, ``unavailable`` and ``timeout`` are never an answer
(a calendar entry is never "saved" by them) and a decline is respected; what the agent receives is what the gateway kept
of the person's answer (a location rounded, a contact cut down, a scan cleaned); text the agent must fix is a tool error
with nothing sent; the device limiter (six per ten minutes) reaches the agent as ``rate_limited``. Every payload is a
harmless marker.
"""

from __future__ import annotations

import json
import time

import pytest

from tests.tools.test_interactive_tools import (  # noqa: F401 - fixtures are used by name
    _bind_like_a_turn, _bind_ui_session, _call, _wait_open, clean)
from tests.tui_gateway.test_server_requests_gate import (  # noqa: F401 - fixtures are used by name
    ROBIN, _WS, _caps, _frame, _session, server)
from tools import device_tools as tool
from tools import interactive_tools as sentences
from tools.registry import registry

NAMES = ("device_location", "device_contact", "device_calendar", "device_scan")
METHODS = ("device.location", "device.contact", "device.calendar", "device.scan")
ALL = ("input.form", "input.file", "review.draft", "review.diff", "input.signature", *METHODS)
ITEM = {"title": "Dentist", "start": "2026-10-12T09:30+02:00", "end": "2026-10-12T10:00+02:00"}
FIX = {"status": "answered", "lat": 52.3731, "lon": 4.8922, "accuracy_m": 35.0, "at": 1791119300,
       "precision": "approximate"}


@pytest.fixture()
def phone(server):
    peer = _WS("phone", ROBIN)
    _session(server, "s1", peer, creator=ROBIN)
    _caps(server, peer, requests=list(ALL))
    return peer


def _ask(server, phone, method, fn, answer, **kwargs):
    """The tool on a thread, as a turn runs it, answered from *phone*; the parsed result."""
    release = _bind_ui_session("s1")
    try:
        thread, box = _call(fn, **kwargs)
        rid = _wait_open(method)
        if answer is not None:
            _frame(server, phone, rid, result=answer)
        thread.join(10)
    finally:
        release()
    return json.loads(box["r"])


# ── registration ────────────────────────────────────────────────────────────────────────────────


def test_the_tools_are_registered_in_their_own_toolset_and_withheld_without_the_bridge():
    from toolsets import TOOLSETS
    assert TOOLSETS["device"]["tools"] == list(NAMES)
    assert "ask_signature" in TOOLSETS["interactive"]["tools"] and not set(NAMES) & set(TOOLSETS["interactive"]["tools"])
    saved = tool._bridge
    try:
        tool.set_bridge(None)
        assert tool.available() is False
        for name in NAMES:
            entry = registry.get_entry(name)
            assert entry is not None and entry.toolset == "device" and entry.check_fn() is False
        tool.set_bridge(lambda *a, **k: None)
        assert all(registry.get_entry(name).check_fn() is True for name in NAMES)
    finally:
        tool.set_bridge(saved)


def test_the_gateway_installs_the_bridge(server):
    assert tool.available()  # importing the gateway installed it


def test_the_toolset_is_off_by_default_and_listed_in_hermes_tools():
    from hermes_cli.tools_config import _DEFAULT_OFF_TOOLSETS, CONFIGURABLE_TOOLSETS, _get_platform_tools
    assert "device" in _DEFAULT_OFF_TOOLSETS
    row = [row for row in CONFIGURABLE_TOOLSETS if row[0] == "device"]
    assert row and all(name in row[0][2] for name in NAMES)
    for platform in ("cli", "telegram"):
        assert "device" not in _get_platform_tools({}, platform)
    assert "device" in _get_platform_tools({"platform_toolsets": {"cli": ["hermes-cli", "device"]}}, "cli")


# ── the schemas ─────────────────────────────────────────────────────────────────────────────────


def test_the_schemas_and_descriptions():
    schemas = {s["name"]: s for s in (tool.DEVICE_LOCATION_SCHEMA, tool.DEVICE_CONTACT_SCHEMA,
                                      tool.DEVICE_CALENDAR_SCHEMA, tool.DEVICE_SCAN_SCHEMA)}
    assert tuple(schemas) == NAMES
    required = {name: set(s["parameters"]["required"]) for name, s in schemas.items()}
    assert required == {"device_location": {"summary"}, "device_contact": {"summary", "fields"},
                        "device_calendar": {"summary", "kind", "item"}, "device_scan": {"summary"}}
    props = {name: set(s["parameters"]["properties"]) for name, s in schemas.items()}
    assert props == {"device_location": {"summary", "precision", "title"},
                     "device_contact": {"summary", "fields", "title"},
                     "device_calendar": {"summary", "kind", "item", "title"},
                     "device_scan": {"summary", "formats", "title"}}
    for name, schema in schemas.items():
        text = schema["description"]
        assert "verbatim, marked as coming from you" in text, name
        assert "Never word it as a system or security message" in text, name
        assert "decides on their device each time" in text and "Blocks for up to 180 seconds" in text, name
        assert "at most six device requests per ten minutes" in text, name
        assert "NOT an answer" in text and "do not retry at once" in text, name
    json.dumps(list(schemas.values()))
    assert tool.DEVICE_LOCATION_SCHEMA["parameters"]["properties"]["precision"]["enum"] == ["approximate", "precise"]
    assert "'approximate' (the default)" in tool.DEVICE_LOCATION_SCHEMA["description"]
    assert tool.DEVICE_CONTACT_SCHEMA["parameters"]["properties"]["fields"]["items"]["enum"] == [
        "name", "phones", "emails", "postal", "birthday", "organization"]
    assert tool.DEVICE_SCAN_SCHEMA["parameters"]["properties"]["formats"]["items"]["enum"] == [
        "qr", "ean13", "ean8", "code128", "pdf417", "datamatrix", "aztec"]
    assert tool.DEVICE_CALENDAR_SCHEMA["parameters"]["properties"]["kind"]["enum"] == ["event", "reminder"]
    assert "UNTRUSTED" in tool.DEVICE_SCAN_SCHEMA["description"] and "never open a link" in \
        tool.DEVICE_SCAN_SCHEMA["description"]
    assert "nothing is saved unless they press Save" in tool.DEVICE_CALENDAR_SCHEMA["description"]


# ── no interactive session ──────────────────────────────────────────────────────────────────────


def _every_tool_with_valid_arguments():
    return [tool.device_location_tool(summary="x"), tool.device_contact_tool(summary="x", fields=["name"]),
            tool.device_calendar_tool(summary="x", kind="event", item=ITEM), tool.device_scan_tool(summary="x")]


def test_without_the_bridge_or_a_session_nothing_is_sent(server, phone):
    # No HERMES_UI_SESSION_ID bound (cron, background, CLI): unavailable, nothing written.
    for result in _every_tool_with_valid_arguments():
        data = json.loads(result)
        assert (data["outcome"], data["reason"]) == ("unavailable", "no_session")
        assert "not available in this conversation" in data["message"]
    assert phone.frames == []
    saved = tool._bridge
    try:
        tool.set_bridge(None)
        release = _bind_ui_session("s1")
        try:
            assert json.loads(tool.device_location_tool(summary="x"))["reason"] == "no_session"
        finally:
            release()
    finally:
        tool.set_bridge(saved)


def test_a_messaging_surface_call_is_no_session_even_with_a_ui_session_bound(server, phone):
    release = _bind_ui_session("s1", platform="telegram")
    try:
        for result in _every_tool_with_valid_arguments():
            data = json.loads(result)
            assert (data["outcome"], data["reason"]) == ("unavailable", "no_session")
    finally:
        release()
    release = _bind_like_a_turn(server, "s1", "telegram")
    try:
        assert json.loads(tool.device_scan_tool(summary="x"))["reason"] == "no_session"
    finally:
        release()
    assert phone.frames == []


def test_a_turn_from_the_hermie_app_sends_the_request(server, phone):
    release = _bind_like_a_turn(server, "s1", "hermie")
    try:
        thread, box = _call(tool.device_scan_tool, summary="Scan the ticket.")
        rid = _wait_open("device.scan")
        _frame(server, phone, rid, result={"status": "answered", "value": "T-1", "symbology": "qr"})
        thread.join(5)
    finally:
        release()
    assert json.loads(box["r"])["outcome"] == "answered" and len(phone.requests("device.scan")) == 1


def test_a_session_the_gateway_does_not_host_is_no_session():
    release = _bind_ui_session("not-hosted")
    try:
        data = json.loads(tool.device_location_tool(summary="x"))
    finally:
        release()
    assert (data["outcome"], data["reason"]) == ("unavailable", "no_session")


# ── the sentences ───────────────────────────────────────────────────────────────────────────────

REASONS = ("no_capable_client", "write_failed", "error_response", "no_session", "no_acting_user", "already_pending",
           "rate_limited", "turn_isolation", "cancelled:interrupted", "cancelled:session_closed",
           "cancelled:shutdown", "too_many_attempts", "cannot_show:no_camera", "cannot_show:no_microphone",
           "cannot_show:not_supported_on_device", "cannot_show:permission_denied", "cannot_show:location_unavailable",
           "cannot_show:unsupported_version", "cannot_show:shutting_down", "cannot_show:declined", "something_new", "")


@pytest.mark.parametrize("method", (*METHODS, "input.signature"))
@pytest.mark.parametrize("reason", REASONS)
def test_unavailable_is_never_an_answer_and_says_what_to_do(method, reason):
    sentence = sentences._sentence(method, {"outcome": "unavailable", "reason": reason})
    if reason == "cannot_show:declined":  # the person knows: the agent is told to respect it instead
        assert "tell the person" not in sentence.lower() and "do not ask again at once" in sentence
    else:
        assert "tell the person" in sentence.lower() and "do not retry at once" in sentence
    assert ("This is not a" in sentence) and ("do not" in sentence)
    for banned in ("The person shared", "The person saved", "The person scanned", "The person signed"):
        assert banned not in sentence


def test_what_is_not_an_answer_is_said_per_request():
    unavailable = {"outcome": "unavailable", "reason": "no_capable_client"}
    assert "do not guess or look up where they are" in sentences._sentence("device.location", unavailable)
    assert "do not guess or look up their contact details" in sentences._sentence("device.contact", unavailable)
    assert "do not say the entry was saved" in sentences._sentence("device.calendar", unavailable)
    assert "do not guess what the code says" in sentences._sentence("device.scan", unavailable)


@pytest.mark.parametrize("method, words", [
    ("device.location", "the Hermie app on a device that can share its location"),
    ("device.contact", "the Hermie app on a phone or tablet"),
    ("device.calendar", "the Hermie app on an iPhone, iPad or Mac"),
    ("device.scan", "the Hermie app on a phone or iPad"),
    ("input.signature", "a Hermie app that can show a signature pad")])
def test_no_capable_client_names_the_kind_of_app(method, words):
    sentence = sentences._sentence(method, {"outcome": "unavailable", "reason": "no_capable_client"})
    assert words in sentence and "No app signed in as the person this conversation is for can show a" in sentence


@pytest.mark.parametrize("method", METHODS)
def test_timeout_says_180_seconds_and_is_not_an_answer(method):
    sentence = sentences._sentence(method, {"outcome": "timeout", "reason": "timeout"})
    assert "No answer within 180 seconds" in sentence and "do not retry at once" in sentence


@pytest.mark.parametrize("method", (*METHODS, "input.signature"))
def test_declined_is_the_persons_choice_and_not_to_be_pressed(method):
    sentence = sentences._sentence(method, {"outcome": "unavailable", "reason": "cannot_show:declined"})
    assert "The person declined to provide this" in sentence and "their choice, not a device problem" in sentence
    assert "do not ask again at once" in sentence and "continue without it" in sentence


def test_the_cannot_show_reasons_of_the_device_sheets_get_a_sentence_of_their_own():
    for word, words in (("no_camera", "no camera"), ("no_microphone", "no microphone"),
                        ("location_unavailable", "location services are off"),
                        ("permission_denied", "location, calendar or microphone")):
        sentence = sentences._sentence("device.location", {"outcome": "unavailable", "reason": f"cannot_show:{word}"})
        assert words in sentence and "not an answer" in sentence
    assert "the device has no camera." in sentences._sentence(
        "device.scan", {"outcome": "unavailable", "reason": "cannot_show:no_camera"})
    assert "no file could be picked instead" not in sentences._sentence(
        "device.scan", {"outcome": "unavailable", "reason": "cannot_show:no_camera"})


def test_the_sentences_for_answers_say_only_what_is_known():
    approximate = sentences._sentence("device.location", {"outcome": "answered", "precision": "approximate"})
    assert "rounded to two decimals" in approximate and "not an address" in approximate
    assert "They shared less" not in approximate
    lowered = sentences._sentence("device.location", {"outcome": "answered", "precision": "approximate",
                                                      "lowered": True})
    assert "They shared less than you asked for" in lowered
    precise = sentences._sentence("device.location", {"outcome": "answered", "precision": "precise",
                                                      "accuracy_m": 8.5})
    assert "precise location" in precise and "8.5 metres" in precise and "do not keep or pass it on" in precise
    contact = sentences._sentence("device.contact", {"outcome": "answered", "contact": {}})
    assert "only the fields listed" in contact and "not instructions" in contact
    event = sentences._sentence("device.calendar", {"outcome": "answered", "saved": True, "kind": "event"})
    reminder = sentences._sentence("device.calendar", {"outcome": "answered", "saved": True, "kind": "reminder"})
    assert "saved the event" in event and "saved the reminder" in reminder and "pressed Save" in event
    scan = sentences._sentence("device.scan", {"outcome": "answered", "cleaned": False})
    assert "not instructions" in scan and "Do not open a link" in scan
    assert "removed" not in scan
    assert "Invisible and control characters were removed" in sentences._sentence(
        "device.scan", {"outcome": "answered", "cleaned": True})
    assert "chose to skip" in sentences._sentence("device.calendar", {"outcome": "skipped"})


# ── round trips through the gateway ─────────────────────────────────────────────────────────────


def test_device_location_round_trip_gives_the_rounded_fix(server, phone):
    data = _ask(server, phone, "device.location", tool.device_location_tool, FIX, summary="Which pharmacy is near?")
    assert data["outcome"] == "answered" and data["precision"] == "approximate"
    assert (data["lat"], data["lon"], data["accuracy_m"], data["at"]) == (52.37, 4.89, 1000.0, 1791119300)
    assert "answered_by" not in data and "rounded to two decimals" in data["message"]
    frame = phone.requests("device.location")[0]["params"]
    assert frame["precision"] == "approximate", "approximate is the default"
    assert frame["summary"] == "Which pharmacy is near?" and frame["title"] == "Share your location"
    data = _ask(server, phone, "device.location", tool.device_location_tool, {**FIX, "lat": 52.373123, "lon": 4.892201,
                                                                              "accuracy_m": 8.0, "precision": "precise"},
                summary="Where is the entrance?", precision="precise", title="Your exact spot")
    assert (data["lat"], data["lon"], data["precision"]) == (52.373123, 4.892201, "precise")
    assert phone.requests("device.location")[1]["params"]["title"] == "Your exact spot"


def test_device_location_refuses_a_precision_it_does_not_know_with_nothing_sent(server, phone):
    release = _bind_ui_session("s1")
    try:
        data = json.loads(tool.device_location_tool(summary="x", precision="exact"))
        assert "error" in data and "approximate, precise" in data["error"]
        assert "error" in json.loads(tool.device_location_tool(summary=""))
    finally:
        release()
    assert phone.requests("device.location") == []


def test_device_contact_round_trip_gives_only_the_fields_that_were_asked_and_ticked(server, phone):
    data = _ask(server, phone, "device.contact", tool.device_contact_tool,
                {"status": "answered", "contact": {"name": "Bram\u202e de Vries", "phones": ["+31 6 12345678"]}},
                summary="Pick the plumber.", fields=json.dumps(["name", "phones"]))
    assert data["outcome"] == "answered"
    assert data["contact"] == {"name": "Bram de Vries", "phones": ["+31 6 12345678"]}
    assert phone.requests("device.contact")[0]["params"]["fields"] == ["name", "phones"]
    data = _ask(server, phone, "device.contact", tool.device_contact_tool,
                {"status": "answered", "contact": {"emails": ["b@example.com"]}}, summary="Pick Bram.",
                fields="emails")      # one field named as a bare word
    assert data["contact"] == {"emails": ["b@example.com"]}


def test_device_contact_refuses_what_the_agent_must_fix_with_nothing_sent(server, phone):
    release = _bind_ui_session("s1")
    try:
        for fields in ([], ["name", "name"], ["nickname"], None, "[not json", ["name", 3]):
            assert "error" in json.loads(tool.device_contact_tool(summary="x", fields=fields)), fields
    finally:
        release()
    assert phone.requests("device.contact") == []


def test_device_calendar_round_trip_says_saved_and_nothing_more(server, phone):
    data = _ask(server, phone, "device.calendar", tool.device_calendar_tool, {"status": "done"},
                summary="Put the dentist in your calendar.", kind="event", item=json.dumps(ITEM))
    assert (data["outcome"], data["saved"], data["kind"]) == ("answered", True, "event")
    assert "saved the event" in data["message"] and set(data) == {"outcome", "saved", "kind", "message"}
    frame = phone.requests("device.calendar")[0]["params"]
    assert frame["item"] == ITEM and frame["title"] == "Add to your calendar"
    data = _ask(server, phone, "device.calendar", tool.device_calendar_tool, {"status": "skipped"},
                summary="Remind you.", kind="reminder", item={"title": "Passport", "start": ITEM["start"]})
    assert data["outcome"] == "skipped" and "chose to skip" in data["message"]
    assert phone.requests("device.calendar")[1]["params"]["title"] == "Add a reminder"


def test_device_calendar_refuses_what_the_agent_must_fix_with_nothing_sent(server, phone):
    release = _bind_ui_session("s1")
    try:
        for kwargs, words in (({"kind": "task", "item": ITEM}, "kind must be one of"),
                              ({"kind": "event", "item": {}}, "item.title is required"),
                              ({"kind": "event", "item": "{not json"}, "item must be JSON"),
                              ({"kind": "event", "item": {**ITEM, "end": "2026-10-12T09:00+02:00"}},
                               "end is before start"),
                              ({"kind": "reminder", "item": ITEM}, "a reminder has one time"),
                              ({"kind": "event", "item": {"title": "x", "url": "javascript:alert(1)"}}, "item: url"),
                              ({"kind": "event", "item": {**ITEM, "attendees": ["a"]}}, "not part of a calendar item")):
            error = json.loads(tool.device_calendar_tool(summary="x", **kwargs))["error"]
            assert words in error, (kwargs, error)
    finally:
        release()
    assert phone.requests("device.calendar") == []


def test_device_scan_round_trip_gives_cleaned_untrusted_text(server, phone):
    data = _ask(server, phone, "device.scan", tool.device_scan_tool,
                {"status": "answered", "value": "https://exa\u200bmple.com/\x1b[0m", "symbology": "qr"},
                summary="Scan the router.", formats=["qr"])
    assert data["outcome"] == "answered" and data["value"] == "https://example.com/[0m"
    assert data["symbology"] == "qr" and data["cleaned"] is True
    assert "Do not open a link" in data["message"] and "were removed" in data["message"]
    assert phone.requests("device.scan")[0]["params"]["formats"] == ["qr"]
    data = _ask(server, phone, "device.scan", tool.device_scan_tool,
                {"status": "answered", "value": "4006381333931", "symbology": "ean13"}, summary="Scan the box.")
    assert data["cleaned"] is False and "formats" not in phone.requests("device.scan")[1]["params"]


def test_device_scan_takes_formats_as_json_text_or_one_bare_word(server, phone):
    for formats, want in ((json.dumps(["qr", "ean13"]), ["qr", "ean13"]), ("aztec", ["aztec"])):
        data = _ask(server, phone, "device.scan", tool.device_scan_tool,
                    {"status": "answered", "value": "x", "symbology": want[0]}, summary="Scan it.", formats=formats)
        assert data["outcome"] == "answered"
        assert phone.requests("device.scan")[-1]["params"]["formats"] == want
    release = _bind_ui_session("s1")
    try:
        assert "formats must be JSON" in json.loads(tool.device_scan_tool(summary="x", formats="[qr"))["error"]
        assert "error" in json.loads(tool.device_scan_tool(summary="x", formats="upc"))
    finally:
        release()


def test_device_scan_refuses_formats_it_does_not_know_with_nothing_sent(server, phone):
    release = _bind_ui_session("s1")
    try:
        for formats in ([], ["upc"], ["qr", "qr"]):
            assert "error" in json.loads(tool.device_scan_tool(summary="x", formats=formats)), formats
    finally:
        release()
    assert phone.requests("device.scan") == []


def test_a_decline_reaches_the_agent_as_the_persons_choice(server, phone):
    from tests.tui_gateway.test_server_requests_gate import _as
    release = _bind_ui_session("s1")
    try:
        thread, box = _call(tool.device_contact_tool, summary="Pick Bram.", fields=["emails"])
        rid = _wait_open("device.contact")
        error = {"code": 4041, "message": "cannot_show", "data": {"reason": "declined"}}
        _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": rid, "error": error}, phone)
        thread.join(5)
    finally:
        release()
    data = json.loads(box["r"])
    assert (data["outcome"], data["reason"]) == ("unavailable", "cannot_show:declined")
    assert "The person declined to provide this" in data["message"] and "emails" not in data["message"]


# ── who is asked, and how often ─────────────────────────────────────────────────────────────────


def test_a_connection_that_did_not_advertise_the_method_is_sent_nothing(server, monkeypatch):
    from tui_gateway import interactive
    monkeypatch.setattr(interactive, "PARK_SECONDS", 0.1)
    web = _WS("web", ROBIN)
    _session(server, "s1", web, creator=ROBIN)
    _caps(server, web, requests=["input.form", "input.file", "review.draft", "review.diff"])   # a client of phase 2
    release = _bind_ui_session("s1")
    try:
        for result in _every_tool_with_valid_arguments():
            data = json.loads(result)
            assert (data["outcome"], data["reason"]) == ("unavailable", "no_capable_client")
            assert "not an answer from the person" in data["message"] or "not a confirmation" in data["message"]
    finally:
        release()
    assert web.frames == []


def test_the_sixth_request_is_the_last_in_ten_minutes(server, phone):
    release = _bind_ui_session("s1")
    try:
        for _ in range(6):
            thread, box = _call(tool.device_scan_tool, summary="Scan it.")
            rid = _wait_open("device.scan")
            _frame(server, phone, rid, result={"status": "skipped"})
            thread.join(5)
            assert json.loads(box["r"])["outcome"] == "skipped"
        data = json.loads(tool.device_location_tool(summary="Where are you?"))
    finally:
        release()
    assert (data["outcome"], data["reason"]) == ("unavailable", "rate_limited")
    assert "do not retry at once" in data["message"] and len(phone.requests("device.location")) == 0


def test_a_second_request_while_one_is_open_is_unavailable(server, phone):
    release = _bind_ui_session("s1")
    try:
        thread, box = _call(tool.device_scan_tool, summary="Scan it.")
        rid = _wait_open("device.scan")
        data = json.loads(tool.device_location_tool(summary="Where are you?"))
        _frame(server, phone, rid, result={"status": "skipped"})
        thread.join(5)
    finally:
        release()
    assert (data["outcome"], data["reason"]) == ("unavailable", "already_pending")
    assert phone.requests("device.location") == []


def test_the_expiry_in_the_frame_is_180_seconds(server, phone):
    release = _bind_ui_session("s1")
    try:
        thread, box = _call(tool.device_location_tool, summary="Where are you?")
        rid = _wait_open("device.location")
        expires = phone.requests("device.location")[0]["params"]["expires_at"]
        _frame(server, phone, rid, result={"status": "skipped"})
        thread.join(5)
    finally:
        release()
    assert 170 <= expires - time.time() <= 181
