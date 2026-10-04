"""Structured ``confirm`` (plan request-types-v2 D7/D8): ``fields``, the version-2 text digest, the
``confirm_fields`` advertisement, ``draft_id`` and the ``confirm_action`` budget preset.

Pinned here: field values are refused, never rewritten, when they hold anything a renderer shows as nothing
or more than one line, and the limits of the contract hold; a ``confirm`` with fields goes only to connections
that advertised ``confirm_fields`` (at ``passkey`` also ``confirm_passkey {v: 2}``) and is ``unavailable
(no_capable_client)`` with nothing sent when none is attached; a version-1 passkey client never gets a
version-2 frame; a version-2 answer is verified against ``text_digest_v2`` and a signature over the text
without the fields (or with them in another order) is refused; ``draft_id`` takes the approved text from the
register verbatim and an unknown, expired or foreign id sends nothing; the audit says ``fields: n`` and
``draft: true`` and never a label, value or the draft.
"""

from __future__ import annotations

import json
import threading

import pytest

from hermes_cli.dashboard_auth.passkeys.challenge import b64u_decode, field_tuple, text_digest, text_digest_v2
from tests.tui_gateway.test_confirm_passkey import (  # noqa: F401 - fixtures are used by name
    ALICE, TEXT, _alice_session, _answer_rpc, _ask, _ask_now, _frame, _turn, native, passkeys)
from tests.tui_gateway.test_confirm_request import (  # noqa: F401 - fixtures are used by name
    _advertise, _as, _Peer, _session, _wait_open, audit_records, server)

BUDGET = [
    {"kind": "amount", "label": "Estimated cost", "value": "4.20", "currency": "€"},
    {"kind": "count", "label": "tokens", "value": "1,200,000"},
    {"kind": "model", "label": "Model", "value": "claude-opus-5-5"},
]


def _advertise_fields(server, peer, *, confirm=("plain",), confirm_fields=True, passkey=None):
    params: dict = {"server_requests": True, "confirm": list(confirm), "confirm_fields": confirm_fields}
    if passkey is not None:
        params["confirm_passkey"] = passkey
    return _as(peer, server.handle_request, {"id": 1, "method": "client.capabilities", "params": params})


def _ask_plain(sid, **kwargs):
    from tui_gateway import confirm
    params = confirm.build_params(summary=kwargs.pop("summary", "Run the long analysis."), level="plain", **kwargs)
    box: dict = {}
    thread = threading.Thread(target=lambda: box.setdefault("r", confirm.request(sid, params, timeout=5)),
                              daemon=True)
    thread.start()
    return thread, box


# ── building the fields ────────────────────────────────────────────────────────────────────────


def test_the_budget_preset_builds_and_validates_against_the_contract():
    from tui_gateway import confirm
    from tui_gateway.contracts import registry
    params = confirm.build_params(summary="Run the analysis with the large model.", fields=BUDGET)
    assert params["fields"] == [
        {"id": "field_1", "kind": "amount", "label": "Estimated cost", "value": "4.20", "currency": "€"},
        {"id": "field_2", "kind": "count", "label": "tokens", "value": "1,200,000"},
        {"id": "field_3", "kind": "model", "label": "Model", "value": "claude-opus-5-5"},
    ]
    registry.SERVER_REQUESTS["confirm"].params.model_validate({"session_id": "s1", **params})
    # No fields, or an empty list: the key is absent and the frame is the version-1 one.
    assert "fields" not in confirm.build_params(summary="x", fields=[])
    assert "fields" not in confirm.build_params(summary="x")


def test_ids_spaces_and_numbers():
    from tui_gateway import confirm
    fields = confirm.build_fields([{"id": "to", "kind": "recipient", "label": "  To ", "value": " alex@example.com"},
                                   {"kind": "count", "label": "Files", "value": 3}])
    assert fields == [{"id": "to", "kind": "recipient", "label": "To", "value": "alex@example.com"},
                      {"id": "field_2", "kind": "count", "label": "Files", "value": "3"}]


@pytest.mark.parametrize("fields, problem", [
    ([{"kind": "text", "label": "L", "value": "v"}] * 9, "the limit is 8"),
    ("amount 4", "must be a list"),
    (["amount"], "must be an object"),
    ([{"kind": "amount", "label": "L", "value": "1", "unit": "EUR"}], "unknown keys: unit"),
    ([{"kind": "iban", "label": "L", "value": "1"}], "kind must be one of"),
    ([{"kind": "text", "label": "L", "value": "1", "currency": "EUR"}], "only for kind amount"),
    ([{"kind": "text", "label": "L"}], "value must be a string"),
    ([{"kind": "text", "label": "L", "value": True}], "value must be a string"),
    ([{"kind": "text", "label": "L", "value": 1.5}], "value must be a string"),
    ([{"kind": "text", "label": "", "value": "1"}], "label is empty"),
    ([{"kind": "text", "label": "L", "value": "   "}], "value is empty"),
    ([{"kind": "text", "label": "L" * 41, "value": "1"}], "the limit is 40"),
    ([{"kind": "text", "label": "L", "value": "v" * 201}], "the limit is 200"),
    ([{"kind": "amount", "label": "L", "value": "1", "currency": "C" * 17}], "the limit is 16"),
    ([{"kind": "text", "label": "L", "value": "one\ntwo"}], "must be one line"),
    ([{"kind": "text", "label": "L", "value": "one two"}], "cannot be shown as it is"),
    ([{"kind": "recipient", "label": "To", "value": "alice‮@evil.example"}], "cannot be shown as it is"),
    ([{"kind": "amount", "label": "L", "value": "1​00"}], "cannot be shown as it is"),
    ([{"kind": "amount", "label": "L", "value": "100", "currency": "EUR️"}], "cannot be shown as it is"),
    ([{"kind": "text", "label": "Lㅤ", "value": "1"}], "cannot be shown as it is"),
    ([{"kind": "text", "label": "L", "value": "a\tb"}], "cannot be shown as it is"),
    ([{"kind": "text", "label": "L", "value": "a" + " " * 17 + "b"}], "spaces in a row"),
    ([{"kind": "text", "label": "L", "value": "e" + "́" * 5}], "combining marks"),
    ([{"id": "Amount", "kind": "text", "label": "L", "value": "1"}], "lower-case identifier"),
    ([{"id": "a", "kind": "text", "label": "L", "value": "1"}, {"id": "a", "kind": "text", "label": "M", "value": "2"}],
     "used twice"),
])
def test_fields_the_person_could_not_see_exactly_are_refused(fields, problem):
    from tui_gateway import confirm
    with pytest.raises(confirm.ConfirmParamsError, match=problem):
        confirm.build_params(summary="x", fields=fields)


def test_the_contract_bounds_are_the_builders():
    from tui_gateway import confirm
    from tui_gateway.contracts import server_requests as contract
    assert (contract.CONFIRM_FIELDS_MAX, contract.CONFIRM_FIELD_LABEL_MAX, contract.CONFIRM_FIELD_VALUE_MAX,
            contract.CONFIRM_FIELD_CURRENCY_MAX) == (8, 40, 200, 16)
    assert confirm.FIELD_KINDS == ("amount", "text", "recipient", "domain", "model", "count", "date")
    model = contract.ConfirmRequestParams
    base = {"session_id": "s", "title": "T", "summary": "S", "level": "plain"}
    for bad in ([], [{"id": "a", "kind": "text", "label": "L", "value": ""}],
                [{"id": "A", "kind": "text", "label": "L", "value": "v"}]):
        with pytest.raises(Exception):
            model.model_validate({**base, "fields": bad})


# ── the advertisement ──────────────────────────────────────────────────────────────────────────


def test_confirm_fields_is_accepted_only_with_a_level_and_exactly_true(server):
    from tui_gateway import server_requests
    from tui_gateway.contracts import registry
    app = _Peer("app")
    result = _advertise(server, app, confirm=["plain"])["result"]
    assert result["confirm_fields"] is False  # a backend that knows the key always sends it
    result = _advertise_fields(server, app)["result"]
    assert result["confirm_fields"] is True and server_requests.shows_confirm_fields(app)
    registry.METHODS["client.capabilities"].result.model_validate(result)
    registry.METHODS["client.capabilities"].params.model_validate(
        {"server_requests": True, "confirm": ["plain"], "confirm_fields": True})
    # Without a level, without server_requests, or not exactly true: not accepted.
    assert _advertise_fields(server, app, confirm=())["result"]["confirm_fields"] is False
    assert _advertise_fields(server, app, confirm_fields=1)["result"]["confirm_fields"] is False
    assert _as(app, server.handle_request, {"id": 1, "method": "client.capabilities", "params": {
        "server_requests": False, "confirm": ["plain"], "confirm_fields": True}})["result"]["confirm_fields"] is False
    # Every call replaces the last one, and a disconnect forgets it.
    assert _advertise_fields(server, app)["result"]["confirm_fields"] is True
    assert _advertise(server, app, confirm=["plain"])["result"]["confirm_fields"] is False
    _advertise_fields(server, app)
    server_requests.forget(app)
    assert not server_requests.shows_confirm_fields(app)


# ── level plain ────────────────────────────────────────────────────────────────────────────────


def test_plain_with_fields_and_no_capable_client_is_unavailable_with_nothing_sent(server, audit_records):
    from tui_gateway import server_requests
    old = _Peer("old")
    _session(server, "s1", old)
    _advertise(server, old, confirm=["plain"])
    thread, box = _ask_plain("s1", fields=BUDGET)
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "unavailable", "method": None, "verified": False,
                                  "reason": "no_capable_client"}
    assert old.requests() == [] and server_requests.open_requests("s1") == []
    # The same request without fields reaches it as before.
    thread, box = _ask_plain("s1")
    _wait_open()
    assert len(old.requests()) == 1 and "fields" not in old.requests()[0]["params"]


def test_plain_with_fields_reaches_only_connections_that_show_them(server, audit_records):
    from tui_gateway.contracts import registry
    old, new = _Peer("old"), _Peer("new")
    _session(server, "s1", old, new)
    _advertise(server, old, confirm=["plain"])
    _advertise_fields(server, new)
    thread, box = _ask_plain("s1", fields=BUDGET)
    _wait_open()
    frame = new.requests()[0]
    registry.SERVER_REQUESTS["confirm"].params.model_validate(frame["params"])
    assert [f["label"] for f in frame["params"]["fields"]] == ["Estimated cost", "tokens", "Model"]
    assert "passkey" not in frame["params"] and old.requests() == []
    # The connection that cannot show the fields cannot settle it either.
    refused = _as(old, server.handle_request, {"id": 5, "method": "request.answer", "params": {
        "id": frame["id"], "result": {"decision": "confirmed", "method": "tap"}}})
    assert refused["error"]["code"] == 4033
    _as(new, server.handle_request, {"id": 6, "method": "request.answer", "params": {
        "id": frame["id"], "result": {"decision": "confirmed", "method": "tap"}}})
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "confirmed", "method": "tap", "verified": False}
    request, outcome = (fields for event, fields in audit_records)
    assert request["fields"] == 3 and outcome["fields"] == 3 and "draft" not in request
    dumped = json.dumps(audit_records, ensure_ascii=False)
    for field in BUDGET:
        assert field["value"] not in dumped and field["label"] not in dumped


# ── level passkey: version 2 ───────────────────────────────────────────────────────────────────


def _v2(server, peer, **kw):
    from tests.tui_gateway.test_confirm_passkey import NATIVE_RP
    return _advertise_fields(server, peer, confirm=("plain", "passkey"),
                             passkey={"v": 2, "kind": "native", "rp_id": NATIVE_RP}, **kw)


def test_a_version_1_passkey_client_never_gets_a_version_2_frame(server, passkeys):
    from tests.tui_gateway.test_confirm_passkey import NATIVE_RP
    phone, _ = _alice_session(server, passkeys)  # advertises confirm_passkey {v: 1}
    assert _ask_now(server, "s1", **TEXT, fields=BUDGET).reason == "no_capable_client"
    assert phone.requests() == []
    # v 1 with confirm_fields: still not a target (it would hash the text without the fields).
    _advertise_fields(server, phone, confirm=("plain", "passkey"),
                      passkey={"v": 1, "kind": "native", "rp_id": NATIVE_RP})
    assert _ask_now(server, "s1", **TEXT, fields=BUDGET).reason == "no_capable_client"
    # v 2 without confirm_fields: not a target either (it would not show them).
    assert _v2(server, phone, confirm_fields=False)["result"]["confirm"] == ["passkey", "plain"]
    assert _ask_now(server, "s1", **TEXT, fields=BUDGET).reason == "no_capable_client"
    assert phone.requests() == []


def test_a_version_2_client_takes_version_1_frames(server, passkeys):
    phone, auth = _alice_session(server, passkeys)
    _v2(server, phone)
    thread, box = _ask(server, "s1")
    frame = _frame(server, phone)
    assert frame["params"]["passkey"]["v"] == 1 and "fields" not in frame["params"]
    _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "confirmed", "method": "passkey", "verified": True}


def _v2_answer(passkeys, auth, frame, **override):
    fields = tuple(field_tuple(f) for f in frame["params"]["fields"])
    return passkeys.answer(auth, frame, **{"fields": fields, **override})


def test_a_version_2_frame_is_verified_against_text_digest_v2(server, passkeys, audit_records):
    from tui_gateway import server_requests
    from tui_gateway.contracts import registry
    phone, auth = _alice_session(server, passkeys)
    old = _Peer("old", ALICE)
    _session(server, "s1", phone, old, creator=ALICE)
    _alice_v1 = _as(old, server.handle_request, {"id": 1, "method": "client.capabilities", "params": {
        "server_requests": True, "confirm": ["plain", "passkey"], "confirm_fields": True,
        "confirm_passkey": {"v": 1, "kind": "native", "rp_id": "confirm.hermie.dev"}}})
    assert _alice_v1["result"]["confirm"] == ["passkey", "plain"]
    _v2(server, phone)
    thread, box = _ask(server, "s1", **TEXT, fields=BUDGET)
    frame = _frame(server, phone)
    params = frame["params"]
    registry.SERVER_REQUESTS["confirm"].params.model_validate(params)
    assert params["passkey"]["v"] == 2 and params["fields"][0]["currency"] == "€"
    assert old.requests() == []  # the v1 client of the same person: never
    # Signed over the text without the fields (the v1 digest): refused, the request stays open.
    for wrong in (passkeys.answer(auth, frame),
                  _v2_answer(passkeys, auth, frame,
                             fields=tuple(reversed([field_tuple(f) for f in params["fields"]])))):
        if wrong["passkey"]["v"] == 1:
            wrong["passkey"]["v"] = 2  # so it fails on the challenge, not the shape
        refused = _answer_rpc(server, phone, frame["id"], wrong)
        assert refused["error"]["code"] == 4034 and refused["error"]["data"]["reason"] == "challenge_mismatch"
    # The right signature with ``v: 1`` in the answer: the shape of a version-1 answer, refused.
    good = _v2_answer(passkeys, auth, frame)
    shaped = json.loads(json.dumps(good))
    shaped["passkey"]["v"] = 1
    assert _answer_rpc(server, phone, frame["id"], shaped)["error"]["data"]["reason"] == "bad_shape"
    assert [r["id"] for r in _as(phone, server_requests.open_requests, "s1")] == [frame["id"]]
    assert _as(old, server_requests.open_requests, "s1") == []  # nor listed to the v1 client on reconnect
    assert _answer_rpc(server, phone, frame["id"], good)["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "confirmed", "method": "passkey", "verified": True}
    verified = dict(audit_records)["confirm_passkey_verified"]
    expected = text_digest_v2(params["title"], params["summary"], params.get("detail"),
                              tuple(field_tuple(f) for f in params["fields"]))
    assert verified["text_digest"] == expected.hex()
    assert expected != text_digest(params["title"], params["summary"], params.get("detail"))
    assert dict(audit_records)["confirm_request"]["fields"] == 3
    receipt = passkeys.store.receipts(user_id=ALICE)[-1]
    assert receipt.request_id == frame["id"] and b64u_decode(params["passkey"]["nonce"])


# ── draft_id ───────────────────────────────────────────────────────────────────────────────────


DRAFT = "Hi Sam,\n\n  the invoice is attached.\n\nAlex"


def test_draft_id_takes_the_approved_text_verbatim(server, audit_records):
    from tui_gateway import confirm, review_register
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    draft = review_register.put("key-s1", DRAFT, edited=True)
    box: dict = {}
    thread = threading.Thread(target=lambda: box.setdefault("r", confirm.request_from_tool(
        "s1", summary="Send the approved mail to Sam.", detail="something else entirely", draft_id=draft.draft_id)),
        daemon=True)
    thread.start()
    _wait_open()
    frame = app.requests()[0]
    assert frame["params"]["detail"] == DRAFT  # verbatim: indentation and blank lines kept, the agent's ignored
    _as(app, server.handle_request, {"id": 6, "method": "request.answer", "params": {
        "id": frame["id"], "result": {"decision": "declined", "method": "tap"}}})
    thread.join(5)
    assert box["r"].outcome == "declined"
    request, outcome = (fields for event, fields in audit_records)
    assert request["draft"] is True and outcome["draft"] is True and "fields" not in request
    assert "invoice" not in json.dumps(audit_records)


@pytest.mark.parametrize("case", ["unknown", "expired", "other_conversation", "too_long", "not_a_string"])
def test_a_draft_id_this_conversation_does_not_have_sends_nothing(server, case):
    from tui_gateway import confirm, review_register
    app = _Peer("app")
    _session(server, "s1", app)
    _advertise(server, app, confirm=["plain"])
    draft_id: object = "drf-000000000000"
    if case == "expired":
        stale = review_register.time.monotonic() - review_register.TTL_SECONDS - 1.0
        draft_id = review_register.put("key-s1", DRAFT, now=stale).draft_id
    elif case == "other_conversation":
        draft_id = review_register.put("key-s2", DRAFT).draft_id
    elif case == "too_long":
        draft_id = review_register.put("key-s1", "word " * 500 + "end").draft_id
    elif case == "not_a_string":
        draft_id = 12
    with pytest.raises(confirm.ConfirmParamsError):
        confirm.request_from_tool("s1", summary="Send it.", draft_id=draft_id)
    assert app.requests() == []


# ── the tool ───────────────────────────────────────────────────────────────────────────────────


def test_tool_passes_fields_and_draft_id_and_answers_tool_error_for_an_unknown_draft(monkeypatch):
    import tools.confirm_tool as tool
    from tui_gateway import confirm
    calls: list = []

    def bridge(sid, **kwargs):
        calls.append(kwargs)
        if kwargs["draft_id"] == "drf-unknown":
            raise confirm.ConfirmParamsError("draft drf-unknown is unknown or expired")
        return confirm.ConfirmOutcome("unavailable", reason="no_capable_client")

    monkeypatch.setattr(tool, "_bridge", bridge)
    monkeypatch.setattr(tool, "get_session_env", lambda name, default="": "s1")
    monkeypatch.setattr(tool, "session_is_messaging_surface", lambda: False)
    reply = json.loads(tool.confirm_action_tool("Run it.", fields=BUDGET))
    assert calls[-1]["fields"] == BUDGET and calls[-1]["draft_id"] is None
    assert reply["reason"] == "no_capable_client" and "WITHOUT fields" in reply["message"]
    assert "WITHOUT fields" not in json.loads(tool.confirm_action_tool("Run it."))["message"]
    error = json.loads(tool.confirm_action_tool("Send it.", draft_id="drf-unknown"))
    assert "error" in error and "unknown or expired" in error["error"]
    assert "error" in json.loads(tool.confirm_action_tool("x", fields="amount 4"))
    # The handler reads both arguments.
    from tools.registry import registry
    entry = registry.get_entry("confirm_action")
    entry.handler({"summary": "Run it.", "fields": BUDGET, "draft_id": "drf-x"})
    assert calls[-1]["draft_id"] == "drf-x" and calls[-1]["fields"] == BUDGET


def test_tool_schema_describes_fields_draft_id_and_the_spending_preset():
    import tools.confirm_tool as tool
    from tui_gateway.contracts.server_requests import ConfirmFieldKind
    props = tool.CONFIRM_ACTION_SCHEMA["parameters"]["properties"]
    assert props["fields"]["items"]["properties"]["kind"]["enum"] == [k.value for k in ConfirmFieldKind]
    assert props["fields"]["maxItems"] == 8 and "draft_id" in props
    description = tool.CONFIRM_ACTION_SCHEMA["description"]
    assert "expensive model" in description and "'tokens'" in description and "draft_id" in description
