"""``contract/requests``: the interactive request methods' written contract agrees with the models.

``examples.json`` is normative. Every frame and every valid answer must parse with the Pydantic models in
``tui_gateway/contracts/server_requests.py`` (and with the rendered ``schema.json``); every invalid answer
names the reason the gateway refuses it with (``request.answer`` 4034 ``data.reason``):

- layer ``model``: the result model refuses it, so the reason is ``bad_shape``;
- layer ``validator``: the result model ACCEPTS it and only a check against the request's params refuses
  it (``not_optional``, ``field:<id>:<problem>``, ``file:<n>:<problem>``, …). Those checks are the
  per-method validators, which live with the gateway's request code, not here; this file pins that each
  such example is well-formed and consistent with its frame, and the validators' own tests must refuse
  every one of them (``validator_cases()``) with exactly its reason. That run of ``validator_cases()``
  against the REAL validators is an acceptance criterion of the task that writes them (plan
  ``request-types-v2``, P1-F4).

Every invalid FRAME (``invalid_frames``) is refused by the params model; layer ``model`` also fails
``schema.json``, layer ``cross_field`` passes it (a rule JSON Schema cannot express: unique ids, ``min`` ≤
``max``, a default that is a valid value, …).

``schema.json`` and ``SHA256SUMS`` are rendered by ``scripts/gen_gateway_contracts.py``
(``test_generated.py`` diffs them); here the sums are also checked the way ``sha256sum -c`` would.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from tui_gateway.contracts.liveness import ClientCapabilitiesParams
from tui_gateway.contracts.prompt_voice import RequestAnswerParams
from tui_gateway.contracts.registry import SERVER_REQUESTS
from tui_gateway.contracts.server_requests import (
    CANNOT_SHOW,
    INTERACTIVE_METHODS,
    FormField,
    FormFieldKind,
    InputFormResult,
    InputStatus,
    InteractiveRequestParams,
    ReviewDecision,
)

REPO = Path(__file__).resolve().parents[3]
DIR = REPO / "contract" / "requests"
EXAMPLES = json.loads((DIR / "examples.json").read_text(encoding="utf-8"))

FORM_PROBLEMS = ("missing", "unknown", "type", "format", "too_long", "below_min", "above_max", "not_integer",
                 "step", "zone", "offset", "order", "not_an_option", "duplicate", "too_few", "too_many")
#: Every reason a method's answer may be refused with (README "Refused answers").
REASONS: dict[str, re.Pattern[str]] = {
    "input.form": re.compile(r"^(bad_shape|not_optional|field:[a-z][a-z0-9_]{0,31}:(%s))$" % "|".join(FORM_PROBLEMS)),
    "input.file": re.compile(r"^(bad_shape|not_optional|files:(too_many|too_large)|"
                             r"file:(0|[1-9][0-9]*):(outside_dir|too_large))$"),
    "review.draft": re.compile(r"^(bad_shape|text:(not_verbatim|edited))$"),
}
#: The discriminator of each method's result and the values every one must have a valid example of.
STATUSES = {
    "input.form": ("status", {s.value for s in InputStatus}),
    "input.file": ("status", {s.value for s in InputStatus}),
    "review.draft": ("decision", {d.value for d in ReviewDecision}),
}


def _frames(method: str) -> dict[str, dict]:
    return {f["id"]: f for f in EXAMPLES["methods"][method]["frames"]}


def _parses(model, data) -> bool:
    try:
        model.model_validate(data)
    except ValidationError:
        return False
    return True


def validator_cases() -> list[tuple[str, dict, dict, str]]:
    """``(method, params, result, reason)`` for every example the result model accepts and the method's
    validator must refuse, including one per invalid form-field value."""
    cases = []
    for method in INTERACTIVE_METHODS:
        frames = _frames(method)
        for case in EXAMPLES["methods"][method]["invalid_answers"]:
            if case["layer"] == "validator":
                cases.append((method, frames[case["request"]]["params"], case["result"], case["reason"]))
    for entry in EXAMPLES["form_fields"]:
        params = _single_field_params(entry["field"])
        for bad in entry["invalid"]:
            result = {"status": "answered", "values": {entry["field"]["id"]: bad["value"]}}
            cases.append(("input.form", params, result, bad["reason"]))
    return cases


def _single_field_params(field: dict) -> dict:
    return {"session_id": "s_example", "v": 1, "title": "One field", "summary": "One field.",
            "expires_at": 0, "optional": True, "fields": [field]}


# ── coverage ────────────────────────────────────────────────────────────────────────────────────


def test_examples_cover_exactly_the_interactive_methods():
    assert set(EXAMPLES["methods"]) == set(INTERACTIVE_METHODS)
    for method in INTERACTIVE_METHODS:
        assert method in SERVER_REQUESTS, method
        assert issubclass(SERVER_REQUESTS[method].params, InteractiveRequestParams), method


@pytest.mark.parametrize("method", INTERACTIVE_METHODS)
def test_each_method_has_enough_examples(method):
    block = EXAMPLES["methods"][method]
    assert block["frames"]
    key, statuses = STATUSES[method]
    assert {a["result"][key] for a in block["answers"]} == statuses
    assert len(block["invalid_answers"]) >= 3
    names = [x["name"] for x in block["answers"] + block["invalid_answers"]]
    assert len(names) == len(set(names)), "example names are unique per method"


def test_every_form_field_kind_has_a_field_a_valid_and_an_invalid_value():
    kinds = {entry["field"]["kind"] for entry in EXAMPLES["form_fields"] if entry["valid"] and entry["invalid"]}
    assert kinds == {k.value for k in FormFieldKind}


# ── frames ──────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", INTERACTIVE_METHODS)
def test_frames_parse(method):
    contract = SERVER_REQUESTS[method]
    for frame in EXAMPLES["methods"][method]["frames"]:
        assert frame["jsonrpc"] == "2.0" and frame["method"] == method
        contract.params.model_validate(frame["params"])


@pytest.mark.parametrize("method", INTERACTIVE_METHODS)
def test_invalid_frames_are_refused_by_the_params_model(method):
    contract = SERVER_REQUESTS[method]
    frames = EXAMPLES["methods"][method]["invalid_frames"]
    assert frames, method
    for case in frames:
        assert case["layer"] in ("model", "cross_field"), case["name"]
        assert not _parses(contract.params, case["params"]), f"{case['name']}: the model accepts it"


def test_frame_ids_are_unique():
    ids = [f["id"] for method in INTERACTIVE_METHODS for f in EXAMPLES["methods"][method]["frames"]]
    assert len(ids) == len(set(ids))


# ── answers ─────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", INTERACTIVE_METHODS)
def test_valid_answers_parse(method):
    contract, frames = SERVER_REQUESTS[method], _frames(method)
    for answer in EXAMPLES["methods"][method]["answers"]:
        assert answer["request"] in frames, answer["name"]
        assert _parses(contract.result, answer["result"]), answer["name"]


@pytest.mark.parametrize("method", INTERACTIVE_METHODS)
def test_invalid_answers_fail_where_they_say(method):
    contract, frames = SERVER_REQUESTS[method], _frames(method)
    for case in EXAMPLES["methods"][method]["invalid_answers"]:
        name, reason = case["name"], case["reason"]
        assert case["request"] in frames, name
        assert REASONS[method].fullmatch(reason), f"{name}: malformed reason {reason!r}"
        if case["layer"] == "model":
            assert reason == "bad_shape", name
            assert not _parses(contract.result, case["result"]), f"{name}: the model accepts it"
        else:
            assert case["layer"] == "validator", name
            assert reason != "bad_shape", name
            assert _parses(contract.result, case["result"]), f"{name}: the model already refuses it"


def test_validator_cases_are_consistent_with_their_frames():
    """What a validator-layer reason claims holds on the example itself: ``not_optional`` only for a
    request that offers no skip, ``field:<id>:unknown`` only for an id the form lacks and every other field
    reason for one it has, ``file:<n>:`` within the answer's files."""
    for method, params, result, reason in validator_cases():
        if reason == "not_optional":
            assert params["optional"] is False and result.get("status") == "skipped", reason
        elif reason.startswith("field:"):
            _, field_id, problem = reason.split(":")
            ids = {f["id"] for f in params["fields"]}
            assert (field_id not in ids) if problem == "unknown" else (field_id in ids), reason
            if problem == "unknown":
                assert field_id in result["values"], reason
            if problem == "missing":
                assert result["values"].get(field_id) in (None, "", []), reason
        elif reason.startswith("file:"):
            assert int(reason.split(":")[1]) < len(result["files"]), reason
        elif reason == "files:too_many":
            limit = params["upload"]["max_files"] if params["multiple"] else 1
            assert len(result["files"]) > limit, reason
        elif reason == "files:too_large":
            assert all(f["bytes"] <= params["upload"]["max_bytes"] for f in result["files"]), reason
            assert sum(f["bytes"] for f in result["files"]) > params["upload"]["max_total_bytes"], reason
        elif reason == "text:edited":
            assert params["editable"] is False and result["text"] != params["text"], reason


# ── form fields ─────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("entry", EXAMPLES["form_fields"], ids=lambda e: e["name"])
def test_form_field_examples(entry):
    field = FormField.model_validate(entry["field"]).root
    assert field.kind.value == entry["field"]["kind"]
    _frame_params = _single_field_params(entry["field"])
    SERVER_REQUESTS["input.form"].params.model_validate(_frame_params)
    for value in entry["valid"]:
        InputFormResult.model_validate({"status": "answered", "values": {field.id: value}})
    for bad in entry["invalid"]:
        # A value of the wrong kind is still a JSON value the result model takes: only the validator,
        # which knows the field, can refuse it.
        InputFormResult.model_validate({"status": "answered", "values": {field.id: bad["value"]}})
        assert REASONS["input.form"].fullmatch(bad["reason"]), bad
        assert bad["reason"].split(":")[1] == field.id, bad


def test_form_field_models_refuse_bad_definitions():
    base = {"id": "guests", "kind": "number", "label": "Guests"}
    assert _parses(FormField, base)
    for bad in ({**base, "kind": "slider"}, {**base, "id": "Guests"}, {**base, "id": "g" * 33},
                {**base, "colour": "red"}, {**base, "step": 0}, {**base, "label": ""},
                {"id": "c", "kind": "choice", "label": "C", "options": []},
                {"id": "a", "kind": "amount", "label": "A", "currency": "eur"},
                {"id": "a", "kind": "amount", "label": "A", "currency": "EUR", "max": 50}):
        assert not _parses(FormField, bad), bad


def test_form_has_one_to_twelve_fields():
    model = SERVER_REQUESTS["input.form"].params
    field = {"id": "f", "kind": "toggle", "label": "F"}
    assert not _parses(model, _single_field_params(field) | {"fields": []})
    many = [{**field, "id": f"f{i}"} for i in range(13)]
    assert not _parses(model, _single_field_params(field) | {"fields": many})


def test_envelope_is_closed():
    params = _single_field_params({"id": "f", "kind": "toggle", "label": "F"})
    model = SERVER_REQUESTS["input.form"].params
    assert _parses(model, params)
    for bad in (params | {"v": 2}, params | {"title": "two\nlines"}, params | {"title": "x" * 81},
                *(params | {"title": f"two{sep}lines"} for sep in "\r\x0b\x0c\x85\u2028\u2029"),
                params | {"summary": ""}, params | {"expires_at": -1}, params | {"extra": True},
                {k: v for k, v in params.items() if k != "optional"}):
        assert not _parses(model, bad)


# ── errors and capabilities ─────────────────────────────────────────────────────────────────────


def test_error_examples():
    seen = set()
    for case in EXAMPLES["errors"]:
        error = case["frame"]["error"]
        assert isinstance(error["data"]["reason"], str) and error["data"]["reason"]
        seen.add(error["code"])
        if error["code"] == CANNOT_SHOW:
            assert case["direction"] == "client_to_gateway" and error["message"] == "cannot_show"
        else:
            assert error["code"] == 4034 and case["direction"] == "gateway_to_client"
            assert case["request"]["method"] == "request.answer"
            RequestAnswerParams.model_validate(case["request"]["params"])
            assert REASONS["input.form"].fullmatch(error["data"]["reason"])
    assert seen == {CANNOT_SHOW, 4034}


@pytest.mark.parametrize("field", [
    {"id": "d", "kind": "date", "label": "D", "min": "2026-10-05\n"},
    {"id": "t", "kind": "time", "label": "T", "max": "18:00\n"},
    {"id": "a", "kind": "amount", "label": "A", "currency": "EUR", "min": "1\n"},
    {"id": "dt", "kind": "datetime", "label": "DT", "min": "2026-10-05T00:00+02:00\n"},
    {"id": "r", "kind": "daterange", "label": "R", "default": {"start": "2026-10-05\n", "end": "2026-10-06"}},
    {"id": "f\n", "kind": "toggle", "label": "F"},
])
def test_a_trailing_newline_never_passes_a_whole_value_pattern(field):
    """Every pattern check anchors at the very end: a value followed by "\n" is refused (``re.fullmatch``)."""
    assert not _parses(SERVER_REQUESTS["input.form"].params, _single_field_params(field))


def test_capabilities_requests_is_bounded():
    assert not _parses(ClientCapabilitiesParams, {"server_requests": True, "requests": ["input.form"] * 33})
    assert _parses(ClientCapabilitiesParams, {"server_requests": True, "requests": ["input.form"] * 32})


def test_capabilities_example():
    for case in EXAMPLES["capabilities"]:
        params = ClientCapabilitiesParams.model_validate(case["request"]["params"])
        assert set(params.requests or ()) <= set(INTERACTIVE_METHODS)


# ── rendered schema and sums ────────────────────────────────────────────────────────────────────


def test_schema_agrees_with_the_models():
    """``schema.json`` accepts every frame and valid answer and refuses every model-layer invalid one, so a
    client validating against it sees what the gateway's models see."""
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((DIR / "schema.json").read_text(encoding="utf-8"))
    assert list(schema["methods"]) == list(INTERACTIVE_METHODS)

    def validator(ref: dict):
        return jsonschema.Draft202012Validator({**ref, "$defs": schema["$defs"]})

    for method in INTERACTIVE_METHODS:
        params_v = validator(schema["methods"][method]["params"])
        result_v = validator(schema["methods"][method]["result"])
        block = EXAMPLES["methods"][method]
        for frame in block["frames"]:
            params_v.validate(frame["params"])
        for answer in block["answers"]:
            result_v.validate(answer["result"])
        for case in block["invalid_answers"]:
            assert result_v.is_valid(case["result"]) == (case["layer"] == "validator"), case["name"]
        for case in block["invalid_frames"]:
            assert params_v.is_valid(case["params"]) == (case["layer"] == "cross_field"), case["name"]
    field_v = validator({"$ref": "#/$defs/FormField"})
    form_result_v = validator(schema["methods"]["input.form"]["result"])
    for entry in EXAMPLES["form_fields"]:
        field_v.validate(entry["field"])
        for value in entry["valid"] + [bad["value"] for bad in entry["invalid"]]:
            form_result_v.validate({"status": "answered", "values": {entry["field"]["id"]: value}})


def test_sha256sums_pin_the_directory():
    lines = (DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    pinned = {}
    for line in lines:
        digest, name = line.split("  ", 1)
        pinned[name] = digest
    assert set(pinned) == {"README.md", "examples.json", "schema.json"}
    for name, digest in pinned.items():
        assert hashlib.sha256((DIR / name).read_bytes()).hexdigest() == digest, f"{name}: run the generator"
