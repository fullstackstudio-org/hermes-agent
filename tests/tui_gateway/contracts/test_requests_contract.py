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
    CalendarStatus,
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
    "input.file": re.compile(r"^(bad_shape|not_optional|files:(too_many|too_large)|text:not_audio|"
                             r"file:(0|[1-9][0-9]*):(outside_dir|too_large|not_audio))$"),
    "review.draft": re.compile(r"^(bad_shape|text:(not_verbatim|edited))$"),
    "review.diff": re.compile(r"^(bad_shape|hunk:h[1-9][0-9]{0,2}:(unknown|missing)|decision:inconsistent)$"),
    "input.signature": re.compile(r"^(bad_shape|not_optional|file:(0|1):(outside_dir|too_large|extension)|files:too_large|"
                                  r"files:not_png_and_svg|statement:mismatch)$"),
    "device.location": re.compile(r"^(bad_shape|not_optional|precision:too_precise)$"),
    "device.contact": re.compile(r"^(bad_shape|not_optional|contact:(name|phones|emails|postal|birthday|organization)"
                                 r":not_requested|contact:birthday:invalid|contact:empty)$"),
    "device.calendar": re.compile(r"^(bad_shape|not_optional)$"),
    "device.scan": re.compile(r"^(bad_shape|not_optional|symbology:not_requested|scan:empty)$"),
}
#: The discriminator of each method's result and the values every one must have a valid example of.
STATUSES = {
    "input.form": ("status", {s.value for s in InputStatus}),
    "input.file": ("status", {s.value for s in InputStatus}),
    "review.draft": ("decision", {d.value for d in ReviewDecision}),
    "review.diff": ("decision", {d.value for d in ReviewDecision}),
    "input.signature": ("status", {s.value for s in InputStatus}),
    "device.location": ("status", {s.value for s in InputStatus}),
    "device.contact": ("status", {s.value for s in InputStatus}),
    "device.calendar": ("status", {s.value for s in CalendarStatus}),
    "device.scan": ("status", {s.value for s in InputStatus}),
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
        elif reason.endswith(":extension"):
            number = int(reason.split(":")[1])
            suffix = ".png" if result["files"][number]["mime"] == "image/png" else ".svg"
            assert not result["files"][number]["path"].endswith(suffix), reason
        elif reason.startswith("file:"):
            assert int(reason.split(":")[1]) < len(result["files"]), reason
        elif reason == "files:too_many":
            limit = params["upload"]["max_files"] if params["multiple"] else 1
            assert len(result["files"]) > limit, reason
        elif reason == "files:too_large":
            assert all(f["bytes"] <= params["upload"]["max_bytes"] for f in result["files"]), reason
            assert sum(f["bytes"] for f in result["files"]) > params["upload"]["max_total_bytes"], reason
        elif reason == "text:not_audio":
            assert result.get("text") and (params["accept"] in ("image", "document") or (
                params["accept"] == "any" and not any(f["mime"].startswith("audio/") for f in result["files"]))), reason
        elif reason.endswith(":not_audio"):
            assert params["accept"] == "audio", reason
        elif reason == "files:not_png_and_svg":
            assert sorted(f["mime"] for f in result["files"]) != ["image/png", "image/svg+xml"], reason
        elif reason == "statement:mismatch":
            import hashlib as _hashlib
            assert result["statement_sha256"] != _hashlib.sha256(params["statement"].encode()).hexdigest(), reason
        elif reason == "precision:too_precise":
            assert params["precision"] == "approximate" and result["precision"] == "precise", reason
        elif reason.startswith("contact:") and reason.endswith(":not_requested"):
            key = reason.split(":")[1]
            assert key in result["contact"] and key not in params["fields"], reason
        elif reason == "contact:empty":
            shown = [v for k, val in result["contact"].items() if k in params["fields"] and val
                     for v in (val if isinstance(val, list) else [val])]
            assert not any(str(v).strip("\u200b\u202e \n") for v in shown), reason
        elif reason == "contact:birthday:invalid":
            assert "birthday" in params["fields"] and "birthday" in result["contact"], reason
        elif reason == "symbology:not_requested":
            assert params.get("formats") and result["symbology"] not in params["formats"], reason
        elif reason == "scan:empty":
            assert not result["value"].strip("\u200b\u202e \n"), reason
        elif reason == "text:edited":
            assert params["editable"] is False and result["text"] != params["text"], reason
        elif reason.startswith("hunk:"):
            _, hunk_id, problem = reason.split(":")
            ids = {h["id"] for h in params["hunks"]}
            assert (hunk_id not in ids and hunk_id in result["hunks"]) if problem == "unknown" else \
                (hunk_id in ids and hunk_id not in result["hunks"]), reason
        elif reason == "decision:inconsistent":
            approved = "approved" in result["hunks"].values()
            assert approved == (result["decision"] == "rejected"), reason


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


@pytest.mark.parametrize("key", ["Name", "name\n", "1st", "", "a" * 33, "na me"])
def test_a_values_key_that_is_no_field_id_fails_the_model(key):
    """A ``values`` key must be a well-formed field id (``propertyNames`` in ``schema.json``), so a refusal never
    carries the client's text: ``field:<id>:unknown`` is only for a well-formed id the form does not have."""
    result = SERVER_REQUESTS["input.form"].result
    assert not _parses(result, {"status": "answered", "values": {key: "x"}})
    assert _parses(result, {"status": "answered", "values": {"colour": "x"}})


def test_an_uploaded_files_path_is_bounded():
    result = SERVER_REQUESTS["input.file"].result
    entry = {"name": "a.txt", "mime": "text/plain", "bytes": 1, "sha256": "0" * 64}
    assert _parses(result, {"status": "answered", "files": [{**entry, "path": "/" + "a" * 4095}]})
    assert not _parses(result, {"status": "answered", "files": [{**entry, "path": "/" + "a" * 4096}]})


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


# ── review.diff ─────────────────────────────────────────────────────────────────────────────────


def _diff_params(hunks: list[dict], **extra) -> dict:
    return {"session_id": "s_example", "v": 1, "title": "Diff", "summary": "A diff.", "expires_at": 0,
            "optional": False, "kind": "modify", "path": "f.py", **extra, "hunks": hunks}


def _hunk(hunk_id: str = "h1", header: str = "@@ -1 +1 @@", lines: list[str] | None = None) -> dict:
    return {"id": hunk_id, "header": header, "lines": lines if lines is not None else ["-a", "+b"]}


def test_example_hunks_are_what_the_gateway_builds():
    """Every hunk of an example frame is one ``diff_hunks`` could have produced: ids ``h1..`` in order, the header's
    counts agree with the lines, and every line and header passes the rules the gateway applies to a diff."""
    from tui_gateway import diff_hunks
    for frame in EXAMPLES["methods"]["review.diff"]["frames"]:
        hunks = frame["params"]["hunks"]
        assert [h["id"] for h in hunks] == [f"h{n}" for n in range(1, len(hunks) + 1)], frame["id"]
        for hunk in hunks:
            assert diff_hunks.header_problem(hunk["header"]) == "", hunk["id"]
            assert all(diff_hunks.line_problem(line) == "" for line in hunk["lines"]), hunk["id"]
            match = diff_hunks.HEADER.fullmatch(hunk["header"])
            body = [line for line in hunk["lines"] if line != diff_hunks.NO_NEWLINE]
            assert (sum(1 for line in body if line[0] in " -"), sum(1 for line in body if line[0] in " +")) == (
                diff_hunks._count(match.group(2)), diff_hunks._count(match.group(4))), hunk["id"]
            assert hunk.get("anchor") == diff_hunks.anchor_of(hunk["header"], hunk["lines"]), hunk["id"]
        # nothing can follow a hunk that is pinned to the end of the file
        assert all(diff_hunks.has_trailing_context(h["lines"]) for h in hunks[:-1]), frame["id"]
        if frame["params"].get("path"):
            assert diff_hunks.path_problem(frame["params"]["path"]) == ""


def test_diff_params_are_bounded():
    model = SERVER_REQUESTS["review.diff"].params
    assert _parses(model, _diff_params([_hunk()]))
    assert _parses(model, _diff_params([_hunk(f"h{n}") for n in range(1, 201)]))
    assert not _parses(model, _diff_params([_hunk(f"h{n}") for n in range(1, 202)]))
    assert not _parses(model, _diff_params([]))
    assert _parses(model, _diff_params([_hunk(lines=[" x"] * 400)]))
    assert not _parses(model, _diff_params([_hunk(lines=[" x"] * 401)]))
    assert not _parses(model, _diff_params([_hunk(lines=[])]))
    assert _parses(model, _diff_params([_hunk(lines=["+" + "x" * 499])]))
    assert not _parses(model, _diff_params([_hunk(lines=["+" + "x" * 500])]))
    header = "@@ -1 +1 @@ " + "f" * (200 - len("@@ -1 +1 @@ "))
    assert _parses(model, _diff_params([_hunk(header=header)]))
    assert not _parses(model, _diff_params([_hunk(header=header + "f")]))
    assert _parses(model, _diff_params([_hunk()], path="p" * 300))
    assert not _parses(model, _diff_params([_hunk()], path="p" * 301))
    assert not _parses(model, _diff_params([_hunk()], path=""))


def test_a_diff_names_its_file_and_what_happens_to_it():
    model = SERVER_REQUESTS["review.diff"].params
    base = _diff_params([_hunk()])
    assert not _parses(model, {k: v for k, v in base.items() if k != "path"}), "the path is required"
    assert not _parses(model, {k: v for k, v in base.items() if k != "kind"}), "the kind is required"
    for kind in ("modify", "new", "delete"):
        assert _parses(model, {**base, "kind": kind})
        assert not _parses(model, {**base, "kind": kind, "old_path": "old.py"}), kind
    assert _parses(model, {**base, "kind": "rename", "old_path": "old.py"})
    assert not _parses(model, {**base, "kind": "rename"}), "a rename names its old path"
    assert not _parses(model, {**base, "kind": "move"}) and not _parses(model, {**base, "kind": "Modify"})
    assert not _parses(model, {**base, "kind": "rename", "old_path": ""})
    assert not _parses(model, {**base, "kind": "rename", "old_path": "o" * 301})
    assert not _parses(model, {**base, "kind": "rename", "old_path": "o\nld"})


@pytest.mark.parametrize("hunk_id, ok", [("h1", True), ("h200", True), ("h999", True), ("h0", False), ("h01", False),
                                         ("h1000", False), ("H1", False), ("h", False), ("h1\n", False), ("1", False)])
def test_a_hunk_id_is_h_and_a_number(hunk_id, ok):
    model = SERVER_REQUESTS["review.diff"]
    assert _parses(model.params, _diff_params([_hunk(hunk_id)])) is ok
    assert _parses(model.result, {"decision": "approved", "hunks": {hunk_id: "approved"}}) is ok


@pytest.mark.parametrize("line, ok", [
    (" ", True), ("+", True), ("-", True), ("+x", True), ("\\ No newline at end of file", True),
    ("\\ No newline", False), ("", False), ("x", False), ("?x", False), ("+a\nb", False), ("+a\rb", False),
    ("+a\x0bb", False), ("+a\x0cb", False), ("+a\x85b", False), ("+a b", False), ("+a b", False),
    ("+a\n", False),
])
def test_a_hunk_line_is_a_marker_and_one_line(line, ok):
    assert _parses(SERVER_REQUESTS["review.diff"].params, _diff_params([_hunk(lines=[line])])) is ok


@pytest.mark.parametrize("header, ok", [
    ("@@ -1 +1 @@", True), ("@@ -1,2 +3,4 @@", True), ("@@ -0,0 +1,2 @@ def f(x):", True), ("@@ -1 +1 @@ ", True),
    ("@@ -1 +1 @@x", False), ("@@ -1 +1", False), ("@@@ -1 -1 +1 @@@", False), ("@@ -a +1 @@", False),
    ("@@ -1 +1 @@ a\nb", False), ("@@ -1 +1 @@\n", False), (" @@ -1 +1 @@", False),
])
def test_a_hunk_header_is_a_hunk_header(header, ok):
    assert _parses(SERVER_REQUESTS["review.diff"].params, _diff_params([_hunk(header=header)])) is ok


def test_a_diff_result_has_every_key_closed():
    result = SERVER_REQUESTS["review.diff"].result
    good = {"decision": "approved", "hunks": {"h1": "approved"}}
    assert _parses(result, good)
    for bad in ({**good, "comment": "x"}, {**good, "text": "x"}, {"decision": "approved"}, {"hunks": good["hunks"]},
                {"decision": "approved", "hunks": {}}, {"decision": "approved", "hunks": {"h1": True}},
                {"decision": "approved", "hunks": {"h1": "approved", "h2": "approved\n"}},
                {"decision": "approved", "hunks": {f"h{n}": "approved" for n in range(1, 202)}}):
        assert not _parses(result, bad), bad
    assert _parses(result, {"decision": "rejected", "hunks": {f"h{n}": "rejected" for n in range(1, 201)}})


@pytest.mark.parametrize("anchor, ok", [("start", True), ("end", True), ("both", True), (None, True), ("middle", False),
                                        ("", False), ("End", False), (["end"], False)])
def test_a_hunk_anchor_is_start_end_or_both(anchor, ok):
    model = SERVER_REQUESTS["review.diff"].params
    hunk = {**_hunk(), "anchor": anchor}
    assert _parses(model, _diff_params([hunk])) is ok
    assert _parses(model, _diff_params([_hunk()])), "the anchor is optional"


def test_only_the_last_hunk_can_be_anchored_at_the_end():
    model = SERVER_REQUESTS["review.diff"].params
    first, last = _hunk("h1"), _hunk("h2")
    for anchor in ("end", "both"):
        assert not _parses(model, _diff_params([{**first, "anchor": anchor}, last])), anchor
        assert _parses(model, _diff_params([first, {**last, "anchor": anchor}])), anchor
    assert _parses(model, _diff_params([{**first, "anchor": "start"}, last]))
    assert _parses(model, _diff_params([{**first, "anchor": "start"}, {**last, "anchor": "both"}]))
    assert _parses(model, _diff_params([{**first, "anchor": "end"}])), "a single hunk is the last one"


# ── input.signature and the device requests ─────────────────────────────────────────────────────


def _env(**extra) -> dict:
    return {"session_id": "s_example", "v": 1, "title": "T", "summary": "S", "expires_at": 0, "optional": True, **extra}


UPLOAD2 = {"dir": "/w/uploads/hermie/2026-10-04", "max_bytes": 1048576, "max_total_bytes": 2097152, "max_files": 2,
           "strip_metadata": False}
PNG = {"path": "/w/uploads/hermie/2026-10-04/aa-s.png", "name": "s.png", "mime": "image/png", "bytes": 1,
       "sha256": "0" * 64}
SVG = {**PNG, "path": "/w/uploads/hermie/2026-10-04/bb-s.svg", "name": "s.svg", "mime": "image/svg+xml"}


def test_the_phase_three_methods_are_interactive_and_in_the_contract_in_this_order():
    assert INTERACTIVE_METHODS[4:] == ("input.signature", "device.location", "device.contact", "device.calendar",
                                       "device.scan")
    assert list(EXAMPLES["methods"]) == list(INTERACTIVE_METHODS)


def test_a_signature_is_a_bounded_statement_and_two_files():
    params, result = SERVER_REQUESTS["input.signature"].params, SERVER_REQUESTS["input.signature"].result
    assert _parses(params, _env(statement="x" * 500, upload=UPLOAD2))
    assert not _parses(params, _env(statement="x" * 501, upload=UPLOAD2))
    assert not _parses(params, _env(statement="", upload=UPLOAD2))
    assert _parses(params, _env(statement="x", signer_name="n" * 80, upload=UPLOAD2))
    assert not _parses(params, _env(statement="x", signer_name="n" * 81, upload=UPLOAD2))
    assert not _parses(params, _env(statement="x", signer_name="a\nb", upload=UPLOAD2))
    assert not _parses(params, _env(statement="x", upload={**UPLOAD2, "max_files": 1}))
    good = {"status": "answered", "files": [PNG, SVG], "signed_at": 0, "statement_sha256": "a" * 64}
    assert _parses(result, good)
    for bad in ({**good, "files": [PNG]}, {**good, "files": [PNG, SVG, SVG]}, {**good, "signed_at": -1},
                {**good, "signed_at": 1.5}, {**good, "signed_at": True}, {**good, "statement_sha256": "A" * 64},
                {**good, "statement_sha256": "a" * 63}, {**good, "statement_sha256": "a" * 64 + "\n"},
                {**good, "text": "x"}):
        assert not _parses(result, bad), bad


def test_a_location_is_bounded_numbers_and_never_text():
    params, result = SERVER_REQUESTS["device.location"].params, SERVER_REQUESTS["device.location"].result
    assert _parses(params, _env(precision="approximate")) and _parses(params, _env(precision="precise"))
    assert not _parses(params, _env(precision="exact")) and not _parses(params, _env())
    good = {"status": "answered", "lat": 0, "lon": 0, "accuracy_m": 0, "at": 0, "precision": "precise"}
    assert _parses(result, good)
    assert _parses(result, {**good, "lat": 90, "lon": 180, "accuracy_m": 10_000_000})
    assert _parses(result, {**good, "lat": -90, "lon": -180})
    for bad in ({**good, "lat": 90.0001}, {**good, "lat": -90.0001}, {**good, "lon": 180.0001},
                {**good, "lon": -180.0001}, {**good, "accuracy_m": -0.1}, {**good, "accuracy_m": 10_000_001},
                {**good, "lat": "1"}, {**good, "lat": True}, {**good, "lat": None}, {**good, "at": -1},
                {**good, "at": 1.0}, {**good, "precision": "exact"}, {**good, "altitude": 1}):
        assert not _parses(result, bad), bad


def test_a_contact_asks_for_one_to_six_distinct_fields_and_is_bounded():
    params, result = SERVER_REQUESTS["device.contact"].params, SERVER_REQUESTS["device.contact"].result
    every = ["name", "phones", "emails", "postal", "birthday", "organization"]
    assert _parses(params, _env(fields=every)) and _parses(params, _env(fields=["name"]))
    assert not _parses(params, _env(fields=[])) and not _parses(params, _env(fields=every + ["name"]))
    assert not _parses(params, _env(fields=["name", "name"])) and not _parses(params, _env(fields=["nickname"]))
    contact = lambda **c: {"status": "answered", "contact": c}  # noqa: E731
    assert _parses(result, contact())     # the model takes it; ``contact:empty`` is the validator's
    assert _parses(result, contact(phones=["1"] * 5, emails=["e@x.nl"] * 5, postal=["a"] * 3, name="n" * 200,
                                   organization="o" * 200, birthday="--02-29"))
    for bad in (contact(phones=["1"] * 6), contact(emails=["e"] * 6), contact(postal=["a"] * 4),
                contact(name="n" * 201), contact(phones=["1" * 41]), contact(emails=["e" * 255]),
                contact(postal=["a" * 301]), contact(name=""), contact(phones=[""]), contact(birthday="2026-13-01"),
                contact(birthday="2026-00-10"), contact(birthday="2026-01-32"), contact(birthday="--1-1"),
                contact(birthday="2026-02-03\n"), contact(nickname="x")):
        assert not _parses(result, bad), bad


def test_a_calendar_item_is_bounded_and_consistent():
    params = SERVER_REQUESTS["device.calendar"].params
    timed = {"title": "T", "start": "2026-10-12T09:30+02:00", "end": "2026-10-12T10:00:30+02:00"}
    assert _parses(params, _env(kind="event", item=timed))
    assert _parses(params, _env(kind="event", item={"title": "T"}))
    assert _parses(params, _env(kind="reminder", item={"title": "T", "start": "2026-10-12T09:30+02:00",
                                                       "alarm_minutes": 40320}))
    assert _parses(params, _env(kind="event", item={"title": "T", "all_day": True, "start": "2026-10-12",
                                                    "end": "2026-10-12"}))
    for url in ("https://example.com", "http://example.com/a@b", "https://example.com?mail=a@b.nl",
                "https://example.com#@x", "https://\u00e9xample.nl/caf\u00e9"):
        assert _parses(params, _env(kind="event", item={"title": "T", "url": url})), url
    assert _parses(params, _env(kind="event", item={"title": "T" * 120, "notes": "n" * 2000, "location": "l" * 200,
                                                    "url": "https://example.com/" + "a" * 270}))
    for bad in ({"title": "T" * 121}, {"title": "T", "notes": "n" * 2001}, {"title": "T", "location": "l" * 201},
                {"title": "T", "url": "https://example.com/" + "a" * 290}, {"title": "T", "url": "ftp://x"},
                {"title": "T", "url": "https://x y"}, {"title": "T", "url": "https://x\ny"},
                {"title": "T", "url": "https://bank.nl@evil.example/"}, {"title": "T", "url": "https://user:pw@host/"},
                {"title": "T", "url": "https://@host/"}, {"title": "T", "url": "https://a.nl\\@b.nl/"}, {"title": "T", "url": "https://a.nl\u202e/x"},
                {"title": "T", "url": "https://a\u200b.nl/"}, {"title": "T", "url": "https://\u2066a.nl/"},
                {"title": "T", "url": "https://a.nl/\ue000"}, {"title": "T", "url": "https://a.nl/\u00ad"},
                {"title": "T", "url": "https://a.nl/\ufeff"}, {"title": "T", "url": "https:///path"},
                {"title": "T", "alarm_minutes": 5}, {"title": "T", "alarm_minutes": True, **timed},
                {**timed, "alarm_minutes": 40321}, {**timed, "alarm_minutes": 1.5},
                {**timed, "end": "2026-10-12T09:00+02:00"}, {"title": "T", "end": timed["end"]},
                {**timed, "all_day": True}, {"title": "T", "all_day": True, "start": "2026-02-30"},
                {**timed, "start": "2026-10-12T09:30Z"}, {**timed, "start": "2026-10-12T25:30+02:00"},
                {**timed, "start": "2026-10-12T09:30+02:00\n"}, {**timed, "tz": "Europe/Amsterdam"}):
        assert not _parses(params, _env(kind="event", item=bad)), bad
    assert not _parses(params, _env(kind="reminder", item=timed)), "a reminder has no end"
    assert not _parses(params, _env(kind="task", item=timed))


def test_a_scan_asks_for_distinct_known_symbologies_and_is_bounded():
    params, result = SERVER_REQUESTS["device.scan"].params, SERVER_REQUESTS["device.scan"].result
    every = ["qr", "ean13", "ean8", "code128", "pdf417", "datamatrix", "aztec"]
    assert _parses(params, _env()) and _parses(params, _env(formats=every)) and _parses(params, _env(formats=["qr"]))
    for bad in ([], every + ["qr"], ["qr", "qr"], ["upc"], "qr"):
        assert not _parses(params, _env(formats=bad)), bad
    assert _parses(result, {"status": "answered", "value": "x" * 4096, "symbology": "qr"})
    for bad in ({"status": "answered", "value": "x" * 4097, "symbology": "qr"},
                {"status": "answered", "value": "", "symbology": "qr"},
                {"status": "answered", "value": "x", "symbology": "upc"}, {"status": "answered", "value": "x"},
                {"status": "answered", "symbology": "qr"}):
        assert not _parses(result, bad), bad


def test_the_calendar_result_has_its_own_status():
    result = SERVER_REQUESTS["device.calendar"].result
    assert _parses(result, {"status": "done"}) and _parses(result, {"status": "skipped"})
    for bad in ({"status": "answered"}, {"status": "done", "id": "x"}, {}, {"status": "Done"}):
        assert not _parses(result, bad), bad


def test_a_clients_clock_is_bounded_to_what_a_json_number_holds():
    big = 2**53
    loc = SERVER_REQUESTS["device.location"].result
    good = {"status": "answered", "lat": 0, "lon": 0, "accuracy_m": 0, "at": big, "precision": "precise"}
    assert _parses(loc, good) and not _parses(loc, {**good, "at": big + 1})
    sig = SERVER_REQUESTS["input.signature"].result
    ok = {"status": "answered", "files": [PNG, SVG], "signed_at": big, "statement_sha256": "a" * 64}
    assert _parses(sig, ok) and not _parses(sig, {**ok, "signed_at": big + 1})
