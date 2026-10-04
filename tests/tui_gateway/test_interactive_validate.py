"""The answer checks of the interactive requests (``tui_gateway/interactive_validate.py``, plan ``request-types-v2``
task P1-F4) against the contract's examples (``contract/requests/examples.json``, normative): every valid answer
passes, every invalid one is refused with exactly the reason the contract names (the shared ``validator_cases()``),
and the edges the examples cannot list: whole-value matching (a trailing newline never passes), ISO 4217 decimals
per currency, datetime values (offset, zone, DST gaps and overlaps, no ``Z``, no fractions, the zone suffix
required), lexical path containment, draft normalisation and a validator that never raises.
"""

from __future__ import annotations

import copy

import pytest

from tests.tui_gateway.contracts.test_requests_contract import EXAMPLES, REASONS, _frames, validator_cases
from tui_gateway import currency_units, interactive_validate as v
from tui_gateway.contracts.server_requests import INTERACTIVE_METHODS


def _field_params(*fields, optional=True):
    return {"session_id": "s", "v": 1, "title": "T", "summary": "S", "expires_at": 0, "optional": optional,
            "fields": list(fields)}


def _answer(**values):
    return {"status": "answered", "values": values}


def _problem(field, value):
    return v.validate_answer("input.form", _field_params(field), _answer(**{field["id"]: value}))


# ── the contract's examples ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", validator_cases(), ids=lambda c: f"{c[0]}:{c[3]}")
def test_every_invalid_example_is_refused_with_exactly_its_reason(case):
    method, params, result, reason = case
    assert v.validate_answer(method, params, result) == reason
    assert REASONS[method].fullmatch(reason)


@pytest.mark.parametrize("method", INTERACTIVE_METHODS)
def test_every_valid_example_answer_passes(method):
    frames = _frames(method)
    answers = EXAMPLES["methods"][method]["answers"]
    assert answers
    for answer in answers:
        assert v.validate_answer(method, frames[answer["request"]]["params"], answer["result"]) is None, \
            answer["name"]


@pytest.mark.parametrize("entry", EXAMPLES["form_fields"], ids=lambda e: e["name"])
def test_every_valid_form_field_value_passes(entry):
    for value in entry["valid"]:
        assert _problem(entry["field"], value) is None, (entry["name"], value)


def test_model_layer_invalid_examples_are_bad_shape():
    for method in INTERACTIVE_METHODS:
        frames = _frames(method)
        for case in EXAMPLES["methods"][method]["invalid_answers"]:
            if case["layer"] == "model":
                assert v.validate_answer(method, frames[case["request"]]["params"], case["result"]) == "bad_shape"


# ── whole values, never a prefix ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("field, value", [
    ({"id": "d", "kind": "date", "label": "D"}, "2026-10-05\n"),
    ({"id": "t", "kind": "time", "label": "T"}, "14:30\n"),
    ({"id": "a", "kind": "amount", "label": "A", "currency": "EUR"}, "12.50\n"),
    ({"id": "w", "kind": "datetime", "label": "W", "tz": "Europe/Amsterdam"},
     "2026-10-07T14:30+02:00[Europe/Amsterdam]\n"),
    ({"id": "r", "kind": "daterange", "label": "R"}, {"start": "2026-10-05\n", "end": "2026-10-06"}),
])
def test_a_trailing_newline_never_passes_a_whole_value_check(field, value):
    assert _problem(field, value) == f"field:{field['id']}:format"


def test_a_form_key_that_is_no_field_id_is_bad_shape_and_never_echoed():
    field = {"id": "name", "kind": "text", "label": "Name"}
    for key in ("Name", "na me", "x" * 40, "name\n", ""):
        assert v.validate_answer("input.form", _field_params(field), _answer(**{key: "x"})) == "bad_shape"


# ── amounts: the currency's minor unit ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("currency, value, ok", [
    ("EUR", "12.50", True), ("EUR", "12.5", True), ("EUR", "12", True), ("EUR", "12.505", False),
    ("JPY", "1500", True), ("JPY", "1500.0", False), ("JPY", "1500.5", False),
    ("KWD", "1.250", True), ("KWD", "1.2505", False),
    ("CLF", "1.250", True),          # four decimals in ISO 4217, but the contract's value format stops at three
    ("XXX", "1.25", True), ("XXX", "1.250", False),  # not in the table: the usual two
])
def test_amount_decimals_follow_the_iso_4217_exponent(currency, value, ok):
    field = {"id": "p", "kind": "amount", "label": "P", "currency": currency}
    assert _problem(field, value) == (None if ok else "field:p:format")


def test_the_currency_table_has_the_exponents_that_matter():
    assert [currency_units.exponent(c) for c in ("EUR", "USD", "JPY", "KRW", "KWD", "BHD", "CLF", "ISK")] == \
        [2, 2, 0, 0, 3, 3, 4, 0]
    assert currency_units.exponent("XAU") is None and currency_units.exponent("eur") is None


def test_amount_bounds_compare_as_decimals_not_text():
    field = {"id": "p", "kind": "amount", "label": "P", "currency": "EUR", "min": "9.99", "max": "100"}
    assert _problem(field, "10") is None
    assert _problem(field, "9.98") == "field:p:below_min"
    assert _problem(field, "100.01") == "field:p:above_max"
    assert _problem(field, 10) == "field:p:type" and _problem(field, 10.5) == "field:p:type"


# ── datetime values ─────────────────────────────────────────────────────────────────────────────

AMS = {"id": "w", "kind": "datetime", "label": "W", "tz": "Europe/Amsterdam"}
DEVICE = {"id": "w", "kind": "datetime", "label": "W"}


@pytest.mark.parametrize("value", [
    "2026-10-07T14:30+02:00[Europe/Amsterdam]",      # seconds are optional
    "2026-10-07T14:30:00+02:00[Europe/Amsterdam]",
    "2026-10-25T02:30+02:00[Europe/Amsterdam]",      # the overlap: both offsets are real
    "2026-10-25T02:30+01:00[Europe/Amsterdam]",
])
def test_datetime_values_with_the_zone_suffix_pass(value):
    assert _problem(AMS, value) is None


@pytest.mark.parametrize("value, reason", [
    ("2026-10-07T14:30:00+02:00", "format"),                      # the suffix is required
    ("2026-10-07T12:30:00Z[Europe/Amsterdam]", "format"),         # no Z
    ("2026-10-07T14:30:00.5+02:00[Europe/Amsterdam]", "format"),  # no fractions
    ("2026-10-07 14:30+02:00[Europe/Amsterdam]", "format"),
    ("2026-02-30T14:30+01:00[Europe/Amsterdam]", "format"),       # a date that only looks like one
    ("2026-10-07T14:30+02:00[]", "format"),
    ("2026-10-07T14:30+02:00[Europe/Amsterdam]x", "format"),
    ("2026-10-07T14:30+02:00[Europe/Amsterdam", "format"),
    ("2026-10-07T14:30+02:00[Europe/London]", "zone"),            # not the field's zone
    ("2026-10-07T14:30+02:00[Mars/Olympus_Mons]", "zone"),
    ("2026-10-07T14:30+02:00[../../etc/passwd]", "format"),
    ("2026-10-07T14:30+01:00[Europe/Amsterdam]", "offset"),       # CEST is +02:00 in October
    ("2026-03-29T02:30+01:00[Europe/Amsterdam]", "offset"),       # the spring-forward gap: that hour never was
    ("2026-03-29T02:30+02:00[Europe/Amsterdam]", "offset"),
    ("2026-10-07T14:30+02:00[Europe/Amsterdam]\n", "format"),
])
def test_datetime_values_that_do_not_hold(value, reason):
    assert _problem(AMS, value) == f"field:w:{reason}"


def test_a_datetime_field_without_tz_takes_any_known_zone_with_its_own_offset():
    assert _problem(DEVICE, "2026-10-07T08:30:00-04:00[America/New_York]") is None
    assert _problem(DEVICE, "2026-10-07T08:30:00-05:00[America/New_York]") == "field:w:offset"
    assert _problem(DEVICE, "2026-10-07T08:30:00-04:00[America/Nowhere]") == "field:w:zone"


def test_datetime_bounds_are_instants_not_wall_clock_text():
    field = {**AMS, "min": "2026-10-07T12:00:00+00:00", "max": "2026-10-07T13:00:00+00:00"}
    # 14:30+02:00 is 12:30 UTC: inside, although "14:30" sorts after "13:00" as text.
    assert _problem(field, "2026-10-07T14:30+02:00[Europe/Amsterdam]") is None
    assert _problem(field, "2026-10-07T15:01+02:00[Europe/Amsterdam]") == "field:w:above_max"
    assert _problem(field, "2026-10-07T15:00:00+02:00[Europe/Amsterdam]") is None  # 13:00 UTC, inclusive
    assert _problem(field, "2026-10-07T13:59:59+02:00[Europe/Amsterdam]") == "field:w:below_min"


def test_instants_have_a_numeric_offset_and_optional_seconds_only():
    assert v.parse_instant("2026-10-03T14:30+02:00").utcoffset().total_seconds() == 7200
    assert v.parse_instant("2026-10-03T14:30:15-03:30") is not None
    for bad in ("2026-10-03T14:30Z", "2026-10-03T14:30:00.1+02:00", "2026-10-03T14:30", "2026-13-03T14:30+02:00"):
        assert v.parse_instant(bad) is None


# ── other kinds, at their edges ─────────────────────────────────────────────────────────────────


def test_required_and_empty_values():
    text = {"id": "n", "kind": "text", "label": "N", "required": True}
    assert _problem(text, "") == "field:n:missing"
    assert v.validate_answer("input.form", _field_params(text), _answer()) == "field:n:missing"
    optional = {**text, "required": False}
    assert _problem(optional, "") is None
    assert v.validate_answer("input.form", _field_params(optional), _answer()) is None
    many = {"id": "c", "kind": "choice", "label": "C", "multiple": True, "required": True,
            "options": [{"value": "a", "label": "A"}]}
    assert _problem(many, []) == "field:c:missing"
    one = {**many, "multiple": False}
    assert _problem(one, []) == "field:c:type"  # [] is "no value" for a multiple choice only


def test_numbers_are_json_numbers_in_range_whole_and_on_the_step():
    field = {"id": "n", "kind": "number", "label": "N", "min": 1, "max": 10, "step": 0.5}
    assert _problem(field, 1.5) is None and _problem(field, 2) is None
    assert _problem(field, 1.7) == "field:n:step"
    for bad in (True, "3", None, [3]):
        assert _problem(field, bad) in ("field:n:type", "bad_shape")
    assert _problem(field, float("nan")) == "field:n:type"
    assert _problem(field, float("inf")) == "field:n:type"
    whole = {"id": "n", "kind": "number", "label": "N", "integer": True}
    assert _problem(whole, 2.0) is None and _problem(whole, 2.5) == "field:n:not_integer"


def test_text_length_is_counted_in_code_points_and_one_line_unless_multiline():
    field = {"id": "n", "kind": "text", "label": "N", "max_length": 3}
    assert _problem(field, "\U0001F600" * 3) is None  # three code points
    assert _problem(field, "\U0001F600" * 4) == "field:n:too_long"
    for sep in ("\n", "\r", " ", "\x85", "\x0b"):
        assert _problem(field, "a" + sep + "b") == "field:n:format"
    assert _problem({**field, "multiline": True}, "a\nb") is None
    assert _problem({"id": "n", "kind": "text", "label": "N"}, "x" * 4001) == "field:n:too_long"


def test_daterange_checks_order_then_bounds():
    field = {"id": "r", "kind": "daterange", "label": "R", "min": "2026-10-05", "max": "2026-12-31"}
    assert _problem(field, {"start": "2026-10-05", "end": "2026-12-31"}) is None
    assert _problem(field, {"start": "2027-01-02", "end": "2026-10-01"}) == "field:r:order"
    assert _problem(field, {"start": "2026-10-01", "end": "2026-10-04"}) == "field:r:below_min"
    assert _problem(field, {"start": "2026-02-30", "end": "2026-03-01"}) == "field:r:format"
    assert _problem(field, {"start": "2026-10-06"}) == "bad_shape"


def test_choice_values_are_not_labels_and_selection_counts_hold():
    field = {"id": "x", "kind": "choice", "label": "X", "multiple": True, "min_selected": 1, "max_selected": 2,
             "options": [{"value": "a", "label": "Apple"}, {"value": "b", "label": "Beta"},
                         {"value": "c", "label": "Gamma"}]}
    assert _problem(field, ["a"]) is None
    assert _problem(field, ["Apple"]) == "field:x:not_an_option"
    assert _problem(field, ["a", "a"]) == "field:x:duplicate"
    assert _problem(field, ["a", "b", "c"]) == "field:x:too_many"


def test_the_first_problem_is_reported_unknown_keys_first_then_fields_in_order():
    first = {"id": "a", "kind": "number", "label": "A", "required": True}
    second = {"id": "b", "kind": "number", "label": "B", "required": True}
    params = _field_params(first, second)
    assert v.validate_answer("input.form", params, _answer()) == "field:a:missing"
    assert v.validate_answer("input.form", params, _answer(b=1)) == "field:a:missing"
    assert v.validate_answer("input.form", params, _answer(a=1, zzz=1)) == "field:zzz:unknown"
    assert v.validate_answer("input.form", params, _answer(a="x", b="y")) == "field:a:type"


def test_shape_is_checked_before_not_optional():
    params = _field_params({"id": "a", "kind": "toggle", "label": "A"}, optional=False)
    assert v.validate_answer("input.form", params, {"status": "skipped", "values": {}}) == "bad_shape"
    assert v.validate_answer("input.form", params, {"status": "skipped"}) == "not_optional"
    assert v.validate_answer("input.form", {**params, "optional": True}, {"status": "skipped"}) is None
    assert v.validate_answer("input.nothing", params, {"status": "skipped"}) == "bad_shape"


# ── files: lexical containment, counts and sizes ────────────────────────────────────────────────

DIR = "/home/ada/work/uploads/hermie/2026-10-04"
SHA = "a" * 64


def _file_params(**upload):
    base = {"dir": DIR, "max_bytes": 1_000, "max_total_bytes": 1_500, "max_files": 3, "strip_metadata": True}
    return {"session_id": "s", "v": 1, "title": "T", "summary": "S", "expires_at": 0, "optional": False,
            "accept": "any", "multiple": True, "upload": {**base, **upload}}


def _files(*entries):
    return {"status": "answered",
            "files": [{"path": p, "name": "f", "mime": "text/plain", "bytes": b, "sha256": SHA} for p, b in entries]}


@pytest.mark.parametrize("path", [
    DIR + "/0123456789abcdef-a.txt",
    DIR + "/./0123456789abcdef-a.txt",
    DIR + "//0123456789abcdef-a.txt",
    DIR + "/sub/../0123456789abcdef-a.txt",
])
def test_paths_under_the_dir_pass_after_lexical_resolution(path):
    assert v.validate_answer("input.file", _file_params(), _files((path, 10))) is None


@pytest.mark.parametrize("path", [
    DIR, DIR + "/", DIR + "/..", DIR + "/../x.txt", DIR + "/../../etc/passwd",
    DIR + "-evil/x.txt", "/home/ada/work/uploads/hermie/x.txt", "/x", "/..", "//",
    "/home/ada/work/uploads/hermie/2026-10-04x/x.txt",
])
def test_paths_outside_the_dir_are_refused(path):
    assert v.validate_answer("input.file", _file_params(), _files((path, 10))) == "file:0:outside_dir"


def test_file_counts_sizes_and_totals():
    ok = DIR + "/0123456789abcdef-a.txt"
    params = _file_params()
    assert v.validate_answer("input.file", params, _files((ok, 1_000), (ok, 500))) is None
    assert v.validate_answer("input.file", params, _files((ok, 1_001))) == "file:0:too_large"
    assert v.validate_answer("input.file", params, _files((ok, 1_000), (ok, 501))) == "files:too_large"
    assert v.validate_answer("input.file", params, _files((ok, 1), (ok, 1), (ok, 1), (ok, 1))) == "files:too_many"
    single = {**params, "multiple": False}
    assert v.validate_answer("input.file", single, _files((ok, 1), (ok, 1))) == "files:too_many"
    # The first problem, in file order: the count, then each file (outside_dir before too_large), then the total.
    assert v.validate_answer("input.file", params, _files((ok, 2_000), ("/x/y", 1))) == "file:0:too_large"
    assert v.validate_answer("input.file", params, _files((ok, 1), ("/x/y", 5_000))) == "file:1:outside_dir"


# ── drafts ──────────────────────────────────────────────────────────────────────────────────────


def _draft(text="Hello Bram,\n\nThanks.", *, editable=True):
    return {"session_id": "s", "v": 1, "title": "T", "summary": "S", "expires_at": 0, "optional": False,
            "kind": "mail", "text": text, "editable": editable}


def _approved(text):
    return {"decision": "approved", "text": text}


def test_trailing_whitespace_goes_and_everything_else_that_cannot_be_shown_is_refused():
    params = _draft()
    assert v.validate_answer("review.draft", params, _approved("Hello Bram,  \n\nThanks.  \n\n")) is None
    for bad in ("Hello\tBram", "Hello ‮Bram", "Hello​Bram", "Hello Bram", "Hello\x00Bram",
                "Hello\rBram", "a" + " " * 40 + "b"):
        assert v.validate_answer("review.draft", params, _approved(bad)) == "text:not_verbatim", repr(bad)
    # Nothing left after the trailing whitespace goes: not an approval of anything.
    assert v.validate_answer("review.draft", params, _approved(" \n \n")) == "text:not_verbatim"


def test_a_locked_draft_accepts_only_its_own_text_apart_from_trailing_whitespace():
    params = _draft(editable=False)
    assert v.validate_answer("review.draft", params, _approved("Hello Bram,\n\nThanks.")) is None
    assert v.validate_answer("review.draft", params, _approved("Hello Bram,  \n\nThanks.\n")) is None
    assert v.validate_answer("review.draft", params, _approved("Hello Bram,\n\nThanks!")) == "text:edited"
    assert v.validate_answer("review.draft", params, {"decision": "rejected"}) is None
    assert v.validate_answer("review.draft", params, {"decision": "rejected", "comment": "No."}) is None


def test_strip_line_ends():
    assert v.strip_line_ends("a  \r\nb\t \n\n") == "a\nb"
    assert v.strip_line_ends("  a") == "  a"


# ── the validator never raises under the request lock ───────────────────────────────────────────


def test_garbage_is_refused_never_raised():
    params = _field_params({"id": "w", "kind": "datetime", "label": "W", "min": "garbage"},
                           {"id": "n", "kind": "number", "label": "N"})
    for result in ({}, {"status": "answered"}, {"status": "answered", "values": {"w": "2026-10-07T14:30+02:00[UTC]"}},
                   {"status": "answered", "values": {"n": [1, 2]}}, {"status": 5}, {"status": "answered", "values": 1},
                   {"decision": "approved", "text": None}):
        assert isinstance(v.validate_answer("input.form", params, result), str)
    assert isinstance(v.validate_answer("input.file", {}, {"status": "skipped"}), (str, type(None)))
    assert v.validate_answer("review.draft", {}, {"decision": "approved", "text": "x"}) is None


def test_the_examples_are_not_mutated_by_checking_them():
    before = copy.deepcopy(EXAMPLES)
    for method, params, result, reason in validator_cases():
        v.validate_answer(method, params, result)
    assert EXAMPLES == before


# ── time zones: one read per zone, outside the request lock ─────────────────────────────────────


@pytest.fixture()
def counted_zones(monkeypatch):
    """``ZoneInfo`` construction counted per name, the strong cache emptied for the test."""
    reads: list[str] = []
    real = v.ZoneInfo

    def counting(name):
        reads.append(name)
        return real(name)

    monkeypatch.setattr(v, "ZoneInfo", counting)
    monkeypatch.setattr(v, "_zones", {})
    return reads


def test_a_zone_is_read_once_and_then_kept(counted_zones):
    assert v.zone("Europe/Amsterdam") is v.zone("Europe/Amsterdam") is not None
    assert counted_zones == ["Europe/Amsterdam"]
    # a name the host does not know is neither read nor kept: the cache stays bounded by the known zones
    assert v.zone("Mars/Olympus_Mons") is None and v.zone("../../etc/passwd") is None
    assert counted_zones == ["Europe/Amsterdam"] and set(v._zones) == {"Europe/Amsterdam"}


def test_warm_loads_the_zones_an_answer_names_and_nothing_else(counted_zones):
    params = _field_params({"id": "at", "kind": "datetime", "label": "At"},
                           {"id": "note", "kind": "text", "label": "Note"})
    check = v.validator("input.form", params)
    answer = _answer(at="2026-10-07T08:30-04:00[America/New_York]", note="x[Europe/Paris]")
    check.warm(answer)
    assert counted_zones == ["America/New_York"]
    assert check(answer) is None and counted_zones == ["America/New_York"], "the check under the lock reads nothing"
    for junk in (None, [], {"values": "x"}, {"values": {"at": 5}}, _answer(at="2026-10-07T08:30-04:00[Nowhere/X]")):
        check.warm(junk)  # never raises, reads nothing it does not know
    assert counted_zones == ["America/New_York"]
    v.validator("review.draft", {"text": "x"}).warm({"decision": "approved", "text": "x"})


def test_a_datetime_field_is_refused_on_a_host_without_a_time_zone_database(monkeypatch):
    from tui_gateway import interactive_fields
    monkeypatch.setattr(v, "_known_zones", frozenset())
    with pytest.raises(ValueError, match=r"fields\[0\]\.kind: datetime is not available.*tzdata"):
        interactive_fields.build_fields([{"id": "at", "kind": "datetime", "label": "At"}], ValueError)
    # the other kinds still work; a tz on them is refused as unknown
    assert interactive_fields.build_fields([{"id": "on", "kind": "date", "label": "On"}], ValueError)
    with pytest.raises(ValueError, match="tz"):
        interactive_fields.build_fields([{"id": "on", "kind": "date", "label": "On", "tz": "Europe/Amsterdam"}],
                                        ValueError)
