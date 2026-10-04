"""The interactive requests ``input.form``, ``input.file`` and ``review.draft`` as the agent's tools use them
(``tui_gateway/interactive.py``, plan ``request-types-v2`` task P1-F4): the params builders, the request (outcomes,
audit, limits), the post-settle file verification and the review register's hand-off.

What is pinned here: every builder cleans, bounds and refuses (over-long, empty and control text never goes out, a
draft is checked verbatim, a bad field definition says which field); the params the builders make are valid frames
of the contract; ``upload.dir`` lies under the session's working directory and is created there without following
a link (a link below the working directory is ``unavailable (upload_dir_unsafe)``); an answered request returns what
the person entered and nothing the client claimed (``edited`` is the gateway's); every way of not getting an answer
is ``unavailable`` or ``timeout`` (an app's listed ``cannot_show`` reason passes through); files are checked on disk
after the request settled without following a link (missing, size, hash, escape, a link, a swapped parent, not a
regular file, total) and become ``unavailable (bad_upload)``, never an answer; ``ref_text`` is what ``file.attach``
gives where it can be quoted; the window counts only a request that opened; one open request and twelve per window per conversation, apart from ``confirm``; the hooks
are fired once, by ``send_gated``; the audit records name ids, never text; no logger ever sees a title, value,
path or draft. Every payload is a harmless marker.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path

import pytest

from tests.tui_gateway.test_server_requests_gate import (  # noqa: F401 - fixtures are used by name
    ROBIN, SAM, _WS, _as, _caps, _frame, _rpc, _session, cancels, clock, server)
from tui_gateway.contracts.registry import SERVER_REQUESTS

MARKER = "MARKER-TEXT-7"
METHODS = ("input.form", "input.file", "review.draft")


@pytest.fixture(autouse=True)
def audit_records(monkeypatch):
    """Capture the dashboard audit records instead of writing them to disk; reset the module's state."""
    from tui_gateway import interactive, review_register
    records: list[tuple[str, dict]] = []
    monkeypatch.setattr(interactive, "_audit_sink", lambda event, **fields: records.append((event, fields)))
    interactive.reset_for_tests()
    yield records
    interactive.reset_for_tests()
    review_register.reset_for_tests()


@pytest.fixture()
def build(server, tmp_path):
    """``interactive``'s builders bound to a live session ``s1`` (creator ROBIN), cwd a temp dir (the file builder
    creates ``uploads/hermie/<date>`` there)."""
    from tui_gateway import interactive
    robin = _WS("robin", ROBIN)
    _session(server, "s1", robin, creator=ROBIN)
    server._sessions["s1"]["cwd"] = str(tmp_path)
    return interactive


def _contract_accepts(method: str, params: dict) -> None:
    SERVER_REQUESTS[method].params.model_validate({"session_id": "s1", **params})


FIELD = {"id": "name", "kind": "text", "label": "Name"}


def _form(build, **kwargs):
    kwargs.setdefault("summary", "Please fill this in.")
    kwargs.setdefault("fields", [FIELD])
    return build.build_form_params("s1", **kwargs)


def _draft(build, **kwargs):
    kwargs.setdefault("summary", "Please read this.")
    kwargs.setdefault("text", "Hello Bram,\n\nThanks.")
    kwargs.setdefault("kind", "mail")
    return build.build_draft_params("s1", **kwargs)


def _file(build, **kwargs):
    kwargs.setdefault("summary", "Please send the receipt.")
    kwargs.setdefault("accept", "image")
    return build.build_file_params("s1", **kwargs)


# ── the builders: envelope ──────────────────────────────────────────────────────────────────────


def test_the_envelope_is_built_by_the_gateway(build):
    before = time.time()
    params = _form(build, title="Booking ‮details", optional=False)
    assert params["v"] == 1 and params["title"] == "Booking details" and params["optional"] is False
    assert before + 299 <= params["expires_at"] <= time.time() + 301
    assert params["acting_user"] == {"id": ROBIN, "name": ROBIN}
    assert "detail" not in params
    _contract_accepts("input.form", params)


def test_optional_defaults_per_method(build):
    assert _form(build)["optional"] is True and _file(build)["optional"] is True
    assert _draft(build)["optional"] is False


def test_no_acting_user_key_when_the_gateway_cannot_name_one(server, build):
    server._sessions["s1"]["auth_user_id"] = None
    assert "acting_user" not in _form(build)


@pytest.mark.parametrize("make", [
    lambda b, **kw: _form(b, **kw), lambda b, **kw: _file(b, **kw), lambda b, **kw: _draft(b, **kw)])
def test_every_builder_refuses_an_empty_or_over_long_summary_and_title(build, make):
    with pytest.raises(build.InteractiveParamsError, match="summary is required"):
        make(build, summary="")
    with pytest.raises(build.InteractiveParamsError, match="summary is required"):
        make(build, summary="‮​ \x00")  # nothing left after cleaning
    with pytest.raises(build.InteractiveParamsError, match="summary is required"):
        make(build, summary=None)
    with pytest.raises(build.InteractiveParamsError, match="summary must be a string"):
        make(build, summary=["x"])
    with pytest.raises(build.InteractiveParamsError, match="summary is 501 characters"):
        make(build, summary="x" * 501)
    with pytest.raises(build.InteractiveParamsError, match="title is 81 characters"):
        make(build, title="t" * 81)
    assert make(build, summary="x" * 500)["summary"] == "x" * 500
    assert make(build, title="t" * 80)["title"] == "t" * 80


@pytest.mark.parametrize("make", [lambda b, **kw: _form(b, **kw), lambda b, **kw: _file(b, **kw)])
def test_text_the_person_sees_is_cleaned_not_passed_through(build, make):
    params = make(build, summary="Payㅤᅟ now‮\x00 please.\r\n\r\n\r\n\r\nThanks", title="ﾠT⠀\n\title")
    assert params["summary"] == "Pay now please.\n\nThanks" and params["title"] == "T itle"
    assert params["title"].isprintable()


def test_detail_is_bounded_and_cleaned(build):
    assert _form(build, detail="a​b\nc")["detail"] == "ab\nc"
    assert "detail" not in _form(build, detail="​")
    with pytest.raises(build.InteractiveParamsError, match="detail is 2001 characters"):
        _form(build, detail="d" * 2001)
    with pytest.raises(build.InteractiveParamsError, match="detail must be a string"):
        _form(build, detail=5)


def test_optional_must_be_a_boolean(build):
    for builder in (_form, _file):
        with pytest.raises(build.InteractiveParamsError, match="optional must be true or false"):
            builder(build, optional="yes")


# ── the builders: input.form ────────────────────────────────────────────────────────────────────


def test_fields_are_cleaned_and_the_frame_is_valid(build):
    params = _form(build, fields=[
        {"id": "name", "kind": "text", "label": "Na‮me", "hint": "Your ​name", "required": True,
         "default": "Ada​\nLovelace", "max_length": 40},
        {"id": "room", "kind": "choice", "label": "Room", "options": ["single", {"value": "dbl", "label": "Dou‮ble"}]},
        {"id": "budget", "kind": "amount", "label": "Budget", "currency": "EUR", "min": 0, "max": "5000.50"},
        {"id": "when", "kind": "datetime", "label": "When", "tz": "Europe/Amsterdam",
         "min": "2026-10-05T00:00+02:00"},
        {"id": "ok", "kind": "toggle", "label": "OK", "default": False},
    ])
    name, room, budget, when, ok = params["fields"]
    assert name["label"] == "Name" and name["hint"] == "Your name" and name["default"] == "Ada Lovelace"
    assert room["options"] == [{"value": "single", "label": "single"}, {"value": "dbl", "label": "Double"}]
    assert budget["min"] == "0" and budget["max"] == "5000.50"
    assert when["tz"] == "Europe/Amsterdam" and ok["default"] is False
    _contract_accepts("input.form", params)


@pytest.mark.parametrize("fields, message", [
    ([], "1 to 12 field objects"),
    ("name", "1 to 12 field objects"),
    ([FIELD] * 2, "used twice"),
    ([{**FIELD, "id": f"f{i}"} for i in range(13)], "13 entries; the limit is 12"),
    (["name"], "fields[0] must be an object"),
    ([{**FIELD, "kind": "color"}], "kind: must be one of"),
    ([{**FIELD, "kind": None}], "kind: must be one of"),
    ([{**FIELD, "kind": ["text"]}], "kind: must be one of"),
    ([{**FIELD, "input": ["email"]}], "input: must be one of"),
    ([{**FIELD, "id": "Name"}], "id: must be lowercase"),
    ([{**FIELD, "id": "n" * 33}], "id: must be lowercase"),
    ([{**FIELD, "id": "name\n"}], "id: must be lowercase"),
    ([{**FIELD, "label": ""}], "label: is empty"),
    ([{**FIELD, "label": "​‮"}], "label: is empty"),
    ([{**FIELD, "label": "l" * 61}], "label: is 61 characters; the limit is 60"),
    ([{**FIELD, "label": 7}], "label: must be a string"),
    ([{k: v for k, v in FIELD.items() if k != "label"}], "label: is required"),
    ([{**FIELD, "hint": "h" * 201}], "hint: is 201 characters; the limit is 200"),
    ([{**FIELD, "required": "yes"}], "required: must be true or false"),
    ([{**FIELD, "multiline": 1}], "multiline: must be true or false"),
    ([{**FIELD, "colour": "red"}], "text fields do not take: colour"),
    ([{**FIELD, "min": 1}], "text fields do not take: min"),
    ([{**FIELD, "max_length": 4001}], "max_length: must be between 1 and 4000"),
    ([{**FIELD, "input": "fax"}], "input: must be one of"),
    ([{**FIELD, "default": 5}], "default: must be a string"),
    ([{**FIELD, "max_length": 3, "default": "abcd"}], "default is longer than max_length"),
    ([{"id": "n", "kind": "number", "label": "N", "min": 5, "max": 1}], "min is greater than max"),
    ([{"id": "n", "kind": "number", "label": "N", "min": True}], "min: must be a number"),
    ([{"id": "n", "kind": "number", "label": "N", "min": float("nan")}], "min: must be a number"),
    ([{"id": "n", "kind": "number", "label": "N", "step": 0}], "step"),
    ([{"id": "n", "kind": "number", "label": "N", "integer": True, "default": 1.5}], "not a whole number"),
    ([{"id": "p", "kind": "amount", "label": "P"}], "currency: is required"),
    ([{"id": "p", "kind": "amount", "label": "P", "currency": "eur"}], "currency: is required"),
    ([{"id": "p", "kind": "amount", "label": "P", "currency": "XXX"}], "not an ISO 4217 currency code"),
    ([{"id": "p", "kind": "amount", "label": "P", "currency": "EUR", "min": 1.5}], 'decimal string such as "12.50"'),
    ([{"id": "p", "kind": "amount", "label": "P", "currency": "EUR", "min": "1,5"}], 'decimal string such as "12.50"'),
    ([{"id": "p", "kind": "amount", "label": "P", "currency": "JPY", "default": "1500.5"}], "more decimals than"),
    ([{"id": "p", "kind": "amount", "label": "P", "currency": "EUR", "default": "1.255"}], "more decimals than"),
    ([{"id": "d", "kind": "date", "label": "D", "min": "2026-02-30"}], "min"),
    ([{"id": "d", "kind": "date", "label": "D", "min": "2026-10-05\n"}], "min"),
    ([{"id": "d", "kind": "date", "label": "D", "tz": "Mars/Base"}], "tz: is not an IANA time zone"),
    ([{"id": "d", "kind": "date", "label": "D", "tz": "../etc"}], "tz: is not an IANA time zone"),
    ([{"id": "w", "kind": "datetime", "label": "W", "min": "2026-10-05T00:00Z"}], "min"),
    ([{"id": "w", "kind": "datetime", "label": "W", "default": "2026-10-05T00:00+02:00[Europe/Amsterdam]"}], "default"),
    ([{"id": "r", "kind": "daterange", "label": "R", "default": {"start": "2026-10-06", "end": "2026-10-05"}}],
     "ends before it starts"),
    ([{"id": "r", "kind": "daterange", "label": "R", "default": {"start": "2026-10-06"}}], "default: must be"),
    ([{"id": "c", "kind": "choice", "label": "C"}], "options: must be a list of 1 to 12"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["a"] * 13}], "13 options; the limit is 12"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["a", "a"]}], "same value"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["a\nb"]}], "options[0].value"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": [" a"]}], "options[0].value"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": [""]}], "options[0].value"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["v" * 65]}], "options[0].value"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": [{"value": "a", "label": "l" * 81}]}],
     "options[0].label"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": [{"value": "a", "extra": 1}]}], "options[0]"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["a"], "default": "b"}], "default is not one option"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["a"], "min_selected": 1}], "need multiple"),
    ([{"id": "c", "kind": "choice", "label": "C", "options": ["a", "b"], "multiple": True, "min_selected": 2,
       "max_selected": 1}], "min_selected is greater"),
    ([{"id": "t", "kind": "toggle", "label": "T", "default": "yes"}], "default: must be true or false"),
])
def test_a_bad_field_definition_is_refused_naming_the_field(build, fields, message):
    with pytest.raises(build.InteractiveParamsError) as raised:
        _form(build, fields=fields)
    assert message in str(raised.value)
    assert "fields" in str(raised.value) or "1 to 12" in str(raised.value)


def test_a_field_error_never_echoes_the_agents_value(build):
    secret = "SECRET-DEFAULT-MARKER"
    with pytest.raises(build.InteractiveParamsError) as raised:
        _form(build, fields=[{"id": "d", "kind": "date", "label": "D", "default": secret}])
    assert secret not in str(raised.value)


def test_a_form_of_twelve_fields_and_every_kind_is_valid(build):
    kinds = [
        {"id": "a", "kind": "text", "label": "A", "input": "email", "multiline": True, "max_length": 100},
        {"id": "b", "kind": "number", "label": "B", "min": 0, "max": 10, "step": 0.5, "default": 1.5},
        {"id": "c", "kind": "amount", "label": "C", "currency": "KWD", "default": "1.250"},
        {"id": "d", "kind": "date", "label": "D", "min": "2026-10-05", "default": "2026-10-06", "tz": "UTC"},
        {"id": "e", "kind": "time", "label": "E", "default": "14:30"},
        {"id": "f", "kind": "datetime", "label": "F", "default": "2026-10-06T14:30:00+02:00"},
        {"id": "g", "kind": "daterange", "label": "G", "default": {"start": "2026-10-06", "end": "2026-10-07"}},
        {"id": "h", "kind": "choice", "label": "H", "options": ["x", "y"], "multiple": True, "max_selected": 2,
         "default": ["x"]},
        {"id": "i", "kind": "toggle", "label": "I"},
    ]
    params = _form(build, fields=kinds + [{**FIELD, "id": f"t{i}"} for i in range(3)])
    assert len(params["fields"]) == 12
    _contract_accepts("input.form", params)


# ── the builders: input.file ────────────────────────────────────────────────────────────────────


def test_the_upload_dir_is_under_the_sessions_working_directory(server, build, tmp_path):
    server._sessions["s1"]["cwd"] = str(tmp_path)
    params = _file(build, multiple=True, capture="scan", accept="document")
    day = time.strftime("%Y-%m-%d")
    assert params["upload"] == {"dir": f"{tmp_path.resolve().as_posix()}/uploads/hermie/{day}",
                                "max_bytes": 25 * 1024 * 1024, "max_total_bytes": 50 * 1024 * 1024,
                                "max_files": 10, "strip_metadata": True}
    assert params["accept"] == "document" and params["capture"] == "scan" and params["multiple"] is True
    _contract_accepts("input.file", params)
    single = _file(build)
    assert single["upload"]["max_files"] == 1 and "capture" not in single and single["multiple"] is False


def test_the_upload_dir_has_the_working_directorys_symlinks_resolved(server, build, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    server._sessions["s1"]["cwd"] = str(link)
    assert _file(build)["upload"]["dir"].startswith(real.resolve().as_posix() + "/uploads/hermie/")


def test_the_upload_dir_is_created_private_by_the_builder(server, build, tmp_path):
    params = _file(build)
    root = Path(params["upload"]["dir"])
    for folder in (tmp_path / "uploads", tmp_path / "uploads" / "hermie", root):
        assert folder.is_dir() and not folder.is_symlink()
        assert folder.stat().st_mode & 0o777 == 0o700
    assert _file(build)["upload"]["dir"] == params["upload"]["dir"], "an existing directory is reused"


@pytest.mark.parametrize("link", ["uploads", "uploads/hermie", "uploads/hermie/{day}"])
def test_a_symlink_below_the_working_directory_refuses_the_upload_dir(server, build, tmp_path, link):
    """An agent that can write its workspace links a component of uploads/hermie/<date> elsewhere: the builder
    refuses instead of handing the client a directory that lands the person's files outside the workspace, and
    creates nothing through the link."""
    day = time.strftime("%Y-%m-%d")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    path = tmp_path / link.format(day=day)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(build.UploadDirUnavailable) as caught:
        _file(build)
    assert caught.value.reason == "upload_dir_unsafe"
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_search_only_ancestor_still_gets_an_upload_dir_and_its_files_verified(server, build, tmp_path):
    """An ancestor of the working directory the gateway may search but not list (``/home`` at 0711): the
    directory and the check open the working directory itself, never walk the ancestors."""
    locked = tmp_path / "locked"
    workspace = locked / "work"
    workspace.mkdir(parents=True)
    server._sessions["s1"]["cwd"] = str(workspace)
    locked.chmod(0o100)
    try:
        params = _file(build)
        root = Path(params["upload"]["dir"])
        path = _put(root, "0123456789abcdef-a.txt", b"alpha")
        assert build.verify_files(params, [_entry(path, b"alpha")]) == ("", [str(path)])
    finally:
        locked.chmod(0o700)


def test_a_file_where_a_folder_belongs_refuses_the_upload_dir(server, build, tmp_path):
    (tmp_path / "uploads").write_bytes(b"MARKER")
    with pytest.raises(build.UploadDirUnavailable) as caught:
        _file(build)
    assert caught.value.reason == "upload_dir_unsafe"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_an_upload_dir_that_cannot_be_created_is_unavailable(server, build, tmp_path):
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(build.UploadDirUnavailable) as caught:
            _file(build)
    finally:
        tmp_path.chmod(0o700)
    assert caught.value.reason == "upload_dir_unavailable"


def test_the_tool_bridge_reports_an_unsafe_upload_dir_as_unavailable_with_nothing_sent(server, build, tmp_path,
                                                                                        audit_records):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    server._sessions["s1"]["cwd"] = str(tmp_path)
    (tmp_path / "uploads").symlink_to(tmp_path.parent, target_is_directory=True)
    outcome = build.request_from_tool("s1", "input.file", summary="Send the receipt.", accept="image")
    assert (outcome.status, outcome.reason) == ("unavailable", "upload_dir_unsafe")
    assert phone.requests("input.file") == []
    assert [event for event, _ in audit_records] == ["interactive_outcome"]
    assert audit_records[-1][1]["reason"] == "upload_dir_unsafe"


@pytest.mark.parametrize("kwargs, message", [
    ({"accept": "video"}, "accept must be one of"), ({"accept": None}, "accept must be one of"),
    ({"accept": ["image"]}, "accept must be one of"),
    ({"capture": "selfie"}, "capture must be one of"), ({"multiple": "yes"}, "multiple must be true or false"),
])
def test_file_params_refuse_what_the_contract_does_not_list(build, kwargs, message):
    with pytest.raises(build.InteractiveParamsError, match=message):
        _file(build, **kwargs)


# ── the builders: review.draft ──────────────────────────────────────────────────────────────────


def test_a_draft_is_shown_verbatim_with_only_trailing_whitespace_removed(build):
    text = "Hi Bram,  \r\n\r\n  The flat   is free.\n\n\n"
    params = _draft(build, text=text, subject="Re:‮ flat\n", recipients=["bram@example.com", "Ada ​L"],
                    editable=False, kind="post")
    assert params["text"] == "Hi Bram,\n\n  The flat   is free."  # inner spacing is the agent's, kept
    assert params["subject"] == "Re: flat" and params["recipients"] == ["bram@example.com", "Ada L"]
    assert params["editable"] is False and params["kind"] == "post" and params["optional"] is False
    _contract_accepts("review.draft", params)


@pytest.mark.parametrize("text, message", [
    ("", "text is required"), ("  \n \n", "text is required"), (None, "text is required"),
    (5, "text is required"),
    ("a" * 20_001, "text is 20001 characters; the limit is 20000"),
    ("Hello\tBram", "cannot be shown verbatim"), ("Hello‮Bram", "cannot be shown verbatim"),
    ("Hello​Bram", "cannot be shown verbatim"), ("Hello Bram", "cannot be shown verbatim"),
    ("Hello\x00Bram", "cannot be shown verbatim"), ("Hello\x1bBram", "cannot be shown verbatim"),
    ("a" + " " * 40 + "b", "spaces in a row"), ("a\n\n\n\n\n\nb", "blank lines in a row"),
    ("x" * 2_001, "2001 characters"),
], ids=lambda value: repr(value)[:24])
def test_a_draft_that_cannot_be_shown_verbatim_is_refused_never_rewritten(build, text, message):
    with pytest.raises(build.InteractiveParamsError, match=message):
        _draft(build, text=text)
    # (and a text of exactly the limit is fine)
    assert len(_draft(build, text=("a" * 1_999 + "\n") * 10)["text"]) == 19_999


@pytest.mark.parametrize("kwargs, message", [
    ({"kind": "memo"}, "kind must be one of"), ({"kind": None}, "kind must be one of"),
    ({"editable": 1}, "editable must be true or false"),
    ({"subject": "s" * 201}, "subject is 201 characters; the limit is 200"), ({"subject": 4}, "subject must be a string"),
    ({"recipients": "bram@example.com"}, "recipients must be a list of strings"),
    ({"recipients": [1]}, "recipients must be a list of strings"),
    ({"recipients": ["a"] * 11}, "recipients has 11 entries"),
    ({"recipients": ["r" * 121]}, r"recipients\[0\] is 121 characters"),
    ({"recipients": ["​"]}, r"recipients\[0\] is required"),
])
def test_draft_display_fields_are_bounded(build, kwargs, message):
    with pytest.raises(build.InteractiveParamsError, match=message):
        _draft(build, **kwargs)


# ── asking: helpers ─────────────────────────────────────────────────────────────────────────────


def _capable(server, *peers, sid="s1", creator=ROBIN, methods=METHODS):
    _session(server, sid, *peers, creator=creator)
    for peer in peers:
        _caps(server, peer, requests=list(methods))


def _start(interactive, sid, method, params, *, timeout=10.0):
    """``interactive.request`` on a thread, the way a turn asks (inside a copy of this context)."""
    box: dict = {}
    ctx = contextvars.copy_context()

    def run():
        try:
            box["outcome"] = ctx.run(interactive.request, sid, method, params, timeout=timeout)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    box["thread"] = thread
    return box


def _open_id(method, timeout=5.0):
    from tui_gateway import server_requests
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with server_requests._lock:
            req = next((r for r in server_requests._open.values() if r.method == method), None)
        if req is not None:
            return req.id
        time.sleep(0.005)
    raise AssertionError(f"{method} never opened")


def _finish(box, timeout=10.0):
    box["thread"].join(timeout)
    assert not box["thread"].is_alive(), "request did not return"
    assert "error" not in box, box.get("error")
    return box["outcome"]


def _ask(server, interactive, method, params, *, peer, answer=None, sid="s1", timeout=10.0):
    box = _start(interactive, sid, method, params, timeout=timeout)
    rid = _open_id(method)
    if answer is not None:
        _frame(server, peer, rid, result=answer)
    return rid, _finish(box)


# ── asking: input.form ──────────────────────────────────────────────────────────────────────────


def test_a_form_round_trip_returns_what_the_person_entered(server, build, audit_records):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    params = _form(build, fields=[FIELD, {"id": "n", "kind": "number", "label": "N", "integer": True}])
    rid, outcome = _ask(server, build, "input.form", params, peer=phone,
                        answer={"status": "answered", "values": {"name": MARKER, "n": 3}})
    assert (outcome.status, outcome.reason) == ("answered", "")
    assert outcome.payload == {"values": {"name": MARKER, "n": 3}} and outcome.answered_by is None
    assert outcome.as_dict() == {"outcome": "answered", "values": {"name": MARKER, "n": 3}}
    frame = phone.requests("input.form")[0]
    assert frame["id"] == rid and frame["params"]["fields"][0]["id"] == "name"
    assert frame["params"]["acting_user"]["id"] == ROBIN
    assert [event for event, _ in audit_records] == ["interactive_request", "interactive_outcome"]


def test_a_datetime_reaches_the_agent_as_an_instant_and_a_zone(server, build):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    params = _form(build, fields=[
        {"id": "call_at", "kind": "datetime", "label": "When", "tz": "Europe/Amsterdam"},
        {"id": "remind", "kind": "datetime", "label": "Remind"},
        {"id": "note", "kind": "text", "label": "Note"},
        {"id": "price", "kind": "amount", "label": "Price", "currency": "EUR"}])
    answer = {"status": "answered", "values": {
        "call_at": "2026-10-07T14:30+02:00[Europe/Amsterdam]",
        "remind": "2026-10-07T08:30:15-04:00[America/New_York]", "note": "a[b]", "price": "12.50"}}
    rid, outcome = _ask(server, build, "input.form", params, peer=phone, answer=answer)
    assert outcome.payload["values"] == {
        "call_at": {"instant": "2026-10-07T14:30+02:00", "zone": "Europe/Amsterdam"},
        "remind": {"instant": "2026-10-07T08:30:15-04:00", "zone": "America/New_York"},
        "note": "a[b]", "price": "12.50"}
    assert answer["values"]["call_at"].endswith("]"), "the answer itself is not changed"


def test_the_zone_of_a_response_frame_is_loaded_outside_the_request_lock(server, build, monkeypatch):
    """A bare response frame is judged under ``server_requests``' lock; the zone its datetime names is loaded
    before that, outside the lock (``_Validator.warm``), so the check under the lock reads no file."""
    from tui_gateway import interactive_validate, server_requests
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    seen: list[tuple[str, bool]] = []
    real = interactive_validate.ZoneInfo

    def counting(name):
        seen.append((name, server_requests._lock.locked()))
        return real(name)

    monkeypatch.setattr(interactive_validate, "ZoneInfo", counting)
    monkeypatch.setattr(interactive_validate, "_zones", {})
    params = _form(build, fields=[{"id": "remind", "kind": "datetime", "label": "Remind"}])
    answer = {"status": "answered", "values": {"remind": "2026-10-07T08:30:15+09:00[Asia/Tokyo]"}}
    rid, outcome = _ask(server, build, "input.form", params, peer=phone, answer=answer)
    assert outcome.status == "answered"
    assert seen == [("Asia/Tokyo", False)]


def test_skip_is_an_outcome_of_its_own_and_only_when_offered(server, build):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    rid, outcome = _ask(server, build, "input.form", _form(build), peer=phone, answer={"status": "skipped"})
    assert outcome.status == "skipped" and outcome.payload == {}
    box = _start(build, "s1", "input.form", _form(build, optional=False))
    rid = _open_id("input.form")
    refused = _rpc(server, phone, "request.answer", {"id": rid, "result": {"status": "skipped"}})
    assert refused["error"]["code"] == 4034 and refused["error"]["data"] == {"reason": "not_optional"}
    _frame(server, phone, rid, result={"status": "answered", "values": {"name": "x"}})
    assert _finish(box).status == "answered"


def test_the_validator_refuses_what_the_form_does_not_allow_and_the_request_stays_open(server, build):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    params = _form(build, fields=[{**FIELD, "required": True, "max_length": 5}])
    box = _start(build, "s1", "input.form", params)
    rid = _open_id("input.form")
    for result, reason in (({"status": "answered", "values": {}}, "field:name:missing"),
                           ({"status": "answered", "values": {"name": "toolong"}}, "field:name:too_long"),
                           ({"status": "answered", "values": {"nope": "x"}}, "field:nope:unknown")):
        error = _rpc(server, phone, "request.answer", {"id": rid, "result": result})["error"]
        assert error["code"] == 4034 and error["data"] == {"reason": reason}
    _frame(server, phone, rid, result={"status": "answered", "values": {"name": "ok"}})
    assert _finish(box).payload == {"values": {"name": "ok"}}


def test_ten_refused_answers_withdraw_the_request(server, build, cancels):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "input.form", _form(build))
    rid = _open_id("input.form")
    last = None
    for _ in range(10):
        last = _rpc(server, phone, "request.answer", {"id": rid, "result": {"status": "maybe"}})["error"]
    assert last["data"] == {"reason": "too_many_attempts"}
    outcome = _finish(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "too_many_attempts")
    assert [c for c in cancels if c[1]["reason"] == "too_many_attempts"]


# ── asking: review.draft ────────────────────────────────────────────────────────────────────────


def test_an_approved_draft_is_kept_by_the_gateway_and_edited_is_its_computation(server, build):
    from tui_gateway import review_register
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    params = _draft(build, text="Hello Bram,\n\nThanks.")
    rid, same = _ask(server, build, "review.draft", params, peer=phone,
                     answer={"decision": "approved", "text": "Hello Bram,  \n\nThanks.\n"})
    assert same.status == "approved" and same.payload["edited"] is False
    assert same.payload["text"] == "Hello Bram,\n\nThanks."
    assert same.payload["sha256"] == hashlib.sha256(b"Hello Bram,\n\nThanks.").hexdigest()
    entry = review_register.get("key-s1", same.payload["draft_id"])
    assert entry is not None and entry.text == same.payload["text"] and entry.sha256 == same.payload["sha256"]
    assert same.payload["draft_id"].startswith("drf-") and len(same.payload["draft_id"]) == 16

    build.reset_for_tests()
    rid, edited = _ask(server, build, "review.draft", params, peer=phone,
                       answer={"decision": "approved", "text": "Hello Bram,\n\nThanks!"})
    assert edited.status == "approved" and edited.payload["edited"] is True
    assert edited.payload["text"] == "Hello Bram,\n\nThanks!"
    assert edited.payload["draft_id"] != same.payload["draft_id"]
    assert review_register.get("key-s1", edited.payload["draft_id"]).edited is True


def test_a_client_cannot_claim_edited_or_a_draft_id(server, build):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "review.draft", _draft(build))
    rid = _open_id("review.draft")
    error = _rpc(server, phone, "request.answer", {
        "id": rid, "result": {"decision": "approved", "text": "x", "edited": False, "draft_id": "drf-0"}})["error"]
    assert error["data"] == {"reason": "bad_shape"}
    _frame(server, phone, rid, result={"decision": "approved", "text": "Hello"})
    assert _finish(box).payload["edited"] is True


def test_a_locked_draft_cannot_come_back_changed_and_a_rejection_carries_a_cleaned_comment(server, build):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    params = _draft(build, editable=False)
    box = _start(build, "s1", "review.draft", params)
    rid = _open_id("review.draft")
    error = _rpc(server, phone, "request.answer", {"id": rid, "result": {"decision": "approved", "text": "other"}})
    assert error["error"]["data"] == {"reason": "text:edited"}
    _frame(server, phone, rid, result={"decision": "rejected", "comment": "Ask for the ‮deposit.\n\n\n\nOK"})
    outcome = _finish(box)
    assert outcome.status == "rejected" and outcome.payload == {"comment": "Ask for the deposit.\n\nOK"}
    build.reset_for_tests()
    rid, bare = _ask(server, build, "review.draft", params, peer=phone, answer={"decision": "rejected"})
    assert bare.status == "rejected" and bare.payload == {}


def test_a_review_in_a_shared_session_naming_nobody_is_unavailable_with_nothing_sent(server, build, audit_records):
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _capable(server, robin, sam)
    params = _draft(build)
    outcome = build.request("s1", "review.draft", params, timeout=5)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_acting_user")
    assert robin.requests("review.draft") == [] and sam.requests("review.draft") == []
    # ...and not charged to the window: nothing reached a person.
    assert build._limiter.sent == {}


def test_the_answering_login_is_named_only_in_a_shared_session(server, build):
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _capable(server, robin, sam)
    rid, shared = _ask(server, build, "input.form", _form(build), peer=sam,
                       answer={"status": "answered", "values": {"name": "x"}})
    assert shared.answered_by == SAM and shared.as_dict()["answered_by"] == SAM
    solo = _WS("solo", ROBIN)
    _capable(server, solo, sid="s2")
    rid, alone = _ask(server, build, "input.form", _form(build), peer=solo, sid="s2",
                      answer={"status": "answered", "values": {"name": "x"}})
    assert alone.answered_by is None and "answered_by" not in alone.as_dict()


# ── asking: unavailable and timeout ─────────────────────────────────────────────────────────────


def test_nobody_capable_within_the_park_window_is_unavailable_and_free(server, build, monkeypatch, cancels):
    monkeypatch.setattr(build, "PARK_SECONDS", 0.1)
    old = _WS("old", ROBIN)
    _session(server, "s1", old, creator=ROBIN)
    _caps(server, old, requests=None)
    for _ in range(14):  # more than the window allows: a request nobody saw is never counted
        outcome = build.request("s1", "input.form", _form(build), timeout=5)
        assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert old.frames == [] and cancels == [] and build._limiter.sent == {}


def test_a_request_parks_until_a_capable_device_attaches(server, build, audit_records):
    laptop, phone = _WS("laptop", ROBIN), _WS("phone", ROBIN)
    _session(server, "s1", laptop, creator=ROBIN)
    _caps(server, laptop, requests=None)
    box = _start(build, "s1", "input.form", _form(build))
    rid = _open_id("input.form")
    assert audit_records[0][0] == "interactive_request" and audit_records[0][1]["reached"] == 0
    from tui_gateway import server_requests
    _as(phone, server._attach_session_transport, server._sessions["s1"], phone)
    _caps(server, phone, requests=["input.form"])
    _frame(server, phone, rid, result={"status": "answered", "values": {"name": "late"}})
    assert _finish(box).payload == {"values": {"name": "late"}}


@pytest.mark.parametrize("error, reason", [
    ({"code": 4041, "message": "cannot_show", "data": {"reason": "no_camera"}}, "cannot_show:no_camera"),
    ({"code": 4041, "message": "cannot_show", "data": {"reason": "upload_failed"}}, "cannot_show:upload_failed"),
    ({"code": 4041, "message": "cannot_show", "data": {"reason": "shutting_down"}}, "cannot_show:shutting_down"),
    ({"code": 4041, "message": "cannot_show", "data": {"reason": "declined"}}, "cannot_show:declined"),
    # a reason the contract does not list, one that is not a machine word, none, or another code: generic
    ({"code": 4041, "message": "cannot_show", "data": {"reason": "battery_low"}}, "error_response"),
    ({"code": 4041, "message": "cannot_show", "data": {"reason": f"no_camera {MARKER}"}}, "error_response"),
    ({"code": 4041, "message": "cannot_show"}, "error_response"),
    ({"code": -32601, "message": "method not found", "data": {"reason": "no_camera"}}, "error_response"),
])
def test_an_error_response_is_unavailable_never_skipped(server, build, audit_records, error, reason):
    """An app's 4041 reaches the agent as ``cannot_show:<reason>`` only for a reason the contract lists; anything
    else of the client's stays out of the outcome and the audit record."""
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "input.file", _file(build))
    rid = _open_id("input.file")
    _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": rid, "error": error}, phone)
    outcome = _finish(box)
    assert (outcome.status, outcome.reason, outcome.payload) == ("unavailable", reason, {})
    assert audit_records[-1][1]["reason"] == reason and MARKER not in repr(audit_records)


@pytest.mark.parametrize("method, make", [("input.form", _form), ("input.file", _file), ("review.draft", _draft)])
def test_a_declined_4041_is_unavailable_for_every_method_and_audited(server, build, audit_records, method, make):
    """``declined`` (the person chose not to provide it) is a listed reason for every interactive method, a
    draft's included: it is never an answer and never a ``skipped`` or ``rejected``."""
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", method, make(build))
    rid = _open_id(method)
    error = {"code": 4041, "message": "cannot_show", "data": {"reason": "declined"}}
    _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": rid, "error": error}, phone)
    outcome = _finish(box)
    assert (outcome.status, outcome.reason, outcome.payload) == ("unavailable", "cannot_show:declined", {})
    assert audit_records[-1][1]["reason"] == "cannot_show:declined"


def test_an_interrupt_withdraws_it(server, build):
    from tui_gateway import server_requests
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "input.form", _form(build))
    _open_id("input.form")
    server_requests.cancel("s1", reason="interrupted")
    outcome = _finish(box)
    assert (outcome.status, outcome.reason) == ("unavailable", "cancelled:interrupted")


def test_the_deadline_is_a_timeout_with_request_cancel(server, build, cancels):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    outcome = build.request("s1", "input.form", _form(build), timeout=0.2)
    assert (outcome.status, outcome.reason) == ("timeout", "timeout")
    assert cancels and cancels[-1][1]["reason"] == "timeout"


def test_turn_isolation_fails_closed_with_nothing_sent(server, build, monkeypatch):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    monkeypatch.setenv("HERMES_COMPUTE_HOST_CHILD", "1")
    outcome = build.request("s1", "input.form", _form(build), timeout=5)
    assert outcome.reason == "turn_isolation" and phone.requests("input.form") == []


def test_a_session_this_process_does_not_host_is_no_session(server, build, audit_records):
    outcome = build.request_from_tool("nope", "input.form", summary="x", fields=[FIELD])
    assert (outcome.status, outcome.reason) == ("unavailable", "no_session")
    assert audit_records[-1][0] == "interactive_outcome" and audit_records[-1][1]["reason"] == "no_session"
    assert build.request_from_tool("", "review.draft").reason == "no_session"
    with pytest.raises(ValueError, match="not an interactive request method"):
        build.request_from_tool("s1", "confirm")
    with pytest.raises(ValueError, match="not an interactive request method"):
        build.request("s1", "clarify", {})


def test_bad_arguments_from_the_tool_raise_before_anything_is_sent(server, build):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    with pytest.raises(build.InteractiveParamsError):
        build.request_from_tool("s1", "input.form", summary="x" * 501, fields=[FIELD])
    with pytest.raises(build.InteractiveParamsError):
        build.request_from_tool("s1", "review.draft", summary="x", text="a\tb", kind="mail")
    assert phone.requests("input.form") == [] and phone.requests("review.draft") == []


# ── limits ──────────────────────────────────────────────────────────────────────────────────────


def test_one_open_request_per_conversation_and_twelve_per_window(server, build, monkeypatch):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "input.form", _form(build))
    rid = _open_id("input.form")
    second = build.request("s1", "review.draft", _draft(build), timeout=5)
    assert (second.status, second.reason) == ("unavailable", "already_pending")
    assert phone.requests("review.draft") == []
    _frame(server, phone, rid, result={"status": "skipped"})
    _finish(box)
    for _ in range(11):
        assert build.request("s1", "input.form", _form(build), timeout=0.01).status == "timeout"
    limited = build.request("s1", "input.form", _form(build), timeout=5)
    assert (limited.status, limited.reason) == ("unavailable", "rate_limited")
    assert len(phone.requests("input.form")) == 12
    clock = time.monotonic() + build.WINDOW_SECONDS + 1
    monkeypatch.setattr(build.time, "monotonic", lambda: clock)
    assert build.request("s1", "input.form", _form(build), timeout=0.01).status == "timeout"


def test_a_request_that_never_opened_does_not_count_against_the_window(server, build, monkeypatch):
    """``send_gated`` refusing the params (a ValueError: our bug, nothing went out) frees the slot and charges
    nothing; only a request that opened (sent, or parked for a device) counts."""
    from tui_gateway import server_requests
    phone = _WS("phone", ROBIN)
    _capable(server, phone)

    def refuse(*args, **kwargs):
        raise ValueError("params refused by the contract")

    real = server_requests.send_gated
    monkeypatch.setattr(server_requests, "send_gated", refuse)
    for _ in range(build.MAX_PER_WINDOW + 1):
        with pytest.raises(ValueError):
            build.request("s1", "input.form", _form(build), timeout=5)
    assert build._limiter.sent == {} and build._limiter.pending == {}
    monkeypatch.setattr(server_requests, "send_gated", real)
    assert build.request("s1", "input.form", _form(build), timeout=0.01).status == "timeout"
    assert len(build._limiter.sent["key-s1"]) == 1


def test_confirm_keeps_its_own_limit_apart_from_interactive_requests(server, build):
    from tui_gateway import confirm
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "input.form", _form(build))
    rid = _open_id("input.form")
    assert confirm._limiter is not build._limiter
    assert confirm._reserve("key-s1", time.monotonic()) == ""  # not blocked by the open form
    confirm._release("key-s1", sent_at=None)
    _frame(server, phone, rid, result={"status": "skipped"})
    _finish(box)


def test_two_conversations_do_not_share_the_limit(server, build):
    phone, other = _WS("phone", ROBIN), _WS("other", ROBIN)
    _capable(server, phone)
    _capable(server, other, sid="s2")
    box = _start(build, "s1", "input.form", _form(build))
    rid = _open_id("input.form")
    assert build.request("s2", "input.form", _form(build), timeout=0.01).status == "timeout"
    _frame(server, phone, rid, result={"status": "skipped"})
    _finish(box)


# ── hooks and audit ─────────────────────────────────────────────────────────────────────────────


def test_pre_and_post_server_request_fire_once_each_from_the_gate(server, build, monkeypatch):
    from tui_gateway import request_hooks
    opened: list[tuple] = []
    real = request_hooks.opened

    def spy(method, sid, request_id, **kwargs):
        opened.append((method, sid, request_id, kwargs))
        return real(method, sid, request_id, **kwargs)

    monkeypatch.setattr(request_hooks, "opened", spy)
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    rid, _ = _ask(server, build, "input.form", _form(build), peer=phone, answer={"status": "skipped"})
    assert [(m, s, r) for m, s, r, _ in opened] == [("input.form", "s1", rid)]


def test_audit_records_name_who_and_what_never_the_text(server, build, audit_records, caplog):
    caplog.set_level(logging.DEBUG)
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    secret_title, secret_value = "TITLE-" + MARKER, "VALUE-" + MARKER
    params = _form(build, title=secret_title, summary="SUMMARY-" + MARKER, detail="DETAIL-" + MARKER,
                   fields=[{**FIELD, "label": "LABEL-" + MARKER, "default": "DEFAULT-" + MARKER}])
    rid, outcome = _ask(server, build, "input.form", params, peer=phone,
                        answer={"status": "answered", "values": {"name": secret_value}})
    assert outcome.status == "answered"
    (request_event, request_fields), (outcome_event, outcome_fields) = audit_records
    assert (request_event, outcome_event) == ("interactive_request", "interactive_outcome")
    assert request_fields == {"session_id": "s1", "request_id": rid, "method": "input.form", "acting_user": ROBIN,
                              "reached": 1}
    assert outcome_fields["outcome"] == "answered" and outcome_fields["answered_by"] == ROBIN
    assert outcome_fields["request_id"] == rid and outcome_fields["method"] == "input.form"
    assert MARKER not in json.dumps(audit_records)
    assert MARKER not in caplog.text, "a logger saw the request's text or the person's answer"


def test_a_refused_and_a_settled_answer_leave_no_text_in_any_log(server, build, caplog):
    caplog.set_level(logging.DEBUG)
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    box = _start(build, "s1", "review.draft", _draft(build, text="DRAFT-" + MARKER, editable=False))
    rid = _open_id("review.draft")
    _rpc(server, phone, "request.answer", {"id": rid, "result": {"decision": "approved", "text": "EDIT-" + MARKER}})
    _frame(server, phone, rid, result={"decision": "approved", "text": "DRAFT-" + MARKER})
    assert _finish(box).status == "approved"
    assert MARKER not in caplog.text


def test_the_hook_audit_events_exist_in_the_dashboard_audit_log():
    from hermes_cli.dashboard_auth.audit import AuditEvent
    assert AuditEvent("interactive_request") and AuditEvent("interactive_outcome")


# ── files, checked after the request settled ────────────────────────────────────────────────────


def _upload(tmp_path: Path, **limits) -> tuple[dict, Path]:
    root = tmp_path / "uploads" / "hermie" / "2026-10-04"
    root.mkdir(parents=True, exist_ok=True)
    upload = {"dir": root.resolve().as_posix(), "max_bytes": 100, "max_total_bytes": 150, "max_files": 3,
              "strip_metadata": True, **limits}
    return {"upload": upload}, root


def _entry(path: Path, data: bytes, **over) -> dict:
    return {"path": str(path), "name": "receipt.txt", "mime": "text/plain", "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), **over}


def _put(root: Path, name: str, data: bytes) -> Path:
    path = root / name
    path.write_bytes(data)
    return path


def test_verify_files_accepts_what_the_client_declared(build, tmp_path):
    params, root = _upload(tmp_path)
    a, b = _put(root, "0123456789abcdef-a.txt", b"alpha"), _put(root, "fedcba9876543210-b.txt", b"b" * 100)
    problem, real = build.verify_files(params, [_entry(a, b"alpha"), _entry(b, b"b" * 100)])
    assert problem == "" and real == [str(a.resolve()), str(b.resolve())]
    empty = _put(root, "0000000000000000-empty.txt", b"")
    assert build.verify_files(params, [_entry(empty, b"")]) == ("", [str(empty.resolve())])


def test_verify_files_refuses_every_way_the_disk_disagrees(build, tmp_path):
    params, root = _upload(tmp_path)
    good = _put(root, "0123456789abcdef-a.txt", b"alpha")
    verify = build.verify_files
    # missing
    assert verify(params, [_entry(root / "0123456789abcdef-gone.txt", b"alpha")]) == ("file:0:missing", [])
    # size smaller or larger than declared, either way
    assert verify(params, [_entry(good, b"alpha", bytes=4)])[0] == "file:0:size"
    assert verify(params, [_entry(good, b"alpha", bytes=6)])[0] == "file:0:size"
    # same size, other content: the hash says so
    other = _put(root, "0123456789abcdef-o.txt", b"omega")
    assert verify(params, [_entry(other, b"alpha")])[0] == "file:0:hash"
    assert verify(params, [_entry(good, b"alpha", sha256="0" * 64)])[0] == "file:0:hash"
    # over the per-file limit on disk, whatever was declared
    big = _put(root, "0123456789abcdef-big.txt", b"x" * 101)
    assert verify(params, [_entry(big, b"x" * 101)])[0] == "file:0:size"
    # a directory is no file
    folder = root / "0123456789abcdef-dir"
    folder.mkdir()
    assert verify(params, [_entry(folder, b"")])[0] == "file:0:not_a_file"
    # the second file is the one named
    assert verify(params, [_entry(good, b"alpha"), _entry(other, b"alpha")])[0] == "file:1:hash"


def test_verify_files_refuses_a_total_over_the_limit_on_disk(build, tmp_path):
    params, root = _upload(tmp_path, max_bytes=100, max_total_bytes=150)
    a, b = _put(root, "0123456789abcdef-a.txt", b"a" * 100), _put(root, "fedcba9876543210-b.txt", b"b" * 60)
    assert build.verify_files(params, [_entry(a, b"a" * 100), _entry(b, b"b" * 60)]) == ("files:too_large", [])


def test_verify_files_refuses_paths_that_escape_through_the_disk(build, tmp_path):
    params, root = _upload(tmp_path)
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"secret")
    # a symlink in the dir to a file outside it: never followed
    (root / "0123456789abcdef-link.txt").symlink_to(outside)
    assert build.verify_files(params, [_entry(root / "0123456789abcdef-link.txt", b"secret")])[0] == "file:0:link"
    # a ".." lexically fine but really outside, and a file in a subdirectory: not directly in the dir
    sibling = tmp_path / "uploads" / "hermie" / "other"
    sibling.mkdir()
    (sibling / "x.txt").write_bytes(b"x")
    assert build.verify_files(params, [_entry(root / ".." / "other" / "x.txt", b"x")])[0] == "file:0:outside_dir"
    (root / "jump").symlink_to(tmp_path, target_is_directory=True)
    assert build.verify_files(params, [_entry(root / "jump" / "secret.txt", b"secret")])[0] == "file:0:outside_dir"
    (root / "sub").mkdir()
    (root / "sub" / "0123456789abcdef-x.txt").write_bytes(b"x")
    assert build.verify_files(params, [_entry(root / "sub" / "0123456789abcdef-x.txt", b"x")])[0] == "file:0:outside_dir"


def test_verify_files_refuses_a_link_that_stays_inside_the_dir(build, tmp_path):
    """A link is refused at the file itself even when it points to a real file in the same directory: the check
    never follows a link, so what it hashed is always the entry the answer named."""
    params, root = _upload(tmp_path)
    real = _put(root, "0123456789abcdef-real.txt", b"real")
    (root / "0123456789abcdef-alias.txt").symlink_to(real)
    assert build.verify_files(params, [_entry(root / "0123456789abcdef-alias.txt", b"real")]) == ("file:0:link", [])
    assert build.verify_files(params, [_entry(real, b"real")]) == ("", [f"{params['upload']['dir']}/{real.name}"])


@pytest.mark.parametrize("swap", ["uploads", "uploads/hermie", "uploads/hermie/2026-10-04"])
def test_verify_files_refuses_a_parent_swapped_for_a_link_after_the_request_was_built(build, tmp_path, swap):
    """The directory was real when the request was built; by the time the answer is checked a component was
    replaced by a link to a look-alike tree elsewhere, with a file that matches the answer. Refused, unread."""
    params, root = _upload(tmp_path)
    decoy = tmp_path / "decoy"
    (decoy / "uploads" / "hermie" / "2026-10-04").mkdir(parents=True)
    _put(decoy / "uploads" / "hermie" / "2026-10-04", "0123456789abcdef-a.txt", b"alpha")
    moved = tmp_path / swap
    moved.rename(tmp_path / "moved-away")
    moved.symlink_to(decoy / swap, target_is_directory=True)
    entry = _entry(root / "0123456789abcdef-a.txt", b"alpha")
    assert Path(entry["path"]).read_bytes() == b"alpha", "the lexical path reaches the decoy through the link"
    assert build.verify_files(params, [entry]) == ("dir:unsafe", [])


def test_verify_files_refuses_an_upload_dir_that_is_not_a_real_path(build, tmp_path):
    params, root = _upload(tmp_path)
    real = _put(root, "0123456789abcdef-a.txt", b"alpha")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    linked = {"upload": {**params["upload"], "dir": alias.as_posix()}}
    assert build.verify_files(linked, [_entry(alias / real.name, b"alpha")]) == ("dir:unsafe", [])
    trailing = {"upload": {**params["upload"], "dir": params["upload"]["dir"] + "/"}}
    assert build.verify_files(trailing, [_entry(real, b"alpha")]) == ("dir:unsafe", [])
    gone = {"upload": {**params["upload"], "dir": (tmp_path / "uploads" / "hermie" / "1999-01-01").resolve().as_posix()}}
    assert build.verify_files(gone, [_entry(real, b"alpha")])[0] == "file:0:missing"


def test_verify_files_refuses_names_with_control_or_format_characters(build, tmp_path):
    params, root = _upload(tmp_path)
    for name in ("0123456789abcdef-a\nb.txt", "0123456789abcdef-a‮b.txt", "0123456789abcdef-a b.txt"):
        path = _put(root, name, b"x")
        assert build.verify_files(params, [_entry(path, b"x")])[0] == "file:0:path"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs fifos")
def test_verify_files_never_blocks_on_a_fifo(build, tmp_path):
    params, root = _upload(tmp_path)
    fifo = root / "0123456789abcdef-fifo"
    os.mkfifo(fifo)
    started = time.monotonic()
    assert build.verify_files(params, [_entry(fifo, b"")])[0] == "file:0:not_a_file"
    assert time.monotonic() - started < 2


def test_an_uploaded_file_round_trip_gives_path_and_the_same_ref_text_as_file_attach(server, build, tmp_path):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    server._sessions["s1"]["cwd"] = str(tmp_path)
    params = _file(build, multiple=True, accept="any")
    root = Path(params["upload"]["dir"])
    assert root.is_dir()
    one, two = _put(root, "0123456789abcdef-my receipt.pdf", b"%PDF-marker"), _put(
        root, "fedcba9876543210-notes.txt", b"hello")
    answer = {"status": "answered", "text": "Voice‮ note\n\n\n\nhere", "files": [
        _entry(one, b"%PDF-marker", name="my‮ receipt.pdf", mime="application/pdf"),
        _entry(two, b"hello", mime="not a mime")]}
    rid, outcome = _ask(server, build, "input.file", params, peer=phone, answer=answer)
    assert outcome.status == "answered" and outcome.payload["text"] == "Voice note\n\nhere"
    first, second = outcome.payload["files"]
    assert first["path"] == str(one.resolve()) and first["name"] == "my receipt.pdf"
    assert first["mime"] == "application/pdf" and first["bytes"] == 11
    assert first["sha256"] == hashlib.sha256(b"%PDF-marker").hexdigest()
    assert second["mime"] == "application/octet-stream" and "ref_text" in second
    # what file.attach says for the same path: workspace-relative, quoted by the same rule
    session = server._sessions["s1"]
    for entry, path in ((first, one), (second, two)):
        ref = server._attachment_ref_path(session, path)
        assert entry["ref_text"] == f"@file:{server._format_ref_value(ref)}"
    assert first["ref_text"].startswith("@file:\"uploads/hermie/") or first["ref_text"].startswith("@file:`uploads/")
    assert second["ref_text"].startswith("@file:uploads/hermie/")


def test_a_file_that_does_not_check_out_is_unavailable_bad_upload_never_an_answer(server, build, tmp_path, audit_records):
    phone = _WS("phone", ROBIN)
    _capable(server, phone)
    server._sessions["s1"]["cwd"] = str(tmp_path)
    params = _file(build)
    root = Path(params["upload"]["dir"])
    assert root.is_dir()
    path = _put(root, "0123456789abcdef-a.txt", b"alpha")
    rid, outcome = _ask(server, build, "input.file", params, peer=phone, answer={
        "status": "answered", "files": [_entry(path, b"alpha", sha256="0" * 64)]})
    assert (outcome.status, outcome.reason) == ("unavailable", "bad_upload")
    assert outcome.payload == {"problem": "file:0:hash"} and "files" not in outcome.payload
    assert audit_records[-1][1]["outcome"] == "unavailable" and audit_records[-1][1]["reason"] == "bad_upload"
    assert path.exists(), "nothing is deleted"
    # a skipped file request needs no disk at all
    rid, skipped = _ask(server, build, "input.file", params, peer=phone, answer={"status": "skipped"})
    assert skipped.status == "skipped"
