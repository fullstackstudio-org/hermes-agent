"""The answer checks of the interactive requests (``input.form``, ``input.file``, ``review.draft``, ``review.diff``,
``input.signature``, ``device.location``, ``device.contact``, ``device.calendar``, ``device.scan``).

:func:`validate_answer` is the ``validate`` ``server_requests.send_gated`` runs on every answer: it returns the
FIRST problem as the reason string ``contract/requests/README.md`` §3-§12 names (``bad_shape``, ``not_optional``,
``field:<id>:<problem>``, ``files:too_many``, ``file:<n>:outside_dir``, ``text:not_verbatim``,
``hunk:<id>:missing``, ``statement:mismatch``, ``contact:<key>:not_requested``, ``precision:too_precise``, ...), or None
for an answer that may settle the request. It runs under ``server_requests``'
lock, so it is PURE and cheap: string, number and date arithmetic on the answer and the frame's own params, no I/O,
no logging, no state. (The one exception is a datetime answer's time zone: a zone is read from its tzdata file the
first time this process looks it up and then kept in :data:`_zones` for good, a cache bounded by the zones the host
knows. The set of known zones and a field's own ``tz`` are loaded by :func:`prepare` before the request opens, and
the zone an answer names by the validator's :meth:`_Validator.warm`, which ``server_requests`` runs outside its lock
before it judges a response frame; ``request.answer`` already judges outside the lock first. So a zone file is read
under the lock only if a race beats both.) Checks that need the disk (a file exists, its size and hash) are the
caller's, after the request settled (``interactive.verify_files``).

The order is the README's: the result model (``bad_shape``), ``not_optional``, then per method. Within a form,
the ``values`` keys first (``unknown``), then each field in the form's order; within a field the structural
problems (``missing``, ``type``, ``format``, ``too_long``, ``zone``, ``offset``, ``order``, ``not_an_option``,
``duplicate``) before the range ones (``below_min`` / ``above_max``, ``not_integer``, ``step``, ``too_few`` /
``too_many``), because a range can only be judged on a value that is well-formed. A diff review: the hunk ids the
request lacks (``hunk:<id>:unknown``), then the ones it has that the answer left out (``hunk:<id>:missing``), then
the decision against the hunks (``decision:inconsistent``).

Every regular expression that validates a WHOLE value is applied with ``re.fullmatch``: Python's ``$`` also matches
before a final newline, so ``re.match("^x$", "x\\n")`` succeeds.
"""

from __future__ import annotations

import datetime as _dt
import math
import posixpath
import re
from decimal import Decimal, InvalidOperation
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import ValidationError

from tui_gateway import currency_units, interactive_device
from tui_gateway.contracts.registry import SERVER_REQUESTS
from tui_gateway.contracts.server_requests import (
    FORM_DATE, FORM_DATETIME_VALUE, FORM_DECIMAL, FORM_FIELD_ID, FORM_TEXT_MAX, FORM_TIME, INTERACTIVE_METHODS,
    SIGNATURE_MIMES)
from tui_gateway.request_text import verbatim_problem

#: Characters a one-line text value may not contain (the contract's ``ONE_LINE`` set).
LINE_BREAKS = "\r\n\x0b\x0c\x85  "

_DATE = re.compile(FORM_DATE)
_TIME = re.compile(FORM_TIME)
_DECIMAL = re.compile(FORM_DECIMAL)
_FIELD_ID = re.compile(FORM_FIELD_ID)
# An instant with its offset parsed out; the value form carries the bracketed zone after it.
_VALUE = re.compile(FORM_DATETIME_VALUE)
_PARTS = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?([+-])(\d{2}):(\d{2})\[(.+)\]")
_INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?([+-])(\d{2}):(\d{2})")

#: The MIME type of a recording: ``audio/`` and a subtype, no parameters (``audio/mp4``, not ``audio/webm;codecs=opus``).
_AUDIO_MIME = re.compile(r"audio/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}")

_known_zones: frozenset[str] | None = None
#: Every zone looked up so far, by name: strong references (``ZoneInfo``'s own cache is small and weak), only for
#: names in :func:`known_zones`, so it holds at most one entry per zone the host knows.
_zones: dict[str, ZoneInfo] = {}


# ── time zones and instants ────────────────────────────────────────────────────────────────────


def known_zones() -> frozenset[str]:
    """Every IANA zone name this host knows; empty on a host without a time zone database (no system zoneinfo and
    no ``tzdata`` package), where a datetime field is refused when the form is built. Built once; :func:`prepare`
    calls it before a request opens, so an answer check never scans the tz database under a lock."""
    global _known_zones
    if _known_zones is None:
        import zoneinfo
        _known_zones = frozenset(zoneinfo.available_timezones())
    return _known_zones


def zone(name: str) -> ZoneInfo | None:
    """The zone *name*, or None when it is not one this host knows (never raises). Read from disk the first time
    and kept in :data:`_zones` from then on."""
    if not isinstance(name, str) or name not in known_zones():
        return None
    if (info := _zones.get(name)) is not None:
        return info
    try:
        info = ZoneInfo(name)
    except Exception:  # noqa: BLE001 - an unreadable zone file is an unknown zone
        return None
    return _zones.setdefault(name, info)


def prepare(params: dict) -> None:
    """Warm what the answer check of *params* needs and would otherwise load under the lock: the known zones (a
    datetime field), and the zone a field names. Never raises."""
    try:
        fields = params.get("fields") if isinstance(params.get("fields"), list) else []
        if any(isinstance(f, dict) and f.get("kind") == "datetime" for f in fields):
            known_zones()
            for field in fields:
                if isinstance(field, dict) and field.get("kind") == "datetime" and isinstance(field.get("tz"), str):
                    zone(field["tz"])
    except Exception:  # noqa: BLE001
        pass


def parse_instant(text: str) -> _dt.datetime | None:
    """An instant ``YYYY-MM-DDTHH:MM[:SS]±HH:MM`` as an aware datetime, None when it is not one (no ``Z``, no
    fractions, a real calendar date and clock time). Seconds are optional."""
    match = _INSTANT.fullmatch(text)
    return _aware(match.groups()) if match else None


def _aware(groups: tuple) -> _dt.datetime | None:
    year, month, day, hour, minute, second, sign, off_h, off_m = groups[:9]
    try:
        offset = _dt.timedelta(hours=int(off_h), minutes=int(off_m))
        return _dt.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second or 0),
                            tzinfo=_dt.timezone(-offset if sign == "-" else offset))
    except ValueError:
        return None


def _decimals(text: str) -> int:
    return len(text.partition(".")[2])


# ── input.form ─────────────────────────────────────────────────────────────────────────────────

_ABSENT = object()


def _empty(kind: str, multiple: bool, value: Any) -> bool:
    """``""`` counts as no value for every string-valued kind, ``[]`` for a multiple choice."""
    if value is _ABSENT:
        return True
    if kind in ("text", "amount", "date", "time", "datetime") or (kind == "choice" and not multiple):
        return value == ""
    return kind == "choice" and multiple and value == []


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _text_problem(field: dict, value: Any) -> str | None:
    if not isinstance(value, str):
        return "type"
    if not field.get("multiline") and any(ch in value for ch in LINE_BREAKS):
        return "format"
    if len(value) > (field.get("max_length") or FORM_TEXT_MAX):
        return "too_long"
    return None


def _number_problem(field: dict, value: Any) -> str | None:
    if not _is_number(value) or not math.isfinite(value):
        return "type"
    if field.get("min") is not None and value < field["min"]:
        return "below_min"
    if field.get("max") is not None and value > field["max"]:
        return "above_max"
    if field.get("integer") and not float(value).is_integer():
        return "not_integer"
    if field.get("step") is not None:
        try:
            steps = (Decimal(str(value)) - Decimal(str(field.get("min") or 0))) / Decimal(str(field["step"]))
        except (InvalidOperation, ValueError):
            return "type"
        if steps != steps.to_integral_value():
            return "step"
    return None


def _amount_problem(field: dict, value: Any) -> str | None:
    if not isinstance(value, str):
        return "type"
    if not _DECIMAL.fullmatch(value):
        return "format"
    places = currency_units.exponent(str(field.get("currency"))) if field.get("currency") else None
    if _decimals(value) > min(currency_units.DEFAULT_EXPONENT if places is None else places,
                              currency_units.MAX_DECIMALS):
        return "format"
    amount = Decimal(value)
    if field.get("min") is not None and amount < Decimal(field["min"]):
        return "below_min"
    if field.get("max") is not None and amount > Decimal(field["max"]):
        return "above_max"
    return None


def _day(text: Any) -> _dt.date | None:
    if not isinstance(text, str) or not _DATE.fullmatch(text):
        return None
    try:
        return _dt.date.fromisoformat(text)
    except ValueError:
        return None


def _date_problem(field: dict, value: Any) -> str | None:
    if not isinstance(value, str):
        return "type"
    day = _day(value)
    if day is None:
        return "format"
    if field.get("min") is not None and day < _day(field["min"]):
        return "below_min"
    if field.get("max") is not None and day > _day(field["max"]):
        return "above_max"
    return None


def _time_problem(field: dict, value: Any) -> str | None:
    if not isinstance(value, str):
        return "type"
    if not _TIME.fullmatch(value):
        return "format"
    clock = _dt.time.fromisoformat(value)
    if field.get("min") is not None and clock < _dt.time.fromisoformat(field["min"]):
        return "below_min"
    if field.get("max") is not None and clock > _dt.time.fromisoformat(field["max"]):
        return "above_max"
    return None


def _datetime_problem(field: dict, value: Any) -> str | None:
    if not isinstance(value, str):
        return "type"
    parts = _PARTS.fullmatch(value) if _VALUE.fullmatch(value) else None
    if parts is None:
        return "format"
    instant = _aware(parts.groups())
    if instant is None:
        return "format"
    name = parts.group(10)
    info = zone(name)
    if info is None or (field.get("tz") and name != field["tz"]):
        return "zone"
    # The offset must be the zone's at that instant: the same instant, seen in the zone, has this wall clock
    # time and this offset (a wall time in a DST gap, or the wrong offset in an overlap, fails here).
    local = instant.astimezone(info)
    if local.replace(tzinfo=None) != instant.replace(tzinfo=None) or local.utcoffset() != instant.utcoffset():
        return "offset"
    if field.get("min") is not None and instant < parse_instant(field["min"]):
        return "below_min"
    if field.get("max") is not None and instant > parse_instant(field["max"]):
        return "above_max"
    return None


def _daterange_problem(field: dict, value: Any) -> str | None:
    if not isinstance(value, dict):
        return "type"
    start, end = _day(value.get("start")), _day(value.get("end"))
    if start is None or end is None:
        return "format"
    if end < start:
        return "order"
    if field.get("min") is not None and start < _day(field["min"]):
        return "below_min"
    if field.get("max") is not None and end > _day(field["max"]):
        return "above_max"
    return None


def _choice_problem(field: dict, value: Any) -> str | None:
    options = {option["value"] for option in field.get("options") or []}
    if not field.get("multiple"):
        if not isinstance(value, str):
            return "type"
        return None if value in options else "not_an_option"
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return "type"
    if any(item not in options for item in value):
        return "not_an_option"
    if len(set(value)) != len(value):
        return "duplicate"
    if field.get("min_selected") is not None and len(value) < field["min_selected"]:
        return "too_few"
    if field.get("max_selected") is not None and len(value) > field["max_selected"]:
        return "too_many"
    return None


def _toggle_problem(field: dict, value: Any) -> str | None:
    return None if isinstance(value, bool) else "type"


_KINDS = {"text": _text_problem, "number": _number_problem, "amount": _amount_problem, "date": _date_problem,
          "time": _time_problem, "datetime": _datetime_problem, "daterange": _daterange_problem,
          "choice": _choice_problem, "toggle": _toggle_problem}


def field_problem(field: dict, value: Any) -> str | None:
    """The problem word (``missing``, ``type``, ``format``, ...) of *value* for the form field definition
    *field*, or None. *value* is ``_ABSENT`` for a field the answer left out."""
    kind = field.get("kind")
    if _empty(kind, bool(field.get("multiple")), value):
        return "missing" if field.get("required") else None
    check = _KINDS.get(kind)
    return check(field, value) if check is not None else "type"


def _form_problem(params: dict, values: dict) -> str | None:
    fields = [f for f in params.get("fields") or [] if isinstance(f, dict)]
    known = {f.get("id") for f in fields}
    for key in values:
        if not isinstance(key, str) or not _FIELD_ID.fullmatch(key):
            # The result model already refuses such a key (``propertyNames``); kept so this check never puts text
            # of the client's into a reason, whatever reaches it.
            return "bad_shape"
        if key not in known:
            return f"field:{key}:unknown"
    for field in fields:
        problem = field_problem(field, values.get(field.get("id"), _ABSENT))
        if problem:
            return f"field:{field.get('id')}:{problem}"
    return None


# ── input.file ─────────────────────────────────────────────────────────────────────────────────


def lexical_path(path: str) -> str | None:
    """*path* with ``.``, ``..`` and empty segments resolved lexically (never touching the disk), as an absolute
    POSIX path; None when it is not absolute or climbs above the root."""
    if not path.startswith("/"):
        return None
    parts: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(segment)
    return "/" + "/".join(parts)


def directly_in_dir(path: str, directory: str) -> bool:
    """Whether *path* names an entry DIRECTLY in *directory* once both have had their ``.``, ``..`` and empty
    segments resolved lexically: its parent is the directory and its last segment is a name (the upload layout is
    flat, ``<upload.dir>/<16 hex>-<name>``). A sibling that merely shares a prefix, the directory itself and a file
    in a subdirectory are not. ``interactive.verify_files`` applies the same rule on disk."""
    norm, base = lexical_path(path), lexical_path(directory)
    if norm is None or base is None or norm == base:
        return False
    parent, name = posixpath.split(norm)
    return parent == base and name not in ("", ".", "..")


def _file_problem(params: dict, files: list[dict]) -> str | None:
    upload = params.get("upload") or {}
    limit = int(upload.get("max_files") or 1) if params.get("multiple") else 1
    if len(files) > limit:
        return "files:too_many"
    audio = params.get("accept") == "audio"
    for number, file in enumerate(files):
        if not directly_in_dir(str(file.get("path")), str(upload.get("dir"))):
            return f"file:{number}:outside_dir"
        if int(file.get("bytes")) > int(upload.get("max_bytes")):
            return f"file:{number}:too_large"
        if audio and not _AUDIO_MIME.fullmatch(str(file.get("mime"))):
            return f"file:{number}:not_audio"
    if sum(int(file.get("bytes")) for file in files) > int(upload.get("max_total_bytes")):
        return "files:too_large"
    return None


# ── review.draft ───────────────────────────────────────────────────────────────────────────────


def strip_line_ends(text: str) -> str:
    """*text* without whitespace at the end of any line or of the text (the draft as the person sees it: nothing a
    rendering shows is lost). Exactly: split on LF only, strip every ``str.isspace`` character from the end of each
    line (CR, tab, VT, FF, NEL U+0085, NBSP U+00A0, U+3000, U+2028, U+2029, ...), then from the end of the whole
    text, so trailing blank lines and a final newline go too. Leading whitespace is kept (contract §6)."""
    return "\n".join(line.rstrip() for line in text.split("\n")).rstrip()


def _draft_problem(params: dict, result: dict) -> str | None:
    if result.get("decision") != "approved":
        return None
    text = strip_line_ends(str(result.get("text")))
    if not text or verbatim_problem(text):
        return "text:not_verbatim"
    if not params.get("editable", True) and text != strip_line_ends(str(params.get("text"))):
        return "text:edited"
    return None


# ── review.diff ────────────────────────────────────────────────────────────────────────────────


def _diff_problem(params: dict, result: dict) -> str | None:
    """Every hunk of the request decided exactly once, and a decision that agrees with them. The ids are the
    GATEWAY's (``params["hunks"]``); a key the result model let through is a well-formed id, so a reason never
    carries text of the client's."""
    ids = [hunk.get("id") for hunk in params.get("hunks") or [] if isinstance(hunk, dict)]
    known = set(ids)
    decided = result["hunks"]
    for key in decided:
        if key not in known:
            return f"hunk:{key}:unknown"
    for hunk_id in ids:
        if hunk_id not in decided:
            return f"hunk:{hunk_id}:missing"
    approved = any(value == "approved" for value in decided.values())
    if (result["decision"] == "approved") != approved:
        return "decision:inconsistent"
    return None


# ── input.signature and the device requests ────────────────────────────────────────────────────


def _transcript_problem(params: dict, body: dict) -> str | None:
    """A transcript belongs to a recording: an ``audio`` request has one to give, an ``any`` request only when an
    ``audio/*`` file was sent, an image or a document request never."""
    if body.get("text") is None:
        return None
    if params.get("accept") == "audio":
        return None
    if params.get("accept") == "any" and any(str(f.get("mime")).startswith("audio/") for f in body["files"]):
        return None
    return "text:not_audio"


def _signature_problem(params: dict, body: dict) -> str | None:
    """The two files (each directly in ``upload.dir`` and within the sizes, as for ``input.file``), then that they are
    one PNG and one SVG by their declared type and the extension of their names (``file:<n>:extension``), then that ``statement_sha256`` is the SHA-256 of the statement the
    request carried (``statement:mismatch``)."""
    upload = params.get("upload") or {}
    files = body["files"]
    for number, file in enumerate(files):
        if not directly_in_dir(str(file.get("path")), str(upload.get("dir"))):
            return f"file:{number}:outside_dir"
        if int(file.get("bytes")) > int(upload.get("max_bytes")):
            return f"file:{number}:too_large"
    if sum(int(file.get("bytes")) for file in files) > int(upload.get("max_total_bytes")):
        return "files:too_large"
    if sorted(str(file.get("mime")) for file in files) != sorted(SIGNATURE_MIMES):
        return "files:not_png_and_svg"
    for number, file in enumerate(files):
        # The name the file is saved under says what it is: ``.png`` for the PNG, ``.svg`` for the SVG.
        suffix = ".png" if file.get("mime") == "image/png" else ".svg"
        if not str(file.get("path")).lower().endswith(suffix):
            return f"file:{number}:extension"
    if body["statement_sha256"] != interactive_device.statement_sha256(str(params.get("statement"))):
        return "statement:mismatch"
    return None


def _location_problem(params: dict, body: dict) -> str | None:
    return interactive_device.precision_problem(str(params.get("precision")), str(body["precision"]))


def _contact_problem(params: dict, contact: dict) -> str | None:
    """A key the request did not ask for (``contact:<key>:not_requested``), a birthday that is no day
    (``contact:birthday:invalid``), then a contact that holds nothing once cleaned (``contact:empty``)."""
    requested = list(params.get("fields") or [])
    if key := interactive_device.unrequested_key(contact, requested):
        return f"contact:{key}:not_requested"
    if contact.get("birthday") is not None and (problem := interactive_device.birthday_problem(contact["birthday"])):
        return problem
    return None if interactive_device.present_contact(contact, requested) else "contact:empty"


def _scan_problem(params: dict, body: dict) -> str | None:
    """A symbology the request did not list (``symbology:not_requested``), then a value with nothing visible left once
    the gateway cleaned it (``scan:empty``)."""
    formats = params.get("formats")
    if formats and body["symbology"] not in formats:
        return "symbology:not_requested"
    return None if interactive_device.clean_scan_value(body["value"]).strip() else "scan:empty"


# ── entry point ────────────────────────────────────────────────────────────────────────────────

#: The methods whose result is ``{status: answered | skipped}`` (``done`` for the calendar) and that may be skipped
#: only when the request is ``optional``.
_SKIPPABLE = ("input.form", "input.file", "input.signature", "device.location", "device.contact", "device.calendar",
              "device.scan")


def validate_answer(method: str, params: dict, result: Any) -> str | None:
    """The reason the answer *result* to the *method* request sent with *params* must not settle it, or None.
    First the result model (``bad_shape``), then ``not_optional``, then the method's own checks."""
    if method not in INTERACTIVE_METHODS:
        return "bad_shape"
    try:
        model = SERVER_REQUESTS[method].result.model_validate(result)
        if method == "review.diff":
            return _diff_problem(params, model.model_dump(mode="python"))
        # ``exclude_unset``: a contact's keys are the ones the client SENT (a ``null`` counts), not the model's defaults.
        body = model.root.model_dump(mode="python", exclude_unset=method == "device.contact")
        if method in _SKIPPABLE:
            if body["status"] == "skipped":
                return None if params.get("optional") else "not_optional"
            if method == "input.form":
                return _form_problem(params, body["values"])
            if method == "input.file":
                return _file_problem(params, body["files"]) or _transcript_problem(params, body)
            if method == "input.signature":
                return _signature_problem(params, body)
            if method == "device.location":
                return _location_problem(params, body)
            if method == "device.contact":
                return _contact_problem(params, body["contact"])
            if method == "device.scan":
                return _scan_problem(params, body)
            return None  # device.calendar: ``done`` says all there is
        return _draft_problem(params, body)
    except ValidationError:
        return "bad_shape"
    except Exception:  # noqa: BLE001 - this runs under the request lock: a check that cannot be made refuses
        return "bad_shape"


def _answer_zones(params: dict, result: Any) -> list[str]:
    """The zone names a form answer's datetime values carry (for :meth:`_Validator.warm`)."""
    values = result.get("values") if isinstance(result, dict) else None
    if not isinstance(values, dict):
        return []
    names = []
    for field in params.get("fields") or []:
        value = values.get(field.get("id")) if isinstance(field, dict) and field.get("kind") == "datetime" else None
        if isinstance(value, str) and (parts := _PARTS.fullmatch(value)) is not None:
            names.append(parts.group(10))
    return names


class _Validator:
    """``validate_answer`` bound to one request, for ``send_gated(validate=...)``. :meth:`warm` loads, outside the
    request lock, the zones an answer names, so the check under the lock finds them in :data:`_zones`."""

    __slots__ = ("method", "params")

    def __init__(self, method: str, params: dict) -> None:
        self.method, self.params = method, params

    def __call__(self, result: Any) -> str | None:
        return validate_answer(self.method, self.params, result)

    def warm(self, result: Any) -> None:
        """Never raises; at most one zone file per known zone is ever read."""
        if self.method != "input.form":
            return
        try:
            for name in _answer_zones(self.params, result):
                zone(name)
        except Exception:  # noqa: BLE001
            pass


def validator(method: str, params: dict) -> _Validator:
    """``validate_answer`` bound to one request, for ``send_gated(validate=...)``."""
    return _Validator(method, params)
