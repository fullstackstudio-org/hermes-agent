"""What the gateway does with the answers of the device requests and of ``input.signature`` (plan
``request-types-v2`` task P3-F1, contract ``contract/requests`` §8-§11): the pure functions both the answer check
(``interactive_validate``, under the request lock) and the hand-off to the agent (``interactive``, after the request
settled) use, so the two can never disagree about what an answer means.

- :func:`round_location`: what the agent receives of a location. An ``approximate`` answer is rounded to two
  decimals (about 1.1 km of latitude) and given an accuracy of at least 1,000 m, WHATEVER the client sent; a
  ``precise`` one keeps six decimals (about 10 cm: the rest is float noise). The agent never gets more than the
  request asked for, even from a client that shared more (:func:`effective_precision`).
- :func:`present_contact`: the contact reduced to the keys the request asked for, every string cleaned. The
  validator refuses an unrequested key outright (:func:`unrequested_key`); this is the same filter a second time
  on the way out, so an answer that somehow got through carries no key the person was not asked for.
- :func:`clean_scan_value`: a decoded barcode is untrusted text. Control, format, private-use and invisible
  characters go (a bidi override, a zero-width character, an ESC), line separators become newlines; spacing is
  kept (a Wi-Fi code or a vCard is not a sentence).
- :func:`statement_sha256`: the SHA-256 of the UTF-8 bytes of a signature request's ``statement`` exactly as it
  went out. The client hashes what it showed; the answer must carry this very value.
- :func:`build_calendar_item`: the agent's calendar item as the contract's ``CalendarItem``: every string the person
  will see cleaned, anything over a bound refused (never truncated), the rest left to the contract's own model.
- :func:`png_or_svg_problem`: a signature's two files are what they say (the PNG signature, an SVG that is XML text
  with no script and no event handler), read after the request settled.

Nothing here does I/O, logs or keeps state.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import unicodedata
from typing import Any, Callable

from pydantic import ValidationError

from tui_gateway.contracts.server_requests import (
    CALENDAR_LOCATION_MAX, CALENDAR_NOTES_MAX, CALENDAR_TITLE_MAX, CONTACT_EMAILS_MAX, CONTACT_PHONES_MAX,
    CONTACT_POSTALS_MAX, LOCATION_APPROXIMATE_DECIMALS, LOCATION_APPROXIMATE_MIN_ACCURACY_M, CalendarItem,
    ContactField)
from tui_gateway.request_text import MAX_COMBINING_MARKS, _INVISIBLE_LETTERS, clean_text, default_ignorable

#: The decimals a ``precise`` location keeps: 1e-6 degree is about 11 cm.
PRECISE_DECIMALS = 6
#: Contact keys in the order the agent receives them.
CONTACT_KEYS = tuple(field.value for field in ContactField)
_LISTS = {"phones": CONTACT_PHONES_MAX, "emails": CONTACT_EMAILS_MAX, "postal": CONTACT_POSTALS_MAX}

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_SVG_START = re.compile(rb"\A(\xef\xbb\xbf)?\s*(<\?xml[^>]*\?>\s*)?(<!--.*?-->\s*)*(<!DOCTYPE\s+svg[^>]*>\s*)?<svg[\s>]",
                        re.IGNORECASE | re.DOTALL)
# What a signature drawn on a pad never needs and an SVG viewer would act on: script, event handlers, ``javascript:``,
# embedded documents and images, a stylesheet import, and a ``<use>`` that points anywhere but inside the file.
_SVG_ACTIVE = re.compile(rb"<script|\son[a-z]+\s*=|javascript:|<foreignObject|<iframe|<embed|<object|<image|@import"
                         rb"|<use\b[^>]*href\s*=\s*(?:\"(?!\#)|'(?!\#)|(?![\"'\#]))", re.IGNORECASE)


# ── location ───────────────────────────────────────────────────────────────────────────────────


def effective_precision(requested: str, answered: str) -> str:
    """The less precise of the two: a client that shares more than was asked is treated as having shared what
    was asked (the validator refuses it, so this only holds a second line)."""
    return "approximate" if "approximate" in (requested, answered) else "precise"


def _round(value: float, decimals: int) -> float:
    rounded = round(float(value), decimals)
    return 0.0 if rounded == 0 else rounded  # no negative zero


def round_location(answer: dict, requested: str) -> dict:
    """``{lat, lon, accuracy_m, at, precision}`` as the agent receives them, from a validated answer.

    ``approximate``: ``lat``/``lon`` to :data:`LOCATION_APPROXIMATE_DECIMALS` places and ``accuracy_m`` raised to
    at least :data:`LOCATION_APPROXIMATE_MIN_ACCURACY_M` (a rounded coordinate is not more accurate than its
    rounding). ``precise``: six places and the accuracy to one. ``at`` is the client's clock."""
    precision = effective_precision(requested, str(answer.get("precision")))
    accuracy = float(answer["accuracy_m"])
    if precision == "approximate":
        decimals, accuracy = LOCATION_APPROXIMATE_DECIMALS, max(accuracy, float(LOCATION_APPROXIMATE_MIN_ACCURACY_M))
    else:
        decimals = PRECISE_DECIMALS
    return {"lat": _round(answer["lat"], decimals), "lon": _round(answer["lon"], decimals),
            "accuracy_m": _round(accuracy, 1), "at": int(answer["at"]), "precision": precision}


def precision_problem(requested: str, answered: str) -> str | None:
    """``precision:too_precise`` when the client shares ``precise`` for an ``approximate`` request."""
    return "precision:too_precise" if requested == "approximate" and answered == "precise" else None


# ── contact ────────────────────────────────────────────────────────────────────────────────────


def unrequested_key(contact: dict, requested: list) -> str | None:
    """The first contact key (in :data:`CONTACT_KEYS` order) the answer carries that the request did not ask for,
    whatever its value (``null`` included: the client was told what to leave out)."""
    asked = {str(key) for key in requested}
    return next((key for key in CONTACT_KEYS if key in contact and key not in asked), None)


def present_contact(contact: dict, requested: list) -> dict:
    """The requested keys of *contact*, cleaned, in :data:`CONTACT_KEYS` order, with nothing empty left in: a string
    is one cleaned line (a postal address keeps its line breaks), a list holds at most as many entries as the
    contract allows, a birthday is as sent (it matched the contract's pattern)."""
    asked = {str(key) for key in requested}
    out: dict[str, Any] = {}
    for key in CONTACT_KEYS:
        value = contact.get(key)
        if key not in asked or value in (None, "", []):
            continue
        if key in _LISTS:
            items = [clean_text(item, multiline=key == "postal") for item in list(value)[:_LISTS[key]]]
            if items := [item for item in items if item]:
                out[key] = items
        elif key == "birthday":
            out[key] = str(value)
        elif text := clean_text(value, multiline=False):
            out[key] = text
    return out


def birthday_problem(value: str) -> str | None:
    """``contact:birthday:invalid`` for a day that does not exist (the pattern only checks the digits); February 29
    counts, with or without a year."""
    parts = value.split("-")
    try:
        if value.startswith("--"):
            # A leap year: a birthday without a year may be February 29.
            _dt.date(2000, int(parts[2]), int(parts[3]))
        else:
            _dt.date(int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, IndexError):
        return "contact:birthday:invalid"
    return None


# ── scan ───────────────────────────────────────────────────────────────────────────────────────


def clean_scan_value(value: object) -> str:
    """The decoded text of a code with what a person cannot see or what could hide something taken out: control
    characters other than a line break (a tab becomes a space), format characters (bidi overrides and isolates,
    zero-width), surrogates, private-use code points, default-ignorable and invisible ones, and combining marks past
    :data:`MAX_COMBINING_MARKS` on one character. Line and paragraph separators become newlines and every other
    kind of space a plain space. Nothing is trimmed or collapsed: ``WIFI:T:WPA;S:my  net;;`` stays as it is."""
    raw = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    out: list[str] = []
    marks = 0
    for ch in raw:
        category = unicodedata.category(ch)
        if ch in _INVISIBLE_LETTERS or default_ignorable(ch):
            marks = 0 if category not in ("Mn", "Me") else marks
            continue
        if category in ("Mn", "Me"):
            marks += 1
            if marks <= MAX_COMBINING_MARKS:
                out.append(ch)
            continue
        marks = 0
        if ch == "\n" or category in ("Zl", "Zp"):
            out.append("\n")
        elif ch == "\t" or category == "Zs":
            out.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    return "".join(out)


# ── signature ──────────────────────────────────────────────────────────────────────────────────


def statement_sha256(statement: str) -> str:
    """Lowercase hex SHA-256 of the UTF-8 bytes of *statement*, exactly as it is (no normalisation, no trimming)."""
    return hashlib.sha256(statement.encode("utf-8")).hexdigest()


def png_or_svg_problem(mime: str, head: bytes) -> str | None:
    """``type`` when the start of a signature file (*head*: at most its first MiB, all of it for a file within the
    signature's own size bound) is not what its declared *mime* says: a PNG begins with the PNG signature; an SVG is
    XML text that begins with ``<svg`` (after an XML declaration, comments or a doctype) and holds no ``<script``,
    event-handler attribute, ``javascript:`` URL, embedded object or external ``<use>`` reference."""
    if mime == "image/png":
        return None if head.startswith(_PNG_SIGNATURE) else "type"
    if mime == "image/svg+xml":
        if not _SVG_START.match(head) or _SVG_ACTIVE.search(head):
            return "type"
        return None
    return "type"


# ── calendar ───────────────────────────────────────────────────────────────────────────────────

_ITEM_KEYS = ("title", "notes", "start", "end", "all_day", "location", "url", "alarm_minutes")


def build_calendar_item(raw: Any, error: Callable[[str], Exception]) -> dict:
    """The ``item`` of a ``device.calendar`` request from what the agent passed. *error* makes the exception for a
    problem the agent must fix. Text the person sees (title, notes, location) is cleaned (``request_text.clean_text``)
    and refused when over its bound, not truncated; ``start``, ``end``, ``url`` and ``alarm_minutes`` are machine values
    and are refused, never rewritten, when they are not what the contract takes; the consistency rules (a date or an
    instant to match ``all_day``, ``end`` after ``start``, an alarm needs a start) are the contract model's, whose
    message goes back to the agent."""
    if not isinstance(raw, dict):
        raise error(f"item must be an object with at least a title (keys: {', '.join(_ITEM_KEYS)})")
    if unknown := [key for key in raw if key not in _ITEM_KEYS]:
        listed = ", ".join(repr(str(key))[:40] for key in unknown[:5])
        raise error(f"item has keys that are not part of a calendar item: {listed}. Allowed: {', '.join(_ITEM_KEYS)}.")

    def text(key: str, limit: int, *, multiline: bool, required: bool = False) -> str:
        value = raw.get(key)
        if value is None:
            if required:
                raise error(f"item.{key} is required")
            return ""
        if not isinstance(value, str):
            raise error(f"item.{key} must be a string")
        cleaned = clean_text(value, multiline=multiline)
        if required and not cleaned:
            raise error(f"item.{key} is required")
        if len(cleaned) > limit:
            raise error(f"item.{key} is {len(cleaned)} characters; the limit is {limit}.")
        return cleaned

    out: dict[str, Any] = {"title": text("title", CALENDAR_TITLE_MAX, multiline=False, required=True)}
    if notes := text("notes", CALENDAR_NOTES_MAX, multiline=True):
        out["notes"] = notes
    if location := text("location", CALENDAR_LOCATION_MAX, multiline=False):
        out["location"] = location
    for key in ("start", "end", "url"):
        if raw.get(key) is not None:
            if not isinstance(raw[key], str):
                raise error(f"item.{key} must be a string")
            out[key] = raw[key]
    if raw.get("all_day") is not None:
        if not isinstance(raw["all_day"], bool):
            raise error("item.all_day must be true or false")
        if raw["all_day"]:
            out["all_day"] = True
    if raw.get("alarm_minutes") is not None:
        if isinstance(raw["alarm_minutes"], bool) or not isinstance(raw["alarm_minutes"], int):
            raise error("item.alarm_minutes must be a whole number of minutes")
        out["alarm_minutes"] = raw["alarm_minutes"]
    try:
        CalendarItem.model_validate(out)
    except ValidationError as exc:
        # Location and message only: never the input.
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or 'item'}: {e['msg'].removeprefix('Value error, ')}"
                             for e in exc.errors()[:3])
        raise error(f"item: {problems}") from None
    return out
