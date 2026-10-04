"""Build the ``fields`` of an ``input.form`` request from what the agent passed.

The agent's field definitions are text and numbers it chose: this module cleans every string the person will SEE
(labels, hints, option labels, a text default) with :func:`request_text.clean_text`, refuses (never rewrites) every
value that is a MACHINE value (ids, option values, patterns, currency codes, zone names), refuses over-long text
instead of truncating it, and leaves the consistency rules (``min`` ≤ ``max``, a default that is a valid value, ...) to
the contract's own models (``contracts/server_requests.py``), whose messages go back to the agent so it can fix the
definition. Anything the models would coerce (``"yes"`` for a boolean) is refused here first: the person is shown
what was meant.

Every problem is raised through the *error* factory the caller passes (``interactive.InteractiveParamsError``),
so one exception type reaches the tool, with a message that names the field and the key.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable

from pydantic import ValidationError

from tui_gateway import currency_units, interactive_validate
from tui_gateway.contracts.server_requests import (
    FORM_CHOICE_OPTIONS_MAX, FORM_DECIMAL, FORM_FIELD_ID, FORM_FIELDS_MAX, FORM_TEXT_MAX, FORM_TIME, FORM_TZ, FormField,
    FormFieldKind, FormTextInput)
from tui_gateway.request_text import clean_text

LABEL_MAX = 60
HINT_MAX = 200
OPTION_VALUE_MAX = 64
OPTION_LABEL_MAX = 80

_COMMON = {"id", "kind", "label", "hint", "required", "default"}
_KIND_KEYS: dict[str, set[str]] = {
    "text": {"multiline", "max_length", "input"},
    "number": {"min", "max", "step", "integer"},
    "amount": {"currency", "min", "max"},
    "date": {"min", "max", "tz"},
    "time": {"min", "max", "tz"},
    "datetime": {"min", "max", "tz"},
    "daterange": {"min", "max", "tz"},
    "choice": {"options", "multiple", "min_selected", "max_selected"},
    "toggle": set(),
}
_ID = re.compile(FORM_FIELD_ID)
_DECIMAL = re.compile(FORM_DECIMAL)
_TZ = re.compile(FORM_TZ)
_CURRENCY = re.compile(r"[A-Z]{3}")
_CLOCK = re.compile(FORM_TIME)


def build_fields(raw: Any, error: Callable[[str], Exception]) -> list[dict]:
    """The cleaned, consistent ``fields`` list for *raw* (1-12 field objects); *error* makes the exception to
    raise for a problem the agent must fix."""
    if not isinstance(raw, list) or not raw:
        raise error("fields must be a list of 1 to 12 field objects")
    if len(raw) > FORM_FIELDS_MAX:
        raise error(f"fields has {len(raw)} entries; the limit is {FORM_FIELDS_MAX}. Ask in several rounds.")
    fields = [_Field(index, entry, error).build() for index, entry in enumerate(raw)]
    seen: set[str] = set()
    for index, field in enumerate(fields):
        if field["id"] in seen:
            raise error(f"fields[{index}]: the id {field['id']!r} is used twice")
        seen.add(field["id"])
    return fields


class _Field:
    def __init__(self, index: int, raw: Any, error: Callable[[str], Exception]) -> None:
        self.where, self.raw, self.error = f"fields[{index}]", raw, error
        self.out: dict = {}

    # ── helpers: every problem names the field and the key ────────────────────────────────────

    def fail(self, key: str, problem: str) -> Exception:
        return self.error(f"{self.where}.{key}: {problem}")

    def line(self, key: str, limit: int, *, required: bool = False) -> str | None:
        """A display string of one line, cleaned; None when absent."""
        value = self.raw.get(key)
        if value is None:
            if required:
                raise self.fail(key, "is required")
            return None
        if not isinstance(value, str):
            raise self.fail(key, "must be a string")
        cleaned = clean_text(value, multiline=False)
        if not cleaned:
            if required:
                raise self.fail(key, "is empty")
            return None
        if len(cleaned) > limit:
            raise self.fail(key, f"is {len(cleaned)} characters; the limit is {limit}")
        return cleaned

    def boolean(self, key: str) -> bool | None:
        value = self.raw.get(key)
        if value is None:
            return None
        if not isinstance(value, bool):
            raise self.fail(key, "must be true or false")
        return value

    def integer(self, key: str) -> int | None:
        value = self.raw.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise self.fail(key, "must be a whole number")
        return value

    def number(self, key: str) -> int | float | None:
        value = self.raw.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise self.fail(key, "must be a number")
        return value

    def string(self, key: str) -> str | None:
        """A machine string (a date, a pattern-checked value): kept exactly or refused."""
        value = self.raw.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise self.fail(key, "must be a string")
        return value

    def decimal(self, key: str, places: int) -> str | None:
        value = self.raw.get(key)
        if value is None:
            return None
        if isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str):
            raise self.fail(key, 'must be a decimal string such as "12.50"')
        if not _DECIMAL.fullmatch(value):
            raise self.fail(key, 'must be a decimal string such as "12.50" (at most 3 decimals, no separators)')
        if len(value.partition(".")[2]) > places:
            raise self.fail(key, f"has more decimals than the currency allows ({places})")
        return value

    # ── the field ─────────────────────────────────────────────────────────────────────────────

    def build(self) -> dict:
        raw = self.raw
        if not isinstance(raw, dict):
            raise self.error(f"{self.where} must be an object")
        kind = raw.get("kind")
        if not isinstance(kind, str) or kind not in {k.value for k in FormFieldKind}:
            raise self.fail("kind", f"must be one of: {', '.join(k.value for k in FormFieldKind)}")
        unknown = sorted(str(key)[:40] for key in raw if key not in _COMMON | _KIND_KEYS[kind])
        if unknown:
            raise self.error(f"{self.where}: {kind} fields do not take: {', '.join(unknown[:5])}")
        field_id = raw.get("id")
        if not isinstance(field_id, str) or not _ID.fullmatch(field_id):
            raise self.fail("id", "must be lowercase letters, digits and underscores, starting with a letter "
                                  "(at most 32 characters)")
        out = self.out
        out.update({"id": field_id, "kind": kind, "label": self.line("label", LABEL_MAX, required=True)})
        if (hint := self.line("hint", HINT_MAX)) is not None:
            out["hint"] = hint
        if (required := self.boolean("required")) is not None:
            out["required"] = required
        getattr(self, f"_{kind}")()
        try:
            FormField.model_validate(out)
        except ValidationError as exc:
            # Location and message only: never the input, which may hold the agent's text.
            problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'][1:]) or 'field'}: "
                                 f"{e['msg'].removeprefix('Value error, ')}"
                                 for e in exc.errors()[:3])
            raise self.error(f"{self.where}: {problems}") from None
        return out

    # ── per kind ──────────────────────────────────────────────────────────────────────────────

    def _text(self) -> None:
        out = self.out
        if (multiline := self.boolean("multiline")) is not None:
            out["multiline"] = multiline
        if (limit := self.integer("max_length")) is not None:
            if not 1 <= limit <= FORM_TEXT_MAX:
                raise self.fail("max_length", f"must be between 1 and {FORM_TEXT_MAX}")
            out["max_length"] = limit
        if (hint := self.raw.get("input")) is not None:
            if not isinstance(hint, str) or hint not in {i.value for i in FormTextInput}:
                raise self.fail("input", f"must be one of: {', '.join(i.value for i in FormTextInput)}")
            out["input"] = hint
        default = self.raw.get("default")
        if default is not None:
            if not isinstance(default, str):
                raise self.fail("default", "must be a string")
            cleaned = clean_text(default, multiline=bool(multiline))
            if cleaned:
                out["default"] = cleaned

    def _number(self) -> None:
        for key in ("min", "max", "default"):
            if (value := self.number(key)) is not None:
                self.out[key] = value
        if (step := self.number("step")) is not None:
            self.out["step"] = step
        if (whole := self.boolean("integer")) is not None:
            self.out["integer"] = whole

    def _amount(self) -> None:
        currency = self.raw.get("currency")
        if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
            raise self.fail("currency", "is required: an ISO 4217 code such as EUR")
        exponent = currency_units.exponent(currency)
        if exponent is None:
            raise self.fail("currency", f"{currency} is not an ISO 4217 currency code this gateway knows")
        self.out["currency"] = currency
        places = min(exponent, currency_units.MAX_DECIMALS)
        for key in ("min", "max", "default"):
            if (value := self.decimal(key, places)) is not None:
                self.out[key] = value

    def _when(self, keys: tuple[str, ...], check: Callable[[str], bool], shape: str) -> None:
        for key in keys:
            if (value := self.string(key)) is not None:
                if not check(value):
                    raise self.fail(key, f"must be {shape}")
                self.out[key] = value

    def _zone(self) -> None:
        if (tz := self.string("tz")) is not None:
            if not _TZ.fullmatch(tz) or interactive_validate.zone(tz) is None:
                raise self.fail("tz", "is not an IANA time zone name this gateway knows (Europe/Amsterdam)")
            self.out["tz"] = tz

    def _date(self) -> None:
        self._when(("min", "max", "default"), lambda text: interactive_validate._day(text) is not None,
                   "a real calendar date, YYYY-MM-DD")
        self._zone()

    def _time(self) -> None:
        self._when(("min", "max", "default"), lambda text: bool(_CLOCK.fullmatch(text)), "a time, HH:MM (24-hour)")
        self._zone()

    def _datetime(self) -> None:
        self._when(("min", "max", "default"), lambda text: interactive_validate.parse_instant(text) is not None,
                   "an instant with a numeric offset, like 2026-10-03T14:30+02:00 (no Z, no fractions)")
        self._zone()

    def _daterange(self) -> None:
        self._when(("min", "max"), lambda text: interactive_validate._day(text) is not None,
                   "a real calendar date, YYYY-MM-DD")
        self._zone()
        default = self.raw.get("default")
        if default is not None:
            if (not isinstance(default, dict) or set(default) != {"start", "end"}
                    or any(interactive_validate._day(day) is None for day in default.values())):
                raise self.fail("default", 'must be {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD"}, real dates')
            self.out["default"] = dict(default)

    def _choice(self) -> None:
        options = self.raw.get("options")
        if not isinstance(options, list) or not options:
            raise self.fail("options", "must be a list of 1 to 12 options")
        if len(options) > FORM_CHOICE_OPTIONS_MAX:
            raise self.fail("options", f"has {len(options)} options; the limit is {FORM_CHOICE_OPTIONS_MAX}")
        built = []
        for number, option in enumerate(options):
            entry = {"value": option, "label": option} if isinstance(option, str) else option
            if not isinstance(entry, dict) or not set(entry) <= {"value", "label"} or "value" not in entry:
                raise self.fail(f"options[{number}]", 'must be a string or {"value": ..., "label": ...}')
            value = entry["value"]
            if (not isinstance(value, str) or not value or len(value) > OPTION_VALUE_MAX
                    or clean_text(value, multiline=False) != value):
                raise self.fail(f"options[{number}].value",
                                f"must be a non-empty plain one-line string of at most {OPTION_VALUE_MAX} characters")
            label = clean_text(entry.get("label", value), multiline=False) if isinstance(
                entry.get("label", value), str) else ""
            if not label or len(label) > OPTION_LABEL_MAX:
                raise self.fail(f"options[{number}].label",
                                f"must be a non-empty string of at most {OPTION_LABEL_MAX} characters")
            built.append({"value": value, "label": label})
        self.out["options"] = built
        if (multiple := self.boolean("multiple")) is not None:
            self.out["multiple"] = multiple
        for key in ("min_selected", "max_selected"):
            if (value := self.integer(key)) is not None:
                self.out[key] = value
        default = self.raw.get("default")
        if default is not None:
            if isinstance(default, str) or (isinstance(default, list) and all(isinstance(v, str) for v in default)):
                self.out["default"] = default if isinstance(default, str) else list(default)
            else:
                raise self.fail("default", "must be an option value, or a list of them with multiple")

    def _toggle(self) -> None:
        if (value := self.boolean("default")) is not None:
            self.out["default"] = value
