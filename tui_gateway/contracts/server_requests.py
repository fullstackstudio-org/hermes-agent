"""Server→client requests: the backend asks the renderer a question (``server_requests.send``).

Every entry is one request method: the ``params`` the frame carries (``session_id`` is added by
the transport and declared on the shared base) and the ``result`` the client answers with. The
``request.cancel`` event that withdraws an open request lives here too.
"""

from __future__ import annotations

import datetime as _dt
import re
from decimal import Decimal
from typing import Annotated, Any, Callable, Literal

from pydantic import Field, RootModel, StrictBool, StrictFloat, StrictInt, StrictStr, model_validator

from .base import JsonValue, Params, Payload, Result, WireEnum
from .registry import event, server_request


class ServerRequestParams(Params):
    """Every request frame's params start with the session the question belongs to."""

    session_id: str


class ValueResult(Result):
    """The answer to any one-string prompt (sudo, secret, vault prompts, desktop bridges):
    ``''`` means skipped / declined."""

    value: str


# ── clarify ───────────────────────────────────────────────────────────────────────────────────


class ClarifyQuestion(Params):
    qid: str
    question: str
    choices: list[str] | None = None
    multi_select: bool = False


class ClarifyRequestParams(ServerRequestParams):
    """Single question: ``question`` / ``choices`` (/ ``multi_select``); batch: ``questions``.
    ``answers`` rides only on a reconnect replay (locks the server already accepted)."""

    question: str | None = None
    choices: list[str] | None = None
    multi_select: bool | None = None
    questions: list[ClarifyQuestion] | None = None
    answers: dict[str, str] | None = None


class ClarifyResult(Result):
    """Single: ``{answer}`` ('' = skip). Batch: ``{answers}`` for the whole set (early locks go through
    the ``clarify.lock`` RPC); a response with neither is cancel-all."""

    answer: str | None = None
    answers: dict[str, str] | None = None


server_request("clarify", params=ClarifyRequestParams, result=ClarifyResult,
               doc="The clarify tool: ask the user one question or a batch.")


# ── approval ──────────────────────────────────────────────────────────────────────────────────


class ApprovalChoice(WireEnum):
    once = "once"
    session = "session"
    always = "always"
    deny = "deny"


class ApprovalRequestParams(ServerRequestParams):
    """``tui_gateway/server.py::_approval_request_payload`` — the command is redacted server-side."""

    request_id: str
    command: str = ""
    description: str = ""
    choices: list[ApprovalChoice] = Field(default_factory=list)
    allow_permanent: bool | None = None
    allow_session: bool | None = None
    smart_denied: bool | None = None
    tool_name: str | None = None
    session_id_hint: str | None = Field(default=None, alias="gateway_session_id")
    # The approval queue entry carries tool-specific context the card may render; the closed set
    # of keys is owned by tools/approval.py, so it stays open here.
    model_config = Params.model_config | {"extra": "allow"}


class ApprovalResult(Result):
    choice: ApprovalChoice
    all: bool | None = None


server_request("approval", params=ApprovalRequestParams, result=ApprovalResult,
               doc="A dangerous command awaits the user's decision.")


# ── one-string prompts ────────────────────────────────────────────────────────────────────────


class EmptyRequestParams(ServerRequestParams):
    pass


class SudoRequestParams(ServerRequestParams):
    """Original command, redacted server-side before any password-injection rewrite."""

    command: str = ""


server_request("sudo", params=SudoRequestParams, result=ValueResult,
               doc="Masked sudo password for the terminal tool.")


class SecretRequestParams(ServerRequestParams):
    env_var: str
    prompt: str
    metadata: dict[str, JsonValue] | None = None


server_request("secret", params=SecretRequestParams, result=ValueResult,
               doc="Masked value for a named env var (skills / setup flows).")


class VaultUnlockRequestParams(ServerRequestParams):
    backend: str
    display_name: str


server_request("vault.unlock_prompt", params=VaultUnlockRequestParams, result=ValueResult,
               doc="Master password to unlock an external password manager for this session.")


class VaultSaveLoginRequestParams(ServerRequestParams):
    origin: str
    site: str


server_request("vault.save_login", params=VaultSaveLoginRequestParams, result=ValueResult,
               doc="Save a login for a site the agent is about to fill; the answer is JSON {identifier, password}.")


class VaultCodeRequestParams(ServerRequestParams):
    site: str | None = None
    hint: str | None = None


server_request("vault.code", params=VaultCodeRequestParams, result=ValueResult,
               doc="A one-time / 2FA code the user reads from their device.")


# ── desktop GUI bridges ───────────────────────────────────────────────────────────────────────


class ReadRangeRequestParams(ServerRequestParams):
    start: int | None = None
    count: int | None = None


server_request("terminal.read", params=ReadRangeRequestParams, result=ValueResult,
               doc="Read the visible in-app terminal buffer (JSON text answer).")
server_request("preview.read", params=ReadRangeRequestParams, result=ValueResult,
               doc="Read the in-app browser preview's text (JSON text answer).")
server_request("window.read", params=EmptyRequestParams, result=ValueResult,
               doc="Enumerate the native window below the app (JSON text answer).")


class PreviewActRequestParams(ServerRequestParams):
    """``tools/drive_preview_tool.py`` and ``tools/annotate_preview_tool.py`` field sets."""

    action: str
    ref: str | None = None
    selector: str | None = None
    text: str | None = None
    key: str | None = None
    submit: bool | None = None
    full: bool | None = None
    to: str | None = None
    amount: int | None = None
    max: int | None = None


server_request("preview.act", params=PreviewActRequestParams, result=ValueResult,
               doc="Click / type / scroll / annotate inside the in-app browser preview.")


class TourStep(Params):
    selector: str | None = None
    title: str | None = None
    text: str | None = None
    side: str | None = None
    model_config = Params.model_config | {"extra": "allow"}


class TourRequestParams(ServerRequestParams):
    """``tools/tour_tool.py`` field set."""

    action: str
    surface: str | None = None
    selector: str | None = None
    title: str | None = None
    text: str | None = None
    side: str | None = None
    steps: list[TourStep] | None = None
    step_index: int | None = None


server_request("tour", params=TourRequestParams, result=ValueResult,
               doc="Drive a guided tour highlight in the desktop renderer.")


# ── confirm ───────────────────────────────────────────────────────────────────────────────────

CONFIRM_TITLE_MAX = 80
CONFIRM_SUMMARY_MAX = 500
CONFIRM_DETAIL_MAX = 2_000


class ConfirmLevel(WireEnum):
    """What a confirmation proves. ``plain``: someone tapped Confirm in a connected client; nothing more,
    and the gateway cannot check even that. ``passkey``: the gateway verified a WebAuthn assertion with
    user verification, made by a passkey enrolled for the person the turn acts for, over a challenge that
    commits to this gateway, session, request and text (``contract/confirm-passkey/README.md``). Sent only
    to connections signed in as that person that advertised the level with an accepted RP. The set is open:
    a later level is one more value here."""

    plain = "plain"
    passkey = "passkey"


class ConfirmDecision(WireEnum):
    confirmed = "confirmed"
    declined = "declined"


class ConfirmMethod(WireEnum):
    """How the client obtained the decision. ``tap``: a button, nothing proven (every decline is a tap).
    ``passkey``: a WebAuthn assertion, carried in ``ConfirmResult.passkey`` and verified by the gateway."""

    tap = "tap"
    passkey = "passkey"


class ConfirmPasskeyUser(Params):
    """The person the request is bound to: the turn's acting user, ``<provider>:<user id>``."""

    id: str
    name: str


class ConfirmPasskeyCredentials(Params):
    """The bound user's active credentials for one RP (base64url ids): a client passes the ones for its own
    RP as ``allowCredentials`` and refuses (4040) a request without any."""

    rp_id: str
    ids: list[str]


class ConfirmPasskeyParams(Params):
    """Level ``passkey`` only (contract §8). ``nonce`` (32 bytes) and ``gateway_id`` (16 bytes) are base64url;
    ``base_url`` is informative (a client always hashes the base URL it dialed); ``expires_at`` is Unix
    seconds."""

    v: int
    nonce: str
    gateway_id: str
    base_url: str
    expires_at: int
    user: ConfirmPasskeyUser
    credentials: list[ConfirmPasskeyCredentials]


class ConfirmPasskeyAssertion(Result):
    """The WebAuthn assertion of a ``passkey`` answer (contract §8); binary fields are base64url. The
    gateway checks it in the order of contract §9; a refusal is ``request.answer`` error 4034 with
    ``data.reason``."""

    v: int
    rp_id: str
    base_url: str
    credential_id: str
    authenticator_data: str
    client_data_json: str
    signature: str
    user_handle: str | None = None


class ConfirmRequestParams(ServerRequestParams):
    """Built and bounded by the gateway (``tui_gateway/confirm.py``), never passed through from the agent:
    control and format characters are stripped, lengths are capped, and every string is PLAIN TEXT — a
    client renders it verbatim, never as markdown or HTML. Button wording is the client's own, not the
    agent's. The text is the AGENT's own words: a client marks it as such and never lets it style its frame.
    Sent only to connections attached to the session whose ``client.capabilities`` listed ``level`` under
    ``confirm``; only such a connection, still attached, may answer. At level ``passkey`` also only to
    connections signed in as ``passkey.user`` that advertised an RP the user has a credential for."""

    title: str = Field(min_length=1, max_length=CONFIRM_TITLE_MAX)
    summary: str = Field(min_length=1, max_length=CONFIRM_SUMMARY_MAX)
    detail: str | None = Field(default=None, max_length=CONFIRM_DETAIL_MAX)
    level: ConfirmLevel
    #: Level ``passkey`` only: what the client needs to compute the challenge and run the ceremony.
    passkey: ConfirmPasskeyParams | None = None


class ConfirmResult(Result):
    """The person's decision. A client that cannot answer right now answers a JSON-RPC ERROR, never a
    made-up ``declined``: the gateway reports that as ``unavailable`` (at level ``passkey``: code 4040,
    ``data.reason``).
    ``verified`` is not the client's to set: the gateway decides it (always false for ``plain``; true only
    after it verified and committed a passkey assertion) and ignores whatever a client sends here at
    ``plain``; at ``passkey`` a client-sent ``verified`` is refused (``bad_shape``). Clients omit it.
    Level ``passkey``: ``{decision: "confirmed", method: "passkey", passkey: {...}}`` or exactly
    ``{decision: "declined", method: "tap"}``, sent through ``request.answer``."""

    decision: ConfirmDecision
    method: ConfirmMethod
    verified: bool | None = None
    passkey: ConfirmPasskeyAssertion | None = None


server_request("confirm", params=ConfirmRequestParams, result=ConfirmResult,
               doc="The agent asks the person to confirm one sensitive action. 120 s. Level plain: a tap in a "
                   "connected client, nothing verified. Level passkey: a WebAuthn assertion the gateway verifies.")


# ── interactive requests: input.* and review.* ────────────────────────────────────────────────
#
# The written contract, with normative examples, is ``contract/requests/`` (``README.md``,
# ``schema.json`` rendered from these models by ``scripts/gen_gateway_contracts.py``, ``examples.json``).
#
# Shared by every method below:
#
# - The gateway builds and bounds every params object (the agent never passes one through); every
#   string is PLAIN TEXT, shown verbatim and marked as the agent's words, never as markdown or HTML.
# - A connection is sent a method only after it listed that method under ``requests`` in
#   ``client.capabilities``.
# - A client that cannot show a request answers a JSON-RPC ERROR with code ``4041`` (``cannot_show``,
#   ``CANNOT_SHOW``) and ``data.reason`` (an open set: ``no_camera``, ``not_supported_on_device``,
#   ``permission_denied``, ``upload_failed``, ``unsupported_version``, ``shutting_down``, ``declined`` (the person
#   chose not to provide it), …), never a
#   made-up ``skipped`` or ``rejected``. The gateway reports that as ``unavailable``.
# - An answer the gateway refuses is ``request.answer`` error ``4034`` with ``data.reason``: ``bad_shape``
#   when it does not match the result model, otherwise one of the reasons in ``contract/requests/README.md``
#   (``field:<id>:<problem>`` for a form). The request stays open; after ten refusals it is withdrawn
#   (``request.cancel`` with reason ``too_many_attempts``).

#: Server→client request methods that carry ``InteractiveRequestParams`` (phases 1 and 2). A connection gets one
#: only after it listed it under ``client.capabilities`` ``requests``.
INTERACTIVE_METHODS: tuple[str, ...] = ("input.form", "input.file", "review.draft", "review.diff")

#: JSON-RPC error code a client answers when it cannot show an interactive request (``data.reason``).
CANNOT_SHOW = 4041

INTERACTIVE_TITLE_MAX = 80
INTERACTIVE_SUMMARY_MAX = 500
INTERACTIVE_DETAIL_MAX = 2_000
#: One line: no CR, LF, VT, FF, NEL, LINE SEPARATOR or PARAGRAPH SEPARATOR (the characters a renderer may break
#: a line at). Literal characters, not escapes, so every regex engine reading ``schema.json`` sees the same set.
ONE_LINE = "^[^\r\n\x0b\x0c\x85\u2028\u2029]+$"


class RequestActingUser(Params):
    """The person the request is for, ``<provider>:<user id>`` and a display name. Informative: the gateway
    enforces who may answer."""

    id: str
    name: str


class InteractiveRequestParams(ServerRequestParams):
    """The envelope of every interactive request. ``v`` is ``1``: a client that does not know the version
    answers ``4041`` with reason ``unsupported_version``. ``title`` is one line; ``summary`` is the agent's
    words; ``detail`` is shown monospaced. ``expires_at`` (Unix seconds, set by the gateway) is when the
    gateway stops waiting: a client hides the request then, and an answer after it is refused. ``optional``
    says whether Skip is offered (``input.*``: true by default; ``review.*``: false). ``acting_user`` is
    set when the gateway can name the person the turn acts for.

    Sent only to connections that listed the method under ``client.capabilities`` ``requests``. A client
    that cannot show the request answers a JSON-RPC ERROR ``4041`` (``cannot_show``) with ``data.reason``,
    never a made-up ``skipped`` or ``rejected``; the gateway reports that as ``unavailable``. A refused
    answer is ``request.answer`` error ``4034`` with ``data.reason`` (``bad_shape``, ``not_optional``,
    ``field:<id>:<problem>``, …, ``contract/requests/README.md``) and leaves the request open."""

    v: Literal[1]
    title: str = Field(min_length=1, max_length=INTERACTIVE_TITLE_MAX, pattern=ONE_LINE)
    summary: str = Field(min_length=1, max_length=INTERACTIVE_SUMMARY_MAX)
    detail: str | None = Field(default=None, max_length=INTERACTIVE_DETAIL_MAX)
    expires_at: int = Field(ge=0)
    optional: bool
    acting_user: RequestActingUser | None = None


class InputStatus(WireEnum):
    """First key of every ``input.*`` result. ``skipped`` only when the request was ``optional``."""

    answered = "answered"
    skipped = "skipped"


class ReviewDecision(WireEnum):
    """First key of every ``review.*`` result."""

    approved = "approved"
    rejected = "rejected"


# ── input.form ────────────────────────────────────────────────────────────────────────────────

# The patterns below validate WHOLE values. Checked in Python, use ``re.fullmatch``, never ``re.match`` or
# ``re.search``: Python's ``$`` also matches before a final "\n", so ``re.match(FORM_DATE, "2026-10-05\n")``
# succeeds. (Pydantic's own ``pattern=`` checks and JSON Schema's ECMA regexes anchor at the very end.) The
# answer checks of P1-F4 follow the same rule.
FORM_FIELDS_MAX = 12
FORM_FIELD_ID = r"^[a-z][a-z0-9_]{0,31}$"
FORM_TEXT_MAX = 4_000
FORM_CHOICE_OPTIONS_MAX = 12
#: A decimal string: an optional minus, no leading zeros, at most three decimals (``"12.50"``, ``"-3"``,
#: ``"1.250"``). How many decimals a value may have is the currency's ISO 4217 minor unit (EUR 2, JPY 0, KWD 3);
#: the gateway's answer check enforces that per currency (``field:<id>:format``), the model only the bound.
FORM_DECIMAL = r"^-?(0|[1-9][0-9]{0,14})(\.[0-9]{1,3})?$"
FORM_DATE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
FORM_TIME = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"
_CLOCK = r"([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?"
_OFFSET = r"[+-]([01][0-9]|2[0-3]):[0-5][0-9]"
#: An INSTANT (a datetime field's ``min``, ``max`` and ``default``): RFC 3339 date and time, seconds optional,
#: no fractions, a numeric offset (``Z`` is not used: write ``+00:00``), no zone.
FORM_DATETIME = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T" + _CLOCK + _OFFSET + "$"
#: An IANA time zone name (``Europe/Amsterdam``, ``UTC``).
FORM_TZ = r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$"
#: A datetime field's VALUE: an instant as :data:`FORM_DATETIME` followed by its IANA zone as an RFC 9557 suffix,
#: ``"2026-10-03T14:30+02:00[Europe/Amsterdam]"``. A parser strips the ``[...]`` suffix before handing the rest to
#: ``Date``, ``ISO8601DateFormatter`` or ``datetime.fromisoformat``. Checked by the gateway's answer check
#: (``field:<id>:format``): a result value is not typed by kind in the model.
FORM_DATETIME_VALUE = (r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T" + _CLOCK + _OFFSET
                       + r"\[[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*\]$")


def _ordered(kind: str, lo: Any, hi: Any, default: Any, key: Callable[[Any], Any]) -> None:
    """``min`` ≤ ``max``, and a ``default`` within them, compared through *key* (which raises ``ValueError`` for
    a value that only looks right, ``2026-02-30``). Raises ``ValueError`` naming the first problem."""
    lo_k = None if lo is None else key(lo)
    hi_k = None if hi is None else key(hi)
    if lo_k is not None and hi_k is not None and lo_k > hi_k:
        raise ValueError(f"{kind} field: min is greater than max")
    if default is not None:
        value = key(default)
        if lo_k is not None and value < lo_k:
            raise ValueError(f"{kind} field: default is below min")
        if hi_k is not None and value > hi_k:
            raise ValueError(f"{kind} field: default is above max")


def _instant(text: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(text)

class FormFieldKind(WireEnum):
    text = "text"
    number = "number"
    amount = "amount"
    date = "date"
    time = "time"
    datetime = "datetime"
    daterange = "daterange"
    choice = "choice"
    toggle = "toggle"


class FormTextInput(WireEnum):
    """A keyboard hint, never a check: the gateway does not validate an address, number or URL."""

    plain = "plain"
    email = "email"
    phone = "phone"
    url = "url"


class FormFieldBase(Params):
    """What every field has. Ids are unique within a form (the gateway builds it so)."""

    id: str = Field(pattern=FORM_FIELD_ID)
    label: str = Field(min_length=1, max_length=60)
    hint: str | None = Field(default=None, max_length=200)
    required: bool = False


class FormTextField(FormFieldBase):
    """Value: a string of at most ``max_length`` (else 4000) code points; one line unless ``multiline``.
    ``""`` counts as no value (as for every string-valued kind). A ``default`` is a value: omit it for none."""

    kind: Literal[FormFieldKind.text]
    multiline: bool = False
    max_length: int | None = Field(default=None, ge=1, le=FORM_TEXT_MAX)
    input: FormTextInput = FormTextInput.plain
    default: str | None = Field(default=None, min_length=1, max_length=FORM_TEXT_MAX)

    @model_validator(mode="after")
    def _default_fits(self) -> FormTextField:
        if self.default is not None:
            if len(self.default) > (self.max_length or FORM_TEXT_MAX):
                raise ValueError("text field: default is longer than max_length")
            if not self.multiline and any(c in self.default for c in "\r\n\x0b\x0c\x85\u2028\u2029"):
                raise ValueError("text field: a one-line field's default has a line break")
        return self


class FormNumberField(FormFieldBase):
    """Value: a JSON number in ``[min, max]``, a whole number when ``integer``, and ``min`` (else 0) plus
    a whole multiple of ``step`` when ``step`` is set."""

    kind: Literal[FormFieldKind.number]
    min: float | None = None
    max: float | None = None
    step: float | None = Field(default=None, gt=0)
    integer: bool = False
    default: float | None = None

    @model_validator(mode="after")
    def _bounds(self) -> FormNumberField:
        _ordered("number", self.min, self.max, self.default, float)
        if self.default is not None:
            if self.integer and not float(self.default).is_integer():
                raise ValueError("number field: default is not a whole number")
            if self.step is not None:
                steps = (Decimal(str(self.default)) - Decimal(str(self.min or 0))) / Decimal(str(self.step))
                if steps != steps.to_integral_value():
                    raise ValueError("number field: default is not min plus a whole multiple of step")
        return self


class FormAmountField(FormFieldBase):
    """Value: a decimal STRING (``"12.50"``: never a JSON number) in ``[min, max]``, in ``currency``
    (ISO 4217)."""

    kind: Literal[FormFieldKind.amount]
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    min: str | None = Field(default=None, pattern=FORM_DECIMAL)
    max: str | None = Field(default=None, pattern=FORM_DECIMAL)
    default: str | None = Field(default=None, pattern=FORM_DECIMAL)

    @model_validator(mode="after")
    def _bounds(self) -> FormAmountField:
        _ordered("amount", self.min, self.max, self.default, Decimal)
        return self


class FormDateField(FormFieldBase):
    """Value: a calendar date ``"2026-10-03"`` in ``[min, max]``. ``tz`` names the zone "today" is in."""

    kind: Literal[FormFieldKind.date]
    min: str | None = Field(default=None, pattern=FORM_DATE)
    max: str | None = Field(default=None, pattern=FORM_DATE)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: str | None = Field(default=None, pattern=FORM_DATE)

    @model_validator(mode="after")
    def _bounds(self) -> FormDateField:
        _ordered("date", self.min, self.max, self.default, _dt.date.fromisoformat)
        return self


class FormTimeField(FormFieldBase):
    """Value: a 24-hour wall-clock time ``"14:30"`` in ``[min, max]``."""

    kind: Literal[FormFieldKind.time]
    min: str | None = Field(default=None, pattern=FORM_TIME)
    max: str | None = Field(default=None, pattern=FORM_TIME)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: str | None = Field(default=None, pattern=FORM_TIME)

    @model_validator(mode="after")
    def _bounds(self) -> FormTimeField:
        _ordered("time", self.min, self.max, self.default, _dt.time.fromisoformat)
        return self


class FormDatetimeField(FormFieldBase):
    """Value (:data:`FORM_DATETIME_VALUE`): RFC 3339 with the offset AND the IANA zone as an RFC 9557 suffix,
    ``"2026-10-03T14:30:00+02:00[Europe/Amsterdam]"``: the zone is ``tz`` when the field has one, else the
    device's; the offset is that zone's at that instant. ``min``, ``max`` and ``default`` are INSTANTS
    (:data:`FORM_DATETIME`: offset, no zone); the client shows ``default`` in the answer's zone."""

    kind: Literal[FormFieldKind.datetime]
    min: str | None = Field(default=None, pattern=FORM_DATETIME)
    max: str | None = Field(default=None, pattern=FORM_DATETIME)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: str | None = Field(default=None, pattern=FORM_DATETIME)

    @model_validator(mode="after")
    def _bounds(self) -> FormDatetimeField:
        _ordered("datetime", self.min, self.max, self.default, _instant)
        return self


class FormDateRange(Params):
    """A ``daterange`` value: two calendar dates, ``start`` ≤ ``end``, both inclusive."""

    start: StrictStr
    end: StrictStr


class FormDaterangeField(FormFieldBase):
    """Value: ``{start, end}`` (``FormDateRange``) with ``min`` ≤ ``start`` ≤ ``end`` ≤ ``max``."""

    kind: Literal[FormFieldKind.daterange]
    min: str | None = Field(default=None, pattern=FORM_DATE)
    max: str | None = Field(default=None, pattern=FORM_DATE)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: FormDateRange | None = None

    @model_validator(mode="after")
    def _bounds(self) -> FormDaterangeField:
        _ordered("daterange", self.min, self.max, None, _dt.date.fromisoformat)
        if self.default is not None:
            start, end = self.default.start, self.default.end
            if not (re.fullmatch(FORM_DATE, start) and re.fullmatch(FORM_DATE, end)):
                raise ValueError("daterange field: default start and end are YYYY-MM-DD")
            if _dt.date.fromisoformat(start) > _dt.date.fromisoformat(end):
                raise ValueError("daterange field: default ends before it starts")
            for day in (start, end):
                _ordered("daterange", self.min, self.max, day, _dt.date.fromisoformat)
        return self


class FormChoiceOption(Params):
    value: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=80)


class FormChoiceField(FormFieldBase):
    """Value: one option ``value`` (a string), or with ``multiple`` a list of distinct option values whose
    length is in ``[min_selected, max_selected]``; ``[]`` counts as no value."""

    kind: Literal[FormFieldKind.choice]
    options: list[FormChoiceOption] = Field(min_length=1, max_length=FORM_CHOICE_OPTIONS_MAX)
    multiple: bool = False
    min_selected: int | None = Field(default=None, ge=0, le=FORM_CHOICE_OPTIONS_MAX)
    max_selected: int | None = Field(default=None, ge=1, le=FORM_CHOICE_OPTIONS_MAX)
    default: str | list[str] | None = None

    @model_validator(mode="after")
    def _consistent(self) -> FormChoiceField:
        values = [option.value for option in self.options]
        if len(set(values)) != len(values):
            raise ValueError("choice field: two options have the same value")
        if not self.multiple and (self.min_selected is not None or self.max_selected is not None):
            raise ValueError("choice field: min_selected / max_selected need multiple")
        lo, hi = self.min_selected, self.max_selected
        if lo is not None and hi is not None and lo > hi:
            raise ValueError("choice field: min_selected is greater than max_selected")
        if (lo or 0) > len(values) or (hi is not None and hi > len(values)):
            raise ValueError("choice field: more selections than options")
        if self.default is None:
            return self
        if not self.multiple:
            if not isinstance(self.default, str) or self.default not in values:
                raise ValueError("choice field: default is not one option value")
            return self
        if not isinstance(self.default, list) or any(value not in values for value in self.default):
            raise ValueError("choice field: default is not a list of option values")
        if len(set(self.default)) != len(self.default):
            raise ValueError("choice field: default lists a value twice")
        if (lo is not None and len(self.default) < lo) or (hi is not None and len(self.default) > hi):
            raise ValueError("choice field: default selects too few or too many")
        return self


class FormToggleField(FormFieldBase):
    """Value: a JSON boolean."""

    kind: Literal[FormFieldKind.toggle]
    default: bool | None = None


class FormField(RootModel[Annotated[
    FormTextField | FormNumberField | FormAmountField | FormDateField | FormTimeField | FormDatetimeField
    | FormDaterangeField | FormChoiceField | FormToggleField,
    Field(discriminator="kind"),
]]):
    """One form field, discriminated by ``kind``. A client that does not know a kind answers ``4041``
    (``not_supported_on_device``) rather than leave the field out."""


class InputFormRequestParams(InteractiveRequestParams):
    """``fields``: 1-12, ids unique within the form. Every field is consistent in itself (``min`` ≤ ``max``, a
    ``default`` that is a valid value, distinct option values, ``min_selected`` ≤ ``max_selected`` ≤ the
    options): rules ``schema.json`` cannot express, pinned by ``examples.json`` ``invalid_frames``."""

    fields: list[FormField] = Field(min_length=1, max_length=FORM_FIELDS_MAX)

    @model_validator(mode="after")
    def _unique_ids(self) -> InputFormRequestParams:
        ids = [field.root.id for field in self.fields]
        if len(set(ids)) != len(ids):
            raise ValueError("input.form: two fields have the same id")
        return self


FormValue = StrictBool | StrictInt | StrictFloat | StrictStr | list[StrictStr] | FormDateRange


def _field_id_keys(schema: dict) -> None:
    """``values`` in JSON Schema: the key rule as ``propertyNames`` and the value schema as ``additionalProperties``
    (pydantic writes a key pattern as ``patternProperties``, which lets every other key through with any value)."""
    patterns = schema.pop("patternProperties", None) or {}
    if len(patterns) == 1:
        ((pattern, value_schema),) = patterns.items()
        schema["propertyNames"] = {"pattern": pattern}
        schema["additionalProperties"] = value_schema


class InputFormAnswered(Result):
    """``values`` maps field ids to values; a field without a value is left out. A key that is not a well-formed
    field id (``FORM_FIELD_ID``) fails the model (``bad_shape``: no text of the client's goes into a reason). The
    gateway re-validates every value against its field (required present, typed, in range, no unknown id) and
    refuses the first problem as ``field:<id>:<problem>``."""

    status: Literal[InputStatus.answered]
    values: dict[Annotated[str, Field(pattern=FORM_FIELD_ID)], FormValue] = Field(
        max_length=FORM_FIELDS_MAX, json_schema_extra=_field_id_keys)


class InputFormSkipped(Result):
    status: Literal[InputStatus.skipped]


class InputFormResult(RootModel[Annotated[InputFormAnswered | InputFormSkipped, Field(discriminator="status")]]):
    """``{status: answered, values}`` or ``{status: skipped}`` (only when ``optional``)."""


server_request("input.form", params=InputFormRequestParams, result=InputFormResult,
               doc="The agent asks the person to fill in a form of typed fields (1-12). 300 s.")


# ── input.file ────────────────────────────────────────────────────────────────────────────────

#: Per FILE.
UPLOAD_MAX_BYTES = 104_857_600
UPLOAD_MAX_FILES = 10
#: An uploaded file's absolute ``path`` (PATH_MAX on Linux).
UPLOAD_PATH_MAX = 4_096
#: For ALL files of one answer together (``upload.max_total_bytes``).
UPLOAD_MAX_TOTAL_BYTES = 104_857_600


class FileAccept(WireEnum):
    image = "image"
    document = "document"
    audio = "audio"
    any = "any"


class FileCapture(WireEnum):
    """A preference for how to obtain the file; the person may always pick an existing one."""

    photo = "photo"
    scan = "scan"
    audio = "audio"


class UploadTarget(Params):
    """Where the answer's files go. ``dir`` is an absolute path under the session's working directory; the
    client uploads each file through the HTTP upload route (the credentials it uses for attachments) to
    ``<dir>/<16 hex>-<safe name>`` and answers with references, never bytes. ``strip_metadata``: remove
    EXIF / GPS from camera and library images before uploading. ``max_bytes`` bounds each file,
    ``max_total_bytes`` (≥ ``max_bytes``, at most 100 MiB) all files of the answer together."""

    dir: str = Field(min_length=2, pattern=r"^/")
    max_bytes: int = Field(ge=1, le=UPLOAD_MAX_BYTES)
    max_total_bytes: int = Field(ge=1, le=UPLOAD_MAX_TOTAL_BYTES)
    max_files: int = Field(ge=1, le=UPLOAD_MAX_FILES)
    strip_metadata: bool

    @model_validator(mode="after")
    def _total_covers_one_file(self) -> UploadTarget:
        if self.max_total_bytes < self.max_bytes:
            raise ValueError("upload: max_total_bytes is smaller than max_bytes")
        return self


class InputFileRequestParams(InteractiveRequestParams):
    accept: FileAccept
    capture: FileCapture | None = None
    multiple: bool
    upload: UploadTarget


class UploadedFile(Result):
    """One uploaded file: its absolute ``path`` (under ``upload.dir``), the name the person sees, the MIME
    type, the size and the lowercase hex SHA-256 of the bytes as uploaded. The gateway checks size and hash
    after the request settles."""

    path: str = Field(min_length=2, max_length=UPLOAD_PATH_MAX, pattern=r"^/")
    name: str = Field(min_length=1, max_length=120)
    mime: str = Field(min_length=1, max_length=80)
    bytes: StrictInt = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class InputFileAnswered(Result):
    """``files`` (at most ``upload.max_files``, one unless ``multiple``) and an optional ``text`` (an audio
    answer's transcript)."""

    status: Literal[InputStatus.answered]
    files: list[UploadedFile] = Field(min_length=1, max_length=UPLOAD_MAX_FILES)
    text: str | None = Field(default=None, max_length=4_000)


class InputFileSkipped(Result):
    status: Literal[InputStatus.skipped]


class InputFileResult(RootModel[Annotated[InputFileAnswered | InputFileSkipped, Field(discriminator="status")]]):
    """``{status: answered, files, text?}`` or ``{status: skipped}`` (only when ``optional``)."""


server_request("input.file", params=InputFileRequestParams, result=InputFileResult,
               doc="The agent asks the person for one or more files (photo, scan, document, audio), uploaded "
                   "to upload.dir and answered by reference. 300 s.")


# ── review.draft ──────────────────────────────────────────────────────────────────────────────

DRAFT_TEXT_MAX = 20_000


class DraftKind(WireEnum):
    mail = "mail"
    post = "post"
    message = "message"
    document = "document"


class ReviewDraftRequestParams(InteractiveRequestParams):
    """``text`` is shown verbatim (the gateway refuses to build a draft it cannot show as it is);
    ``subject`` and ``recipients`` are display only, shown apart from the body. With ``editable`` the
    person may change the text before approving."""

    kind: DraftKind
    text: str = Field(min_length=1, max_length=DRAFT_TEXT_MAX)
    subject: str | None = Field(default=None, max_length=200)
    recipients: list[Annotated[str, Field(max_length=120)]] | None = Field(default=None, max_length=10)
    editable: bool = True


class ReviewDraftApproved(Result):
    """The text as approved: unchanged unless ``editable``. The gateway removes trailing whitespace per line
    and refuses text it could not show verbatim (``text:not_verbatim``) or, when not ``editable``, any
    change (``text:edited``)."""

    decision: Literal[ReviewDecision.approved]
    text: str = Field(min_length=1, max_length=DRAFT_TEXT_MAX)


class ReviewDraftRejected(Result):
    decision: Literal[ReviewDecision.rejected]
    comment: str | None = Field(default=None, max_length=1_000)


class ReviewDraftResult(RootModel[Annotated[ReviewDraftApproved | ReviewDraftRejected,
                                            Field(discriminator="decision")]]):
    """``{decision: approved, text}`` or ``{decision: rejected, comment?}``."""


server_request("review.draft", params=ReviewDraftRequestParams, result=ReviewDraftResult,
               doc="The agent shows the person a draft (mail, post, message, document) to approve, edit or "
                   "reject before it acts on it. 300 s.")


# ── review.diff ───────────────────────────────────────────────────────────────────────────────

DIFF_HUNKS_MAX = 200
DIFF_HUNK_LINES_MAX = 400
DIFF_LINE_MAX = 500
DIFF_HEADER_MAX = 200
DIFF_PATH_MAX = 300
DIFF_HUNK_ID = r"^h[1-9][0-9]{0,2}$"
#: ``@@ -a,b +c,d @@`` and, after a space, the section text git adds; one line.
DIFF_HEADER = "^@@ -[0-9]{1,9}(,[0-9]{1,9})? \\+[0-9]{1,9}(,[0-9]{1,9})? @@( [^\r\n\x0b\x0c\x85\u2028\u2029]*)?$"
#: A hunk line: its marker (space = context, ``+`` added, ``-`` removed) and one line of text, or git's marker for a
#: missing final newline. Literal characters, as in :data:`ONE_LINE`.
DIFF_LINE = "^([ +-][^\r\n\x0b\x0c\x85\u2028\u2029]*|\\\\ No newline at end of file)$"


class DiffAnchor(WireEnum):
    """Where ``git apply`` pins a hunk whatever the header's line numbers say (``contract/requests`` §7): ``start``
    (it must match at the beginning of the file), ``end`` (no context line after its last change: it must match at
    the END of the file) or ``both`` (a whole-file hunk)."""

    start = "start"
    end = "end"
    both = "both"


class DiffHunk(Params):
    """One hunk of the diff: ``id`` (``h1``, ``h2``, ... as the gateway numbered them), the ``@@ -a,b +c,d @@`` line
    and the hunk's lines, each with its marker, and ``anchor`` when the hunk is pinned to the start and/or the end of
    the file (absent otherwise). The gateway built it from the agent's diff and keeps its own copy: what the person
    approves is that copy. The header's line numbers are not checked against the file; ``anchor`` is what the gateway
    can vouch for, and a client shows it next to the line numbers."""

    id: str = Field(pattern=DIFF_HUNK_ID)
    header: str = Field(min_length=1, max_length=DIFF_HEADER_MAX, pattern=DIFF_HEADER)
    lines: list[Annotated[str, Field(min_length=1, max_length=DIFF_LINE_MAX, pattern=DIFF_LINE)]] = Field(
        min_length=1, max_length=DIFF_HUNK_LINES_MAX)
    anchor: DiffAnchor | None = None


class DiffKind(WireEnum):
    """What the diff does to its file, as the gateway read it from the header: ``modify`` an existing file, ``new``
    a file that does not exist yet, ``delete`` a file, ``rename`` a file to another path (with the edits the hunks
    show; the person is shown the old path too)."""

    modify = "modify"
    new = "new"
    delete = "delete"
    rename = "rename"


class ReviewDiffRequestParams(InteractiveRequestParams):
    """The changes to one file, hunk by hunk, for the person to approve or reject each (``contract/requests``
    §7). ``path`` (required) is the file's relative path, display only: the new path of a rename, the deleted file's
    path for ``delete``. ``kind`` says what happens to it and ``old_path`` is a rename's previous path (present for
    ``rename`` only). ``hunks``: 1-200, ids unique. Every line of every hunk is shown verbatim (the rules of §6 on
    the line without its marker, with tabs allowed, and the layout limits of §7.1)."""

    kind: DiffKind
    path: str = Field(min_length=1, max_length=DIFF_PATH_MAX, pattern=ONE_LINE)
    old_path: str | None = Field(default=None, min_length=1, max_length=DIFF_PATH_MAX, pattern=ONE_LINE)
    hunks: list[DiffHunk] = Field(min_length=1, max_length=DIFF_HUNKS_MAX)

    @model_validator(mode="after")
    def _consistent(self) -> ReviewDiffRequestParams:
        ids = [hunk.id for hunk in self.hunks]
        if len(set(ids)) != len(ids):
            raise ValueError("review.diff: two hunks have the same id")
        if (self.kind == DiffKind.rename) != (self.old_path is not None):
            raise ValueError("review.diff: old_path is given for a rename and only for a rename")
        return self


class HunkDecision(WireEnum):
    approved = "approved"
    rejected = "rejected"


class ReviewDiffResult(Result):
    """``decision`` and one entry in ``hunks`` for EVERY hunk of the request, keyed by its id. A key that is not a
    well-formed hunk id fails the model (``bad_shape``: no text of the client's goes into a reason). The gateway
    refuses the first problem against the request: ``hunk:<id>:unknown`` (an id the request lacks),
    ``hunk:<id>:missing`` (an id of the request left out), then ``decision:inconsistent`` (``approved`` with no hunk
    approved, or ``rejected`` with one approved)."""

    decision: ReviewDecision
    hunks: dict[Annotated[str, Field(pattern=DIFF_HUNK_ID)], HunkDecision] = Field(
        min_length=1, max_length=DIFF_HUNKS_MAX, json_schema_extra=_field_id_keys)


server_request("review.diff", params=ReviewDiffRequestParams, result=ReviewDiffResult,
               doc="The agent shows the person the changes to a file, hunk by hunk, to approve or reject each "
                   "before it applies them. 300 s.")


# ── withdrawal ────────────────────────────────────────────────────────────────────────────────


class RequestCancelReason(WireEnum):
    timeout = "timeout"
    interrupted = "interrupted"
    shutdown = "shutdown"
    resolved = "resolved"
    session_closed = "session_closed"
    #: A ``confirm`` at level ``passkey`` was settled ``unavailable`` after five refused answers.
    too_many_attempts = "too_many_attempts"
    #: A ``confirm`` at level ``passkey`` was answered with a valid assertion (``request.answer`` said
    #: ``ok``), but the gateway could not commit it (the passkey was revoked meanwhile, a replay, a counter
    #: regression, a store error): it is NOT confirmed. Clear any "confirmed" state for that id.
    verification_failed = "verification_failed"


class RequestCancelPayload(Payload):
    id: str
    method: str
    reason: str  # a RequestCancelReason value; callers in tools/approval may pass their own wording


event("request.cancel", RequestCancelPayload,
      doc="The backend withdrew an open server→client request; clear the matching card only.")
