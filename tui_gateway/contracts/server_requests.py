"""Server→client requests: the backend asks the renderer a question (``server_requests.send``).

Every entry is one request method: the ``params`` the frame carries (``session_id`` is added by
the transport and declared on the shared base) and the ``result`` the client answers with. The
``request.cancel`` event that withdraws an open request lives here too.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, RootModel, StrictBool, StrictFloat, StrictInt, StrictStr

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
#   ``permission_denied``, ``upload_failed``, ``unsupported_version``, ``shutting_down``, …), never a
#   made-up ``skipped`` or ``rejected``. The gateway reports that as ``unavailable``.
# - An answer the gateway refuses is ``request.answer`` error ``4034`` with ``data.reason``: ``bad_shape``
#   when it does not match the result model, otherwise one of the reasons in ``contract/requests/README.md``
#   (``field:<id>:<problem>`` for a form). The request stays open; after ten refusals it is withdrawn
#   (``request.cancel`` with reason ``too_many_attempts``).

#: Server→client request methods that carry ``InteractiveRequestParams`` (phase 1). A connection gets one
#: only after it listed it under ``client.capabilities`` ``requests``.
INTERACTIVE_METHODS: tuple[str, ...] = ("input.form", "input.file", "review.draft")

#: JSON-RPC error code a client answers when it cannot show an interactive request (``data.reason``).
CANNOT_SHOW = 4041

INTERACTIVE_TITLE_MAX = 80
INTERACTIVE_SUMMARY_MAX = 500
INTERACTIVE_DETAIL_MAX = 2_000


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
    title: str = Field(min_length=1, max_length=INTERACTIVE_TITLE_MAX, pattern=r"^[^\r\n]+$")
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

FORM_FIELDS_MAX = 12
FORM_FIELD_ID = r"^[a-z][a-z0-9_]{0,31}$"
FORM_TEXT_MAX = 4_000
FORM_CHOICE_OPTIONS_MAX = 12
#: A decimal string: an optional minus, no leading zeros, at most two decimals (``"12.50"``, ``"-3"``).
FORM_DECIMAL = r"^-?(0|[1-9][0-9]{0,14})(\.[0-9]{1,2})?$"
FORM_DATE = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
FORM_TIME = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"
#: RFC 3339 date-time with an offset (a datetime field's ``min`` / ``max``).
FORM_DATETIME = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?(Z|[+-][0-9]{2}:[0-9]{2})$"
#: An IANA time zone name (``Europe/Amsterdam``, ``UTC``).
FORM_TZ = r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$"

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
    ``""`` counts as no value."""

    kind: Literal[FormFieldKind.text]
    multiline: bool = False
    max_length: int | None = Field(default=None, ge=1, le=FORM_TEXT_MAX)
    input: FormTextInput = FormTextInput.plain
    default: str | None = Field(default=None, max_length=FORM_TEXT_MAX)


class FormNumberField(FormFieldBase):
    """Value: a JSON number in ``[min, max]``, a whole number when ``integer``, and ``min`` (else 0) plus
    a whole multiple of ``step`` when ``step`` is set."""

    kind: Literal[FormFieldKind.number]
    min: float | None = None
    max: float | None = None
    step: float | None = Field(default=None, gt=0)
    integer: bool = False
    default: float | None = None


class FormAmountField(FormFieldBase):
    """Value: a decimal STRING (``"12.50"``: never a JSON number) in ``[min, max]``, in ``currency``
    (ISO 4217)."""

    kind: Literal[FormFieldKind.amount]
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    min: str | None = Field(default=None, pattern=FORM_DECIMAL)
    max: str | None = Field(default=None, pattern=FORM_DECIMAL)
    default: str | None = Field(default=None, pattern=FORM_DECIMAL)


class FormDateField(FormFieldBase):
    """Value: a calendar date ``"2026-10-03"`` in ``[min, max]``. ``tz`` names the zone "today" is in."""

    kind: Literal[FormFieldKind.date]
    min: str | None = Field(default=None, pattern=FORM_DATE)
    max: str | None = Field(default=None, pattern=FORM_DATE)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: str | None = Field(default=None, pattern=FORM_DATE)


class FormTimeField(FormFieldBase):
    """Value: a 24-hour wall-clock time ``"14:30"`` in ``[min, max]``."""

    kind: Literal[FormFieldKind.time]
    min: str | None = Field(default=None, pattern=FORM_TIME)
    max: str | None = Field(default=None, pattern=FORM_TIME)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: str | None = Field(default=None, pattern=FORM_TIME)


class FormDatetimeField(FormFieldBase):
    """Value: RFC 3339 with the offset AND the IANA zone as an RFC 9557 suffix,
    ``"2026-10-03T14:30:00+02:00[Europe/Amsterdam]"``: the zone is ``tz`` when the field has one, else the
    device's; the offset is that zone's at that instant. ``min`` / ``max`` (offset, no zone) are instants."""

    kind: Literal[FormFieldKind.datetime]
    min: str | None = Field(default=None, pattern=FORM_DATETIME)
    max: str | None = Field(default=None, pattern=FORM_DATETIME)
    tz: str | None = Field(default=None, max_length=64, pattern=FORM_TZ)
    default: str | None = Field(default=None, pattern=FORM_DATETIME)


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
    fields: list[FormField] = Field(min_length=1, max_length=FORM_FIELDS_MAX)


FormValue = StrictBool | StrictInt | StrictFloat | StrictStr | list[StrictStr] | FormDateRange


class InputFormAnswered(Result):
    """``values`` maps field ids to values; a field without a value is left out. The gateway re-validates
    every value against its field (required present, typed, in range, no unknown id) and refuses the
    first problem as ``field:<id>:<problem>``."""

    status: Literal[InputStatus.answered]
    values: dict[str, FormValue] = Field(max_length=FORM_FIELDS_MAX)


class InputFormSkipped(Result):
    status: Literal[InputStatus.skipped]


class InputFormResult(RootModel[Annotated[InputFormAnswered | InputFormSkipped, Field(discriminator="status")]]):
    """``{status: answered, values}`` or ``{status: skipped}`` (only when ``optional``)."""


server_request("input.form", params=InputFormRequestParams, result=InputFormResult,
               doc="The agent asks the person to fill in a form of typed fields (1-12). 300 s.")


# ── input.file ────────────────────────────────────────────────────────────────────────────────

UPLOAD_MAX_BYTES = 104_857_600
UPLOAD_MAX_FILES = 10


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
    EXIF / GPS from camera and library images before uploading."""

    dir: str = Field(min_length=2, pattern=r"^/")
    max_bytes: int = Field(ge=1, le=UPLOAD_MAX_BYTES)
    max_files: int = Field(ge=1, le=UPLOAD_MAX_FILES)
    strip_metadata: bool


class InputFileRequestParams(InteractiveRequestParams):
    accept: FileAccept
    capture: FileCapture | None = None
    multiple: bool
    upload: UploadTarget


class UploadedFile(Result):
    """One uploaded file: its absolute ``path`` (under ``upload.dir``), the name the person sees, the MIME
    type, the size and the lowercase hex SHA-256 of the bytes as uploaded. The gateway checks size and hash
    after the request settles."""

    path: str = Field(min_length=2, pattern=r"^/")
    name: str = Field(min_length=1, max_length=120)
    mime: str = Field(min_length=1, max_length=80)
    bytes: int = Field(ge=0)
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
