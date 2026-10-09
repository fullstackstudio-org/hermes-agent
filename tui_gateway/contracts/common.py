"""Value shapes shared by several methods and events (declared once, imported everywhere)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .base import JsonValue, Params, Payload, Result, WireEnum


class OpenModel(Result):
    """A result/payload row whose known fields are typed but which the producer may extend
    (the closed set is owned elsewhere: hermes_state rows, provider inventories)."""

    model_config = Result.model_config | {"extra": "allow"}


class Usage(OpenModel):
    """``tui_gateway/server.py::_get_usage`` + ``agent/context_breakdown.py::context_usage_fields``."""

    model: str = ""
    input: int = 0
    output: int = 0
    reasoning: int = 0
    prompt: int = 0
    completion: int = 0
    total: int = 0
    calls: int = 0
    compressions: int | None = None
    context_used: int | None = None
    context_max: int | None = None
    context_percent: int | None = None
    context_source: str | None = None
    context_estimated: bool | None = None
    cache_hit_pct: int | None = None
    cache_read: int | None = None
    cache_write: int | None = None
    avg_latency_s: float | None = None
    avg_tps: float | None = None
    active_subagents: int | None = None
    dev_credits_spent_micros: int | None = None
    cost_usd: float | None = None
    cost_status: str | None = None


class ProjectRef(Result):
    """``tui_gateway/server.py::_project_info_for_cwd``."""

    id: str
    slug: str
    name: str
    primary_path: str | None = None


class McpServerStatus(OpenModel):
    name: str = ""
    status: str | None = None
    tool_count: int | None = None
    error: str | None = None


class SessionLiveInfo(OpenModel):
    """``tui_gateway/server.py::_session_info`` — the ``session.info`` event and the ``info`` field of
    ``session.create`` / ``session.resume`` / ``session.activate`` results."""

    model: str = ""
    provider: str = ""
    reasoning_effort: str = ""
    # The level the route's entry clamp actually sends for ``reasoning_effort`` ("" when unset/none;
    # equal when verbatim). Lets clients label a clamped Hermes step ("ultra sends max on this route").
    reasoning_effort_wire: str = ""
    service_tier: str = ""
    fast: bool = False
    yolo: bool = False
    approval_mode: str = "manual"
    tools: dict[str, list[str]] = Field(default_factory=dict)
    skills: dict[str, list[str]] = Field(default_factory=dict)
    cwd: str = ""
    branch: str | None = None
    project: ProjectRef | None = None
    terminal_backend: str = ""
    personality: str = ""
    running: bool = False
    turn_started_at: float | None = None
    title: str = ""
    stored_session_id: str = ""
    desktop_contract: int | str | None = None
    version: str = ""
    release_date: str = ""
    update_behind: JsonValue | None = None
    update_command: str = ""
    usage: Usage | None = None
    profile_name: str | None = None
    mcp_servers: list[McpServerStatus] = Field(default_factory=list)
    system_prompt: str | None = None
    credential_warning: str | None = None
    lazy: bool | None = None


class StoredSessionRow(OpenModel):
    """One ``sessions`` row as ``hermes_state`` lists it (``session.list`` / ``session.info`` rows /
    ``sessions.changed``)."""

    id: str
    title: str | None = None
    preview: str | None = None
    source: str | None = None
    model: str | None = None
    started_at: float | None = None
    ended_at: float | None = None
    last_active: float | None = None
    message_count: int = 0
    tool_call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    is_active: bool = False
    cwd: str | None = None
    git_branch: str | None = None
    git_repo_root: str | None = None
    parent_session_id: str | None = None
    pinned: bool | None = None
    unread: bool | None = None
    archived: bool | None = None
    actual_cost_usd: float | None = None
    estimated_cost_usd: float | None = None
    handoff_platform: str | None = None
    handoff_state: str | None = None
    lineage_root_id: str | None = Field(default=None, alias="_lineage_root_id")
    lineage_ids: list[str] | None = Field(default=None, alias="_lineage_ids")


class ToolLabelKind(WireEnum):
    """Which surface one inner call of a bridged ``tool_call`` runs on."""

    connector = "connector"
    mcp = "mcp"
    tool = "tool"


class ToolLabel(Payload):
    """``tools.tool_labels.ToolLabel`` — what one call executed through the tool_search bridge is,
    in words. Clients render ``text`` (or ``app``/``action`` in their own columns) and never parse
    the tool name themselves."""

    kind: ToolLabelKind
    app: str
    action: str
    emoji: str
    text: str
    name: str
    preview: str = ""


class AttachmentKind(WireEnum):
    """How a client shows a shared file (``tui_gateway/outbox.classify``): the first four are served inline and
    their bytes were checked against the type; ``file`` is a download."""

    image = "image"
    video = "video"
    audio = "audio"
    pdf = "pdf"
    file = "file"


class OutboxAttachment(Result):
    """A file a bot shared with the person (``tui_gateway/outbox.attachment_of``; ``contract/outbox``). Fetch it
    from ``url`` (``GET /api/files/outbox/{id}/{name}``, add ``?profile=`` like every per-profile route) with the
    session header or cookie. No path on the server, ever."""

    #: 32 URL-safe characters: the unguessable token of this copy.
    id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{32}$")]
    #: The file's base name as the bot named it (control characters and separators replaced, <= 180 chars).
    name: Annotated[str, Field(min_length=1, max_length=180)]
    #: The type recorded for it (``application/octet-stream`` when the bytes contradict the name).
    mime: str
    kind: AttachmentKind
    size: Annotated[int, Field(ge=0)]
    #: Lower-case hex SHA-256 of the bytes.
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    #: Unix seconds.
    created_at: float
    #: ``/api/files/outbox/<id>/<name, percent-encoded>`` relative to the gateway's origin.
    url: str


class SourceVia(WireEnum):
    """How a reply used a page (``tui_gateway/sources.py``): ``read`` = ``web_extract`` fetched it; ``found`` =
    ``web_search`` returned it."""

    read = "read"
    found = "found"


class Source(Result):
    """A page a reply used (``tui_gateway/sources.py``; ``contract/sources``): built by the gateway from the turn's
    web tool results, never from the model's text. A client shows the domain beside the title and opens the URL
    only on the person's tap; it never fetches anything for it."""

    #: ``http``/``https`` with a host and no user info. Scheme and host are lower-case ASCII (a non-ASCII host as
    #: punycode, an IPv6 literal in brackets), with an optional port; path, query and fragment as the tool returned
    #: them, without white space, controls (C0, C1) or format characters (the gateway refuses every Unicode ``Cf``;
    #: the pattern names the BMP ones).
    url: Annotated[str, Field(min_length=1, max_length=2048, pattern=(
        r"^https?://(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?"
        r"(?:[/?#][^\s\u0000-\u001F\u007F-\u009F\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2"
        r"\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]*)?$"))]
    #: Cleaned text (no control or invisible characters, whitespace collapsed); may be empty.
    title: Annotated[str, Field(max_length=160)]
    via: SourceVia


class TranscriptMessage(OpenModel):
    """One transcript row as the gateway PROJECTS it for renderers (``session_history._project_history``):
    ``text``, display-only ``timestamp`` / ``display_kind`` / ``display_metadata``, the durable ``row_id``
    rewind targets (tool rows carry theirs too), and for tool rows raw ``content``, ``tool_call_id``, ``name``,
    ``context`` and ``args``.
    Assistant detail sidecars (``reasoning``, …) ride as extra keys."""

    role: str
    text: str | None = None
    content: JsonValue | None = None
    tool_call_id: str | None = None
    timestamp: float | None = None
    row_id: int | None = None
    display_kind: str | None = None
    display_metadata: JsonValue | None = None
    name: str | None = None
    context: str | None = None
    args: dict[str, JsonValue] | None = None
    labels: list[ToolLabel] | None = None
    reasoning: str | None = None
    # Tool rows: the assistant row holding the call and the call's position in it, the same pair the
    # tool.start / tool.complete frames of that call carried. Absent when the row cannot be tied to one.
    call_row_id: int | None = None
    call_index: int | None = None
    # Assistant rows: the files a bot shared in this reply (``tui_gateway/outbox_share.project_row``); the
    # row's ``text`` no longer carries their ``MEDIA:`` directives. Absent on every other row.
    attachments: list[OutboxAttachment] | None = None


class SubagentStatus(WireEnum):
    """Lifecycle of one delegated child (``tools/delegate_tool_child_run.py``); ``failed`` /
    ``error`` / ``timeout`` / ``interrupted`` / ``completed`` are terminal."""

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    error = "error"
    timeout = "timeout"
    interrupted = "interrupted"


TERMINAL_SUBAGENT_STATUSES = frozenset({
    SubagentStatus.completed, SubagentStatus.failed, SubagentStatus.error,
    SubagentStatus.timeout, SubagentStatus.interrupted,
})


class PendingApproval(OpenModel):
    """One unresolved ``tools/approval.py`` gateway queue entry as ``server._approval_request_payload``
    renders it (command redacted; ``choices`` precomputed). The key set is owned by the approval tool."""

    request_id: str | None = None
    command: str | None = None
    description: str | None = None
    pattern_key: str | None = None
    pattern_keys: list[str] | None = None
    allow_permanent: bool | None = None
    allow_session: bool | None = None
    smart_denied: bool | None = None
    choices: list[str] | None = None
    tool_name: str | None = None


class MessageReaction(OpenModel):
    """One persisted reaction row (``hermes_state_messages.set_message_reaction``); ``seen`` is
    stamped once announced."""

    emoji: str
    author: str
    at: float | None = None
    seen: bool | None = None


class SessionParams(Params):
    """Any method addressed at one live session."""

    session_id: str
    profile: str | None = None


class ProfileParams(Params):
    """Any method the desktop may route to a named profile (``requestGatewayForProfile`` adds ``profile``)."""

    profile: str | None = None


class SessionOwner(Params):
    type: Literal["session"]
    session_id: str = Field(min_length=1)


class AccountOwner(Params):
    type: Literal["account"]


ConnectorOwner = Annotated[SessionOwner | AccountOwner, Field(discriminator="type")]


class OkResult(Result):
    ok: bool = True


class StatusResult(OpenModel):
    status: str


class EmptyResult(Result):
    pass


class EmptyPayload(Payload):
    pass


__all__ = [
    "TERMINAL_SUBAGENT_STATUSES", "AccountOwner", "ConnectorOwner", "EmptyPayload", "EmptyResult", "McpServerStatus",
    "MessageReaction", "OkResult", "OpenModel", "PendingApproval",
    "ProfileParams", "ProjectRef", "SessionLiveInfo", "SessionOwner", "SessionParams", "StatusResult", "StoredSessionRow",
    "SubagentStatus", "ToolLabel", "ToolLabelKind", "TranscriptMessage", "Usage",
]
