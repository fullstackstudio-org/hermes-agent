"""What an UNTRUSTED session import may set (HERM-127).

``POST /api/sessions/import`` is open to every signed-in user of a dashboard, so whatever its payload says
is that user's statement, never the gateway's. Hermes trusts some stored fields because only Hermes
writes them, and replays or obeys them later:

* ``api_content``: the sidecar a user row replays to the model verbatim. The genuine turn note lives
  there, so lookalike relabelling skips it (``agent/turn_sender.py``).
* ``display_metadata``: ``author`` / ``replayed_by`` (who wrote a row, HERM-83), ``reactions`` (announced
  to the model on the next turn), the compaction and delivery markers, shared-file attachments.
* ``display_kind``: a gateway notice, a hidden scaffolding row (stored, sent, never shown), a steer.
* ``_compressed_summary`` / ``observed`` / ``platform_message_id``: the compaction summary carrier,
  observed group context framed apart, the platform's own message identity.
* ``effect_disposition``: Hermes' verdict on whether a tool's side effect happened.
* ``reasoning_details`` / ``codex_reasoning_items`` / ``codex_message_items``: provider replay items
  sent back as they are, which can hold items of any role.
* Rows of any role but user / assistant / tool (``system``, ``session_meta``): bookkeeping.
* On the session: ``system_prompt`` (replayed verbatim on resume when its identity lines match, the
  gateway's own voice), ``model_config`` (resume restores provider/base URL/reasoning from it, the CLI
  re-enables YOLO from it), ``user_id`` (the login a reopened session is attached to and audited
  against), and ``parent_session_id`` pointing at a session the payload did not bring.

An untrusted import keeps none of them. Each message keeps only :data:`_UNTRUSTED_MESSAGE_FIELDS`; a
list ``content`` keeps only text and image parts (a bare string becomes a text part, an image needs an
``http(s)`` or ``data:image/`` URL, every other part type is dropped); the text of every row, of every
text part, of plain reasoning and of each tool call's ``arguments`` has Hermes' control frames
(``agent.prompt_builder.relabel_control_frames``, the turn note among them) and any note-shaped text
relabelled, so no imported word speaks in the gateway's voice wherever it is replayed, summarised or
titled; an assistant row that is exactly the failed-turn notice is marked as imported, so it is not read
as Hermes' boundary row. Every row's ``display_metadata`` is ``{"imported": true}``; a user row adds the
importer as its ``author`` (none when no person is signed in) and the name the payload claimed, as plain
display text, in ``imported_author`` (clients may show "imported, said to be from X"; nothing else reads
it). On the session, ``user_id`` becomes the importer's login; the system prompt, ``model_config``,
``end_reason`` and the working directory (``cwd``, ``git_*``) are left empty; ``source`` is ``import``; an
id shaped like one the gateway mints (``cron_...``, ``room_...``) is replaced by a fresh one; a title that
switches on a special mode ("Bot Chat", "Group: ...") is prefixed "Imported: " and its control frames are
relabelled; and only a parent inserted by the same import is linked
(``SessionDB.import_sessions``). Tool rows and assistant text stay the importer's data: the model already
treats them as not the user's channel.

A local operator restore (``hermes sessions import --from hermes``) and the gateway's own lineage
adoption pass ``keep_provenance=True`` and store everything as before.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

#: The only message keys an untrusted import stores.
_UNTRUSTED_MESSAGE_FIELDS = frozenset({
    "role", "content", "tool_call_id", "tool_calls", "tool_name", "timestamp", "token_count", "finish_reason",
    "reasoning", "reasoning_content",
})
_UNTRUSTED_ROLES = frozenset({"user", "assistant", "tool"})
#: Stands in for the ``[`` of a control frame in imported text: the words stay, the trusted shape does not.
IMPORTED_FRAME_RELABEL = "[imported "
_TEXT_PART_TYPES = frozenset({"text", "input_text"})
_IMAGE_URL_PREFIXES = ("https://", "http://", "data:image/")
_IMAGE_DETAILS = frozenset({"auto", "low", "high"})
#: Session ids only the gateway mints: a cron run (``cron/scheduler.py``) and a hosted room member's
#: session (``gateway/platforms/api_server_room_dispatch.py``).
_GATEWAY_ID_PREFIXES = ("cron_", "room_")
#: Marks a title that would switch on a special mode, and an imported copy of the failed-turn notice.
IMPORTED_TITLE_PREFIX = "Imported: "
_IMPORTED_NOTICE_PREFIX = "(imported) "


def relabel_imported_text(text: Any) -> Any:
    """``text`` with every Hermes control frame and note-shaped opener relabelled; non-strings unchanged."""
    if not isinstance(text, str) or not text:
        return text
    from agent.prompt_builder import relabel_control_frames
    from agent.turn_sender import relabel_note_lookalikes

    return relabel_note_lookalikes(relabel_control_frames(text, IMPORTED_FRAME_RELABEL))


def _image_url(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip().lower().startswith(_IMAGE_URL_PREFIXES):
        return None
    value = value.strip()
    # The scheme (and a data URL's header) stored lower-case: the converters match it case-sensitively.
    if value[:5].lower() == "data:":
        header, comma, rest = value.partition(",")
        return header.lower() + comma + rest
    scheme, sep, rest = value.partition("://")
    return scheme.lower() + sep + rest


def _clean_part(part: Any) -> Optional[Dict[str, Any]]:
    """One list-content part as an untrusted import stores it, or None to drop it."""
    if isinstance(part, str):
        return {"type": "text", "text": relabel_imported_text(part)} if part else None
    if not isinstance(part, dict):
        return None
    ptype = part.get("type")
    if ptype in _TEXT_PART_TYPES:
        text = part.get("text")
        return {"type": ptype, "text": relabel_imported_text(text)} if isinstance(text, str) else None
    if ptype not in ("image_url", "input_image"):
        return None
    value, detail = part.get("image_url"), part.get("detail")
    if isinstance(value, dict):
        value, detail = value.get("url"), value.get("detail", detail)
    url = _image_url(value)
    if url is None:
        return None
    detail = detail if detail in _IMAGE_DETAILS else None
    if ptype == "image_url":
        return {"type": "image_url", "image_url": {"url": url, **({"detail": detail} if detail else {})}}
    return {"type": "input_image", "image_url": url, **({"detail": detail} if detail else {})}


def _relabel_content(content: Any) -> Any:
    if content is None or isinstance(content, str):
        return relabel_imported_text(content)
    if isinstance(content, list):
        return [clean for clean in map(_clean_part, content) if clean is not None]
    return ""


def _relabel_json_strings(value: Any) -> Any:
    if isinstance(value, str):
        return relabel_imported_text(value)
    if isinstance(value, list):
        return [_relabel_json_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: _relabel_json_strings(item) for key, item in value.items()}
    return value


def _relabel_arguments(arguments: Any) -> Any:
    """A tool call's ``arguments``: every string inside the JSON relabelled (the raw text when it is not JSON)."""
    if not isinstance(arguments, str):
        return _relabel_json_strings(arguments)
    try:
        parsed = json.loads(arguments)
    except ValueError:
        return relabel_imported_text(arguments)
    relabelled = _relabel_json_strings(parsed)
    return arguments if relabelled == parsed else json.dumps(relabelled, ensure_ascii=False)


def _relabel_tool_calls(tool_calls: Any) -> Any:
    if not isinstance(tool_calls, list):
        return None
    kept = []
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        function = call.get("function")
        if isinstance(function, dict) and "arguments" in function:
            call = {**call, "function": {**function, "arguments": _relabel_arguments(function["arguments"])}}
        kept.append(call)
    return kept


def _claimed_author(message: Mapping[str, Any]) -> str:
    """The display name a payload row claims, as inert text ("" when none)."""
    from agent.turn_sender import NAME_LIMIT, clean_value

    metadata = message.get("display_metadata")
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except ValueError:
            return ""
    author = metadata.get("author") if isinstance(metadata, dict) else None
    if not isinstance(author, dict):
        return ""
    return clean_value(author.get("name") or author.get("display_name"), NAME_LIMIT)


def untrusted_messages(messages: List[Dict[str, Any]], author: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """The rows an untrusted import stores for *messages* (see the module docstring); *author* is the
    importer's row author (``tui_gateway.row_author.row_author``) or None."""
    from agent.turn_failure_copy import untyped_failed_turn_display_kind

    kept: List[Dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role not in _UNTRUSTED_ROLES:
            continue
        clean = {key: value for key, value in message.items() if key in _UNTRUSTED_MESSAGE_FIELDS}
        clean["content"] = _relabel_content(clean.get("content"))
        if untyped_failed_turn_display_kind(role, clean["content"]):
            clean["content"] = _IMPORTED_NOTICE_PREFIX + clean["content"].strip()
        if "tool_calls" in clean:
            clean["tool_calls"] = _relabel_tool_calls(clean["tool_calls"])
        for key in ("reasoning", "reasoning_content"):
            if key in clean:
                clean[key] = relabel_imported_text(clean[key])
        metadata: Dict[str, Any] = {"imported": True}
        if role == "user":
            if author:
                metadata = {"author": dict(author), **metadata}
            if claimed := _claimed_author(message):
                metadata["imported_author"] = claimed
        clean["display_metadata"] = metadata
        kept.append(clean)
    return kept


def fresh_session_ids(session_ids: Iterable[str]) -> Dict[str, str]:
    """``{old: new}`` for each id shaped like one only the gateway mints; the import stores it under the new one."""
    from hermes_state_ids import new_session_id

    return {sid: new_session_id(hex_len=12) for sid in session_ids if sid.startswith(_GATEWAY_ID_PREFIXES)}


def _special_title(title: str) -> bool:
    from agent.turn_sender import _folded

    folded = " ".join(_folded(title)[0].split()).casefold()
    if folded == "bot chat" or folded.startswith("group:"):
        return True
    # "<title> #<n>": a numbered title joins an existing title's lineage, and the newest of a lineage is what
    # resolving that title (``hermes --resume "<title>"``, ``/resume``) returns.
    from hermes_state_titles import _NUMBERED_TITLE_RE

    return _NUMBERED_TITLE_RE.match(title.strip()) is not None


def _untrusted_title(title: Any) -> Any:
    if not isinstance(title, str) or not title.strip():
        return title
    title = relabel_imported_text(title)
    return IMPORTED_TITLE_PREFIX + title if _special_title(title) else title


def untrusted_session(session: Dict[str, Any], importer_id: Optional[str],
                      renamed: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """*session* without the session-level fields only Hermes may set; ``user_id`` names the importer and
    ids in *renamed* (:func:`fresh_session_ids`) are replaced, as the session's own id or its parent."""
    renamed = renamed or {}
    session_id, parent_id = session.get("id"), session.get("parent_session_id")
    return {
        **session, "id": renamed.get(session_id, session_id),
        "parent_session_id": renamed.get(parent_id, parent_id) if parent_id else parent_id,
        "system_prompt": None, "model_config": None, "user_id": importer_id or None, "source": "import",
        "end_reason": None, "cwd": None, "git_branch": None, "git_repo_root": None,
        "billing_provider": None, "billing_base_url": None, "billing_mode": None,
        "started_at": _not_after_now(session.get("started_at")),
        "ended_at": _not_after_now(session.get("ended_at")),
        "title": _untrusted_title(session.get("title")),
    }


def _not_after_now(value: Any) -> Any:
    """A timestamp from the payload, never later than now: a session dated in the future would sort as the
    newest of everything it is listed or resolved with."""
    import time

    from hermes_cli.timefmt import coerce_epoch

    epoch = coerce_epoch(value, field="started_at")
    return value if epoch is None else min(epoch, time.time())
