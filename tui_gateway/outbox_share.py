"""When a turn's files are shared, and what the person's client sees of the reply instead of their paths.

Sharing is for the person's chat surface only: a session whose ``source`` (the live record's, else the stored
row's) is listed in ``files.outbox_sources`` (default ``["hermie"]``, the Hermie apps). The TUI, the Desktop app
and the dashboard Chat tab render ``MEDIA:`` lines themselves from a path on their own machine and are left
exactly as they were.

For such a session, at the end of a completed turn (``prompt_turn._complete_turn_payload``):

- the files are the reply's ``MEDIA:`` directives (``BasePlatformAdapter.extract_media``, which skips examples in
  code and quotes) and those this turn's producer tools emitted (``text_to_speech``, ``image_generate``:
  ``gateway.run._collect_auto_append_media_tags``, the same set the messaging gateway appends);
- each is copied into the outbox (``tui_gateway/outbox.share_file``) and becomes an attachment;
- ``message.complete`` carries ``attachments`` and its ``text`` without the directives;
- the final assistant row gets ``display_metadata.attachments`` (``SessionDB.set_message_attachments``), and
  every history projection shows that row without its directives and with ``attachments``
  (:func:`project_row`).

The row's ``content`` keeps the agent's own text: the model is sent what it wrote, the prompt cache is untouched
and the agent's copy of the file is never moved. While the reply streams, :class:`MediaDeltaFilter` holds back a
line that holds a directive and drops the directive from it, so no frame of the turn shows the path either.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from tui_gateway import outbox

logger = logging.getLogger(__name__)

_MARK = "MEDIA:"
#: A line holding a directive is held at most this long before it is let through (cleaned) unfinished.
_MAX_HELD_CHARS = 8192


def session_shares_files(session: Mapping[str, Any], settings: outbox.OutboxSettings,
                         stored_source: Callable[[], str | None] | None = None) -> bool:
    """Whether *session* is a chat surface the outbox serves (``files.outbox_sources``)."""
    if not settings.sources:
        return False
    if str(session.get("source") or "").strip().lower() in settings.sources:
        return True
    if stored_source is None:
        return False
    try:
        return str(stored_source() or "").strip().lower() in settings.sources
    except Exception:
        logger.debug("outbox: stored session source unreadable", exc_info=True)
        return False


def strip_directives(text: str) -> str:
    """*text* without its deliverable ``MEDIA:`` directives and voice/document markers (the display strip the
    messaging gateway uses: examples inside code and quotes are kept)."""
    if not isinstance(text, str) or ("MEDIA:" not in text and "[[" not in text):
        return text
    from gateway.platforms.base import BasePlatformAdapter
    return BasePlatformAdapter.strip_media_directives_for_display(text)


def _turn_tool_messages(messages: list, start: int | None) -> list:
    """This turn's messages: after the turn's own user row when its index is known, else after the last
    user row (a compaction moved everything before it)."""
    if not isinstance(messages, list):
        return []
    if type(start) is int and 0 <= start < len(messages) and (messages[start] or {}).get("role") == "user":
        return messages[start + 1:]
    for index in range(len(messages) - 1, -1, -1):
        if isinstance(messages[index], dict) and messages[index].get("role") == "user":
            return messages[index + 1:]
    return messages


def media_paths(final_text: Any, turn_messages: list) -> list[str]:
    """The paths the reply asks to deliver, in order: its ``MEDIA:`` directives, then this turn's producer
    tools' (deduplicated by the path as written; :func:`share_turn_files` dedupes by the file)."""
    paths: list[str] = []
    if isinstance(final_text, str) and _MARK in final_text:
        from gateway.platforms.base import BasePlatformAdapter
        media, _ = BasePlatformAdapter.extract_media(final_text)
        paths.extend(path for path, _voice in media)
    try:
        from gateway.run import _collect_auto_append_media_tags
        tags, _voice = _collect_auto_append_media_tags(turn_messages)
    except Exception:
        logger.debug("outbox: tool media scan failed", exc_info=True)
        tags = []
    paths.extend(tag[len(_MARK):] for tag in tags)
    return list(dict.fromkeys(p for p in paths if p))


@dataclass
class SharedTurn:
    text: Any
    attachments: list[dict] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    #: True when the reply named files at all (the row then carries ``attachments``, even ``[]``).
    named: bool = False


def share_turn_files(final_text: Any, turn_messages: list, *, home, session_id: str, logins: Iterable[str],
                     settings: outbox.OutboxSettings, session_key: str = "") -> SharedTurn:
    """Share every file the turn's reply names; return the text clients see and the attachments."""
    paths = media_paths(final_text, turn_messages)
    shown = strip_directives(final_text) if isinstance(final_text, str) else final_text
    result = SharedTurn(text=shown, named=bool(paths))
    seen: set[str] = set()
    logins = [x for x in logins if x]
    for path in paths:
        try:
            real = os.path.realpath(os.path.expanduser(path))
        except (OSError, ValueError):
            real = path
        if real in seen:
            continue
        seen.add(real)
        try:
            record = outbox.share_file(path, home=home, session_id=session_id, logins=logins,
                                       settings=settings, session_key=session_key)
        except outbox.ShareRefused as refused:
            result.refused.append(refused.reason)
            logger.warning("outbox: a file named in session %s was not shared (%s)", session_id, refused.reason)
            continue
        except Exception:
            result.refused.append("io_error")
            logger.exception("outbox: sharing a file of session %s failed", session_id)
            continue
        result.attachments.append(outbox.attachment_of(record))
    return result


def project_row(role: Any, text: Any, display_metadata: Any) -> tuple[Any, list[dict] | None, Any]:
    """``(text, attachments, display_metadata)`` a client is shown for one stored row. An assistant row that
    carries ``display_metadata.attachments`` loses its directives and shows the attachments; the key leaves
    ``display_metadata`` (empty metadata becomes None). Every other row is returned unchanged with None."""
    if role != "assistant" or not isinstance(display_metadata, Mapping) \
            or outbox.METADATA_KEY not in display_metadata:
        return text, None, display_metadata
    attachments = outbox.clean_attachments(display_metadata.get(outbox.METADATA_KEY))
    rest = {key: value for key, value in display_metadata.items() if key != outbox.METADATA_KEY}
    return (strip_directives(text) if isinstance(text, str) else text), attachments, (rest or None)


def _partial_mark_len(text: str) -> int:
    """Length of the longest suffix of *text* that is a proper prefix of ``MEDIA:``."""
    for size in range(min(len(_MARK) - 1, len(text)), 0, -1):
        if text.endswith(_MARK[:size]):
            return size
    return 0


class MediaDeltaFilter:
    """Streamed deltas without ``MEDIA:`` directives. A line that holds (or may be starting) one is held until
    it ends, then let through with the directive removed (a line left empty disappears). Text that cannot be
    part of a directive passes at once. The final ``message.complete`` text is authoritative either way."""

    def __init__(self) -> None:
        self._held = ""

    def feed(self, delta: str) -> str:
        if not isinstance(delta, str):
            return delta
        text, self._held = self._held + delta, ""
        out: list[str] = []
        while text:
            index = text.find(_MARK)
            if index < 0:
                partial = _partial_mark_len(text)
                if not partial:
                    out.append(text)
                    break
                line_start = text.rfind("\n", 0, len(text) - partial) + 1
                out.append(text[:line_start])
                self._held = text[line_start:]
                break
            line_start = text.rfind("\n", 0, index) + 1
            out.append(text[:line_start])
            line_end = text.find("\n", index)
            if line_end < 0:
                if len(text) - line_start > _MAX_HELD_CHARS:
                    out.append(strip_directives(text[line_start:]))
                else:
                    self._held = text[line_start:]
                break
            line = strip_directives(text[line_start:line_end])
            if line.strip():
                out.append(line + "\n")
            text = text[line_end + 1:]
        return "".join(out)
