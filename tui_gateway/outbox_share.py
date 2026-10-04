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
import re
import threading
import time
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
    """*text* without any ``MEDIA:`` directive or voice/document marker outside code and quotes. First the
    messaging gateway's display strip (deliverable directives), then every directive left over: a path that
    could not be delivered (an unknown extension that did not validate) stays visible on a messaging platform,
    but a person in the apps is never shown a server path."""
    return _strip_leftovers(text)[0]


def _strip_leftovers(text: Any) -> tuple[Any, int]:
    """``(text, how many leftover directives were removed)`` (see :func:`strip_directives`)."""
    if not isinstance(text, str) or ("MEDIA:" not in text and "[[" not in text):
        return text, 0
    from gateway.platforms.base import BasePlatformAdapter, _delete_spans, _mask_media_scan_text
    from hermes_state_common import _PREVIEW_MEDIA_RE
    cleaned = BasePlatformAdapter.strip_media_directives_for_display(text)
    if "MEDIA:" not in cleaned:
        return cleaned, 0
    spans = [m.span() for m in _PREVIEW_MEDIA_RE.finditer(_mask_media_scan_text(cleaned))
             if "MEDIA:" in m.group(0)]
    if not spans:
        return cleaned, 0
    left = re.sub(r"[ \t]{2,}", " ", _delete_spans(cleaned, spans))
    return re.sub(r"\n{3,}", "\n\n", left).strip(), len(spans)


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


#: ``display_metadata`` key: how many files the reply named that could not be shared (shown as a note).
REFUSED_KEY = "attachments_refused"


def refused_note(count: int) -> str:
    """The note a client is shown for files that could not be shared: a count, never a path or a reason."""
    return f"({count} file could not be shared.)" if count == 1 else f"({count} files could not be shared.)"


def with_refused_note(text: Any, count: Any) -> Any:
    if not isinstance(count, int) or count <= 0 or not isinstance(text, str):
        return text
    return f"{text}\n\n{refused_note(count)}" if text.strip() else refused_note(count)


class _Share:
    """One share on a worker thread, so the turn waits for it a bounded time (``files.outbox_turn_timeout_s``).
    A copy given up on is cancelled (checked between chunks) and, should it finish anyway, removed: nothing
    the turn did not announce stays in the outbox."""

    def __init__(self, path: str, home, kwargs: dict):
        self.cancel = threading.Event()
        self._lock = threading.Lock()
        self._abandoned = False
        self.record: dict | None = None
        self.refused: str | None = None
        self._home, self._kwargs, self._path = home, kwargs, path
        self._thread = threading.Thread(target=self._run, daemon=True, name="outbox-share")

    def _run(self) -> None:
        try:
            record = outbox.share_file(self._path, home=self._home, cancel=self.cancel, **self._kwargs)
        except outbox.ShareRefused as refused:
            record, self.refused = None, refused.reason
        except Exception:
            logger.exception("outbox: sharing a file failed")
            record, self.refused = None, "io_error"
        with self._lock:
            if self._abandoned and record is not None:
                outbox.remove_shared(self._home, record["id"])
                return
            self.record = record

    def wait(self, seconds: float) -> None:
        self._thread.start()
        self._thread.join(max(0.0, seconds))
        with self._lock:
            if self.record is None and self.refused is None:
                self._abandoned = True
                self.cancel.set()
                self.refused = "timeout"


def share_turn_files(final_text: Any, turn_messages: list, *, home, session_id: str, logins: Iterable[str],
                     settings: outbox.OutboxSettings, session_key: str = "",
                     conversation_id: str | Callable[[], str] = "") -> SharedTurn:
    """Share every file the turn's reply names; return the text clients see and the attachments.
    *conversation_id* is the conversation that owns the copies (the root of *session_id*'s compression lineage,
    so a conversation compaction moved to a new session id still owns what it shared before). A callable is
    called once, and only when a file is about to be shared: a reply that names none never pays for the lookup.

    Per turn: at most ``max_turn_files`` files and ``max_turn_bytes`` bytes, all within ``turn_timeout_seconds``
    (a copy still running then is abandoned and removed). A file over any limit is refused, never shared by
    pushing out another conversation's recent files (``outbox._prune_locked``)."""
    paths = media_paths(final_text, turn_messages)
    shown, leftovers = _strip_leftovers(final_text)
    result = SharedTurn(text=shown, named=bool(paths) or bool(leftovers), refused=["denied"] * leftovers)
    seen: set[str] = set()
    logins = [x for x in logins if x]
    deadline = time.monotonic() + settings.turn_timeout_seconds
    spent = 0
    owner: str | None = None
    for path in paths:
        try:
            real = os.path.realpath(os.path.expanduser(path))
        except (OSError, ValueError):
            real = path
        if real in seen:
            continue
        seen.add(real)
        remaining = deadline - time.monotonic()
        if len(result.attachments) >= settings.max_turn_files:
            reason = "turn_limit"
        elif remaining <= 0:
            reason = "timeout"
        else:
            if owner is None:
                owner = (conversation_id() if callable(conversation_id) else conversation_id) or session_id
            share = _Share(path, home, dict(
                session_id=session_id, conversation_id=owner, logins=logins,
                settings=settings, session_key=session_key, max_bytes=settings.max_turn_bytes - spent,
                lock_timeout=remaining,
                protect=frozenset(a["id"] for a in result.attachments)))
            share.wait(remaining)
            if share.record is not None:
                spent += int(share.record["size"])
                result.attachments.append(outbox.attachment_of(share.record))
                continue
            reason = share.refused or "io_error"
        result.refused.append(reason)
        logger.warning("outbox: a file named in session %s was not shared (%s)", session_id, reason)
    if result.refused:
        result.text = with_refused_note(result.text, len(result.refused))
    return result


def project_row(role: Any, text: Any, display_metadata: Any) -> tuple[Any, list[dict] | None, Any]:
    """``(text, attachments, display_metadata)`` a client is shown for one stored row. An assistant row that
    carries ``display_metadata.attachments`` loses its directives, gains the note for files that could not be
    shared, and shows the attachments; both keys leave ``display_metadata`` (empty metadata becomes None).
    Every other row is returned unchanged with None."""
    if role != "assistant" or not isinstance(display_metadata, Mapping) \
            or outbox.METADATA_KEY not in display_metadata:
        return text, None, display_metadata
    attachments = outbox.clean_attachments(display_metadata.get(outbox.METADATA_KEY))
    rest = {key: value for key, value in display_metadata.items()
            if key not in (outbox.METADATA_KEY, REFUSED_KEY)}
    shown = strip_directives(text) if isinstance(text, str) else text
    return with_refused_note(shown, display_metadata.get(REFUSED_KEY)), attachments, (rest or None)


def _partial_mark_len(text: str) -> int:
    """Length of the longest suffix of *text* that is a proper prefix of ``MEDIA:``."""
    for size in range(min(len(_MARK) - 1, len(text)), 0, -1):
        if text.endswith(_MARK[:size]):
            return size
    return 0


_FENCES = ("```", "~~~")
_TAG_QUOTES = "`\"'*_"
_MARKERS = ("[[audio_as_voice]]", "[[as_document]]")


class MediaDeltaFilter:
    """Streamed deltas without ``MEDIA:`` directives.

    Text passes at once unless it holds (or may be starting) a directive: from there to the end of the line it is
    held, then let through with the directive removed (a line left empty disappears). Inside a fenced code block
    nothing is held or removed: a directive there is an example, kept by the final text too. A held run longer
    than 8 KiB is let through up to the end of its directive's path; a "path" with no end in sight is dropped.
    :meth:`flush` lets out what is held when the turn ends. The final ``message.complete`` text is authoritative.
    """

    def __init__(self) -> None:
        self._held = ""  # the not-yet-emitted rest of the current line
        self._line = ""  # the emitted start of the current line
        self._in_fence = False
        self._skipping = False  # inside an over-long path, dropped up to the next whitespace

    def feed(self, delta: str) -> str:
        if not isinstance(delta, str) or not delta:
            return delta
        out: list[str] = []
        text = delta
        while text:
            if self._skipping:
                cut = next((i for i, ch in enumerate(text) if ch.isspace()), -1)
                if cut < 0:
                    return "".join(out)
                self._skipping, text = False, text[cut:]
                continue
            newline = text.find("\n")
            piece, text = (text, "") if newline < 0 else (text[:newline], text[newline + 1:])
            if newline < 0:
                out.append(self._partial(piece))
            else:
                out.append(self._end_line(piece))
        return "".join(out)

    def _partial(self, piece: str) -> str:
        """More of the current line, no newline yet."""
        if self._in_fence:
            self._line += piece
            return piece
        held = self._held + piece
        starts = [i for i in (held.find(_MARK), held.find("[[")) if i >= 0]
        if starts:
            cut = min(starts)
        else:
            partial = _partial_mark_len(held) or (1 if held.endswith("[") else 0)
            cut = len(held) - partial
        if cut < len(held):  # a directive may start here: hold it with its opening quotes
            while cut > 0 and held[cut - 1] in _TAG_QUOTES:
                cut -= 1
        emit, self._held = held[:cut], held[cut:]
        self._line += emit
        if len(self._held) > _MAX_HELD_CHARS:
            emit += self._release_long()
        return emit

    def _release_long(self) -> str:
        """An over-long held run: let out what precedes the end of the directive's path, cleaned."""
        last = self._held.rfind(_MARK)
        end = next((i for i in range(max(last, 0) + len(_MARK), len(self._held)) if self._held[i].isspace()), -1)
        if end < 0:  # the path itself runs past the cap: no real file; drop it up to its end
            emit = strip_directives(self._held[:last]) if last > 0 else ""
            self._held, self._skipping = "", True
        else:
            emit, self._held = strip_directives(self._held[:end]), self._held[end:]
        self._line += emit
        return emit

    def _end_line(self, piece: str) -> str:
        """The rest of the current line and its newline."""
        rest, self._held = self._held + piece, ""
        line, self._line = self._line + rest, ""
        opens_fence = line.lstrip().startswith(_FENCES)
        if self._in_fence:
            if opens_fence:
                self._in_fence = False
            return rest + "\n"
        if opens_fence:
            self._in_fence = True
            return rest + "\n"
        if _MARK not in rest and not any(m in rest for m in _MARKERS):
            return rest + "\n"
        cleaned = strip_directives(rest)
        for marker in _MARKERS:
            cleaned = cleaned.replace(marker, "")
        if not cleaned.strip() and not line[: len(line) - len(rest)].strip():
            return ""  # the whole line was a directive
        return cleaned + "\n"

    def flush(self) -> str:
        """What is still held when the turn ends, cleaned (the stream's last words)."""
        held, self._held, self._line, self._skipping = self._held, "", "", False
        if not held or self._in_fence:
            return held
        cleaned = strip_directives(held)
        for marker in _MARKERS:
            cleaned = cleaned.replace(marker, "")
        return cleaned
