"""The interactive server→client requests ``input.form``, ``input.file``, ``review.draft``, ``review.diff``,
``input.signature`` and the device requests ``device.location``, ``device.contact``, ``device.calendar`` and
``device.scan``: the agent asks the person for typed fields, files, the approval of a draft or of the hunks of a diff,
a signature, a location, a contact, a calendar entry or a scanned code through a connected app (plan
``request-types-v2``, contract ``contract/requests``).

What this module adds on top of ``server_requests.send_gated`` (method-gated: a connection gets a request only after
it listed the method under ``client.capabilities {requests}``; ``acting_user_target`` narrows it to the login the
turn acts for; ``send_gated`` parks the request until a capable device attaches and fires ``pre_server_request`` /
``post_server_request`` itself, so nothing here calls a hook):

- the params are BUILT here, never passed through (:func:`build_form_params`, :func:`build_file_params`,
  :func:`build_draft_params`, :func:`build_diff_params`): text the person will see is cleaned
  (``request_text.clean_text``) or, for a draft and every line of a diff, checked verbatim; over-long or empty text is
  refused with :class:`InteractiveParamsError`, never truncated; the
  gateway sets ``expires_at``, ``optional``, ``acting_user`` and the upload directory (under the session's working
  directory, ``<cwd>/uploads/hermie/<date>``, created by the builder without following a symbolic link: a link
  anywhere below the working directory makes the request ``unavailable (upload_dir_unsafe)`` with nothing sent);
- every answer is checked by a pure validator (``interactive_validate``) against the request's own params while the
  request is open; the answer that settles it is the first that passes;
- :func:`request` returns an :class:`Outcome`: ``answered``, ``skipped``, ``approved``, ``rejected``,
  ``unavailable`` (nobody can show it, the app answered an error, withdrawn, a rate limit, turn isolation, a bad
  upload, ...; NOT an answer) or ``timeout`` (300 s). A client's claim never decides an outcome: the gateway reads
  the validated answer, computes ``edited`` itself, and checks uploaded files on disk. An app's ``4041``
  ``cannot_show`` reaches the agent as ``cannot_show:<reason>`` when the reason is one the contract lists
  (:data:`CANNOT_SHOW_REASONS`), else as ``error_response``;
- ``input.file`` answers name files by reference. After the request settled, outside every lock, the upload
  directory is opened without following a symbolic link from ``uploads`` down, each file is opened inside it by name
  (it must sit directly in the directory, and a link is refused, never followed), and its size and SHA-256 must
  match what the client declared (:func:`verify_files`); anything else is ``unavailable (bad_upload)`` and nothing is
  deleted;
- an approved draft's final text goes into ``review_register`` under a ``draft_id`` (the gateway's copy, what a
  later confirmation binds to);
- a diff is read by ``diff_hunks`` into hunks the gateway numbers and keeps (the request's own ``hunks``); an approved
  diff hands the agent ``approved_patch``, composed by ``diff_hunks.compose_patch`` from those hunks and the file's
  head the gateway read, with the hunks the person approved, never from anything the client sent;
- one open interactive request per conversation, whichever family (:func:`_reserve`), and per :data:`WINDOW_SECONDS`
  :data:`MAX_PER_WINDOW` sent for ``input.*`` and ``review.*`` (:data:`_limiter`) and :data:`DEVICE_MAX_PER_WINDOW` for
  ``device.*`` (:data:`_device_limiter`); ``confirm`` keeps its own key and numbers;
- the device requests and the signature carry what is personal, so the gateway keeps them to what the person chose to
  share (``interactive_device``): a location is rounded for an ``approximate`` request whatever the client sent, a
  contact is cut down to the keys the request asked for, a scanned value is cleaned (untrusted text), a signature's
  answer must carry the SHA-256 of the exact statement shown and its two files are checked to be a PNG and a plain
  SVG; a calendar entry is saved by the person in the system sheet and only ``done`` comes back;
- one audit record per request and per outcome in the dashboard auth audit log (``interactive_request`` /
  ``interactive_outcome``): session, request id, method, the login the turn acts for, connections reached,
  outcome, reason, and the login and peer address of the answering connection. Never a title, summary, value, path,
  name or draft. Params and results are never logged.

Under turn isolation (``HERMES_COMPUTE_HOST_CHILD``) the agent's process cannot see which connection advertised
what, so a request fails closed (``unavailable (turn_isolation)``), exactly as ``confirm`` does.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import logging
import errno
import os
import posixpath
import re
import stat
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from tui_gateway import (
    diff_hunks, interactive_device, interactive_fields, interactive_validate, request_limits, review_register,
    server_requests, upload_dirs)
from tui_gateway.contracts.server_requests import (
    CONTACT_FIELDS_MAX, DRAFT_TEXT_MAX, INTERACTIVE_METHODS, INTERACTIVE_SUMMARY_MAX, INTERACTIVE_TITLE_MAX,
    SCAN_FORMATS_MAX, SIGNATURE_SIGNER_MAX, SIGNATURE_STATEMENT_MAX, UPLOAD_MAX_FILES, CalendarKind, ContactField,
    DraftKind, FileAccept, FileCapture, LocationPrecision, ScanFormat)
from tui_gateway.request_text import clean_text, verbatim_problem

logger = logging.getLogger(__name__)
audit = logging.getLogger("tui_gateway.interactive.audit")

TIMEOUT_SECONDS = 300.0
#: How long a device request waits for the person (they pick, or the system asks for a permission).
DEVICE_TIMEOUT_SECONDS = 180.0
#: How long a request waits for a capable device to attach before it is ``unavailable (no_capable_client)``.
PARK_SECONDS = 120.0
#: Answers refused by the validator before the request is withdrawn (``unavailable (too_many_attempts)``).
MAX_REFUSALS = 10
MAX_PENDING = 1
MAX_PER_WINDOW = 12
#: ``device.*`` per conversation per :data:`WINDOW_SECONDS`: what is personal is asked for less often.
DEVICE_MAX_PER_WINDOW = 6
WINDOW_SECONDS = 600.0
#: A signature is two small images (a PNG and an SVG of a pad): one MiB each is far more than a drawn line needs, and
#: it lets the post-settle check read a whole file at once.
SIGNATURE_MAX_BYTES = 1024 * 1024
SIGNATURE_MAX_TOTAL_BYTES = 2 * 1024 * 1024
#: Per file and for all files of one answer (the contract allows 100 MiB each; a photo, a scan or a voice note is
#: far smaller, and the model reads what comes back).
UPLOAD_MAX_BYTES = 25 * 1024 * 1024
UPLOAD_MAX_TOTAL_BYTES = 50 * 1024 * 1024
DEFAULT_TITLES = {"input.form": "Fill in a form", "input.file": "Send a file", "review.draft": "Review a draft",
                  "review.diff": "Review changes", "input.signature": "Sign", "device.location": "Share your location",
                  "device.contact": "Share a contact", "device.calendar": "Add to your calendar",
                  "device.scan": "Scan a code"}
REMINDER_TITLE = "Add a reminder"
SUBJECT_MAX = 200
RECIPIENT_MAX = 120
RECIPIENTS_MAX = 10
#: Outcomes that carry an answer of the person's, and the ones where nothing reached a person.
ANSWER_STATUSES = frozenset({"answered", "skipped", "approved", "rejected"})
NOT_SHOWN_REASONS = frozenset({"no_capable_client", "write_failed", server_requests.NO_ACTING_USER})
#: The ``4041 cannot_show`` reasons the contract lists (``contract/requests`` §3), passed to the agent as
#: ``cannot_show:<reason>``; any other reason (the set is open) is reported as plain ``error_response``.
CANNOT_SHOW_REASONS = frozenset({"no_camera", "no_microphone", "not_supported_on_device", "permission_denied",
                                 "location_unavailable", "upload_failed", "unsupported_version", "shutting_down",
                                 "declined"})

_MIME = re.compile(r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}")
_HASH_CHUNK = 1024 * 1024

#: ``interactive.request``'s pending slot and window, per conversation, for ``input.*`` and ``review.*``; the device
#: requests have a window of their own. Exposed (not copied) for tests.
_limiter = request_limits.Limiter(MAX_PENDING, MAX_PER_WINDOW, WINDOW_SECONDS)
_device_limiter = request_limits.Limiter(MAX_PENDING, DEVICE_MAX_PER_WINDOW, WINDOW_SECONDS)
# One lock for taking a slot in either limiter: "one open request at a time across the families" is a check of the
# other limiter's pending count and a reservation in this one, which must be one step.
_reserve_lock = threading.Lock()


def timeout_for(method: str) -> float:
    """How long a *method* request waits for the person: :data:`DEVICE_TIMEOUT_SECONDS` for a device request, else
    :data:`TIMEOUT_SECONDS`."""
    return DEVICE_TIMEOUT_SECONDS if method.startswith("device.") else TIMEOUT_SECONDS


def _reserve(method: str, key: str, now: float) -> tuple[request_limits.Limiter, str]:
    """Take the conversation's slot for a *method* request: ``(the limiter to release, "")`` or ``(that limiter, the
    reason it is refused)``. Only one interactive request is open per conversation across both families (a person is
    asked one thing at a time); each family has its own number per window."""
    own, other = (_device_limiter, _limiter) if method.startswith("device.") else (_limiter, _device_limiter)
    with _reserve_lock:
        if other.pending.get(key, 0) >= other.max_pending:
            return own, request_limits.ALREADY_PENDING
        return own, own.reserve(key, now)


class InteractiveParamsError(ValueError):
    """The agent's text or definition cannot be shown as given (empty, over a bound, hidden characters, an
    inconsistent field). Nothing was sent; the message says what to fix."""


class UploadDirUnavailable(Exception):
    """The upload directory cannot be made safely: a symbolic link or a non-directory below the working directory
    (``reason`` ``upload_dir_unsafe``) or the directory cannot be created (``upload_dir_unavailable``). Not the
    agent's text to fix, so not an :class:`InteractiveParamsError`: :func:`request_from_tool` reports it as
    ``unavailable (<reason>)``, audited, with nothing sent."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Outcome:
    """What the agent learns. ``status`` ∈ answered | skipped | approved | rejected | unavailable | timeout.
    ``reason`` is a short machine word (never user text); ``payload`` holds the answer for an answered outcome (form
    values, files, an approved draft) or a detail for ``unavailable`` (``problem`` for ``bad_upload``);
    ``answered_by`` is the answering login, set only in a shared session."""

    status: str
    reason: str = ""
    payload: dict = field(default_factory=dict)
    answered_by: str | None = None

    def as_dict(self) -> dict:
        return {"outcome": self.status, **self.payload, **({"reason": self.reason} if self.reason else {}),
                **({"answered_by": self.answered_by} if self.answered_by else {})}


# ── params ────────────────────────────────────────────────────────────────────────────────────


def _acting_user(sid: str) -> dict | None:
    """``{id, name}`` of the person the turn acts for, None when the gateway cannot name one. Reads the turn's
    ContextVar: call it on the turn's thread."""
    from tui_gateway import server
    try:
        acting = server._acting_auth_user(server._sessions.get(sid))
    except Exception:  # noqa: BLE001 - informative only; the gateway decides who may answer
        logger.debug("interactive: acting user unresolved", exc_info=True)
        return None
    login = acting[0] if acting else None
    if not login:
        return None
    name = clean_text(acting[1] if len(acting) > 1 else "", multiline=False)[:80]
    return {"id": str(login), "name": name or str(login)}


def _line(name: str, value: object, limit: int, *, required: bool = False) -> str:
    """One cleaned display line, refused (not truncated) over *limit*; "" when absent and not *required*."""
    if value is not None and not isinstance(value, str):
        raise InteractiveParamsError(f"{name} must be a string")
    text = clean_text(value, multiline=False) if value is not None else ""
    if required and not text:
        raise InteractiveParamsError(f"{name} is required")
    if len(text) > limit:
        raise InteractiveParamsError(f"{name} is {len(text)} characters; the limit is {limit}.")
    return text


def _one_of(name: str, value: object, choices) -> None:
    if not isinstance(value, str) or value not in {choice.value for choice in choices}:
        raise InteractiveParamsError(f"{name} must be one of: {', '.join(choice.value for choice in choices)}")


def _envelope(sid: str, method: str, *, summary: object, title: object, detail: object, optional: bool,
              timeout: float) -> dict:
    """The keys every interactive request carries (``InteractiveRequestParams``)."""
    if not isinstance(optional, bool):
        raise InteractiveParamsError("optional must be true or false")
    if summary is not None and not isinstance(summary, str):
        raise InteractiveParamsError("summary must be a string")
    summary_text = clean_text(summary, multiline=True)
    if not summary_text:
        raise InteractiveParamsError("summary is required: one or two plain sentences saying what you ask and why")
    if len(summary_text) > INTERACTIVE_SUMMARY_MAX:
        raise InteractiveParamsError(f"summary is {len(summary_text)} characters; the limit is "
                                     f"{INTERACTIVE_SUMMARY_MAX}. Shorten it.")
    if detail is not None and not isinstance(detail, str):
        raise InteractiveParamsError("detail must be a string")
    detail_text = clean_text(detail, multiline=True) if detail is not None else ""
    if len(detail_text) > 2_000:
        raise InteractiveParamsError(f"detail is {len(detail_text)} characters; the limit is 2000.")
    title_text = _line("title", title, INTERACTIVE_TITLE_MAX)
    params: dict = {"v": 1, "title": title_text or DEFAULT_TITLES[method], "summary": summary_text,
                    "expires_at": int(time.time() + timeout), "optional": optional}
    if detail_text:
        params["detail"] = detail_text
    if (acting := _acting_user(sid)) is not None:
        params["acting_user"] = acting
    return params


def build_form_params(sid: str, *, summary: object, fields: object, title: object = None, detail: object = None,
                      optional: object = True, timeout: float = TIMEOUT_SECONDS) -> dict:
    """The ``input.form`` params (without ``session_id``) for the agent's *fields* (see
    :func:`interactive_fields.build_fields`). Raises :class:`InteractiveParamsError`."""
    params = _envelope(sid, "input.form", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    params["fields"] = interactive_fields.build_fields(fields, InteractiveParamsError)
    return params


def _upload_dir(sid: str, *, today: _dt.date | None = None) -> str:
    """``<session cwd>/uploads/hermie/<YYYY-MM-DD>``: absolute and a REAL path (the working directory's own
    symlinks resolved), so :func:`verify_files` can compare it with ``realpath``.

    The working directory is the agent's, so nothing below it is trusted: the resolved working directory is opened
    (its ancestors need only search permission), then ``uploads``, ``hermie`` and the date are walked one at a time
    without following a link (``upload_dirs.walk``) and created when missing (mode 0700) inside their parent's
    descriptor. A symbolic link (or a non-directory) at any of them raises :class:`UploadDirUnavailable`
    ``upload_dir_unsafe``; a directory that cannot be created or opened raises it with ``upload_dir_unavailable``.
    Links above ``uploads`` are followed by design (``upload_dirs``)."""
    from tui_gateway import server
    cwd = str(server._session_cwd(server._sessions.get(sid)) or "")
    root = Path(os.path.expanduser(cwd)).resolve().as_posix() if cwd else ""
    if not root.startswith("/"):
        raise InteractiveParamsError("this session has no absolute working directory to receive files in")
    day = (today or _dt.date.today()).isoformat()
    if not upload_dirs.supported():
        raise UploadDirUnavailable("upload_dir_unavailable")
    try:
        parts = upload_dirs.components(root)
        fd = upload_dirs.walk([*upload_dirs.UPLOAD_SEGMENTS, day], create_from=0, start=root)
    except upload_dirs.UnsafePath:
        raise UploadDirUnavailable("upload_dir_unsafe") from None
    except OSError:
        raise UploadDirUnavailable("upload_dir_unavailable") from None
    os.close(fd)
    return "/".join(["", *parts, *upload_dirs.UPLOAD_SEGMENTS, day])


def build_file_params(sid: str, *, summary: object, accept: object, capture: object = None, multiple: object = False,
                      title: object = None, detail: object = None, optional: object = True,
                      max_bytes: int = UPLOAD_MAX_BYTES, max_total_bytes: int = UPLOAD_MAX_TOTAL_BYTES,
                      strip_metadata: bool = True, timeout: float = TIMEOUT_SECONDS) -> dict:
    """The ``input.file`` params. The files go to ``upload.dir`` (under the session's working directory); images
    from a camera or library lose their EXIF / GPS data on the device (*strip_metadata*)."""
    _one_of("accept", accept, FileAccept)
    if capture is not None:
        _one_of("capture", capture, FileCapture)
        if (capture == "audio") != (accept == "audio"):
            raise InteractiveParamsError("capture audio records a voice note and goes with accept audio; accept audio "
                                         "takes capture audio or none (a photo or a scan is for an image or a "
                                         "document)")
    if not isinstance(multiple, bool):
        raise InteractiveParamsError("multiple must be true or false")
    params = _envelope(sid, "input.file", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    params["accept"] = accept
    if capture is not None:
        params["capture"] = capture
    params["multiple"] = multiple
    params["upload"] = {"dir": _upload_dir(sid), "max_bytes": max_bytes, "max_total_bytes": max_total_bytes,
                        "max_files": UPLOAD_MAX_FILES if multiple else 1,
                        # ``strip_metadata`` is about images: nothing for the client to strip from a recording it makes.
                        "strip_metadata": strip_metadata and accept != "audio"}
    return params


def build_draft_params(sid: str, *, summary: object, text: object, kind: object, subject: object = None,
                       recipients: object = None, editable: object = True, title: object = None,
                       timeout: float = TIMEOUT_SECONDS) -> dict:
    """The ``review.draft`` params. The draft is shown VERBATIM, so it is not cleaned: whitespace at the end of
    a line or of the text (invisible in any rendering) is removed, and text that still cannot be shown as it is
    (a tab, a control, bidi or other format character, padding that could hide part of it) is refused for the agent
    to fix. Subject and recipients are display text: cleaned, one line each."""
    _one_of("kind", kind, DraftKind)
    if not isinstance(editable, bool):
        raise InteractiveParamsError("editable must be true or false")
    if not isinstance(text, str):
        raise InteractiveParamsError("text is required: the draft, as plain text")
    body = interactive_validate.strip_line_ends(text.replace("\r\n", "\n"))
    if not body:
        raise InteractiveParamsError("text is required: the draft, as plain text")
    if len(body) > DRAFT_TEXT_MAX:
        raise InteractiveParamsError(f"text is {len(body)} characters; the limit is {DRAFT_TEXT_MAX}.")
    if problem := verbatim_problem(body):
        raise InteractiveParamsError(f"text cannot be shown verbatim: {problem}")
    params = _envelope(sid, "review.draft", summary=summary, title=title, detail=None, optional=False,
                       timeout=timeout)
    params.update({"kind": kind, "text": body, "editable": editable})
    if subject_text := _line("subject", subject, SUBJECT_MAX):
        params["subject"] = subject_text
    if recipients is not None:
        if not isinstance(recipients, list) or not all(isinstance(r, str) for r in recipients):
            raise InteractiveParamsError("recipients must be a list of strings")
        if len(recipients) > RECIPIENTS_MAX:
            raise InteractiveParamsError(f"recipients has {len(recipients)} entries; the limit is {RECIPIENTS_MAX}.")
        cleaned = [_line(f"recipients[{i}]", r, RECIPIENT_MAX, required=True) for i, r in enumerate(recipients)]
        if cleaned:
            params["recipients"] = cleaned
    return params


def build_diff(sid: str, *, summary: object, diff: object, path: object = None, title: object = None,
               timeout: float = TIMEOUT_SECONDS) -> tuple[dict, diff_hunks.FileHead]:
    """The ``review.diff`` params and the file head the gateway read from the diff (what :func:`request` needs to put
    the approved patch back together). *diff* is the agent's unified diff of ONE file (``diff_hunks.parse``: bounded,
    every line verbatim, one file, text only); a diff that cannot be shown as it is raises
    :class:`InteractiveParamsError` saying what to change. *path* names the file and is required when the diff has
    no ``---``/``+++`` lines (the person must see which file it is); with them it must be the file they name. The
    params carry ``kind`` (modify, new, delete, rename), ``path`` (and a rename's ``old_path``) and the hunks: the
    gateway's own copy."""
    if path is not None and not isinstance(path, str):
        raise InteractiveParamsError("path must be a string")
    try:
        parsed = diff_hunks.parse(diff, path)
    except diff_hunks.DiffError as exc:
        raise InteractiveParamsError(str(exc)) from None
    params = _envelope(sid, "review.diff", summary=summary, title=title, detail=None, optional=False,
                       timeout=timeout)
    params["kind"], params["path"] = parsed.head.kind, parsed.path
    if parsed.head.old_path is not None:
        params["old_path"] = parsed.head.old_path
    params["hunks"] = [hunk.as_dict() for hunk in parsed.hunks]
    return params, parsed.head


def build_diff_params(sid: str, **kwargs: Any) -> dict:
    """:func:`build_diff` without the head: the ``review.diff`` params alone."""
    return build_diff(sid, **kwargs)[0]


def build_signature_params(sid: str, *, summary: object, statement: object, signer_name: object = None,
                           title: object = None, detail: object = None, optional: object = True,
                           timeout: float = TIMEOUT_SECONDS) -> dict:
    """The ``input.signature`` params. The statement is shown in full and VERBATIM above the pad and the answer
    carries the SHA-256 of exactly these characters, so, like a draft, it is not cleaned: whitespace at the end of a
    line or of the text is removed and text that still cannot be shown as it is is refused for the agent to fix.
    ``signer_name`` is display text: cleaned, one line. The two files (a PNG and an SVG) go to ``upload.dir``."""
    if not isinstance(statement, str):
        raise InteractiveParamsError("statement is required: the text the person signs, as plain text")
    body = interactive_validate.strip_line_ends(statement.replace("\r\n", "\n"))
    if not body:
        raise InteractiveParamsError("statement is required: the text the person signs, as plain text")
    if len(body) > SIGNATURE_STATEMENT_MAX:
        raise InteractiveParamsError(f"statement is {len(body)} characters; the limit is {SIGNATURE_STATEMENT_MAX}.")
    if problem := verbatim_problem(body):
        raise InteractiveParamsError(f"statement cannot be shown verbatim: {problem}")
    params = _envelope(sid, "input.signature", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    params["statement"] = body
    if name := _line("signer_name", signer_name, SIGNATURE_SIGNER_MAX):
        params["signer_name"] = name
    params["upload"] = {"dir": _upload_dir(sid), "max_bytes": SIGNATURE_MAX_BYTES,
                        "max_total_bytes": SIGNATURE_MAX_TOTAL_BYTES, "max_files": 2, "strip_metadata": False}
    return params


def build_location_params(sid: str, *, summary: object, precision: object = "approximate", title: object = None,
                          detail: object = None, optional: object = True,
                          timeout: float = DEVICE_TIMEOUT_SECONDS) -> dict:
    """The ``device.location`` params: one fix, ``approximate`` unless the agent asks for ``precise``."""
    _one_of("precision", precision, LocationPrecision)
    params = _envelope(sid, "device.location", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    params["precision"] = precision
    return params


def _distinct(name: str, value: object, choices, limit: int, *, required: bool) -> list[str] | None:
    """A list of distinct members of the enum *choices*, at most *limit*; None when absent and not *required*."""
    if value is None and not required:
        return None
    allowed = ", ".join(choice.value for choice in choices)
    if not isinstance(value, list) or not value:
        raise InteractiveParamsError(f"{name} must be a list of 1 to {limit} of: {allowed}")
    if len(value) > limit:
        raise InteractiveParamsError(f"{name} has {len(value)} entries; the limit is {limit}.")
    for entry in value:
        _one_of(f"{name} entry", entry, choices)
    if len(set(value)) != len(value):
        raise InteractiveParamsError(f"{name} lists the same entry twice")
    return list(value)


def build_contact_params(sid: str, *, summary: object, fields: object, title: object = None, detail: object = None,
                         optional: object = True, timeout: float = DEVICE_TIMEOUT_SECONDS) -> dict:
    """The ``device.contact`` params: the fields (1-6, no repeats) the person may share from the contact they pick.
    The agent asks only for what it needs."""
    asked = _distinct("fields", fields, ContactField, CONTACT_FIELDS_MAX, required=True)
    params = _envelope(sid, "device.contact", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    params["fields"] = asked
    return params


def build_calendar_params(sid: str, *, summary: object, kind: object, item: object, title: object = None,
                          detail: object = None, optional: object = True,
                          timeout: float = DEVICE_TIMEOUT_SECONDS) -> dict:
    """The ``device.calendar`` params: *kind* (``event`` or ``reminder``) and the *item* the system sheet is prefilled
    with (:func:`interactive_device.build_calendar_item`). Nothing is saved until the person saves in that sheet."""
    _one_of("kind", kind, CalendarKind)
    entry = interactive_device.build_calendar_item(item, InteractiveParamsError)
    if kind == "reminder" and "end" in entry:
        raise InteractiveParamsError("a reminder has one time: give start (when it is due) and no end")
    params = _envelope(sid, "device.calendar", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    if kind == "reminder" and params["title"] == DEFAULT_TITLES["device.calendar"]:
        params["title"] = REMINDER_TITLE
    params["kind"], params["item"] = kind, entry
    return params


def build_scan_params(sid: str, *, summary: object, formats: object = None, title: object = None,
                      detail: object = None, optional: object = True,
                      timeout: float = DEVICE_TIMEOUT_SECONDS) -> dict:
    """The ``device.scan`` params: the symbologies to look for (1-7, no repeats), or every one the device reads."""
    asked = _distinct("formats", formats, ScanFormat, SCAN_FORMATS_MAX, required=False)
    params = _envelope(sid, "device.scan", summary=summary, title=title, detail=detail, optional=optional,
                       timeout=timeout)
    if asked is not None:
        params["formats"] = asked
    return params


#: The methods that ask the person's device for something of theirs.
DEVICE_METHODS = tuple(method for method in INTERACTIVE_METHODS if method.startswith("device."))

BUILDERS = {"input.form": build_form_params, "input.file": build_file_params, "review.draft": build_draft_params,
            "review.diff": build_diff_params, "input.signature": build_signature_params,
            "device.location": build_location_params, "device.contact": build_contact_params,
            "device.calendar": build_calendar_params, "device.scan": build_scan_params}


# ── files, after the request settled ──────────────────────────────────────────────────────────


def _unprintable(path: str) -> bool:
    return "\x00" in path or any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") for ch in path)


def _open_upload_dir(directory: str) -> tuple[int | None, str]:
    """``(descriptor, "")`` of the upload directory -- a real path; its anchor (the folder holding ``uploads``)
    opened normally and every component from ``uploads`` down without following a link -- checked to be the very
    directory ``lstat`` names; ``(None, problem)`` otherwise."""
    if not upload_dirs.supported() or os.path.realpath(directory) != directory:
        return None, "dir:unsafe"
    try:
        fd = upload_dirs.open_upload_dir(directory)
    except FileNotFoundError:
        return None, "file:0:missing"
    except OSError:  # a link or a non-directory on the way (UnsafePath), or unreadable
        return None, "dir:unsafe"
    try:
        opened, named = os.fstat(fd), os.lstat(directory)
    except OSError:
        os.close(fd)
        return None, "dir:unsafe"
    if not stat.S_ISDIR(named.st_mode) or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        os.close(fd)
        return None, "dir:unsafe"
    return fd, ""


def verify_files(params: dict, files: list[dict], *,
                 sniff: Callable[[dict, bytes], str | None] | None = None) -> tuple[str, list[str]]:
    """Check on disk what an ``input.file`` answer claims, OUTSIDE every lock, without following a symbolic link
    at or below ``uploads``. ``upload.dir`` must be a real path (``realpath(dir) == dir``); its anchor (the folder
    holding ``uploads``) is opened normally, each component from ``uploads`` down with ``O_NOFOLLOW``, and the
    descriptor must be the directory ``lstat(dir)`` names (device and inode).
    Each answered path must sit DIRECTLY in it (its lexical parent is ``dir``: the layout is flat,
    ``<dir>/<16 hex>-<name>``) and is opened by name inside that descriptor with ``O_NOFOLLOW``: it must be a
    regular file, not a link (a link is refused even when it points inside the directory), its size the declared
    one (at most ``max_bytes``, all together at most ``max_total_bytes``) and its SHA-256 the declared one, all
    read from that descriptor. Returns ``("", paths)`` (``<dir>/<name>``, real by construction) or
    ``("file:<n>:<problem>" | "files:too_large" | "dir:unsafe", [])``; the file problems: ``path`` (a control or
    format character), ``outside_dir`` (not directly in the directory), ``missing``, ``link``, ``not_a_file``,
    ``size``, ``hash``; ``dir:unsafe`` when the directory itself is not a real path, is reached through a link or
    changed under the check. Nothing is read beyond the declared size, and nothing is deleted.

    *sniff*, when given, is called for each file that passed with ``(entry, first_bytes)`` (the first MiB of the file,
    however the reads were split: the whole file when it is at most one MiB) and may return a problem word, which becomes
    ``file:<n>:<word>`` (a signature's files must be what their ``mime`` says, ``interactive_device``)."""
    upload = params["upload"]
    directory = str(upload["dir"])
    dir_fd, problem = _open_upload_dir(directory)
    if dir_fd is None:
        return problem, []
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    real_paths: list[str] = []
    total = 0
    try:
        for number, entry in enumerate(files):
            path = str(entry["path"])
            if _unprintable(path):
                return f"file:{number}:path", []
            lexical = interactive_validate.lexical_path(path)
            name = posixpath.basename(lexical) if lexical else ""
            if lexical is None or posixpath.dirname(lexical) != directory or name in ("", ".", ".."):
                return f"file:{number}:outside_dir", []
            try:
                fd = os.open(name, flags, dir_fd=dir_fd)
            except FileNotFoundError:
                return f"file:{number}:missing", []
            except OSError as exc:
                return f"file:{number}:{'link' if exc.errno in (errno.ELOOP, errno.EMLINK) else 'not_a_file'}", []
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    return f"file:{number}:not_a_file", []
                declared = int(entry["bytes"])
                if info.st_size != declared or declared > int(upload["max_bytes"]):
                    return f"file:{number}:size", []
                total += info.st_size
                if total > int(upload["max_total_bytes"]):
                    return "files:too_large", []
                digest, read, first = hashlib.sha256(), 0, bytearray()
                while chunk := os.read(fd, min(_HASH_CHUNK, declared + 1 - read)):
                    if len(first) < _HASH_CHUNK:  # a short read is not the end: keep up to a MiB for *sniff*
                        first += chunk[:_HASH_CHUNK - len(first)]
                    read += len(chunk)
                    digest.update(chunk)
                    if read > declared:
                        break
                if read != declared:
                    return f"file:{number}:size", []
                if not hmac.compare_digest(digest.hexdigest(), str(entry["sha256"])):
                    return f"file:{number}:hash", []
                if sniff is not None and (word := sniff(entry, bytes(first))):
                    return f"file:{number}:{word}", []
            finally:
                os.close(fd)
            real_paths.append(f"{directory}/{name}")
    finally:
        os.close(dir_fd)
    return "", real_paths


def _ref_text(sid: str, path: str) -> str | None:
    """The ``@file:`` reference for *path*, built like ``file.attach``'s (workspace-relative inside the session's
    working directory, absolute outside it, quoted by the same rule). Not always the same: where the path needs
    quoting but no quote form fits it, ``file.attach`` hands the reference back unquoted and this returns None, so
    the file then carries no ``ref_text`` (the agent still gets its ``path``). Safer, and deliberately so."""
    from tui_gateway import prompt_attachments, server
    ref = server._attachment_ref_path(server._sessions.get(sid), Path(path))
    quoted = prompt_attachments._format_ref_value(ref)
    if quoted == ref and prompt_attachments._ATTACHMENT_REF_NEEDS_QUOTING_RE.search(ref):
        return None
    return f"@file:{quoted}"


def _mime(value: object) -> str:
    return str(value) if isinstance(value, str) and _MIME.fullmatch(value) else "application/octet-stream"


def _file_payload(sid: str, entry: dict, real: str) -> dict:
    payload = {"path": real, "name": clean_text(entry.get("name"), multiline=False)[:120] or Path(real).name,
               "mime": _mime(entry.get("mime")), "bytes": int(entry["bytes"]), "sha256": str(entry["sha256"])}
    if (ref := _ref_text(sid, real)) is not None:
        payload["ref_text"] = ref
    return payload


# ── audit ─────────────────────────────────────────────────────────────────────────────────────


def _audit_sink(event: str, **fields) -> None:
    """Write one record to the dashboard auth audit log (never raises). Replaced in tests."""
    try:
        from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
        audit_log(AuditEvent(event), **fields)
    except Exception:
        logger.debug("interactive audit record not written", exc_info=True)


def _connection(transport) -> tuple[str, str]:
    """``(login, peer address)`` of a client connection, ``"-"`` for what is unknown."""
    if transport is None:
        return "-", "-"
    from tui_gateway import server
    return server._transport_auth_user_id(transport) or "-", str(getattr(transport, "_peer", "") or "-")


class _Audit:
    """The two audit records of one request. Fields name who and what, never the text."""

    def __init__(self, sid: str, method: str) -> None:
        self.sid, self.method, self.request_id, self.reached, self.acting = sid, method, "", 0, "-"
        try:
            self.acting = (_acting_user(sid) or {}).get("id") or "-"
        except Exception:  # noqa: BLE001
            logger.debug("interactive audit: acting user unresolved", exc_info=True)

    def opened(self, request_id: str, reached: int) -> None:
        self.request_id, self.reached = request_id, reached
        audit.info("interactive request session=%s request=%s method=%s acting_user=%s reached=%d",
                   self.sid, request_id, self.method, self.acting, reached)
        _audit_sink("interactive_request", session_id=self.sid, request_id=request_id, method=self.method,
                    acting_user=self.acting, reached=reached)

    def outcome(self, outcome: Outcome, *, request_id: str = "", answered_by=None) -> Outcome:
        user, peer = _connection(answered_by)
        request_id = request_id or self.request_id or "-"
        audit.info("interactive outcome session=%s request=%s method=%s acting_user=%s outcome=%s reason=%s "
                   "answered_by=%s peer=%s", self.sid, request_id, self.method, self.acting, outcome.status,
                   outcome.reason or "-", user, peer)
        _audit_sink("interactive_outcome", session_id=self.sid, request_id=request_id, method=self.method,
                    acting_user=self.acting, outcome=outcome.status, reason=outcome.reason, answered_by=user,
                    answered_from=peer)
        return outcome


# ── request ───────────────────────────────────────────────────────────────────────────────────


def _rate_key(sid: str) -> str:
    """The conversation, not the window: a reconnect can mint a new UI session id for the same one."""
    from tui_gateway import server
    return str((server._sessions.get(sid) or {}).get("session_key") or sid)


def request(sid: str, method: str, params: dict, *, timeout: float | None = None,
            head: diff_hunks.FileHead | None = None) -> Outcome:
    """Ask the clients of *sid* that can show *method* (and belong to the person the turn acts for) and block for
    the outcome. *params* come from the matching builder (for ``review.diff``, *head* is the file head
    :func:`build_diff` returned and is required: the approved patch is written from it). Call it on the turn's own
    thread: the acting user is read from its context. Never raises for a client-side failure: every way of not
    getting a valid answer is ``unavailable`` or ``timeout``."""
    if method not in INTERACTIVE_METHODS:
        raise ValueError(f"{method!r} is not an interactive request method")
    if method == "review.diff" and head is None:
        raise ValueError("a review.diff request needs the file head build_diff returned")
    log = _Audit(sid, method)
    if timeout is None:
        timeout = timeout_for(method)
    if os.environ.get("HERMES_COMPUTE_HOST_CHILD") == "1":
        return log.outcome(Outcome("unavailable", reason="turn_isolation"))
    key = _rate_key(sid)
    limiter, refused = _reserve(method, key, time.monotonic())
    if refused:
        return log.outcome(Outcome("unavailable", reason=refused))
    sent_at: float | None = None

    def opened(request_id: str, reached: int) -> None:
        # The window is charged from the moment the request is open (sent, or parked for a device), never for a
        # call that failed before that (params the contract refuses raise ValueError from send_gated).
        nonlocal sent_at
        sent_at = time.monotonic()
        log.opened(request_id, reached)

    try:
        target = server_requests.acting_user_target(sid, method)
        outgoing = {**params, "expires_at": int(time.time() + timeout)}
        interactive_validate.prepare(outgoing)
        result = server_requests.send_gated(
            method, sid, outgoing, level=None, park_seconds=PARK_SECONDS, timeout=timeout, target=target,
            validate=interactive_validate.validator(method, outgoing), max_refusals=MAX_REFUSALS,
            on_open=opened)
        if result.status == "unavailable" and result.reason in NOT_SHOWN_REASONS:
            sent_at = None  # nothing reached a person: it does not count against the window
    finally:
        limiter.release(key, sent_at=sent_at)
    return _outcome(sid, key, method, outgoing, result, log, head)


def _present_values(params: dict, values: dict) -> dict:
    """The form values as the agent receives them: as the person gave them, except a datetime, which is two things
    and arrives as ``{"instant": "2026-10-03T14:30+02:00", "zone": "Europe/Amsterdam"}`` (the RFC 9557 suffix is
    stripped, so the instant parses with any ISO 8601 reader)."""
    shown = dict(values)
    for field in params.get("fields") or []:
        value = shown.get(field.get("id"))
        if field.get("kind") == "datetime" and isinstance(value, str) and value.endswith("]") and "[" in value:
            instant, _, zone = value[:-1].partition("[")
            shown[field["id"]] = {"instant": instant, "zone": zone}
    return shown


def _signature_sniff(entry: dict, head: bytes) -> str | None:
    """A signature file is judged WHOLE: one longer than what was kept (never, with the signature's own size bound)
    cannot be, so it is refused."""
    if int(entry["bytes"]) != len(head):
        return "type"
    return interactive_device.png_or_svg_problem(str(entry.get("mime")), head)


def _device_outcome(sid: str, method: str, params: dict, answer: dict, login: str | None) -> Outcome:
    """What the agent receives of an ``input.signature`` or ``device.*`` answer that passed the validator: only what the
    person chose to share, in the gateway's own form (:mod:`interactive_device`), never the client's claim as it was."""
    if answer["status"] == "skipped":
        return Outcome("skipped", answered_by=login)
    if method == "device.location":
        shared = interactive_device.round_location(answer, str(params["precision"]))
        if shared["precision"] != params["precision"]:
            shared["lowered"] = True  # the person shared less than the agent asked for
        return Outcome("answered", payload=shared, answered_by=login)
    if method == "device.contact":
        return Outcome("answered", payload={"contact": interactive_device.present_contact(answer["contact"],
                                                                                          params["fields"])},
                       answered_by=login)
    if method == "device.calendar":
        return Outcome("answered", payload={"saved": True, "kind": params["kind"]}, answered_by=login)
    if method == "device.scan":
        cleaned = interactive_device.clean_scan_value(answer["value"])
        return Outcome("answered", answered_by=login, payload={
            "value": cleaned, "symbology": answer["symbology"], "cleaned": cleaned != answer["value"]})
    # input.signature: the files are the person's drawing, checked to be what they say.
    problem, real_paths = verify_files(params, answer["files"], sniff=_signature_sniff)
    if problem:
        return Outcome("unavailable", reason="bad_upload", payload={"problem": problem})
    payload: dict = {"signed": True, "statement_sha256": answer["statement_sha256"],
                     "signed_at": int(answer["signed_at"]), "received_at": int(time.time()),
                     "files": [_file_payload(sid, entry, real) for entry, real in zip(answer["files"], real_paths)]}
    if params.get("signer_name"):
        payload["signer_name"] = params["signer_name"]
    return Outcome("answered", payload=payload, answered_by=login)


def _answer_outcome(sid: str, key: str, method: str, params: dict, answer: dict, shared: bool, answered_by,
                    head: diff_hunks.FileHead | None = None) -> Outcome:
    login = None
    if shared:
        from tui_gateway import server
        login = server._transport_auth_user_id(answered_by) if answered_by is not None else None
    if method == "input.form":
        if answer["status"] == "skipped":
            return Outcome("skipped", answered_by=login)
        return Outcome("answered", payload={"values": _present_values(params, answer["values"])}, answered_by=login)
    if method == "input.file":
        if answer["status"] == "skipped":
            return Outcome("skipped", answered_by=login)
        problem, real_paths = verify_files(params, answer["files"])
        if problem:
            return Outcome("unavailable", reason="bad_upload", payload={"problem": problem})
        payload: dict = {"files": [_file_payload(sid, entry, real)
                                   for entry, real in zip(answer["files"], real_paths)]}
        if (transcript := clean_text(answer.get("text"), multiline=True)):
            payload["text"] = transcript
        return Outcome("answered", payload=payload, answered_by=login)
    if method in DEVICE_METHODS or method == "input.signature":
        return _device_outcome(sid, method, params, answer, login)
    if method == "review.diff":
        # In the gateway's order and with the gateway's ids: what the client sent is only each hunk's decision.
        hunks = {hunk["id"]: answer["hunks"][hunk["id"]] for hunk in params["hunks"]}
        if answer["decision"] == "rejected":
            return Outcome("rejected", payload={"hunks": hunks}, answered_by=login)
        approved = {hunk_id for hunk_id, decision in hunks.items() if decision == "approved"}
        patch = diff_hunks.compose_patch(head, params["hunks"], approved)
        return Outcome("approved", payload={"approved_patch": patch, "hunks": hunks}, answered_by=login)
    if answer["decision"] == "rejected":
        comment = clean_text(answer.get("comment"), multiline=True)
        return Outcome("rejected", payload={"comment": comment} if comment else {}, answered_by=login)
    text = interactive_validate.strip_line_ends(str(answer["text"]))
    edited = text != interactive_validate.strip_line_ends(str(params["text"]))
    draft = review_register.put(key, text, edited=edited)
    return Outcome("approved", answered_by=login,
                   payload={"draft_id": draft.draft_id, "text": text, "sha256": draft.sha256, "edited": edited})


def _outcome(sid: str, key: str, method: str, params: dict, result, log: _Audit,
             head: diff_hunks.FileHead | None = None) -> Outcome:
    rid = result.request_id
    if result.status == "answered":
        from tui_gateway import server
        try:
            shared = bool(server._session_identity_is_ambiguous(server._sessions.get(sid)))
        except Exception:  # noqa: BLE001 - name the answerer when in doubt
            shared = True
        outcome = _answer_outcome(sid, key, method, params, result.result or {}, shared, result.answered_by, head)
        return log.outcome(outcome, request_id=rid, answered_by=result.answered_by)
    if result.status == "timeout":
        return log.outcome(Outcome("timeout", reason="timeout"), request_id=rid)
    if result.status == "cancelled":
        return log.outcome(Outcome("unavailable", reason=f"cancelled:{result.reason}"), request_id=rid)
    if result.reason == "error_response":
        return log.outcome(Outcome("unavailable", reason=_error_reason(result)), request_id=rid)
    return log.outcome(Outcome("unavailable", reason=result.reason or "unavailable"), request_id=rid)


def _error_reason(result) -> str:
    """``cannot_show:<reason>`` for an app's ``4041`` whose ``data.reason`` the contract lists, else
    ``error_response``: nothing else of the client's reaches the agent or the audit log."""
    client = getattr(result, "error_reason", "") or ""
    return f"cannot_show:{client}" if client in CANNOT_SHOW_REASONS else "error_response"


def request_from_tool(sid: str, method: str, **kwargs: Any) -> Outcome:
    """The bridge ``tools/interactive_tools.py`` calls (installed by ``tui_gateway/server.py``). *sid* is the turn's
    ``HERMES_UI_SESSION_ID``; a sid this process does not host is ``unavailable (no_session)`` with nothing sent.
    Raises :class:`InteractiveParamsError` for text or fields the agent must fix."""
    from tui_gateway import server
    if method not in BUILDERS:
        raise ValueError(f"{method!r} is not an interactive request method")
    if not sid or sid not in server._sessions:
        return _Audit(sid or "-", method).outcome(Outcome("unavailable", reason="no_session"))
    head = None
    timeout = timeout_for(method)
    try:
        if method == "review.diff":
            params, head = build_diff(sid, timeout=timeout, **kwargs)
        else:
            params = BUILDERS[method](sid, timeout=timeout, **kwargs)
    except UploadDirUnavailable as exc:
        return _Audit(sid, method).outcome(Outcome("unavailable", reason=exc.reason))
    return request(sid, method, params, timeout=timeout, head=head)


def reset_for_tests() -> None:
    _limiter.reset()
    _device_limiter.reset()
    review_register.reset_for_tests()
