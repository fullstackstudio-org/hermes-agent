"""The ``confirm`` server→client request: the agent asks the person to confirm one sensitive action.

Levels (:data:`LEVELS`): ``plain`` is a tap on Confirm in a connected client that advertised ``plain``; it
proves nothing beyond that, and the gateway cannot check even that — any client that can attach to the
session can advertise it and answer. ``passkey`` is a confirmation the gateway verifies itself: a WebAuthn
assertion by a passkey enrolled for the person the running turn acts for, over a challenge that commits to
this gateway, session, request and text. Its verification lives in ``tui_gateway/confirm_passkey.py``;
``verified: true`` is set there and nowhere else.

What this module adds on top of ``server_requests.send_gated``:

- the params are built here, never passed through: plain text only, control and format characters
  (bidi overrides, zero-width characters) stripped, lengths checked against the contract bounds;
- four outcomes the caller can act on: ``confirmed``, ``declined``, ``unavailable`` (no connected client
  can answer the level, a client answered an error, the request was withdrawn, a rate limit, turn
  isolation, a ``plain`` request inside the no-downgrade window, or one of the ``passkey`` reasons),
  ``timeout`` (120 s, ``request.cancel {reason: timeout}``);
- ``verified`` decided by the gateway, never taken from the client;
- a per-conversation rate limit: one open confirmation at a time and at most
  :data:`MAX_PER_WINDOW` sent per :data:`WINDOW_SECONDS`. A confirmation the gateway forces for an operator
  rule (``tools/passkey_policy.py``, :func:`request` with ``forced=True``) counts under its own key
  (``forced:<conversation>``, same limits), so an agent asking voluntarily cannot use up the operator's
  floor, and the operator's floor cannot use up the agent's confirmations;
- no downgrade: once a ``passkey`` request in a conversation ends in a failure a third party can cause
  after sending (declined, timeout, verification failed, an error response, withdrawn, no capable client:
  :func:`opens_downgrade_window`), ``plain`` requests in that conversation are ``unavailable
  (downgrade_refused)`` for :data:`DOWNGRADE_WINDOW_SECONDS`, with nothing sent. A ``passkey`` request that
  is ``unavailable`` before sending opens nothing;
- the plugin hook ``pre_confirm_request`` once the frame is out, without the text;
- one audit record per request and per outcome in the dashboard auth audit log
  (``$HERMES_HOME/logs/dashboard-auth.log``, events ``confirm_request`` / ``confirm_outcome``): session,
  request id, level, the login the turn acts for, the connections reached, outcome, method, reason, and the
  login and peer address of the connection whose answer settled it — never the title, summary or detail.

A level that needs per-request state (``passkey``: the bound user, a nonce, a credential snapshot) builds it
in its own module before the frame goes out; :class:`Level` covers the context-free part (the shape of a
``plain`` answer).
"""

from __future__ import annotations

import bisect
import collections
import logging
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass

from tui_gateway import request_hooks, server_requests
from tui_gateway.contracts.server_requests import (CONFIRM_DETAIL_MAX, CONFIRM_SUMMARY_MAX, CONFIRM_TITLE_MAX,
                                                   ConfirmDecision, ConfirmMethod)

logger = logging.getLogger(__name__)
audit = logging.getLogger("tui_gateway.confirm.audit")

TIMEOUT_SECONDS = 120.0
MAX_PENDING = 1
MAX_PER_WINDOW = 6
WINDOW_SECONDS = 600.0
#: After a ``passkey`` request ends other than ``confirmed``, ``plain`` is refused this long in that conversation.
DOWNGRADE_WINDOW_SECONDS = 600.0
#: The kwargs ``pre_confirm_request`` is fired with (kept in step with ``VALID_HOOKS`` and hooks.md by a test).
HOOK_KWARGS = ("session_id", "session_key", "request_id", "level", "user_id", "expires_at", "reached")
DEFAULT_TITLE = "Confirm an action"

_DECISIONS = frozenset(decision.value for decision in ConfirmDecision)
_METHODS = frozenset(method.value for method in ConfirmMethod)

#: The outcomes after which a ``passkey`` request opens the no-downgrade window: the ones a third party can
#: cause once a frame was (to be) sent. A ``passkey`` request that is ``unavailable`` before sending
#: (the level is off, nobody to bind, not enrolled, turn isolation, a rate limit) opens nothing: there
#: ``plain`` is the only level there is, and one stray ``passkey`` call must not deny every confirm.
DOWNGRADE_OUTCOMES = frozenset({"declined", "timeout"})
DOWNGRADE_REASONS = frozenset({"verification_failed", "error_response", "no_capable_client"})


def opens_downgrade_window(outcome: "ConfirmOutcome") -> bool:
    return (outcome.outcome in DOWNGRADE_OUTCOMES
            or (outcome.outcome == "unavailable"
                and (outcome.reason in DOWNGRADE_REASONS or outcome.reason.startswith("cancelled:"))))


class Level:
    """One confirm level: whether it is implemented, whether a client may advertise it, what it adds to the
    outgoing params and how an answer is checked. The base class is the ``plain`` behaviour."""

    name = ""
    implemented = True
    advertisable = True
    #: The ``method`` values an answer at this level may carry (a subset of ``ConfirmMethod``).
    methods: frozenset[str] = frozenset({"tap"})

    def challenge(self, sid: str, params: dict) -> dict:
        """Extension point 1: extra params for this request (e.g. a fresh challenge). ``plain``: none."""
        return {}

    def check(self, params: dict, result: dict) -> tuple[str | None, bool]:
        """Extension point 2: ``(problem, verified)`` for one client answer. A problem leaves the request
        open for a valid answer. ``plain``: the shape only, and never verified — whatever the client sent
        as ``verified`` is ignored."""
        decision, method = result.get("decision"), result.get("method")
        if decision not in _DECISIONS:
            return f"decision must be one of {sorted(_DECISIONS)}", False
        if method not in self.methods or method not in _METHODS:
            # ``bad_shape``: e.g. ``method: "passkey"`` on a plain request, so an unverified outcome never
            # reads "passkey".
            return f"bad_shape: method must be one of {sorted(self.methods)} at level {self.name}", False
        return None, False


class _Plain(Level):
    name = "plain"


class _Passkey(Level):
    """Checked per request by ``confirm_passkey.Verification`` (it needs the request's nonce, user and
    credential snapshot). Without that context no answer passes and nothing is ever verified here."""

    name = "passkey"
    # ``tap`` only in the exact decline shape (``confirm_passkey.DECLINE``); checked per request.
    methods = frozenset({"passkey", "tap"})

    def check(self, params: dict, result: dict) -> tuple[str | None, bool]:
        return "a passkey answer is checked against its own request", False


#: Every level in the contract.
LEVELS: dict[str, Level] = {"plain": _Plain(), "passkey": _Passkey()}


@dataclass(frozen=True)
class ConfirmOutcome:
    """What the agent learns. ``method`` is set for ``confirmed`` / ``declined`` only; ``verified`` is set by
    the gateway from the level (always False for ``plain``). ``reason`` is a short machine word for logs and
    the tool result (never user text)."""

    outcome: str  # confirmed | declined | unavailable | timeout
    method: str | None = None
    verified: bool = False
    reason: str = ""

    def as_dict(self) -> dict:
        return {"outcome": self.outcome, "method": self.method, "verified": self.verified,
                **({"reason": self.reason} if self.reason else {})}


class ConfirmParamsError(ValueError):
    """The agent's text cannot be shown as given (empty, or longer than the contract allows)."""


# ── text ──────────────────────────────────────────────────────────────────────────────────────


# Letters and symbols that render as nothing (Hangul fillers, the blank Braille pattern, the musical null
# notehead): text built from them looks empty or hides where a line really ends.
_INVISIBLE_LETTERS = frozenset({"\u115f", "\u1160", "\u3164", "\uffa0", "\u2800", "\U0001d159"})
_LINE_BREAKS = frozenset({"\n", "\u2028", "\u2029"})
#: ``Default_Ignorable_Code_Point`` as Unicode publishes it (``DerivedCoreProperties.txt``; unchanged
#: from 14.0, which added U+180F, through 16.0): code points a renderer shows as nothing. ``unicodedata``
#: does not expose the property, so the ranges are copied here (``tools/passkey_policy.py`` holds the same
#: table; a test keeps the two and the running Unicode database's ``Cf`` in step). Most are ``Cf`` and
#: refused as such; the rest are variation selectors, the combining grapheme joiner, the Khmer inherent
#: vowels (``Mn``), the Hangul fillers (``Lo``) and reserved ranges (``Cn``). Refused in a VERBATIM
#: detail; :func:`_clean` keeps the ``Mn`` ones under :data:`MAX_COMBINING_MARKS` (an emoji's U+FE0F).
DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_IGNORABLE_STARTS = [low for low, _ in DEFAULT_IGNORABLE]


def default_ignorable(ch: str) -> bool:
    """Whether *ch* is a ``Default_Ignorable_Code_Point`` (:data:`DEFAULT_IGNORABLE`)."""
    code = ord(ch)
    at = bisect.bisect_right(_IGNORABLE_STARTS, code) - 1
    return at >= 0 and code <= DEFAULT_IGNORABLE[at][1]

#: At most this many combining marks (Mn, Me) on one base character; more stack into unreadable glyphs.
MAX_COMBINING_MARKS = 4

# The layout of a VERBATIM detail (:func:`verbatim_problem`). Clients show it monospaced with every space
# kept and scroll long lines sideways instead of wrapping them (web: ``white-space: pre``); a phone in
# portrait shows about 40 columns and a dozen lines of it. Spacing beyond these bounds is padding that
# can park a second command outside that view (``git status`` + 300 spaces + ``; curl … | sh``, or 80
# blank lines before it); ordinary code stays well inside them. The text is refused, never rewritten:
# the passkey challenge covers the exact characters.
#: Spaces in a row after a line's first non-space character. Column-aligned comments and arguments
#: rarely need more than a few; 16 still leaves the next word on a 40-column screen after a short command.
MAX_SPACE_RUN = 16
#: Spaces at the start of a line: 8 levels of 4-space Python, 16 levels of 2-space YAML or JSON (a
#: Kubernetes manifest's secret reference sits at 18). Deeper is a jump to the right, not structure.
MAX_INDENT = 32
#: Empty lines in a row. PEP 8 puts two between top-level definitions; more than three only pushes what
#: follows down the sheet.
MAX_BLANK_LINES = 3
#: Characters on one line, whatever the detail's own bound (``CONFIRM_DETAIL_MAX``) becomes.
MAX_LINE_CHARS = 2_000
# These bounds LIMIT padding; they cannot by themselves keep everything in view. Gaps just under them,
# repeated, still run a line off the screen, as do many short lines, a long visible prefix or wide glyphs
# (U+FDFD three hundred times). That is the clients' part: an overflow marker on the detail, and Confirm
# disabled until it has been scrolled to its end (``website/docs/guides/confirm-sensitive-actions.md``).
_SPACE_RUN = re.compile(" +")


def _clean(text: object, *, multiline: bool) -> str:
    """Plain text safe to show verbatim: line/paragraph separators become newlines, every other control
    (Cc), format (Cf: bidi overrides and isolates, zero-width characters), surrogate (Cs) and private-use
    (Co) code point is dropped, as are invisible letters, and combining marks beyond
    :data:`MAX_COMBINING_MARKS` per base character. A single-line field collapses all whitespace to single
    spaces."""
    raw = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    out = []
    marks = 0
    for ch in raw:
        category = unicodedata.category(ch)
        if category in ("Mn", "Me"):
            marks += 1
            if marks <= MAX_COMBINING_MARKS:
                out.append(ch)
            continue
        marks = 0
        if ch in _LINE_BREAKS:
            out.append("\n" if multiline else " ")
        elif ch == "\t":
            out.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co") or ch in _INVISIBLE_LETTERS:
            continue
        else:
            out.append(ch)
    cleaned = "".join(out)
    if not multiline:
        return " ".join(cleaned.split())
    lines = [" ".join(line.split()) for line in cleaned.split("\n")]
    # At most one blank line in a row, none at either end.
    kept: list[str] = []
    for line in lines:
        if line or (kept and kept[-1]):
            kept.append(line)
    while kept and not kept[-1]:
        kept.pop()
    return "\n".join(kept)


def _layout_problem(text: str, *, json_strings: bool = False) -> str:
    """Why the spacing of *text* could hide part of it from the person confirming it, or "" (see
    :data:`MAX_SPACE_RUN`, :data:`MAX_INDENT`, :data:`MAX_BLANK_LINES`, :data:`MAX_LINE_CHARS`). Tabs and
    every other kind of whitespace are refused before this runs, so only spaces and newlines count.

    *json_strings* (a tool call's detail: its name, then its arguments as indented JSON): a string value
    keeps its line breaks as the visible escape ``\\n``, so the indentation of each line of code in it
    shows as a run of spaces right after that escape. Such a run is that line's indentation and may be up
    to :data:`MAX_INDENT`; every other run keeps :data:`MAX_SPACE_RUN`."""
    blank = 0
    for number, line in enumerate(text.split("\n"), start=1):
        if not line.strip(" "):
            blank += 1
            if blank > MAX_BLANK_LINES:
                return f"line {number - blank + 1} starts more than {MAX_BLANK_LINES} blank lines in a row"
            continue
        blank = 0
        if len(line) > MAX_LINE_CHARS:
            return f"line {number} is {len(line)} characters (at most {MAX_LINE_CHARS})"
        body = line.lstrip(" ")
        if (indent := len(line) - len(body)) > MAX_INDENT:
            return f"line {number} is indented {indent} spaces (at most {MAX_INDENT})"
        for run in _SPACE_RUN.finditer(body):
            size = run.end() - run.start()
            if size <= MAX_SPACE_RUN:
                continue
            if json_strings and size <= MAX_INDENT and body[max(0, run.start() - 2):run.start()] == "\\n":
                continue
            return f"line {number} has {size} spaces in a row (at most {MAX_SPACE_RUN})"
    return ""


def verbatim_problem(text: str, *, json_strings: bool = False) -> str:
    """Why *text* cannot be shown VERBATIM (no cleaning at all), or "": a character :func:`_clean` would
    drop or rewrite (a control character other than newline, a tab, a format, surrogate or private-use
    character, a line or paragraph separator, whitespace other than space, an invisible letter, more than
    :data:`MAX_COMBINING_MARKS` combining marks on one character), an unassigned code point (``Cn``: the
    running Unicode database does not know it, so neither does this check) or a default-ignorable one
    (:data:`DEFAULT_IGNORABLE`, which renders as nothing), whitespace at the end of a line or of the text,
    which no rendering shows, or spacing that could push part of it out of view (:func:`_layout_problem`,
    with *json_strings* for a tool call's detail)."""
    marks = 0
    for ch in text:
        category = unicodedata.category(ch)
        if category == "Cn" or default_ignorable(ch):
            return f"character U+{ord(ch):04X} cannot be shown as it is"
        if category in ("Mn", "Me"):
            marks += 1
            if marks > MAX_COMBINING_MARKS:
                return "too many combining marks on one character"
            continue
        marks = 0
        if ch in ("\n", " "):
            continue
        if category in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp", "Zs") or ch in _INVISIBLE_LETTERS or ch.isspace():
            return f"character U+{ord(ch):04X} cannot be shown as it is"
    if any(line != line.rstrip() for line in text.split("\n")) or text != text.rstrip():
        return "whitespace at the end of a line or of the text cannot be seen"
    if problem := _layout_problem(text, json_strings=json_strings):
        return f"{problem}, which can put part of it out of view; present it without padding"
    return ""


DETAIL_LAYOUTS = ("text", "json")


def build_params(*, summary: object, detail: object = None, title: object = None,
                 level: object = "plain", verbatim_detail: bool = False, detail_layout: str = "text") -> dict:
    """The ``confirm`` params (without ``session_id``), cleaned and bounded. Raises
    :class:`ConfirmParamsError` instead of truncating: the person must see the whole of what the agent
    asks, so text over a bound goes back to the agent to shorten.

    *verbatim_detail* (a confirmation the gateway forces for an operator rule): the detail is the command
    exactly as it runs and is NOT cleaned (no whitespace collapsing, no stripping, indentation kept); text
    :func:`verbatim_problem` refuses (hidden characters, trailing whitespace, padding that could push part
    of it out of view) raises instead, never rewritten. *detail_layout* ``json`` is a tool call's detail
    (:func:`verbatim_problem` with ``json_strings``). Clients render the detail monospaced with whitespace
    preserved."""
    if detail_layout not in DETAIL_LAYOUTS:
        raise ConfirmParamsError(f"detail_layout must be one of: {', '.join(DETAIL_LAYOUTS)}")
    level = str(level or "").strip()
    if level not in LEVELS:
        raise ConfirmParamsError(f"level must be one of: {', '.join(sorted(LEVELS))}")
    summary_text = _clean(summary, multiline=True)
    if not summary_text:
        raise ConfirmParamsError("summary is required: one or two plain sentences saying exactly what will happen")
    if len(summary_text) > CONFIRM_SUMMARY_MAX:
        raise ConfirmParamsError(f"summary is {len(summary_text)} characters; the limit is {CONFIRM_SUMMARY_MAX}. "
                                 "Shorten it and put specifics in detail.")
    if verbatim_detail and detail is not None:
        detail_text = detail if isinstance(detail, str) else str(detail)
        if problem := verbatim_problem(detail_text, json_strings=detail_layout == "json"):
            raise ConfirmParamsError(f"detail cannot be shown verbatim: {problem}")
    else:
        detail_text = _clean(detail, multiline=True) if detail is not None else ""
    if len(detail_text) > CONFIRM_DETAIL_MAX:
        raise ConfirmParamsError(f"detail is {len(detail_text)} characters; the limit is {CONFIRM_DETAIL_MAX}.")
    title_text = _clean(title, multiline=False) if title is not None else ""
    if len(title_text) > CONFIRM_TITLE_MAX:
        raise ConfirmParamsError(f"title is {len(title_text)} characters; the limit is {CONFIRM_TITLE_MAX}.")
    params: dict = {"title": title_text or DEFAULT_TITLE, "summary": summary_text, "level": level}
    if detail_text:
        params["detail"] = detail_text
    return params


def result_problem(params: dict):
    """The validator ``send_gated`` runs on every answer for a request sent with *params*: None for an
    answer that may settle it, else why not (the level's :meth:`Level.check`)."""
    level = LEVELS[params["level"]]
    return lambda result: level.check(params, result)[0]


# ── rate limit ────────────────────────────────────────────────────────────────────────────────

_rate_lock = threading.Lock()
_pending: dict[str, int] = {}
_sent: dict[str, collections.deque] = {}
# Conversation key → monotonic time the last ``passkey`` request there ended other than ``confirmed``.
_passkey_failed: dict[str, float] = {}


def _rate_key(sid: str) -> str:
    """The conversation, not the window: a reconnect can mint a new UI session id for the same one."""
    from tui_gateway import server
    session = server._sessions.get(sid) or {}
    return str(session.get("session_key") or sid)


def _reserve(key: str, now: float) -> str:
    """Take the one open slot for *key*; "" on success, else the reason it is refused."""
    with _rate_lock:
        history = _sent.get(key)
        if history is not None:
            while history and now - history[0] >= WINDOW_SECONDS:
                history.popleft()
            if not history:
                _sent.pop(key, None)
                history = None
        if _pending.get(key, 0) >= MAX_PENDING:
            return "already_pending"
        if history is not None and len(history) >= MAX_PER_WINDOW:
            return "rate_limited"
        _pending[key] = _pending.get(key, 0) + 1
        return ""


def _release(key: str, *, sent_at: float | None) -> None:
    with _rate_lock:
        left = _pending.get(key, 0) - 1
        if left > 0:
            _pending[key] = left
        else:
            _pending.pop(key, None)
        if sent_at is not None:
            _sent.setdefault(key, collections.deque()).append(sent_at)


def _downgrade_refused(key: str, now: float) -> bool:
    with _rate_lock:
        failed = _passkey_failed.get(key)
        if failed is not None and now - failed >= DOWNGRADE_WINDOW_SECONDS:
            _passkey_failed.pop(key, None)
            failed = None
        return failed is not None


def _note_passkey_failed(key: str, now: float) -> None:
    with _rate_lock:
        _passkey_failed[key] = now


def reset_for_tests() -> None:
    with _rate_lock:
        _pending.clear()
        _sent.clear()
        _passkey_failed.clear()


# ── request ───────────────────────────────────────────────────────────────────────────────────


def _audit_sink(event: str, **fields) -> None:
    """Write one record to the dashboard auth audit log (never raises). Replaced in tests."""
    try:
        from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
        audit_log(AuditEvent(event), **fields)
    except Exception:
        logger.debug("confirm audit record not written", exc_info=True)


def _connection(transport) -> tuple[str, str]:
    """``(login, peer address)`` of a client connection, ``"-"`` for what is unknown."""
    if transport is None:
        return "-", "-"
    from tui_gateway import server
    login = server._transport_auth_user_id(transport)
    return login or "-", str(getattr(transport, "_peer", "") or "-")


class _Audit:
    """The two audit records of one confirm request. Fields name who and what, never the text."""

    def __init__(self, sid: str, level: str, *, forced: bool = False) -> None:
        self.sid, self.level, self.request_id, self.reached = sid, level, "", 0
        # Only set on a forced request, so the records of every other request keep their shape.
        self.extra = {"forced": True} if forced else {}
        self.acting = "-"
        try:
            from tui_gateway import server
            self.acting = server._acting_auth_user(server._sessions.get(sid))[0] or "-"
        except Exception:
            logger.debug("confirm audit: acting user unresolved", exc_info=True)

    def opened(self, request_id: str, reached: int) -> None:
        self.request_id, self.reached = request_id, reached
        audit.info("confirm request session=%s request=%s level=%s acting_user=%s reached=%d forced=%s",
                   self.sid, request_id, self.level, self.acting, reached, bool(self.extra))
        _audit_sink("confirm_request", session_id=self.sid, request_id=request_id, level=self.level,
                    acting_user=self.acting, reached=reached, **self.extra)

    def outcome(self, outcome: ConfirmOutcome, *, request_id: str = "", answered_by=None) -> ConfirmOutcome:
        user, peer = _connection(answered_by)
        request_id = request_id or self.request_id or "-"
        audit.info("confirm outcome session=%s request=%s level=%s acting_user=%s outcome=%s method=%s reason=%s "
                   "answered_by=%s peer=%s", self.sid, request_id, self.level, self.acting, outcome.outcome,
                   outcome.method or "-", outcome.reason or "-", user, peer)
        _audit_sink("confirm_outcome", session_id=self.sid, request_id=request_id, level=self.level,
                    acting_user=self.acting, outcome=outcome.outcome, method=outcome.method or "",
                    reason=outcome.reason, verified=outcome.verified, answered_by=user, answered_from=peer,
                    **self.extra)
        return outcome


def _fire_pre_confirm_request(**kwargs) -> threading.Event:
    """The ``pre_confirm_request`` plugin hook (a push for the request), off the request's own thread so a
    slow plugin never eats into the person's 120 seconds. Never the text: ids, level, user, expiry. The event
    is set once the hook returned: ``post_server_request`` for the request is not delivered before it."""
    done = threading.Event()

    def fire() -> None:
        try:
            from hermes_cli.plugins import invoke_hook
            invoke_hook("pre_confirm_request", **kwargs)
        except Exception:  # noqa: BLE001 - a plugin must not affect the request
            logger.debug("pre_confirm_request hook failed", exc_info=True)
        finally:
            done.set()

    threading.Thread(target=fire, name="confirm-hook", daemon=True).start()
    return done


def forced_rate_key(key: str) -> str:
    """The rate-limit key of a confirmation forced by an operator rule in conversation *key*."""
    return f"forced:{key}"


def request(sid: str, params: dict, *, timeout: float = TIMEOUT_SECONDS, forced: bool = False) -> ConfirmOutcome:
    """Ask the clients of *sid* that advertised ``params["level"]`` to confirm, and block for the outcome.
    *params* come from :func:`build_params`. Never raises for a client-side failure: every way of not
    getting a valid answer is ``unavailable`` or ``timeout``, never ``declined`` and never ``confirmed``.
    A ``passkey`` request that ends in one of the post-send failures (:func:`opens_downgrade_window`) opens
    the no-downgrade window of the conversation, forced or not. *forced*: the gateway asks for an operator
    rule (level ``passkey`` only); it counts under :func:`forced_rate_key` and is audited as forced."""
    if forced and params["level"] != "passkey":
        raise ValueError("a forced confirmation is at level passkey")
    outcome = _request(sid, params, timeout=timeout, forced=forced)
    if params["level"] == "passkey" and opens_downgrade_window(outcome):
        _note_passkey_failed(_rate_key(sid), time.monotonic())
    return outcome


def _request(sid: str, params: dict, *, timeout: float, forced: bool = False) -> ConfirmOutcome:
    level_name = params["level"]
    level = LEVELS[level_name]
    log = _Audit(sid, level_name, forced=forced)
    if not level.implemented:
        return log.outcome(ConfirmOutcome("unavailable", reason="level_not_implemented"))
    if os.environ.get("HERMES_COMPUTE_HOST_CHILD") == "1":
        # Under turn isolation the agent runs in a child whose only peer is the host pipe: it cannot see
        # which connection advertised which level, so it cannot gate the frame. Fail closed.
        return log.outcome(ConfirmOutcome("unavailable", reason="turn_isolation"))
    key = _rate_key(sid)
    if level_name == "plain" and _downgrade_refused(key, time.monotonic()):
        return log.outcome(ConfirmOutcome("unavailable", reason="downgrade_refused"))
    verification = None
    if level_name == "passkey":
        from tui_gateway import confirm_passkey
        try:
            verification = confirm_passkey.open(sid, params, timeout=timeout)
        except confirm_passkey.Unavailable as exc:
            return log.outcome(ConfirmOutcome("unavailable", reason=exc.reason))
        log.acting = verification.user_id
    refused = _reserve(forced_rate_key(key) if forced else key, time.monotonic())
    if refused:
        return log.outcome(ConfirmOutcome("unavailable", reason=refused))
    if verification is not None:
        outgoing = {**params, **verification.params()}
        gated: dict = {"validate": verification.validate, "target": verification.target,
                       "request_id": verification.request_id, "max_refusals": verification.max_refusals,
                       "on_refusal": verification.on_refusal}
        hook_user, expires_at = verification.user_id, verification.expires_at
    else:
        outgoing = {**params, **level.challenge(sid, params)}
        gated = {"validate": result_problem(outgoing)}
        hook_user, expires_at = ("" if log.acting == "-" else log.acting), int(time.time() + timeout)

    tracked: list[request_hooks.Tracked] = []

    def opened(request_id: str, reached: int) -> None:
        log.opened(request_id, reached)
        announced = _fire_pre_confirm_request(session_id=sid, session_key=key, request_id=request_id,
                                              level=level_name, user_id=hook_user, expires_at=expires_at,
                                              reached=reached)
        # ``post_server_request`` for the same request once it settles (``pre_confirm_request`` is its pre).
        handle = request_hooks.opened("confirm", sid, request_id, announce=False, session_key=key,
                                      user_id=hook_user, announced=announced)
        if handle is not None:
            tracked.append(handle)

    sent_at: float | None = None
    try:
        sent_at = time.monotonic()
        result = server_requests.send_gated("confirm", sid, outgoing, level=level_name, timeout=timeout,
                                            on_open=opened, **gated)
        if result.status == "unavailable" and result.reason in ("no_capable_client", "write_failed"):
            sent_at = None  # nothing reached a person: it does not count against the window
    except BaseException:
        _release(forced_rate_key(key) if forced else key, sent_at=sent_at)
        for handle in tracked:
            handle.settled("interrupted")
        raise
    _release(forced_rate_key(key) if forced else key, sent_at=sent_at)
    for handle in tracked:
        handle.settled(request_hooks.settle_reason(result))
    rid = result.request_id
    if result.status == "answered":
        answer = result.result or {}
        if verification is not None:
            # Commit, receipt and ``verified``: once, here, outside every lock.
            outcome, method, verified, reason = verification.settle(answer, result.answered_by)
            return log.outcome(ConfirmOutcome(outcome, method=method or None, verified=verified, reason=reason),
                               request_id=rid, answered_by=result.answered_by)
        # The gateway decides ``verified`` (the level's check), never the client.
        _, verified = level.check(outgoing, answer)
        return log.outcome(ConfirmOutcome(str(answer["decision"]), method=str(answer["method"]), verified=verified),
                           request_id=rid, answered_by=result.answered_by)
    if result.status == "timeout":
        return log.outcome(ConfirmOutcome("timeout", reason="timeout"), request_id=rid)
    if result.status == "cancelled":
        return log.outcome(ConfirmOutcome("unavailable", reason=f"cancelled:{result.reason}"), request_id=rid)
    if result.reason == "too_many_attempts":
        return log.outcome(ConfirmOutcome("unavailable", reason="verification_failed"), request_id=rid)
    return log.outcome(ConfirmOutcome("unavailable", reason=result.reason or "unavailable"), request_id=rid)


def strong_confirm(sid: str):
    """The strong-confirm callback this gateway registers for session *sid*
    (``tools.passkey_policy.register_strong_confirm``, keyed by the conversation): a forced ``passkey``
    confirmation of the gateway-built ``{title, summary, detail, detail_layout?}`` (``"json"`` for a tool
    call). It runs on the thread of the guarded command or tool call, inside the turn's context, so the
    request binds to the turn's submitter. Raises :class:`ConfirmParamsError` for text over the contract's
    bounds."""
    def ask(text: dict) -> ConfirmOutcome:
        params = build_params(level="passkey", title=text.get("title"), summary=text.get("summary"),
                              detail=text.get("detail"), verbatim_detail=True,
                              detail_layout=str(text.get("detail_layout") or "text"))
        return request(sid, params, timeout=TIMEOUT_SECONDS, forced=True)

    return ask


def request_from_tool(sid: str, *, summary: object, detail: object = None, title: object = None,
                      level: object = "plain") -> ConfirmOutcome:
    """The bridge ``tools/confirm_tool.py`` calls (installed by ``tui_gateway/server.py``). *sid* is the turn's
    ``HERMES_UI_SESSION_ID``; a sid this process does not host is ``unavailable`` with nothing sent.
    Raises :class:`ConfirmParamsError` for text the agent must fix."""
    from tui_gateway import server
    params = build_params(summary=summary, detail=detail, title=title, level=level)
    if not sid or sid not in server._sessions:
        return _Audit(sid or "-", params["level"]).outcome(ConfirmOutcome("unavailable", reason="no_session"))
    return request(sid, params)
