"""The ``confirm`` server→client request: the agent asks the person to confirm one sensitive action.

Levels (:data:`LEVELS`): ``plain`` is the one that exists. It is a tap on Confirm in a connected client
that advertised ``plain``; it proves nothing beyond that, and the gateway cannot check even that — any
client that can attach to the session can advertise it and answer. ``passkey`` is reserved for a verified
level the gateway will check itself; it is not implemented, and a request for it is ``unavailable`` at
once with nothing sent.

What this module adds on top of ``server_requests.send_gated``:

- the params are built here, never passed through: plain text only, control and format characters
  (bidi overrides, zero-width characters) stripped, lengths checked against the contract bounds;
- four outcomes the caller can act on: ``confirmed``, ``declined``, ``unavailable`` (no connected client
  can answer the level, a client answered an error, the request was withdrawn, a rate limit, a level that
  is not implemented, or turn isolation), ``timeout`` (120 s, ``request.cancel {reason: timeout}``);
- ``verified`` decided by the gateway from the level, never taken from the client;
- a per-conversation rate limit: one open confirmation at a time and at most
  :data:`MAX_PER_WINDOW` sent per :data:`WINDOW_SECONDS`;
- one audit log line per request and per outcome (conversation, level, outcome, method — never the
  title, summary or detail).

Extension points for a verified level (each is one method on :class:`Level`):

1. :meth:`Level.challenge` — level-specific fields added to the outgoing params (a fresh challenge bound
   to this request); the contract's ``ConfirmRequestParams`` gains the matching optional field.
2. :meth:`Level.check` — verifies a level-specific proof in the client's result before the answer may
   settle the request, and says whether the outcome is ``verified``; ``ConfirmResult`` gains the field.
3. Per-user credential registration — which connections may advertise the level at all:
   ``server_requests.advertise`` (``CONFIRM_LEVELS``) is where an advertisement would be accepted only
   for a signed-in user with a registered credential, and :attr:`Level.advertisable` flips on.
"""

from __future__ import annotations

import collections
import logging
import os
import threading
import time
import unicodedata
from dataclasses import dataclass

from tui_gateway import server_requests
from tui_gateway.contracts.server_requests import (CONFIRM_DETAIL_MAX, CONFIRM_SUMMARY_MAX, CONFIRM_TITLE_MAX,
                                                   ConfirmDecision, ConfirmMethod)

logger = logging.getLogger(__name__)
audit = logging.getLogger("tui_gateway.confirm.audit")

TIMEOUT_SECONDS = 120.0
MAX_PENDING = 1
MAX_PER_WINDOW = 6
WINDOW_SECONDS = 600.0
DEFAULT_TITLE = "Confirm an action"

_DECISIONS = frozenset(decision.value for decision in ConfirmDecision)
_METHODS = frozenset(method.value for method in ConfirmMethod)


class Level:
    """One confirm level: whether it is implemented, whether a client may advertise it, what it adds to the
    outgoing params and how an answer is checked. The base class is the ``plain`` behaviour."""

    name = ""
    implemented = True
    advertisable = True

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
        if method not in _METHODS:
            return f"method must be one of {sorted(_METHODS)}", False
        return None, False


class _Plain(Level):
    name = "plain"


class _Reserved(Level):
    """A level named in the contract whose design is not built yet: never sent, never advertisable."""

    implemented = False
    advertisable = False

    def __init__(self, name: str) -> None:
        self.name = name

    def check(self, params: dict, result: dict) -> tuple[str | None, bool]:
        return "level not implemented", False


#: Every level in the contract. ``passkey`` is reserved for the verified level.
LEVELS: dict[str, Level] = {"plain": _Plain(), "passkey": _Reserved("passkey")}


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


def _clean(text: object, *, multiline: bool) -> str:
    """Plain text safe to show verbatim: line/paragraph separators become newlines, every other control
    (Cc), format (Cf: bidi overrides and isolates, zero-width characters), surrogate (Cs) and private-use
    (Co) code point is dropped. A single-line field collapses all whitespace to single spaces."""
    raw = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    out = []
    for ch in raw:
        if ch in "\n  ":
            out.append("\n" if multiline else " ")
        elif ch == "\t":
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co"):
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


def build_params(*, summary: object, detail: object = None, title: object = None,
                 level: object = "plain") -> dict:
    """The ``confirm`` params (without ``session_id``), cleaned and bounded. Raises
    :class:`ConfirmParamsError` instead of truncating: the person must see the whole of what the agent
    asks, so text over a bound goes back to the agent to shorten."""
    level = str(level or "").strip()
    if level not in LEVELS:
        raise ConfirmParamsError(f"level must be one of: {', '.join(sorted(LEVELS))}")
    summary_text = _clean(summary, multiline=True)
    if not summary_text:
        raise ConfirmParamsError("summary is required: one or two plain sentences saying exactly what will happen")
    if len(summary_text) > CONFIRM_SUMMARY_MAX:
        raise ConfirmParamsError(f"summary is {len(summary_text)} characters; the limit is {CONFIRM_SUMMARY_MAX}. "
                                 "Shorten it and put specifics in detail.")
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


def reset_for_tests() -> None:
    with _rate_lock:
        _pending.clear()
        _sent.clear()


# ── request ───────────────────────────────────────────────────────────────────────────────────


def _log_outcome(sid: str, level: str, outcome: ConfirmOutcome) -> ConfirmOutcome:
    audit.info("confirm outcome session=%s level=%s outcome=%s method=%s reason=%s",
               sid, level, outcome.outcome, outcome.method or "-", outcome.reason or "-")
    return outcome


def request(sid: str, params: dict, *, timeout: float = TIMEOUT_SECONDS) -> ConfirmOutcome:
    """Ask the clients of *sid* that advertised ``params["level"]`` to confirm, and block for the outcome.
    *params* come from :func:`build_params`. Never raises for a client-side failure: every way of not
    getting a valid answer is ``unavailable`` or ``timeout``, never ``declined`` and never ``confirmed``."""
    level_name = params["level"]
    level = LEVELS[level_name]
    audit.info("confirm request session=%s level=%s", sid, level_name)
    if not level.implemented:
        return _log_outcome(sid, level_name, ConfirmOutcome("unavailable", reason="level_not_implemented"))
    if os.environ.get("HERMES_COMPUTE_HOST_CHILD") == "1":
        # Under turn isolation the agent runs in a child whose only peer is the host pipe: it cannot see
        # which connection advertised which level, so it cannot gate the frame. Fail closed.
        return _log_outcome(sid, level_name, ConfirmOutcome("unavailable", reason="turn_isolation"))
    key = _rate_key(sid)
    refused = _reserve(key, time.monotonic())
    if refused:
        return _log_outcome(sid, level_name, ConfirmOutcome("unavailable", reason=refused))
    outgoing = {**params, **level.challenge(sid, params)}
    sent_at: float | None = None
    try:
        sent_at = time.monotonic()
        result = server_requests.send_gated("confirm", sid, outgoing, level=level_name, timeout=timeout,
                                            validate=result_problem(outgoing))
        if result.status == "unavailable" and result.reason in ("no_capable_client", "write_failed"):
            sent_at = None  # nothing reached a person: it does not count against the window
    except BaseException:
        _release(key, sent_at=sent_at)
        raise
    _release(key, sent_at=sent_at)
    if result.status == "answered":
        answer = result.result or {}
        # The gateway decides ``verified`` (the level's check), never the client.
        _, verified = level.check(outgoing, answer)
        return _log_outcome(sid, level_name, ConfirmOutcome(str(answer["decision"]), method=str(answer["method"]),
                                                            verified=verified))
    if result.status == "timeout":
        return _log_outcome(sid, level_name, ConfirmOutcome("timeout", reason="timeout"))
    if result.status == "cancelled":
        return _log_outcome(sid, level_name, ConfirmOutcome("unavailable", reason=f"cancelled:{result.reason}"))
    return _log_outcome(sid, level_name, ConfirmOutcome("unavailable", reason=result.reason or "unavailable"))


def request_from_tool(sid: str, *, summary: object, detail: object = None, title: object = None,
                      level: object = "plain") -> ConfirmOutcome:
    """The bridge ``tools/confirm_tool.py`` calls (installed by ``tui_gateway/server.py``). *sid* is the turn's
    ``HERMES_UI_SESSION_ID``; a sid this process does not host is ``unavailable`` with nothing sent.
    Raises :class:`ConfirmParamsError` for text the agent must fix."""
    from tui_gateway import server
    params = build_params(summary=summary, detail=detail, title=title, level=level)
    if not sid or sid not in server._sessions:
        return _log_outcome(sid or "-", params["level"], ConfirmOutcome("unavailable", reason="no_session"))
    return request(sid, params)
