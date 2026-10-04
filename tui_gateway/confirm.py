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
- structured ``fields`` (plan request-types-v2 D8): at most :data:`CONFIRM_FIELDS_MAX` one-line facts
  (``amount``, ``recipient``, ``model``, …), each checked VERBATIM (refused, never rewritten); a request with
  fields goes only to connections that advertised ``confirm_fields`` (at ``passkey`` also
  ``confirm_passkey {v: 2}``: the challenge then commits to ``text_digest_v2``), and is ``unavailable
  (no_capable_client)`` when none is attached, never sent without them;
- ``draft_id`` (D7): the detail is the text the person approved in ``review.draft``, taken verbatim from
  ``review_register`` (whatever detail the agent passed is ignored); an unknown or expired id is refused
  before anything is sent;
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
  login and peer address of the connection whose answer settled it, plus ``fields: <n>`` and ``draft: true``
  when present — never the title, summary, detail or a field's label or value.

A level that needs per-request state (``passkey``: the bound user, a nonce, a credential snapshot) builds it
in its own module before the frame goes out; :class:`Level` covers the context-free part (the shape of a
``plain`` answer).
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass

from tui_gateway import request_hooks, request_limits, review_register, server_requests
from tui_gateway.contracts.server_requests import (CONFIRM_DETAIL_MAX, CONFIRM_FIELD_CURRENCY_MAX, CONFIRM_FIELD_ID,
                                                   CONFIRM_FIELD_LABEL_MAX, CONFIRM_FIELD_VALUE_MAX,
                                                   CONFIRM_FIELDS_MAX, CONFIRM_SUMMARY_MAX, CONFIRM_TITLE_MAX,
                                                   ConfirmDecision, ConfirmFieldKind, ConfirmMethod)
# The text rules live in ``request_text``; these names are re-exported because the policy and the tests read them here.
from tui_gateway.request_text import (DEFAULT_IGNORABLE, MAX_BLANK_LINES, MAX_COMBINING_MARKS, MAX_INDENT,  # noqa: F401
                                      MAX_LINE_CHARS, MAX_SPACE_RUN, clean_text, default_ignorable,  # noqa: F401
                                      verbatim_problem)

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


# ── params ────────────────────────────────────────────────────────────────────────────────────

DETAIL_LAYOUTS = ("text", "json")
FIELD_KINDS = tuple(kind.value for kind in ConfirmFieldKind)
_FIELD_KEYS = frozenset({"id", "kind", "label", "value", "currency"})
_FIELD_ID = re.compile(CONFIRM_FIELD_ID)


def _field_text(index: int, key: str, raw: object, limit: int) -> str:
    """One string of a structured field: ONE line, shown exactly as given. Spaces at either end are the only
    thing removed; a value that is not a string (no number is converted: the agent writes it as it should be
    shown), anything :func:`verbatim_problem` refuses (an invisible, bidi or control character, a character
    that renders as nothing, padding) and a line break raise, never rewritten."""
    if not isinstance(raw, str):
        raise ConfirmParamsError(f"fields[{index}].{key} must be a string, written exactly as it should be shown")
    text = raw.strip(" ")
    if not text:
        raise ConfirmParamsError(f"fields[{index}].{key} is empty")
    if len(text) > limit:
        raise ConfirmParamsError(f"fields[{index}].{key} is {len(text)} characters; the limit is {limit}.")
    if "\n" in text:
        raise ConfirmParamsError(f"fields[{index}].{key} must be one line")
    if problem := verbatim_problem(text):
        raise ConfirmParamsError(f"fields[{index}].{key} cannot be shown as it is: {problem}")
    return text


def build_fields(fields: object) -> list[dict] | None:
    """The ``fields`` of a ``confirm`` (contract ``ConfirmField``), or None for none. Raises
    :class:`ConfirmParamsError` for anything the person could not be shown exactly: more than
    :data:`CONFIRM_FIELDS_MAX`, an unknown key or kind, an id that is not ``[a-z][a-z0-9_]{0,31}`` or not unique
    (a missing id becomes ``field_<n>``), ``currency`` on anything but an ``amount``, and every string
    :func:`_field_text` refuses."""
    if fields is None or (isinstance(fields, (list, tuple)) and not fields):
        return None
    if not isinstance(fields, (list, tuple)):
        raise ConfirmParamsError("fields must be a list of {kind, label, value, currency?, id?} objects")
    if len(fields) > CONFIRM_FIELDS_MAX:
        raise ConfirmParamsError(f"{len(fields)} fields; the limit is {CONFIRM_FIELDS_MAX}.")
    built: list[dict] = []
    for index, raw in enumerate(fields):
        if not isinstance(raw, dict):
            raise ConfirmParamsError(f"fields[{index}] must be an object with kind, label and value")
        if unknown := sorted(str(key) for key in set(raw) - _FIELD_KEYS):
            raise ConfirmParamsError(f"fields[{index}] has unknown keys: {', '.join(unknown)}")
        kind = raw.get("kind")
        if kind not in FIELD_KINDS:
            raise ConfirmParamsError(f"fields[{index}].kind must be one of: {', '.join(FIELD_KINDS)}")
        field_id = raw.get("id")
        field_id = f"field_{index + 1}" if field_id is None else field_id
        if not isinstance(field_id, str) or not _FIELD_ID.fullmatch(field_id):
            raise ConfirmParamsError(f"fields[{index}].id must be a lower-case identifier ([a-z][a-z0-9_]*, at "
                                     "most 32 characters)")
        if any(field["id"] == field_id for field in built):
            raise ConfirmParamsError(f"fields[{index}].id {field_id!r} is used twice")
        field = {"id": field_id, "kind": kind,
                 "label": _field_text(index, "label", raw.get("label"), CONFIRM_FIELD_LABEL_MAX),
                 "value": _field_text(index, "value", raw.get("value"), CONFIRM_FIELD_VALUE_MAX)}
        if raw.get("currency") is not None:
            if kind != "amount":
                raise ConfirmParamsError(f"fields[{index}].currency is only for kind amount")
            field["currency"] = _field_text(index, "currency", raw["currency"], CONFIRM_FIELD_CURRENCY_MAX)
        built.append(field)
    return built


def draft_detail(sid: str, draft_id: object) -> str:
    """The text the person approved as draft *draft_id* in the conversation of session *sid*
    (``review_register``), or :class:`ConfirmParamsError` when this conversation has no such live draft
    (unknown, expired, or another conversation's): nothing is sent then."""
    if not isinstance(draft_id, str) or not draft_id:
        raise ConfirmParamsError("draft_id must be the draft_id a review_draft approval returned")
    draft = review_register.get(_rate_key(sid), draft_id)
    if draft is None:
        raise ConfirmParamsError(f"draft {draft_id} is unknown or expired in this conversation (drafts are kept "
                                 f"{int(review_register.TTL_SECONDS // 60)} minutes): ask for a review_draft "
                                 "approval again; nothing was sent")
    if len(draft.text) > CONFIRM_DETAIL_MAX:
        raise ConfirmParamsError(f"draft {draft_id} is {len(draft.text)} characters; a confirmation shows at most "
                                 f"{CONFIRM_DETAIL_MAX}, so it cannot be confirmed with draft_id; nothing was sent")
    return draft.text


def build_params(*, summary: object, detail: object = None, title: object = None,
                 level: object = "plain", verbatim_detail: bool = False, detail_layout: str = "text",
                 fields: object = None) -> dict:
    """The ``confirm`` params (without ``session_id``), cleaned and bounded. Raises
    :class:`ConfirmParamsError` instead of truncating: the person must see the whole of what the agent
    asks, so text over a bound goes back to the agent to shorten.

    *verbatim_detail* (a confirmation the gateway forces for an operator rule): the detail is the command
    exactly as it runs and is NOT cleaned (no whitespace collapsing, no stripping, indentation kept); text
    :func:`verbatim_problem` refuses (hidden characters, trailing whitespace, padding that could push part
    of it out of view) raises instead, never rewritten. *detail_layout* ``json`` is a tool call's detail
    (:func:`verbatim_problem` with ``json_strings``). Clients render the detail monospaced with whitespace
    preserved. A reviewed draft (:func:`draft_detail`) comes in as a *verbatim_detail* too. *fields*: see
    :func:`build_fields`."""
    if detail_layout not in DETAIL_LAYOUTS:
        raise ConfirmParamsError(f"detail_layout must be one of: {', '.join(DETAIL_LAYOUTS)}")
    level = str(level or "").strip()
    if level not in LEVELS:
        raise ConfirmParamsError(f"level must be one of: {', '.join(sorted(LEVELS))}")
    summary_text = clean_text(summary, multiline=True)
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
        detail_text = clean_text(detail, multiline=True) if detail is not None else ""
    if len(detail_text) > CONFIRM_DETAIL_MAX:
        raise ConfirmParamsError(f"detail is {len(detail_text)} characters; the limit is {CONFIRM_DETAIL_MAX}.")
    title_text = clean_text(title, multiline=False) if title is not None else ""
    if len(title_text) > CONFIRM_TITLE_MAX:
        raise ConfirmParamsError(f"title is {len(title_text)} characters; the limit is {CONFIRM_TITLE_MAX}.")
    built_fields = build_fields(fields)
    params: dict = {"title": title_text or DEFAULT_TITLE, "summary": summary_text, "level": level}
    if detail_text:
        params["detail"] = detail_text
    if built_fields:
        params["fields"] = built_fields
    return params


def result_problem(params: dict):
    """The validator ``send_gated`` runs on every answer for a request sent with *params*: None for an
    answer that may settle it, else why not (the level's :meth:`Level.check`)."""
    level = LEVELS[params["level"]]
    return lambda result: level.check(params, result)[0]


# ── rate limit ────────────────────────────────────────────────────────────────────────────────

_limiter = request_limits.Limiter(MAX_PENDING, MAX_PER_WINDOW, WINDOW_SECONDS)
#: The limiter's send history (the same dict, not a copy; tests read and fill it).
_sent = _limiter.sent
#: Guards :data:`_passkey_failed` only; the limiter has a lock of its own and the two are never held together.
_rate_lock = threading.Lock()
# Conversation key → monotonic time the last ``passkey`` request there ended other than ``confirmed``.
_passkey_failed: dict[str, float] = {}


def _rate_key(sid: str) -> str:
    """The conversation, not the window: a reconnect can mint a new UI session id for the same one."""
    from tui_gateway import server
    session = server._sessions.get(sid) or {}
    return str(session.get("session_key") or sid)


def _reserve(key: str, now: float) -> str:
    """Take the one open slot for *key*; "" on success, else the reason it is refused."""
    return _limiter.reserve(key, now)


def _release(key: str, *, sent_at: float | None) -> None:
    _limiter.release(key, sent_at=sent_at)


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
    _limiter.reset()
    with _rate_lock:
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

    def __init__(self, sid: str, level: str, *, forced: bool = False, fields: int = 0, draft: bool = False) -> None:
        self.sid, self.level, self.request_id, self.reached = sid, level, "", 0
        # Only set where they apply, so the records of every other request keep their shape. ``fields`` is a
        # count and ``draft`` a flag: never a label, value or the draft's text.
        self.extra: dict = {"forced": True} if forced else {}
        if fields:
            self.extra["fields"] = fields
        if draft:
            self.extra["draft"] = True
        self.acting = "-"
        try:
            from tui_gateway import server
            self.acting = server._acting_auth_user(server._sessions.get(sid))[0] or "-"
        except Exception:
            logger.debug("confirm audit: acting user unresolved", exc_info=True)

    def _sink(self, event: str, **fields) -> None:
        """A ``passkey`` request's records go to the GATEWAY's dashboard-auth log (``passkeys.paths.
        gateway_scope``), beside its verification records and the sign-ins the passkeys belong to, whatever
        profile the turn runs in; every other level's stay with the turn's profile."""
        if self.level != "passkey":
            _audit_sink(event, **fields)
            return
        try:
            from hermes_cli.dashboard_auth.passkeys.paths import gateway_scope
            with gateway_scope():
                _audit_sink(event, **fields)  # never raises
            return
        except Exception:  # noqa: BLE001 - the gateway's home is unresolved: still written, in the turn's log
            logger.debug("confirm audit: the gateway's home is unresolved", exc_info=True)
        _audit_sink(event, **fields)

    def opened(self, request_id: str, reached: int) -> None:
        self.request_id, self.reached = request_id, reached
        audit.info("confirm request session=%s request=%s level=%s acting_user=%s reached=%d forced=%s fields=%d "
                   "draft=%s", self.sid, request_id, self.level, self.acting, reached, bool(self.extra.get("forced")),
                   int(self.extra.get("fields", 0)), bool(self.extra.get("draft")))
        self._sink("confirm_request", session_id=self.sid, request_id=request_id, level=self.level,
                    acting_user=self.acting, reached=reached, **self.extra)

    def outcome(self, outcome: ConfirmOutcome, *, request_id: str = "", answered_by=None) -> ConfirmOutcome:
        user, peer = _connection(answered_by)
        request_id = request_id or self.request_id or "-"
        audit.info("confirm outcome session=%s request=%s level=%s acting_user=%s outcome=%s method=%s reason=%s "
                   "answered_by=%s peer=%s", self.sid, request_id, self.level, self.acting, outcome.outcome,
                   outcome.method or "-", outcome.reason or "-", user, peer)
        self._sink("confirm_outcome", session_id=self.sid, request_id=request_id, level=self.level,
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


def request(sid: str, params: dict, *, timeout: float = TIMEOUT_SECONDS, forced: bool = False,
            draft: bool = False) -> ConfirmOutcome:
    """Ask the clients of *sid* that advertised ``params["level"]`` to confirm, and block for the outcome.
    *params* come from :func:`build_params`. Never raises for a client-side failure: every way of not
    getting a valid answer is ``unavailable`` or ``timeout``, never ``declined`` and never ``confirmed``.
    A ``passkey`` request that ends in one of the post-send failures (:func:`opens_downgrade_window`) opens
    the no-downgrade window of the conversation, forced or not. *forced*: the gateway asks for an operator
    rule (level ``passkey`` only); it counts under :func:`forced_rate_key` and is audited as forced. *draft*:
    the detail came from ``review_register`` (audited as ``draft: true``). A request with ``fields`` reaches
    only connections that advertised ``confirm_fields`` (and, at ``passkey``, ``confirm_passkey {v: 2}``)."""
    if forced and params["level"] != "passkey":
        raise ValueError("a forced confirmation is at level passkey")
    outcome = _request(sid, params, timeout=timeout, forced=forced, draft=draft)
    if params["level"] == "passkey" and opens_downgrade_window(outcome):
        _note_passkey_failed(_rate_key(sid), time.monotonic())
    return outcome


def _request(sid: str, params: dict, *, timeout: float, forced: bool = False, draft: bool = False) -> ConfirmOutcome:
    level_name = params["level"]
    level = LEVELS[level_name]
    log = _Audit(sid, level_name, forced=forced, fields=len(params.get("fields") or ()), draft=draft)
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
        if params.get("fields"):
            # Only to connections that show the fields: a client that would drop them would ask the person to
            # confirm less than the agent asked. None attached: ``unavailable (no_capable_client)``.
            gated["target"] = server_requests.confirm_fields_target
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
                      level: object = "plain", fields: object = None, draft_id: object = None) -> ConfirmOutcome:
    """The bridge ``tools/confirm_tool.py`` calls (installed by ``tui_gateway/server.py``). *sid* is the turn's
    ``HERMES_UI_SESSION_ID``; a sid this process does not host is ``unavailable`` with nothing sent.
    *draft_id* (``review.draft``'s approval): the detail is that draft's approved text, verbatim, from the
    gateway's register; *detail* is ignored then. Raises :class:`ConfirmParamsError` for text the agent must
    fix and for a *draft_id* this conversation does not have (nothing sent)."""
    from tui_gateway import server
    hosted = bool(sid) and sid in server._sessions
    if draft_id is not None and hosted:
        params = build_params(summary=summary, detail=draft_detail(sid, draft_id), title=title, level=level,
                              verbatim_detail=True, fields=fields)
    else:
        params = build_params(summary=summary, detail=detail, title=title, level=level, fields=fields)
    log_extra = {"fields": len(params.get("fields") or ()), "draft": draft_id is not None}
    if not hosted:
        return _Audit(sid or "-", params["level"], **log_extra).outcome(
            ConfirmOutcome("unavailable", reason="no_session"))
    return request(sid, params, draft=draft_id is not None)
