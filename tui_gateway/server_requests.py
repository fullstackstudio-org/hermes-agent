"""Server→client JSON-RPC requests: the backend asks the renderer a question and waits for the
response frame carrying the same ``id``.

JSON-RPC is peer-to-peer; this is the backend's half. Every "ask the renderer" bridge (clarify,
approval, sudo, secret, vault prompts, desktop GUI reads, MCP setup consent, the tour) is one
:func:`send` (blocking) or :func:`send_async` (queue-backed approvals) and one response frame from
the client — no paired ``*.request`` notification / ``*.respond`` method, no per-kind ``*.expire``.

Ids are ``srq-<12 hex>``: strings never collide with client-minted integer ids, and the random
part keeps a compute-host child's requests distinct from the parent's when both reach one socket.
A request that times out or is cancelled (interrupt, session close, shutdown) emits ONE
``request.cancel {id, method, reason}`` notification so every renderer tears the card down the
same way. A response for an id that is no longer open is dropped — the wait already returned.

Reconnect: unanswered requests are returned as ``open_requests`` by ``session.resume`` /
``session.activate`` / ``session.events.since`` (:func:`open_requests`); the shared TypeScript
channel re-delivers them as if they had just arrived, so the notification replay ring never
has to carry "a question still waiting for an answer".

Batch clarify keeps per-question locks (``clarify.lock`` → :func:`lock_answer`): answers stay
editable until every question is locked, locked answers survive a timeout, and the last lock
resolves the request with the full answer set.

Capability: a client says once per connection that it answers server→client requests
(``client.capabilities {server_requests: true}`` → :func:`advertise`). A WebSocket client that never
did is a build older than this half of the protocol — it drops the frame silently and the agent
would wait the full deadline (clarify's 300s) for nothing — so :func:`send` / :func:`send_async`
return the same ``None`` an error response produces without writing the frame (#112548).

Outcomes: :func:`send` folds "nobody could answer", "the client answered an error", "cancelled" and
(for single questions) "timed out" into one ``None``. :func:`send_detailed` returns the same wait as a
:class:`RequestOutcome` that keeps them apart; :func:`send` is a thin wrapper over it, so the existing
callers see exactly what they always saw.

Gated requests (``confirm``): :func:`send_gated` writes the frame only to the session's connections
that advertised the requested level (``client.capabilities {confirm: [...]}`` → :func:`advertise`),
never to the whole session. An answer is accepted only from a connection that advertised the level
(response frame or ``request.answer``) and only when the request's own validator accepts the result;
anything else is refused and the request stays open. An error response from a connection the frame
went to takes that connection out of the running; when none is left the outcome is ``unavailable``.
The first valid answer wins and the other connections get ``request.cancel {reason: "resolved"}``.

A gated request may narrow its audience further with a TARGET PREDICATE (``target(transport, detail)``,
``confirm`` at level ``passkey``: signed in as the bound user, with an accepted RP the user has a
credential for). The same predicate decides who gets the frame, who may answer (:func:`_may_answer`, both
answer paths) and who sees it in ``open_requests``; ``detail`` is what the connection advertised with the
level (``client.capabilities {confirm_passkey: ...}``). It may also cap refused answers (``max_refusals``):
each refused answer from a connection allowed to answer counts, and the last one settles the request
``unavailable (too_many_attempts)``; ``request.answer`` then reports refusals as 4034 with ``data.reason``.

METHOD GATE (the interactive requests ``input.form``, ``input.file``, ``review.draft``, ...: ``INTERACTIVE_METHODS``
in ``contracts/server_requests.py``). :func:`send_gated` with ``level=None`` qualifies a connection on the METHOD
instead of a level: it must have listed the method under ``client.capabilities {requests: [...]}``
(:func:`advertise`, recorded per connection beside the confirm levels and cleared by :func:`forget`). Everything
else above holds unchanged: the frame goes only to qualifying connections attached right now, the answer is
accepted only from one (4033 otherwise, 4034 for a refused result), an error response from every connection the
frame went to settles ``unavailable (error_response)``. The usual target predicate is :func:`acting_user_target`:
only the connections signed in as the login the turn acts for; when the gateway cannot name one, anyone capable
(no auth provider; or a shared session for ``input.*``) or nobody (a shared session for ``review.*``: ``unavailable
(no_acting_user)`` at once). An agent's connection never qualifies for a method-gated request (its advertisement
is ignored too).

PARKING (``send_gated(park_seconds=...)``, method-gated requests only; ``confirm`` keeps declining at once). When
no qualifying connection is attached, the request is still registered open, with no targets, ``on_open`` runs
with 0 connections reached and the ``pre_server_request`` hook fires with ``reached: 0`` (the push that brings
the person's phone). A qualifying connection that attaches later gets it from :func:`open_requests` (or pushed
by :func:`deliver_late`, when it advertises the method while already attached) and becomes a target, so its
error response counts like any other. ONE rule decides the wait of every method-gated request: while it has a
target (a live connection it was written or listed to) it waits for its ``timeout``; while it has none it waits
for the end of the park window (``min(timeout, park_seconds)`` from when it opened; 0 without parking) and after
that settles ``unavailable (no_capable_client)``. A target is lost by a failed write, by a disconnect
(:func:`forget`) and by an advertisement that no longer lists the method (:func:`advertise`), so a phone that
reconnects as a new connection replaces its old one instead of leaving it as a target. A request that was shown
and then lost its last target gets a FRESH window from that moment, never past its ``timeout``
(:func:`_drop_target_locked`): a phone that went to the background may come back to it. ``request.cancel {reason:
timeout}`` accompanies ``no_capable_client`` only when some connection was ever shown the request: a request
nobody saw ends silently (a cancel for an id nobody knows would only be noise). A cancel (interrupt, session
close, shutdown) withdraws a parked request like any other; :func:`open_request_count` and :func:`pending_kind`
count it while it waits.

AGENTS (a connection whose ``auth_identity`` carries ``agent``: an agent acting for its signed-in person
through MCP). Such a connection still receives every frame its session fans out, and :func:`open_requests`
still lists the ungated ones to it, read-only, so it can say what the person is being asked. It may answer
``clarify`` and nothing else (:func:`agent_answer_refusal`, on every answer path: the response frame, the
``request.answer`` proxy, ``clarify.lock`` and the compute-host relays); approvals, sudo, secrets and vault
prompts are the person's own, and a gated request never reaches it at all. It may answer a clarify only of a
turn it sent itself -- the request remembers, when it opens, who sent the turn it belongs to (the in-flight
record's ``author`` with ``via``) -- and never a question somebody already locked (:func:`agent_request_refusal`,
checked again under the lock that settles). A clarify answer it gives has every non-empty answer prefixed
(:func:`mark_agent_answer`), and text shaped like the gateway note relabelled, before it reaches the tool, so
the model reads it as the agent's and not the person's; ``dashboard.mcp.answer_clarify: false`` refuses
clarify too. Each answer and each refusal is an audit line naming the grant.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from typing import Any, Callable, NamedTuple

from tui_gateway import request_hooks
from tui_gateway.contracts.server_requests import CANNOT_SHOW, INTERACTIVE_METHODS

logger = logging.getLogger(__name__)


class RequestOutcome(NamedTuple):
    """How one server→client request ended.

    ``status``: ``answered`` (``result`` is the client's result object), ``unavailable`` (never sent
    because no attached client can answer it, or every client it went to answered a JSON-RPC error),
    ``timeout`` (the deadline passed; ``request.cancel {reason: timeout}`` went out; a batch clarify
    carries ``{"answers": <locked so far>, "timed_out": True}`` as ``result``) or ``cancelled``
    (withdrawn: interrupt, session close, shutdown; ``reason`` names which). ``request_id`` is the frame's id
    when one was minted; ``answered_by`` is the connection whose answer settled it (None when unknown or
    in-process). ``error_reason``: for ``unavailable (error_response)``, the settling error's ``data.reason``
    when it was a ``4041`` (``CANNOT_SHOW``) with a short machine word there (:func:`_cannot_show_reason`), else
    ""; the caller decides what of it to pass on."""

    status: str
    result: dict | None = None
    reason: str = ""
    request_id: str = ""
    answered_by: Any = None
    error_reason: str = ""


_MACHINE_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _cannot_show_reason(error: Any) -> str:
    """The ``data.reason`` of a ``4041 cannot_show`` error object when it is a short machine word, else ""."""
    if not isinstance(error, dict) or error.get("code") != CANNOT_SHOW:
        return ""
    data = error.get("data")
    reason = data.get("reason") if isinstance(data, dict) else None
    return reason if isinstance(reason, str) and _MACHINE_WORD.fullmatch(reason) else ""


def new_request_id() -> str:
    """A fresh request id (``srq-<12 hex>``), for a caller that must know it before the frame goes out (the
    passkey challenge commits to it)."""
    return f"srq-{uuid.uuid4().hex[:12]}"


class ServerRequest:
    __slots__ = ("id", "sid", "method", "params", "event", "result", "answered", "created_at",
                 "qids", "locked", "on_result", "errored", "cancel_reason", "level", "validate", "targets",
                 "answered_by", "target", "max_refusals", "refusals", "exhausted", "on_refusal", "turn_author",
                 "method_gated", "park_until", "listed", "shown",
                 "park_seconds", "deadline", "error_reason")

    def __init__(self, sid: str, method: str, params: dict, *, qids: list[str] | None = None,
                 on_result: Callable[[dict | None], None] | None = None, level: str | None = None,
                 validate: Callable[[dict], str | None] | None = None, request_id: str | None = None) -> None:
        self.id = request_id or new_request_id()
        self.sid = sid
        self.method = method
        self.params = dict(params)
        self.event = threading.Event()
        self.result: dict | None = None
        self.answered = False
        self.created_at = time.time()
        # Batch clarify: question ids still to lock, and the answers locked so far.
        self.qids = list(qids) if qids else None
        self.locked: dict[str, str] = {}
        self.on_result = on_result
        # Why a request settled without an answer: an error response, or the cancel reason.
        self.errored = False
        self.error_reason = ""
        self.cancel_reason = ""
        # Gated requests only: the advertised level a connection needs to receive or answer this
        # request, the validator a result must pass, and the connections the frame went to that have
        # not answered an error yet (identity list: transports are compared with ``is``).
        self.level = level
        self.validate = validate
        self.targets: list = []
        self.answered_by: Any = None
        # Gated requests that narrow their audience (``send_gated(target=...)``) and cap refused answers.
        self.target: Callable[[Any, Any], bool] | None = None
        self.max_refusals: int | None = None
        self.refusals = 0
        self.exhausted = False
        self.on_refusal: Callable[[Any, str, Any, bool], None] | None = None
        # Gated on the METHOD (``send_gated(level=None)``): a connection qualifies by having listed it under
        # ``client.capabilities {requests}`` instead of by a ``confirm`` level.
        self.method_gated = False
        # Method-gated only: the end of the park window (``time.monotonic()``): while the request has no target
        # (nobody reached yet, or every connection it reached is gone) it waits until then, and after it settles
        # ``unavailable (no_capable_client)``. None for every other request.
        self.park_until: float | None = None
        # Method-gated only: the park window's length (a shown request that loses its last target gets a fresh
        # one) and the answer deadline (``time.monotonic()``, None without one) that bounds every window.
        self.park_seconds = 0.0
        self.deadline: float | None = None
        # Method-gated only: the connections ``open_requests`` handed it to (a target that must survive a failed
        # push to the same connection: it has the request already).
        self.listed: list = []
        # Method-gated only: some connection was written or listed the request (a withdrawal then needs a cancel).
        self.shown = False
        # Who sent the turn this request was opened in (the in-flight record's ``author``, with ``via`` when an
        # agent sent it), read once now: an agent may answer only a request of its own turn.
        self.turn_author = _read_turn_author(sid)

    def frame(self) -> dict:
        return {"jsonrpc": "2.0", "id": self.id, "method": self.method,
                "params": {"session_id": self.sid, **self.params}}

    def snapshot(self) -> dict:
        """``open_requests`` entry: the request as sent, plus the batch answers locked so far so a
        reconnecting client restores its ✓ state."""
        params = {"session_id": self.sid, **self.params}
        if self.locked:
            params["answers"] = dict(self.locked)
        return {"id": self.id, "method": self.method, "params": params}


_lock = threading.Lock()
_open: dict[str, ServerRequest] = {}
#: The clock method-gated waits are measured on (park window, deadline). A seam: a test moves it and wakes the wait
#: through the request's event instead of sleeping.
_monotonic: Callable[[], float] = time.monotonic

# Frame sinks, bound by ``bind_sinks`` from server.py at import time (like the method_ctx split
# modules): importing server back from here would pick a different module object under the test
# fixtures that patch ``sys.modules`` around the server import.
_write: Callable[[dict], Any] = lambda frame: None  # noqa: E731
_emit: Callable[[str, str, dict], Any] = lambda event, sid, payload: None  # noqa: E731
# ``answerable(sid)``: False only when every client attached to the session is a build that never
# advertised handling server→client requests (session_transports.py::_session_client_answers_requests).
_answerable: Callable[[str], bool] = lambda sid: True  # noqa: E731
# ``access(sid, transport)``: whether that connection may settle (and see) requests of session *sid*
# (session_transports.py::_transport_may_access_session). Unbound (tests of this module alone): everyone.
_access: Callable[[str, Any], bool] = lambda sid, transport: True  # noqa: E731
# ``peers(sid)``: the client connections attached to the session right now (each one, not the fan-out
# that wraps them) — where a gated request may be written (session_transports.py::_session_client_peers).
_peers: Callable[[str], list] = lambda sid: []  # noqa: E731
# ``turn_author(sid)``: the ``author`` of the turn running in session *sid* (its in-flight record's
# ``display_metadata``), None when none runs or it names nobody (``server._inflight_turn_author``).
_turn_author: Callable[[str], dict | None] = lambda sid: None  # noqa: E731


def _identity_login(transport: Any) -> str | None:
    """``<provider>:<user id>`` of *transport*'s signed-in identity, None when it carries none (the unbound
    default of :data:`_transport_user`; server.py binds ``_transport_login``, the same login with its internal
    caller excluded). Pure: attribute reads and string work only."""
    identity = getattr(transport, "auth_identity", None)
    if not isinstance(identity, dict):
        return None
    provider, user_id = identity.get("provider"), identity.get("user_id")
    if not isinstance(provider, str) or not provider.strip() or not isinstance(user_id, str) or not user_id.strip():
        return None
    return f"{provider.strip()}:{user_id.strip()}"


# ``acting_user(sid) -> (login, ambiguous)``: the login session *sid*'s work is attributed to right now (None when
# the gateway cannot name one, ``server._acting_auth_user(session)[0]``) and whether that None is because more than
# one person could be behind the session (``_session_identity_is_ambiguous``) rather than because nobody is signed
# in at all (no auth provider: one trust domain). Read on the calling thread: it depends on the turn's context.
_acting_user: Callable[[str], tuple[str | None, bool]] = lambda sid: (None, False)  # noqa: E731
# ``transport_user(transport)``: the login a connection is signed in as (``server._transport_login``).
# Pure (no import, no object construction): it runs under ``_lock`` inside a target predicate.
_transport_user: Callable[[Any], str | None] = _identity_login


def _read_turn_author(sid: str) -> dict | None:
    try:
        author = _turn_author(sid)
    except Exception:  # noqa: BLE001 - unknown is "nobody's": an agent is then refused, a person unaffected
        logger.debug("server request: turn author of %s unreadable", sid, exc_info=True)
        return None
    return dict(author) if isinstance(author, dict) else None

# Client transports that sent ``client.capabilities {server_requests: true}`` (identity set: StdioTransport
# has __slots__ and cannot be weak-referenced; ws.py forgets a peer on disconnect).
_answering_clients: set = set()
# The ``confirm`` levels each answering transport advertised (``client.capabilities {confirm: [...]}``).
_confirm_levels: dict[Any, frozenset[str]] = {}
# What a transport advertised WITH a level that needs more than its name (``passkey``: ``{kind, rp_id}``,
# accepted by ``confirm_passkey.accept_advertisement``). Handed to a request's target predicate.
_confirm_details: dict[Any, dict[str, Any]] = {}
# Answering transports that advertised ``client.capabilities {confirm_fields: true}`` with at least one accepted
# level: the only ones a ``confirm`` with structured ``fields`` may go to (:func:`shows_confirm_fields_locked`).
_confirm_fields: set = set()
# The interactive request methods each answering transport advertised (``client.capabilities {requests: [...]}``,
# intersected with ``INTERACTIVE_METHODS``): what a method-gated request (``send_gated(level=None)``) needs.
_handled: dict[Any, frozenset[str]] = {}

#: The ``confirm`` levels a CLIENT may advertise; anything else it lists is ignored. Kept equal to the
#: advertisable levels in ``tui_gateway/confirm.py::LEVELS`` (a test pins that).
CONFIRM_LEVELS = ("plain", "passkey")
#: Levels accepted only together with a detail the caller of :func:`advertise` already checked (``passkey``:
#: a signed-in connection with an accepted RP, see ``methods_voice.py`` ``client.capabilities``).
DETAILED_LEVELS = frozenset({"passkey"})


def bind_sinks(write_json: Callable[[dict], Any], emit: Callable[[str, str, dict], Any],
               answerable: Callable[[str], bool], peers: Callable[[str], list] | None = None,
               access: Callable[[str, Any], bool] | None = None,
               turn_author: Callable[[str], dict | None] | None = None,
               acting_user: Callable[[str], tuple[str | None, bool]] | None = None,
               transport_user: Callable[[Any], str | None] | None = None) -> None:
    global _write, _emit, _answerable, _peers, _access, _turn_author, _acting_user, _transport_user
    _write, _emit, _answerable = write_json, emit, answerable
    if peers is not None:
        _peers = peers
    if access is not None:
        _access = access
    if turn_author is not None:
        _turn_author = turn_author
    if acting_user is not None:
        _acting_user = acting_user
    if transport_user is not None:
        _transport_user = transport_user


def _caller() -> Any:
    """The connection the current RPC or response frame arrived on (``rpc_dispatch`` binds it); None outside one."""
    from tui_gateway.transport import current_transport
    return current_transport()


def advertise(transport: Any, server_requests: bool, confirm: Any = None,
              details: dict[str, Any] | None = None, requests: Any = None, confirm_fields: Any = None) -> list[str]:
    """Record whether *transport*'s client answers server→client requests (``client.capabilities``), which
    ``confirm`` levels it can perform, whether it shows a ``confirm``'s structured fields (*confirm_fields*:
    exactly ``True``, and only with an accepted level), and which interactive request methods it can show
    (*requests*). Levels and methods count only together with ``server_requests``; unknown or malformed entries
    are dropped, and a level in :data:`DETAILED_LEVELS` counts only with an entry in *details* (already checked
    by the caller).
    Methods count only when they are in ``INTERACTIVE_METHODS`` and never for an agent's connection (an agent
    acting through MCP answers no interactive request). Every call replaces the previous advertisement (a call
    without *requests* clears the methods). Returns the levels accepted (sorted); :func:`handled_methods`
    reads the methods accepted."""
    details = details or {}
    levels = frozenset(level for level in (confirm if isinstance(confirm, (list, tuple)) else ())
                       if isinstance(level, str) and level in CONFIRM_LEVELS
                       and (level not in DETAILED_LEVELS or details.get(level) is not None)
                       ) if server_requests else frozenset()
    kept = {level: details[level] for level in levels if level in DETAILED_LEVELS}
    methods = frozenset(method for method in (requests if isinstance(requests, (list, tuple)) else ())
                        if isinstance(method, str) and method in INTERACTIVE_METHODS
                        ) if server_requests and _agent_identity(transport) is None else frozenset()
    with _lock:
        dropped = _handled.get(transport, frozenset()) - methods
        if methods:
            _handled[transport] = methods
        else:
            _handled.pop(transport, None)
        # A method it no longer lists takes it out of those requests, as a disconnect would (forget).
        for req in list(_open.values()):
            if req.method_gated and req.method in dropped:
                _drop_target_locked(req, transport)
        if server_requests:
            _answering_clients.add(transport)
        else:
            _answering_clients.discard(transport)
        if levels:
            _confirm_levels[transport] = levels
        else:
            _confirm_levels.pop(transport, None)
        if kept:
            _confirm_details[transport] = kept
        else:
            _confirm_details.pop(transport, None)
        if levels and confirm_fields is True:
            _confirm_fields.add(transport)
        else:
            _confirm_fields.discard(transport)
    return sorted(levels)


def forget(transport: Any) -> None:
    """Drop a disconnected transport's advertisement, and take it out of every open method-gated request it was
    a target of (:func:`_drop_target_locked`: a request left with no target parks again or ends ``unavailable
    (no_capable_client)``). Level-gated requests (``confirm``) keep their targets as they always did."""
    with _lock:
        _answering_clients.discard(transport)
        _confirm_levels.pop(transport, None)
        _confirm_details.pop(transport, None)
        _confirm_fields.discard(transport)
        _handled.pop(transport, None)
        for req in list(_open.values()):
            if req.method_gated:
                _drop_target_locked(req, transport)


def _drop_target_locked(req: ServerRequest, transport: Any) -> bool:
    """Caller holds ``_lock``. Take the connection *transport* out of the method-gated *req*'s targets (it is
    gone, stopped advertising the method, or the frame could not be written to it). When that leaves *req* with
    no target, wake its waiter: it parks until ``park_until`` and then settles ``unavailable
    (no_capable_client)``. A request that was SHOWN somewhere first gets a fresh window from now,
    ``park_until = max(park_until, min(deadline, now + park_seconds))``: the person who saw it on a phone that
    went to the background may come back to it, and the whole wait stays within the request's ``timeout``. A
    request nobody saw keeps the window it opened with. True when *transport* was a target. ``Event.set`` and
    the clock are the only calls made here: no I/O, no callback."""
    if not any(peer is transport for peer in req.targets):
        return False
    req.targets = [peer for peer in req.targets if peer is not transport]
    req.listed = [peer for peer in req.listed if peer is not transport]
    if not req.targets:
        if req.shown and req.park_until is not None:
            fresh = _monotonic() + req.park_seconds
            if req.deadline is not None:
                fresh = min(req.deadline, fresh)
            req.park_until = max(req.park_until, fresh)
        req.event.set()
    return True


def answers_requests(transport: Any) -> bool:
    with _lock:
        return transport in _answering_clients


def confirm_levels(transport: Any) -> frozenset[str]:
    """The ``confirm`` levels *transport* advertised (empty when none, or when it is not an answering client)."""
    with _lock:
        return _confirm_levels.get(transport, frozenset()) if transport in _answering_clients else frozenset()


def shows_confirm_fields(transport: Any) -> bool:
    """Whether *transport* advertised ``confirm_fields: true`` and it was accepted (what ``client.capabilities``
    echoes)."""
    with _lock:
        return transport in _confirm_fields and transport in _answering_clients


def shows_confirm_fields_locked(transport: Any) -> bool:
    """Caller holds ``_lock`` (a target predicate): :func:`shows_confirm_fields` without taking it. Pure."""
    return transport in _confirm_fields and transport in _answering_clients


def confirm_fields_target(transport: Any, detail: Any) -> bool:
    """``send_gated``'s target predicate for a ``plain`` ``confirm`` with ``fields``: the connection shows
    them. Runs under ``_lock``."""
    return shows_confirm_fields_locked(transport)


def handled_methods(transport: Any) -> list[str]:
    """The interactive request methods *transport* advertised and this gateway accepted (sorted; empty when
    none, or when it is not an answering client): what ``client.capabilities`` echoes as ``requests``."""
    with _lock:
        return sorted(_handled.get(transport, frozenset())) if transport in _answering_clients else []


def _gated(req: ServerRequest) -> bool:
    """*req* goes only to, and is answered only by, qualifying connections (a ``confirm`` level or a method)."""
    return req.level is not None or req.method_gated


def _qualifies(req: ServerRequest, transport: Any) -> bool:
    """Caller holds ``_lock``. *transport* advertised *req*'s level (or, method-gated, its method) and passes its
    target predicate (attachment is checked by the caller). The predicate runs under ``_lock``: it must be pure
    and must not call back here. An agent's connection never qualifies for a method-gated request."""
    if req.method_gated:
        return (transport is not None and transport in _answering_clients
                and req.method in _handled.get(transport, frozenset())
                and _agent_identity(transport) is None
                and (req.target is None or bool(req.target(transport, None))))
    return (transport is not None and transport in _answering_clients
            and req.level in _confirm_levels.get(transport, frozenset())
            and (req.target is None or bool(req.target(transport, _confirm_details.get(transport, {}).get(req.level)))))


def _may_answer(req: ServerRequest, transport: Any) -> bool:
    """Caller holds ``_lock``. Ungated requests: a connection that may act on the session (``_access``).
    Gated: only a connection attached to the request's session RIGHT NOW (a peer of its slot) that advertised
    the request's level and passes its target predicate — never one that merely knows the session id or
    attached to it in the past. A reconnecting client gets a gated request back after it reattaches
    (``session.resume`` / ``activate``) and advertises the level again."""
    if not _access(req.sid, transport):
        return False
    if not _gated(req):
        return True
    return _qualifies(req, transport) and any(peer is transport for peer in _peers(req.sid))


#: Method prefixes whose requests need a NAMED acting person when more than one could be behind the session:
#: approving a draft is consent given in somebody's name, a signature is a statement signed in somebody's name, and a
#: ``device.*`` request asks for something personal (where they are, one of their contacts, their calendar, what
#: their camera sees). ``input.*`` otherwise goes to every capable connection then (the result names who answered).
STRICT_ACTING_USER_PREFIXES = ("review.", "device.", "input.signature")
#: ``RequestOutcome.reason`` of a request :func:`send_gated` refused because nobody may answer it for the acting
#: person: the session is shared and the turn names nobody, or the acting login could not be read.
NO_ACTING_USER = "no_acting_user"


class ActingUserTarget:
    """A target predicate "signed in as *login*" (everyone when *login* is None). ``refusal`` is set when no
    connection may answer at all; :func:`send_gated` then returns ``unavailable`` with it as the reason, writing
    and opening nothing. Calling it is pure (an identity read and a string compare): it runs under ``_lock``."""

    __slots__ = ("login", "refusal", "_transport_user")

    def __init__(self, login: str | None, refusal: str | None, transport_user: Callable[[Any], str | None]) -> None:
        self.login, self.refusal, self._transport_user = login, refusal, transport_user

    def __call__(self, transport: Any, detail: Any) -> bool:
        if self.refusal is not None:
            return False
        if self.login is None:
            return True
        try:
            return self._transport_user(transport) == self.login
        except Exception:  # noqa: BLE001 - fail closed, never raise under the module lock
            return False


def acting_user_target(sid: str, method: str) -> ActingUserTarget:
    """The target predicate "signed in as the login session *sid*'s work is attributed to RIGHT NOW"
    (``server._acting_auth_user``) for a *method* request, for ``send_gated(target=...)``.

    The login is resolved HERE, once: ``_acting_auth_user`` reads a ContextVar (the turn's submitter), so call
    this on the turn's (or the request's) own thread, or inside a ``contextvars.copy_context()`` of it — never
    on a fresh thread. The returned predicate only compares against that login. When the gateway cannot name
    the acting person:

    - no auth provider (one trust domain): every capable connection qualifies, as for ``confirm`` at ``plain``;
    - a shared session whose turn names nobody (``_session_identity_is_ambiguous``): every capable connection
      for ``input.*`` (the result names who answered), NOBODY for ``review.*``, ``device.*`` and ``input.signature``
      (:data:`STRICT_ACTING_USER_PREFIXES`; ``refusal`` :data:`NO_ACTING_USER`);
    - reading it fails: nobody, ``refusal`` :data:`NO_ACTING_USER` (a request for the wrong person is worse
      than none)."""
    try:
        login, ambiguous = _acting_user(sid)
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("server request: acting user of %s unresolved; no connection qualifies", sid, exc_info=True)
        return ActingUserTarget(None, NO_ACTING_USER, _transport_user)
    if login:
        return ActingUserTarget(str(login), None, _transport_user)
    if ambiguous and method.startswith(STRICT_ACTING_USER_PREFIXES):
        return ActingUserTarget(None, NO_ACTING_USER, _transport_user)
    return ActingUserTarget(None, None, _transport_user)


#: The server requests an agent acting through MCP may answer: a clarify answer is words, the capability a
#: prompt already is, and is marked as the agent's. An approval is consent to run something, and a sudo,
#: secret or vault prompt is the person's own: those go to the person's app.
AGENT_ANSWERABLE = frozenset({"clarify"})


def _agent_identity(transport: Any) -> dict | None:
    """``transport``'s identity when it is an agent's (it carries ``agent`` at all, whatever its shape), else None."""
    identity = getattr(transport, "auth_identity", None)
    return identity if isinstance(identity, dict) and identity.get("agent") is not None else None


def _agent_clarify_allowed() -> bool:
    """``dashboard.mcp.answer_clarify`` (default true) in the GATEWAY's config (``passkeys.paths.gateway_scope``):
    the MCP grants are the dashboard's, so a session scoped to a profile this gateway serves must not read the
    profile's file, where the operator's ``false`` is absent. An unreadable config refuses: the operator may
    have turned it off, and a refused clarify only waits for the person's own app."""
    try:
        from hermes_cli.config import load_config
        from hermes_cli.dashboard_auth.mcp.settings import from_config
        from hermes_cli.dashboard_auth.passkeys.paths import gateway_scope
        with gateway_scope():
            return bool(from_config(load_config()).answer_clarify)
    except Exception:  # noqa: BLE001 - refuse rather than guess
        logger.warning("dashboard.mcp.answer_clarify unreadable; refusing clarify answers from agents", exc_info=True)
        return False


def agent_answer_refusal(method: str, transport: Any) -> tuple[int, str] | None:
    """Why ``transport`` may not answer a ``method`` request because it is an agent, as ``(4033, message)``;
    None when it is not an agent, or may (``clarify``, unless the operator turned that off)."""
    if _agent_identity(transport) is None:
        return None
    if method not in AGENT_ANSWERABLE:
        return 4033, (f"an agent connected through MCP cannot answer {method} requests; "
                      "they are answered in the person's own app")
    if not _agent_clarify_allowed():
        return 4033, "answering clarify questions through MCP is turned off on this gateway"
    return None


def agent_turn_refusal(turn_author: Any, transport: Any) -> tuple[int, str] | None:
    """Why the agent ``transport`` may not answer a request of the turn *turn_author* sent: (4033, message) unless
    that turn was sent by this connection's person through this agent (``author.id`` and ``via``). None for a
    connection that is not an agent's. A turn the person sent in her app, or another person's, is theirs to
    answer."""
    identity = _agent_identity(transport)
    if identity is None:
        return None
    from tui_gateway.row_author import AGENT_KIND, UNNAMED_AGENT, agent_from_row_author, agent_marker

    login = (f"{str(identity.get('provider') or '').strip()}:{str(identity.get('user_id') or '').strip()}"
             if identity.get("provider") and identity.get("user_id") else None)
    marker = agent_marker(identity.get("agent")) or {"kind": AGENT_KIND, "client": UNNAMED_AGENT}
    if (isinstance(turn_author, dict) and login is not None and turn_author.get("id") == login
            and agent_from_row_author(turn_author) == marker):
        return None
    return 4033, ("an agent connected through MCP answers only the questions of a turn it sent; this one belongs "
                  "to a turn somebody else sent")


#: Why an agent's answer to an already-locked batch question is refused (4034).
LOCKED_MESSAGE = "a question the person already answered cannot be answered again"


def _overwrites_locked(req: ServerRequest, result: Any) -> bool:
    """Caller holds ``_lock``. *result* answers a question of the batch *req* that is already locked."""
    answers = result.get("answers") if isinstance(result, dict) else None
    return bool(req.qids) and isinstance(answers, dict) and any(qid in req.locked for qid in answers)


def _agent_request_refusal_locked(req: ServerRequest, result: Any, transport: Any) -> tuple[int, str, str] | None:
    """Caller holds ``_lock``. ``(code, message, audit reason)`` when the agent *transport* may not settle *req*
    with *result*: not its turn's request, or an answer over a locked question."""
    if (refusal := agent_turn_refusal(req.turn_author, transport)) is not None:
        return (*refusal, "not_agents_turn")
    if _overwrites_locked(req, result):
        return 4034, LOCKED_MESSAGE, "locked"
    return None


def agent_request_refusal(request_id: str, result: Any, transport: Any) -> tuple[int, str] | None:
    """:func:`agent_turn_refusal` and the locked-question rule for the open request *request_id*, with the audit
    line of a refusal; None when it may (or *transport* is not an agent's, or the request is not open here)."""
    if _agent_identity(transport) is None:
        return None
    with _lock:
        req = _open.get(request_id)
        refusal = _agent_request_refusal_locked(req, result, transport) if req is not None else None
        sid, method = (req.sid, req.method) if req is not None else ("", "")
    if refusal is None:
        return None
    audit_agent_answer(transport, sid=sid, request_id=request_id, method=method, outcome="refused", reason=refusal[2])
    return refusal[0], refusal[1]


class AgentLockRefused(ValueError):
    """:func:`lock_answer` refused an agent's lock (:func:`agent_turn_refusal`, or a question already locked)."""

    def __init__(self, code: int, message: str, reason: str) -> None:
        super().__init__(message)
        self.code, self.message, self.reason = code, message, reason


def _agent_answer_prefix(transport: Any) -> str:
    """``[Answered by the agent «<client>» through MCP, not by «<person>»] ``. Both names are cleaned and
    quoted like the turn note's values."""
    from agent.turn_sender import person_label
    from tui_gateway.row_author import UNNAMED_AGENT, agent_marker

    identity = _agent_identity(transport) or {}
    client = (agent_marker(identity.get("agent")) or {}).get("client") or UNNAMED_AGENT
    login = (f"{str(identity.get('provider') or '').strip()}:{str(identity.get('user_id') or '').strip()}"
             if identity.get("provider") and identity.get("user_id") else "")
    person = person_label(login, identity.get("user_name")) or "the person"
    return f"[Answered by the agent «{client}» through MCP, not by {person}] "


def mark_agent_answer(method: str, result: Any, transport: Any) -> Any:
    """``result`` with every non-empty clarify answer prefixed as the agent's (:func:`_agent_answer_prefix`)
    when ``transport`` is an agent; unchanged otherwise. An empty answer stays a skip. After the prefix, text
    shaped like the gateway note is relabelled (``relabel_note_lookalikes``, HERM-239), as any user text is:
    an agent's answer must not pass for a note the gateway wrote."""
    if method not in AGENT_ANSWERABLE or _agent_identity(transport) is None or not isinstance(result, dict):
        return result
    from agent.turn_sender import relabel_note_lookalikes

    prefix = _agent_answer_prefix(transport)
    out = dict(result)
    if isinstance(out.get("answer"), str) and out["answer"]:
        out["answer"] = prefix + relabel_note_lookalikes(out["answer"])
    if isinstance(out.get("answers"), dict):
        out["answers"] = {qid: prefix + relabel_note_lookalikes(answer) if isinstance(answer, str) and answer
                          else answer for qid, answer in out["answers"].items()}
    return out


def mark_agent_answer_text(answer: str, transport: Any) -> str:
    """One clarify answer (a ``clarify.lock``) marked as :func:`mark_agent_answer` marks a result."""
    return mark_agent_answer("clarify", {"answer": answer}, transport)["answer"]


def audit_agent_answer(transport: Any, *, sid: str, request_id: str, method: str, outcome: str,
                       reason: str = "") -> None:
    """One audit line for an answer from an agent's connection; nothing for anyone else. Never the answer."""
    identity = _agent_identity(transport)
    if identity is None:
        return
    try:
        from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
        from tui_gateway.row_author import agent_marker

        agent = identity.get("agent")
        audit_log(AuditEvent.MCP_REQUEST_ANSWERED if outcome == "answered" else AuditEvent.MCP_REQUEST_ANSWER_REFUSED,
                  user_id=f"{identity.get('provider') or ''}:{identity.get('user_id') or ''}",
                  grant_id=str(agent.get("grant") or "") if isinstance(agent, dict) else "",
                  client_name=(agent_marker(agent) or {}).get("client", ""), session=sid,
                  request_id=request_id, method=method, outcome=outcome, reason=reason)
    except Exception:  # noqa: BLE001 - an audit line must not fail the answer path
        logger.debug("server request %s: agent answer audit failed", request_id, exc_info=True)


def request_method(request_id: str) -> str | None:
    """The method of the open request ``request_id`` (None when it is not open here)."""
    with _lock:
        req = _open.get(request_id)
        return req.method if req is not None else None


def _unanswerable(method: str, sid: str) -> bool:
    if _answerable(sid):
        return False
    logger.info("server request %s for %s not sent: the attached client predates server→client requests "
                "(update the Hermes app)", method, sid)
    return True


def _emit_cancel(req: ServerRequest, reason: str) -> None:
    _emit("request.cancel", req.sid, {"id": req.id, "method": req.method, "reason": reason})


def withdraw_settled(sid: str, request_id: str, method: str, reason: str) -> None:
    """``request.cancel`` for a request that already SETTLED here but whose owner then rejected the answer
    (``confirm`` at level ``passkey``: the store refused the commit). The clients were told ``ok`` /
    ``resolved``; this tells them the answer did not count, so none keeps showing it as accepted. Like every
    ``request.cancel`` it goes to the session's clients and carries only the id, the method and the reason."""
    _emit("request.cancel", sid, {"id": request_id, "method": method, "reason": reason})


def _contract(method: str):
    from tui_gateway.contracts import registry as contracts

    contract = contracts.SERVER_REQUESTS.get(method)
    if contract is None:
        raise RuntimeError(f"server request {method!r} has no contract in tui_gateway/contracts")
    return contract


def _register(req: ServerRequest) -> int:
    """Validate and write the frame; the number of connections it went to (0 when the write failed, e.g. nobody
    is attached: the request stays open for the reconnect replay). The session's own fan-out takes the frame, so
    this counts the clients attached to it, not individual writes."""
    from tui_gateway.contracts import registry as contracts

    contract = _contract(req.method)
    _, problem = contracts.validate_params(contract, {"session_id": req.sid, **req.params})
    if problem is not None:
        raise ValueError(problem)  # a key the renderer's typed handler would never read: our bug
    with _lock:
        _open[req.id] = req
    written = _write(req.frame())
    return 0 if written is False else max(1, len(_peers(req.sid)))


def send(method: str, sid: str, params: dict, *, timeout: float | None,
         qids: list[str] | None = None) -> dict | None:
    """Send one request and block for the response ``result`` (a dict).

    Returns ``None`` when the renderer never answered (timeout, cancel, or an error response — e.g.
    a client without a handler for ``method``). ``timeout`` semantics: None → wait until answered or
    cancelled, 0 → return immediately, > 0 → bounded wait. A batch (``qids``) that times out
    returns ``{"answers": <locked so far>, "timed_out": True}`` instead of None.

    :func:`send_detailed` is the same wait with the reasons kept apart.
    """
    outcome = send_detailed(method, sid, params, timeout=timeout, qids=qids)
    if outcome.status == "answered" or (outcome.status == "timeout" and qids is not None):
        return outcome.result
    return None


def send_detailed(method: str, sid: str, params: dict, *, timeout: float | None,
                  qids: list[str] | None = None) -> RequestOutcome:
    """:func:`send`, reporting HOW the wait ended (:class:`RequestOutcome`) instead of folding every
    unanswered end into ``None``: ``unavailable`` (no attached client answers server→client requests, or the
    client answered an error such as -32601) is not ``cancelled`` and not ``timeout``, and none of them is
    the person skipping or declining (that is an ``answered`` result with an empty value)."""
    if _unanswerable(method, sid):
        return RequestOutcome("unavailable", None, "no_answering_client")
    req = ServerRequest(sid, method, params, qids=qids)
    reached = _register(req)
    tracked = None
    if request_hooks.covers(method):
        # ``pre_server_request`` / ``post_server_request`` (``request_hooks``): a plugin push for a question or
        # secure input. Off this thread, never the text, never able to change what the wait returns.
        tracked = request_hooks.opened(method, sid, req.id, reached=reached,
                                       expires_at=None if timeout is None else int(time.time() + timeout))
    try:
        outcome = _await(req, timeout)
    except BaseException:
        if tracked is not None:
            tracked.settled("interrupted")
        raise
    if tracked is not None:
        tracked.settled(request_hooks.settle_reason(outcome))
    return outcome


def _await(req: ServerRequest, timeout: float | None, deadline: float | None = None) -> RequestOutcome:
    """Block until *req* settles or *timeout* passes; withdraw it on timeout (``request.cancel``). A method-gated
    request waits by :func:`_await_method_gated` instead, against *deadline* (``time.monotonic()``)."""
    try:
        if req.park_until is not None:
            if (outcome := _await_method_gated(req, deadline)) is not None:
                return outcome
        else:
            req.event.wait(timeout)
    except BaseException:
        # The wait itself died (KeyboardInterrupt, SystemExit, injected error): withdraw the request
        # or it stays in _open forever — replayed to every reconnecting client and reported by
        # pending_kind() as a human still being waited on.
        with _lock:
            still_open = _open.pop(req.id, None) is req
        if still_open:
            _emit_cancel(req, "interrupted")
        raise
    with _lock:
        # The verdict is the state committed under the lock, never wait()'s return value: a
        # response frame can land after the deadline expires and before this removal, and
        # settlement (resolve_response / lock_answer / cancel) already popped it (#112548).
        timed_out = _open.pop(req.id, None) is req
        answered, result, locked = req.answered, req.result, dict(req.locked)
        errored, cancel_reason = req.errored, req.cancel_reason
    if answered:
        return RequestOutcome("answered", result, "", req.id, req.answered_by)
    if req.exhausted:
        return RequestOutcome("unavailable", None, "too_many_attempts", req.id)
    if timed_out:
        _emit_cancel(req, "timeout")
        return RequestOutcome("timeout", {"answers": locked, "timed_out": True} if req.qids is not None else None,
                              "timeout", req.id)
    if errored:
        return RequestOutcome("unavailable", None, "error_response", req.id, error_reason=req.error_reason)
    return RequestOutcome("cancelled", None, cancel_reason or "cancelled", req.id)


def _await_method_gated(req: ServerRequest, deadline: float | None) -> RequestOutcome | None:
    """The wait of a method-gated request, one rule throughout: while it has a target (a live connection it was
    written or listed to) it waits for *deadline*; while it has none (nobody reached yet, or every connection it
    reached is gone: a failed write, a disconnect) it waits for ``req.park_until``, and once that has passed it
    settles ``unavailable (no_capable_client)``. ``request.cancel {reason: timeout}`` goes out then only when some
    connection was ever shown the request (``req.shown``); a request nobody saw ends silently.

    Returns that outcome, or None when the request settled otherwise or *deadline* passed with a target (the
    caller's verdict reads which). Every decision is taken under ``_lock``; a lost last target wakes this wait
    through ``req.event`` (:func:`_drop_target_locked`), which is cleared under the lock only while the request is
    still open, so a settlement (which always removes the request before setting the event) is never missed."""
    while True:
        with _lock:
            now = _monotonic()  # read under the lock: a test that moves the clock wakes the wait under it too
            if _open.get(req.id) is not req:
                return None
            if not req.targets:
                if now >= req.park_until:
                    _open.pop(req.id, None)
                    shown = req.shown
                    break
                wait: float | None = req.park_until - now
            elif deadline is None:
                wait = None
            elif now >= deadline:
                return None
            else:
                wait = deadline - now
            req.event.clear()
        req.event.wait(wait)
    if shown:
        _emit_cancel(req, "timeout")
    return RequestOutcome("unavailable", None, "no_capable_client", req.id)


def send_gated(method: str, sid: str, params: dict, *, level: str | None = None, methods_gate: bool = True,
               timeout: float | None, validate: Callable[[dict], str | None],
               on_open: Callable[[str, int], None] | None = None,
               target: Callable[[Any, Any], bool] | None = None, request_id: str | None = None,
               max_refusals: int | None = None,
               on_refusal: Callable[[Any, str, Any, bool], None] | None = None,
               park_seconds: float = 0) -> RequestOutcome:
    """Send *method* only to the connections attached to *sid* that advertised *level* (the ``confirm``
    levels) or, with ``level=None``, the METHOD itself (``client.capabilities {requests}``, the interactive
    requests; ``methods_gate`` must then be True: a gated request needs a gate), and wait like
    :func:`send_detailed`.

    ``unavailable`` at once, with nothing written and nothing left open, when no such connection is
    attached (``reason: no_capable_client``) or every write failed — unless the request is method-gated and
    ``park_seconds`` > 0: it is then PARKED (module docstring): registered open with no targets, ``on_open``
    runs with 0 reached, a later qualifying connection gets it through :func:`open_requests` or
    :func:`deliver_late`, and with no target at the end of the park window it settles ``unavailable
    (no_capable_client)``. A *target* with a ``refusal`` (:func:`acting_user_target`) settles ``unavailable``
    with that reason at once. A method-gated request covered by ``request_hooks`` fires ``pre_server_request``
    exactly once (``reached``: 0 when parked; ``expires_at``: the park deadline while nobody is reached, else
    the answer deadline) and ``post_server_request`` itself; a level-gated one leaves its hooks to the caller
    (``confirm``). If ``on_open`` raises, the request is withdrawn before the error propagates. ``params`` are
    validated against the
    request's contract in full (not only unknown keys): a gated request is built by the gateway, so a
    violation is our bug and raises ``ValueError``. ``validate(result)`` returns a problem string for an
    answer that must not settle the request (the request stays open for a valid one). A valid answer
    withdraws the request from every other connection (``request.cancel {reason: resolved}``).
    ``on_open(request_id, connections_reached)`` runs once the frame is out (the audit line).

    Narrowing (``confirm`` at level ``passkey``): ``target(transport, detail)`` must also hold for a
    connection to get the frame, answer, or see the request in ``open_requests`` (it runs under the module
    lock: pure, fast, no calls back into this module). ``request_id`` fixes the frame's id
    (:func:`new_request_id`). ``max_refusals``: the answer refused that many times by ``validate`` (from
    connections allowed to answer; 4033s, errors and accepted answers do not count) settles the request
    ``unavailable (too_many_attempts)`` and withdraws it everywhere (``request.cancel {reason:
    too_many_attempts}``). ``on_refusal(transport, reason, result, exhausted)`` runs outside the lock for every
    counted refusal (the audit line); ``reason`` is ``validate``'s problem.

    Delivery notes. The frame is written to each target's own transport, NOT through the session's
    fan-out mailbox, so it may overtake events already queued for that connection; that is harmless for a
    request, which a client keys by id. A connection that was not attached when the frame went out never
    gets it pushed: it sees the request only through ``open_requests`` once it has reattached
    (``session.resume`` / ``activate``) and advertised the level (the second ``client.capabilities``). A
    method-gated request is also pushed to a connection that advertises the method while attached
    (:func:`deliver_late`), and a connection it reaches late becomes one of its targets.
    ``request.cancel`` goes through ``_emit`` to EVERY client of the session, including ones that never
    received the request; it carries only the id, the method and the reason."""
    from pydantic import ValidationError

    contract = _contract(method)
    try:
        contract.params.model_validate({"session_id": sid, **params})
    except ValidationError as exc:
        raise ValueError(f"invalid {method} params: {exc}") from exc
    if level is None:
        if not methods_gate:
            raise ValueError("send_gated needs a gate: a level, or methods_gate")
        if method not in INTERACTIVE_METHODS:
            raise ValueError(f"{method!r} is not an interactive request method; only those are method-gated")
    elif level not in CONFIRM_LEVELS:
        raise ValueError(f"unknown level {level!r}")
    if getattr(target, "refusal", None) is not None:
        # ``acting_user_target``: nobody may answer it for the acting person; nothing is written or opened.
        return RequestOutcome("unavailable", None, str(target.refusal))
    parkable = level is None and park_seconds > 0
    req = ServerRequest(sid, method, params, level=level, validate=validate, request_id=request_id)
    req.target, req.max_refusals, req.on_refusal = target, max_refusals, on_refusal
    req.method_gated = level is None
    started = _monotonic()
    deadline = None if timeout is None else started + timeout
    if req.method_gated:
        req.park_seconds = max(0.0, park_seconds)
        req.deadline = deadline
        req.park_until = started + (req.park_seconds if timeout is None else min(timeout, req.park_seconds))
    candidates = list(_peers(sid))
    with _lock:
        # Choice and registration are one step under the lock: a connection forgotten (disconnected, or no longer
        # advertising) after ``_peers`` listed it no longer qualifies here, so it is never kept as a target.
        targets = [peer for peer in candidates if _qualifies(req, peer)]
        if targets or parkable:
            req.targets = list(targets)
            _open[req.id] = req
    if not targets and not parkable:
        return RequestOutcome("unavailable", None, "no_capable_client")
    frame = req.frame()
    reached = []
    for peer in targets:
        try:
            if peer.write(frame) is not False:
                reached.append(peer)
        except Exception:
            logger.debug("server request %s: write to one client failed", req.id, exc_info=True)
    if targets:
        with _lock:
            failed = [peer for peer in targets if not any(peer is ok for ok in reached)]
            if req.method_gated:
                # One rule for every lost target (:func:`_await_method_gated`): none left parks it again.
                req.shown = req.shown or bool(reached)
                for peer in failed:
                    if not any(listed is peer for listed in req.listed):
                        _drop_target_locked(req, peer)
                write_failed = not parkable and not req.targets
            else:
                req.targets = [peer for peer in req.targets if any(peer is ok for ok in reached)]
                write_failed = not req.targets
            if write_failed and _open.get(req.id) is req and not req.answered:
                # Settled at once, never shown: no on_open, no hook, no cancel (as before parking existed).
                _open.pop(req.id, None)
                return RequestOutcome("unavailable", None, "write_failed", req.id)
    if req.method_gated and not reached:
        # A connection that attached (and listed its open requests) between the scan above and the registration
        # would otherwise miss the request until it reattaches: scan once more now that it is open.
        late_peers = list(_peers(sid))
        with _lock:
            late = [peer for peer in late_peers if _qualifies(req, peer) and _add_target_locked(req, peer)]
        reached = [peer for peer in late if _write_late([req], peer)]
    try:
        if on_open is not None:
            on_open(req.id, len(reached))
    except BaseException:
        # The owner could not record it (the audit line): it must not stay open with nobody waiting for it.
        with _lock:
            still_open = _open.pop(req.id, None) is req
            shown = req.shown or req.level is not None
        if still_open and shown:
            _emit_cancel(req, "interrupted")
        raise
    tracked = None
    if req.method_gated and request_hooks.covers(method):
        # ``expires_at``: when the gateway stops waiting if nothing else happens. A request that reached nobody
        # yet waits for a device until the park deadline; one that reached a device waits for the answer.
        with _lock:
            ends = req.park_until if not req.targets else deadline
        tracked = request_hooks.opened(method, sid, req.id, reached=len(reached),
                                       expires_at=None if ends is None else int(time.time() + ends - _monotonic()))
    try:
        outcome = _await(req, timeout, deadline)
    except BaseException:
        if tracked is not None:
            tracked.settled("interrupted")
        raise
    if tracked is not None:
        tracked.settled(request_hooks.settle_reason(outcome))
    if outcome.status == "answered":
        # The other connections still show the card: withdraw it there (the answering one ignores it).
        _emit_cancel(req, "resolved")
    elif req.exhausted:
        _emit_cancel(req, "too_many_attempts")
    return outcome


def send_async(method: str, sid: str, params: dict, on_result: Callable[[dict | None], None]) -> Callable[[str], None]:
    """Send one request whose wait is owned elsewhere (the approval queue's own timeout). ``on_result``
    runs on the dispatching thread when the response lands. Returns ``settle(reason)``: call it when
    the underlying wait ends; if the request is still open it is withdrawn with ``request.cancel``."""
    if _unanswerable(method, sid):
        on_result(None)
        return lambda reason: None
    req = ServerRequest(sid, method, params, on_result=on_result)
    _register(req)

    def settle(reason: str) -> None:
        with _lock:
            still_open = _open.pop(req.id, None) is not None
        if still_open:
            _emit_cancel(req, reason)

    return settle


def answer_problem(request_id: str, result: Any) -> tuple[int, str] | tuple[int, str, dict] | None:
    """Why the CALLING connection may not settle the open request *request_id* with *result*, as
    ``(code, message[, data])`` for a ``request.answer`` error; None when it may, or when *request_id* is not
    open here (the ordinary path decides). 4033: the connection may not act on the request's session, or
    (gated requests) is not attached to it, did not advertise the level or fails its target predicate; 4034:
    the result is not a valid answer for this gated request. A request with ``max_refusals`` counts the
    refusal here and answers ``(4034, "answer refused", {"reason": ...})``; the refusal that reaches the cap
    settles the request and its reason is ``too_many_attempts``. An agent's connection is refused 4033 for
    every method but ``clarify`` (:func:`agent_answer_refusal`)."""
    transport = _caller()
    if _agent_identity(transport) is not None and (method := request_method(request_id)) is not None:
        if (refusal := agent_answer_refusal(method, transport)) is not None:
            audit_agent_answer(transport, sid=request_session(request_id) or "", request_id=request_id,
                               method=method, outcome="refused", reason="agent")
            return refusal
        if (refusal := agent_request_refusal(request_id, result, transport)) is not None:
            return refusal
    with _lock:
        req = _open.get(request_id)
        if req is None:
            return None
        if not _may_answer(req, transport):
            if not _gated(req) or not _access(req.sid, transport):
                return 4033, "this connection may not answer requests of that session"
            return 4033, _not_qualified_message(req)
        if not _gated(req):
            return None
        validate = req.validate
    # Outside the lock: a validator may be slow (a signature check). It is pure, so the answer path that
    # settles the request (``resolve_response``) reaches the same verdict.
    problem = validate(result) if validate is not None and isinstance(result, dict) else (
        None if isinstance(result, dict) else "result must be an object")
    if not problem:
        return None
    if req.max_refusals is None:
        return 4034, problem
    with _lock:
        if _open.get(request_id) is not req:
            return None  # settled meanwhile: the ordinary path answers "expired"
        if not _may_answer(req, transport):
            return 4033, _not_qualified_message(req)
        exhausted = _count_refusal(req)
    _after_refusal(req, transport, problem, result, exhausted)
    return 4034, "answer refused", {"reason": "too_many_attempts" if exhausted else problem}


def _not_qualified_message(req: ServerRequest) -> str:
    """The 4033 message for a connection that may act on the session but not answer the gated *req*."""
    if req.level is None:
        return f"this connection is not attached or did not advertise {req.method} requests"
    return f"this connection is not attached or may not answer {req.method} level {req.level!r}"


def _count_refusal(req: ServerRequest) -> bool:
    """Caller holds ``_lock`` and *req* is open. Count one refused answer; True when that used up
    ``max_refusals`` (the request is then settled: removed, marked exhausted)."""
    req.refusals += 1
    if req.max_refusals is None or req.refusals < req.max_refusals:
        return False
    _open.pop(req.id, None)
    req.result, req.answered, req.exhausted = None, False, True
    return True


def _after_refusal(req: ServerRequest, transport: Any, problem: str, result: Any, exhausted: bool) -> None:
    """Outside the lock: tell the request's owner about a counted refusal, and wake the waiter when it settled."""
    if req.on_refusal is not None:
        try:
            req.on_refusal(transport, problem, result, exhausted)
        except Exception:
            logger.debug("server request %s: on_refusal failed", req.id, exc_info=True)
    if exhausted:
        req.event.set()


def request_session(request_id: str) -> str | None:
    """The session id an open request belongs to (None when it is not open here)."""
    with _lock:
        req = _open.get(request_id)
        return req.sid if req is not None else None


def _warm_validator(request_id: str, frame: dict) -> None:
    """Let the validator of the open request *request_id* load what its check needs (an interactive form's time
    zone file: ``interactive_validate._Validator.warm``) OUTSIDE the lock, before :func:`resolve_response` reaches
    its verdict under it. Only a validator with a ``warm`` method takes part; never raises."""
    if not isinstance(frame.get("result"), dict):
        return
    with _lock:
        req = _open.get(request_id)
        warm = getattr(req.validate, "warm", None) if req is not None else None
    if warm is None:
        return
    try:
        warm(frame["result"])
    except Exception:  # noqa: BLE001 - warming is an optimisation; the verdict under the lock decides
        logger.debug("server request %s: validator warm-up failed", request_id, exc_info=True)


def resolve_response(frame: dict) -> bool:
    """Route one client response frame to its open request. False when nothing is waiting for that id
    (already timed out / cancelled, or owned by another process — see the compute-host bridge)."""
    rid = frame.get("id")
    if not isinstance(rid, str):
        return False
    transport = _caller()
    exhausted = False
    agent_answer: tuple[str, str] | None = None
    agent_refused: tuple[int, str, str] | None = None
    if _agent_identity(transport) is not None and (method := request_method(rid)) is not None:
        # An agent: refused for every method but clarify (an error frame too -- it would settle an approval
        # as unanswered); a clarify answer is marked as the agent's before anything can read it. Returns
        # True for a refusal: the request IS here, so no other process may be handed the frame.
        sid = request_session(rid) or ""
        if (refusal := agent_answer_refusal(method, transport)) is not None:
            logger.warning("server request %s (%s): answer refused, an agent may not answer it", rid, method)
            audit_agent_answer(transport, sid=sid, request_id=rid, method=method, outcome="refused", reason="agent")
            return True
        if "result" in frame:
            frame = {**frame, "result": mark_agent_answer(method, frame.get("result"), transport)}
        agent_answer = (sid, method)
    _warm_validator(rid, frame)
    with _lock:
        req = _open.get(rid)
        if req is None:
            # Already settled (timed out, cancelled, answered from another surface) or owned by
            # another process; say so — a dropped answer used to vanish without a trace.
            logger.debug("server request %s: response dropped, request no longer open", rid)
            return False
        if not _access(req.sid, transport):
            logger.warning("server request %s (%s): response refused, the connection may not act on session %s",
                           rid, req.method, req.sid)
            return False
        if agent_answer is not None:
            # Checked here, under the lock that settles: the person may lock a question until this very moment.
            agent_refused = _agent_request_refusal_locked(req, frame.get("result"), transport)
        verdict, problem = ("refused", "") if agent_refused is not None else (
            _gated_verdict(req, frame) if _gated(req) else ("settle", ""))
        if verdict == "counted":
            exhausted = _count_refusal(req)
        elif verdict != "settle":
            if agent_refused is None:
                return verdict == "kept"
        else:
            # Removing the request and committing its outcome are one settlement.
            # ``cancel()`` also settles under this lock, so the first side to get
            # here wins instead of a later cancellation overwriting a response.
            _open.pop(rid, None)
            if "error" in frame:
                logger.debug("server request %s (%s) answered with error: %s", rid, req.method, frame.get("error"))
                req.result, req.answered, req.errored = None, False, True
                req.error_reason = _cannot_show_reason(frame.get("error"))
            else:
                result = frame.get("result")
                req.result = result if isinstance(result, dict) else {}
                if req.qids and "answers" in req.result:
                    # Batch clarify: answers locked early via clarify.lock belong to the final set even when
                    # the closing response only carries the tail the user answered last.
                    answers = req.result.get("answers")
                    merged = dict(req.locked)
                    if isinstance(answers, dict):
                        merged.update(answers)
                    req.result = {**req.result, "answers": merged}
                req.answered = True
                req.answered_by = transport
    if agent_refused is not None and agent_answer is not None:
        # The request stays open for the one whose turn it is; True: it is here, so no child is handed the frame.
        logger.warning("server request %s (%s): answer refused: %s", rid, agent_answer[1], agent_refused[2])
        audit_agent_answer(transport, sid=agent_answer[0], request_id=rid, method=agent_answer[1],
                           outcome="refused", reason=agent_refused[2])
        return True
    if verdict == "counted":
        # A bare response frame gets no reply; the refusal is still counted and reported to the owner.
        _after_refusal(req, transport, problem, frame.get("result"), exhausted)
        return exhausted
    if agent_answer is not None:
        audit_agent_answer(transport, sid=agent_answer[0], request_id=rid, method=agent_answer[1],
                           outcome="answered" if req.answered else "declined")
    if req.on_result is not None:
        req.on_result(req.result)
    req.event.set()
    return True


def _gated_verdict(req: ServerRequest, frame: dict) -> tuple[str, str]:
    """Caller holds ``_lock``. What *frame* does to the open gated *req*, with the validator's problem:
    ``settle`` it now, leave it open having taken the frame into account (``kept``), leave it open ignoring
    the frame (``refused``), or refuse it as an answer that counts toward ``max_refusals`` (``counted``).

    An error response from a connection the frame went to takes that connection out of the running and
    settles (as ``unavailable``) only when it was the last one; an error from any other connection is
    ignored. A result settles only from a connection allowed to answer (:func:`_may_answer`) and only when it
    passes ``req.validate``; a refused result leaves the request open for a valid answer and is logged."""
    transport = _caller()
    if "error" in frame:
        if not any(peer is transport for peer in req.targets):
            logger.debug("server request %s (%s): error from a connection it was not sent to, ignored",
                         req.id, req.method)
            return "refused", ""
        req.targets = [peer for peer in req.targets if peer is not transport]
        if req.targets:
            logger.info("server request %s (%s): one client answered an error, %d still asked",
                        req.id, req.method, len(req.targets))
            return "kept", ""
        return "settle", ""
    if not _may_answer(req, transport):
        logger.warning("server request %s (%s): answer refused, the connection may not answer it (level %r)",
                       req.id, req.method, req.level)
        return "refused", ""
    result = frame.get("result")
    # Runs under the module lock, also for ``confirm`` at level ``passkey`` (an ES256 check): acceptable only
    # because that validator is pure (no I/O, no logging), memoised per answer, and bounded (size checks first,
    # five refusals per request). Never add I/O to a validator.
    problem = req.validate(result) if req.validate is not None and isinstance(result, dict) else (
        None if isinstance(result, dict) else "result must be an object")
    if problem:
        logger.warning("server request %s (%s): answer refused: %s", req.id, req.method, problem)
        return ("counted" if req.max_refusals is not None else "refused"), problem
    return "settle", ""


def lock_answer(request_id: str, question_id: str, answer: str, *, agent: Any = None) -> list[str] | None:
    """Lock one batch-clarify answer (update-in-place). Returns the question ids still unanswered;
    the last lock resolves the request with the full ``{"answers"}`` set. ``None`` when no open
    batch has that id (expired or foreign); ``ValueError`` for an unknown question id. *agent*: the agent's
    connection locking it, held to :func:`agent_turn_refusal` and to a question nobody locked yet
    (:class:`AgentLockRefused`, checked under the same lock as the write)."""
    with _lock:
        req = _open.get(request_id)
        if req is None or req.qids is None:
            return None
        if question_id not in req.qids:
            raise ValueError(f"unknown question_id {question_id!r}")
        if agent is not None and _agent_identity(agent) is not None:
            refusal = _agent_request_refusal_locked(req, {"answers": {question_id: answer}}, agent)
            if refusal is not None:
                raise AgentLockRefused(*refusal)
        req.locked[question_id] = answer
        remaining = [qid for qid in req.qids if qid not in req.locked]
        if not remaining:
            req.result, req.answered = {"answers": dict(req.locked)}, True
            _open.pop(request_id, None)
    if not remaining:
        req.event.set()
    return remaining


def cancel(sid: str | None = None, reason: str = "interrupted") -> int:
    """Withdraw open requests — only *sid*'s (session.interrupt must not touch other sessions'), or
    every one when *sid* is None (shutdown). Blocked waits return None; queue-backed requests run
    ``on_result(None)`` so their owner can settle. Returns the number withdrawn."""
    with _lock:
        targets = [req for req in _open.values() if sid is None or req.sid == sid]
        for req in targets:
            _open.pop(req.id, None)
            req.result, req.answered, req.cancel_reason = None, False, reason
    for req in targets:
        if req.on_result is not None:
            req.on_result(None)
        req.event.set()
        _emit_cancel(req, reason)
    return len(targets)


def open_requests(sid: str) -> list[dict]:
    """Unanswered requests for *sid*, oldest first, when the calling connection may act on *sid* (else none).
    A gated request (``confirm``) is listed only to a calling connection that advertised its level: it could
    not answer it, and must not see it."""
    caller = _caller()
    if not _access(sid, caller):
        return []
    with _lock:
        reqs = sorted((req for req in _open.values() if req.sid == sid and _may_answer(req, caller)),
                      key=lambda r: r.created_at)
        for req in reqs:
            if req.method_gated:
                _add_target_locked(req, caller)
                if not any(peer is caller for peer in req.listed):
                    req.listed.append(caller)
                req.shown = True
    return [req.snapshot() for req in reqs]


def _add_target_locked(req: ServerRequest, transport: Any) -> bool:
    """Caller holds ``_lock`` and *transport* may answer *req*. A method-gated request delivered to *transport*
    after it opened (``open_requests``, :func:`deliver_late`) makes it a target: its error response then counts,
    and a parked request counts as reached. True when it was added (it was not a target yet). A level-gated
    request (``confirm``) is left as it always was: only the connections its frame went to are targets."""
    if not req.method_gated or any(peer is transport for peer in req.targets):
        return False
    req.targets.append(transport)
    return True


def deliver_late(transport: Any) -> int:
    """Write every open method-gated request *transport* may answer now but was never given (it advertised the
    method while already attached to the session, so the ``open_requests`` of its attach did not list it), and
    make it a target. Call it after :func:`advertise`. The frames are written outside the lock. Returns how many
    were delivered."""
    if transport is None:
        return 0
    with _lock:
        late = sorted((req for req in _open.values()
                       if req.method_gated and _may_answer(req, transport) and _add_target_locked(req, transport)),
                      key=lambda r: r.created_at)
    return _write_late(late, transport)


def _write_late(reqs: list[ServerRequest], transport: Any) -> int:
    """Outside the lock: write each of the method-gated *reqs* (already targets of *transport*) to *transport*.
    A write that fails takes *transport* out of that request's targets again (:func:`_drop_target_locked`),
    unless ``open_requests`` handed it the request meanwhile. Returns how many were written."""
    delivered = 0
    for req in reqs:
        try:
            ok = transport.write(req.frame()) is not False
        except Exception:  # noqa: BLE001 - treated as a failed write
            logger.debug("server request %s: late write failed", req.id, exc_info=True)
            ok = False
        with _lock:
            if ok:
                req.shown = True
            elif not any(peer is transport for peer in req.listed):
                _drop_target_locked(req, transport)
        delivered += ok
    return delivered


def open_request_count() -> int:
    """Unanswered server→client requests across every session: the process is waiting on a
    human (clarify, approval, sudo, secret, ...) and must not be treated as idle."""
    with _lock:
        return len(_open)


def pending_kind(sid: str) -> str:
    """Method of the oldest open request for *sid* ("" when none) — the session is waiting on a human."""
    with _lock:
        reqs = [req for req in _open.values() if req.sid == sid]
    return min(reqs, key=lambda r: r.created_at).method if reqs else ""


def is_response_frame(obj: Any) -> bool:
    """A client response: has an ``id`` and a ``result``/``error`` member but no ``method``."""
    return isinstance(obj, dict) and "method" not in obj and "id" in obj and ("result" in obj or "error" in obj)


def reset_for_tests() -> None:
    with _lock:
        _open.clear()
        _answering_clients.clear()
        _confirm_levels.clear()
        _confirm_details.clear()
        _confirm_fields.clear()
        _handled.clear()
