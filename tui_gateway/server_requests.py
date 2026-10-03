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
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Callable, NamedTuple

from tui_gateway import request_hooks

logger = logging.getLogger(__name__)


class RequestOutcome(NamedTuple):
    """How one server→client request ended.

    ``status``: ``answered`` (``result`` is the client's result object), ``unavailable`` (never sent
    because no attached client can answer it, or every client it went to answered a JSON-RPC error),
    ``timeout`` (the deadline passed; ``request.cancel {reason: timeout}`` went out; a batch clarify
    carries ``{"answers": <locked so far>, "timed_out": True}`` as ``result``) or ``cancelled``
    (withdrawn: interrupt, session close, shutdown; ``reason`` names which). ``request_id`` is the frame's id
    when one was minted; ``answered_by`` is the connection whose answer settled it (None when unknown or
    in-process)."""

    status: str
    result: dict | None = None
    reason: str = ""
    request_id: str = ""
    answered_by: Any = None


def new_request_id() -> str:
    """A fresh request id (``srq-<12 hex>``), for a caller that must know it before the frame goes out (the
    passkey challenge commits to it)."""
    return f"srq-{uuid.uuid4().hex[:12]}"


class ServerRequest:
    __slots__ = ("id", "sid", "method", "params", "event", "result", "answered", "created_at",
                 "qids", "locked", "on_result", "errored", "cancel_reason", "level", "validate", "targets",
                 "answered_by", "target", "max_refusals", "refusals", "exhausted", "on_refusal")

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

# Client transports that sent ``client.capabilities {server_requests: true}`` (identity set: StdioTransport
# has __slots__ and cannot be weak-referenced; ws.py forgets a peer on disconnect).
_answering_clients: set = set()
# The ``confirm`` levels each answering transport advertised (``client.capabilities {confirm: [...]}``).
_confirm_levels: dict[Any, frozenset[str]] = {}
# What a transport advertised WITH a level that needs more than its name (``passkey``: ``{kind, rp_id}``,
# accepted by ``confirm_passkey.accept_advertisement``). Handed to a request's target predicate.
_confirm_details: dict[Any, dict[str, Any]] = {}

#: The ``confirm`` levels a CLIENT may advertise; anything else it lists is ignored. Kept equal to the
#: advertisable levels in ``tui_gateway/confirm.py::LEVELS`` (a test pins that).
CONFIRM_LEVELS = ("plain", "passkey")
#: Levels accepted only together with a detail the caller of :func:`advertise` already checked (``passkey``:
#: a signed-in connection with an accepted RP, see ``methods_voice.py`` ``client.capabilities``).
DETAILED_LEVELS = frozenset({"passkey"})


def bind_sinks(write_json: Callable[[dict], Any], emit: Callable[[str, str, dict], Any],
               answerable: Callable[[str], bool], peers: Callable[[str], list] | None = None,
               access: Callable[[str, Any], bool] | None = None) -> None:
    global _write, _emit, _answerable, _peers, _access
    _write, _emit, _answerable = write_json, emit, answerable
    if peers is not None:
        _peers = peers
    if access is not None:
        _access = access


def _caller() -> Any:
    """The connection the current RPC or response frame arrived on (``rpc_dispatch`` binds it); None outside one."""
    from tui_gateway.transport import current_transport
    return current_transport()


def advertise(transport: Any, server_requests: bool, confirm: Any = None,
              details: dict[str, Any] | None = None) -> list[str]:
    """Record whether *transport*'s client answers server→client requests (``client.capabilities``), and
    which ``confirm`` levels it can perform. Levels count only together with ``server_requests``; unknown
    or malformed entries are dropped, and a level in :data:`DETAILED_LEVELS` counts only with an entry in
    *details* (already checked by the caller). Every call replaces the previous advertisement. Returns the
    levels accepted (sorted)."""
    details = details or {}
    levels = frozenset(level for level in (confirm if isinstance(confirm, (list, tuple)) else ())
                       if isinstance(level, str) and level in CONFIRM_LEVELS
                       and (level not in DETAILED_LEVELS or details.get(level) is not None)
                       ) if server_requests else frozenset()
    kept = {level: details[level] for level in levels if level in DETAILED_LEVELS}
    with _lock:
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
    return sorted(levels)


def forget(transport: Any) -> None:
    """Drop a disconnected transport's advertisement."""
    with _lock:
        _answering_clients.discard(transport)
        _confirm_levels.pop(transport, None)
        _confirm_details.pop(transport, None)


def answers_requests(transport: Any) -> bool:
    with _lock:
        return transport in _answering_clients


def confirm_levels(transport: Any) -> frozenset[str]:
    """The ``confirm`` levels *transport* advertised (empty when none, or when it is not an answering client)."""
    with _lock:
        return _confirm_levels.get(transport, frozenset()) if transport in _answering_clients else frozenset()


def _qualifies(req: ServerRequest, transport: Any) -> bool:
    """Caller holds ``_lock``. *transport* advertised *req*'s level and passes its target predicate (attachment
    is checked by the caller). The predicate runs under ``_lock``: it must be pure and must not call back here."""
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
    if req.level is None:
        return True
    return _qualifies(req, transport) and any(peer is transport for peer in _peers(req.sid))


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


def _await(req: ServerRequest, timeout: float | None) -> RequestOutcome:
    """Block until *req* settles or *timeout* passes; withdraw it on timeout (``request.cancel``)."""
    try:
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
        return RequestOutcome("unavailable", None, "error_response", req.id)
    return RequestOutcome("cancelled", None, cancel_reason or "cancelled", req.id)


def send_gated(method: str, sid: str, params: dict, *, level: str, timeout: float | None,
               validate: Callable[[dict], str | None],
               on_open: Callable[[str, int], None] | None = None,
               target: Callable[[Any, Any], bool] | None = None, request_id: str | None = None,
               max_refusals: int | None = None,
               on_refusal: Callable[[Any, str, Any, bool], None] | None = None) -> RequestOutcome:
    """Send *method* only to the connections attached to *sid* that advertised *level* (today: the
    ``confirm`` levels), and wait like :func:`send_detailed`.

    ``unavailable`` at once, with nothing written and nothing left open, when no such connection is
    attached (``reason: no_capable_client``) or every write failed. ``params`` are validated against the
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
    (``session.resume`` / ``activate``) and advertised the level (the second ``client.capabilities``).
    ``request.cancel`` goes through ``_emit`` to EVERY client of the session, including ones that never
    received the request; it carries only the id, the method and the reason."""
    from pydantic import ValidationError

    contract = _contract(method)
    try:
        contract.params.model_validate({"session_id": sid, **params})
    except ValidationError as exc:
        raise ValueError(f"invalid {method} params: {exc}") from exc
    if level not in CONFIRM_LEVELS:
        raise ValueError(f"unknown level {level!r}")
    req = ServerRequest(sid, method, params, level=level, validate=validate, request_id=request_id)
    req.target, req.max_refusals, req.on_refusal = target, max_refusals, on_refusal
    candidates = list(_peers(sid))
    with _lock:
        targets = [peer for peer in candidates if _qualifies(req, peer)]
    if not targets:
        return RequestOutcome("unavailable", None, "no_capable_client")
    req.targets = list(targets)
    with _lock:
        _open[req.id] = req
    frame = req.frame()
    reached = []
    for peer in targets:
        try:
            if peer.write(frame) is not False:
                reached.append(peer)
        except Exception:
            logger.debug("server request %s: write to one client failed", req.id, exc_info=True)
    with _lock:
        req.targets = [peer for peer in req.targets if any(peer is ok for ok in reached)]
        if not req.targets and _open.get(req.id) is req and not req.answered:
            _open.pop(req.id, None)
            return RequestOutcome("unavailable", None, "write_failed", req.id)
    if on_open is not None:
        on_open(req.id, len(reached))
    outcome = _await(req, timeout)
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
    settles the request and its reason is ``too_many_attempts``."""
    transport = _caller()
    with _lock:
        req = _open.get(request_id)
        if req is None:
            return None
        if not _may_answer(req, transport):
            if req.level is None or not _access(req.sid, transport):
                return 4033, "this connection may not answer requests of that session"
            return 4033, f"this connection is not attached or may not answer {req.method} level {req.level!r}"
        if req.level is None:
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
            return 4033, f"this connection is not attached or may not answer {req.method} level {req.level!r}"
        exhausted = _count_refusal(req)
    _after_refusal(req, transport, problem, result, exhausted)
    return 4034, "answer refused", {"reason": "too_many_attempts" if exhausted else problem}


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


def resolve_response(frame: dict) -> bool:
    """Route one client response frame to its open request. False when nothing is waiting for that id
    (already timed out / cancelled, or owned by another process — see the compute-host bridge)."""
    rid = frame.get("id")
    if not isinstance(rid, str):
        return False
    transport = _caller()
    exhausted = False
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
        verdict, problem = _gated_verdict(req, frame) if req.level is not None else ("settle", "")
        if verdict == "counted":
            exhausted = _count_refusal(req)
        elif verdict != "settle":
            return verdict == "kept"
        else:
            # Removing the request and committing its outcome are one settlement.
            # ``cancel()`` also settles under this lock, so the first side to get
            # here wins instead of a later cancellation overwriting a response.
            _open.pop(rid, None)
            if "error" in frame:
                logger.debug("server request %s (%s) answered with error: %s", rid, req.method, frame.get("error"))
                req.result, req.answered, req.errored = None, False, True
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
    if verdict == "counted":
        # A bare response frame gets no reply; the refusal is still counted and reported to the owner.
        _after_refusal(req, transport, problem, frame.get("result"), exhausted)
        return exhausted
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
        logger.warning("server request %s (%s): answer refused, the connection may not answer level %r",
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


def lock_answer(request_id: str, question_id: str, answer: str) -> list[str] | None:
    """Lock one batch-clarify answer (update-in-place). Returns the question ids still unanswered;
    the last lock resolves the request with the full ``{"answers"}`` set. ``None`` when no open
    batch has that id (expired or foreign); ``ValueError`` for an unknown question id."""
    with _lock:
        req = _open.get(request_id)
        if req is None or req.qids is None:
            return None
        if question_id not in req.qids:
            raise ValueError(f"unknown question_id {question_id!r}")
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
    return [req.snapshot() for req in reqs]


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
