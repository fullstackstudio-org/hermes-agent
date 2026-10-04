"""One :class:`TurnWatch` per turn an agent submits through MCP (plan D8).

The watch owns the agent's :class:`~tui_gateway.mcp_bridge.transport.AgentTransport` from the submit
until the turn concludes plus :data:`DETACH_AFTER_END_S`; then it releases it and the session follows
the ordinary detached/reaper path. While attached it records what the session streams -- the reply's text
(at most :data:`TEXT_CAP_BYTES`), the server requests that open and close, the turn's end -- and
:meth:`TurnWatch.wait` answers with the turn's status:

``running``             the turn has not concluded and nobody is being asked anything;
``waiting_for_person``  it has not concluded and at least one server request is open (a clarify the agent
                        may answer; an approval, sudo, secret or vault prompt only the person's app can);
``done``                ``message.complete`` with status ``complete``;
``interrupted``         ``message.complete`` with status ``interrupted`` (a stop, a redirect);
``error``               ``message.complete`` with status ``error``, or an error that ended the turn
                        before it started (an admission refusal, an agent that failed to build);
``restarted``           the gateway interrupted the turn on its way out (``interrupt_reason:
                        "shutdown"``, HERM-245): the turn continues after the restart, so wait again then.

Which turn is ours. ``prompt.submit`` answers before the turn's first frame and does not name the turn, so
the watch is ARMED before the submit and keeps every frame that arrives until the submit's answer says
how the text was taken: ``streaming`` (a new turn: the next ``message.start``), ``queued`` (the turn after
the one running now), ``steered`` / ``redirected`` (the running turn). Frames of a turn that ran before
the watch armed are never adopted. A turn that fails before it starts sends no ``message.start``; its
terminal frame is held as a candidate until ``session.active_list`` shows the session idle (or the
stored user row of ``message.complete`` matches the submit's ``user_row_id``). The public ``turn_id`` is
the bridge's own handle (minted at submit, so it exists before the turn starts); ``gateway_turn_id`` is
the turn's id on the wire and on its rows, once known.

Requests. A frame of a request (``clarify``, ``approval``, ...) opens one; ``request.cancel`` closes it.
An ungated request answered by the person's app emits nothing, so while one is open the watch
reconciles with ``session.events.since`` (``open_requests``, listed to an agent read-only) on the waiter's
thread, at most every :data:`RECONCILE_INTERVAL_S` or when the turn moves on. Summaries carry the kind,
whether the agent may answer it (``server_requests.agent_answer_refusal``), and for ``clarify`` the
questions and for ``approval`` the description, the tool and the (server-redacted) command. Never the
prompt of a ``secret``, ``sudo`` or ``vault.*`` request: those are a kind only.

Threads. :meth:`TurnWatch._feed` runs on whatever thread emits (see ``transport.py``): it only records,
under the watch's own lock, and never calls into the gateway. RPCs (reconcile, answers) run on the
caller's thread. Process-wide: at most :data:`MAX_WATCHES` watches; a concluded one is evicted
:data:`RETAIN_AFTER_END_S` after it ended (or earlier, oldest first, to make room), and one that never
concluded after :data:`STALE_AFTER_S`.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Callable

from tui_gateway.mcp_bridge import rpc
from tui_gateway.mcp_bridge.transport import AgentTransport, login_of
from tui_gateway.row_identity import TURN_STREAM_EVENTS

logger = logging.getLogger(__name__)

STATUSES = ("running", "done", "waiting_for_person", "interrupted", "error", "restarted")
TERMINAL_STATUSES = frozenset({"done", "interrupted", "error", "restarted"})

MAX_WATCHES = 200
RETAIN_AFTER_END_S = 3600.0
DETACH_AFTER_END_S = 60.0
#: A watch whose turn never concluded (a lost frame, a wedged turn) is dropped after this, like an idle session.
STALE_AFTER_S = 6 * 3600.0
TEXT_CAP_BYTES = 256 * 1024
PROGRESS_TAIL_CHARS = 2000
PROGRESS_INTERVAL_S = 1.0
RECONCILE_INTERVAL_S = 2.0
_RECONCILE_MIN_GAP_S = 0.5
_WAIT_SLICE_S = 0.25
_RECONCILE_TIMEOUT_S = 10.0
_EARLY_FRAMES_MAX = 4096
_PRE_ARM_TURNS_MAX = 64
#: ``session.events.since`` with this watermark returns no events, only ``open_requests``.
_NO_EVENTS_SEQ = 2**53 - 1
_SUBMIT_MODES = frozenset({"streaming", "queued", "steered", "redirected"})

_QUESTION_MAX = 2000
_CHOICE_MAX = 200
_CHOICES_MAX = 20
_QUESTIONS_MAX = 20
_COMMAND_MAX = 500
_FIELD_MAX = 200


class WatchLimitReached(rpc.BridgeError):
    """:data:`MAX_WATCHES` watches exist and none of them has concluded."""


class NotAnswerable(rpc.BridgeError):
    """The gateway refused the agent's answer (4033: not a clarify, clarify through MCP turned off, or not this
    connection's session; 4034: not a valid answer). The tool error ``not_answerable``."""

    kind = "not_answerable"

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ── request summaries ─────────────────────────────────────────────────────────────────────────


def _cap(value: Any, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _question(entry: dict) -> dict:
    choices = entry.get("choices") if isinstance(entry.get("choices"), list) else []
    return {"id": _cap(entry.get("qid"), _FIELD_MAX), "question": _cap(entry.get("question"), _QUESTION_MAX),
            "choices": [_cap(choice, _CHOICE_MAX) for choice in choices[:_CHOICES_MAX] if isinstance(choice, str)],
            "multi_select": bool(entry.get("multi_select"))}


def summarize_request(request_id: str, method: str, params: dict | None, transport: Any) -> dict:
    """What the agent may know of one open server request (see the module docstring). Every string came
    from the bot and is untrusted."""
    from tui_gateway import server_requests

    params = params if isinstance(params, dict) else {}
    summary: dict[str, Any] = {
        "id": str(request_id), "kind": str(method),
        "answerable": server_requests.agent_answer_refusal(str(method), transport) is None}
    if method == "clarify":
        batch = isinstance(params.get("questions"), list)
        entries = params["questions"] if batch else [params]
        summary["batch"] = batch
        summary["questions"] = [_question(entry) for entry in entries[:_QUESTIONS_MAX] if isinstance(entry, dict)]
        if isinstance(params.get("answers"), dict):
            summary["locked"] = sorted(str(qid) for qid in params["answers"])
    elif method == "approval":
        summary.update(description=_cap(params.get("description"), _QUESTION_MAX),
                       tool_name=_cap(params.get("tool_name"), _FIELD_MAX),
                       command=_cap(params.get("command"), _COMMAND_MAX))
    return summary


def summarize_open_requests(open_requests: Any, transport: Any) -> list[dict]:
    """:func:`summarize_request` for each entry of an ``open_requests`` list (``session.resume`` /
    ``session.events.since``)."""
    return [summarize_request(entry["id"], entry["method"], entry.get("params"), transport)
            for entry in (open_requests if isinstance(open_requests, list) else [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str) and isinstance(entry.get("method"), str)]


def answer_clarify(transport: AgentTransport, request_id: str, answers: str | dict, *,
                   timeout: float | None = rpc.DEFAULT_TIMEOUT_S) -> str:
    """Answer the open ``clarify`` *request_id* through ``request.answer``: *answers* is the answer to a single
    question or ``{question id: answer}`` for a batch. The gateway prefixes each answer as the agent's; the
    bridge adds nothing. ``"ok"`` or ``"expired"`` (the wait already ended); :class:`NotAnswerable` on 4033 /
    4034."""
    if isinstance(answers, str):
        result: dict = {"answer": answers}
    elif isinstance(answers, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in answers.items()):
        result = {"answers": dict(answers)}
    else:
        raise ValueError("answers is a string or {question id: string}")
    try:
        response = rpc.call(transport, "request.answer", {"id": str(request_id), "result": result}, timeout=timeout)
    except rpc.RpcError as exc:
        if exc.code in (4033, 4034):
            raise NotAnswerable(exc.code, exc.message) from exc
        raise
    return str(response.get("status") or "")


# ── frames ──────────────────────────────────────────────────────────────────────────────────


def _event_item(params: dict) -> tuple:
    """``("event", type, turn id, data)`` with only what the watch reads, copied off the frame now."""
    kind = str(params.get("type") or "")
    payload = params.get("payload") if isinstance(params.get("payload"), dict) else {}
    tid = params.get("turn_id") if isinstance(params.get("turn_id"), str) and params.get("turn_id") else None
    data: dict[str, Any] = {}
    if kind == "message.delta":
        data["text"] = payload.get("text") if isinstance(payload.get("text"), str) else ""
    elif kind == "message.complete":
        persisted = payload.get("persisted_turn") if isinstance(payload.get("persisted_turn"), dict) else {}
        data = {"text": payload.get("text") if isinstance(payload.get("text"), str) else "",
                "status": str(payload.get("status") or ""),
                "interrupt_reason": str(payload.get("interrupt_reason") or ""),
                "error": payload.get("error") if isinstance(payload.get("error"), str) else "",
                "row_id": payload.get("row_id") if isinstance(payload.get("row_id"), int) else None,
                "user_row_id": (persisted.get("user_row_id")
                                if isinstance(persisted.get("user_row_id"), int) else None)}
    elif kind == "error":
        data["message"] = payload.get("message") if isinstance(payload.get("message"), str) else ""
    elif kind == "request.cancel":
        data["id"] = payload.get("id")
    elif kind == "status.update":
        data["kind"] = payload.get("kind")
    return ("event", kind, tid, data)


def _request_item(request_id: str, method: str, params: dict) -> tuple:
    try:
        copy = json.loads(json.dumps({k: v for k, v in params.items() if k not in ("session_id", "seq")},
                                     default=str))
    except (TypeError, ValueError):
        copy = {}
    return ("request", method, request_id, copy)


def _cap_bytes(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


class TurnWatch:
    """See the module docstring. Built by :func:`start_turn`; found again with :func:`get`."""

    def __init__(self, transport: AgentTransport, *, chat_id: str, session_id: str) -> None:
        self.chat_id = str(chat_id)
        self.session_id = str(session_id)
        #: The bridge's handle for the turn, given to the agent (``bot_wait(chat_id, turn_id)``).
        self.turn_id = uuid.uuid4().hex
        #: The turn's id on the wire and on its rows (``display_metadata.turn_id``), once known.
        self.gateway_turn_id: str | None = None
        self.owner = transport.login
        self.grant = transport.grant
        self.created_at = time.monotonic()
        self.ended_at: float | None = None
        self.submit_status = ""
        self._transport = transport
        self._cond = threading.Condition()
        self._status = "running"
        self._armed = False
        self._mode: str | None = None
        self._early: list[tuple] = []
        self._pre_tids: OrderedDict[str, None] = OrderedDict()
        self._running_tid: str | None = None
        self._after_complete = False
        self._started = False
        self._candidate: tuple | None = None
        self._user_row_id: int | None = None
        self._parts: list[str] = []
        self._text_bytes = 0
        self._truncated = False
        self._tail = ""
        self._text_version = 0
        self._final: str | None = None
        self._requests: OrderedDict[str, tuple[str, dict]] = OrderedDict()
        self._req_version = 0
        self._reported_req_version = 0
        self._requests_dirty = False
        self._error = ""
        self._row_id: int | None = None
        self._restarting = False
        self._last_seq = 0
        self._waiter_gen = 0
        self._detach_timer: threading.Timer | None = None
        self._detached = False
        transport.set_event_sink(self._feed)

    # ── the emitting side (never blocks, never calls the gateway) ────────────────────────────

    def _feed(self, frame: dict) -> None:
        params = frame.get("params")
        if not isinstance(params, dict) or str(params.get("session_id") or "") != self.session_id:
            return
        method = frame.get("method")
        if method == "event":
            item = _event_item(params)
        elif isinstance(method, str) and isinstance(frame.get("id"), str):
            item = _request_item(frame["id"], method, params)
        else:
            return
        with self._cond:
            if isinstance(seq := params.get("seq"), int):
                self._last_seq = max(self._last_seq, seq)
            if not self._armed:
                self._note_pre_arm(item)
            elif self._mode is None:
                if len(self._early) < _EARLY_FRAMES_MAX:
                    self._early.append(item)
            else:
                self._apply(item)
            self._cond.notify_all()

    def _note_pre_arm(self, item: tuple) -> None:
        """Caller holds the lock. Remember which turns ran before the watch armed: never ours, except the one
        a steer or redirect joins."""
        if item[0] != "event" or item[1] not in TURN_STREAM_EVENTS or item[2] is None:
            return
        tid = item[2]
        self._pre_tids[tid] = None
        self._pre_tids.move_to_end(tid)
        while len(self._pre_tids) > _PRE_ARM_TURNS_MAX:
            self._pre_tids.popitem(last=False)
        if item[1] == "message.complete":
            if self._running_tid == tid:
                self._running_tid = None
        else:
            self._running_tid = tid

    def _apply(self, item: tuple) -> None:
        """Caller holds the lock and the submit's mode is known."""
        if self._status in TERMINAL_STATUSES:
            return
        if item[0] == "request":
            _, method, request_id, params = item
            if self._started:
                self._open_request(request_id, method, params)
            return
        _, kind, tid, data = item
        if kind == "request.cancel":
            self._close_request(data.get("id"))
            return
        if kind == "status.update":
            if data.get("kind") == "restart":
                self._restarting = True
            return
        if kind not in TURN_STREAM_EVENTS:
            return
        if not self._started:
            if not self._adopt(kind, tid, data):
                return
        elif tid is not None and self.gateway_turn_id is not None and tid != self.gateway_turn_id:
            return
        elif tid is not None and self.gateway_turn_id is None:
            self.gateway_turn_id = tid
        self._on_turn_frame(kind, data)

    def _adopt(self, kind: str, tid: str | None, data: dict) -> bool:
        """Caller holds the lock. Whether this frame is the first of OUR turn (it is then started)."""
        if self._mode in ("steered", "redirected"):
            if tid is None or (self._running_tid is not None and tid != self._running_tid):
                return False
            return self._start(tid)
        if self._mode == "queued" and not self._after_complete:
            # The turn running at submit time ends first; ours is the one after it.
            if kind == "message.complete":
                self._after_complete = True
            return False
        if tid is not None and tid in self._pre_tids:
            return False
        if kind == "message.start":
            return self._start(tid)
        if kind in ("message.complete", "error"):
            # A terminal frame with no start: ours failing before it started, or a straggler of the turn
            # before. The stored user row settles it when both sides name one; else the session's state does.
            ours, theirs = self._user_row_id, data.get("user_row_id")
            if ours is not None and theirs is not None:
                return self._start(tid) if ours == theirs else False
            self._candidate = (kind, tid, data)
            self._requests_dirty = True  # settle it at the waiter's next reconcile, not the periodic one
        return False

    def _start(self, tid: str | None) -> bool:
        self._started = True
        self.gateway_turn_id = tid
        self._candidate = None
        return True

    def _on_turn_frame(self, kind: str, data: dict) -> None:
        if kind == "message.delta":
            self._append_text(data.get("text") or "")
        elif kind == "message.complete":
            self._conclude_from_complete(data)
            return
        elif kind == "error":
            # A stamped error inside a started turn is not necessarily its end: that is message.complete.
            self._error = data.get("message") or self._error
        if self._requests:
            self._requests_dirty = True

    def _append_text(self, text: str) -> None:
        if not text:
            return
        self._tail = (self._tail + text)[-PROGRESS_TAIL_CHARS:]
        self._text_version += 1
        if self._truncated:
            return
        size = len(text.encode("utf-8", errors="replace"))
        if self._text_bytes + size <= TEXT_CAP_BYTES:
            self._parts.append(text)
            self._text_bytes += size
            return
        head, _ = _cap_bytes(text, TEXT_CAP_BYTES - self._text_bytes)
        if head:
            self._parts.append(head)
        self._text_bytes = TEXT_CAP_BYTES
        self._truncated = True

    def _conclude_from_complete(self, data: dict) -> None:
        status, text = data.get("status"), data.get("text") or ""
        if status == "interrupted":
            outcome = "restarted" if data.get("interrupt_reason") == "shutdown" else "interrupted"
        elif status == "error":
            outcome = "error"
        else:
            outcome = "done"
        self._conclude(outcome, text, (data.get("error") or text) if outcome == "error" else "", data.get("row_id"))

    def _conclude(self, outcome: str, text: str, error: str, row_id: int | None) -> None:
        """Caller holds the lock."""
        if outcome == "done" or text:
            self._final, truncated = _cap_bytes(text, TEXT_CAP_BYTES)
            self._truncated = truncated
        if error:
            self._error = error[:_QUESTION_MAX]
        self._row_id = row_id
        self._status = outcome
        self.ended_at = time.monotonic()
        self._requests.clear()
        self._candidate = None
        self._schedule_detach()
        self._cond.notify_all()

    def _open_request(self, request_id: str, method: str, params: dict) -> None:
        if request_id in self._requests:
            return
        self._requests[request_id] = (method, params)
        self._req_version += 1

    def _close_request(self, request_id: Any) -> None:
        if isinstance(request_id, str):
            self._requests.pop(request_id, None)

    # ── the submit ───────────────────────────────────────────────────────────────────────────

    def _arm(self) -> None:
        with self._cond:
            self._armed = True

    def _set_mode(self, status: str, user_row_id: Any) -> None:
        with self._cond:
            self.submit_status = status
            self._user_row_id = user_row_id if isinstance(user_row_id, int) else None
            if status not in _SUBMIT_MODES:
                # No turn was started for this text (a typed voice stop phrase ends the voice chat instead).
                self._mode = "none"
                self._early = []
                self._conclude("done", "", "", None)
                return
            self._mode = status
            early, self._early = self._early, []
            for item in early:
                self._apply(item)
            self._cond.notify_all()

    # ── reading ───────────────────────────────────────────────────────────────────────────────

    @property
    def status(self) -> str:
        with self._cond:
            return self._status_locked()

    def _status_locked(self) -> str:
        if self._status in TERMINAL_STATUSES:
            return self._status
        return "waiting_for_person" if self._requests else "running"

    def snapshot(self, *, mark_reported: bool = True) -> dict:
        """The turn as the agent may see it now (JSON-plain). Marks every open request as reported unless told
        not to (an answer nobody will read must not swallow the news of a request)."""
        with self._cond:
            status = self._status_locked()
            text = self._final if self._final is not None else "".join(self._parts)
            data: dict[str, Any] = {
                "status": status, "chat_id": self.chat_id, "turn_id": self.turn_id, "text": text,
                "text_truncated": self._truncated, "submit_status": self.submit_status}
            if self.gateway_turn_id:
                data["gateway_turn_id"] = self.gateway_turn_id
            if self._error and status == "error":
                data["error"] = self._error
            if self._row_id is not None:
                data["row_id"] = self._row_id
            if status == "restarted" or (self._restarting and status not in TERMINAL_STATUSES):
                data["restarting"] = True
                data["retry_after_seconds"] = rpc.RESTART_RETRY_AFTER_S
            requests = list(self._requests.items())
            if mark_reported:
                self._reported_req_version = self._req_version
        data["requests"] = [summarize_request(request_id, method, params, self._transport)
                            for request_id, (method, params) in requests]
        return data

    def wait(self, deadline: float | None = None, *, on_progress: Callable[[str], None] | None = None,
             stop: threading.Event | None = None) -> dict:
        """Block until the turn concludes, a request opens that no earlier answer reported, *stop* is set, a
        newer ``wait`` on this turn supersedes this one, or the monotonic *deadline* passes (None: do not
        wait). Returns :meth:`snapshot`. ``on_progress(tail)`` gets the last :data:`PROGRESS_TAIL_CHARS`
        characters of the streamed text at most every :data:`PROGRESS_INTERVAL_S`, on this thread. Call it
        from a worker thread: it may run RPCs (request reconciliation)."""
        with self._cond:
            self._waiter_gen += 1
            generation = self._waiter_gen
            self._cond.notify_all()
            started = self._started
        if started:
            self._reconcile()
        last_reconcile = time.monotonic()
        last_progress, progress_version = 0.0, self._text_version
        abandoned = False
        while True:
            tail = None
            reconcile = False
            with self._cond:
                now = time.monotonic()
                abandoned = self._waiter_gen != generation or (stop is not None and stop.is_set())
                if (abandoned or self._status in TERMINAL_STATUSES or self._req_version != self._reported_req_version
                        or deadline is None or now >= deadline):
                    break
                if (on_progress is not None and self._text_version != progress_version
                        and now - last_progress >= PROGRESS_INTERVAL_S):
                    tail, progress_version, last_progress = self._tail, self._text_version, now
                elif (self._requests or self._candidate is not None) and now - last_reconcile >= _RECONCILE_MIN_GAP_S \
                        and (self._requests_dirty or now - last_reconcile >= RECONCILE_INTERVAL_S):
                    reconcile = True
                else:
                    self._cond.wait(min(_WAIT_SLICE_S, max(0.0, deadline - now)))
                    continue
            if tail is not None:
                try:
                    on_progress(tail)
                except Exception:  # noqa: BLE001 - progress is garnish; the wait goes on
                    logger.debug("turn watch: progress callback failed", exc_info=True)
            if reconcile:
                self._reconcile()
                last_reconcile = time.monotonic()
        return self.snapshot(mark_reported=not abandoned)

    def _reconcile(self) -> None:
        """Bring the open requests (and a held candidate terminal frame) in line with the gateway, over RPC."""
        with self._cond:
            if self._status in TERMINAL_STATUSES or self._transport.closed:
                return
            check_requests = self._started
            candidate = self._candidate is not None and not self._started
            self._requests_dirty = False
        try:
            if check_requests:
                result = rpc.call(self._transport, "session.events.since",
                                  {"session_id": self.session_id, "last_seen": _NO_EVENTS_SEQ},
                                  timeout=_RECONCILE_TIMEOUT_S)
                self._apply_open_requests(result.get("open_requests"))
            if candidate:
                result = rpc.call(self._transport, "session.active_list", {}, timeout=_RECONCILE_TIMEOUT_S)
                rows = result.get("sessions") if isinstance(result.get("sessions"), list) else []
                row = next((r for r in rows if isinstance(r, dict) and r.get("id") == self.session_id), None)
                if row is None or row.get("status") == "idle":
                    self._adopt_candidate()
        except rpc.GatewayRestarting:
            with self._cond:
                self._restarting = True
        except rpc.BridgeError:
            logger.debug("turn watch: reconcile failed", exc_info=True)

    def _apply_open_requests(self, open_requests: Any) -> None:
        entries = [e for e in (open_requests if isinstance(open_requests, list) else [])
                   if isinstance(e, dict) and isinstance(e.get("id"), str) and isinstance(e.get("method"), str)]
        with self._cond:
            if self._status in TERMINAL_STATUSES:
                return
            live = {entry["id"] for entry in entries}
            for request_id in [r for r in self._requests if r not in live]:
                self._requests.pop(request_id, None)
            for entry in entries:
                params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
                self._open_request(entry["id"], entry["method"], _request_item(entry["id"], entry["method"], params)[3])
            self._cond.notify_all()

    def _adopt_candidate(self) -> None:
        with self._cond:
            if self._candidate is None or self._started or self._status in TERMINAL_STATUSES:
                return
            kind, tid, data = self._candidate
            self._start(tid)
            if kind == "message.complete":
                self._conclude_from_complete(data)
            else:
                self._conclude("error", "", data.get("message") or "the turn ended before it started", None)

    # ── acting on the turn ────────────────────────────────────────────────────────────────────

    def answer_clarify(self, request_id: str, answers: str | dict, *,
                       timeout: float | None = rpc.DEFAULT_TIMEOUT_S) -> str:
        """:func:`answer_clarify` on this turn's connection; the request leaves the watch once answered or
        expired."""
        status = answer_clarify(self._transport, request_id, answers, timeout=timeout)
        with self._cond:
            self._requests.pop(str(request_id), None)
            self._cond.notify_all()
        return status

    # ── lifetime ──────────────────────────────────────────────────────────────────────────────

    @property
    def detached(self) -> bool:
        return self._detached

    def _schedule_detach(self) -> None:
        """Caller holds the lock."""
        if self._detach_timer is not None or self._detached:
            return
        timer = threading.Timer(DETACH_AFTER_END_S, self._detach)
        timer.daemon = True
        self._detach_timer = timer
        timer.start()

    def _detach(self) -> None:
        with self._cond:
            if self._detached:
                return
            self._detached = True
            timer, self._detach_timer = self._detach_timer, None
        if timer is not None:
            timer.cancel()
        self._transport.set_event_sink(None)
        self._transport.release()

    def release(self) -> None:
        """Detach now (eviction, an abandoned submit is not this: see :func:`start_turn`). May block."""
        self._detach()


# ── the process-wide registry ─────────────────────────────────────────────────────────────────

_registry: OrderedDict[tuple[str, str], TurnWatch] = OrderedDict()
_registry_lock = threading.Lock()


def _purge_locked(now: float) -> list[TurnWatch]:
    gone = [key for key, watch in _registry.items()
            if (watch.ended_at is not None and now - watch.ended_at >= RETAIN_AFTER_END_S)
            or (watch.ended_at is None and now - watch.created_at >= STALE_AFTER_S)]
    return [_registry.pop(key) for key in gone]


def _register(watch: TurnWatch) -> None:
    evicted: list[TurnWatch] = []
    try:
        with _registry_lock:
            evicted = _purge_locked(time.monotonic())
            if len(_registry) >= MAX_WATCHES:
                ended = [(w.ended_at, key) for key, w in _registry.items() if w.ended_at is not None]
                if not ended:
                    raise WatchLimitReached(f"{MAX_WATCHES} turns are being watched; none has concluded")
                evicted.append(_registry.pop(min(ended)[1]))
            _registry[(watch.chat_id, watch.turn_id)] = watch
    finally:
        for old in evicted:
            old.release()


def _unregister(watch: TurnWatch) -> None:
    with _registry_lock:
        if _registry.get((watch.chat_id, watch.turn_id)) is watch:
            _registry.pop((watch.chat_id, watch.turn_id), None)


def get(chat_id: str, turn_id: str, *, identity: dict) -> TurnWatch | None:
    """The watch of *turn_id* in *chat_id* when it belongs to the person *identity* names; None otherwise (an
    unknown turn, another person's, or one evicted -- after a restart every turn is unknown)."""
    login = login_of(identity)
    evicted: list[TurnWatch] = []
    try:
        with _registry_lock:
            evicted = _purge_locked(time.monotonic())
            watch = _registry.get((str(chat_id), str(turn_id)))
    finally:
        for old in evicted:
            old.release()
    return watch if watch is not None and login is not None and watch.owner == login else None


def watch_count() -> int:
    with _registry_lock:
        return len(_registry)


def start_turn(transport: AgentTransport, *, chat_id: str, session_id: str, text: str,
               params: dict | None = None, timeout: float | None = rpc.DEFAULT_TIMEOUT_S) -> TurnWatch:
    """Submit *text* to the live session *session_id* (the stored chat *chat_id*, already resumed or created
    on *transport*) and return the watch of the turn it starts or joins.

    On success the watch OWNS *transport*: it releases it :data:`DETACH_AFTER_END_S` after the turn
    concludes (or when evicted). On failure nothing is watched, the transport stays the caller's, and the
    error propagates: :class:`WatchLimitReached`, :class:`~tui_gateway.mcp_bridge.rpc.GatewayRestarting`
    (5035), :class:`~tui_gateway.mcp_bridge.rpc.RpcError` (4001 for a session this person may not act on,
    4009 busy, ...), or any other :class:`~tui_gateway.mcp_bridge.rpc.BridgeError`. *params* adds
    ``prompt.submit`` parameters (``queued``, ...), checked by the RPC allowlist."""
    if not isinstance(transport, AgentTransport):
        raise rpc.DisallowedCall("a turn is watched on an AgentTransport only")
    if transport.has_event_sink:
        raise rpc.DisallowedCall("one turn per agent transport: this one already feeds a watch")
    watch = TurnWatch(transport, chat_id=chat_id, session_id=session_id)
    try:
        _register(watch)
    except BaseException:
        transport.set_event_sink(None)
        raise
    try:
        # Advertised before arming, so the request frames of the turn find a connection that answers them.
        rpc.ensure_capabilities(transport, timeout=timeout)
        watch._arm()
        result = rpc.call(transport, "prompt.submit",
                          {**(params or {}), "session_id": str(session_id), "text": text}, timeout=timeout)
    except BaseException:
        _unregister(watch)
        transport.set_event_sink(None)
        raise
    watch._set_mode(str(result.get("status") or ""), result.get("user_row_id"))
    return watch


def reset_for_tests() -> None:
    with _registry_lock:
        watches = list(_registry.values())
        _registry.clear()
    for watch in watches:
        with watch._cond:
            timer = watch._detach_timer
        if timer is not None:
            timer.cancel()
