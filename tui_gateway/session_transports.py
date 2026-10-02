"""Additive transport membership for shared live sessions."""
from __future__ import annotations

import contextlib
import contextvars
import threading
from collections import OrderedDict
from tui_gateway.method_ctx import bind_module

# Leaf lock: callers may hold sessions/history locks, never acquire them here.
_session_transport_lock = threading.RLock()


def _transport_is_live_peer(transport) -> bool:
    """Exclude the process fallback sink, parked sentinel, and closed peers."""
    return (transport is not None
            and transport is not _detached_ws_transport
            and transport is not _stdio_transport
            and not isinstance(transport, (_DropTransport, StdioTransport))
            and not _transport_is_dead(transport))


def _session_transport_contains(session: dict | None, transport) -> bool:
    if not session or transport is None or _transport_is_dead(transport):
        return False
    existing = session.get("transport")
    return existing is transport or (
        isinstance(existing, FanoutTransport) and existing.contains(transport))


def _session_live_transports(session: dict | None) -> list:
    existing = (session or {}).get("transport")
    peers = existing.transports() if isinstance(existing, FanoutTransport) else [existing]
    return [peer for peer in peers if _transport_is_live_peer(peer)]


def _session_has_live_transport(session: dict | None, *, excluding=None) -> bool:
    return any(peer is not excluding for peer in _session_live_transports(session))


def _session_client_answers_requests(sid: str) -> bool:
    """Whether a server→client request for *sid* can be answered: False only when every live WebSocket
    client attached to the session is a build that never sent ``client.capabilities`` (Desktop / dashboard
    update separately from this backend; the stdio TUI ships with it). No attached client is still True — the
    question waits in ``open_requests`` for the reconnect replay. Compute-host relays and other non-client
    transports never count."""
    from tui_gateway import server_requests
    from tui_gateway.ws import WSTransport
    clients = [peer for peer in _session_live_transports(_sessions.get(sid)) if isinstance(peer, WSTransport)]
    return not clients or any(server_requests.answers_requests(peer) for peer in clients)


#: Set while the gateway itself dispatches an RPC handler in process on a caller's behalf after that caller
#: was authorized for the outer action (a relayed bot DM landing in a Bot Chat, a hosted room driving its
#: member sessions). Never settable from the wire: underscore params can be, so they are no marker.
_INTERNAL_DISPATCH: contextvars.ContextVar = contextvars.ContextVar("tui_gateway_internal_dispatch", default=False)


@contextlib.contextmanager
def _internal_dispatch():
    token = _INTERNAL_DISPATCH.set(True)
    try:
        yield
    finally:
        _INTERNAL_DISPATCH.reset(token)


#: Who could access a live session that has since been dropped (closed, reaped, evicted): its creator and
#: everyone who attached, kept so a reconnecting owner or participant still gets the replay ring's tail and
#: the epoch from ``session.events.since`` (a client turns a refusal into "no gap" and would never refetch).
#: Bounded like the replay ring itself; the oldest entries go first.
DROPPED_ACCESS_MAX = 512
_dropped_access: OrderedDict = OrderedDict()
_dropped_access_lock = threading.Lock()


def _forget_dropped_session(sid: str) -> None:
    """Called when *sid* becomes live (again): a reused runtime id must not let the people of an earlier
    session under that id replay the new one."""
    with _dropped_access_lock:
        _dropped_access.pop(str(sid or ""), None)


def _remember_dropped_session(sid: str, session: dict | None) -> None:
    """Called when *sid* leaves the live registry. Replaces whatever an earlier session under the same id left."""
    if not sid:
        return
    logins = set((session or {}).get("attached_logins") or ())
    if session and (creator := _session_auth_user_id(session)) is not None:
        logins.add(creator)
    with _dropped_access_lock:
        _dropped_access.pop(sid, None)
        if not logins:
            return
        _dropped_access[sid] = frozenset(logins)
        _dropped_access.move_to_end(sid)
        while len(_dropped_access) > DROPPED_ACCESS_MAX:
            _dropped_access.popitem(last=False)


def _record_attached_login(session: dict, transport) -> None:
    """Remember every signed-in login that ever attached to *session* (never pruned, like ``auth_user_shared``):
    a person who took part may reconnect and replay or answer before their new socket has resumed."""
    login = _transport_auth_user_id(transport)
    if login is not None:
        session.setdefault("attached_logins", set()).add(login)


def _transport_may_access_session(session: dict | None, transport, *, sid: str = "") -> bool:
    """Whether *transport* may read *session*'s event ring and settle its server→client requests.

    Allowed: in-process callers (no transport); a connection attached to the session now (a peer of its slot
    or a viewer); a connection with no per-person identity (session-token / loopback mode, stdio: one
    trust domain, as before; the dashboard Chat tab carries the login that opened it); and a signed-in connection whose login created
    the session or has attached to it before. The last rule keeps a reconnecting client working: it replays
    (``session.events.since``) before its new socket resumes. A different signed-in person has to attach
    first, through resume, which is logged and marks the session shared (``_note_foreign_login``).

    The app-level empty session id (``""``) has no record and stays open to every caller."""
    if transport is None or _INTERNAL_DISPATCH.get():
        return True
    login = _transport_auth_user_id(transport)
    # Rule B below trusts EVERY transport without a per-person identity: session-token / loopback clients,
    # stdio, but also non-client objects that can be bound as the current transport (a fan-out, the detached
    # drop sentinel, the slot a turn thread runs with). Nothing in a turn calls this today; a future
    # dispatcher that runs session RPCs from inside a turn must bind None or use ``_internal_dispatch``
    # deliberately, never inherit the slot. The ContextVar isolation this relies on is per thread/task;
    # revisit if the gateway ever runs on free-threaded Python with shared contexts.
    if session is None:
        if not sid or login is None:
            return True
        with _dropped_access_lock:
            return login in _dropped_access.get(sid, ())
    if (_session_transport_contains(session, transport)
            or any(viewer is transport for viewer in list(session.get("viewers") or {}))):
        return True
    if login is None:
        return True
    return login == _session_auth_user_id(session) or login in (session.get("attached_logins") or ())


def _caller_may_access_session_id(sid: str) -> bool:
    """:func:`_transport_may_access_session` for the connection of the current RPC and the live session *sid*."""
    return _transport_may_access_session(_sessions.get(sid), current_transport(), sid=sid)


def _caller_may_access_session_key(key) -> bool:
    """Whether the current RPC's connection may see work keyed by *key* (a live sid or a session key, as the
    process registry records it). Work with no live session behind it is visible only to connections without
    a per-person identity (the operator's own trust domain)."""
    transport = current_transport()
    if transport is None or _transport_auth_user_id(transport) is None:
        return True
    key = str(key or "")
    for sid, session in list(_sessions.items()):
        if sid == key or str(session.get("session_key") or "") == key:
            return _transport_may_access_session(session, transport, sid=sid)
    return False


def _caller_live_session(sid) -> dict | None:
    """The live session *sid* when the current RPC's connection may act on it, else None — for handlers that
    treat "no live session" as a normal case (completion, one-shot LLM, config, slash dispatch): a session the
    caller may not access looks exactly like one that does not exist."""
    session = _sessions.get(str(sid or ""))
    if session is not None and not _transport_may_access_session(session, current_transport(), sid=str(sid)):
        return None
    return session


# ── resume guessing throttle and the foreign-attach audit ─────────────────────────────────────────────

#: Failed resume lookups (no session under that id or title) one signed-in login may make per window before
#: EVERY resume by that login is refused until the window has passed. Refusing all of them, not only the
#: failures, keeps a throttled guesser from telling a hit from a miss.
RESUME_FAILURE_LIMIT = 30
RESUME_FAILURE_WINDOW_S = 600.0
_RESUME_FAILURE_KEYS_MAX = 10_000
# Module-level state is published onto server.py by ``bind_module``; functions import what they use locally
# (imported modules are not published).
_resume_failures: OrderedDict = OrderedDict()
_resume_failures_lock = threading.Lock()
_resume_throttle_noted: dict = {}  # login -> monotonic time until which its refusal is already audited


def _resume_failure_count(login: str, now: float) -> int:
    """Caller holds the lock. Failures of *login* still inside the window."""
    window = _resume_failures.get(login)
    if window is None:
        return 0
    while window and now - window[0] >= RESUME_FAILURE_WINDOW_S:
        window.popleft()
    if not window:
        _resume_failures.pop(login, None)
        return 0
    return len(window)


def _resume_throttled(login: str | None) -> tuple[bool, bool]:
    """``(throttled, first_in_window)`` for *login*: whether it has used up its failed-resume budget, and
    whether this is the first refusal of the window (audit once per window, not per refused request).
    Connections without a per-person identity are never throttled (one trust domain)."""
    import time
    if login is None:
        return False, False
    now = time.monotonic()
    with _resume_failures_lock:
        if _resume_failure_count(login, now) < RESUME_FAILURE_LIMIT:
            return False, False
        first = _resume_throttle_noted.get(login, 0.0) <= now
        if first:
            _resume_throttle_noted[login] = now + RESUME_FAILURE_WINDOW_S
            while len(_resume_throttle_noted) > _RESUME_FAILURE_KEYS_MAX:
                _resume_throttle_noted.pop(next(iter(_resume_throttle_noted)))
        return True, first


def _note_resume_failure(login: str | None) -> None:
    import time
    from collections import deque
    if login is None:
        return
    now = time.monotonic()
    with _resume_failures_lock:
        _resume_failure_count(login, now)
        _resume_failures.setdefault(login, deque()).append(now)
        _resume_failures.move_to_end(login)
        while len(_resume_failures) > _RESUME_FAILURE_KEYS_MAX:
            _resume_failures.popitem(last=False)


def _session_audit(event: str, transport, **fields) -> None:
    """One record in the dashboard auth audit log (``dashboard-auth.log``); never raises."""
    try:
        from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
        audit_log(AuditEvent(event), login=_transport_auth_user_id(transport) or "",
                  ip=str(getattr(transport, "_peer", "") or ""), **fields)
    except Exception:
        logger.debug("session audit record not written", exc_info=True)


def _note_foreign_login(session: dict, transport) -> None:
    """Ownership is not enforced; a second login sharing a session is only logged, and the agent keeps the
    creator's user id. The record is ALSO marked shared, for good: from here on ``auth_user_id`` is the
    login that opened the conversation and not an answer to who is acting, so the session-identity vars
    must fail closed (:func:`_session_identity_is_ambiguous`)."""
    attaching = _transport_auth_user_id(transport)
    if attaching is None:
        return
    creator = _session_auth_user_id(session)
    if creator != attaching:
        session["auth_user_shared"] = True
        logger.warning("Session %s keeps the user id %s it was created with; a client logged in as %s attached",
                       session.get("session_key"), creator or "(none)", attaching)
        # Audit a person joining someone else's conversation. The owner is the login the STORED conversation
        # was opened under when the record is a reopening (whoever reopened it stamped the record), so the
        # owner coming back is not "foreign".
        owner = session.get("stored_owner") or creator
        if owner != attaching:
            _session_audit("session_foreign_attach", transport, session_id=str(session.get("session_key") or ""),
                           owner=owner or "", how="attach")


def _session_auth_logins(session: dict | None) -> set[str]:
    """Every distinct signed-in login attached to *session*'s transport slot right now."""
    return {login for peer in _session_live_transports(session)
            if (login := _transport_auth_user_id(peer)) is not None}


def _session_identity_is_ambiguous(session: dict | None) -> bool:
    """Whether more than one signed-in person could be behind this session's work.

    ``auth_user_id`` names the login the record was CREATED under, and nothing re-stamps it when a second
    window attaches, so on a shared session the stamp is not proof of who is acting. Two things make it
    unprovable and both count: ``auth_user_shared``, set once by :func:`_note_foreign_login` and never
    unset (the second person leaving does not turn the creator's stamp back into proof of who typed what
    while they were there), and a slot that right now carries a login the stamp does not name — a peer
    that reached it without passing through this module.

    A slot naming no login at all is NOT ambiguous: a parked session, a stdio peer and the compute-host
    child's own pipe have no competing person attached, so the stamp is the one identity in play."""
    session = session or {}
    if session.get("auth_user_shared"):
        return True
    logins = _session_auth_logins(session)
    if not logins:
        return False
    creator = _session_auth_user_id(session)
    return len(logins) > 1 or (creator is not None and logins != {creator})


def _attach_session_transport(session: dict | None, transport) -> bool:
    """Add live peers; flatten captured queued fanouts without nesting authority."""
    if not session or transport is None:
        return False
    with _session_transport_lock:
        if isinstance(transport, FanoutTransport):
            # Snapshot and attach share detach's lock: a queued fanout cannot
            # resurrect a still-open peer removed during flattening.
            attached = [_attach_session_transport(session, peer) for peer in transport.transports()]
            return any(attached)
        existing = session.get("transport")
        if _transport_is_dead(transport):
            if isinstance(existing, FanoutTransport):
                existing.detach(transport)
            return False
        if not _transport_is_live_peer(transport):
            if _session_has_live_transport(session):
                return False
            session["transport"] = transport
            return True
        _record_attached_login(session, transport)
        if existing is transport:
            return True
        if isinstance(existing, FanoutTransport):
            if not existing.contains(transport):
                _note_foreign_login(session, transport)
            existing.attach(transport)
            return existing.contains(transport)
        _note_foreign_login(session, transport)
        if _transport_is_live_peer(existing):
            session["transport"] = FanoutTransport(existing, transport)
        else:
            session["transport"] = transport
        return True


def _detach_session_transport(session: dict | None, transport) -> bool:
    """Remove membership; return whether another live client prevents parking."""
    if not session:
        return False
    with _session_transport_lock:
        (session.get("viewers") or {}).pop(transport, None)
        existing = session.get("transport")
        if isinstance(existing, FanoutTransport):
            existing.detach(transport)
            viewers = session.get("viewers") or {}
            for viewer in list(viewers):
                if not existing.contains(viewer) or _transport_is_dead(viewer):
                    viewers.pop(viewer, None)
            # Keep the surviving mailbox: collapsing to a bare transport lets
            # new frames overtake its already queued terminal/control events.
        return _session_has_live_transport(session, excluding=transport)


def _detach_transport_from_sessions(transport) -> list[tuple[str, dict]]:
    """Remove even closed/pruned peers' viewer entries; return clientless slots."""
    with _sessions_lock:
        attached = []
        for sid, session in _sessions.items():
            existing = session.get("transport")
            if (existing is transport
                    or isinstance(existing, FanoutTransport) and existing.contains(transport)
                    or transport in (session.get("viewers") or {})):
                attached.append((sid, session))
    return [(sid, session) for sid, session in attached
            if not _detach_session_transport(session, transport)]


def register(server) -> None:
    bind_module(globals(), server)
