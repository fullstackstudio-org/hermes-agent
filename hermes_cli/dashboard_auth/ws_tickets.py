"""WS-upgrade auth credentials for gated mode.

Browsers cannot set ``Authorization`` on a WebSocket upgrade, and gated mode has no token injected into
the SPA, so two credential shapes exist:

1. single-use browser tickets (``mint_ticket`` / ``consume_ticket``) fetched via authenticated
   ``POST /api/auth/ws-ticket`` and passed as ``?ticket=`` on the upgrade: 30 s TTL, a leak is
   uninteresting;
2. per-PTY credentials (``mint_pty_credential``) for the embedded Chat tab's terminal child, which reuses
   its attach URL on every reconnect, possibly long after boot. Each one carries the login that opened
   that Chat tab, is accepted only on ``/api/ws`` and ``/api/pub`` from the gateway host itself
   (``web_server_chat._pty_peer_allowed``), and is revoked when that terminal ends; revoking also closes
   every socket still open with it (:func:`track_pty_socket`).

What is NOT closed: the value travels to the terminal child in its environment, so while that terminal
runs, any process of the same OS user on the gateway host (an agent's terminal tool included) can read
it and act as that login. There is no process-wide credential any more.

In-memory; ``time.time`` patchable.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Any, Callable, Dict, Optional, Set, Tuple

#: Long enough for ``getWsTicket()`` -> open WS, short enough that a leaked ticket is uninteresting.
TTL_SECONDS = 30

_lock = threading.Lock()
_tickets: Dict[str, Tuple[int, Dict[str, Any]]] = {}  # ticket -> (expires_at, info)
_pty_credentials: Dict[str, Dict[str, Any]] = {}  # per-PTY credential -> the login it carries
_pty_sockets: Dict[str, Set[Callable[[], None]]] = {}  # per-PTY credential -> closers of its open sockets

#: The identity a server-internal caller would carry; still recognised (and treated as naming no person)
#: by the gateway's identity checks, though no credential mints it any more.
INTERNAL_USER_ID = "server-internal"
INTERNAL_PROVIDER = "server-internal"


class TicketInvalid(Exception):
    """Ticket missing, expired, or already consumed."""


def mint_ticket(
    *, user_id: str, provider: str, user_name: str = "", extra: Optional[Dict[str, Any]] = None,
) -> str:
    """One-shot base64url ticket (32 random bytes) bound to this identity; ``consume_ticket``
    hands the ``info`` dict back to the WS handler.

    ``user_name`` is the provider-verified display name of THIS ``user_id``, taken from the very
    :class:`~hermes_cli.dashboard_auth.base.Session` that authorizes the mint, so the WS session can
    label the person without a second token verification later. It travels as one pair with the
    login and is ``""`` when the provider minted no name (then only the login id exists).

    ``extra`` rides along for routes that need server-chosen context (the Bot Desktop bridge pins
    the RFB socket's profile home here so a client can never pick another profile's screen).
    """
    ticket = secrets.token_urlsafe(32)
    info = {"user_id": user_id, "provider": provider, "user_name": user_name,
            "minted_at": int(time.time()), **(extra or {})}
    with _lock:
        _tickets[ticket] = (int(time.time()) + TTL_SECONDS, info)
        _gc_expired_locked()
    return ticket


def consume_ticket(ticket: str) -> Dict[str, Any]:
    """Validate and consume (single-use). Raises :class:`TicketInvalid` on missing/expired/used."""
    now = int(time.time())
    with _lock:
        entry = _tickets.pop(ticket, None)
        if entry is None:
            # Truncated so misuse never logs the secret in full.
            truncated = (ticket[:8] + "…") if ticket else "<empty>"
            raise TicketInvalid(f"unknown ticket: {truncated}")
        expires_at, info = entry
        if expires_at < now:
            raise TicketInvalid("expired")
        return info


def _gc_expired_locked() -> None:
    """Drop expired tickets. Caller must hold ``_lock``."""
    now = int(time.time())
    for t in [t for t, (exp, _) in _tickets.items() if exp < now]:
        _tickets.pop(t, None)


def mint_pty_credential(*, user_id: str, provider: str, user_name: str = "") -> str:
    """A multi-use credential for ONE embedded-chat PTY, carrying the login that opened it. The PTY child
    reuses it on every reconnect of ``/api/ws`` and ``/api/pub``; :func:`revoke_pty_credential` ends it
    when the PTY ends."""
    value = secrets.token_urlsafe(32)
    info = {"user_id": user_id, "provider": provider, **({"user_name": user_name} if user_name else {})}
    with _lock:
        _pty_credentials[value] = info
    return value


def consume_pty_credential(value: str) -> Dict[str, Any]:
    """The login a live per-PTY credential carries (NOT single-use). Raises :class:`TicketInvalid` for an
    unknown or revoked value."""
    with _lock:
        info = _pty_credentials.get(value) if value else None
    if info is None:
        raise TicketInvalid("unknown or revoked pty credential")
    return dict(info)


def track_pty_socket(value: str, closer: Callable[[], None]) -> bool:
    """Register an open socket authenticated with *value*; *closer* runs when the credential is revoked.
    False (and nothing registered) when the credential is already gone: close that socket now."""
    with _lock:
        if value not in _pty_credentials:
            return False
        _pty_sockets.setdefault(value, set()).add(closer)
        return True


def untrack_pty_socket(value: str, closer: Callable[[], None]) -> None:
    with _lock:
        closers = _pty_sockets.get(value)
        if closers is not None:
            closers.discard(closer)
            if not closers:
                _pty_sockets.pop(value, None)


def revoke_pty_credential(value: Optional[str]) -> None:
    """End a per-PTY credential (idempotent) and close every socket still open with it."""
    if not value:
        return
    with _lock:
        _pty_credentials.pop(value, None)
        closers = _pty_sockets.pop(value, set())
    for closer in closers:
        try:
            closer()
        except Exception:
            pass


def _reset_for_tests() -> None:
    """Test-only: drop all tickets and PTY credentials."""
    with _lock:
        _tickets.clear()
        _pty_credentials.clear()
        _pty_sockets.clear()
