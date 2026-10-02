"""WS-upgrade auth credentials for gated mode.

Browsers cannot set ``Authorization`` on a WebSocket upgrade, and gated mode has no token
injected into the SPA, so two credential shapes exist: (1) single-use browser tickets
(``mint_ticket`` / ``consume_ticket``) fetched via authenticated ``POST /api/auth/ws-ticket`` and
passed as ``?ticket=`` on the upgrade — 30 s TTL, a leak is uninteresting; (2) a process-lifetime
internal credential (``internal_ws_credential`` / ``consume_internal_credential``) for
*server-spawned* WS clients (the embedded-TUI PTY child on ``/api/ws`` + ``/api/pub``), which
reuse their attach URL on every reconnect, possibly >30 s after boot — minted once, never expires,
multi-use, never injected into any HTML/SPA (leaves the process only via the child's environment,
so browser XSS cannot read it; grants no more than a ticket). In-memory; ``time.time`` patchable.

The embedded Chat tab no longer uses (2): every ``/api/pty`` gets its own credential (3)
(``mint_pty_credential``), bound to the login that opened it, multi-use for that PTY's reconnects and
revoked when the PTY ends. A connection authenticated with it IS that login, so the gateway's access
rules, throttle and audit apply to the Chat tab like to any other client. The value still sits in that
one PTY child's environment, readable by processes of the same OS user while the PTY runs; it grants
that one login and nothing after the PTY exits.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Any, Dict, Optional, Tuple

#: Long enough for ``getWsTicket()`` -> open WS, short enough that a leaked ticket is uninteresting.
TTL_SECONDS = 30

_lock = threading.Lock()
_tickets: Dict[str, Tuple[int, Dict[str, Any]]] = {}  # ticket -> (expires_at, info)
_internal_credential: Optional[str] = None  # lazily minted; guarded by ``_lock``
_pty_credentials: Dict[str, Dict[str, Any]] = {}  # per-PTY credential -> the login it carries

#: Identity recorded for internal-credential connections (audit logs distinguish them from tickets).
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


def internal_ws_credential() -> str:
    """Process-lifetime internal WS credential, minted once. Never injected into the SPA or
    returned over REST — only passed to a spawned child via its environment."""
    global _internal_credential
    with _lock:
        if _internal_credential is None:
            _internal_credential = secrets.token_urlsafe(32)
        return _internal_credential


def consume_internal_credential(value: str) -> Dict[str, Any]:
    """Validate an internal credential (NOT single-use); returns the fixed server-internal
    ``{user_id, provider}`` info dict, mirroring ``consume_ticket``. Constant-time compare; any
    value is rejected until a credential has been minted."""
    with _lock:
        expected = _internal_credential
    if not value or expected is None:
        raise TicketInvalid("no internal credential")
    if not secrets.compare_digest(value.encode(), expected.encode()):
        raise TicketInvalid("internal credential mismatch")
    return {"user_id": INTERNAL_USER_ID, "provider": INTERNAL_PROVIDER}


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


def revoke_pty_credential(value: Optional[str]) -> None:
    """End a per-PTY credential (idempotent)."""
    if value:
        with _lock:
            _pty_credentials.pop(value, None)


def _reset_for_tests() -> None:
    """Test-only: drop all tickets and the internal credential."""
    global _internal_credential
    with _lock:
        _tickets.clear()
        _pty_credentials.clear()
        _internal_credential = None
