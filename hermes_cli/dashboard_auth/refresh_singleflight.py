"""Single-flight + short replay cache for rotating refresh tokens (both refresh paths).

Rotating refresh tokens with reuse detection (Nous Portal, Authelia, most OIDC IdPs) make a
replay of an already-rotated RT fatal: the provider revokes the whole session. The desktop and
the browser both fire bursts of parallel requests on wake or after the access token lapses,
each still carrying the same old RT, so the gateway must let exactly ONE of them reach the
provider and hand the rotated session to the rest. The cookie gate (``middleware``) and the
native bearer route (``routes.auth_native_refresh``) share this one flight table.

A provider hint only orders discovery: it must neither split one rotating credential's lock
nor let an unrelated provider reuse its result. Raw refresh tokens are never keys.

A native revoke (``routes.auth_native_revoke``) takes the same flight, so it waits out a rotation
of the token already under way, and then drops the token's cached result: otherwise a refresh
arriving within the replay window would still be handed the session the revoked token produced.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from hermes_cli.dashboard_auth import list_session_providers
from hermes_cli.dashboard_auth.base import DashboardAuthProvider, RefreshExpiredError, Session
from hermes_cli.dashboard_auth.request_utils import scan_session_providers

# The success TTL covers the window between the winning response and the siblings' arrival
# (a laptop waking from sleep can deliver its burst over many seconds); the failure TTL only
# absorbs a retry storm against a token the provider has already declared dead.
_SUCCESS_TTL = 30.0
_FAILURE_TTL = 5.0
_MAX_ENTRIES = 256
_guard = threading.Lock()


@dataclass
class _Flight:
    lock: threading.Lock = field(default_factory=threading.Lock)
    users: int = 0


# Hold the provider itself while caching: replacement (including same-name scoped
# registrations) invalidates identity, and Python cannot recycle its id under a live entry.
_cache: dict[tuple[int, bytes], tuple[float, DashboardAuthProvider, Session | None]] = {}
_flights: dict[tuple[int, bytes], _Flight] = {}


def _prune(now: float) -> None:
    for key, (expires, _, _) in list(_cache.items()):
        if expires <= now:
            del _cache[key]
    while len(_cache) > _MAX_ENTRIES:
        del _cache[min(_cache, key=lambda key: _cache[key][0])]


def _token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


@contextmanager
def _holding_flight(key: tuple[int, bytes]) -> Iterator[None]:
    """Hold the one flight lock for ``key`` (created on first use, dropped by its last user)."""
    with _guard:
        _prune(time.monotonic())
        flight = _flights.setdefault(key, _Flight())
        flight.users += 1
    try:
        with flight.lock:
            yield
    finally:
        with _guard:
            flight.users -= 1
            if flight.users == 0:
                _flights.pop(key, None)


def _refresh_provider(provider: DashboardAuthProvider, token: str) -> Session | None:
    # Keyed on the token alone: whoever presents this RT already owns the session, and a client
    # that changed network between two requests of one burst must still hit the cache.
    key = (id(provider), _token_digest(token))
    with _holding_flight(key):
        with _guard:
            cached = _cache.get(key)
            if cached is not None and cached[0] > time.monotonic():
                return cached[2]
        try:
            session = provider.refresh_session(refresh_token=token)
        except RefreshExpiredError:
            session = None
        # ProviderError and unexpected execution failures are deliberately not cached.
        with _guard:
            now = time.monotonic()
            _cache[key] = (now + (_SUCCESS_TTL if session is not None else _FAILURE_TTL), provider, session)
            _prune(now)
        return session


def refresh_session_coalesced(
    token: str, provider_hint: str, *, phase: str, log: logging.Logger,
    on_rejected: Optional[Callable[[DashboardAuthProvider], None]] = None,
    on_unreachable: Optional[Callable[[DashboardAuthProvider], None]] = None,
) -> Optional[tuple[Session, str]]:
    """Rotate ``token`` through the provider stack with per-provider single-flight.

    ``(Session, provider_name)`` or ``None`` when every provider rejects the token; a
    ``ProviderError`` propagates when nothing rotated and one provider was unreachable
    (``scan_session_providers`` semantics, so callers keep their 503-not-relogin handling).
    Synchronous and network-bound: async callers run it in a threadpool.
    """
    def _call(provider: DashboardAuthProvider):
        session = _refresh_provider(provider, token)
        if session is None:
            if on_rejected is not None:
                on_rejected(provider)
            return None
        return session, provider.name

    return scan_session_providers(
        provider_hint, _call, phase=phase, log=log, on_unreachable=on_unreachable)


def revoke_targets(provider_hint: str) -> list[DashboardAuthProvider]:
    """The session providers a revoke of a token with this hint is handed to.

    A hint naming a registered session provider selects that provider alone. That is what refresh
    reaches for a correct hint (the hinted provider goes first and rotates the token), and here it
    is also what keeps a token away from every other provider: a revoke cannot tell which provider
    owns an opaque token, and handing a password provider's live refresh token to an OIDC
    provider's revocation endpoint would disclose it to that identity provider. Without a hint, or
    with one that names no registered provider, every session provider in registration order, as
    refresh and ``/auth/logout`` do."""
    providers = list_session_providers()
    hinted = [p for p in providers if provider_hint and p.name == provider_hint]
    return hinted[:1] or providers


def revoke_session_coalesced(
    token: str, provider_hint: str, *, log: logging.Logger) -> list[DashboardAuthProvider]:
    """Best-effort revoke of ``token`` at :func:`revoke_targets`; returns the providers it was
    handed to. Never raises.

    Each provider's revoke runs under that token's refresh flight, so it waits for a rotation
    already under way, and every cached refresh result for the token is dropped afterwards.
    A provider's failure is logged by exception class only: neither the token nor anything a
    provider sent back reaches the log. Synchronous and network-bound: async callers run it in a
    threadpool."""
    digest = _token_digest(token)
    targets = revoke_targets(provider_hint)
    for provider in targets:
        with _holding_flight((id(provider), digest)):
            try:
                provider.revoke_session(refresh_token=token)
            except Exception as e:  # noqa: BLE001 -- best effort; the protocol says must not raise
                log.warning("dashboard-auth: revoke on %r failed (%s)", provider.name,
                            type(e).__name__)
            # Still inside the flight, so no refresh of this token can read the entry in between.
            with _guard:
                for key in [key for key in _cache if key[1] == digest]:
                    del _cache[key]
    return targets
