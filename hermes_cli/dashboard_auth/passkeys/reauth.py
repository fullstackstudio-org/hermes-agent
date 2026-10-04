"""Re-authentication grants for passkey self-enrolment: opening one, checking it where a sign-in starts, and
completing it with the sign-in that comes back.

A grant (``store.py``) lets a signed-in person add a passkey without an enrolment code, by signing in
again. The flow, and who calls what here:

1. ``POST /api/auth/passkeys/reauth/begin`` (the passkey routes): :func:`open_grant` for the caller's
   session. A ``web`` grant (cookie caller) comes with a secret the route puts in the ``hermes_reauth``
   cookie (``cookies.set_reauth_cookie``); a ``native`` grant (bearer caller) has none, its binding is the
   app's PKCE verifier.
2. ``GET /auth/login?reauth=`` and ``GET /auth/native/authorize?reauth=`` (``dashboard_auth/routes.py``):
   :func:`grant_for_login` before any redirect or cookie. A web grant needs this browser's cookie secret, a
   native grant must not come through the web route nor a web grant through the native one.
3. The callback, the password login (web) and ``POST /auth/native/token`` (native): :func:`complete` with
   the session the provider returned. The grant becomes ``fresh`` when that session is the same person of
   the same provider and the provider reports a recent authentication, else ``failed``. The sign-in itself
   always stands (S7): a grant's failure never undoes a login. A fresh native grant gets a one-time
   ``use_secret`` (stored hashed), returned only in the token route's answer.
4. ``register/begin`` and ``register/finish`` (the passkey routes) use the fresh grant with its use binding
   (the web cookie, or the native ``use_secret``); the store checks it and spends the grant with the
   credential insert. The grant id alone, which can end up in an access log or a browser history, is never
   enough.

Everything here is tolerant of the level being off or self-enrolment being disabled: no grant is usable
then (the answer is ``unknown``), and nothing touches the store. The audit lines name the user, provider,
client kind, the first 8 characters of the grant id, a reason and the times compared; never a secret, a
code or a token. Nothing from the identity provider is logged beyond that.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import Session
from hermes_cli.dashboard_auth.passkeys.store import (
    GRANT_CLIENTS, Grant, GrantInvalid, PasskeyStore, StoreError, new_reauth_secret, reauth_secret_hash)
from hermes_cli.dashboard_auth.rate_limit import SlidingWindowLimiter

_log = logging.getLogger(__name__)

#: A grant id as the store mints it: 16 random bytes, base64url without padding.
_GRANT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")

#: Refusals of a ``reauth`` parameter on the public sign-in routes. A refused check costs a config read, a
#: store read and an audit line (also while the level is off), so two budgets apply, both reserved before
#: anything is read (:func:`begin_attempt`: check and count in one step, the slot given back when the grant
#: is found, so concurrent requests cannot overshoot either budget):
#:
#: - per address (:data:`REFUSALS_PER_ADDRESS`), checked FIRST: a wide ceiling on every refusal from one
#:   address, so spraying random well-formed ids ends in 429 instead of costing reads and log lines forever;
#: - per address AND grant id (:data:`REFUSALS_PER_GRANT`): the narrow budget, so one client behind a shared
#:   address (a proxy, a NAT) retrying a dead grant does not use up the ceiling's room for anybody else's
#:   grant long before the ceiling is reached. That protection holds only below the ceiling: once the
#:   address has used it up, every grant from that address gets 429 until the window frees a slot. A
#:   malformed id is not counted here (it costs no store read).
#:
#: Grant ids are 128-bit random, so trying other ids learns nothing either way.
REFUSALS_PER_ADDRESS = SlidingWindowLimiter(200, 600)
REFUSALS_PER_GRANT = SlidingWindowLimiter(20, 600)

#: The page a browser gets for a dead or foreign grant at ``/auth/login`` (400, never a redirect).
EXPIRED_TEXT = "This passkey set-up has expired or was not started here; go back and start again."


@dataclass(frozen=True)
class Policy:
    """``confirm.passkey`` as far as self-enrolment is concerned."""

    level_enabled: bool = False
    self_enrol: bool = True
    accept_missing_auth_time: bool = False

    @property
    def usable(self) -> bool:
        return self.level_enabled and self.self_enrol


@dataclass(frozen=True)
class Opened:
    grant: Grant
    secret: Optional[str]  # web only: the cookie value. Never logged, never in a response body.


@dataclass(frozen=True)
class Outcome:
    """How a sign-in left a grant: ``fresh``, or ``failed`` with a reason (a store failure such as
    ``user_mismatch``, or ``unknown`` / ``not_open`` / ``client_mismatch`` when the grant could not be
    completed at all and was left as it was)."""

    grant_id: str
    state: str  # "fresh" | "failed"
    reason: str = ""
    expires_at: int = 0  # 0 when the grant is unknown
    use_secret: str = field(default="", repr=False)  # a fresh native grant's use binding; never logged

    def body(self) -> dict[str, Any]:
        """The ``reauth`` object of the native token route's answer."""
        out: dict[str, Any] = {"grant_id": self.grant_id, "state": self.state, "expires_at": self.expires_at}
        if self.reason:
            out["reason"] = self.reason
        if self.use_secret:
            out["use_secret"] = self.use_secret
        return out


def is_grant_id(value: object) -> bool:
    return isinstance(value, str) and bool(_GRANT_ID_RE.match(value))


def _short(grant_id: str) -> str:
    return str(grant_id)[:8]


def policy(cfg: Any = None) -> Policy:
    """Read the policy from *cfg* (default: the gateway's config) with the passkey settings' own parser
    (``settings.settings_from_config``), so the sign-in routes and the passkey routes never disagree: an
    unreadable flag, a ``self_enrol`` that is not a mapping or an unreadable cooling-off all mean off. An
    unreadable config never makes a grant usable."""
    from hermes_cli.dashboard_auth.passkeys.settings import load_settings, settings_from_config

    try:
        settings = load_settings() if cfg is None else settings_from_config(cfg)
    except Exception:  # noqa: BLE001 - an unreadable config never enables the level
        _log.warning("passkey self-enrolment: confirm.passkey could not be read", exc_info=False)
        return Policy()
    return Policy(level_enabled=settings.enabled, self_enrol=settings.self_enrol.enabled,
                  accept_missing_auth_time=settings.self_enrol.accept_missing_auth_time)


def provider_reauth_reason(provider: Any) -> str:
    """``""`` when *provider* (a registered provider object, or None) can authenticate the person again on
    request, else ``provider_no_reauth``."""
    if provider is None or not getattr(provider, "supports_session", True):
        return "provider_no_reauth"
    return "" if getattr(provider, "supports_reauth", False) is True else "provider_no_reauth"


def _default_store() -> PasskeyStore:
    # Lazily, and through the passkey routes, so there is one store object per file (and tests that swap
    # the routes' store swap this one too).
    from hermes_cli.dashboard_auth.passkeys import routes as passkey_routes
    return passkey_routes._store()


def session_user(session: Session) -> str:
    """The store's user id of *session*: ``<provider>:<user id>``."""
    return f"{str(session.provider or '').strip()}:{str(session.user_id or '').strip()}"


# ── 1. opening ───────────────────────────────────────────────────────────────────────────────────


def open_grant(*, store: PasskeyStore, user_id: str, provider: str, client: str, ip: str = "",
               auth: str = "") -> Opened:
    """Open a grant for the signed-in *user_id* (``<provider>:<user id>``) of *provider*. ``web`` gets a fresh
    secret for the cookie; ``native`` none. The caller checks the policy, the provider and its rate limits
    first. Raises ``StoreError`` when the store is unavailable."""
    if client not in GRANT_CLIENTS:
        raise ValueError(f"unknown client {client!r}")
    secret = new_reauth_secret() if client == "web" else None
    grant = store.open_grant(user_id, provider, client, reauth_secret_hash(secret) if secret else None)
    audit_log(AuditEvent.PASSKEY_REAUTH_OPENED, user_id=user_id, provider=provider, client=client,
              grant=_short(grant.id), expires_at=grant.expires_at, ip=ip, **({"auth": auth} if auth else {}))
    return Opened(grant=grant, secret=secret)


# ── 2. where a sign-in starts ────────────────────────────────────────────────────────────────────


def _refusal_key(ip: str, grant_id: str) -> str:
    return f"{ip}|{grant_id}"


@dataclass
class Attempt:
    """One ``reauth`` check on a public sign-in route, holding a reserved slot in each refusal budget that
    applies. ``allowed`` False: answer 429 with ``retry_after`` seconds, nothing was reserved. A check that
    found the grant gives its slots back with :meth:`succeeded`; a refusal keeps them (it was counted)."""

    allowed: bool
    retry_after: int = 0
    _slots: list = field(default_factory=list, repr=False)

    def succeeded(self) -> None:
        for limiter, key, stamp in self._slots:
            limiter.release(key, stamp)
        self._slots.clear()


def begin_attempt(ip: str, grant_id: str) -> Attempt:
    """Reserve this attempt in the per-address ceiling (first) and, for a well-formed id, in the per-grant
    budget, before anything is read. Each reservation checks and counts atomically."""
    stamp = REFUSALS_PER_ADDRESS.reserve(ip)
    if stamp is None:
        return Attempt(allowed=False, retry_after=REFUSALS_PER_ADDRESS.retry_after(ip))
    slots = [(REFUSALS_PER_ADDRESS, ip, stamp)]
    if is_grant_id(grant_id):
        key = _refusal_key(ip, grant_id)
        grant_stamp = REFUSALS_PER_GRANT.reserve(key)
        if grant_stamp is None:
            REFUSALS_PER_ADDRESS.release(ip, stamp)
            return Attempt(allowed=False, retry_after=REFUSALS_PER_GRANT.retry_after(key))
        slots.append((REFUSALS_PER_GRANT, key, grant_stamp))
    return Attempt(allowed=True, _slots=slots)


def _refused(*, grant_id: str, provider: str, client: str, reason: str, ip: str, where: str,
             user_id: str = "", **fields: Any) -> None:
    audit_log(AuditEvent.PASSKEY_REAUTH_REFUSED, user_id=user_id, provider=provider, client=client,
              grant=_short(grant_id), reason=reason, at=where, ip=ip, **fields)


def grant_for_login(grant_id: str, *, provider: Any, client: str, secret: Optional[str], ip: str = "",
                    store: Optional[PasskeyStore] = None, cfg: Any = None) -> Optional[Grant]:
    """The open, unexpired *client* grant a sign-in with *provider* (a provider object) may start for, or None
    (audited; the caller counts it with the :class:`Attempt` it reserved). A ``web`` grant needs this browser's cookie
    *secret*; a ``native`` one is looked up without a secret and must be a native grant. Never raises."""
    name = str(getattr(provider, "name", "") or "")
    reason = ""
    grant: Optional[Grant] = None
    if not is_grant_id(grant_id):
        reason = "malformed"
    elif not policy(cfg).usable:
        reason = "unknown"
    elif provider_reauth_reason(provider):
        reason = "provider_no_reauth"
    elif client == "web" and not secret:
        reason = "client_mismatch"  # no binding cookie in this browser: the link attack ends here
    else:
        try:
            grant = (store or _default_store()).grant_for_login(
                grant_id, name, secret if client == "web" else None)
        except StoreError:
            _log.warning("passkey self-enrolment: the passkey store is unavailable", exc_info=False)
            grant, reason = None, "unavailable"
        if grant is None and not reason:
            reason = "unknown"
        elif grant is not None and grant.client != client:
            grant, reason = None, "client_mismatch"
    if grant is None:
        _refused(grant_id=grant_id if is_grant_id(grant_id) else "", provider=name, client=client, reason=reason,
                 ip=ip, where="start")
    return grant


def native_grant_for_login(grant_id: str, *, providers: list, ip: str = "",
                           store: Optional[PasskeyStore] = None, cfg: Any = None) -> tuple[Any, Optional[Grant]]:
    """A native authorize request named no provider: the grant names it. ``(provider, grant)`` for the one
    of *providers* the open native grant belongs to, else ``(None, None)`` (refused once, audited)."""
    if is_grant_id(grant_id) and policy(cfg).usable:
        try:
            store = store or _default_store()
            for provider in providers:
                if provider_reauth_reason(provider):
                    continue
                grant = store.grant_for_login(grant_id, str(provider.name), None)
                if grant is not None and grant.client == "native":
                    return provider, grant
        except StoreError:
            _log.warning("passkey self-enrolment: the passkey store is unavailable", exc_info=False)
    _refused(grant_id=grant_id if is_grant_id(grant_id) else "", provider="", client="native",
             reason="unknown" if is_grant_id(grant_id) else "malformed", ip=ip, where="start")
    return None, None


# ── 3. completing ────────────────────────────────────────────────────────────────────────────────


def complete(grant_id: str, session: Session, *, client: str, secret: Optional[str], ip: str = "",
             store: Optional[PasskeyStore] = None, cfg: Any = None) -> Outcome:
    """Complete *grant_id* with the *session* a sign-in just produced (``web``: with the cookie *secret*;
    ``native``: at the token route, no secret). Audited either way; never raises, and never undoes the
    sign-in. A web completion without the cookie, or with another grant's, leaves the grant as it was (the
    store refuses to let anyone without the binding change it) and answers ``client_mismatch``."""
    user = session_user(session)
    provider = str(session.provider or "")
    pol = policy(cfg)
    reason = ""
    if not is_grant_id(grant_id):
        reason = "unknown"
    elif not pol.usable:
        reason = "unknown"
    elif client == "web" and not secret:
        reason = "client_mismatch"
    if reason:
        _refused(grant_id=grant_id, provider=provider, client=client, reason=reason, ip=ip, where="complete",
                 user_id=user)
        return Outcome(grant_id=grant_id, state="failed", reason=reason)
    use_secret = new_reauth_secret() if client == "native" else ""
    try:
        grant = (store or _default_store()).complete_grant(
            grant_id, session_user=user, session_provider=provider, auth_time=int(session.auth_time or 0),
            client=client, secret=secret if client == "web" else None,
            use_secret_hash=reauth_secret_hash(use_secret) if use_secret else None,
            accept_missing=pol.accept_missing_auth_time)
    except GrantInvalid as refusal:
        # "unknown" to the store also covers a grant of the other kind of client and a web secret that does
        # not match; at this point, for a web sign-in, it means this browser holds another grant's cookie (or a
        # stale one), or the grant is the app's: the binding failed. Nothing changed either way, so a tossed
        # PKCE cookie naming somebody's grant cannot fail it.
        reason = "client_mismatch" if client == "web" and refusal.reason == "unknown" else refusal.reason
        _refused(grant_id=grant_id, provider=provider, client=client, reason=reason, ip=ip, where="complete",
                 user_id=user)
        return Outcome(grant_id=grant_id, state="failed", reason=reason)
    except StoreError:
        _log.warning("passkey self-enrolment: the passkey store is unavailable", exc_info=False)
        _refused(grant_id=grant_id, provider=provider, client=client, reason="unavailable", ip=ip,
                 where="complete", user_id=user)
        return Outcome(grant_id=grant_id, state="failed", reason="unavailable")
    times = {"auth_time": int(session.auth_time or 0), "grant_created_at": grant.created_at}
    if grant.state == "fresh":
        audit_log(AuditEvent.PASSKEY_REAUTH_FRESH, user_id=user, provider=provider, client=client,
                  grant=_short(grant.id), auth_time_assumed=grant.auth_time_assumed, ip=ip, **times)
        return Outcome(grant_id=grant.id, state="fresh", expires_at=grant.expires_at, use_secret=use_secret)
    _refused(grant_id=grant.id, provider=provider, client=client, reason=grant.failure, ip=ip, where="complete",
             user_id=user, **times)
    return Outcome(grant_id=grant.id, state="failed", reason=grant.failure, expires_at=grant.expires_at)


def reset_for_tests() -> None:
    REFUSALS_PER_ADDRESS.reset()
    REFUSALS_PER_GRANT.reset()


__all__ = ["Attempt", "EXPIRED_TEXT", "Opened", "Outcome", "Policy", "REFUSALS_PER_ADDRESS", "REFUSALS_PER_GRANT",
           "complete",
           "grant_for_login", "is_grant_id", "native_grant_for_login", "open_grant", "policy", "begin_attempt",
           "provider_reauth_reason", "reset_for_tests", "session_user"]
