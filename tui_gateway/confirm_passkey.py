"""The ``confirm`` level ``passkey``: a confirmation the gateway verifies itself.

``tui_gateway/confirm.py`` owns the request (text, outcomes, rate limit, audit, the no-downgrade window);
this module owns what is particular to the level. It implements ``contract/confirm-passkey/README.md`` §8
and §9 on top of ``hermes_cli/dashboard_auth/passkeys`` (verifier, store, settings).

One request, in order:

1. :func:`open` decides, before anything is sent, whether the level can work here, and raises
   :class:`Unavailable` with the reason when not: ``disabled`` (``confirm.passkey.enabled`` is false),
   ``no_base_url`` / ``private_origin`` (the operator listed no usable base URL), ``no_identity`` (nobody
   on this session is signed in: session-token, loopback or stdio mode), ``no_acting_user`` (the running
   turn was not submitted by a signed-in person: cron, a relayed message, a crash continuation, or no turn
   at all), ``not_enrolled`` (the bound user has no active credential for an accepted RP),
   ``settings_unavailable`` / ``store_unavailable``.
2. The BOUND USER is the running turn's submitter as the gateway itself resolved it
   (``server._turn_auth_user``, bound by ``prompt_turn.run_body`` from the WS-upgrade credential of the
   connection that submitted the turn, carried into tool threads with the turn's context). It is never
   read from tool arguments, the session record or a watching peer, and it must equal
   ``server._acting_auth_user`` for the session (checked).
3. A :class:`Verification` is the request's context: the bound user, a fresh 32-byte nonce, the request
   id (minted here: the challenge commits to it), the gateway context, and a SNAPSHOT of the user's
   active credentials. Its :meth:`Verification.target` is ``send_gated``'s target predicate: a connection
   signed in as the bound user that advertised ``passkey`` with an accepted RP the user has a credential
   for. The same predicate decides who gets the frame, who may answer and who sees it on reconnect. A
   request with structured ``fields`` is version 2 (contract §4.1: ``text_digest_v2``, ``passkey.v: 2``) and
   its target also needs ``confirm_passkey {v: 2}`` and ``confirm_fields: true``: a version-1 client never
   gets a frame whose text it would hash differently, or show without its fields.
4. :meth:`Verification.validate` is the pure validator ``send_gated`` runs on every answer, under its
   lock and again from ``request.answer``: no I/O, memoised per answer
   (``webauthn.memoised_assertion_validator``). A decline is exactly ``{decision: declined, method: tap}``
   and needs no assertion. Five refused answers settle the request ``unavailable (verification_failed)``
   (``send_gated(max_refusals=5)``); each refusal is audited (``confirm_passkey_refused``) outside the lock.
5. :meth:`Verification.settle` runs once, after the request settled, outside every lock: the only place
   with side effects. It commits the assertion (the store re-reads the credential: revoked meanwhile →
   refused; applies the counter rule with compare-and-set; writes the receipt), audits
   ``confirm_passkey_verified`` (with ``counter_warning``) and is the ONLY place ``verified: true`` is set.
   A refused commit or any store error is ``unavailable (verification_failed)``, never consent, and the
   clients get ``request.cancel {reason: verification_failed}``: ``request.answer`` → ``ok`` meant
   "received and valid", not "confirmed".

Nothing here logs or audits a title, summary, detail, nonce, signature or client data.
"""

from __future__ import annotations

import logging
import math
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from hermes_cli.dashboard_auth.passkeys.challenge import GatewayContext, b64u, field_tuple
from hermes_cli.dashboard_auth.passkeys.settings import PasskeySettings, gateway_context, load_settings
from hermes_cli.dashboard_auth.passkeys.store import CommitRefused, PasskeyStore, StoreError, default_path
from hermes_cli.dashboard_auth.passkeys.webauthn import (
    AssertionOk, AssertionRequest, StoredCredential, memoised_assertion_validator)

logger = logging.getLogger(__name__)

VERSION = 1
#: The ``confirm_passkey.v`` values a client may advertise: 2 also computes ``text_digest_v2`` (contract §4.1).
VERSIONS = (1, 2)
NONCE_BYTES = 32
#: Refused answers (from connections allowed to answer) after which the request is settled ``unavailable``.
MAX_REFUSALS = 5
PRUNE_EVERY_S = 3600.0
KINDS = ("native", "web")
DECLINE = {"decision": "declined", "method": "tap"}

#: Reasons :func:`open` gives for a request that is ``unavailable`` before anything is sent.
OPEN_REASONS = ("disabled", "no_base_url", "private_origin", "no_identity", "no_acting_user", "not_enrolled",
                "settings_unavailable", "store_unavailable")


class Unavailable(Exception):
    """The level cannot work for this request; ``reason`` is one of :data:`OPEN_REASONS`. Nothing was sent."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── settings and store ────────────────────────────────────────────────────────────────────────

_stores: dict[str, PasskeyStore] = {}
_stores_lock = threading.Lock()
_prune_lock = threading.Lock()
_last_prune: dict[str, float] = {}


def _settings() -> PasskeySettings:
    return load_settings()


def _store() -> PasskeyStore:
    """One store object per file (``$HERMES_HOME/dashboard_auth/passkeys.db``), so its identity is read once."""
    path = str(default_path())
    with _stores_lock:
        store = _stores.get(path)
        if store is None:
            store = _stores[path] = PasskeyStore(path)
        return store


def _maybe_prune(store: PasskeyStore, settings: PasskeySettings) -> None:
    """Receipts, old codes and closed ceremonies age out here too, at most once an hour per store, after a
    request has settled (never on the way to sending one)."""
    now = time.monotonic()
    with _prune_lock:
        last = _last_prune.get(str(store.path))
        if last is not None and now - last < PRUNE_EVERY_S:
            return
        _last_prune[str(store.path)] = now
    try:
        store.prune(receipts_days=settings.receipts_days)
    except StoreError:
        logger.warning("passkey store: pruning failed")


def reset_for_tests() -> None:
    with _stores_lock:
        _stores.clear()
    with _prune_lock:
        _last_prune.clear()


def _audit(event: str, **fields: Any) -> None:
    # Through confirm's sink, so one test seam captures every confirm audit record.
    from tui_gateway import confirm
    confirm._audit_sink(event, **fields)


def _login(transport: Any) -> str | None:
    from tui_gateway import server
    return server._transport_auth_user_id(transport)


# ── capability (``client.capabilities``) ─────────────────────────────────────────────────────────


def _rps(ctx: GatewayContext) -> dict:
    return {"native": sorted(ctx.native_rp_ids), "web": sorted(ctx.web_rp_ids)}


def capability(transport: Any) -> dict:
    """The ``confirm_passkey`` object of a ``client.capabilities`` result for *transport* (contract §8)."""
    off = {"v": VERSION, "enabled": False, "gateway_id": "", "rp": {"native": [], "web": []},
           "versions": list(VERSIONS)}
    try:
        settings = _settings()
    except Exception:  # noqa: BLE001 - an unreadable config never enables the level
        logger.warning("confirm passkey: confirm.passkey could not be read")
        return {**off, "reason": "disabled"}
    if not settings.enabled:
        return {**off, "reason": "disabled"}
    try:
        ctx = gateway_context(_store().identity(), settings)
    except StoreError:
        logger.warning("confirm passkey: the passkey store is unavailable")
        return {**off, "reason": "store_unavailable"}
    reason = ctx.capability_reason(enabled=True, identity=_login(transport) is not None)
    return {"v": VERSION, "enabled": reason == "", "reason": reason, "gateway_id": b64u(ctx.gateway_id),
            "rp": _rps(ctx), "versions": list(VERSIONS)}


def accept_advertisement(transport: Any, advertisement: Any) -> dict | None:
    """The detail ``server_requests.advertise`` records with ``passkey`` for *transport*, or None when the
    level must not be accepted from it: the level is not enabled here, the connection has no signed-in user,
    ``v`` is not one of :data:`VERSIONS`, or ``{v, kind, rp_id}`` names an RP this gateway does not accept for
    that kind. The detail keeps ``v``: a version-2 frame goes only where it is 2. Whether the user has a
    credential is decided per request."""
    if not isinstance(advertisement, dict) or type(advertisement.get("v")) is not int \
            or advertisement.get("v") not in VERSIONS:
        return None
    kind, rp_id = advertisement.get("kind"), advertisement.get("rp_id")
    if kind not in KINDS or not isinstance(rp_id, str) or _login(transport) is None:
        return None
    try:
        settings = _settings()
        if not settings.enabled:
            return None
        ctx = gateway_context(_store().identity(), settings)
    except Exception:  # noqa: BLE001 - config or store unreadable: the level is not offered
        logger.warning("confirm passkey: advertisement not accepted, settings or store unavailable")
        return None
    if ctx.capability_reason(enabled=True, identity=True):
        return None
    accepted = ctx.native_rp_ids if kind == "native" else ctx.web_rp_ids
    return {"kind": kind, "rp_id": rp_id, "v": advertisement["v"]} if rp_id in accepted else None


# ── the bound user ────────────────────────────────────────────────────────────────────────────


def bound_user(session: dict | None) -> tuple[str, str]:
    """``(<provider>:<user id>, display name)`` of the person a ``passkey`` request in the RUNNING turn is for.

    Only the turn's submitter as ``prompt_turn`` bound it (``server._turn_auth_user``): that value comes from
    the WS-upgrade credential of the connection that submitted the turn and reaches tool threads with the
    turn's context. Not the session record (in a shared chat that is whoever created it), not a watching
    peer, not tool arguments. Raises :class:`Unavailable` (``no_identity`` / ``no_acting_user``)."""
    from tui_gateway import server
    turn = server._turn_auth_user.get()
    if turn is None or turn is server._UNATTRIBUTED_TURN or not turn[0]:
        raise Unavailable(_nobody_reason(session))
    acting = server._acting_auth_user(session)
    if acting[0] != turn[0]:  # by construction equal; anything else is a resolver change to look at
        logger.warning("confirm passkey: the turn's submitter and the acting user differ; refusing")
        raise Unavailable("no_acting_user")
    return str(acting[0]), acting[1]


def _nobody_reason(session: dict | None) -> str:
    """``no_identity`` when nobody on this session is signed in at all (session-token, loopback or stdio
    mode), else ``no_acting_user`` (signed-in people are here, but none of them submitted this turn)."""
    from tui_gateway import server
    # ``session_transports`` helpers are bound onto the server module at import (``method_ctx.bind_module``);
    # imported directly they would run without the server's globals.
    session_auth_logins = getattr(server, "_session_auth_logins")
    session = session or {}
    if session.get("auth_user_id") or session_auth_logins(session):
        return "no_acting_user"
    return "no_identity"


# ── one request ───────────────────────────────────────────────────────────────────────────────


def _is_decline(result: Any) -> bool:
    return isinstance(result, dict) and set(result) == set(DECLINE) \
        and all(isinstance(result[k], str) and result[k] == v for k, v in DECLINE.items())


def _field(result: Any, key: str, limit: int) -> str:
    """One string of the client's ``passkey`` object for an audit line (untrusted: bounded, never raw bytes)."""
    passkey = result.get("passkey") if isinstance(result, dict) else None
    value = passkey.get(key) if isinstance(passkey, dict) else None
    return value[:limit] if isinstance(value, str) else ""


@dataclass
class Verification:
    """The verification context of one ``passkey`` request (built by :func:`open`)."""

    max_refusals = MAX_REFUSALS  # class constant, not a field

    sid: str
    request_id: str
    user_id: str
    user_name: str
    nonce: bytes
    expires_at: int
    settings: PasskeySettings
    store: PasskeyStore
    ctx: GatewayContext
    snapshot: tuple[StoredCredential, ...]  # the user's active credentials for accepted RPs, at open
    title: str
    summary: str
    detail: str | None
    #: The frame's structured fields as ``challenge.field_tuple`` values (empty: a version-1 request).
    fields: tuple = ()
    enrolled_rps: frozenset = field(init=False)
    _request: AssertionRequest = field(init=False, repr=False)
    _validator: Callable[[Any], Any] = field(init=False, repr=False)
    # The memo is a plain OrderedDict; the frame path (under send_gated's lock) and request.answer threads
    # share it. Order is always send_gated's lock → this one, never the reverse: no deadlock.
    _memo_lock: Any = field(init=False, repr=False, default_factory=threading.Lock)
    # ``server_requests.shows_confirm_fields_locked``, bound here so the target predicate imports nothing.
    _shows_fields: Callable[[Any], bool] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        from tui_gateway import server_requests
        self._shows_fields = server_requests.shows_confirm_fields_locked
        self.enrolled_rps = frozenset(c.rp_id for c in self.snapshot)
        self._request = AssertionRequest(user_id=self.user_id, request_id=self.request_id, nonce=self.nonce,
                                         title=self.title, summary=self.summary, detail=self.detail,
                                         session_id=self.sid, purpose="confirm", fields=self.fields)
        memo = memoised_assertion_validator(self.ctx, self._request, self.snapshot)

        def validator(answer: Any) -> Any:
            with self._memo_lock:
                return memo(answer)

        self._validator = validator

    @property
    def text_digest(self) -> bytes:
        return self._request.text_digest

    @property
    def version(self) -> int:
        """2 for a request with structured fields (``text_digest_v2``), else 1."""
        return self._request.version

    def params(self) -> dict:
        """The ``passkey`` object added to the frame's params (contract §8)."""
        by_rp: dict[str, list[str]] = {}
        for credential in self.snapshot:
            by_rp.setdefault(credential.rp_id, []).append(b64u(credential.credential_id))
        return {"passkey": {"v": self.version, "nonce": b64u(self.nonce), "gateway_id": b64u(self.ctx.gateway_id),
                            "base_url": self.ctx.accepted_base_urls[0], "expires_at": self.expires_at,
                            "user": {"id": self.user_id, "name": self.user_name},
                            "credentials": [{"rp_id": rp, "ids": ids} for rp, ids in sorted(by_rp.items())]}}

    # ── under send_gated's lock: pure, no I/O ──

    def target(self, transport: Any, detail: Any) -> bool:
        """``send_gated``'s target predicate: signed in as the bound user, advertised ``passkey`` with an RP
        this gateway accepts for its kind, and the user has an active credential for that RP. A version-2
        request (structured fields) also needs ``confirm_passkey {v: 2}`` and ``confirm_fields: true``."""
        if _login(transport) != self.user_id or not isinstance(detail, dict):
            return False
        if self.version >= 2 and (detail.get("v") != 2 or not self._shows_fields(transport)):
            return False
        kind, rp_id = detail.get("kind"), detail.get("rp_id")
        accepted = self.ctx.native_rp_ids if kind == "native" else self.ctx.web_rp_ids if kind == "web" else ()
        return rp_id in accepted and rp_id in self.enrolled_rps

    def validate(self, result: Any) -> str | None:
        """None for an answer that may settle the request (a valid assertion, or a decline), else the
        refusal reason of contract §9. Pure and memoised: it runs under the request lock and twice per
        ``request.answer``."""
        if _is_decline(result):
            return None
        verdict = self._validator(result)
        return None if isinstance(verdict, AssertionOk) else verdict.reason

    # ── outside every lock ──

    def on_refusal(self, transport: Any, reason: str, result: Any, exhausted: bool) -> None:
        """One audit line per counted refusal (``send_gated`` calls it outside its lock)."""
        login, peer = _peer(transport)
        _audit("confirm_passkey_refused", user_id=self.user_id, session_id=self.sid, request_id=self.request_id,
               reason=reason, refusals_exhausted=exhausted, credential=_field(result, "credential_id", 16),
               rp_id=_field(result, "rp_id", 253), base_url=_field(result, "base_url", 512),
               text_digest=self.text_digest.hex(), answered_by=login, answered_from=peer)

    def settle(self, answer: dict, answered_by: Any) -> tuple[str, str, bool, str]:
        """Called once, after the request settled with *answer*: ``(outcome, method, verified, reason)``.
        The only place a confirmation becomes ``verified``."""
        if _is_decline(answer):
            return "declined", "tap", False, ""
        verdict = self._validator(answer)
        login, peer = _peer(answered_by)
        fields = dict(user_id=self.user_id, session_id=self.sid, request_id=self.request_id,
                      text_digest=self.text_digest.hex(), answered_by=login, answered_from=peer)
        if not isinstance(verdict, AssertionOk):  # cannot happen: send_gated only settles validated answers
            _audit("confirm_passkey_refused", reason=getattr(verdict, "reason", "refused"), **fields)
            return "unavailable", "", False, "verification_failed"
        fields.update(credential=b64u(verdict.credential_id)[:16], rp_id=verdict.rp_id, base_url=verdict.base_url)
        used = next(c for c in self.snapshot if c.credential_id == verdict.credential_id)
        try:
            committed = self.store.commit_assertion(verdict, user_id=self.user_id, snapshot=used)
        except CommitRefused as exc:
            _audit("confirm_passkey_refused", reason=exc.reason, at_commit=True, **fields)
            return self._commit_failed()
        except StoreError:
            logger.warning("confirm passkey: the passkey store failed at commit")
            _audit("confirm_passkey_refused", reason="store_error", at_commit=True, **fields)
            return self._commit_failed()
        _audit("confirm_passkey_verified", receipt_id=committed.receipt_id,
               counter_warning=committed.counter_warning, sign_count=committed.credential.sign_count, **fields)
        _maybe_prune(self.store, self.settings)
        return "confirmed", "passkey", True, ""

    def _commit_failed(self) -> tuple[str, str, bool, str]:
        """The answer was valid (``request.answer`` said ``ok``) but did not commit: tell the clients it did
        not count (``request.cancel {reason: verification_failed}``), so none keeps showing "Confirmed"."""
        from tui_gateway import server_requests
        server_requests.withdraw_settled(self.sid, self.request_id, "confirm", "verification_failed")
        return "unavailable", "", False, "verification_failed"


def _peer(transport: Any) -> tuple[str, str]:
    if transport is None:
        return "-", "-"
    return _login(transport) or "-", str(getattr(transport, "_peer", "") or "-")


def open(sid: str, params: dict, *, timeout: float) -> Verification:  # noqa: A001 - the request's verb
    """The verification context for a ``passkey`` request in session *sid* with the built *params*, or
    :class:`Unavailable` with the reason nothing will be sent. Reads the config and the store (I/O), so it
    runs before ``send_gated`` and never under its lock."""
    from tui_gateway import server, server_requests
    try:
        settings = _settings()
    except Exception:  # noqa: BLE001 - an unreadable config never enables the level
        logger.warning("confirm passkey: confirm.passkey could not be read")
        raise Unavailable("settings_unavailable") from None
    if not settings.enabled:
        raise Unavailable("disabled")
    try:
        store = _store()
        ctx = gateway_context(store.identity(), settings)
    except StoreError:
        logger.warning("confirm passkey: the passkey store is unavailable")
        raise Unavailable("store_unavailable") from None
    reason = ctx.capability_reason(enabled=True, identity=True)
    if reason:
        raise Unavailable(reason)
    user_id, user_name = bound_user(server._sessions.get(sid))
    accepted_rps = ctx.native_rp_ids | ctx.web_rp_ids
    try:
        snapshot = tuple(c for c in store.snapshot(user_id) if c.rp_id in accepted_rps)
        now = store.now()
    except StoreError:
        logger.warning("confirm passkey: the passkey store is unavailable")
        raise Unavailable("store_unavailable") from None
    if not snapshot:
        raise Unavailable("not_enrolled")
    return Verification(sid=sid, request_id=server_requests.new_request_id(), user_id=user_id,
                        user_name=user_name, nonce=secrets.token_bytes(NONCE_BYTES),
                        expires_at=now + math.ceil(timeout), settings=settings, store=store, ctx=ctx,
                        snapshot=snapshot, title=params["title"], summary=params["summary"],
                        detail=params.get("detail"),
                        fields=tuple(field_tuple(f) for f in params.get("fields") or ()))


__all__ = ["DECLINE", "MAX_REFUSALS", "OPEN_REASONS", "VERSIONS", "Unavailable", "Verification", "accept_advertisement",
           "bound_user", "capability", "open"]
