"""A strict, small WebAuthn verifier for the confirm level ``passkey`` (ES256 only, on ``cryptography``).

It implements ``contract/confirm-passkey/README.md`` §9 (assertions) and §11 (registrations) in exactly
that step order; the first failing step names the refusal. Everything is a pure function of its inputs:
no I/O, no clock, no logging, no global state, so the ``confirm`` answer path can run it under its lock
and run it twice for one answer. Garbage never raises: every failure is a :class:`Refusal`.

What it does not do: decide whether a request is still open, whether an enrolment code is valid, whether
a credential id is already stored, or store anything. Those are the caller's (the store commits a
counter with compare-and-set and refuses a credential revoked meanwhile).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hermes_cli.dashboard_auth.passkeys import cbor
from hermes_cli.dashboard_auth.passkeys.challenge import (
    GatewayContext, b64u, b64u_decode, challenge, host_of, origin_of, text_digest, user_handle)

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80
ALG_ES256 = -7

#: README §9 refusal reasons, in order (``too_many_attempts`` is the caller's: it counts refusals).
ASSERTION_REASONS = ("bad_shape", "unknown_credential", "rp_not_accepted", "base_url_not_accepted",
                     "rp_host_mismatch", "bad_client_data", "challenge_mismatch", "bad_authenticator_data",
                     "uv_required", "backup_state_mismatch", "signature_invalid", "counter_regression")
#: README §11 refusal reasons, in order.
REGISTRATION_REASONS = ("bad_shape", "rp_not_accepted", "base_url_not_accepted", "rp_host_mismatch",
                        "bad_client_data", "challenge_mismatch", "bad_attestation_object",
                        "bad_authenticator_data", "uv_required", "unsupported_algorithm", "bad_public_key")

_ANSWER_KEYS = frozenset({"decision", "method", "passkey"})
_PASSKEY_KEYS = frozenset({"v", "rp_id", "base_url", "credential_id", "authenticator_data", "client_data_json",
                           "signature"})
_PASSKEY_OPTIONAL = frozenset({"user_handle"})


# ── inputs and results ────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class StoredCredential:
    """One credential as the store holds it (a snapshot taken when the request opened)."""

    credential_id: bytes
    user_id: str
    rp_id: str
    public_x: bytes
    public_y: bytes
    sign_count: int
    backup_eligible: bool
    active: bool = True


@dataclass(frozen=True)
class AssertionRequest:
    """What the assertion must commit to (README §5). For ``confirm``: the frame's session id, JSON-RPC id,
    nonce and text. For a step-up (``invite`` / ``revoke``): ``session_id`` ``""``, ``request_id`` the
    step-up id, title and detail ``""``, summary the subject."""

    user_id: str
    request_id: str
    nonce: bytes
    title: str
    summary: str
    detail: str | None
    session_id: str = ""
    purpose: str = "confirm"

    @property
    def text_digest(self) -> bytes:
        return text_digest(self.title, self.summary, self.detail)


@dataclass(frozen=True)
class PendingRegistration:
    """An open registration created by ``register/begin``."""

    registration_id: str
    user_id: str
    rp_id: str
    base_url: str
    name: str
    nonce: bytes


@dataclass(frozen=True)
class Refusal:
    reason: str

    @property
    def ok(self) -> bool:
        return False


@dataclass(frozen=True)
class AssertionOk:
    credential_id: bytes
    rp_id: str
    base_url: str
    sign_count: int
    backup_eligible: bool
    backed_up: bool
    counter_warning: bool  # a synced credential's counter went down: audit, do not refuse (README §9 step 12)
    challenge: bytes
    text_digest: bytes
    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes
    # The request the signature was checked against, so the store commits it to exactly that request
    # (a step-up is taken by its own id and nonce, never by another one of the same user).
    user_id: str
    purpose: str
    session_id: str
    request_id: str
    nonce: bytes

    @property
    def ok(self) -> bool:
        return True


@dataclass(frozen=True)
class RegistrationOk:
    credential_id: bytes
    rp_id: str
    alg: int
    public_x: bytes
    public_y: bytes
    sign_count: int
    backup_eligible: bool
    backed_up: bool
    aaguid: bytes
    transports: tuple[str, ...]
    # The open registration the attestation was checked against; the store takes exactly that one.
    registration_id: str
    user_id: str
    nonce: bytes

    @property
    def ok(self) -> bool:
        return True


class _Refuse(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── shared steps ──────────────────────────────────────────────────────────────────────────────


def _json_object_without_duplicates(raw: bytes) -> dict:
    """``client_data_json`` as a JSON object; duplicate keys at any level are refused."""

    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if not isinstance(value, dict):
        raise ValueError("not an object")
    return value


def _rp_kind(ctx: GatewayContext, rp_id: str, base_url: str) -> str:
    """Steps rp_not_accepted, base_url_not_accepted, rp_host_mismatch; ``"native"`` or ``"web"``."""
    if rp_id in ctx.native_rp_ids:
        kind = "native"
    elif rp_id in ctx.web_rp_ids:
        kind = "web"
    else:
        raise _Refuse("rp_not_accepted")
    if base_url not in ctx.accepted_base_urls:
        raise _Refuse("base_url_not_accepted")
    if kind == "web" and host_of(base_url) != rp_id:
        raise _Refuse("rp_host_mismatch")
    return kind


def _client_data(raw: bytes, *, type_: str, kind: str, rp_id: str, base_url: str, ctx: GatewayContext) -> dict:
    """Step bad_client_data. Fields are read by name; the bytes are never compared with a template."""
    try:
        cd = _json_object_without_duplicates(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise _Refuse("bad_client_data") from exc
    if cd.get("type") != type_ or not isinstance(cd.get("challenge"), str):
        raise _Refuse("bad_client_data")
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        raise _Refuse("bad_client_data")
    if "topOrigin" in cd:
        raise _Refuse("bad_client_data")
    allowed = ctx.native_rps.get(rp_id, ()) if kind == "native" else (origin_of(base_url),)
    origin = cd.get("origin")
    if not isinstance(origin, str) or origin not in allowed:
        raise _Refuse("bad_client_data")
    return cd


def _check_challenge(cd: dict, expected: bytes) -> None:
    try:
        got = b64u_decode(cd["challenge"], 32, 32)
    except ValueError as exc:
        raise _Refuse("challenge_mismatch") from exc
    if not hmac.compare_digest(got, expected):
        raise _Refuse("challenge_mismatch")


def _rp_id_hash_ok(auth: bytes, rp_id: str) -> bool:
    return len(auth) >= 37 and hmac.compare_digest(auth[:32], hashlib.sha256(rp_id.encode("utf-8")).digest())


def _public_key(x: bytes, y: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)


# ── assertions (README §9) ────────────────────────────────────────────────────────────────────


def verify_assertion(ctx: GatewayContext, request: AssertionRequest, credentials: Iterable[StoredCredential],
                     answer: Any) -> AssertionOk | Refusal:
    """Verify one ``confirm`` answer (or step-up assertion object wrapped the same way) against *request*.
    *credentials* is the snapshot of the bound user's credentials (others are ignored)."""
    try:
        return _verify_assertion(ctx, request, tuple(credentials), answer)
    except _Refuse as refusal:
        return Refusal(refusal.reason)


def _verify_assertion(ctx: GatewayContext, request: AssertionRequest, credentials: tuple, answer: Any) -> AssertionOk:
    # 1 bad_shape — every size bound before any parsing
    try:
        if not isinstance(answer, Mapping) or set(answer) != _ANSWER_KEYS:
            raise ValueError
        if answer["decision"] != "confirmed" or answer["method"] != "passkey":
            raise ValueError
        p = answer["passkey"]
        if not isinstance(p, Mapping) or not _PASSKEY_KEYS <= set(p) <= _PASSKEY_KEYS | _PASSKEY_OPTIONAL:
            raise ValueError
        if type(p["v"]) is not int or p["v"] != 1:
            raise ValueError
        rp_id, base_url = p["rp_id"], p["base_url"]
        if not (isinstance(rp_id, str) and 1 <= len(rp_id) <= 253):
            raise ValueError
        if not (isinstance(base_url, str) and 1 <= len(base_url) <= 512):
            raise ValueError
        credential_id = b64u_decode(p["credential_id"], 1, 1023)
        auth = b64u_decode(p["authenticator_data"], 37, 1024)
        cdj = b64u_decode(p["client_data_json"], 1, 4096)
        signature = b64u_decode(p["signature"], 8, 72)
        handle = b64u_decode(p["user_handle"], 1, 64) if "user_handle" in p else None
    except (ValueError, KeyError, TypeError) as exc:
        raise _Refuse("bad_shape") from exc
    # 2 unknown_credential
    cred = next((c for c in credentials if c.active and c.user_id == request.user_id and c.rp_id == rp_id
                 and hmac.compare_digest(c.credential_id, credential_id)), None)
    if cred is None:
        raise _Refuse("unknown_credential")
    if handle is not None and not hmac.compare_digest(handle, user_handle(ctx.handle_key, request.user_id)):
        raise _Refuse("unknown_credential")
    # 3 rp_not_accepted, 4 base_url_not_accepted, 5 rp_host_mismatch
    kind = _rp_kind(ctx, rp_id, base_url)
    # 6 bad_client_data
    cd = _client_data(cdj, type_="webauthn.get", kind=kind, rp_id=rp_id, base_url=base_url, ctx=ctx)
    # 7 challenge_mismatch
    digest = request.text_digest
    expected = challenge(purpose=request.purpose, base_url=base_url, gateway_id=ctx.gateway_id,
                         user_id=request.user_id, session_id=request.session_id, request_id=request.request_id,
                         nonce=request.nonce, digest=digest)
    _check_challenge(cd, expected)
    # 8 bad_authenticator_data
    flags = auth[32]
    if not _rp_id_hash_ok(auth, rp_id) or flags & FLAG_AT or (flags & FLAG_BS and not flags & FLAG_BE):
        raise _Refuse("bad_authenticator_data")
    if flags & FLAG_ED:
        try:
            extensions, end = cbor.decode(auth, 37)
        except cbor.CborError as exc:
            raise _Refuse("bad_authenticator_data") from exc
        if not isinstance(extensions, dict) or end != len(auth):
            raise _Refuse("bad_authenticator_data")
    elif len(auth) != 37:
        raise _Refuse("bad_authenticator_data")
    # 9 uv_required
    if not (flags & FLAG_UP and flags & FLAG_UV):
        raise _Refuse("uv_required")
    # 10 backup_state_mismatch
    if bool(flags & FLAG_BE) != cred.backup_eligible:
        raise _Refuse("backup_state_mismatch")
    # 11 signature_invalid — strict DER (cryptography refuses anything else); high S is valid
    try:
        _public_key(cred.public_x, cred.public_y).verify(
            signature, auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise _Refuse("signature_invalid") from exc
    # 12 counter_regression — refused for a device-bound credential, audited for a synced one
    count = struct.unpack(">I", auth[33:37])[0]
    regressed = not (count == 0 and cred.sign_count == 0) and count <= cred.sign_count
    if regressed and not cred.backup_eligible:
        raise _Refuse("counter_regression")
    return AssertionOk(credential_id=credential_id, rp_id=rp_id, base_url=base_url, sign_count=count,
                       backup_eligible=bool(flags & FLAG_BE), backed_up=bool(flags & FLAG_BS),
                       counter_warning=regressed, challenge=expected, text_digest=digest,
                       authenticator_data=auth, client_data_json=cdj, signature=signature,
                       user_id=request.user_id, purpose=request.purpose, session_id=request.session_id,
                       request_id=request.request_id, nonce=request.nonce)


def memoised_assertion_validator(ctx: GatewayContext, request: AssertionRequest,
                                 credentials: Iterable[StoredCredential], *, size: int = 16
                                 ) -> Callable[[Any], AssertionOk | Refusal]:
    """A validator bound to one open request and its credential snapshot, remembering its last *size*
    verdicts by the answer's canonical JSON: the answer path runs it twice for one answer (under the
    request lock, and again from ``request.answer``) and an ECDSA verification is not free. Pure: the
    cache holds verdicts only, never inputs it did not receive."""
    snapshot = tuple(credentials)
    cache: OrderedDict[str, AssertionOk | Refusal] = OrderedDict()

    def validate(answer: Any) -> AssertionOk | Refusal:
        try:
            key = json.dumps(answer, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError):
            return verify_assertion(ctx, request, snapshot, answer)
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        verdict = verify_assertion(ctx, request, snapshot, answer)
        cache[key] = verdict
        while len(cache) > size:
            cache.popitem(last=False)
        return verdict

    return validate


# ── registrations (README §11) ────────────────────────────────────────────────────────────────


def verify_registration(ctx: GatewayContext, pending: PendingRegistration, finish: Any) -> RegistrationOk | Refusal:
    """Verify a ``register/finish`` body for *pending*. The enrolment code and "credential already
    stored" are the route's to check."""
    try:
        return _verify_registration(ctx, pending, finish)
    except _Refuse as refusal:
        return Refusal(refusal.reason)


def _verify_registration(ctx: GatewayContext, pending: PendingRegistration, finish: Any) -> RegistrationOk:
    # 1 bad_shape
    try:
        if not isinstance(finish, Mapping):
            raise ValueError
        credential = finish["credential"]
        if not isinstance(credential, Mapping):
            raise ValueError
        credential_id = b64u_decode(credential["id"], 1, 1023)
        cdj = b64u_decode(credential["client_data_json"], 1, 4096)
        att = b64u_decode(credential["attestation_object"], 1, 16384)
        if finish["registration_id"] != pending.registration_id or finish["base_url"] != pending.base_url:
            raise ValueError
        transports = credential.get("transports", ())
        if not isinstance(transports, (list, tuple)) or len(transports) > 8 or not all(
                isinstance(t, str) and 0 < len(t) <= 32 for t in transports):
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise _Refuse("bad_shape") from exc
    # 2, 3, 4
    kind = _rp_kind(ctx, pending.rp_id, pending.base_url)
    # 5 bad_client_data
    cd = _client_data(cdj, type_="webauthn.create", kind=kind, rp_id=pending.rp_id, base_url=pending.base_url, ctx=ctx)
    # 6 challenge_mismatch
    _check_challenge(cd, challenge(purpose="register", base_url=pending.base_url, gateway_id=ctx.gateway_id,
                                   user_id=pending.user_id, session_id="", request_id=pending.registration_id,
                                   nonce=pending.nonce, digest=text_digest("", pending.name, "")))
    # 7 bad_attestation_object
    try:
        obj = cbor.decode_exactly(att)
    except cbor.CborError as exc:
        raise _Refuse("bad_attestation_object") from exc
    if (not isinstance(obj, dict) or set(obj) != {"fmt", "attStmt", "authData"} or not isinstance(obj["fmt"], str)
            or not isinstance(obj["attStmt"], dict) or not isinstance(obj["authData"], bytes)):
        raise _Refuse("bad_attestation_object")
    auth: bytes = obj["authData"]
    # 8 bad_authenticator_data
    if len(auth) < 55 or len(auth) > 16384 or not _rp_id_hash_ok(auth, pending.rp_id):
        raise _Refuse("bad_authenticator_data")
    flags = auth[32]
    if not flags & FLAG_AT or (flags & FLAG_BS and not flags & FLAG_BE):
        raise _Refuse("bad_authenticator_data")
    id_len = struct.unpack(">H", auth[53:55])[0]
    if 55 + id_len > len(auth) or not hmac.compare_digest(auth[55:55 + id_len], credential_id):
        raise _Refuse("bad_authenticator_data")
    try:
        cose, pos = cbor.decode(auth, 55 + id_len)
        if not isinstance(cose, dict):
            raise cbor.CborError("COSE key is not a map")
        if flags & FLAG_ED:
            extensions, pos = cbor.decode(auth, pos)
            if not isinstance(extensions, dict):
                raise cbor.CborError("extensions are not a map")
        if pos != len(auth):
            raise cbor.CborError("trailing bytes")
    except cbor.CborError as exc:
        raise _Refuse("bad_authenticator_data") from exc
    # 9 uv_required
    if not (flags & FLAG_UP and flags & FLAG_UV):
        raise _Refuse("uv_required")
    # 10 unsupported_algorithm
    # ``type(...) is int``: CBOR true decodes to True, and True == 1 would pass a crv check.
    if any(type(cose.get(k)) is not int for k in (1, 3, -1)) \
            or cose.get(1) != 2 or cose.get(3) != ALG_ES256 or cose.get(-1) != 1:
        raise _Refuse("unsupported_algorithm")
    # 11 bad_public_key
    x, y = cose.get(-2), cose.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
        raise _Refuse("bad_public_key")
    try:
        _public_key(x, y)
    except ValueError as exc:
        raise _Refuse("bad_public_key") from exc
    return RegistrationOk(credential_id=credential_id, rp_id=pending.rp_id, alg=ALG_ES256, public_x=x, public_y=y,
                          sign_count=struct.unpack(">I", auth[33:37])[0], backup_eligible=bool(flags & FLAG_BE),
                          backed_up=bool(flags & FLAG_BS), aaguid=auth[37:53], transports=tuple(transports),
                          registration_id=pending.registration_id, user_id=pending.user_id, nonce=pending.nonce)


__all__ = ["ASSERTION_REASONS", "REGISTRATION_REASONS", "AssertionOk", "AssertionRequest", "PendingRegistration",
           "Refusal", "RegistrationOk", "StoredCredential", "b64u", "memoised_assertion_validator",
           "verify_assertion", "verify_registration"]
