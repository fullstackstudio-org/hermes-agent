"""A software WebAuthn authenticator for tests (ES256, attestation ``none``).

It builds exactly what a platform authenticator returns for a registration and an assertion under the
confirm-passkey construction, so the verifier, the store and the routes can be tested end to end without
a device. Test-only: the private keys live in memory and are generated per instance.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hermes_cli.dashboard_auth.passkeys.challenge import b64u, challenge, origin_of, text_digest, user_handle
from hermes_cli.dashboard_auth.passkeys.webauthn import (
    FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, AssertionRequest, PendingRegistration)


def _cbor(value) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
            if n < 1 << (8 * struct.calcsize(fmt)):
                return bytes([major << 5 | info]) + struct.pack(fmt, n)
        raise ValueError(n)

    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(_cbor(k) + _cbor(v) for k, v in value.items())
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(_cbor(v) for v in value)
    raise TypeError(type(value))


@dataclass
class SoftAuthenticator:
    rp_id: str
    client_origin: str  # the clientDataJSON.origin this authenticator's client reports
    synced: bool = True
    sign_count: int = 0
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))

    @property
    def flags(self) -> int:
        return FLAG_UP | FLAG_UV | ((FLAG_BE | FLAG_BS) if self.synced else 0)

    def _client_data(self, type_: str, chal: bytes) -> bytes:
        return json.dumps({"type": type_, "challenge": b64u(chal), "origin": self.client_origin,
                           "crossOrigin": False}, separators=(",", ":")).encode()

    def register(self, gateway_id: bytes, pending: PendingRegistration, *, cose_fields: dict | None = None) -> dict:
        """The ``register/finish`` body for *pending*; ``cose_fields`` overrides entries of the COSE key."""
        chal = challenge(purpose="register", base_url=pending.base_url, gateway_id=gateway_id,
                         user_id=pending.user_id, session_id="", request_id=pending.registration_id,
                         nonce=pending.nonce, digest=text_digest("", pending.name, ""))
        numbers = self.key.public_key().public_numbers()
        cose = _cbor({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big"),
                      **(cose_fields or {})})
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([self.flags | FLAG_AT])
                + struct.pack(">I", self.sign_count) + b"\x00" * 16 + struct.pack(">H", len(self.credential_id))
                + self.credential_id + cose)
        return {"registration_id": pending.registration_id, "base_url": pending.base_url, "code": "",
                "credential": {"id": b64u(self.credential_id),
                               "client_data_json": b64u(self._client_data("webauthn.create", chal)),
                               "attestation_object": b64u(_cbor({"fmt": "none", "attStmt": {}, "authData": auth})),
                               "transports": ["internal"]}}

    def assert_(self, gateway_id: bytes, handle_key: bytes, request: AssertionRequest, base_url: str,
                *, with_user_handle: bool = True) -> dict:
        """The ``confirm`` answer for *request*, as dialed at *base_url*."""
        if not self.synced:
            self.sign_count += 1
        chal = challenge(purpose=request.purpose, base_url=base_url, gateway_id=gateway_id, user_id=request.user_id,
                         session_id=request.session_id, request_id=request.request_id, nonce=request.nonce,
                         digest=request.text_digest)
        cdj = self._client_data("webauthn.get", chal)
        auth = hashlib.sha256(self.rp_id.encode()).digest() + bytes([self.flags]) + struct.pack(">I", self.sign_count)
        signature = self.key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        passkey = {"v": request.version, "rp_id": self.rp_id, "base_url": base_url,
                   "credential_id": b64u(self.credential_id),
                   "authenticator_data": b64u(auth), "client_data_json": b64u(cdj), "signature": b64u(signature)}
        if with_user_handle:
            passkey["user_handle"] = b64u(user_handle(handle_key, request.user_id))
        return {"decision": "confirmed", "method": "passkey", "passkey": passkey}


def web_authenticator(base_url: str, **kwargs) -> SoftAuthenticator:
    """A browser on *base_url*: RP = its host, client origin = its origin."""
    from hermes_cli.dashboard_auth.passkeys.challenge import host_of
    return SoftAuthenticator(rp_id=host_of(base_url), client_origin=origin_of(base_url), **kwargs)
