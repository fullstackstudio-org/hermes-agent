#!/usr/bin/env python3
"""Generate (or check) ``vectors.json`` for the ``confirm`` level ``passkey``.

    python generate.py           write vectors.json next to this file
    python generate.py --check   rebuild in memory and compare with vectors.json byte for byte

Everything in the file is derived from fixed labels, so the generator reproduces it exactly, with one
exception: ECDSA signatures are randomised, so they are STORED. A rebuild reuses each stored signature
when it still verifies over that vector's message under that vector's signing key, and ``--check``
fails when one does not (the message changed: run without ``--check`` to sign again).

The keys in the file are test keys derived from public labels. They are not used anywhere else and
must never be.

Needs Python 3.11+ and ``cryptography``. See README.md for the construction this implements.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "vectors.json"

CHALLENGE_TAG = "hermie-confirm-v1"
TEXT_TAG = "hermie-confirm-text-v1"
USER_HANDLE_TAG = b"user-handle-v1"
PURPOSES = ("confirm", "register", "invite", "revoke")

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# ── primitives ────────────────────────────────────────────────────────────────────────────────


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def S(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def LP(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def det(label: str, size: int) -> bytes:
    """Fixed pseudo-random bytes for *label* (test data only)."""
    return hashlib.shake_256(("confirm-passkey-vectors/" + label).encode("utf-8")).digest(size)


# ── origin serialisation ──────────────────────────────────────────────────────────────────────


def _a_label(label: str) -> str:
    # UTS #46 non-transitional processing as the WHATWG URL parser does it, restricted to what the
    # vectors use: NFC, lower-case, Punycode for a label with non-ASCII characters. ``ß`` is kept
    # (non-transitional), never mapped to ``ss``.
    label = unicodedata.normalize("NFC", label).lower()
    if label.isascii():
        return label
    return "xn--" + label.encode("punycode").decode("ascii")


def serialise_origin(url: str) -> str:
    """``scheme://host[:port]`` per README §2. Raises ValueError for anything that is not an http(s) origin."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("not_an_origin")
    host = parts.hostname or ""
    if not host:
        raise ValueError("not_an_origin")
    if ":" in host:
        host = "[" + ipaddress.IPv6Address(host).compressed + "]"
    else:
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError:
            host = ".".join(_a_label(label) for label in host.split("."))
    port = parts.port
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + (f":{port}" if port is not None and port != default else "")


# ── construction ──────────────────────────────────────────────────────────────────────────────


def text_digest(title: str, summary: str, detail: str | None) -> bytes:
    return sha256(S(TEXT_TAG) + S(title) + S(summary) + S(detail or ""))


def challenge_preimage(*, purpose: str, origin: str, gateway_id: bytes, user_id: str, session_id: str,
                       request_id: str, nonce: bytes, digest: bytes) -> bytes:
    assert purpose in PURPOSES
    return (S(CHALLENGE_TAG) + S(purpose) + S(origin) + LP(gateway_id) + S(user_id) + S(session_id)
            + S(request_id) + LP(nonce) + LP(digest))


def challenge(**kwargs) -> bytes:
    return sha256(challenge_preimage(**kwargs))


def user_handle(handle_key: bytes, user_id: str) -> bytes:
    return hmac.new(handle_key, USER_HANDLE_TAG + user_id.encode("utf-8"), hashlib.sha256).digest()


# ── keys ──────────────────────────────────────────────────────────────────────────────────────


class Key:
    def __init__(self, name: str):
        self.name = name
        self.label = f"test key {name}"
        scalar = int.from_bytes(det(self.label, 48), "big") % (P256_ORDER - 1) + 1
        self.private = ec.derive_private_key(scalar, ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.scalar = scalar
        self.x = numbers.x.to_bytes(32, "big")
        self.y = numbers.y.to_bytes(32, "big")

    def public(self):
        return self.private.public_key()

    def describe(self) -> dict:
        return {"derivation": f"scalar = int(SHAKE256('confirm-passkey-vectors/{self.label}', 48 bytes)) mod (n-1) + 1",
                "private_scalar": b64u(self.scalar.to_bytes(32, "big")), "x": b64u(self.x), "y": b64u(self.y)}


KEYS = {name: Key(name) for name in ("credential-a", "credential-b", "other-c")}


def verifies(key: Key, signature: bytes, message: bytes) -> bool:
    try:
        key.public().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# ── minimal CBOR encoder (canonical, for building test inputs) ─────────────────────────────────


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    for info, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if value < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | info]) + struct.pack(fmt, value)
    raise ValueError("too large")


def cbor(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


def cose_es256(key: Key) -> bytes:
    return cbor({1: 2, 3: -7, -1: 1, -2: key.x, -3: key.y})


# ── shared fixture ────────────────────────────────────────────────────────────────────────────

GATEWAY_ID = det("gateway id", 16)
HANDLE_KEY = det("handle key", 32)
NATIVE_RP = "confirm.hermie.dev"
NATIVE_CLIENT_ORIGIN = "https://confirm.hermie.dev"
GW_ORIGIN = "https://gw.example.com"
LAN_ORIGIN = "http://192.168.1.10:9119"
EVIL_ORIGIN = "https://evil.example.net"
WEB_RP = "gw.example.com"
OLD_WEB_RP = "old.example.org"
USER = "self_hosted:7c1f0e2a"
USER_NAME = "Alex Example"
OTHER_USER = "self_hosted:91b44d03"
AAGUID = det("aaguid", 16)

CONTEXT = {
    "gateway_id": b64u(GATEWAY_ID),
    "handle_key": b64u(HANDLE_KEY),
    "public_origins": [GW_ORIGIN, LAN_ORIGIN],
    "native_rps": {NATIVE_RP: [NATIVE_CLIENT_ORIGIN]},
    "accepted_rps": {"native": [NATIVE_RP], "web": [WEB_RP]},
    "user": {"id": USER, "name": USER_NAME},
}

CRED_NATIVE = b64u(det("credential native", 32))
CRED_WEB = b64u(det("credential web", 20))
CRED_OLD = b64u(det("credential old web", 20))
CRED_OTHER_USER = b64u(det("credential other user", 32))
CRED_REVOKED = b64u(det("credential revoked", 32))


def stored(credential_id: str, key: Key, rp_id: str, *, user_id: str = USER, sign_count: int = 0,
           backup_eligible: bool = True, backed_up: bool = True, active: bool = True) -> dict:
    return {"credential_id": credential_id, "user_id": user_id, "rp_id": rp_id, "alg": -7,
            "public_key": {"x": b64u(key.x), "y": b64u(key.y)}, "sign_count": sign_count,
            "backup_eligible": backup_eligible, "backed_up": backed_up, "active": active}


REQUEST: dict[str, Any] = {
    "session_id": "sess-7Q2xK",
    "request_id": "srq-3f9a0c41d2e8",
    "nonce": b64u(det("request nonce", 32)),
    "title": "Pay invoice",
    "summary": "Pay 120.00 EUR to Example Plumbing B.V. for invoice 2026-114.",
    "detail": "IBAN NL00 TEST 0123 4567 89\nReference 2026-114",
    "user_id": USER,
    "expires_at": 1790000120,
}


def request_challenge(req: dict, origin: str, **override) -> bytes:
    fields: dict[str, Any] = dict(purpose="confirm", origin=origin, gateway_id=GATEWAY_ID, user_id=req["user_id"],
                  session_id=req["session_id"], request_id=req["request_id"], nonce=unb64u(req["nonce"]),
                  digest=text_digest(req["title"], req["summary"], req["detail"]))
    fields.update(override)
    return challenge(**fields)


def client_data(type_: str, chal: bytes, origin: str, *, cross_origin: bool | None = False,
                extra: str = "") -> bytes:
    body = f'{{"type":"{type_}","challenge":"{b64u(chal)}","origin":"{origin}"'
    if cross_origin is not None:
        body += f',"crossOrigin":{"true" if cross_origin else "false"}'
    return (body + extra + "}").encode("utf-8")


def auth_data(rp_id: str, flags: int, sign_count: int, tail: bytes = b"") -> bytes:
    return sha256(rp_id.encode("ascii")) + bytes([flags]) + struct.pack(">I", sign_count) + tail


# ── origin, text, challenge and handle vectors ────────────────────────────────────────────────

ORIGIN_INPUTS = [
    ("plain https", "https://gw.example.com"),
    ("default https port dropped", "https://gw.example.com:443"),
    ("default http port dropped", "http://gw.example.com:80"),
    ("explicit port kept", "https://gw.example.com:8443"),
    ("http on the https default port keeps it", "http://gw.example.com:443"),
    ("upper case scheme and host, path dropped", "HTTPS://GW.Example.COM/"),
    ("path, query, fragment dropped", "https://gw.example.com/chat/s?x=1#y"),
    ("userinfo dropped", "https://someone:secret@gw.example.com"),
    ("ipv4 with port", "http://192.168.1.10:9119"),
    ("ipv6 lower-cased", "http://[FE80::1]:9119"),
    ("ipv6 compressed", "https://[2001:DB8:0:0:0:0:0:1]"),
    ("ipv6 loopback default port", "http://[::1]:80"),
    ("idn to a-label", "https://bücher.example"),
    ("idn upper case to a-label", "https://BÜCHER.Example:8443"),
    ("idn sharp s kept (non-transitional)", "https://straße.example"),
    ("a-label unchanged", "https://xn--bcher-kva.example"),
    ("localhost", "http://localhost:9119"),
]
ORIGIN_ERRORS = [
    ("other scheme", "ftp://gw.example.com"),
    ("no scheme", "gw.example.com"),
    ("no host", "https://"),
]


def origin_vectors() -> list[dict]:
    out = [{"name": name, "input": url, "origin": serialise_origin(url)} for name, url in ORIGIN_INPUTS]
    for name, url in ORIGIN_ERRORS:
        try:
            serialise_origin(url)
        except ValueError:
            out.append({"name": name, "input": url, "error": "not_an_origin"})
        else:
            raise AssertionError(f"{url} should not serialise")
    return out


TEXT_CASES = [
    ("empty detail as null", "Delete backups", "Delete 3 old backups.", None),
    ("empty detail as empty string (same digest as null)", "Delete backups", "Delete 3 old backups.", ""),
    ("multi-byte text", "Überweisung bestätigen", "Zahle 120,00 € an Bäckerei Größe — Rechnung 7 🧾", "日本語の詳細\n第二行"),
    ("precomposed e-acute", "Café", "s", "d"),
    ("decomposed e-acute (no normalisation: differs)", "Café", "s", "d"),
    ("request text", REQUEST["title"], REQUEST["summary"], REQUEST["detail"]),
]


def text_vectors() -> list[dict]:
    return [{"name": name, "title": t, "summary": s, "detail": d, "text_digest": b64u(text_digest(t, s, d))}
            for name, t, s, d in TEXT_CASES]


def challenge_vectors() -> list[dict]:
    cases = [
        ("confirm, https default port", "confirm", GW_ORIGIN, REQUEST["session_id"], REQUEST["request_id"],
         REQUEST["title"], REQUEST["summary"], REQUEST["detail"]),
        ("confirm, explicit port", "confirm", "https://gw.example.com:8443", "s1", "srq-000000000001",
         "T", "S", None),
        ("confirm, ipv4 http", "confirm", LAN_ORIGIN, "s1", "srq-000000000002", "T", "S", ""),
        ("confirm, ipv6", "confirm", "http://[fe80::1]:9119", "s1", "srq-000000000003", "T", "S", None),
        ("confirm, idn", "confirm", "https://xn--bcher-kva.example", "s1", "srq-000000000004", "T", "S", None),
        ("confirm, multi-byte text", "confirm", GW_ORIGIN, "s1", "srq-000000000005",
         "Überweisung bestätigen", "Zahle 120,00 € 🧾", "日本語"),
        ("register", "register", GW_ORIGIN, "", "reg-5d1e0a77b3c4", "", "Alex Example — gw.example.com", ""),
        ("invite", "invite", GW_ORIGIN, "", "stp-0b8e4f2a9c61", "", "invite", ""),
        ("revoke", "revoke", GW_ORIGIN, "", "stp-7a2c9e1d0f35", "", CRED_WEB, ""),
    ]
    out = []
    for i, (name, purpose, origin, sid, rid, title, summary, detail) in enumerate(cases):
        nonce = det(f"challenge nonce {i}", 32)
        digest = text_digest(title, summary, detail)
        pre = challenge_preimage(purpose=purpose, origin=origin, gateway_id=GATEWAY_ID, user_id=USER,
                                 session_id=sid, request_id=rid, nonce=nonce, digest=digest)
        out.append({"name": name, "purpose": purpose, "origin": origin, "gateway_id": b64u(GATEWAY_ID),
                    "user_id": USER, "session_id": sid, "request_id": rid, "nonce": b64u(nonce),
                    "title": title, "summary": summary, "detail": detail, "text_digest": b64u(digest),
                    "preimage_hex": pre.hex(), "challenge": b64u(sha256(pre))})
    return out


def handle_vectors() -> list[dict]:
    return [{"handle_key": b64u(HANDLE_KEY), "user_id": uid, "user_handle": b64u(user_handle(HANDLE_KEY, uid))}
            for uid in (USER, OTHER_USER, "basic:admin")]


# ── assertion vectors ─────────────────────────────────────────────────────────────────────────

STORE = [
    stored(CRED_NATIVE, KEYS["credential-a"], NATIVE_RP),
    stored(CRED_WEB, KEYS["credential-b"], WEB_RP, sign_count=10, backup_eligible=False, backed_up=False),
    stored(CRED_OLD, KEYS["credential-b"], OLD_WEB_RP, backup_eligible=False, backed_up=False),
    stored(CRED_OTHER_USER, KEYS["other-c"], NATIVE_RP, user_id=OTHER_USER),
    stored(CRED_REVOKED, KEYS["credential-a"], NATIVE_RP, active=False),
]
UV_FLAGS_SYNCED = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS
UV_FLAGS_DEVICE = FLAG_UP | FLAG_UV


class A:
    """One assertion vector under construction."""

    def __init__(self, name, *, expect, reason=None, description="", rp_id=NATIVE_RP, origin=GW_ORIGIN,
                 credential_id=CRED_NATIVE, key="credential-a", flags=UV_FLAGS_SYNCED, sign_count=0,
                 cd_type="webauthn.get", cd_origin=None, cross_origin=False, cd_extra="", cd_raw=None,
                 chal_origin=None, chal_override=None, ad_tail=b"", ad_rp=None, store=None,
                 user_handle_for=USER, fixed_signature=None, answer_patch=None, request=None):
        self.name, self.expect, self.reason, self.description = name, expect, reason, description
        self.request = request or REQUEST
        cd_origin = cd_origin if cd_origin is not None else (NATIVE_CLIENT_ORIGIN if rp_id == NATIVE_RP else origin)
        chal = request_challenge(self.request, chal_origin or origin, **(chal_override or {}))
        self.cdj = cd_raw if cd_raw is not None else client_data(cd_type, chal, cd_origin,
                                                                  cross_origin=cross_origin, extra=cd_extra)
        self.ad = auth_data(ad_rp or rp_id, flags, sign_count, ad_tail)
        self.key = KEYS[key]
        self.fixed_signature = fixed_signature
        self.store = store if store is not None else STORE
        self.answer_passkey = {"v": 1, "rp_id": rp_id, "origin": origin, "credential_id": credential_id,
                               "authenticator_data": b64u(self.ad), "client_data_json": b64u(self.cdj),
                               "signature": None}
        if user_handle_for is not None:
            self.answer_passkey["user_handle"] = b64u(user_handle(HANDLE_KEY, user_handle_for))
        self.answer_patch = answer_patch

    def message(self) -> bytes:
        return self.ad + sha256(self.cdj)

    def build(self, signature: bytes) -> dict:
        passkey = dict(self.answer_passkey, signature=b64u(signature))
        answer = {"decision": "confirmed", "method": "passkey", "passkey": passkey}
        if self.answer_patch:
            answer = self.answer_patch(answer)
        expect: dict[str, Any] = {"ok": True} if self.expect == "accept" else {"ok": False, "code": 4034, "reason": self.reason}
        if self.expect == "accept":
            flags = self.ad[32]
            expect.update(sign_count=struct.unpack(">I", self.ad[33:37])[0],
                          backup_eligible=bool(flags & FLAG_BE), backed_up=bool(flags & FLAG_BS))
        return {"name": self.name, "description": self.description, "request": self.request,
                "store": self.store, "answer": answer, "signed_by": None if self.fixed_signature else self.key.name,
                "expect": expect}


def _drop(field):
    def patch(answer):
        answer["passkey"].pop(field)
        return answer
    return patch


def _set(path, value):
    def patch(answer):
        target = answer
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        return answer
    return patch


def _pad(field):
    def patch(answer):
        value = answer["passkey"][field]
        answer["passkey"][field] = value + "=" * (-len(value) % 4 or 4)
        return answer
    return patch


def assertion_cases() -> list[A]:
    big_extra = ',"padding":"' + "x" * 4096 + '"'
    other_req = dict(REQUEST, request_id="srq-000000000099")
    return [
        # accepted
        A("native passkey, synced, counter 0/0", expect="accept",
          description="Native app, shared RP, listed https gateway origin; BE and BS set; signCount 0 stays 0."),
        A("web passkey, device-bound, counter increases", expect="accept", rp_id=WEB_RP, credential_id=CRED_WEB,
          key="credential-b", flags=UV_FLAGS_DEVICE, sign_count=11, user_handle_for=None,
          cd_extra=',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"',
          description="Browser on the gateway origin; RP = that host; unknown clientDataJSON keys are ignored; "
                      "no user_handle."),
        A("native passkey over a listed private http origin", expect="accept", origin=LAN_ORIGIN,
          description="The native path works for an http origin the operator listed (its RP is https elsewhere)."),
        A("counter from 0 to 5", expect="accept", sign_count=5,
          description="A stored 0 followed by a positive counter is an increase."),
        # bad_shape
        A("missing signature", expect="refuse", reason="bad_shape", answer_patch=_drop("signature"),
          fixed_signature=b"\x00"),
        A("padded base64url", expect="refuse", reason="bad_shape", answer_patch=_pad("authenticator_data"),
          description="Base64url values carry no padding."),
        A("unknown version", expect="refuse", reason="bad_shape", answer_patch=_set(["passkey", "v"], 2)),
        A("unknown key in the passkey object", expect="refuse", reason="bad_shape",
          answer_patch=_set(["passkey", "extension"], "x")),
        A("confirmed with method tap", expect="refuse", reason="bad_shape", answer_patch=_set(["method"], "tap")),
        A("client data over 4096 bytes", expect="refuse", reason="bad_shape", cd_extra=big_extra),
        # unknown_credential
        A("credential id not stored", expect="refuse", reason="unknown_credential",
          credential_id=b64u(det("credential never stored", 32))),
        A("credential of another user", expect="refuse", reason="unknown_credential", credential_id=CRED_OTHER_USER,
          key="other-c", user_handle_for=OTHER_USER),
        A("revoked credential", expect="refuse", reason="unknown_credential", credential_id=CRED_REVOKED),
        A("credential stored for another RP", expect="refuse", reason="unknown_credential", rp_id=WEB_RP,
          credential_id=CRED_NATIVE, flags=UV_FLAGS_SYNCED),
        A("user handle of another user", expect="refuse", reason="unknown_credential", user_handle_for=OTHER_USER),
        # rp_not_accepted
        A("web RP whose origin is no longer listed", expect="refuse", reason="rp_not_accepted", rp_id=OLD_WEB_RP,
          credential_id=CRED_OLD, key="credential-b", flags=UV_FLAGS_DEVICE, origin="https://old.example.org"),
        # origin_not_accepted
        A("relay: valid signature for another gateway's origin", expect="refuse", reason="origin_not_accepted",
          origin=EVIL_ORIGIN,
          description="An attacker's gateway had the app sign a challenge with its own origin and replays the "
                      "answer here as-is. Signature valid; the origin is not listed."),
        A("origin claim not in canonical form", expect="refuse", reason="origin_not_accepted",
          origin="https://GW.example.com:443", chal_origin=GW_ORIGIN),
        # bad_client_data
        A("type webauthn.create in an assertion", expect="refuse", reason="bad_client_data", cd_type="webauthn.create"),
        A("crossOrigin true", expect="refuse", reason="bad_client_data", cross_origin=True),
        A("native client origin not allowed for the RP", expect="refuse", reason="bad_client_data",
          cd_origin=EVIL_ORIGIN),
        A("web client origin differs from the claimed origin", expect="refuse", reason="bad_client_data",
          rp_id=WEB_RP, credential_id=CRED_WEB, key="credential-b", flags=UV_FLAGS_DEVICE, sign_count=11,
          user_handle_for=None, cd_origin="https://gw.example.com:8443"),
        A("client data is not a JSON object", expect="refuse", reason="bad_client_data", cd_raw=b'["webauthn.get"]'),
        A("client data with a duplicate key", expect="refuse", reason="bad_client_data",
          cd_extra=',"type":"webauthn.get"'),
        # challenge_mismatch
        A("relay: listed origin claimed, challenge made for another gateway", expect="refuse",
          reason="challenge_mismatch", chal_origin=EVIL_ORIGIN,
          description="Same relay, but the answer claims this gateway's origin: the recomputed challenge differs."),
        A("challenge for other text", expect="refuse", reason="challenge_mismatch",
          chal_override={"digest": text_digest(REQUEST["title"], "Pay 1200.00 EUR to someone else.", REQUEST["detail"])}),
        A("challenge for another request", expect="refuse", reason="challenge_mismatch",
          chal_override={"request_id": "srq-000000000099"}),
        A("challenge for another session", expect="refuse", reason="challenge_mismatch",
          chal_override={"session_id": "sess-other"}),
        A("challenge for another user", expect="refuse", reason="challenge_mismatch",
          chal_override={"user_id": OTHER_USER}),
        A("challenge with another nonce", expect="refuse", reason="challenge_mismatch",
          chal_override={"nonce": det("stale nonce", 32)}),
        A("challenge with purpose register", expect="refuse", reason="challenge_mismatch",
          chal_override={"purpose": "register"}),
        A("challenge for another gateway id", expect="refuse", reason="challenge_mismatch",
          chal_override={"gateway_id": det("other gateway id", 16)}),
        A("answer replayed onto another request", expect="refuse", reason="challenge_mismatch", request=other_req,
          chal_override={"request_id": REQUEST["request_id"]},
          description="A valid answer for request srq-3f9a0c41d2e8 presented for srq-000000000099."),
        # bad_authenticator_data
        A("rpIdHash of another RP", expect="refuse", reason="bad_authenticator_data", ad_rp=WEB_RP),
        A("attested credential data flag in an assertion", expect="refuse", reason="bad_authenticator_data",
          flags=UV_FLAGS_SYNCED | FLAG_AT),
        A("trailing bytes without the extension flag", expect="refuse", reason="bad_authenticator_data",
          ad_tail=b"\x00"),
        A("extension flag with malformed CBOR", expect="refuse", reason="bad_authenticator_data",
          flags=UV_FLAGS_SYNCED | FLAG_ED, ad_tail=b"\xbf\x61a\x01\xff",
          description="Extensions must be one definite-length CBOR map; 0xbf opens an indefinite-length map."),
        A("backup state without backup eligibility", expect="refuse", reason="bad_authenticator_data",
          flags=FLAG_UP | FLAG_UV | FLAG_BS),
        # uv_required
        A("user verification flag clear", expect="refuse", reason="uv_required", flags=FLAG_UP | FLAG_BE | FLAG_BS),
        A("user presence flag clear", expect="refuse", reason="uv_required", flags=FLAG_UV | FLAG_BE | FLAG_BS),
        # backup_state_mismatch
        A("backup eligibility changed since registration", expect="refuse", reason="backup_state_mismatch",
          flags=UV_FLAGS_DEVICE),
        # signature_invalid
        A("signature by another key", expect="refuse", reason="signature_invalid", key="credential-b",
          description="A valid ES256 signature over the right message, made by a key that is not the credential's."),
        A("structurally valid DER, wrong values", expect="refuse", reason="signature_invalid",
          fixed_signature=bytes.fromhex("3006020101020101")),
        # counter_regression
        A("counter equal to the stored one", expect="refuse", reason="counter_regression", rp_id=WEB_RP,
          credential_id=CRED_WEB, key="credential-b", flags=UV_FLAGS_DEVICE, sign_count=10, user_handle_for=None),
        A("counter back to 0 after 10", expect="refuse", reason="counter_regression", rp_id=WEB_RP,
          credential_id=CRED_WEB, key="credential-b", flags=UV_FLAGS_DEVICE, sign_count=0, user_handle_for=None),
    ]


# ── registration vectors ──────────────────────────────────────────────────────────────────────

REG_ID = "reg-5d1e0a77b3c4"
REG_NONCE = det("registration nonce", 32)
REG_NAME = "Alex Example — gw.example.com"
REG_CRED_ID = det("registered credential", 32)


def registration_begin() -> dict:
    return {"registration_id": REG_ID, "rp_id": NATIVE_RP, "origin": GW_ORIGIN, "name": REG_NAME,
            "nonce": b64u(REG_NONCE), "user": {"id": USER, "handle": b64u(user_handle(HANDLE_KEY, USER))}}


def reg_challenge(**override) -> bytes:
    fields: dict[str, Any] = dict(purpose="register", origin=GW_ORIGIN, gateway_id=GATEWAY_ID, user_id=USER, session_id="",
                  request_id=REG_ID, nonce=REG_NONCE, digest=text_digest("", REG_NAME, ""))
    fields.update(override)
    return challenge(**fields)


def reg_auth_data(*, flags=FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT, cose=None, cred_id=REG_CRED_ID,
                  tail=b"") -> bytes:
    attested = AAGUID + struct.pack(">H", len(cred_id)) + cred_id + (cose if cose is not None else
                                                                    cose_es256(KEYS["credential-a"]))
    return auth_data(NATIVE_RP, flags, 0, attested + tail)


def att_object(ad: bytes, *, raw: bytes | None = None) -> bytes:
    return raw if raw is not None else cbor({"fmt": "none", "attStmt": {}, "authData": ad})


def registration_vectors() -> list[dict]:
    good_ad = reg_auth_data()
    good_cd = client_data("webauthn.create", reg_challenge(), NATIVE_CLIENT_ORIGIN)
    off_curve = cbor({1: 2, 3: -7, -1: 1, -2: KEYS["credential-a"].x, -3: det("not a y coordinate", 32)})
    rs256 = cbor({1: 3, 3: -257, -1: det("modulus", 256), -2: b"\x01\x00\x01"})
    good_att = att_object(good_ad)
    cases = [
        ("native registration", "accept", None, good_cd, good_att,
         "fmt none, empty attStmt, ES256 key; BE and BS set (a synced passkey)."),
        ("attestation statement is ignored", "accept", None, good_cd,
         cbor({"fmt": "packed", "attStmt": {"alg": -7, "sig": b"\x30\x00"}, "authData": good_ad}),
         "Any fmt is accepted and its statement is not checked."),
        ("type webauthn.get", "refuse", "bad_client_data",
         client_data("webauthn.get", reg_challenge(), NATIVE_CLIENT_ORIGIN), good_att, ""),
        ("challenge with purpose confirm", "refuse", "challenge_mismatch",
         client_data("webauthn.create", reg_challenge(purpose="confirm"), NATIVE_CLIENT_ORIGIN), good_att, ""),
        ("challenge for another credential name", "refuse", "challenge_mismatch",
         client_data("webauthn.create", reg_challenge(digest=text_digest("", "Someone — evil.example.net", "")),
                     NATIVE_CLIENT_ORIGIN), good_att, ""),
        ("malformed CBOR: indefinite-length map", "refuse", "bad_attestation_object", good_cd,
         b"\xbf" + good_att[1:] + b"\xff", ""),
        ("malformed CBOR: duplicate key", "refuse", "bad_attestation_object", good_cd,
         _head(5, 3) + cbor("fmt") + cbor("none") + cbor("fmt") + cbor("none") + cbor("authData") + cbor(good_ad), ""),
        ("malformed CBOR: trailing byte", "refuse", "bad_attestation_object", good_cd, good_att + b"\x00", ""),
        ("malformed CBOR: truncated", "refuse", "bad_attestation_object", good_cd, good_att[:-5], ""),
        ("malformed CBOR: tag", "refuse", "bad_attestation_object", good_cd, b"\xc0" + good_att, ""),
        ("authData without attested credential data", "refuse", "bad_authenticator_data", good_cd,
         att_object(auth_data(NATIVE_RP, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS, 0)), ""),
        ("authData for another RP", "refuse", "bad_authenticator_data", good_cd,
         att_object(auth_data(WEB_RP, FLAG_UP | FLAG_UV | FLAG_AT, 0, good_ad[37:])), ""),
        ("credential id in authData differs from credential.id", "refuse", "bad_authenticator_data", good_cd,
         att_object(reg_auth_data(cred_id=det("another credential", 32))), ""),
        ("user verification flag clear", "refuse", "uv_required", good_cd,
         att_object(reg_auth_data(flags=FLAG_UP | FLAG_AT)), ""),
        ("RS256 key", "refuse", "unsupported_algorithm", good_cd, att_object(reg_auth_data(cose=rs256)), ""),
        ("point not on P-256", "refuse", "bad_public_key", good_cd, att_object(reg_auth_data(cose=off_curve)), ""),
    ]
    out = []
    for name, expect, reason, cd, att, description in cases:
        finish = {"registration_id": REG_ID, "origin": GW_ORIGIN,
                  "code": enrolment_code_display(det("enrolment code", 13)),
                  "credential": {"id": b64u(REG_CRED_ID), "client_data_json": b64u(cd),
                                 "attestation_object": b64u(att), "transports": ["internal", "hybrid"]}}
        if expect == "accept":
            result = {"ok": True, "credential_id": b64u(REG_CRED_ID), "rp_id": NATIVE_RP, "alg": -7,
                      "public_key": {"x": b64u(KEYS["credential-a"].x), "y": b64u(KEYS["credential-a"].y)},
                      "sign_count": 0, "backup_eligible": True, "backed_up": True, "aaguid": b64u(AAGUID)}
        else:
            result = {"ok": False, "status": 422, "error": "attestation_invalid", "reason": reason}
        out.append({"name": name, "description": description, "begin": registration_begin(),
                    "finish": finish, "expect": result})
    return out


# ── enrolment codes ───────────────────────────────────────────────────────────────────────────

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_IN = {**{c: c for c in CROCKFORD}, "O": "0", "I": "1", "L": "1"}


def enrolment_code_display(raw: bytes) -> str:
    """100 bits (the top 100 of *raw*) as 20 Crockford base32 characters in groups of five."""
    value = int.from_bytes(raw, "big") >> (len(raw) * 8 - 100)
    chars = "".join(CROCKFORD[(value >> (5 * (19 - i))) & 31] for i in range(20))
    return "-".join(chars[i:i + 5] for i in range(0, 20, 5))


def enrolment_code_canonical(text: str) -> str | None:
    """Upper-case, drop hyphens and spaces, map O to 0 and I/L to 1; None unless exactly 20 symbols remain."""
    out = []
    for ch in text.upper():
        if ch in "- ":
            continue
        if ch not in _CROCKFORD_IN:
            return None
        out.append(_CROCKFORD_IN[ch])
    return "".join(out) if len(out) == 20 else None


def enrolment_code_vectors() -> list[dict]:
    code = enrolment_code_display(det("enrolment code", 13))
    plain = code.replace("-", "")
    inputs = [("as displayed", code), ("lower case, no hyphens", plain.lower()),
              ("spaces instead of hyphens", code.replace("-", " ")),
              ("look-alikes O, I, L", plain[:17] + "OIL"), ("too short", plain[:19]), ("U is not a symbol", "U" + plain[1:])]
    out = []
    for name, text in inputs:
        canonical = enrolment_code_canonical(text)
        out.append({"name": name, "input": text, "canonical": canonical,
                    "code_hash": b64u(sha256(canonical.encode("ascii"))) if canonical else None})
    return out


# ── wire examples ─────────────────────────────────────────────────────────────────────────────


def wire_examples() -> dict:
    return {
        "capabilities_first_result": {
            "server_requests": ["approval", "clarify", "confirm"],
            "confirm": [],
            "confirm_passkey": {"v": 1, "enabled": True, "reason": "", "gateway_id": b64u(GATEWAY_ID),
                                "rp": {"native": [NATIVE_RP], "web": [WEB_RP]}}},
        "capabilities_second_call_params": {
            "server_requests": True, "confirm": ["plain", "passkey"],
            "confirm_passkey": {"v": 1, "kind": "native", "rp_id": NATIVE_RP}},
        "capabilities_second_result": {"server_requests": ["approval", "clarify", "confirm"],
                                       "confirm": ["passkey", "plain"]},
        "confirm_request_frame": {
            "jsonrpc": "2.0", "id": REQUEST["request_id"], "method": "confirm",
            "params": {"session_id": REQUEST["session_id"], "title": REQUEST["title"],
                       "summary": REQUEST["summary"], "detail": REQUEST["detail"], "level": "passkey",
                       "passkey": {"v": 1, "nonce": REQUEST["nonce"], "gateway_id": b64u(GATEWAY_ID),
                                   "expires_at": REQUEST["expires_at"],
                                   "user": {"id": USER, "name": USER_NAME},
                                   "credentials": [{"rp_id": NATIVE_RP, "ids": [CRED_NATIVE]},
                                                   {"rp_id": WEB_RP, "ids": [CRED_WEB]}]}}},
        "result_declined": {"decision": "declined", "method": "tap"},
        "error_cannot_run_ceremony": {"jsonrpc": "2.0", "id": REQUEST["request_id"],
                                      "error": {"code": 4040, "message": "passkey ceremony unavailable",
                                                "data": {"reason": "no_credential"}}},
        "request_answer_refused": {"jsonrpc": "2.0", "id": 7,
                                   "error": {"code": 4034, "message": "answer refused",
                                             "data": {"reason": "challenge_mismatch"}}},
    }


# ── build / check ─────────────────────────────────────────────────────────────────────────────


def _stored_signatures(existing: dict | None) -> dict[str, str]:
    if not existing:
        return {}
    return {v["name"]: v["answer"]["passkey"].get("signature", "")
            for v in existing.get("assertion_vectors", []) if isinstance(v.get("answer", {}).get("passkey"), dict)}


def build(existing: dict | None, *, sign: bool) -> tuple[dict, list[str]]:
    problems: list[str] = []
    stored_sigs = _stored_signatures(existing)
    assertions = []
    for case in assertion_cases():
        if case.fixed_signature is not None:
            signature = case.fixed_signature
        else:
            old = stored_sigs.get(case.name)
            signature = unb64u(old) if old else b""
            if not (signature and verifies(case.key, signature, case.message())):
                if not sign:
                    problems.append(f"assertion {case.name!r}: stored signature missing or no longer valid")
                signature = case.key.private.sign(case.message(), ec.ECDSA(hashes.SHA256())) if sign else signature
        assertions.append(case.build(signature))
    names = [v["name"] for v in assertions]
    if len(names) != len(set(names)):
        problems.append("duplicate assertion vector names")
    refusals = {v["expect"].get("reason") for v in assertions if not v["expect"]["ok"]}
    missing = set(REFUSAL_ORDER) - refusals - {"too_many_attempts"}
    if missing:
        problems.append(f"no assertion vector for {sorted(missing)}")
    doc = {
        "version": 1,
        "about": "Test vectors for the confirm level passkey. Construction and rules: README.md in this directory.",
        "encoding": "Binary values are base64url without padding. preimage_hex is lower-case hex.",
        "keys": {name: key.describe() for name, key in KEYS.items()},
        "context": CONTEXT,
        "origin_vectors": origin_vectors(),
        "text_digest_vectors": text_vectors(),
        "challenge_vectors": challenge_vectors(),
        "user_handle_vectors": handle_vectors(),
        "assertion_refusal_order": REFUSAL_ORDER,
        "assertion_vectors": assertions,
        "sequence_vectors": [{
            "name": "fifth refusal settles the request",
            "steps": ["challenge for other text", "challenge for another request", "signature by another key",
                      "rpIdHash of another RP", "user verification flag clear"],
            "expect": ["refused"] * 4 + ["settled"],
            "settled_outcome": {"outcome": "unavailable", "reason": "verification_failed",
                                "refusal_reason": "too_many_attempts"},
            "description": "Five refused answers for one request (any mix of reasons): the first four leave it "
                           "open; the fifth is refused with too_many_attempts and settles the request.",
        }],
        "registration_vectors": registration_vectors(),
        "enrolment_code_vectors": enrolment_code_vectors(),
        "wire_examples": wire_examples(),
    }
    return doc, problems


REFUSAL_ORDER = ["bad_shape", "unknown_credential", "rp_not_accepted", "origin_not_accepted", "bad_client_data",
                 "challenge_mismatch", "bad_authenticator_data", "uv_required", "backup_state_mismatch",
                 "signature_invalid", "counter_regression", "too_many_attempts"]


def render(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or check vectors.json for the confirm level passkey.")
    parser.add_argument("--check", action="store_true", help="compare with vectors.json instead of writing it")
    args = parser.parse_args(argv)
    existing = json.loads(VECTORS.read_text(encoding="utf-8")) if VECTORS.exists() else None
    if args.check:
        if existing is None:
            print("vectors.json is missing", file=sys.stderr)
            return 1
        doc, problems = build(existing, sign=False)
        if render(doc) != VECTORS.read_text(encoding="utf-8"):
            problems.append("vectors.json differs from a rebuild: run generate.py")
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    doc, problems = build(existing, sign=True)
    for problem in problems:
        if "signature" not in problem:
            print(problem, file=sys.stderr)
            return 1
    VECTORS.write_text(render(doc), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
