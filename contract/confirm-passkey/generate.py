#!/usr/bin/env python3
"""Generate (or check) the test vectors for the ``confirm`` level ``passkey``.

    python generate.py           write vectors.json and SHA256SUMS next to this file
    python generate.py --check   rebuild in memory and compare byte for byte; verify SHA256SUMS

Everything is derived from fixed labels, and signatures use deterministic ECDSA (RFC 6979), so a rebuild
reproduces the files exactly. Before writing or checking, every vector is run through the reference
evaluator below (``evaluate_assertion`` / ``evaluate_registration``), written from README.md's step order
and independent of any production verifier: a vector whose labelled result differs from what the README
says it should be fails the build.

The keys in the file are test keys derived from public labels. They are not used anywhere else and must
never be.

Needs Python 3.11+ and ``cryptography`` 43 or newer.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "vectors.json"
SUMS = HERE / "SHA256SUMS"
SUMMED = ("README.md", "generate.py", "vectors.json")

CHALLENGE_TAG = "hermie-confirm-v1"
TEXT_TAG = "hermie-confirm-text-v1"
USER_HANDLE_TAG = b"user-handle-v1"
PURPOSES = ("confirm", "register", "invite", "revoke")

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ES256 = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)


# ── primitives ────────────────────────────────────────────────────────────────────────────────


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def strict_b64u(text: Any, low: int | None = None, high: int | None = None) -> bytes:
    """README §2: no padding, alphabet only, canonical trailing bits; optional decoded length bounds."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    raw = unb64u(text)
    if b64u(raw) != text:
        raise ValueError("non-canonical base64url")
    if low is not None and high is not None and not low <= len(raw) <= high:
        raise ValueError("length")
    return raw


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


# ── base URL serialisation and eligibility (README §3, §10) ───────────────────────────────────


def _a_label(label: str) -> str:
    # UTS #46 non-transitional processing as the WHATWG URL parser does it, restricted to what the
    # vectors use: NFC, lower-case, Punycode for a label with non-ASCII characters. ``ß`` is kept.
    label = unicodedata.normalize("NFC", label).lower()
    return label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")


_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})+")


def serialise_base_url(url: str) -> str:
    """README §3. Raises ValueError("not_a_base_url")."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.netloc or not parts.hostname:
        raise ValueError("not_a_base_url")
    host = parts.hostname
    if ":" in host:
        host = "[" + ipaddress.IPv6Address(host).compressed + "]"
    else:
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError:
            host = ".".join(_a_label(label) for label in host.split("."))
    port = parts.port
    default = 443 if scheme == "https" else 80
    origin = f"{scheme}://{host}" + (f":{port}" if port is not None and port != default else "")
    path = parts.path.rstrip("/")
    if not path:
        return origin
    segments = path.split("/")[1:]
    if any(seg in ("", ".", "..") or not _SEGMENT.fullmatch(seg) for seg in segments):
        raise ValueError("not_a_base_url")
    segments = [re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), seg) for seg in segments]
    return origin + "/" + "/".join(segments)


def origin_of(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


def host_of(base_url: str) -> str:
    host = urlsplit(base_url).hostname or ""
    return f"[{host}]" if ":" in host else host


_PRIVATE_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


def is_private(base_url: str) -> bool:
    """README §10: an address that can name a different machine on another network."""
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        return True
    host = parts.hostname or ""
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return host == "localhost" or "." not in host or host.endswith(_PRIVATE_SUFFIXES)


def accepted(context: dict) -> tuple[list[str], list[str], list[str]]:
    """(accepted base URLs, accepted native RPs, accepted web RPs) for a gateway context (README §10)."""
    base_urls = [u for u in context["base_urls"] if context["allow_private_base_urls"] or not is_private(u)]
    native = sorted(context["native_rps"]) if base_urls else []
    web = sorted({host_of(u) for u in base_urls if u.startswith("https://") and urlsplit(u).path == ""})
    return base_urls, native, web


def capability_reason(context: dict, *, enabled: bool = True, identity: bool = True) -> str:
    if not enabled:
        return "disabled"
    if not context["base_urls"]:
        return "no_base_url"
    if not accepted(context)[0]:
        return "private_origin"
    return "" if identity else "no_identity"


# ── construction (README §4–§7) ───────────────────────────────────────────────────────────────


def text_digest(title: str, summary: str, detail: str | None) -> bytes:
    return sha256(S(TEXT_TAG) + S(title) + S(summary) + S(detail or ""))


def challenge_preimage(*, purpose: str, base_url: str, gateway_id: bytes, user_id: str, session_id: str,
                       request_id: str, nonce: bytes, digest: bytes) -> bytes:
    assert purpose in PURPOSES
    return (S(CHALLENGE_TAG) + S(purpose) + S(base_url) + LP(gateway_id) + S(user_id) + S(session_id)
            + S(request_id) + LP(nonce) + LP(digest))


def challenge(**kwargs) -> bytes:
    return sha256(challenge_preimage(**kwargs))


def user_handle(handle_key: bytes, user_id: str) -> bytes:
    return hmac.new(handle_key, USER_HANDLE_TAG + user_id.encode("utf-8"), hashlib.sha256).digest()


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_IN = {**{c: c for c in CROCKFORD}, "O": "0", "I": "1", "L": "1"}


def enrolment_code_display(raw: bytes) -> str:
    value = int.from_bytes(raw, "big") >> (len(raw) * 8 - 100)
    chars = "".join(CROCKFORD[(value >> (5 * (19 - i))) & 31] for i in range(20))
    return "-".join(chars[i:i + 5] for i in range(0, 20, 5))


def enrolment_code_canonical(text: str) -> str | None:
    out = []
    for ch in text.upper():
        if ch in "- ":
            continue
        if ch not in _CROCKFORD_IN:
            return None
        out.append(_CROCKFORD_IN[ch])
    return "".join(out) if len(out) == 20 else None


# ── keys and signatures ───────────────────────────────────────────────────────────────────────


class Key:
    def __init__(self, name: str):
        self.name = name
        self.label = f"test key {name}"
        self.scalar = int.from_bytes(det(self.label, 48), "big") % (P256_ORDER - 1) + 1
        self.private = ec.derive_private_key(self.scalar, ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.x = numbers.x.to_bytes(32, "big")
        self.y = numbers.y.to_bytes(32, "big")

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message, ES256)

    def describe(self) -> dict:
        return {"derivation": f"scalar = int(SHAKE256('confirm-passkey-vectors/{self.label}', 48 bytes)) mod (n-1) + 1",
                "private_scalar": b64u(self.scalar.to_bytes(32, "big")), "x": b64u(self.x), "y": b64u(self.y)}


KEYS = {name: Key(name) for name in ("credential-a", "credential-b", "other-c")}


def high_s(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return encode_dss_signature(r, s if s > P256_ORDER // 2 else P256_ORDER - s)


def raw_rs(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ── CBOR: canonical encoder (test inputs) and the README §12 subset decoder (evaluator) ───────


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


class CborError(ValueError):
    pass


def cbor_decode(buf: bytes, pos: int = 0, depth: int = 1) -> tuple[Any, int]:
    """One item of the README §12 subset at *pos*; returns (value, end). Raises CborError only."""
    if depth > 4:
        raise CborError("depth")
    if pos >= len(buf):
        raise CborError("truncated")
    initial = buf[pos]
    major, info = initial >> 5, initial & 31
    pos += 1
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(buf):
            raise CborError("truncated")
        value = int.from_bytes(buf[pos:pos + size], "big")
        pos += size
    else:
        raise CborError("indefinite or reserved length")
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if pos + value > len(buf):
            raise CborError("truncated")
        raw = buf[pos:pos + value]
        if major == 2:
            return raw, pos + value
        try:
            return raw.decode("utf-8"), pos + value
        except UnicodeDecodeError as exc:
            raise CborError("text") from exc
    if major == 4:
        items = []
        for _ in range(value):
            item, pos = cbor_decode(buf, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        out: dict = {}
        for _ in range(value):
            key, pos = cbor_decode(buf, pos, depth + 1)
            if isinstance(key, bool) or not isinstance(key, (int, str)):
                raise CborError("map key")
            if key in out:
                raise CborError("duplicate key")
            out[key], pos = cbor_decode(buf, pos, depth + 1)
        return out, pos
    if major == 6:
        raise CborError("tag")
    if info == 20:
        return False, pos
    if info == 21:
        return True, pos
    if info == 22:
        return None, pos
    raise CborError("simple value")


def cose_es256(key: Key) -> bytes:
    return cbor({1: 2, 3: -7, -1: 1, -2: key.x, -3: key.y})


# ── reference evaluator (README §9, §11) ──────────────────────────────────────────────────────


class Refuse(Exception):
    pass


def _json_object(raw: bytes) -> dict:
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if not isinstance(value, dict):
        raise ValueError("not an object")
    return value


def _client_data(raw: bytes, *, type_: str, rp_kind: str, rp_id: str, base_url: str, context: dict) -> dict:
    try:
        cd = _json_object(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refuse("bad_client_data") from exc
    if cd.get("type") != type_ or not isinstance(cd.get("challenge"), str):
        raise Refuse("bad_client_data")
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        raise Refuse("bad_client_data")
    if "topOrigin" in cd:
        raise Refuse("bad_client_data")
    allowed = context["native_rps"][rp_id] if rp_kind == "native" else [origin_of(base_url)]
    if cd.get("origin") not in allowed:
        raise Refuse("bad_client_data")
    return cd


def _check_challenge(cd: dict, expected: bytes) -> None:
    try:
        got = strict_b64u(cd["challenge"], 32, 32)
    except ValueError as exc:
        raise Refuse("challenge_mismatch") from exc
    if not hmac.compare_digest(got, expected):
        raise Refuse("challenge_mismatch")


def _rp_and_base_url(context: dict, rp_id: str, base_url: str) -> str:
    base_urls, native, web = accepted(context)
    kind = "native" if rp_id in native else "web" if rp_id in web else ""
    if not kind:
        raise Refuse("rp_not_accepted")
    if base_url not in base_urls:
        raise Refuse("base_url_not_accepted")
    if kind == "web" and host_of(base_url) != rp_id:
        raise Refuse("rp_host_mismatch")
    return kind


_ASSERTION_KEYS = {"v", "rp_id", "base_url", "credential_id", "authenticator_data", "client_data_json", "signature"}


def evaluate_assertion(context: dict, vector: dict) -> dict:
    request, store, answer = vector["request"], vector["store"], vector["answer"]
    user = request["user_id"]
    try:  # 1
        if not isinstance(answer, dict) or set(answer) != {"decision", "method", "passkey"}:
            raise ValueError
        if answer["decision"] != "confirmed" or answer["method"] != "passkey":
            raise ValueError
        p = answer["passkey"]
        if not isinstance(p, dict) or not _ASSERTION_KEYS <= set(p) <= _ASSERTION_KEYS | {"user_handle"}:
            raise ValueError
        if type(p["v"]) is not int or p["v"] != 1:
            raise ValueError
        if not (isinstance(p["rp_id"], str) and 1 <= len(p["rp_id"]) <= 253):
            raise ValueError
        if not (isinstance(p["base_url"], str) and 1 <= len(p["base_url"]) <= 512):
            raise ValueError
        strict_b64u(p["credential_id"], 1, 1023)
        auth = strict_b64u(p["authenticator_data"], 37, 1024)
        cdj = strict_b64u(p["client_data_json"], 1, 4096)
        signature = strict_b64u(p["signature"], 8, 72)
        handle = strict_b64u(p["user_handle"], 1, 64) if "user_handle" in p else None
    except (ValueError, KeyError) as exc:
        raise Refuse("bad_shape") from exc
    cred = next((c for c in store if c["credential_id"] == p["credential_id"] and c["user_id"] == user
                 and c["active"] and c["rp_id"] == p["rp_id"]), None)  # 2
    if cred is None:
        raise Refuse("unknown_credential")
    if handle is not None and not hmac.compare_digest(handle, user_handle(unb64u(context["handle_key"]), user)):
        raise Refuse("unknown_credential")
    kind = _rp_and_base_url(context, p["rp_id"], p["base_url"])  # 3, 4, 5
    cd = _client_data(cdj, type_="webauthn.get", rp_kind=kind, rp_id=p["rp_id"], base_url=p["base_url"],
                      context=context)  # 6
    _check_challenge(cd, challenge(  # 7
        purpose="confirm", base_url=p["base_url"], gateway_id=unb64u(context["gateway_id"]), user_id=user,
        session_id=request["session_id"], request_id=request["request_id"], nonce=unb64u(request["nonce"]),
        digest=text_digest(request["title"], request["summary"], request["detail"])))
    flags = auth[32]  # 8
    if auth[:32] != sha256(p["rp_id"].encode("utf-8")) or flags & FLAG_AT or (flags & FLAG_BS and not flags & FLAG_BE):
        raise Refuse("bad_authenticator_data")
    if flags & FLAG_ED:
        try:
            extensions, end = cbor_decode(auth, 37)
        except CborError as exc:
            raise Refuse("bad_authenticator_data") from exc
        if not isinstance(extensions, dict) or end != len(auth):
            raise Refuse("bad_authenticator_data")
    elif len(auth) != 37:
        raise Refuse("bad_authenticator_data")
    if not (flags & FLAG_UP and flags & FLAG_UV):  # 9
        raise Refuse("uv_required")
    if bool(flags & FLAG_BE) != cred["backup_eligible"]:  # 10
        raise Refuse("backup_state_mismatch")
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(cred["public_key"]["x"]), "big"),
                                           int.from_bytes(unb64u(cred["public_key"]["y"]), "big"),
                                           ec.SECP256R1()).public_key()
    try:  # 11
        public.verify(signature, auth + sha256(cdj), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise Refuse("signature_invalid") from exc
    count, stored = struct.unpack(">I", auth[33:37])[0], cred["sign_count"]  # 12
    regressed = not (count == 0 and stored == 0) and count <= stored
    if regressed and not cred["backup_eligible"]:
        raise Refuse("counter_regression")
    return {"ok": True, "sign_count": count, "backup_eligible": bool(flags & FLAG_BE),
            "backed_up": bool(flags & FLAG_BS), "counter_warning": regressed}


def evaluate_registration(context: dict, vector: dict) -> dict:
    begin, finish = vector["begin"], vector["finish"]
    try:  # 1
        credential = finish["credential"]
        cred_id = strict_b64u(credential["id"], 1, 1023)
        cdj = strict_b64u(credential["client_data_json"], 1, 4096)
        att = strict_b64u(credential["attestation_object"], 1, 16384)
        if finish["registration_id"] != begin["registration_id"] or finish["base_url"] != begin["base_url"]:
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise Refuse("bad_shape") from exc
    kind = _rp_and_base_url(context, begin["rp_id"], begin["base_url"])  # 2, 3, 4
    cd = _client_data(cdj, type_="webauthn.create", rp_kind=kind, rp_id=begin["rp_id"],
                      base_url=begin["base_url"], context=context)  # 5
    _check_challenge(cd, challenge(  # 6
        purpose="register", base_url=begin["base_url"], gateway_id=unb64u(context["gateway_id"]),
        user_id=begin["user"]["id"], session_id="", request_id=begin["registration_id"],
        nonce=unb64u(begin["nonce"]), digest=text_digest("", begin["name"], "")))
    try:  # 7
        obj, end = cbor_decode(att)
        if end != len(att) or not isinstance(obj, dict) or set(obj) != {"fmt", "attStmt", "authData"}:
            raise CborError("shape")
        if not isinstance(obj["fmt"], str) or not isinstance(obj["attStmt"], dict) or not isinstance(obj["authData"], bytes):
            raise CborError("types")
    except CborError as exc:
        raise Refuse("bad_attestation_object") from exc
    auth = obj["authData"]
    try:  # 8
        if len(auth) < 37 or auth[:32] != sha256(begin["rp_id"].encode("utf-8")):
            raise CborError("rp")
        flags = auth[32]
        if not flags & FLAG_AT or (flags & FLAG_BS and not flags & FLAG_BE) or len(auth) < 55:
            raise CborError("flags")
        id_len = struct.unpack(">H", auth[53:55])[0]
        if auth[55:55 + id_len] != cred_id:
            raise CborError("credential id")
        cose, pos = cbor_decode(auth, 55 + id_len)
        if not isinstance(cose, dict):
            raise CborError("cose")
        if flags & FLAG_ED:
            extensions, pos = cbor_decode(auth, pos)
            if not isinstance(extensions, dict):
                raise CborError("extensions")
        if pos != len(auth):
            raise CborError("trailing")
    except CborError as exc:
        raise Refuse("bad_authenticator_data") from exc
    if not (flags & FLAG_UP and flags & FLAG_UV):  # 9
        raise Refuse("uv_required")
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:  # 10
        raise Refuse("unsupported_algorithm")
    x, y = cose.get(-2), cose.get(-3)  # 11
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
        raise Refuse("bad_public_key")
    try:
        ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise Refuse("bad_public_key") from exc
    return {"ok": True, "credential_id": credential["id"], "rp_id": begin["rp_id"], "alg": -7,
            "public_key": {"x": b64u(x), "y": b64u(y)}, "sign_count": struct.unpack(">I", auth[33:37])[0],
            "backup_eligible": bool(flags & FLAG_BE), "backed_up": bool(flags & FLAG_BS), "aaguid": b64u(auth[37:53])}


# ── fixture ───────────────────────────────────────────────────────────────────────────────────

GATEWAY_ID = det("gateway id", 16)
HANDLE_KEY = det("handle key", 32)
NATIVE_RP = "confirm.hermie.dev"
NATIVE_CLIENT_ORIGIN = "https://confirm.hermie.dev"
GW = "https://gw.example.com"
OTHER_GW = "https://other.example.com"
LAN = "http://192.168.1.10:9119"
EVIL = "https://evil.example.net"
ALICE_GW, BOB_GW = "https://shared.example/alice", "https://shared.example/bob"
WEB_RP = "gw.example.com"
OLD_WEB_RP = "old.example.org"
USER = "self_hosted:7c1f0e2a"
USER_NAME = "Alex Example"
OTHER_USER = "self_hosted:91b44d03"
AAGUID = det("aaguid", 16)


def _context(base_urls: list[str], *, allow_private: bool = False, description: str) -> dict:
    ctx: dict[str, Any] = {"description": description, "gateway_id": b64u(GATEWAY_ID), "handle_key": b64u(HANDLE_KEY),
           "base_urls": base_urls, "allow_private_base_urls": allow_private,
           "native_rps": {NATIVE_RP: [NATIVE_CLIENT_ORIGIN]}, "user": {"id": USER, "name": USER_NAME}}
    urls, native, web = accepted(ctx)
    ctx["derived"] = {"accepted_base_urls": urls, "accepted_rps": {"native": native, "web": web},
                      "capability_reason": capability_reason(ctx)}
    return ctx


CONTEXTS = {
    "main": _context([GW, OTHER_GW, LAN], description="A public gateway that also lists a LAN address."),
    "private_allowed": _context([GW, OTHER_GW, LAN], allow_private=True,
                                description="The same, with the operator's opt-in for private base URLs."),
    "only_private": _context([LAN], description="Only a LAN address listed and no opt-in: level not offered."),
    "prefixed": _context([ALICE_GW], description="One of two gateways sharing a host under path prefixes."),
}

CRED_NATIVE = b64u(det("credential native", 32))
CRED_WEB = b64u(det("credential web", 20))
CRED_OLD = b64u(det("credential old web", 20))
CRED_OTHER_USER = b64u(det("credential other user", 32))
CRED_REVOKED = b64u(det("credential revoked", 32))
CRED_SYNCED_COUNTED = b64u(det("credential synced with counter", 32))
CRED_SHARED_WEB = b64u(det("credential shared host web", 20))


def stored(credential_id: str, key: Key, rp_id: str, *, user_id: str = USER, sign_count: int = 0,
           backup_eligible: bool = True, backed_up: bool = True, active: bool = True) -> dict:
    return {"credential_id": credential_id, "user_id": user_id, "rp_id": rp_id, "alg": -7,
            "public_key": {"x": b64u(key.x), "y": b64u(key.y)}, "sign_count": sign_count,
            "backup_eligible": backup_eligible, "backed_up": backed_up, "active": active}


STORE = [
    stored(CRED_NATIVE, KEYS["credential-a"], NATIVE_RP),
    stored(CRED_WEB, KEYS["credential-b"], WEB_RP, sign_count=10, backup_eligible=False, backed_up=False),
    stored(CRED_OLD, KEYS["credential-b"], OLD_WEB_RP, backup_eligible=False, backed_up=False),
    stored(CRED_OTHER_USER, KEYS["other-c"], NATIVE_RP, user_id=OTHER_USER),
    stored(CRED_REVOKED, KEYS["credential-a"], NATIVE_RP, active=False),
    stored(CRED_SYNCED_COUNTED, KEYS["credential-a"], NATIVE_RP, sign_count=10),
    stored(CRED_SHARED_WEB, KEYS["credential-b"], "shared.example", backup_eligible=False, backed_up=False),
]

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


def request_challenge(req: dict, base_url: str, **override) -> bytes:
    fields: dict[str, Any] = dict(purpose="confirm", base_url=base_url, gateway_id=GATEWAY_ID, user_id=req["user_id"],
                                  session_id=req["session_id"], request_id=req["request_id"],
                                  nonce=unb64u(req["nonce"]),
                                  digest=text_digest(req["title"], req["summary"], req["detail"]))
    fields.update(override)
    return challenge(**fields)


def client_data(type_: str, chal: str, origin: str, *, cross_origin: Any = False, extra: str = "") -> bytes:
    body = f'{{"type":"{type_}","challenge":{chal},"origin":"{origin}"'
    if cross_origin is not None:
        body += f',"crossOrigin":{json.dumps(cross_origin)}'
    return (body + extra + "}").encode("utf-8")


def auth_data(rp_id: str, flags: int, sign_count: int, tail: bytes = b"") -> bytes:
    return sha256(rp_id.encode("utf-8")) + bytes([flags]) + struct.pack(">I", sign_count) + tail


SYNCED = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS
DEVICE = FLAG_UP | FLAG_UV


# ── assertion vectors ─────────────────────────────────────────────────────────────────────────


class A:
    """One assertion vector: a valid native answer for REQUEST at GW, changed by the keyword arguments."""

    def __init__(self, name, *, expect, reason=None, description="", context="main", rp_id=NATIVE_RP,
                 base_url=GW, credential_id=CRED_NATIVE, key="credential-a", flags=SYNCED, sign_count=0,
                 cd_type="webauthn.get", cd_origin=None, cross_origin=False, cd_extra="", cd_raw=None,
                 chal_json=None, chal_base_url=None, chal_override=None, ad_tail=b"", ad_rp=None,
                 user_handle_for=USER, signature=None, patch=None, request=None, counter_warning=False):
        self.name, self.expect, self.reason, self.description = name, expect, reason, description
        self.context, self.counter_warning = context, counter_warning
        self.request = request or REQUEST
        if cd_origin is None:
            cd_origin = NATIVE_CLIENT_ORIGIN if rp_id == NATIVE_RP else origin_of(base_url)
        chal = request_challenge(self.request, chal_base_url or base_url, **(chal_override or {}))
        self.cdj = cd_raw if cd_raw is not None else client_data(
            cd_type, chal_json if chal_json is not None else json.dumps(b64u(chal)), cd_origin,
            cross_origin=cross_origin, extra=cd_extra)
        self.ad = auth_data(ad_rp or rp_id, flags, sign_count, ad_tail)
        self.key = KEYS[key]
        self.signature = signature
        self.passkey = {"v": 1, "rp_id": rp_id, "base_url": base_url, "credential_id": credential_id,
                        "authenticator_data": b64u(self.ad), "client_data_json": b64u(self.cdj)}
        if user_handle_for is not None:
            self.passkey["user_handle"] = b64u(user_handle(HANDLE_KEY, user_handle_for))
        self.patch = patch

    def build(self) -> dict:
        valid = self.key.sign(self.ad + sha256(self.cdj))
        signature = self.signature(valid) if callable(self.signature) else valid
        answer: dict[str, Any] = {"decision": "confirmed", "method": "passkey",
                                  "passkey": dict(self.passkey, signature=b64u(signature))}
        if self.patch:
            answer = self.patch(answer)
        if self.expect == "accept":
            flags = self.ad[32]
            expect: dict[str, Any] = {"ok": True, "sign_count": struct.unpack(">I", self.ad[33:37])[0],
                                      "backup_eligible": bool(flags & FLAG_BE), "backed_up": bool(flags & FLAG_BS),
                                      "counter_warning": self.counter_warning}
        else:
            expect = {"ok": False, "code": 4034, "reason": self.reason}
        return {"name": self.name, "description": self.description, "context": self.context,
                "request": self.request, "store": STORE, "answer": answer, "signed_by": self.key.name,
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
    big = ',"padding":"' + "x" * 4096 + '"'
    other_request = dict(REQUEST, request_id="srq-000000000099")
    other_request_nonce = dict(REQUEST, request_id="srq-000000000098", nonce=b64u(det("another nonce", 32)))
    web = dict(rp_id=WEB_RP, credential_id=CRED_WEB, key="credential-b", flags=DEVICE, sign_count=11,
               user_handle_for=None)
    return [
        # accepted
        A("native passkey, synced, counter 0/0", expect="accept",
          description="Native app, shared RP, listed https gateway; BE and BS set; signCount 0 stays 0."),
        A("web passkey, device-bound, counter increases", expect="accept", **web,
          cd_extra=',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"',
          description="Browser on the gateway origin; RP = that host; unknown clientDataJSON keys are ignored."),
        A("counter from 0 to 5", expect="accept", sign_count=5),
        A("extensions map with the ED flag", expect="accept", flags=SYNCED | FLAG_ED,
          ad_tail=cbor({"credProtect": 2}), description="One well-formed CBOR map after the 37 bytes is ignored."),
        A("high-S signature", expect="accept", signature=high_s,
          description="ES256 in WebAuthn does not require low S; a verifier must not reject the high form."),
        A("synced passkey counter regression is accepted with a warning", expect="accept",
          credential_id=CRED_SYNCED_COUNTED, sign_count=5, counter_warning=True,
          description="BE=1: the counter is per device for a synced passkey, so a lower value is audited, "
                      "not refused."),
        A("listed private base URL with the operator's opt-in", expect="accept", context="private_allowed",
          base_url=LAN, description="Accepted only because the operator opted in; see README §10."),
        A("gateway under a path prefix", expect="accept", context="prefixed", base_url=ALICE_GW),
        # bad_shape
        A("missing signature", expect="refuse", reason="bad_shape", patch=_drop("signature")),
        A("padded base64url", expect="refuse", reason="bad_shape", patch=_pad("authenticator_data")),
        A("unknown version", expect="refuse", reason="bad_shape", patch=_set(["passkey", "v"], 2)),
        A("unknown key in the passkey object", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "extension"], "x")),
        A("client-sent verified at the top level", expect="refuse", reason="bad_shape", patch=_set(["verified"], True)),
        A("confirmed with method tap", expect="refuse", reason="bad_shape", patch=_set(["method"], "tap")),
        A("client data over 4096 bytes", expect="refuse", reason="bad_shape", cd_extra=big),
        A("authenticator data under 37 bytes", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "authenticator_data"], b64u(auth_data(NATIVE_RP, SYNCED, 0)[:36]))),
        A("signature over 72 bytes", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "signature"], b64u(det("long signature", 73)))),
        A("credential id over 1023 bytes", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "credential_id"], b64u(det("long credential id", 1024)))),
        A("user handle over 64 bytes", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "user_handle"], b64u(det("long handle", 65)))),
        A("rp_id over 253 characters", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "rp_id"], "a" * 254)),
        A("base_url over 512 characters", expect="refuse", reason="bad_shape",
          patch=_set(["passkey", "base_url"], GW + "/" + "p" * 500)),
        # unknown_credential
        A("credential id not stored", expect="refuse", reason="unknown_credential",
          credential_id=b64u(det("credential never stored", 32))),
        A("credential of another user", expect="refuse", reason="unknown_credential", credential_id=CRED_OTHER_USER,
          key="other-c", user_handle_for=OTHER_USER),
        A("revoked credential", expect="refuse", reason="unknown_credential", credential_id=CRED_REVOKED),
        A("credential stored for another RP", expect="refuse", reason="unknown_credential", rp_id=WEB_RP),
        A("user handle of another user", expect="refuse", reason="unknown_credential", user_handle_for=OTHER_USER),
        # rp_not_accepted
        A("web RP whose base URL is no longer listed", expect="refuse", reason="rp_not_accepted", rp_id=OLD_WEB_RP,
          credential_id=CRED_OLD, key="credential-b", flags=DEVICE, base_url="https://old.example.org"),
        A("native RP while only private base URLs are listed", expect="refuse", reason="rp_not_accepted",
          context="only_private", base_url=LAN),
        A("web RP of a gateway under a path prefix", expect="refuse", reason="rp_not_accepted", context="prefixed",
          rp_id="shared.example", base_url=ALICE_GW, credential_id=CRED_SHARED_WEB, key="credential-b", flags=DEVICE,
          user_handle_for=None, description="Gateways sharing an origin share the browser's security boundary; "
                                            "the web path is only offered on a base URL without a path prefix."),
        # base_url_not_accepted
        A("relay: valid signature for another gateway's base URL", expect="refuse", reason="base_url_not_accepted",
          base_url=EVIL, description="An attacker's gateway had the app sign for its own base URL and replays the "
                                     "answer as-is. Signature valid; the base URL is not listed here."),
        A("relay between two gateways on one host", expect="refuse", reason="base_url_not_accepted",
          context="prefixed", base_url=BOB_GW,
          description="Signed for https://shared.example/bob, replayed at the gateway listing only /alice."),
        A("base URL claim not in canonical form", expect="refuse", reason="base_url_not_accepted",
          base_url="https://GW.example.com:443/", chal_base_url=GW),
        A("private base URL without the operator's opt-in", expect="refuse", reason="base_url_not_accepted",
          base_url=LAN),
        # rp_host_mismatch
        A("web RP with another listed gateway's base URL", expect="refuse", reason="rp_host_mismatch",
          **dict(web, rp_id=WEB_RP), base_url=OTHER_GW,
          description="Both base URLs are listed, but a web RP must be the host of the base URL."),
        # bad_client_data
        A("type webauthn.create in an assertion", expect="refuse", reason="bad_client_data", cd_type="webauthn.create"),
        A("crossOrigin true", expect="refuse", reason="bad_client_data", cross_origin=True),
        A("crossOrigin not a boolean", expect="refuse", reason="bad_client_data", cross_origin="false"),
        A("topOrigin present", expect="refuse", reason="bad_client_data", cd_extra=',"topOrigin":"https://gw.example.com"'),
        A("challenge not a string", expect="refuse", reason="bad_client_data", chal_json="12345"),
        A("native client origin not allowed for the RP", expect="refuse", reason="bad_client_data", cd_origin=EVIL),
        A("web client origin differs from the base URL's origin", expect="refuse", reason="bad_client_data", **web,
          cd_origin="https://gw.example.com:8443"),
        A("client data is not a JSON object", expect="refuse", reason="bad_client_data", cd_raw=b'["webauthn.get"]'),
        A("client data with a duplicate key", expect="refuse", reason="bad_client_data",
          cd_extra=',"type":"webauthn.get"'),
        # challenge_mismatch
        A("relay: listed base URL claimed, challenge made for another gateway", expect="refuse",
          reason="challenge_mismatch", chal_base_url=EVIL),
        A("relay between two gateways on one host, own base URL claimed", expect="refuse",
          reason="challenge_mismatch", context="prefixed", base_url=ALICE_GW, chal_base_url=BOB_GW),
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
        A("answer replayed onto another request", expect="refuse", reason="challenge_mismatch", request=other_request,
          chal_override={"request_id": REQUEST["request_id"]}),
        A("answer replayed onto another request with another nonce", expect="refuse", reason="challenge_mismatch",
          request=other_request_nonce,
          chal_override={"request_id": REQUEST["request_id"], "nonce": unb64u(REQUEST["nonce"])}),
        A("challenge padded", expect="refuse", reason="challenge_mismatch",
          chal_json=json.dumps(b64u(request_challenge(REQUEST, GW)) + "=")),
        A("challenge of 31 bytes", expect="refuse", reason="challenge_mismatch",
          chal_json=json.dumps(b64u(request_challenge(REQUEST, GW)[:31]))),
        # bad_authenticator_data
        A("rpIdHash of another RP", expect="refuse", reason="bad_authenticator_data", ad_rp=WEB_RP),
        A("attested credential data flag in an assertion", expect="refuse", reason="bad_authenticator_data",
          flags=SYNCED | FLAG_AT),
        A("trailing bytes without the extension flag", expect="refuse", reason="bad_authenticator_data",
          ad_tail=b"\x00"),
        A("extension flag with malformed CBOR", expect="refuse", reason="bad_authenticator_data",
          flags=SYNCED | FLAG_ED, ad_tail=b"\xbf\x61a\x01\xff"),
        A("extension flag with bytes after the map", expect="refuse", reason="bad_authenticator_data",
          flags=SYNCED | FLAG_ED, ad_tail=cbor({"credProtect": 2}) + b"\x00"),
        A("backup state without backup eligibility", expect="refuse", reason="bad_authenticator_data",
          flags=FLAG_UP | FLAG_UV | FLAG_BS),
        # uv_required
        A("user verification flag clear", expect="refuse", reason="uv_required", flags=FLAG_UP | FLAG_BE | FLAG_BS),
        A("user presence flag clear", expect="refuse", reason="uv_required", flags=FLAG_UV | FLAG_BE | FLAG_BS),
        # backup_state_mismatch
        A("backup eligibility changed since registration", expect="refuse", reason="backup_state_mismatch",
          flags=DEVICE),
        # signature_invalid
        A("signature by another key", expect="refuse", reason="signature_invalid", key="credential-b"),
        A("structurally valid DER, wrong values", expect="refuse", reason="signature_invalid",
          signature=lambda _valid: bytes.fromhex("3006020101020101")),
        A("raw 64-byte r and s instead of DER", expect="refuse", reason="signature_invalid", signature=raw_rs,
          description="WebAuthn ES256 signatures are ASN.1 DER; the raw form of a valid signature is refused."),
        # counter_regression
        A("counter equal to the stored one (device-bound)", expect="refuse", reason="counter_regression",
          **dict(web, sign_count=10)),
        A("counter back to 0 after 10 (device-bound)", expect="refuse", reason="counter_regression",
          **dict(web, sign_count=0)),
    ]


# ── registration vectors ──────────────────────────────────────────────────────────────────────

REG_ID = "reg-5d1e0a77b3c4"
REG_NONCE = det("registration nonce", 32)
REG_NAME = "Alex Example — gw.example.com"
REG_CRED_ID = det("registered credential", 32)
ENROLMENT_CODE = enrolment_code_display(det("enrolment code", 13))


def reg_begin(**override) -> dict:
    begin = {"registration_id": REG_ID, "rp_id": NATIVE_RP, "base_url": GW, "name": REG_NAME,
             "nonce": b64u(REG_NONCE), "user": {"id": USER, "handle": b64u(user_handle(HANDLE_KEY, USER))}}
    begin.update(override)
    return begin


def reg_challenge(begin: dict, **override) -> bytes:
    fields: dict[str, Any] = dict(purpose="register", base_url=begin["base_url"], gateway_id=GATEWAY_ID,
                                  user_id=USER, session_id="", request_id=begin["registration_id"], nonce=REG_NONCE,
                                  digest=text_digest("", begin["name"], ""))
    fields.update(override)
    return challenge(**fields)


def reg_auth_data(*, rp_id=NATIVE_RP, flags=FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT, cose=None,
                  cred_id=REG_CRED_ID, tail=b"") -> bytes:
    key = KEYS["credential-a"]
    attested = AAGUID + struct.pack(">H", len(cred_id)) + cred_id + (cose if cose is not None else cose_es256(key))
    return auth_data(rp_id, flags, 0, attested + tail)


def att(ad: bytes, **fields) -> bytes:
    return cbor({"fmt": "none", "attStmt": {}, "authData": ad, **fields})


def registration_vectors() -> list[dict]:
    key = KEYS["credential-a"]
    good_ad = reg_auth_data()
    good_att = att(good_ad)
    off_curve = cbor({1: 2, 3: -7, -1: 1, -2: key.x, -3: det("not a y coordinate", 32)})
    short_x = cbor({1: 2, 3: -7, -1: 1, -2: key.x[:31], -3: key.y})
    rs256 = cbor({1: 3, 3: -257, -1: det("modulus", 256), -2: b"\x01\x00\x01"})
    p384 = cbor({1: 2, 3: -7, -1: 2, -2: key.x, -3: key.y})

    def cd(begin, *, type_="webauthn.create", origin=NATIVE_CLIENT_ORIGIN, **override):
        return client_data(type_, json.dumps(b64u(reg_challenge(begin, **override))), origin)

    main = reg_begin()
    lan = reg_begin(base_url=LAN)
    evil = reg_begin(base_url=EVIL)
    web = reg_begin(rp_id=WEB_RP)
    old_web = reg_begin(rp_id=OLD_WEB_RP, base_url="https://old.example.org")
    cases: list[tuple] = [
        # name, expect/reason, begin, client data, attestation object, finish patch, description
        ("native registration", None, main, cd(main), good_att, None,
         "fmt none, empty attStmt, ES256 key; BE and BS set (a synced passkey)."),
        ("attestation statement is ignored", None, main, cd(main),
         cbor({"fmt": "packed", "attStmt": {"alg": -7, "sig": b"\x30\x00"}, "authData": good_ad}), None,
         "Any fmt is accepted and its statement is not checked."),
        ("web registration with an extensions map", None, web, cd(web, origin=GW),
         att(reg_auth_data(rp_id=WEB_RP, flags=FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED, tail=cbor({"credProtect": 2}))),
         None, "Device-bound; ED set and one extensions map after the COSE key."),
        ("finish base URL differs from begin", "bad_shape", main, cd(main), good_att,
         _set(["base_url"], OTHER_GW), ""),
        ("attestation object not base64url", "bad_shape", main, cd(main), good_att,
         _set(["credential", "attestation_object"], "not base64url!"), ""),
        ("web RP no longer listed", "rp_not_accepted", old_web, cd(old_web, origin="https://old.example.org"),
         att(reg_auth_data(rp_id=OLD_WEB_RP)), None, ""),
        ("base URL not listed", "base_url_not_accepted", evil, cd(evil), good_att, None, ""),
        ("private base URL without opt-in", "base_url_not_accepted", lan, cd(lan), good_att, None, ""),
        ("web RP with another gateway's base URL", "rp_host_mismatch", reg_begin(rp_id=WEB_RP, base_url=OTHER_GW),
         cd(reg_begin(rp_id=WEB_RP, base_url=OTHER_GW), origin=OTHER_GW), att(reg_auth_data(rp_id=WEB_RP)), None, ""),
        ("type webauthn.get", "bad_client_data", main, cd(main, type_="webauthn.get"), good_att, None, ""),
        ("challenge with purpose confirm", "challenge_mismatch", main, cd(main, purpose="confirm"), good_att, None, ""),
        ("challenge for another credential name", "challenge_mismatch", main,
         cd(main, digest=text_digest("", "Someone — evil.example.net", "")), good_att, None, ""),
        ("malformed CBOR: indefinite-length map", "bad_attestation_object", main, cd(main),
         b"\xbf" + good_att[1:] + b"\xff", None, ""),
        ("malformed CBOR: duplicate key", "bad_attestation_object", main, cd(main),
         _head(5, 3) + cbor("fmt") + cbor("none") + cbor("fmt") + cbor("none") + cbor("authData") + cbor(good_ad),
         None, ""),
        ("malformed CBOR: trailing byte", "bad_attestation_object", main, cd(main), good_att + b"\x00", None, ""),
        ("malformed CBOR: truncated", "bad_attestation_object", main, cd(main), good_att[:-5], None, ""),
        ("malformed CBOR: tag", "bad_attestation_object", main, cd(main), b"\xc0" + good_att, None, ""),
        ("attStmt not a map", "bad_attestation_object", main, cd(main),
         cbor({"fmt": "none", "attStmt": [], "authData": good_ad}), None, ""),
        ("fmt not text", "bad_attestation_object", main, cd(main),
         cbor({"fmt": 1, "attStmt": {}, "authData": good_ad}), None, ""),
        ("extra key in the attestation object", "bad_attestation_object", main, cd(main),
         att(good_ad, extra=1), None, ""),
        ("authData without attested credential data", "bad_authenticator_data", main, cd(main),
         att(auth_data(NATIVE_RP, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS, 0)), None, ""),
        ("authData for another RP", "bad_authenticator_data", main, cd(main),
         att(reg_auth_data(rp_id=WEB_RP)), None, ""),
        ("credential id in authData differs from credential.id", "bad_authenticator_data", main, cd(main),
         att(reg_auth_data(cred_id=det("another credential", 32))), None, ""),
        ("backup state without backup eligibility", "bad_authenticator_data", main, cd(main),
         att(reg_auth_data(flags=FLAG_UP | FLAG_UV | FLAG_BS | FLAG_AT)), None, ""),
        ("extension flag set but no extensions map", "bad_authenticator_data", main, cd(main),
         att(reg_auth_data(flags=FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT | FLAG_ED)), None, ""),
        ("extensions map without the extension flag", "bad_authenticator_data", main, cd(main),
         att(reg_auth_data(tail=cbor({"credProtect": 2}))), None, ""),
        ("user verification flag clear", "uv_required", main, cd(main),
         att(reg_auth_data(flags=FLAG_UP | FLAG_AT)), None, ""),
        ("user presence flag clear", "uv_required", main, cd(main),
         att(reg_auth_data(flags=FLAG_UV | FLAG_AT)), None, ""),
        ("RS256 key", "unsupported_algorithm", main, cd(main), att(reg_auth_data(cose=rs256)), None, ""),
        ("EC2 key on another curve", "unsupported_algorithm", main, cd(main), att(reg_auth_data(cose=p384)), None, ""),
        ("x coordinate of 31 bytes", "bad_public_key", main, cd(main), att(reg_auth_data(cose=short_x)), None, ""),
        ("point not on P-256", "bad_public_key", main, cd(main), att(reg_auth_data(cose=off_curve)), None, ""),
    ]
    out = []
    for name, reason, begin, cdj, att_obj, patch, description in cases:
        finish: dict[str, Any] = {
            "registration_id": begin["registration_id"], "base_url": begin["base_url"], "code": ENROLMENT_CODE,
            "credential": {"id": b64u(REG_CRED_ID), "client_data_json": b64u(cdj),
                           "attestation_object": b64u(att_obj), "transports": ["internal", "hybrid"]}}
        if patch:
            finish = patch(finish)
        if reason is None:
            ad = cbor_decode(att_obj)[0]["authData"]
            flags = ad[32]
            expect = {"ok": True, "credential_id": b64u(REG_CRED_ID), "rp_id": begin["rp_id"], "alg": -7,
                      "public_key": {"x": b64u(key.x), "y": b64u(key.y)}, "sign_count": 0,
                      "backup_eligible": bool(flags & FLAG_BE), "backed_up": bool(flags & FLAG_BS),
                      "aaguid": b64u(AAGUID)}
        else:
            expect = {"ok": False, "status": 422, "error": "attestation_invalid", "reason": reason}
        out.append({"name": name, "description": description, "context": "main", "begin": begin,
                    "finish": finish, "expect": expect})
    return out


# ── simple vectors ────────────────────────────────────────────────────────────────────────────

BASE_URL_INPUTS = [
    ("plain https", "https://gw.example.com"),
    ("trailing slash dropped", "https://gw.example.com/"),
    ("default https port dropped", "https://gw.example.com:443"),
    ("default http port dropped", "http://gw.example.com:80"),
    ("explicit port kept", "https://gw.example.com:8443"),
    ("http on the https default port keeps it", "http://gw.example.com:443"),
    ("upper case scheme and host", "HTTPS://GW.Example.COM/"),
    ("query and fragment dropped", "https://gw.example.com/?x=1#y"),
    ("userinfo dropped", "https://someone:secret@gw.example.com"),
    ("path prefix kept, trailing slash dropped", "https://shared.example/alice/"),
    ("path prefix is case-sensitive", "https://Shared.Example/Alice"),
    ("nested path prefix", "https://shared.example/gw/alice"),
    ("percent-encoding normalised to upper case", "https://shared.example/a%2fb"),
    ("ipv4 with port", "http://192.168.1.10:9119"),
    ("ipv6 lower-cased", "http://[FE80::1]:9119"),
    ("ipv6 compressed", "https://[2001:DB8:0:0:0:0:0:1]"),
    ("idn to a-label", "https://bücher.example"),
    ("idn upper case to a-label", "https://BÜCHER.Example:8443"),
    ("idn sharp s kept (non-transitional)", "https://straße.example"),
    ("localhost", "http://localhost:9119"),
]
BASE_URL_ERRORS = [
    ("other scheme", "ftp://gw.example.com"),
    ("no scheme", "gw.example.com"),
    ("no host", "https://"),
    ("dot segment", "https://shared.example/alice/../bob"),
    ("empty segment", "https://shared.example//alice"),
    ("space in the path", "https://shared.example/al ice"),
]


def base_url_vectors() -> list[dict]:
    out = []
    for name, url in BASE_URL_INPUTS:
        value = serialise_base_url(url)
        out.append({"name": name, "input": url, "base_url": value, "origin": origin_of(value),
                    "private": is_private(value)})
    for name, url in BASE_URL_ERRORS:
        try:
            serialise_base_url(url)
        except ValueError:
            out.append({"name": name, "input": url, "error": "not_a_base_url"})
        else:
            raise AssertionError(f"{url} should not serialise")
    for name, url in (("public https IP literal", "https://203.0.113.7"), ("CGNAT", "https://100.64.1.1"),
                      ("single-label host", "https://gateway"), (".internal", "https://gw.corp.internal"),
                      ("loopback IPv6", "https://[::1]")):
        value = serialise_base_url(url)
        out.append({"name": name, "input": url, "base_url": value, "origin": origin_of(value),
                    "private": is_private(value)})
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
        ("confirm, https default port", "confirm", GW, REQUEST["session_id"], REQUEST["request_id"],
         REQUEST["title"], REQUEST["summary"], REQUEST["detail"]),
        ("confirm, explicit port", "confirm", "https://gw.example.com:8443", "s1", "srq-000000000001", "T", "S", None),
        ("confirm, ipv4 http", "confirm", LAN, "s1", "srq-000000000002", "T", "S", ""),
        ("confirm, ipv6", "confirm", "http://[fe80::1]:9119", "s1", "srq-000000000003", "T", "S", None),
        ("confirm, idn", "confirm", "https://xn--bcher-kva.example", "s1", "srq-000000000004", "T", "S", None),
        ("confirm, multi-byte text", "confirm", GW, "s1", "srq-000000000005", "Überweisung bestätigen",
         "Zahle 120,00 € 🧾", "日本語"),
        ("confirm, path prefix alice", "confirm", ALICE_GW, "s1", "srq-000000000006", "T", "S", None),
        ("confirm, path prefix bob (same host, other gateway)", "confirm", BOB_GW, "s1", "srq-000000000006",
         "T", "S", None),
        ("register", "register", GW, "", "reg-5d1e0a77b3c4", "", "Alex Example — gw.example.com", ""),
        ("invite", "invite", GW, "", "stp-0b8e4f2a9c61", "", "invite", ""),
        ("revoke", "revoke", GW, "", "stp-7a2c9e1d0f35", "", CRED_WEB, ""),
    ]
    out = []
    for i, (name, purpose, base_url, sid, rid, title, summary, detail) in enumerate(cases):
        nonce = det(f"challenge nonce {6 if 'path prefix' in name else i}", 32)
        digest = text_digest(title, summary, detail)
        pre = challenge_preimage(purpose=purpose, base_url=base_url, gateway_id=GATEWAY_ID, user_id=USER,
                                 session_id=sid, request_id=rid, nonce=nonce, digest=digest)
        out.append({"name": name, "purpose": purpose, "base_url": base_url, "gateway_id": b64u(GATEWAY_ID),
                    "user_id": USER, "session_id": sid, "request_id": rid, "nonce": b64u(nonce), "title": title,
                    "summary": summary, "detail": detail, "text_digest": b64u(digest), "preimage_hex": pre.hex(),
                    "challenge": b64u(sha256(pre))})
    return out


def handle_vectors() -> list[dict]:
    return [{"handle_key": b64u(HANDLE_KEY), "user_id": uid, "user_handle": b64u(user_handle(HANDLE_KEY, uid))}
            for uid in (USER, OTHER_USER, "basic:admin")]


def enrolment_code_vectors() -> list[dict]:
    plain = ENROLMENT_CODE.replace("-", "")
    inputs = [("as displayed", ENROLMENT_CODE), ("lower case, no hyphens", plain.lower()),
              ("spaces instead of hyphens", ENROLMENT_CODE.replace("-", " ")),
              ("look-alikes O, I, L", plain[:17] + "OIL"), ("too short", plain[:19]),
              ("U is not a symbol", "U" + plain[1:])]
    out = []
    for name, text in inputs:
        canonical = enrolment_code_canonical(text)
        out.append({"name": name, "input": text, "canonical": canonical,
                    "code_hash": b64u(sha256(canonical.encode("ascii"))) if canonical else None})
    return out


def wire_examples() -> dict:
    main = CONTEXTS["main"]
    return {
        "capabilities_first_result": {
            "server_requests": ["approval", "clarify", "confirm"], "confirm": [],
            "confirm_passkey": {"v": 1, "enabled": True, "reason": "", "gateway_id": b64u(GATEWAY_ID),
                                "rp": main["derived"]["accepted_rps"]}},
        "capabilities_first_result_private_only": {
            "server_requests": ["approval", "clarify", "confirm"], "confirm": [],
            "confirm_passkey": {"v": 1, "enabled": False, "reason": "private_origin",
                                "gateway_id": b64u(GATEWAY_ID), "rp": {"native": [], "web": []}}},
        "capabilities_first_result_without_passkey": {"server_requests": ["approval", "clarify", "confirm"],
                                                      "confirm": []},
        "capabilities_second_call_params_with_passkey": {
            "server_requests": True, "confirm": ["plain", "passkey"],
            "confirm_passkey": {"v": 1, "kind": "native", "rp_id": NATIVE_RP}},
        "capabilities_second_call_params_plain_only": {"server_requests": True, "confirm": ["plain"]},
        "capabilities_second_result": {"server_requests": ["approval", "clarify", "confirm"],
                                       "confirm": ["passkey", "plain"]},
        "confirm_request_frame": {
            "jsonrpc": "2.0", "id": REQUEST["request_id"], "method": "confirm",
            "params": {"session_id": REQUEST["session_id"], "title": REQUEST["title"], "summary": REQUEST["summary"],
                       "detail": REQUEST["detail"], "level": "passkey",
                       "passkey": {"v": 1, "nonce": REQUEST["nonce"], "gateway_id": b64u(GATEWAY_ID),
                                   "base_url": GW, "expires_at": REQUEST["expires_at"],
                                   "user": {"id": USER, "name": USER_NAME},
                                   "credentials": [{"rp_id": NATIVE_RP, "ids": [CRED_NATIVE]},
                                                   {"rp_id": WEB_RP, "ids": [CRED_WEB]}]}}},
        "result_declined": {"decision": "declined", "method": "tap"},
        "error_cannot_run_ceremony": {"jsonrpc": "2.0", "id": REQUEST["request_id"],
                                      "error": {"code": 4040, "message": "passkey ceremony unavailable",
                                                "data": {"reason": "no_credential"}}},
        "request_answer_refused": {"jsonrpc": "2.0", "id": 7, "error": {"code": 4034, "message": "answer refused",
                                                                        "data": {"reason": "challenge_mismatch"}}},
    }


REFUSAL_ORDER = ["bad_shape", "unknown_credential", "rp_not_accepted", "base_url_not_accepted", "rp_host_mismatch",
                 "bad_client_data", "challenge_mismatch", "bad_authenticator_data", "uv_required",
                 "backup_state_mismatch", "signature_invalid", "counter_regression"]
REGISTRATION_REFUSAL_ORDER = ["bad_shape", "rp_not_accepted", "base_url_not_accepted", "rp_host_mismatch",
                              "bad_client_data", "challenge_mismatch", "bad_attestation_object",
                              "bad_authenticator_data", "uv_required", "unsupported_algorithm", "bad_public_key"]


# ── build / check ─────────────────────────────────────────────────────────────────────────────


def _verdict(fn, context: dict, vector: dict, refusal: dict) -> dict:
    try:
        return fn(context, vector)
    except Refuse as exc:
        return {**refusal, "reason": str(exc)}


def build() -> tuple[dict, list[str]]:
    problems: list[str] = []
    assertions = [case.build() for case in assertion_cases()]
    registrations = registration_vectors()
    for vector in assertions:
        got = _verdict(evaluate_assertion, CONTEXTS[vector["context"]], vector, {"ok": False, "code": 4034})
        if got != vector["expect"]:
            problems.append(f"assertion {vector['name']!r}: labelled {vector['expect']}, the README gives {got}")
    for vector in registrations:
        got = _verdict(evaluate_registration, CONTEXTS[vector["context"]], vector,
                       {"ok": False, "status": 422, "error": "attestation_invalid"})
        if got != vector["expect"]:
            problems.append(f"registration {vector['name']!r}: labelled {vector['expect']}, the README gives {got}")
    for label, vectors, order in (("assertion", assertions, REFUSAL_ORDER),
                                  ("registration", registrations, REGISTRATION_REFUSAL_ORDER)):
        names = [v["name"] for v in vectors]
        if len(names) != len(set(names)):
            problems.append(f"duplicate {label} vector names")
        missing = set(order) - {v["expect"].get("reason") for v in vectors}
        if missing:
            problems.append(f"no {label} vector for {sorted(missing)}")
    doc = {
        "version": 1,
        "about": "Test vectors for the confirm level passkey. Construction and rules: README.md in this directory.",
        "encoding": "Binary values are base64url without padding. preimage_hex is lower-case hex.",
        "keys": {name: key.describe() for name, key in KEYS.items()},
        "contexts": CONTEXTS,
        "base_url_vectors": base_url_vectors(),
        "text_digest_vectors": text_vectors(),
        "challenge_vectors": challenge_vectors(),
        "user_handle_vectors": handle_vectors(),
        "enrolment_code_vectors": enrolment_code_vectors(),
        "assertion_refusal_order": REFUSAL_ORDER + ["too_many_attempts"],
        "assertion_vectors": assertions,
        "sequence_vectors": [{
            "name": "fifth refusal settles the request",
            "steps": ["challenge for other text", "challenge for another request", "signature by another key",
                      "rpIdHash of another RP", "user verification flag clear"],
            "expect": ["refused"] * 4 + ["settled"],
            "settled_outcome": {"outcome": "unavailable", "reason": "verification_failed",
                                "refusal_reason": "too_many_attempts"},
            "description": "Five refused answers for one request from connections allowed to answer it: the first "
                           "four leave it open; the fifth is refused with too_many_attempts and settles it. "
                           "Declines, 4033 refusals and client errors do not count.",
        }],
        "registration_refusal_order": REGISTRATION_REFUSAL_ORDER,
        "registration_vectors": registrations,
        "wire_examples": wire_examples(),
    }
    return doc, problems


def render(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def sums(texts: dict[str, bytes]) -> str:
    return "".join(f"{hashlib.sha256(texts[name]).hexdigest()}  {name}\n" for name in SUMMED)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or check the confirm passkey test vectors.")
    parser.add_argument("--check", action="store_true", help="compare with the committed files instead of writing")
    args = parser.parse_args(argv)
    doc, problems = build()
    rendered = render(doc)
    if args.check:
        if not VECTORS.exists() or VECTORS.read_text(encoding="utf-8") != rendered:
            problems.append("vectors.json differs from a rebuild: run generate.py")
        texts = {name: (HERE / name).read_bytes() for name in SUMMED if (HERE / name).exists()}
        if len(texts) != len(SUMMED) or not SUMS.exists() or SUMS.read_text(encoding="utf-8") != sums(texts):
            problems.append("SHA256SUMS does not match README.md, generate.py and vectors.json: run generate.py")
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    VECTORS.write_text(rendered, encoding="utf-8")
    SUMS.write_text(sums({name: (HERE / name).read_bytes() for name in SUMMED}), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
