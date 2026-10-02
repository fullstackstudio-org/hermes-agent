"""The confirm-passkey construction (``contract/confirm-passkey/README.md`` §2–§7, §10). Pure functions.

Base URLs are serialised here, not with ``origins.PublicOrigin``: the contract's serialisation (§3) keeps
the path prefix and normalises hosts the way the WHATWG URL parser does, and every client computes the
same string from what it dialed. A divergence would refuse every answer as ``challenge_mismatch``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import struct
import unicodedata
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit

CHALLENGE_TAG = "hermie-confirm-v1"
TEXT_TAG = "hermie-confirm-text-v1"
USER_HANDLE_TAG = b"user-handle-v1"
PURPOSES = frozenset({"confirm", "register", "invite", "revoke"})

GATEWAY_ID_BYTES = 16
HANDLE_KEY_BYTES = 32
NONCE_BYTES = 32


class NotABaseUrl(ValueError):
    """The input is not an http(s) base URL (README §3)."""


# ── encoding (§2) ─────────────────────────────────────────────────────────────────────────────

_B64U = re.compile(r"[A-Za-z0-9_-]*")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: object, low: int | None = None, high: int | None = None) -> bytes:
    """Strict base64url: no padding, alphabet only, canonical trailing bits; optional decoded length
    bounds. Raises ``ValueError`` for anything else (never another exception)."""
    if not isinstance(text, str) or len(text) % 4 == 1 \
            or (high is not None and len(text) > (high * 4 + 2) // 3) or not _B64U.fullmatch(text):
        raise ValueError("not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("not base64url") from exc
    if b64u(raw) != text:
        raise ValueError("non-canonical base64url")
    if low is not None and high is not None and not low <= len(raw) <= high:
        raise ValueError("length out of bounds")
    return raw


def S(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def LP(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


# ── base URLs (§3, §10) ───────────────────────────────────────────────────────────────────────

_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})+")
_PRIVATE_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


def _a_label(label: str) -> str:
    # UTS #46 non-transitional as the WHATWG host parser applies it to ordinary input: NFC, lower case,
    # Punycode for a non-ASCII label; ``ß`` is kept (xn--strae-oqa), never mapped to ``ss``.
    label = unicodedata.normalize("NFC", label).lower()
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError as exc:
        raise NotABaseUrl("host") from exc


def serialise_base_url(url: str) -> str:
    """``scheme://host[:port][/prefix]`` per README §3. Raises :class:`NotABaseUrl`."""
    try:
        parts = urlsplit(str(url))
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        port = parts.port
    except ValueError as exc:
        raise NotABaseUrl("unparseable") from exc
    if scheme not in ("http", "https") or not parts.netloc or not host:
        raise NotABaseUrl("not an http(s) URL with a host")
    if ":" in host:
        try:
            host = "[" + ipaddress.IPv6Address(host).compressed + "]"
        except ValueError as exc:
            raise NotABaseUrl("ipv6") from exc
    else:
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError:
            labels = host.split(".")
            if any(not label for label in labels):
                raise NotABaseUrl("empty host label") from None
            host = ".".join(_a_label(label) for label in labels)
    default = 443 if scheme == "https" else 80
    origin = f"{scheme}://{host}" + (f":{port}" if port is not None and port != default else "")
    path = parts.path.rstrip("/")
    if not path:
        return origin
    segments = path.split("/")[1:]
    if any(seg in ("", ".", "..") or not _SEGMENT.fullmatch(seg) for seg in segments):
        raise NotABaseUrl("path prefix")
    segments = [re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), seg) for seg in segments]
    return origin + "/" + "/".join(segments)


def origin_of(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


def host_of(base_url: str) -> str:
    host = urlsplit(base_url).hostname or ""
    return f"[{host}]" if ":" in host else host


def has_path_prefix(base_url: str) -> bool:
    return urlsplit(base_url).path not in ("", "/")


def is_private(base_url: str) -> bool:
    """README §10: a base URL that can name a different machine on another network."""
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        return True
    host = parts.hostname or ""
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return host == "localhost" or "." not in host or host.endswith(_PRIVATE_SUFFIXES)


# ── the gateway's side of the construction ────────────────────────────────────────────────────


@dataclass(frozen=True)
class GatewayContext:
    """What the verifier needs to know about this gateway (README §9 inputs).

    ``base_urls`` are the operator's list for this level (``confirm.passkey.base_urls``), already
    serialised (§3), never the dashboard's public URLs; ``native_rps`` maps a native RP id to the
    ``clientDataJSON.origin`` values allowed for it."""

    gateway_id: bytes
    handle_key: bytes
    base_urls: tuple[str, ...]
    native_rps: Mapping[str, tuple[str, ...]]
    allow_private_base_urls: bool = False
    accepted_base_urls: tuple[str, ...] = field(init=False)
    native_rp_ids: frozenset = field(init=False)
    web_rp_ids: frozenset = field(init=False)

    def __post_init__(self) -> None:
        accepted = tuple(u for u in self.base_urls if self.allow_private_base_urls or not is_private(u))
        object.__setattr__(self, "accepted_base_urls", accepted)
        object.__setattr__(self, "native_rp_ids", frozenset(self.native_rps) if accepted else frozenset())
        object.__setattr__(self, "web_rp_ids", frozenset(
            host_of(u) for u in accepted if u.startswith("https://") and not has_path_prefix(u)))

    def capability_reason(self, *, enabled: bool = True, identity: bool = True) -> str:
        """The ``confirm_passkey.reason`` of the first ``client.capabilities`` result (README §8)."""
        if not enabled:
            return "disabled"
        if not self.base_urls:
            return "no_base_url"
        if not self.accepted_base_urls:
            return "private_origin"
        return "" if identity else "no_identity"


def text_digest(title: str, summary: str, detail: str | None) -> bytes:
    """README §4."""
    return hashlib.sha256(S(TEXT_TAG) + S(title) + S(summary) + S(detail or "")).digest()


def challenge_preimage(*, purpose: str, base_url: str, gateway_id: bytes, user_id: str, session_id: str,
                       request_id: str, nonce: bytes, digest: bytes) -> bytes:
    if purpose not in PURPOSES:
        raise ValueError(f"unknown purpose {purpose!r}")
    return (S(CHALLENGE_TAG) + S(purpose) + S(base_url) + LP(gateway_id) + S(user_id) + S(session_id)
            + S(request_id) + LP(nonce) + LP(digest))


def challenge(**fields) -> bytes:
    """README §5: SHA-256 of :func:`challenge_preimage`."""
    return hashlib.sha256(challenge_preimage(**fields)).digest()


def user_handle(handle_key: bytes, user_id: str) -> bytes:
    """README §6."""
    return hmac.new(handle_key, USER_HANDLE_TAG + user_id.encode("utf-8"), hashlib.sha256).digest()


# ── enrolment codes (§7) ──────────────────────────────────────────────────────────────────────

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_IN = {**{c: c for c in CROCKFORD}, "O": "0", "I": "1", "L": "1"}


def enrolment_code_display(raw: bytes) -> str:
    """The top 100 bits of *raw* (at least 13 bytes) as ``XXXXX-XXXXX-XXXXX-XXXXX``."""
    if len(raw) < 13:
        raise ValueError("need at least 100 bits")
    value = int.from_bytes(raw, "big") >> (len(raw) * 8 - 100)
    chars = "".join(CROCKFORD[(value >> (5 * (19 - i))) & 31] for i in range(20))
    return "-".join(chars[i:i + 5] for i in range(0, 20, 5))


def enrolment_code_canonical(text: object) -> str | None:
    """Upper-case, drop ``-`` and spaces, map ``O``→``0`` and ``I``/``L``→``1``; None unless exactly 20
    Crockford symbols remain."""
    if not isinstance(text, str) or len(text) > 64:
        return None
    out = []
    for ch in text.upper():
        if ch in "- ":
            continue
        if ch not in _CROCKFORD_IN:
            return None
        out.append(_CROCKFORD_IN[ch])
    return "".join(out) if len(out) == 20 else None


def enrolment_code_hash(text: object) -> bytes | None:
    """``SHA-256(canonical ASCII)`` of a code, or None when it is not a code."""
    canonical = enrolment_code_canonical(text)
    return hashlib.sha256(canonical.encode("ascii")).digest() if canonical else None
