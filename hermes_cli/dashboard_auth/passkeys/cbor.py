"""The CBOR subset WebAuthn needs (``contract/confirm-passkey/README.md`` §12), decoding only.

Accepted: major types 0 and 1 (integers up to 64 bits), 2 (byte string), 3 (UTF-8 text), 4 (array),
5 (map), and the simple values false, true, null. Definite lengths only; no tags, floats, undefined or
other simple values; nesting depth at most 4; map keys are integers or text and never repeat. The
decoder never reads past the buffer, reports how many bytes it consumed, and raises only
:class:`CborError`. Non-shortest integer encodings are accepted.
"""

from __future__ import annotations

from typing import Any

MAX_DEPTH = 4


class CborError(ValueError):
    pass


def decode(buf: bytes, pos: int = 0, *, depth: int = 1) -> tuple[Any, int]:
    """One item at *pos*; ``(value, end)``."""
    if depth > MAX_DEPTH:
        raise CborError("nesting too deep")
    if pos >= len(buf):
        raise CborError("truncated")
    initial = buf[pos]
    major, info = initial >> 5, initial & 31
    pos += 1
    if info < 24:
        value = info
    elif info <= 27:
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
        if value > len(buf) - pos:
            raise CborError("truncated")
        raw = bytes(buf[pos:pos + value])
        if major == 2:
            return raw, pos + value
        try:
            return raw.decode("utf-8"), pos + value
        except UnicodeDecodeError as exc:
            raise CborError("text is not UTF-8") from exc
    if major == 4:
        if value > len(buf) - pos:  # every item takes at least one byte
            raise CborError("truncated")
        items = []
        for _ in range(value):
            item, pos = decode(buf, pos, depth=depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        if value > (len(buf) - pos) // 2:  # every entry takes at least two bytes
            raise CborError("truncated")
        out: dict = {}
        for _ in range(value):
            key, pos = decode(buf, pos, depth=depth + 1)
            if isinstance(key, bool) or not isinstance(key, (int, str)):
                raise CborError("map key is not an integer or text")
            if key in out:
                raise CborError("duplicate map key")
            out[key], pos = decode(buf, pos, depth=depth + 1)
        return out, pos
    if major == 6:
        raise CborError("tags are not accepted")
    if info == 20:
        return False, pos
    if info == 21:
        return True, pos
    if info == 22:
        return None, pos
    raise CborError("simple value or float not accepted")


def decode_exactly(buf: bytes) -> Any:
    """One item that consumes the whole buffer."""
    value, end = decode(buf)
    if end != len(buf):
        raise CborError("trailing bytes")
    return value
