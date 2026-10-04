"""Uploaded images live on disk; a conversation carries their path, never their bytes.

``image_routing.build_native_content_parts`` turns an attached image into two things: a text handle
(``[Image attached at: <path>]``) and an inline ``data:`` image part with the whole file base64-encoded.
The inline part is for the turn the image was sent in: a vision model sees the picture at once. Kept any
longer it is a multi-megabyte blob that every later request re-sends, every stored row carries and every
client reading the history downloads. So, for an inline image whose message names its file:

- **stored rows** (``SessionDB._encode_content``) drop it; the handle in the text says where the file is;
- **later turns** (``replay_cleanup.canonicalize_replay_history``, and the live history at the end of the
  turn) replay the handle only; the model looks at the file again with ``vision_analyze`` by path;
- **the current turn** keeps it unless ``images.inline_current_turn`` is false, in which case it carries
  the handle only from the start.

An inline image no handle names (an OpenAI-compatible API client sending ``data:`` URLs) has no file to
fall back on, so the model keeps it. Clients never see one either way: history text shows a named image
by its ``@image:`` reference and an unnamed one as ``[image]`` (:func:`inline_images_for_display`).
"""

from __future__ import annotations

import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

#: What clients see in place of an inline image whose message names no file for it.
INLINE_IMAGE_NOTE = "[image]"

_IMAGE_PART_TYPES = frozenset({"image_url", "input_image", "image"})

#: The handles a message uses to name an attached image file, one per image and each at the start of
#: its own line: the native-attach hint (``[Image attached at: <path>]``) and the ``@image:<path>``
#: reference the TUI gateway persists. ``foo@image:bar`` inside prose is not a handle.
IMAGE_HANDLE_RE = re.compile(r"^(?:\[Image attached at: .+\][ \t]*$|@image:\S)", re.MULTILINE)
_LOCAL_HANDLE_RE = re.compile(r"^\[Image attached at: (.+?)\][ \t]*$", re.MULTILINE)

# A base64 image data URL inside plain text (a legacy row flattened for display, a resent copy of one).
# At least 16 payload characters, so prose that only mentions the scheme ("data:image/png;base64,...")
# is left alone.
_TEXT_DATA_URL_RE = re.compile(r"data:image/[\w.+-]+;base64,[A-Za-z0-9+/]{16,}={0,2}", re.IGNORECASE)


def _part_url(part: Dict[str, Any]) -> str:
    """The URL an image part carries ("data:" for an Anthropic-style base64 source; "" when none)."""
    image_url = part.get("image_url")
    if isinstance(image_url, dict):
        image_url = image_url.get("url")
    if isinstance(image_url, str):
        return image_url
    source = part.get("source")
    if isinstance(source, dict) and source.get("type") == "base64":
        return "data:"
    return ""


def is_inline_image_part(part: Any) -> bool:
    """True for an image content part that carries the image bytes (a ``data:`` URL or base64 source)."""
    return (
        isinstance(part, dict)
        and part.get("type") in _IMAGE_PART_TYPES
        and _part_url(part).lstrip()[:5].lower() == "data:"
    )


def has_inline_images(content: Any) -> bool:
    return isinstance(content, list) and any(is_inline_image_part(p) for p in content)


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        p if isinstance(p, str) else p["text"]
        for p in content
        if isinstance(p, str) or (isinstance(p, dict) and isinstance(p.get("text"), str))
    )


def named_image_count(text: str) -> int:
    """How many attached image files ``text`` names (handle lines, see :data:`IMAGE_HANDLE_RE`)."""
    return len(IMAGE_HANDLE_RE.findall(text)) if text else 0


def names_an_image(text: str) -> bool:
    """Whether ``text`` names an attached image file (``[Image attached at: …]`` or ``@image:…``)."""
    return named_image_count(text) > 0


def named_inline_flags(content: List[Any]) -> List[bool]:
    """For each part of ``content``: is it an inline image a handle names? Handles name images in order
    and every producer puts its file images first (``build_native_content_parts``; a delegated goal
    appends caller data: URLs after them), so the first N inline images are the N named ones and any
    beyond N have no file."""
    remaining = named_image_count(_text_of(content))
    flags = []
    for part in content:
        named = remaining > 0 and is_inline_image_part(part)
        remaining -= named
        flags.append(named)
    return flags


def strip_inline_images(content: Any) -> Any:
    """``content`` without the inline images its text names a file for; the same object otherwise.

    Text parts (which carry the handles), every other part and any inline image beyond the named ones
    (it is the only copy) are kept."""
    if not has_inline_images(content):
        return content
    flags = named_inline_flags(content)
    if not any(flags):
        return content
    return [p for p, named in zip(content, flags) if not named]


def inline_images_for_display(content: Any) -> Any:
    """``content`` as a client may see it: no inline image at all. A named one is dropped (the text names
    its file); an unnamed one becomes an ``[image]`` text part; a data URL inside text becomes ``[image]``."""
    if isinstance(content, str):
        return strip_inline_image_text(content)
    if not has_inline_images(content):
        return content
    out: List[Any] = []
    for part, named in zip(content, named_inline_flags(content)):
        if not is_inline_image_part(part):
            out.append(part)
        elif not named:
            out.append({"type": "text", "text": INLINE_IMAGE_NOTE})
    return out


def strip_inline_image_text(text: Any) -> Any:
    """``text`` with every base64 image data URL replaced by ``[image]``; non-strings unchanged."""
    if not isinstance(text, str) or "base64," not in text:
        return text
    return _TEXT_DATA_URL_RE.sub(INLINE_IMAGE_NOTE, text)


def _replay_user_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    """``msg`` as a later turn replays it: a copy when something was stripped, else ``msg`` itself."""
    content = msg.get("content")
    if isinstance(content, list):
        stripped = strip_inline_images(content)
        if stripped is content:
            return msg
        return {**msg, "content": stripped}
    # A flattened copy of a native turn (a client resent the text it was shown): the data URL is text
    # tokens, not an image, and the handle beside it names the file.
    if isinstance(content, str) and names_an_image(content):
        stripped = strip_inline_image_text(content)
        sidecar = msg.get("api_content")
        stripped_sidecar = strip_inline_image_text(sidecar)
        if stripped != content or stripped_sidecar != sidecar:
            out = {**msg, "content": stripped}
            if isinstance(sidecar, str):
                out["api_content"] = stripped_sidecar
            return out
    return msg


def strip_replayed_inline_images(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """History as later turns replay it: user messages carry their image handles, not the named images.

    Pure: the input and its messages are not modified; the same list is returned when nothing changes."""
    if not history:
        return history
    out: List[Dict[str, Any]] = []
    changed = False
    for msg in history:
        if isinstance(msg, dict) and msg.get("role") == "user":
            replayed = _replay_user_message(msg)
            changed = changed or replayed is not msg
            out.append(replayed)
        else:
            out.append(msg)
    return out if changed else history


def drop_inline_images_in_place(messages: Optional[List[Any]]) -> int:
    """Strip the named inline images from the user messages of a finished turn's live history, in place
    (the dicts keep their identity and persistence markers). Returns how many messages changed."""
    changed = 0
    for msg in messages or ():
        if isinstance(msg, dict) and msg.get("role") == "user":
            stripped = strip_inline_images(msg.get("content"))
            if stripped is not msg.get("content"):
                msg["content"] = stripped
                changed += 1
    return changed


def display_image_handles(text: str, format_path=None) -> str:
    """User text for clients: ``[Image attached at: <path>]`` lines become ``@image:<path>`` references
    (the form clients already render and the TUI gateway persists). ``format_path`` quotes the path."""
    if not text or "[Image attached at: " not in text:
        return text
    fmt = format_path or (lambda value: value)
    return _LOCAL_HANDLE_RE.sub(lambda m: f"@image:{fmt(m.group(1).strip())}", text)


def create_image_file(directory: Path, prefix: str, ext: str, data: Optional[bytes] = None) -> Path:
    """Create a NEW image file ``<directory>/<prefix>_<timestamp>_<random>.<ext>`` and return its path.

    The file is the only record of an attached image and clients fetch it by name, so two sessions of
    one profile attaching in the same second must never share a name: the name carries 48 random bits
    and the file is created with ``O_CREAT | O_EXCL`` (never an existing file, never through a link),
    mode 0600. ``data`` is written when given; without it the empty file reserves the name for a writer
    that fills it (a clipboard tool), and the caller removes it if that writer fails."""
    directory.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for _ in range(8):
        path = directory / f"{prefix}_{stamp}_{secrets.token_hex(6)}{ext}"
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        try:
            with os.fdopen(fd, "wb") as handle:
                if data:
                    handle.write(data)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path
    raise FileExistsError(f"could not create a new image file in {directory}")


def inline_current_turn_enabled(cfg: Optional[Dict[str, Any]] = None) -> bool:
    """``images.inline_current_turn`` (default true): may the turn an image was sent in carry the image
    inline? ``cfg`` None reads config.yaml; an unreadable config keeps the default."""
    if cfg is None:
        try:
            from hermes_cli.config import load_config

            cfg = load_config()
        except Exception:
            return True
    section = cfg.get("images") if isinstance(cfg, dict) else None
    raw = section.get("inline_current_turn", True) if isinstance(section, dict) else True
    if isinstance(raw, str):
        return raw.strip().lower() not in {"false", "0", "no", "off"}
    return raw is not False and raw != 0


__all__ = [
    "create_image_file",
    "INLINE_IMAGE_NOTE",
    "IMAGE_HANDLE_RE",
    "display_image_handles",
    "drop_inline_images_in_place",
    "has_inline_images",
    "inline_current_turn_enabled",
    "inline_images_for_display",
    "is_inline_image_part",
    "named_image_count",
    "named_inline_flags",
    "names_an_image",
    "strip_inline_image_text",
    "strip_inline_images",
    "strip_replayed_inline_images",
]
