"""The outbox: files a bot shares with the person, copied where a client can fetch them and nothing else.

An agent attaches a file to its reply with a ``MEDIA:<path>`` line (the convention every messaging platform
delivers natively), and some tools produce one in their result (``text_to_speech``, ``image_generate``). On a
messaging platform the gateway uploads the file. On the Hermie apps the gateway SHARES it instead
(``tui_gateway/outbox_share.py`` decides when): :func:`share_file` checks the path the way native delivery does
(``gateway.platforms.base.validate_media_delivery_path``: the credential and system denylist, strict mode, a
container path mapped to the host) plus the read guard (``agent.file_safety.get_read_block_error``) and a
basename denylist, opens it without following a link, refuses anything but a regular file and anything over
``files.outbox_max_file_mb``, and copies it into ``<profile home>/outbox/<token>/``:

- ``<token>`` is ``secrets.token_urlsafe(24)`` (32 characters, 192 random bits), created with ``mkdir``
  (never an existing folder); every component from the home down is opened with ``O_NOFOLLOW`` relative to
  its parent (``tui_gateway/upload_dirs.walk``);
- ``blob`` holds the bytes (``O_CREAT | O_EXCL | O_NOFOLLOW``, mode 0600), ``record.json`` what is known
  about them: :data:`RECORD_KEYS`.

The agent's own file is never touched. Clients see the record's public part, :func:`attachment_of`, and fetch
the bytes from ``GET /api/files/outbox/{token}/{name}`` (``hermes_cli/web_routers/files.py``), which reads them
back through :func:`open_shared`. :func:`prune_outbox` applies ``files.outbox_retention_days`` and
``files.outbox_max_total_mb``. Platforms that cannot open without following a link (no ``O_NOFOLLOW`` /
``dir_fd``: Windows) share nothing.

The wire shape is written down in ``contract/outbox/``.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from tui_gateway import upload_dirs

logger = logging.getLogger(__name__)

OUTBOX_DIR = "outbox"
BLOB_NAME = "blob"
RECORD_NAME = "record.json"
RECORD_VERSION = 1
#: ``secrets.token_urlsafe(24)``: 32 URL-safe characters.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
#: The keys of ``record.json``. ``source`` (the agent's path), ``session_id`` and ``logins`` never leave the
#: server: :func:`attachment_of` is what a client sees.
RECORD_KEYS = ("v", "id", "name", "mime", "kind", "inline", "size", "sha256", "created_at", "session_id", "logins",
               "source")
#: What a client sees of a shared file (``contract/outbox``).
ATTACHMENT_KEYS = ("id", "name", "mime", "kind", "size", "sha256", "created_at", "url")
URL_PREFIX = "/api/files/outbox"
#: The ``display_metadata`` key of a row's attachments (``SessionDB.ATTACHMENTS_METADATA_KEY``).
METADATA_KEY = "attachments"
KINDS = ("image", "video", "audio", "pdf", "file")

DEFAULT_MAX_FILE_MB = 200
DEFAULT_MAX_TOTAL_MB = 2048
DEFAULT_RETENTION_DAYS = 30
DEFAULT_SOURCES = ("hermie",)
DEFAULT_MAX_TURN_FILES = 20
DEFAULT_MAX_TURN_MB = 500
DEFAULT_TURN_TIMEOUT_S = 120
#: The cross-process lock file inside ``outbox/`` (``flock``); never a share, never pruned.
LOCK_NAME = ".lock"
#: A hard ceiling on the number of shared files per profile, whatever their size: pruning reads every entry.
MAX_ENTRIES = 10_000
_NAME_MAX_CHARS = 180
_RECORD_MAX_BYTES = 64 * 1024
_SNIFF_BYTES = 64
_COPY_CHUNK = 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class ShareRefused(Exception):
    """A file that cannot be shared; ``reason`` is one of :data:`REFUSAL_REASONS` (logged, never a path)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


#: ``linked``: the file has another hard link; ``turn_limit``: the turn shared its maximum number of files;
#: ``no_room``: the outbox is full of other conversations' recent files; ``busy``: the outbox stayed locked;
#: ``timeout``: the copy did not finish within the turn's time.
REFUSAL_REASONS = ("unsupported", "invalid_path", "denied", "not_found", "not_regular", "linked", "too_large",
                   "turn_limit", "no_room", "busy", "timeout", "io_error")


# ── what a file is ───────────────────────────────────────────────────────────────────────────────────────────

#: Extensions served INLINE: ``(type, kind, families the first bytes must show)``. A file whose bytes do not
#: show one of the families (a ``.png`` that is HTML) is served as ``application/octet-stream`` attachment.
_INLINE_TYPES: dict[str, tuple[str, str, frozenset[str]]] = {
    ".png": ("image/png", "image", frozenset({"png"})),
    ".jpg": ("image/jpeg", "image", frozenset({"jpeg"})),
    ".jpeg": ("image/jpeg", "image", frozenset({"jpeg"})),
    ".gif": ("image/gif", "image", frozenset({"gif"})),
    ".webp": ("image/webp", "image", frozenset({"webp"})),
    ".bmp": ("image/bmp", "image", frozenset({"bmp"})),
    ".heic": ("image/heic", "image", frozenset({"heif"})),
    ".heif": ("image/heif", "image", frozenset({"heif"})),
    ".mp4": ("video/mp4", "video", frozenset({"isobmff"})),
    ".m4v": ("video/mp4", "video", frozenset({"isobmff"})),
    ".mov": ("video/quicktime", "video", frozenset({"isobmff"})),
    ".webm": ("video/webm", "video", frozenset({"ebml"})),
    ".mp3": ("audio/mpeg", "audio", frozenset({"mpeg_audio"})),
    ".m4a": ("audio/mp4", "audio", frozenset({"isobmff"})),
    ".aac": ("audio/aac", "audio", frozenset({"mpeg_audio", "isobmff"})),
    ".ogg": ("audio/ogg", "audio", frozenset({"ogg"})),
    ".oga": ("audio/ogg", "audio", frozenset({"ogg"})),
    ".opus": ("audio/ogg", "audio", frozenset({"ogg"})),
    ".wav": ("audio/wav", "audio", frozenset({"wav"})),
    ".flac": ("audio/flac", "audio", frozenset({"flac"})),
    ".pdf": ("application/pdf", "pdf", frozenset({"pdf"})),
}

#: A file with no (or an unknown) extension whose bytes are unmistakable is still shown: family -> type.
_FAMILY_TYPES: dict[str, tuple[str, str]] = {
    "png": ("image/png", "image"), "jpeg": ("image/jpeg", "image"), "gif": ("image/gif", "image"),
    "webp": ("image/webp", "image"), "pdf": ("application/pdf", "pdf"), "mpeg_audio": ("audio/mpeg", "audio"),
    "ogg": ("audio/ogg", "audio"), "wav": ("audio/wav", "audio"), "flac": ("audio/flac", "audio"),
}

#: Types a download is labelled with (never inline). Anything not here is ``application/octet-stream``.
_ATTACHMENT_TYPES: dict[str, str] = {
    ".txt": "text/plain", ".log": "text/plain", ".md": "text/markdown", ".csv": "text/csv",
    ".tsv": "text/tab-separated-values", ".json": "application/json", ".yaml": "application/yaml",
    ".yml": "application/yaml", ".xml": "application/xml", ".html": "text/html", ".htm": "text/html",
    ".svg": "image/svg+xml", ".tif": "image/tiff", ".tiff": "image/tiff", ".rtf": "application/rtf",
    ".zip": "application/zip", ".gz": "application/gzip", ".tgz": "application/gzip", ".tar": "application/x-tar",
    ".7z": "application/x-7z-compressed", ".rar": "application/vnd.rar", ".epub": "application/epub+zip",
    ".doc": "application/msword", ".xls": "application/vnd.ms-excel", ".ppt": "application/vnd.ms-powerpoint",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text", ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation", ".mkv": "video/x-matroska",
    ".avi": "video/x-msvideo", ".3gp": "video/3gpp",
}

#: Types a browser would run or render as a document. The route labels them ``application/octet-stream``
#: whatever the record says, on top of ``attachment``, ``nosniff`` and the sandbox CSP.
ACTIVE_TYPES = frozenset({
    "text/html", "image/svg+xml", "application/xhtml+xml", "application/xml", "text/xml", "text/javascript",
    "application/javascript", "application/ecmascript", "text/ecmascript",
})


def sniff_family(head: bytes) -> str | None:
    """The file family the first bytes show, or None. Only signatures that cannot be text."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "wav"
    if head.startswith(b"BM") and len(head) >= 14:
        return "bmp"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head[4:8] == b"ftyp":
        return "heif" if head[8:12] in (b"heic", b"heix", b"mif1", b"msf1", b"heim", b"heis") else "isobmff"
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "ebml"
    if head.startswith(b"OggS"):
        return "ogg"
    if head.startswith(b"fLaC"):
        return "flac"
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return "mpeg_audio"
    return None


def classify(name: str, head: bytes) -> tuple[str, str, bool]:
    """``(type, kind, inline)`` for a file called *name* whose first bytes are *head*."""
    ext = os.path.splitext(name)[1].lower()
    family = sniff_family(head)
    inline = _INLINE_TYPES.get(ext)
    if inline is not None:
        mime, kind, families = inline
        if family in families:
            return mime, kind, True
        return "application/octet-stream", "file", False  # the bytes contradict the name: a download only
    if ext not in _ATTACHMENT_TYPES and family in _FAMILY_TYPES:
        mime, kind = _FAMILY_TYPES[family]
        return mime, kind, True
    return _ATTACHMENT_TYPES.get(ext, "application/octet-stream"), "file", False


def served_type(mime: str) -> str:
    """The Content-Type the route sends for a recorded type: active content is never labelled as such."""
    return "application/octet-stream" if mime.split(";", 1)[0].strip().lower() in ACTIVE_TYPES else mime


# ── settings ─────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class OutboxSettings:
    max_file_bytes: int = DEFAULT_MAX_FILE_MB * 1024 * 1024
    max_total_bytes: int = DEFAULT_MAX_TOTAL_MB * 1024 * 1024
    retention_seconds: float = DEFAULT_RETENTION_DAYS * 86400.0
    sources: frozenset[str] = frozenset(DEFAULT_SOURCES)
    max_turn_files: int = DEFAULT_MAX_TURN_FILES
    max_turn_bytes: int = DEFAULT_MAX_TURN_MB * 1024 * 1024
    turn_timeout_seconds: float = float(DEFAULT_TURN_TIMEOUT_S)


def _positive(value: Any, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def settings_from(cfg: Mapping[str, Any] | None) -> OutboxSettings:
    """The ``files:`` section of a config (``files.outbox_*``); a missing or invalid value keeps its default."""
    files = (cfg or {}).get("files") if isinstance(cfg, Mapping) else None
    files = files if isinstance(files, Mapping) else {}
    raw_sources = files.get("outbox_sources", DEFAULT_SOURCES)
    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    sources = frozenset(str(s).strip().lower() for s in raw_sources or () if str(s).strip()) \
        if isinstance(raw_sources, (list, tuple)) else frozenset(DEFAULT_SOURCES)
    return OutboxSettings(
        max_file_bytes=int(_positive(files.get("outbox_max_file_mb"), DEFAULT_MAX_FILE_MB) * 1024 * 1024),
        max_total_bytes=int(_positive(files.get("outbox_max_total_mb"), DEFAULT_MAX_TOTAL_MB) * 1024 * 1024),
        retention_seconds=_positive(files.get("outbox_retention_days"), DEFAULT_RETENTION_DAYS) * 86400.0,
        sources=sources,
        max_turn_files=int(_positive(files.get("outbox_max_turn_files"), DEFAULT_MAX_TURN_FILES)),
        max_turn_bytes=int(_positive(files.get("outbox_max_turn_mb"), DEFAULT_MAX_TURN_MB) * 1024 * 1024),
        turn_timeout_seconds=_positive(files.get("outbox_turn_timeout_s"), DEFAULT_TURN_TIMEOUT_S),
    )


def load_settings() -> OutboxSettings:
    """:func:`settings_from` the active profile's config (``load_config`` honours the profile home in scope)."""
    try:
        from hermes_cli.config import load_config
        return settings_from(load_config())
    except Exception:
        logger.debug("outbox: config unreadable, defaults apply", exc_info=True)
        return OutboxSettings()


def settings_for_home(home: Path) -> OutboxSettings:
    """:func:`settings_from` ``<home>/config.yaml`` read directly (the background pruner has no profile scope)."""
    try:
        import yaml
        with open(Path(home) / "config.yaml", encoding="utf-8") as handle:
            return settings_from(yaml.safe_load(handle) or {})
    except FileNotFoundError:
        return OutboxSettings()
    except Exception:
        logger.debug("outbox: %s/config.yaml unreadable, defaults apply", home, exc_info=True)
        return OutboxSettings()


# ── names ────────────────────────────────────────────────────────────────────────────────────────────────────

_UNSAFE_NAME_CHARS = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029/\\]")


def display_name(source_name: str) -> str:
    """The name a shared file is shown and fetched by: the source's base name (NFC), control characters and
    separators replaced, at most 180 characters with the extension kept. Never ``.``/``..``/empty."""
    name = _UNSAFE_NAME_CHARS.sub("_", unicodedata.normalize("NFC", source_name)).strip()
    if len(name) > _NAME_MAX_CHARS:
        stem, ext = os.path.splitext(name)
        ext = ext if len(ext) <= 16 else ""
        name = stem[: _NAME_MAX_CHARS - len(ext)] + ext
    while len(name.encode("utf-8")) > 240:  # a file system's 255-byte name limit, with room to spare
        name = name[:-1]
    return name if name.strip(".") else "file"


def attachment_url(token: str, name: str) -> str:
    return f"{URL_PREFIX}/{token}/{quote(name, safe='')}"


def attachment_of(record: Mapping[str, Any]) -> dict:
    """What a client sees of a shared file: no path, no session, no logins."""
    return {
        "id": record["id"], "name": record["name"], "mime": record["mime"], "kind": record["kind"],
        "size": int(record["size"]), "sha256": record["sha256"], "created_at": float(record["created_at"]),
        "url": attachment_url(record["id"], record["name"]),
    }


def clean_attachments(value: Any) -> list[dict]:
    """The well-formed attachments of a stored list (``display_metadata.attachments``), reduced to
    :data:`ATTACHMENT_KEYS`; anything else is dropped, so a row never carries a path to a client."""
    out: list[dict] = []
    if not isinstance(value, list):
        return out
    for item in value:
        if not isinstance(item, Mapping):
            continue
        token, name = item.get("id"), item.get("name")
        if not (isinstance(token, str) and TOKEN_RE.match(token) and isinstance(name, str) and name):
            continue
        if display_name(name) != name or item.get("kind") not in KINDS:
            continue
        try:
            out.append(attachment_of({**item, "id": token, "name": name, "mime": str(item.get("mime") or ""),
                                      "sha256": str(item.get("sha256") or "")}))
        except (KeyError, TypeError, ValueError):
            continue
    return out


# ── sharing ──────────────────────────────────────────────────────────────────────────────────────────────────

#: Basenames never shared wherever they sit (on top of the delivery denylist and the read guard).
_DENIED_BASENAMES = frozenset({
    ".env", ".envrc", ".git-credentials", ".netrc", "_netrc", ".pgpass", ".npmrc", ".pypirc", "auth.json",
    "auth.lock", "credentials", ".anthropic_oauth.json", "google_token.json", "google_oauth.json",
    "google_oauth_pending.json", "webhook_subscriptions.json", "bws_cache.json", "bws_cache.enc.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
_DENIED_PARTS = frozenset({"mcp-tokens", "pairing", ".ssh", ".gnupg"})


def _denied_basename(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered in _DENIED_BASENAMES or lowered.startswith(".env."):
        return True
    with contextlib.suppress(Exception):
        from hermes_cli.dashboard_auth.passkeys.paths import is_store_file_name
        if is_store_file_name(path.name):
            return True
    return any(part.lower() in _DENIED_PARTS for part in path.parent.parts)


def hermes_homes(*extra: Path | str) -> list[Path]:
    """Every Hermes home on this host, resolved: the active one, the root, every ``<root>/profiles/*`` and
    *extra*. Read at call time, so a profile made after start counts."""
    homes: list[Path | str] = [*extra]
    with contextlib.suppress(Exception):
        from hermes_constants import get_default_hermes_root, get_hermes_home
        root = Path(get_default_hermes_root())
        homes += [get_hermes_home(), root]
        with contextlib.suppress(OSError):
            homes += [p for p in (root / "profiles").iterdir() if p.is_dir()]
    out: dict[str, Path] = {}
    for home in homes:
        with contextlib.suppress(OSError, RuntimeError, ValueError):
            resolved = Path(home).expanduser().resolve()
            out.setdefault(str(resolved), resolved)
    return list(out.values())


def _is_shared_store(resolved: Path, homes: Iterable[Path]) -> bool:
    """Whether *resolved* is inside a home's ``outbox/`` (another conversation's copy: re-sharing it would hand
    it to whoever is in THIS conversation) or a person's upload folder (``.../uploads/hermie/...``)."""
    for home in homes:
        if resolved == home / OUTBOX_DIR or (home / OUTBOX_DIR) in resolved.parents:
            return True
    parts = resolved.parts
    return any((parts[i], parts[i + 1]) == upload_dirs.UPLOAD_SEGMENTS for i in range(len(parts) - 1))


def check_source(path: str, *, session_key: str = "", home: Path | str | None = None) -> Path:
    """The resolved path of a file that may be shared, else :class:`ShareRefused`. Symbolic links are resolved
    first, so every check below judges the file that would actually be read (and :func:`_open_source` reads
    that path without following a link)."""
    from tools.path_security import has_unsafe_path_chars
    if not isinstance(path, str) or not path.strip() or has_unsafe_path_chars(path):
        raise ShareRefused("invalid_path")
    from gateway.platforms.base import validate_media_delivery_path
    safe = validate_media_delivery_path(path, session_key=session_key)
    if not safe:
        raise ShareRefused("denied")
    resolved = Path(safe)
    from agent.file_safety import get_read_block_error
    try:
        blocked = get_read_block_error(str(resolved))
    except Exception:
        blocked = "unreadable"
    if blocked or _denied_basename(resolved):
        raise ShareRefused("denied")
    if _is_shared_store(resolved, hermes_homes(*(() if home is None else (home,)))):
        raise ShareRefused("denied")
    return resolved


_SOURCE_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NONBLOCK


def _open_walked(resolved: Path) -> int:
    """Open *resolved* one component at a time from ``/``, never following a link (``upload_dirs.walk``): the
    file read is the one the checks judged, whatever is swapped in after them. ``PermissionError`` when an
    ancestor may be searched but not opened (``/home`` at 0711)."""
    parts = upload_dirs.components(str(resolved))
    if not parts:
        raise ShareRefused("not_regular")
    dir_fd = upload_dirs.walk(parts[:-1], start="/")
    try:
        return os.open(parts[-1], _SOURCE_FLAGS, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def _open_checked(resolved: Path) -> int:
    """The fallback when an ancestor cannot be opened: the path itself without following its last component,
    then proof it is still the judged file (the path resolves to itself and names the opened inode)."""
    fd = os.open(str(resolved), _SOURCE_FLAGS)
    try:
        info, now = os.fstat(fd), os.stat(resolved, follow_symlinks=False)
        if os.path.realpath(resolved) != str(resolved) or (info.st_dev, info.st_ino) != (now.st_dev, now.st_ino):
            raise ShareRefused("denied")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_source(resolved: Path) -> int:
    """Open the checked file for reading (see :func:`_open_walked`), a FIFO never blocking; only a regular file
    with ONE link: a hard link to a secret elsewhere would pass every path check under an innocent name."""
    try:
        try:
            fd = _open_walked(resolved)
        except PermissionError:
            fd = _open_checked(resolved)
    except FileNotFoundError:
        raise ShareRefused("not_found")
    except upload_dirs.UnsafePath:
        raise ShareRefused("denied")
    except OSError as exc:
        raise ShareRefused("not_regular" if exc.errno in (errno.ELOOP, errno.ENXIO) else "io_error")
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ShareRefused("not_regular")
    if info.st_nlink != 1:
        os.close(fd)
        raise ShareRefused("linked")
    return fd


_HOME_LOCKS: dict[str, threading.Lock] = {}
_HOME_LOCKS_GUARD = threading.Lock()


def _home_lock(home: Path) -> threading.Lock:
    with _HOME_LOCKS_GUARD:
        return _HOME_LOCKS.setdefault(str(home), threading.Lock())


def _resolved_home(home: Path | str) -> Path:
    return Path(home).expanduser().resolve()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


@contextlib.contextmanager
def _locked_outbox(root: Path, *, create: bool, timeout: float | None = None):
    """Hold *root*'s outbox exclusively, in this process (a lock per home) and across processes (``flock`` on
    ``outbox/.lock``), and yield the outbox folder's descriptor, or None when there is no outbox and *create*
    is false. ``ShareRefused("busy")`` when either lock is not had within *timeout* seconds (None: wait)."""
    deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
    lock = _home_lock(root)
    if not lock.acquire(timeout=-1 if deadline is None else max(0.0, deadline - time.monotonic())):
        raise ShareRefused("busy")
    try:
        try:
            outbox_fd = upload_dirs.walk([OUTBOX_DIR], create_from=0 if create else None, start=str(root))
        except FileNotFoundError:
            if create:
                raise ShareRefused("io_error")
            yield None
            return
        except OSError as exc:
            logger.warning("outbox: cannot open %s/%s: %s", root, OUTBOX_DIR, type(exc).__name__)
            raise ShareRefused("io_error")
        try:
            lock_fd = _flock(outbox_fd, deadline)
            try:
                yield outbox_fd
            finally:
                os.close(lock_fd)  # releases the flock
        finally:
            os.close(outbox_fd)
    finally:
        lock.release()


def _flock(outbox_fd: int, deadline: float | None) -> int:
    try:
        import fcntl
    except ImportError:  # no flock (Windows): sharing is unsupported there anyway
        return os.dup(outbox_fd)
    try:
        lock_fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | _NOFOLLOW | _CLOEXEC, 0o600, dir_fd=outbox_fd)
    except OSError:
        raise ShareRefused("io_error")
    while True:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_fd
        except BlockingIOError:
            if deadline is not None and time.monotonic() >= deadline:
                os.close(lock_fd)
                raise ShareRefused("busy")
            time.sleep(0.05)
        except OSError:
            os.close(lock_fd)
            raise ShareRefused("io_error")


def share_file(source: str, *, home: Path | str, session_id: str, logins: Iterable[str] = (),
               settings: OutboxSettings | None = None, session_key: str = "", now: float | None = None,
               max_bytes: int | None = None, protect: Iterable[str] = (), cancel: threading.Event | None = None,
               lock_timeout: float | None = None) -> dict:
    """Copy the file *source* names into *home*'s outbox and return its record (:data:`RECORD_KEYS`).
    :class:`ShareRefused` when it may not or cannot be shared; nothing is left behind then.

    *max_bytes* is what is left of the turn's byte budget; *protect* the tokens this turn already shared (never
    evicted to make room); *cancel* stops a copy in progress (``timeout``); *lock_timeout* bounds the wait for the
    outbox (``busy``)."""
    if not upload_dirs.supported():
        raise ShareRefused("unsupported")
    settings = settings or OutboxSettings()
    root = _resolved_home(home)
    resolved = check_source(source, session_key=session_key, home=root)
    src_fd = _open_source(resolved)
    try:
        size = os.fstat(src_fd).st_size
        limit = min(settings.max_file_bytes, settings.max_total_bytes,
                    settings.max_turn_bytes if max_bytes is None else max_bytes)
        if size > limit:
            raise ShareRefused("too_large")
        name = display_name(resolved.name)
        with _locked_outbox(root, create=True, timeout=lock_timeout) as outbox_fd:
            _prune_locked(outbox_fd, root, settings, now=now, room_for=size, session_id=str(session_id or ""),
                          protect=frozenset(protect))
            return _copy_in(outbox_fd, src_fd, name, size, session_id=session_id, logins=logins,
                            limit=limit, source=str(resolved), now=now, cancel=cancel)
    finally:
        os.close(src_fd)


def _copy_in(outbox_fd: int, src_fd: int, name: str, size: int, *, session_id: str, logins: Iterable[str],
             limit: int, source: str, now: float | None, cancel: threading.Event | None) -> dict:
    token = ""
    for _ in range(8):
        token = secrets.token_urlsafe(24)
        try:
            os.mkdir(token, upload_dirs.DIR_MODE, dir_fd=outbox_fd)
            break
        except FileExistsError:
            token = ""
    if not token:
        raise ShareRefused("io_error")
    try:
        return _fill_entry(outbox_fd, token, src_fd, name, size, session_id=session_id, logins=logins,
                           limit=limit, source=source, now=now, cancel=cancel)
    except BaseException:
        _remove_entry(outbox_fd, token)
        raise


def _fill_entry(outbox_fd: int, token: str, src_fd: int, name: str, size: int, *, session_id: str,
                logins: Iterable[str], limit: int, source: str, now: float | None,
                cancel: threading.Event | None) -> dict:
    entry_fd = upload_dirs.open_dir(token, dir_fd=outbox_fd)
    try:
        create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
        blob_fd = os.open(BLOB_NAME, create, 0o600, dir_fd=entry_fd)
        digest, head, copied = hashlib.sha256(), b"", 0
        try:
            os.lseek(src_fd, 0, os.SEEK_SET)
            while True:
                if cancel is not None and cancel.is_set():
                    raise ShareRefused("timeout")
                chunk = os.read(src_fd, _COPY_CHUNK)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > limit:  # it grew while being copied
                    raise ShareRefused("too_large")
                if len(head) < _SNIFF_BYTES:
                    head += chunk[: _SNIFF_BYTES - len(head)]
                digest.update(chunk)
                _write_all(blob_fd, chunk)
            os.fsync(blob_fd)
        except OSError:
            raise ShareRefused("io_error")
        finally:
            os.close(blob_fd)
        mime, kind, inline = classify(name, head)
        created_at = time.time() if now is None else float(now)
        record = {
            "v": RECORD_VERSION, "id": token, "name": name, "mime": mime, "kind": kind, "inline": inline,
            "size": copied, "sha256": digest.hexdigest(), "created_at": created_at,
            "session_id": str(session_id or ""), "logins": sorted({str(x) for x in logins if x}),
            "source": source,
        }
        record_fd = os.open(RECORD_NAME, create, 0o600, dir_fd=entry_fd)
        try:
            _write_all(record_fd, json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        finally:
            os.close(record_fd)
        with contextlib.suppress(OSError):
            os.utime(BLOB_NAME, (created_at, created_at), dir_fd=entry_fd, follow_symlinks=False)
        return record
    finally:
        os.close(entry_fd)


def _remove_entry(outbox_fd: int, token: str) -> None:
    """Remove ``outbox/<token>`` and what is in it, never following a link."""
    try:
        entry_fd = upload_dirs.open_dir(token, dir_fd=outbox_fd)
    except FileNotFoundError:
        return
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(token, dir_fd=outbox_fd)  # a link or a file planted under a token's name
        return
    try:
        for entry in os.listdir(entry_fd):
            with contextlib.suppress(OSError):
                info = os.stat(entry, dir_fd=entry_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    shutil.rmtree(entry, dir_fd=entry_fd)
                else:
                    os.unlink(entry, dir_fd=entry_fd)
    finally:
        os.close(entry_fd)
    with contextlib.suppress(OSError):
        os.rmdir(token, dir_fd=outbox_fd)


# ── reading back ─────────────────────────────────────────────────────────────────────────────────────────────


@dataclass
class SharedFile:
    """An open shared file: ``fd`` (the caller closes it, :meth:`close`), its ``record`` and ``size``."""

    fd: int
    record: dict
    size: int
    mtime: float

    def close(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self.fd)


def _read_record(entry_fd: int) -> dict | None:
    try:
        fd = os.open(RECORD_NAME, os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=entry_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _RECORD_MAX_BYTES:
            return None
        raw = os.read(fd, _RECORD_MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(record, dict) or record.get("v") != RECORD_VERSION:
        return None
    if not (isinstance(record.get("id"), str) and isinstance(record.get("name"), str)
            and record.get("kind") in KINDS and isinstance(record.get("mime"), str)
            and isinstance(record.get("size"), int) and isinstance(record.get("logins", []), list)):
        return None
    return record


def open_shared(home: Path | str, token: str, name: str) -> SharedFile | None:
    """The shared file ``outbox/<token>`` of *home* when its record names exactly *name*, opened without
    following a link at any step; None for anything else (no such entry, a link, a file that is not the one
    recorded), with no hint which."""
    if not upload_dirs.supported() or not TOKEN_RE.match(token or "") or not name:
        return None
    try:
        root = _resolved_home(home)
        outbox_fd = upload_dirs.walk([OUTBOX_DIR], start=str(root))
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        try:
            entry_fd = upload_dirs.open_dir(token, dir_fd=outbox_fd)
        except OSError:
            return None
        try:
            record = _read_record(entry_fd)
            if record is None or record["id"] != token or record["name"] != name:
                return None
            try:
                fd = os.open(BLOB_NAME, os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=entry_fd)
            except OSError:
                return None
            info = os.fstat(fd)
            # A hard link planted in place of the copy would serve another file: only the one we wrote.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != record["size"]:
                os.close(fd)
                return None
            return SharedFile(fd=fd, record=record, size=info.st_size, mtime=info.st_mtime)
        finally:
            os.close(entry_fd)
    finally:
        os.close(outbox_fd)


def may_fetch(record: Mapping[str, Any], login: str | None, live_logins: Iterable[str] = ()) -> bool:
    """Whether a caller signed in as *login* may fetch the shared file. No per-person identity (the session
    token, loopback): one trust domain, yes. A signed-in person: only one the conversation belonged to when the
    file was shared (its creator, its stored owner, everyone who had attached), or who has attached since
    (*live_logins*, from the live session). A file shared by a conversation with no signed-in person is
    refused to every signed-in caller."""
    if login is None:
        return True
    allowed = {str(x) for x in record.get("logins") or () if x} | {str(x) for x in live_logins if x}
    return login in allowed


# ── retention ────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(order=True)
class _Entry:
    mtime: float
    size: int
    token: str
    session_id: str = ""


def _entries(outbox_fd: int) -> list[_Entry]:
    """Every entry (oldest first by its blob's mtime); a planted non-token name is aged 0 (removed first). The
    lock file is not an entry."""
    out: list[_Entry] = []
    for entry in os.listdir(outbox_fd):
        if entry == LOCK_NAME:
            continue
        if not TOKEN_RE.match(entry):
            out.append(_Entry(0.0, 0, entry))
            continue
        try:
            info = os.stat(entry, dir_fd=outbox_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                out.append(_Entry(0.0, 0, entry))
                continue
            entry_fd = upload_dirs.open_dir(entry, dir_fd=outbox_fd)
            try:
                record = _read_record(entry_fd) or {}
                session_id = str(record.get("session_id") or "")
                try:
                    blob = os.stat(BLOB_NAME, dir_fd=entry_fd, follow_symlinks=False)
                    out.append(_Entry(blob.st_mtime, blob.st_size, entry, session_id))
                except FileNotFoundError:
                    out.append(_Entry(info.st_mtime, 0, entry, session_id))  # interrupted: aged like the folder
            finally:
                os.close(entry_fd)
        except OSError:
            continue
    return sorted(out)


def _prune_locked(outbox_fd: int | None, root: Path, settings: OutboxSettings, *, now: float | None = None,
                  room_for: int | None = None, session_id: str = "", protect: frozenset[str] = frozenset()) -> int:
    """Prune the locked outbox. Always: every entry past the retention. Then:

    - making room for a share (*room_for* bytes, one more entry): only the SAME conversation's oldest
      (*session_id*), never a token in *protect* (this turn's own); still over the cap means
      ``ShareRefused("no_room")``: one conversation cannot push out another's recent files;
    - the periodic pass (*room_for* None): the oldest of any conversation until within the cap (it only bites
      when the cap was lowered).
    """
    if outbox_fd is None:
        return 0
    removed = 0
    now = time.time() if now is None else float(now)
    cutoff = now - settings.retention_seconds
    keep: list[_Entry] = []
    for entry in _entries(outbox_fd):
        if entry.mtime < cutoff and entry.token not in protect:
            _remove_entry(outbox_fd, entry.token)
            removed += 1
        else:
            keep.append(entry)
    total = sum(entry.size for entry in keep)
    budget = settings.max_total_bytes - (room_for or 0)
    max_entries = MAX_ENTRIES - (0 if room_for is None else 1)
    for entry in list(keep):
        if total <= budget and len(keep) <= max_entries:
            break
        if room_for is not None and (entry.token in protect or not session_id or entry.session_id != session_id):
            continue
        _remove_entry(outbox_fd, entry.token)
        keep.remove(entry)
        total -= entry.size
        removed += 1
    if removed:
        logger.info("outbox: removed %d shared file(s) from %s", removed, root)
    if room_for is not None and (total > budget or len(keep) > max_entries):
        raise ShareRefused("no_room")
    return removed


def prune_outbox(home: Path | str, settings: OutboxSettings | None = None, *, now: float | None = None) -> int:
    """Remove *home*'s shared files older than the retention, then the oldest until the outbox is within its
    total size (and :data:`MAX_ENTRIES`). Returns how many were removed."""
    if not upload_dirs.supported():
        return 0
    try:
        root = _resolved_home(home)
    except (OSError, RuntimeError):
        return 0
    settings = settings or settings_for_home(root)
    with _locked_outbox(root, create=False) as outbox_fd:
        return _prune_locked(outbox_fd, root, settings, now=now)


def remove_shared(home: Path | str, token: str) -> None:
    """Remove one shared copy (a share the turn gave up on). Never raises."""
    if not TOKEN_RE.match(token or "") or not upload_dirs.supported():
        return
    try:
        with _locked_outbox(_resolved_home(home), create=False, timeout=30.0) as outbox_fd:
            if outbox_fd is not None:
                _remove_entry(outbox_fd, token)
    except Exception:
        logger.warning("outbox: could not remove an abandoned share in %s", home, exc_info=True)


def remove_session_files(home: Path | str, session_ids: Iterable[str]) -> int:
    """Remove every copy *home*'s outbox holds for the conversations *session_ids* (they were deleted).
    Returns how many were removed. Never raises."""
    ids = {str(sid) for sid in session_ids if sid}
    if not ids or not upload_dirs.supported():
        return 0
    try:
        root = _resolved_home(home)
        if not (root / OUTBOX_DIR).is_dir():
            return 0
        removed = 0
        with _locked_outbox(root, create=False, timeout=30.0) as outbox_fd:
            if outbox_fd is None:
                return 0
            for entry in _entries(outbox_fd):
                if entry.session_id in ids:
                    _remove_entry(outbox_fd, entry.token)
                    removed += 1
        return removed
    except Exception:
        logger.warning("outbox: could not remove the shared files of deleted sessions in %s", home, exc_info=True)
        return 0


def outbox_homes() -> list[Path]:
    """The launch home and every named profile's home: where the background pruner looks."""
    homes: list[Path] = []
    with contextlib.suppress(Exception):
        from hermes_constants import get_hermes_home
        homes.append(Path(get_hermes_home()))
    with contextlib.suppress(Exception):
        from hermes_cli import profiles
        homes.extend(profiles.get_profile_dir(name) for name in profiles.list_profile_names())
    seen: dict[str, Path] = {}
    for home in homes:
        with contextlib.suppress(OSError, RuntimeError):
            seen.setdefault(str(Path(home).resolve()), Path(home))
    return list(seen.values())


#: How often the background pruner runs (and once at start).
PRUNE_INTERVAL_SECONDS = 6 * 3600.0


def run_pruner(stop: threading.Event, *, interval: float = PRUNE_INTERVAL_SECONDS) -> None:
    """Prune every home's outbox now and then every *interval* seconds until *stop* is set (a daemon thread)."""
    while not stop.is_set():
        for home in outbox_homes():
            try:
                prune_outbox(home)
            except Exception:
                logger.debug("outbox: prune of %s failed", home, exc_info=True)
        stop.wait(interval)


def start_pruner() -> threading.Event:
    """Start :func:`run_pruner` on a daemon thread; set the returned event to stop it."""
    stop = threading.Event()
    threading.Thread(target=run_pruner, args=(stop,), daemon=True, name="outbox-pruner").start()
    return stop
