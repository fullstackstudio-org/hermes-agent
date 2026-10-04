"""Upload directories opened and created without following a symbolic link.

The Hermie apps upload files to ``<session cwd>/uploads/hermie/<YYYY-MM-DD>/<16 hex>-<name>`` (attachments through
``POST /api/files/upload-stream``, and the ``upload.dir`` of an ``input.file`` request, contract
``contract/requests`` §5). The working directory is the agent's: an agent in a sandbox with a bind-mounted
workspace can put a symbolic link there (``ln -s ~/.config/autostart uploads``), and a write that follows it lands
the person's file outside the workspace. So everything at and below ``uploads/hermie`` is walked one component at a
time, each opened with ``O_NOFOLLOW | O_DIRECTORY`` relative to its parent's descriptor (and created with
``mkdir(..., dir_fd=)`` when missing): a link or a non-directory anywhere on the way is :class:`UnsafePath`, never
followed, and a link swapped in after a check cannot redirect the walk.

Used by ``tui_gateway/interactive.py`` (the ``upload.dir`` builder and the post-settle file check) and
``hermes_cli/web_routers/files.py`` (the upload routes).
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Sequence

#: The path segments the upload convention puts under the working directory.
UPLOAD_SEGMENTS = ("uploads", "hermie")
#: The mode of a directory this module creates.
DIR_MODE = 0o700

_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
              | getattr(os, "O_CLOEXEC", 0))


class UnsafePath(OSError):
    """A component on the way is a symbolic link or not a directory."""


def supported() -> bool:
    """Whether this platform can walk without following links (``O_NOFOLLOW``, ``O_DIRECTORY`` and ``dir_fd``)."""
    return (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd
            and os.mkdir in os.supports_dir_fd and os.stat in os.supports_dir_fd)


def _check_name(name: str) -> None:
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise UnsafePath(errno.EINVAL, "not a single path component", name)


def open_dir(name: str, *, dir_fd: int) -> int:
    """Open the directory *name* inside *dir_fd* without following a link. ``FileNotFoundError`` when it is not
    there; :class:`UnsafePath` when it is a link or not a directory."""
    _check_name(name)
    info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafePath(errno.ENOTDIR, "a link or not a directory", name)
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
            raise UnsafePath(exc.errno, "a link or not a directory", name) from exc
        raise


def walk(parts: Sequence[str], *, create_from: int | None = None, start: str = "/") -> int:
    """Open *start* (an absolute directory; ``/`` by default), then each of *parts* in turn without following a
    link, and return the last one's descriptor (the caller closes it). Components from index *create_from* on are
    created (mode :data:`DIR_MODE`) when missing; None creates nothing. Raises :class:`UnsafePath`,
    ``FileNotFoundError`` or another ``OSError``."""
    fd = os.open(start, _DIR_FLAGS)
    try:
        for index, name in enumerate(parts):
            _check_name(name)
            if create_from is not None and index >= create_from:
                try:
                    os.mkdir(name, DIR_MODE, dir_fd=fd)
                except FileExistsError:
                    pass
            child = open_dir(name, dir_fd=fd)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def components(path: str) -> list[str]:
    """The components of the absolute *path* (``/a/b`` -> ``["a", "b"]``); :class:`UnsafePath` for a relative path,
    an empty segment, ``.`` or ``..``."""
    if not path.startswith("/"):
        raise UnsafePath(errno.EINVAL, "not an absolute path", path)
    parts = path.strip("/").split("/") if path.strip("/") else []
    for name in parts:
        _check_name(name)
    return parts


def open_real_dir(path: str) -> int:
    """Open the absolute directory *path* from ``/`` without following a link anywhere: it must be a real path
    (``os.path.realpath(path) == path``) for this to succeed."""
    return walk(components(path))


def anchor_index(parts: Sequence[str]) -> int | None:
    """The index of the first ``uploads`` in *parts* that is followed by ``hermie``, or None."""
    for index in range(len(parts) - 1):
        if (parts[index], parts[index + 1]) == UPLOAD_SEGMENTS:
            return index
    return None
