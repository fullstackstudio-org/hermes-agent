"""Whether a path names a given file or lies inside a given folder, however it is spelled.

``Path.resolve()`` and ``os.path.realpath`` follow links but keep the spelling they were handed. On a
case-insensitive volume (macOS and Windows by default, a FAT/exFAT mount, an ext4 ``casefold`` folder)
``<home>/STATE.DB`` and ``~/.CONFIG/gh/hosts.yml`` open ``<home>/state.db`` and ``~/.config/gh/hosts.yml`` yet
compare unequal to them as strings, and on macOS a name typed in another Unicode form (NFD/NFC) does too, so a
denylist built on string comparison misses them. This module compares what the names lead to:

- :func:`fd_path`: the path the kernel holds for an open descriptor, in the spelling the volume stores (macOS
  ``F_GETPATH``, Linux ``/proc/self/fd``), so a check can judge the file that was actually opened;
- :class:`PathProbe`: "is this path that file" / "is it inside that folder" by the device and inode of the path
  and of its existing ancestors, and by a case- and Unicode-folded string where the volume is case-insensitive
  (a name that does not exist yet has no inode).

Fork-only (``tui_gateway/outbox.py`` and the delivery and file guards it relies on).
"""

from __future__ import annotations

import os
import sys
import unicodedata
from pathlib import Path
from typing import Iterable

#: ``fcntl.F_GETPATH`` (macOS); ``fcntl`` exposes it from Python 3.9 on.
_F_GETPATH = 50
#: ``pathconf`` name ``_PC_CASE_SENSITIVE`` (macOS): 1 case-sensitive, 0 not.
_PC_CASE_SENSITIVE = 11
_MAXPATHLEN = 1024


def fd_path(fd: int) -> str | None:
    """The absolute path of the open descriptor *fd* as the file system stores it, or None when the platform
    cannot say (or the file has no name any more)."""
    try:
        if sys.platform == "darwin":
            import fcntl
            raw = fcntl.fcntl(fd, getattr(fcntl, "F_GETPATH", _F_GETPATH), bytes(_MAXPATHLEN + 1))
            path = os.fsdecode(raw.split(b"\0", 1)[0])
        elif sys.platform.startswith("linux"):
            if os.fstat(fd).st_nlink == 0:
                return None
            path = os.readlink(f"/proc/self/fd/{fd}")
        else:
            return None
    except (OSError, ValueError):
        return None
    return path if path.startswith("/") else None


def fold(text: str) -> str:
    """*text* case-folded and in one Unicode form: the key a case-insensitive volume compares names by."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", text).casefold())


def _nearest_dir(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        try:
            if candidate.is_dir():
                return candidate
        except (OSError, ValueError):
            continue
    return None


def case_insensitive(path: str | os.PathLike) -> bool:
    """Whether names at *path* (its nearest existing folder) are looked up without regard to case."""
    if os.name == "nt":
        return True
    folder = _nearest_dir(Path(path))
    if folder is None:
        return False
    if sys.platform == "darwin":
        try:
            return os.pathconf(folder, _PC_CASE_SENSITIVE) == 0
        except (OSError, ValueError):
            pass
    # Elsewhere: the nearest named folder looked up under its name with the case swapped.
    for candidate in (folder, *folder.parents):
        swapped = candidate.name.swapcase()
        if swapped == candidate.name:
            continue
        try:
            return os.path.samestat(os.stat(candidate), os.stat(candidate.parent / swapped))
        except (OSError, ValueError):
            return False
    return False


def _identity(path: str | os.PathLike) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return None
    return (info.st_dev, info.st_ino) if info.st_ino else None


class PathProbe:
    """One resolved, absolute path, compared against files and folders by what they are, not how they are
    spelled. Built once per check: the path's identities and case rule are read on first use."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._chain: set[tuple[int, int]] | None = None
        self._self_id: tuple[int, int] | None = None
        self._insensitive: bool | None = None

    def _ids(self) -> set[tuple[int, int]]:
        """The identities of the path (when it exists) and of each of its existing ancestors."""
        if self._chain is None:
            chain: set[tuple[int, int]] = set()
            for index, candidate in enumerate((self.path, *self.path.parents)):
                ident = _identity(candidate)
                if ident is not None:
                    chain.add(ident)
                    if index == 0:
                        self._self_id = ident
            self._chain = chain
        return self._chain

    def _folds(self) -> bool:
        if self._insensitive is None:
            self._insensitive = case_insensitive(self.path)
        return self._insensitive

    def is_(self, other: str | os.PathLike) -> bool:
        """Whether the path names the file or folder *other* (the same object, a hard link included)."""
        other = Path(other)
        if self.path == other:
            return True
        if self._folds() and fold(str(self.path)) == fold(str(other)):
            return True
        self._ids()
        return self._self_id is not None and self._self_id == _identity(other)

    def within(self, root: str | os.PathLike) -> bool:
        """Whether the path is *root* or lies inside it."""
        root = Path(root)
        if self.path == root or root in self.path.parents:
            return True
        if self._folds():
            key, root_key = fold(str(self.path)), fold(str(root)).rstrip(os.sep)
            if key == root_key or key.startswith(root_key + os.sep):
                return True
        ident = _identity(root)
        return ident is not None and ident in self._ids()

    def within_any(self, roots: Iterable[str | os.PathLike]) -> bool:
        return any(self.within(root) for root in roots)
