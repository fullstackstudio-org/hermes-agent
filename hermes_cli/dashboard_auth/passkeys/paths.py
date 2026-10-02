"""Where passkey stores live, for the code that must never copy, restore, overwrite or delete one.

A store is ``<home>/dashboard_auth/passkeys.db`` plus its ``-wal`` / ``-shm`` / ``-journal`` siblings, for
the active home, the default root and each profile. Names are compared case-folded and directories by
``os.path.samestat``, because macOS (APFS) and Windows file systems ignore case: ``Dashboard_Auth/Passkeys.db``
in an archive, or ``<home>/../.HERMES`` in a request, names the same file or folder. Standard library only:
backups, profiles and the file manager import this.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePath
from typing import Iterable

STORE_DIR = "dashboard_auth"
STORE_PREFIX = "passkeys.db"


def is_store_name(directory_name: str, file_name: str) -> bool:
    """A file *file_name* in a directory named *directory_name* is (part of) a passkey store."""
    return directory_name.casefold() == STORE_DIR and file_name.casefold().startswith(STORE_PREFIX)


def is_store_member(rel_path: PurePath) -> bool:
    """A relative path (archive member, walk entry) that is (part of) a passkey store."""
    return len(rel_path.parts) >= 2 and is_store_name(rel_path.parts[-2], rel_path.parts[-1])


def drop_store_copies(home: Path) -> list[Path]:
    """Delete every store file under ``<home>/<any case of dashboard_auth>/``; the paths removed."""
    removed: list[Path] = []
    if not home.is_dir():
        return removed
    for directory in home.iterdir():
        if directory.is_dir() and not directory.is_symlink() and directory.name.casefold() == STORE_DIR:
            for entry in directory.iterdir():
                if is_store_name(directory.name, entry.name) and (entry.is_file() or entry.is_symlink()):
                    entry.unlink()
                    removed.append(entry)
    return removed


def _homes() -> Iterable[Path]:
    from hermes_constants import get_default_hermes_root, get_hermes_home
    root = get_default_hermes_root()
    yield get_hermes_home()
    yield root
    profiles = root / "profiles"
    if profiles.is_dir():
        yield from (p for p in profiles.iterdir() if p.is_dir())


def store_dirs() -> list[Path]:
    """Every store directory that holds a store now, as real paths (symbolic links resolved), once each."""
    found: list[Path] = []
    for home in _homes():
        directory = home / STORE_DIR
        try:
            if any(e.name.casefold().startswith(STORE_PREFIX) for e in os.scandir(directory)):
                real = Path(os.path.realpath(directory))
                if real not in found:
                    found.append(real)
        except OSError:
            continue
    return found


def _stats(paths: Iterable[Path]) -> list[os.stat_result]:
    out: list[os.stat_result] = []
    for candidate in paths:
        try:
            out.append(os.stat(candidate))
        except OSError:
            continue
    return out


def holds_store(path: Path) -> bool:
    """True when *path* is a store directory or one of its parents (deleting it takes a store along), by
    file identity: case variants and symbolic links to those directories count."""
    try:
        target = os.stat(path)
    except OSError:
        return False
    return any(os.path.samestat(target, st)
               for store in store_dirs() for st in _stats((store, *store.parents)))


def inside_store_dir(path: Path) -> bool:
    """True when writing *path* would put a file in a store directory: a ``dashboard_auth`` part in any case,
    or an existing ancestor (the path itself included) that is a store directory by file identity."""
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    if any(part.casefold() == STORE_DIR for part in path.parts):
        return True
    stores = _stats(store_dirs())
    return any(os.path.samestat(st, store) for st in _stats((path, *path.parents)) for store in stores)
