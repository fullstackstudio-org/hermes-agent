"""``hermes sessions import --from hermes FILE``: restore a Hermes session export as the operator.

The file is what ``hermes sessions export`` (JSONL, one session per line), the dashboard's per-session
export (one JSON object) or a ``{"sessions": [...]}`` body holds. Unlike ``POST /api/sessions/import``,
this restore keeps provenance -- sidecars, authors, the stored system prompt, the session's login --
because the person running it is the operator of this Hermes home, on this machine, and named the file
as a Hermes export (``hermes_state_import_provenance``). A file only recognised as one (no ``--from``)
is imported untrusted, as the HTTP import does.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _sessions_in(data: Any) -> Optional[List[Dict[str, Any]]]:
    if isinstance(data, dict) and isinstance(data.get("sessions"), list):
        return data["sessions"]
    if isinstance(data, dict) and isinstance(data.get("messages"), list) and data.get("id"):
        return [data]
    if isinstance(data, list) and data and all(_sessions_in(item) == [item] for item in data):
        return data
    return None


def read_hermes_export(path) -> Optional[List[Dict[str, Any]]]:
    """The sessions a Hermes export file holds, or None when the file is not one (a Claude Code or Codex
    transcript, anything else)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return _sessions_in(json.loads(text))
    except ValueError:
        pass
    sessions: List[Dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            found = _sessions_in(json.loads(line))
        except ValueError:
            return None
        if found is None:
            return None
        sessions.extend(found)
    return sessions or None


def restore_hermes_export(path, db=None, *, keep_provenance: bool = True) -> Dict[str, Any]:
    """Import every session in the export at *path* (with provenance kept unless *keep_provenance* is
    False: then as the untrusted import ``POST /api/sessions/import`` does); returns ``import_sessions``'
    report. Raises ``ValueError`` when the file is not a Hermes export."""
    sessions = read_hermes_export(path)
    if sessions is None:
        raise ValueError(f"Not a Hermes session export: {path}")
    owns_db = db is None
    if owns_db:
        from hermes_state_registry import acquire
        db = acquire()
    try:
        return db.import_sessions(sessions, keep_provenance=keep_provenance)
    finally:
        if owns_db:
            with contextlib.suppress(Exception):
                db.close()
