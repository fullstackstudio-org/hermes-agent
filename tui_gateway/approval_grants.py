"""Standing and session approvals as the apps list and revoke them (``approval.grants`` /
``approval.revoke`` in ``methods_prompt.py``).

The state lives in ``tools/approval.py``; this leaf only shapes it for the wire. A grant's ``id`` is
``perm:`` / ``sess:`` plus the first 16 hex characters of sha256(``profile home key`` NUL ``key``),
recomputed on revoke, so a client never has to echo raw command text back. An allowlist entry and
its legacy regex-derived alias are one grant: the canonical rule key names it, and a revoke removes
both. Callers run under the profile's scope (``@_profile_scoped``).
"""

from __future__ import annotations

import hashlib

# Keys the approval gates store that are not detection descriptions (``tools/approval.py``
# ``check_execute_code_guard``, ``file_tools_write_guards``, ``computer_use/tool.py``,
# ``request_tool_approval``, the tirith findings) or are built per finding.
_SYNTHETIC_KEYS = frozenset({"execute_code", "ssh_config_write", "shell command via -c/-lc flag"})
_SYNTHETIC_PREFIXES = ("tirith:", "plugin_rule:", "cua:", "arbitrary program execution via ")


def _home() -> str:
    from hermes_constants import hermes_home_key
    return hermes_home_key()


def _grant_id(prefix: str, key: str) -> str:
    digest = hashlib.sha256(f"{_home()}\0{key}".encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:16]}"


def _descriptions() -> frozenset[str]:
    from tools import approval_detection as detection
    return frozenset({description for _, description in detection.DANGEROUS_PATTERNS}
                     | set(detection._REMOVED_PATTERN_KEY_ALIASES)
                     | {detection._PARSER_LIMIT_DESCRIPTION, detection._MALFORMED_EXEC_DESCRIPTION,
                        detection._GATEWAY_LIFECYCLE_SPLICE_DESCRIPTION})


def _canonical(key: str, descriptions: frozenset[str]) -> str:
    """The rule description an alias group is known by (a legacy regex key maps to it), else *key*."""
    from tools.approval_detection import _approval_key_aliases
    if key in descriptions:
        return key
    named = sorted(alias for alias in _approval_key_aliases(key) if alias in descriptions)
    return named[0] if named else key


def _kind(key: str, descriptions: frozenset[str]) -> str:
    from tools.approval_detection import _PATTERN_KEY_ALIASES
    if (key in descriptions or key in _PATTERN_KEY_ALIASES or key in _SYNTHETIC_KEYS
            or key.startswith(_SYNTHETIC_PREFIXES)):
        return "pattern"
    return "glob" if any(ch in key for ch in "*?[") else "command"


def _label(key: str) -> str:
    from agent.redact import redact_sensitive_text
    return redact_sensitive_text(key)


def _grouped(keys) -> list[tuple[str, str]]:
    """``(stored key, canonical key)`` per grant, one per alias group, in a stable order."""
    descriptions = _descriptions()
    groups: dict[str, str] = {}
    for key in sorted(keys):
        groups.setdefault(_canonical(key, descriptions), key)
    return sorted((key, canonical) for canonical, key in groups.items())


def _permanent() -> list[tuple[str, dict]]:
    from tools import approval
    descriptions = _descriptions()
    return [(key, {"id": _grant_id("perm", canonical), "kind": _kind(canonical, descriptions),
                   "label": _label(canonical)})
            for key, canonical in _grouped(approval.permanent_grants())]


def _session(session_key: str) -> list[tuple[str, dict]]:
    from tools import approval
    return [(key, {"id": _grant_id("sess", canonical), "kind": "pattern", "label": _label(canonical),
                   "tirith": canonical.startswith("tirith:")})
            for key, canonical in _grouped(approval.session_grants(session_key))]


def permanent_rows() -> list[dict]:
    return [row for _, row in _permanent()]


def session_row(sid: str, session: dict, *, keep_empty: bool) -> dict | None:
    """The ``sessions[]`` row of one live session; None when it holds nothing and *keep_empty* is off."""
    from tools.approval import is_session_yolo_enabled
    session_key = str(session.get("session_key") or "")
    grants = [row for _, row in _session(session_key)] if session_key else []
    yolo = bool(session_key) and is_session_yolo_enabled(session_key)
    if not grants and not yolo and not keep_empty:
        return None
    return {"session_id": sid, "session_key": session_key, "yolo": yolo, "grants": grants}


def revoke_permanent(grant_id: str | None) -> int:
    """Revoke the standing grant *grant_id* names, or every one when it is None."""
    from tools import approval
    return sum(approval.revoke_permanent(key) for key, row in _permanent()
               if grant_id is None or row["id"] == grant_id)


def revoke_session(session: dict, grant_id: str | None) -> int:
    """Revoke one of *session*'s session grants, or every one when *grant_id* is None."""
    from tools import approval
    session_key = str(session.get("session_key") or "")
    if grant_id is None:
        return approval.revoke_session(session_key, None)
    return sum(approval.revoke_session(session_key, key) for key, row in _session(session_key)
               if row["id"] == grant_id)
