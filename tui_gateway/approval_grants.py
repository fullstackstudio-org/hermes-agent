"""Standing and session approvals as the apps list and revoke them (``approval.grants`` /
``approval.revoke`` in ``methods_prompt.py``).

The state lives in ``tools/approval.py``; this leaf shapes it for the wire. One grant (one row) is a
group of stored keys that approve overlapping rules. ``is_approved`` honours a stored key for every
rule whose alias set contains it, and that relation is neither symmetric nor transitive: a legacy
regex key such as ``sudo`` or ``git\\s+push`` approves several rules at once, and one rule may be
approved by several spellings. So a row names every rule its keys approve, and revoking it removes
every key of the group: afterwards none of those rules is approved permanently, and nothing outside
them is touched.

A row's ``id`` is ``perm:`` / ``sess:`` plus the first 16 hex characters of sha256(``profile home
key`` NUL the group's rules), recomputed on revoke, so a client never echoes raw command text back.
Callers run under the profile's scope (``@_profile_scoped``).
"""

from __future__ import annotations

import hashlib
import re

# Keys the approval gates store that are not detection descriptions (``tools/approval.py``
# ``check_execute_code_guard``, ``file_tools_write_guards``, ``computer_use/tool.py``,
# ``request_tool_approval``, the tirith findings) or are built per finding.
_SYNTHETIC_KEYS = frozenset({"execute_code", "ssh_config_write", "shell command via -c/-lc flag"})
_SYNTHETIC_PREFIXES = ("tirith:", "plugin_rule:", "cua:", "arbitrary program execution via ")

# Password shapes the shared redactor leaves in command text (it has no notion of CLI flags). A
# label is display only, so masking a harmless ``-p22`` too is the right side to err on.
_PASSWORD_SHAPES = (
    (re.compile(r"(?<![\w-])(-p)(\S+)"), r"\1***"),                                   # mysql -pSECRET
    (re.compile(r"(--pass(?:word|wd)?)(=|\s+)(\S+)", re.I), r"\1\2***"),              # --password SECRET
    (re.compile(r"(\bsshpass\s+-p\s+)(\S+)"), r"\1***"),
    (re.compile(r"(\b[A-Za-z0-9_]*(?:PASS(?:WORD|WD)?|SECRET|TOKEN)[A-Za-z0-9_]*=)(\S+)", re.I), r"\1***"),
)


def _home() -> str:
    from hermes_constants import hermes_home_key
    return hermes_home_key()


def _grant_id(prefix: str, rules: frozenset[str]) -> str:
    digest = hashlib.sha256(f"{_home()}\0{chr(10).join(sorted(rules))}".encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:16]}"


def _descriptions() -> frozenset[str]:
    from tools import approval_detection as detection
    return frozenset({description for _, description in detection.DANGEROUS_PATTERNS}
                     | set(detection._REMOVED_PATTERN_KEY_ALIASES)
                     | {detection._PARSER_LIMIT_DESCRIPTION, detection._MALFORMED_EXEC_DESCRIPTION,
                        detection._GATEWAY_LIFECYCLE_SPLICE_DESCRIPTION})


def _rule_index(descriptions: frozenset[str]) -> dict[str, frozenset[str]]:
    """stored key -> the rules ``is_approved`` honours it for (``key in _approval_key_aliases(rule)``)."""
    from tools.approval_detection import _approval_key_aliases
    index: dict[str, set[str]] = {}
    for rule in descriptions:
        for alias in _approval_key_aliases(rule):
            index.setdefault(alias, set()).add(rule)
    return {key: frozenset(rules) for key, rules in index.items()}


def _groups(keys) -> list[tuple[frozenset[str], frozenset[str]]]:
    """``(stored keys, rules)`` per grant: keys whose rules overlap are one grant. A key no rule
    lists (command text, a glob, a synthetic gate key) is its own rule. Sorted by rules."""
    index = _rule_index(_descriptions())
    groups: list[tuple[set[str], set[str]]] = []
    for key in sorted(keys):
        members, rules = {key}, set(index.get(key) or {key})
        disjoint = []
        for other_members, other_rules in groups:  # existing groups are pairwise disjoint
            if other_rules & rules:
                members |= other_members
                rules |= other_rules
            else:
                disjoint.append((other_members, other_rules))
        groups = [*disjoint, (members, rules)]
    return sorted(((frozenset(m), frozenset(r)) for m, r in groups), key=lambda group: sorted(group[1]))


def _kind(members: frozenset[str], rules: frozenset[str], descriptions: frozenset[str]) -> str:
    from tools.approval_detection import _PATTERN_KEY_ALIASES
    if any(rule in descriptions or rule in _PATTERN_KEY_ALIASES or rule in _SYNTHETIC_KEYS
           or rule.startswith(_SYNTHETIC_PREFIXES) for rule in rules):
        return "pattern"
    return "glob" if any(ch in key for key in members for ch in "*?[") else "command"


def _redact(text: str) -> str:
    """Like an approval card, but forced (a profile with ``security.redact_secrets: false`` too) and
    with URL credentials (``?token=``, ``user:pass@``) and password flags masked."""
    from agent.redact import redact_sensitive_text
    text = redact_sensitive_text(text, force=True, redact_url_credentials=True)
    for shape, replacement in _PASSWORD_SHAPES:
        text = shape.sub(replacement, text)
    return text


def _label(rules: frozenset[str]) -> str:
    return "; ".join(_redact(rule) for rule in sorted(rules))


def _permanent() -> list[tuple[frozenset[str], dict]]:
    from tools import approval
    descriptions = _descriptions()
    return [(members, {"id": _grant_id("perm", rules), "kind": _kind(members, rules, descriptions),
                       "label": _label(rules)})
            for members, rules in _groups(approval.permanent_grants())]


def _session(session_key: str) -> list[tuple[frozenset[str], dict]]:
    from tools import approval
    return [(members, {"id": _grant_id("sess", rules), "kind": "pattern", "label": _label(rules),
                       "tirith": any(rule.startswith("tirith:") for rule in rules)})
            for members, rules in _groups(approval.session_grants(session_key))]


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


def _chooser(prefix: str, grant_id: str | None):
    """The stored keys to remove, decided by ``tools.approval`` under its locks against what is
    stored at that moment: every key (``all``), or every key of the group *grant_id* names."""
    def choose(keys: set[str]) -> set[str]:
        if grant_id is None:
            return set(keys)
        return next((set(members) for members, rules in _groups(keys)
                     if _grant_id(prefix, rules) == grant_id), set())
    return choose


def revoke_permanent(grant_id: str | None) -> int:
    """Revoke the standing grant *grant_id* names, or every one when it is None (one pass)."""
    from tools import approval
    return approval.revoke_permanent(_chooser("perm", grant_id))


def revoke_session(session: dict, grant_id: str | None) -> int:
    """Revoke one of *session*'s session grants, or every one when *grant_id* is None."""
    from tools import approval
    return approval.revoke_session(str(session.get("session_key") or ""), _chooser("sess", grant_id))
