"""The ``dashboard.mcp`` config section as the authorization server reads it.

Pure: no file, no logging. :func:`parse` takes a config mapping (raw or defaulted) and returns the
settings plus a list of problems (a key with a value of the wrong type or out of range keeps its
default); the caller decides whether to log them. The section is operator-only (config file or the
container env), like ``confirm.passkey``: a stolen dashboard session must not be able to switch it on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

SECTION_PATH = ("dashboard", "mcp")

#: Every scope a grant can hold. A client that registers without ``scope`` gets all of them, and a
#: registration or authorization asking for anything else is refused.
SCOPES: tuple[str, ...] = ("bots:read", "bots:prompt", "requests:read", "requests:clarify")

#: ``(minimum, maximum)`` per integer key, in seconds or counts.
RANGES: dict[str, tuple[int, int]] = {
    "access_token_ttl": (60, 24 * 3600),
    "refresh_token_ttl": (3600, 365 * 86400),
    "grant_max_age": (86400, 365 * 86400),
    "max_running_turns_per_grant": (1, 20),
    "max_grants_per_user": (1, 50),
}
LABEL_LIMIT = 64


@dataclass(frozen=True)
class MCPSettings:
    enabled: bool = False
    access_token_ttl: int = 3600  # 1 h
    refresh_token_ttl: int = 30 * 86400  # sliding: every refresh starts it again
    grant_max_age: int = 90 * 86400  # absolute: then the person consents again
    answer_clarify: bool = True
    max_running_turns_per_grant: int = 3
    max_grants_per_user: int = 5
    label: str = ""  # the server name in the ``claude mcp add`` command; "" = derived from the dashboard label


def default_section() -> dict[str, Any]:
    """The defaults as a ``config.yaml`` section (what ``config_defaults`` should carry)."""
    d = MCPSettings()
    return {key: getattr(d, key) for key in MCPSettings.__dataclass_fields__}


def _section(cfg: Any) -> Mapping[str, Any] | None:
    section: Any = cfg
    for key in SECTION_PATH:
        section = section.get(key) if isinstance(section, Mapping) else None
    return section if isinstance(section, Mapping) else None


def parse(cfg: Any) -> tuple[MCPSettings, list[str]]:
    """``(settings, problems)`` for the ``dashboard.mcp`` section of *cfg*. A missing section is the
    defaults (off) with no problem; a section that is not a mapping is the defaults with one."""
    raw = _section(cfg)
    problems: list[str] = []
    if raw is None:
        dashboard = cfg.get("dashboard") if isinstance(cfg, Mapping) else None
        if isinstance(dashboard, Mapping) and dashboard.get("mcp") is not None:
            problems.append("dashboard.mcp is not a mapping; using the defaults")
        return MCPSettings(), problems
    values: dict[str, Any] = {}
    defaults = MCPSettings()
    for key in ("enabled", "answer_clarify"):
        if key in raw and raw[key] is not None:
            if isinstance(raw[key], bool):
                values[key] = raw[key]
            else:
                problems.append(f"dashboard.mcp.{key} must be true or false; using {getattr(defaults, key)}")
    for key, (low, high) in RANGES.items():
        if key not in raw or raw[key] is None:
            continue
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            problems.append(f"dashboard.mcp.{key} must be a whole number from {low} to {high}; "
                            f"using {getattr(defaults, key)}")
            continue
        values[key] = value
    if "label" in raw and raw["label"] is not None:
        label = raw["label"]
        if isinstance(label, str) and len(label.strip()) <= LABEL_LIMIT:
            values["label"] = label.strip()
        else:
            problems.append(f"dashboard.mcp.label must be text of at most {LABEL_LIMIT} characters; using \"\"")
    settings = MCPSettings(**values)
    if settings.access_token_ttl > settings.grant_max_age:
        problems.append("dashboard.mcp.access_token_ttl is longer than grant_max_age; tokens end with the grant")
    return settings, problems


def from_config(cfg: Any) -> MCPSettings:
    """:func:`parse` without the problems."""
    return parse(cfg)[0]
