"""The ``confirm.passkey`` config section: reading it, and telling whether a write would change it.

The section is protected: only the operator changes it, on the gateway host (``config.yaml`` or ``hermes
config set``). The dashboard's config writers (REST ``PUT /api/config``, ``PUT /api/config/raw``) and the
``config.set`` RPC refuse a write that would change what the gateway reads here (:func:`changes_protected`)
and answer ``protected_setting``. "What the gateway reads" is :func:`effective_section`: the defaults with
the file's section merged over them, so a client that echoes the section back unchanged (the settings
page saves the whole defaulted record) is not refused, and one that changes any key, adds one, or
replaces the section with something else is.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Mapping, cast

from hermes_cli.dashboard_auth.passkeys.challenge import (
    GatewayContext, NotABaseUrl, has_path_prefix, serialise_base_url)

_log = logging.getLogger(__name__)

PROTECTED_PATH = ("confirm", "passkey")
PROTECTED_KEY = ".".join(PROTECTED_PATH)
PROTECTED_SETTING = "protected_setting"
PROTECTED_DETAIL = ("protected_setting: confirm.passkey can only be changed on the gateway host "
                    "(config.yaml or `hermes config set`)")
RECEIPTS_DAYS_RANGE = (1, 3650)


def _defaults() -> dict:
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    confirm = cast(dict, DEFAULT_CONFIG["confirm"])
    return copy.deepcopy(cast(dict, confirm["passkey"]))


def _merge(base: dict, over: Mapping) -> dict:
    # The config loader's rule (``hermes_cli.config._deep_merge``): dict over dict recurses, ``None`` over
    # a dict is ignored, anything else replaces.
    out = dict(base)
    for key, value in over.items():
        if isinstance(out.get(key), dict) and isinstance(value, Mapping):
            out[key] = _merge(out[key], value)
        elif not (isinstance(out.get(key), dict) and value is None):
            out[key] = value
    return out


def effective_section(cfg: Any) -> dict:
    """``confirm.passkey`` as the gateway reads it from *cfg* (a raw or a defaulted config mapping)."""
    section: Any = cfg
    for key in PROTECTED_PATH:
        section = section.get(key) if isinstance(section, Mapping) else None
    return _merge(_defaults(), section) if isinstance(section, Mapping) else _defaults()


def changes_protected(before: Any, after: Any) -> bool:
    """True when *after* would make the gateway read a different ``confirm.passkey`` than *before*."""
    return effective_section(before) != effective_section(after)


def audit_refusal(surface: str, *, user_id: str = "", ip: str = "", **fields) -> None:
    """One audit line for a refused write: which surface (``config_put``, ``config_raw``, ``config_set``),
    who (``<provider>:<user id>``, empty for a connection without a signed-in user) and from where."""
    from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
    audit_log(AuditEvent.PROTECTED_SETTING_REFUSED, surface=surface, key=PROTECTED_KEY, user_id=user_id, ip=ip,
              **fields)


def audit_refusal_for_request(surface: str, request: Any) -> None:
    """:func:`audit_refusal` for a REST request: the gate's verified session and the settled client address."""
    session = getattr(getattr(request, "state", None), "session", None)
    user_id = f"{session.provider}:{session.user_id}" if session is not None else ""
    try:
        from hermes_cli.dashboard_auth.request_utils import client_ip
        ip = client_ip(request)
    except Exception:  # noqa: BLE001 - an audit line must not fail the refusal
        ip = ""
    audit_refusal(surface, user_id=user_id, ip=ip, path=str(getattr(getattr(request, "url", None), "path", "")))


def is_protected_key(key: str) -> bool:
    """A dotted config key that names ``confirm``, ``confirm.passkey`` or anything below it."""
    parts = str(key).strip().split(".")
    return parts[0] == PROTECTED_PATH[0] and (len(parts) == 1 or parts[1] == PROTECTED_PATH[1])


@dataclass(frozen=True)
class Require:
    """The operator rules (``confirm.passkey.require``), enforced by ``tools/passkey_policy.py``."""

    commands: tuple[str, ...] = ()
    smart_denied: bool = False
    approvals: bool = False
    tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class PasskeySettings:
    enabled: bool = False
    base_urls: tuple[str, ...] = ()  # serialised (contract §3); the only base URLs a challenge may name
    native_rps: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    user_invites: bool = True
    receipts_days: int = 90
    allow_private_base_urls: bool = False
    require: Require = Require()
    problems: tuple[str, ...] = ()  # entries that were ignored, for ``passkey status``


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(v.strip() for v in value if isinstance(v, str) and v.strip()) if isinstance(value, list) else ()


def _native_rps(value: Any, problems: list[str]) -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    if not isinstance(value, Mapping):
        problems.append("native_rps is not a mapping")
        return out
    for rp_id, origins in value.items():
        if not isinstance(rp_id, str) or not rp_id or rp_id != rp_id.strip().lower() or "/" in rp_id \
                or ":" in rp_id:
            problems.append(f"native_rps: {rp_id!r} is not a lower-case host name")
            continue
        if origins == []:
            continue  # how a listed RP (the default one too: the section is merged over the defaults) is removed
        accepted: list[str] = []
        for origin in origins if isinstance(origins, list) else []:
            try:
                serialised = serialise_base_url(origin)
            except NotABaseUrl:
                serialised = ""
            if not serialised.startswith("https://") or has_path_prefix(serialised) or serialised != origin:
                problems.append(f"native_rps.{rp_id}: {origin!r} is not a serialised https origin")
                continue
            accepted.append(serialised)
        if accepted:
            out[rp_id] = tuple(accepted)
        else:
            problems.append(f"native_rps.{rp_id}: no usable origin")
    return out


def _base_urls(value: Any, problems: list[str]) -> tuple[str, ...]:
    if not isinstance(value, list):
        problems.append("base_urls is not a list")
        return ()
    urls, rejected = serialise_base_urls(value)
    problems.extend(f"base_urls: {url!r} is not an http(s) base URL" for url in rejected)
    return urls


def settings_from_config(cfg: Any) -> PasskeySettings:
    """Typed, validated settings. Unusable entries are dropped (and named in ``problems``), never guessed."""
    raw = effective_section(cfg)
    problems: list[str] = []

    def flag(name: str) -> bool:
        value = raw.get(name)
        if isinstance(value, bool):
            return value
        problems.append(f"{name} is not true or false; using {_defaults()[name]}")
        return bool(_defaults()[name])

    days = raw.get("receipts_days")
    low, high = RECEIPTS_DAYS_RANGE
    if isinstance(days, bool) or not isinstance(days, int) or not low <= days <= high:
        problems.append(f"receipts_days must be a whole number from {low} to {high}; using 90")
        days = 90
    return PasskeySettings(enabled=flag("enabled"), base_urls=_base_urls(raw.get("base_urls"), problems),
                           native_rps=_native_rps(raw.get("native_rps"), problems),
                           user_invites=flag("user_invites"), receipts_days=days,
                           allow_private_base_urls=flag("allow_private_base_urls"),
                           require=_require(raw, problems), problems=tuple(problems))


def _require(raw: Mapping, problems: list[str]) -> Require:
    """``require`` as the policy applies it: a glob list that is not a list, or an entry that is not a
    non-empty string, is dropped (and named in *problems*); a flag that is not ``true`` is off."""
    req = raw.get("require")
    if not isinstance(req, Mapping):
        problems.append("require is not a mapping; no operator rules apply")
        return Require()
    for name in ("commands", "tools"):
        value = req.get(name)
        if value is not None and not isinstance(value, list):
            problems.append(f"require.{name} is not a list; ignored")
        elif isinstance(value, list) and len(_strings(value)) != len(value):
            problems.append(f"require.{name}: entries that are not non-empty strings are ignored")
    for name in ("smart_denied", "approvals"):
        if req.get(name) not in (None, True, False):
            problems.append(f"require.{name} is not true or false; using false")
    return Require(commands=_strings(req.get("commands")), smart_denied=req.get("smart_denied") is True,
                   approvals=req.get("approvals") is True, tools=_strings(req.get("tools")))


_logged_require_problems: set[str] = set()


def require_from_config(cfg: Any) -> Require:
    """Only the operator rules, read the same way: the per-command and per-tool-call path, which must not
    pay for parsing base URLs and RPs. Each problem is logged once per process (a scalar
    ``commands: "git push*"`` would otherwise silently mean no rule)."""
    problems: list[str] = []
    require = _require(effective_section(cfg), problems)
    for problem in problems:
        if problem not in _logged_require_problems:
            _logged_require_problems.add(problem)
            _log.warning("confirm.passkey.%s", problem)
    return require


def load_settings() -> PasskeySettings:
    from hermes_cli.config import load_config
    return settings_from_config(load_config())


def serialise_base_urls(urls: list) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(serialised, rejected)``: each URL serialised per contract §3, duplicates dropped, in order."""
    out: list[str] = []
    rejected: list[str] = []
    for url in urls:
        try:
            serialised = serialise_base_url(url) if isinstance(url, str) else ""
        except NotABaseUrl:
            serialised = ""
        if not serialised:
            rejected.append(str(url))
            continue
        if serialised not in out:
            out.append(serialised)
    return tuple(out), tuple(rejected)


def gateway_context(identity: tuple[bytes, bytes], settings: PasskeySettings) -> GatewayContext:
    """The verifier's view of this gateway: store identity, the level's own base URLs, native RPs.

    Never the dashboard's public URLs (``dashboard.public_url(s)``): a dashboard session can change those,
    and a second gateway's address there would let answers given to that gateway verify here."""
    gateway_id, handle_key = identity
    return GatewayContext(gateway_id=gateway_id, handle_key=handle_key, base_urls=settings.base_urls,
                          native_rps=dict(settings.native_rps),
                          allow_private_base_urls=settings.allow_private_base_urls)
