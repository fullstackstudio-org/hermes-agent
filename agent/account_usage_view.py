"""Structured, credential-free provider account usage: the data behind the ``account.usage`` RPC.

``agent/account_usage.py`` fetches a provider's quota windows and credits; the text ``/usage`` renders them as
lines. An app needs the same numbers as fields, for the providers the profile's configured models run on, and
needs the call to be cheap enough to poll. This module owns that: which providers, one entry per provider in a
fixed shape, a short cache, a floor on how often a provider is actually asked, and a wall-clock bound per fetch.

What leaves here is built field by field from the snapshot -- never the snapshot's ``raw`` provider body, never a
header, token or request URL, and never an exception's text (a failed fetch becomes one of a few fixed reasons).
Free text that did pass through (plan name, detail lines) is dropped whole when the redactor would touch it.
"""

from __future__ import annotations

import contextvars
import copy
import logging
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

logger = logging.getLogger(__name__)

#: A fetched entry is served for this long; ``refresh`` skips it, but never more often than the floor below.
CACHE_TTL_S = 60.0
#: A failed fetch (timeout, provider error) is remembered for the shortest span that keeps a down provider from being asked
#: on every poll.
FAILURE_TTL_S = 15.0
#: The most often a (profile, provider) pair is really fetched, ``refresh`` or not.
REFRESH_MIN_INTERVAL_S = 15.0
#: Wall-clock bound per provider; past it the entry is ``available: false``.
PROVIDER_TIMEOUT_S = 10.0
#: How long a caller with nothing cached waits for a fetch of the same pair that is already running, before it
#: answers :data:`REFRESHING_REASON` instead of holding an RPC worker for up to the whole bound.
WAITER_TIMEOUT_S = 2.0
REFRESHING_REASON = "Usage for this provider is being refreshed; ask again in a moment."

_MAX_TEXT = 300
_MAX_CACHE_ENTRIES = 512

#: Provider ids that are not a provider with an account (a custom endpoint), whatever the config says.
_NO_ACCOUNT_PROVIDERS = frozenset({"", "auto", "custom"})

_DEFAULT_TITLES = {
    "anthropic": "Claude account limits",
    "openai-codex": "Codex account limits",
    "openrouter": "OpenRouter credits",
    "nous": "Nous credits",
}
_DEFAULT_SOURCES = {
    "anthropic": "oauth_usage_api", "openai-codex": "usage_api", "openrouter": "credits_api", "nous": "portal-account",
}
# Lines of the text ``/usage`` that are a call to action for that surface, not data about the account.
_TEXT_ONLY_DETAIL_PREFIXES = ("Top up:", "(or run", "(dev fixture")

Fetcher = Callable[[str], Any]  # provider -> AccountUsageSnapshot | None (may raise)


def iso_utc(moment: Optional[datetime]) -> Optional[str]:
    """``2026-10-05T12:00:00Z`` for a datetime (naive is taken as UTC), None for None."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_iso() -> str:
    return iso_utc(datetime.now(timezone.utc)) or ""


# ── which providers ─────────────────────────────────────────────────────────────────────────────


def configured_providers(cfg: Optional[dict]) -> list[str]:
    """The providers the profile's configured models run on, in config order: ``model.provider`` (or what
    ``auto`` resolves to), then the fallback chain, de-duplicated, keeping only those with a usage source."""
    from agent.account_usage import usage_supported
    from hermes_cli.fallback_config import get_fallback_chain
    from hermes_cli.models import normalize_provider

    cfg = cfg if isinstance(cfg, dict) else {}
    model = cfg.get("model")
    primary = str((model.get("provider") if isinstance(model, dict) else "") or "").strip().lower()
    if primary in {"", "auto"}:
        primary = _resolve_auto()
    raw = [primary, *(str(entry.get("provider") or "") for entry in get_fallback_chain(cfg) if isinstance(entry, dict))]
    names: list[str] = []
    for value in raw:
        name = value.strip().lower()
        if name in _NO_ACCOUNT_PROVIDERS or name.startswith("custom:"):
            continue
        name = normalize_provider(name)
        if name not in names and usage_supported(name):
            names.append(name)
    return names


def _resolve_auto() -> str:
    try:
        from hermes_cli.auth import resolve_provider

        return str(resolve_provider("auto") or "").strip().lower()
    except Exception:
        return ""


# ── one entry ───────────────────────────────────────────────────────────────────────────────────


# What no usage text from a provider has a reason to contain: an auth scheme with its value, a credential-named
# assignment, userinfo in a URL, one long opaque run, or a shorter run of 24+ letters and digits that mixes both (a
# 32-hex key, a base64 secret). The redactor catches known token prefixes; this catches the shape. Words, numbers,
# dates and slugs such as ``default_claude_max_20x`` stay: a word has no digits, a number no letters, and ``_``,
# ``-`` and ``:`` break a run.
_CREDENTIAL_SHAPES = re.compile(
    r"(?i)\b(bearer|basic|authorization)\b[:\s]+\S{6,}"
    r"|\b(token|api[_-]?key|secret|password|passwd|credential)s?\b\s*[=:]\s*\S{4,}"
    r"|://[^/\s@]*@"
    r"|[A-Za-z0-9_\-.=+/]{40,}"
    r"|(?<![A-Za-z0-9])(?=[A-Za-z]*[0-9])(?=[0-9]*[A-Za-z])[A-Za-z0-9]{24,}")


def _safe_text(value: Any) -> Optional[str]:
    """*value* as a short string, or None when it is empty or anything credential-shaped is in it (the redactor's
    known token formats, or :data:`_CREDENTIAL_SHAPES`): the whole string goes, never a masked remnant."""
    if not isinstance(value, str) or not (text := value.strip()):
        return None
    from agent.redact import redact_sensitive_text

    if redact_sensitive_text(text, force=True) != text or _CREDENTIAL_SHAPES.search(text):
        return None
    return text[:_MAX_TEXT]


def _finite(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


#: The label of a window whose own label was dropped as credential-shaped (its id is ``window_<n>``).
_FALLBACK_WINDOW_LABEL = "Usage window"


def _window_ids(labels: Sequence[Optional[str]]) -> list[str]:
    """A stable slug per window. *labels* are the already vetted ones (``_safe_text``): a dropped label (None)
    gets ``window_<position>``, never a slug of the text that was dropped, which would carry it out reworded."""
    ids: list[str] = []
    for position, label in enumerate(labels, start=1):
        base = "".join(ch if ch.isalnum() else "_" for ch in (label or "").lower()).strip("_") or f"window_{position}"
        base = "_".join(part for part in base.split("_") if part)
        candidate, n = base, 2
        while candidate in ids:
            candidate, n = f"{base}_{n}", n + 1
        ids.append(candidate)
    return ids


def entry_from_snapshot(provider: str, snapshot: Any) -> dict:
    """The wire entry for one ``AccountUsageSnapshot``; a None snapshot is a provider with no credentials here."""
    if snapshot is None:
        return unavailable_entry(provider, "Not signed in to this provider in this profile.")
    windows_in = list(snapshot.windows)
    labels = [_safe_text(window.label) for window in windows_in]
    ids = _window_ids(labels)
    windows = []
    for window_id, label, window in zip(ids, labels, windows_in):
        used = _finite(window.used_percent)
        windows.append({
            "id": window_id, "label": label or _FALLBACK_WINDOW_LABEL,
            "used_percent": None if used is None else round(max(0.0, min(100.0, used)), 2),
            "reset_at": iso_utc(window.reset_at), "detail": _safe_text(window.detail),
        })
    details = [text for line in snapshot.details
               if not str(line).lstrip().startswith(_TEXT_ONLY_DETAIL_PREFIXES) and (text := _safe_text(line))]
    credits = None
    if (snap_credits := getattr(snapshot, "credits", None)) is not None:
        remaining, total = _finite(snap_credits.remaining), _finite(snap_credits.total)
        if remaining is not None and (currency := _safe_text(snap_credits.currency)):
            credits = {"currency": currency, "remaining": round(remaining, 4),
                       "total": None if total is None else round(total, 4)}
    reason = _safe_text(snapshot.unavailable_reason)
    available = bool(windows or details or credits) and not snapshot.unavailable_reason
    return {
        "provider": provider,
        "source": _safe_text(snapshot.source) or _DEFAULT_SOURCES.get(provider, provider),
        "title": _safe_text(snapshot.title) or _DEFAULT_TITLES.get(provider, "Account limits"),
        "plan": _safe_text(snapshot.plan),
        "available": available,
        "unavailable_reason": None if available else (reason or "The provider reported no usage for this account."),
        "fetched_at": iso_utc(snapshot.fetched_at) or _now_iso(),
        "windows": windows, "details": details, "credits": credits,
    }


def unavailable_entry(provider: str, reason: str) -> dict:
    return {
        "provider": provider, "source": _DEFAULT_SOURCES.get(provider, provider),
        "title": _DEFAULT_TITLES.get(provider, "Account limits"), "plan": None, "available": False,
        "unavailable_reason": reason, "fetched_at": _now_iso(), "windows": [], "details": [], "credits": None,
    }


def _failure_reason(exc: BaseException) -> str:
    """One of a few fixed sentences: an exception's own text can carry a URL, a header or a token."""
    import httpx

    from hermes_cli.auth import AuthError

    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status in (401, 403):
            return f"The provider rejected this profile's credentials (HTTP {status})."
        return f"The provider answered HTTP {status}."
    if isinstance(exc, (httpx.HTTPError, OSError)):
        return "Could not reach the provider."
    if isinstance(exc, AuthError):
        return "Not signed in to this provider in this profile."
    return "Could not read usage from the provider."


# ── the cache, the floor and the bound ───────────────────────────────────────────────────────────


@dataclass
class _Slot:
    entry: dict
    stored_at: float
    fetched_at: float
    ttl: float


_cache: dict[tuple[str, str], _Slot] = {}
_key_locks: dict[tuple[str, str], threading.Lock] = {}
_registry_lock = threading.Lock()


def reset_for_tests() -> None:
    with _registry_lock:
        _cache.clear()
        _key_locks.clear()


def _key_lock(key: tuple[str, str]) -> threading.Lock:
    with _registry_lock:
        return _key_locks.setdefault(key, threading.Lock())


def _store(key: tuple[str, str], slot: _Slot) -> None:
    with _registry_lock:
        _cache[key] = slot
        while len(_cache) > _MAX_CACHE_ENTRIES:
            _cache.pop(min(_cache, key=lambda k: _cache[k].fetched_at))


def _read(key: tuple[str, str]) -> Optional[_Slot]:
    with _registry_lock:
        return _cache.get(key)


def default_fetch(provider: str) -> Any:
    """The fetch under the active profile scope: on-disk credentials of the profile the call is bound to."""
    from agent.account_usage import fetch_account_usage_strict

    return fetch_account_usage_strict(provider)


def _fetch_entry(provider: str, fetch: Fetcher) -> tuple[dict, float]:
    """``(entry, ttl)`` of one bounded fetch; never raises."""
    from agent.deadline import run_bounded_sync

    timeout = PROVIDER_TIMEOUT_S
    try:
        bounded = run_bounded_sync(lambda: fetch(provider), timeout, label=f"account-usage-{provider}")
    except Exception as exc:
        logger.debug("account usage for %s failed", provider, exc_info=True)
        return unavailable_entry(provider, _failure_reason(exc)), FAILURE_TTL_S
    if bounded.timed_out:
        return unavailable_entry(provider, f"The provider did not answer within {timeout:g} seconds."), FAILURE_TTL_S
    try:
        entry = entry_from_snapshot(provider, bounded.value)
    except Exception:
        logger.debug("account usage for %s could not be read", provider, exc_info=True)
        return unavailable_entry(provider, "Could not read usage from the provider."), FAILURE_TTL_S
    return entry, (CACHE_TTL_S if entry["available"] else FAILURE_TTL_S)


def provider_entry(profile_key: str, provider: str, *, refresh: bool = False, fetch: Optional[Fetcher] = None) -> dict:
    """The entry for (*profile_key*, *provider*): the cached one while it is younger than the TTL, else one
    bounded fetch. ``refresh`` skips a fresh entry only when the pair was last fetched at least
    ``REFRESH_MIN_INTERVAL_S`` ago. One fetch per pair at a time, so a burst makes one fetch; a caller that finds
    it running does not queue behind it for up to the bound (it would hold an RPC worker all that time): it
    answers the entry the pair has, however old, or with nothing cached waits ``WAITER_TIMEOUT_S`` for the
    fetch and else answers :data:`REFRESHING_REASON`, which is not cached."""
    key = (profile_key, provider)
    lock = _key_lock(key)
    if not lock.acquire(blocking=False):
        if (slot := _read(key)) is not None:
            return copy.deepcopy(slot.entry)
        if not lock.acquire(timeout=WAITER_TIMEOUT_S):
            return unavailable_entry(provider, REFRESHING_REASON)
    try:
        slot = _read(key)
        now = time.monotonic()
        if slot is not None:
            fresh = now - slot.stored_at < slot.ttl
            may_refresh = refresh and now - slot.fetched_at >= REFRESH_MIN_INTERVAL_S
            if fresh and not may_refresh:
                return copy.deepcopy(slot.entry)
        entry, ttl = _fetch_entry(provider, fetch or default_fetch)
        stamp = time.monotonic()
        _store(key, _Slot(entry=entry, stored_at=stamp, fetched_at=stamp, ttl=ttl))
        return copy.deepcopy(entry)
    finally:
        lock.release()


def collect(profile_key: str, providers: Sequence[str], *, refresh: bool = False,
            fetch: Optional[Fetcher] = None) -> list[dict]:
    """One entry per provider, fetched side by side so the call takes about one bound, not one per provider."""
    if len(providers) <= 1:
        return [provider_entry(profile_key, p, refresh=refresh, fetch=fetch) for p in providers]
    from tools.daemon_pool import DaemonThreadPoolExecutor

    pool = DaemonThreadPoolExecutor(max_workers=len(providers))
    try:
        # One context copy per task (a Context cannot be entered twice at once): the profile scope rides along.
        futures = [pool.submit(contextvars.copy_context().run, provider_entry, profile_key, p, refresh=refresh, fetch=fetch)
                   for p in providers]
        return [future.result() for future in futures]
    finally:
        pool.shutdown(wait=False)
