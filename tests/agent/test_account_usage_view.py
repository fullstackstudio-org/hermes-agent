"""``agent/account_usage_view.py``: the structured, credential-free account usage behind ``account.usage``.

Fetchers are mocked; the one place real fetchers run (the "no secret leaves" test) feeds them a marker credential
and a provider body that echoes it, then looks for the marker in everything the view returned.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from agent import account_usage, account_usage_view as view
from agent.account_usage import AccountCredits, AccountUsageSnapshot, AccountUsageWindow

# A harmless stand-in shaped like an OAuth token; it is the thing that must never come back out.
MARKER = "sk-ant-oat01-USAGEVIEWMARKER0123456789abcdef"
RESET = datetime(2026, 10, 5, 18, 30, tzinfo=timezone.utc)
FETCHED = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)

ENTRY_KEYS = {"provider", "source", "title", "plan", "available", "unavailable_reason", "fetched_at", "windows",
              "details", "credits"}
WINDOW_KEYS = {"id", "label", "used_percent", "reset_at", "detail"}


@pytest.fixture(autouse=True)
def _fresh_cache():
    view.reset_for_tests()
    yield
    view.reset_for_tests()


def _snap(provider="anthropic", **kw):
    kw.setdefault("source", "test_source")
    return AccountUsageSnapshot(provider=provider, fetched_at=FETCHED, **kw)


# ── shape ───────────────────────────────────────────────────────────────────────────────────────


def test_anthropic_snapshot_becomes_the_wire_entry():
    snapshot = _snap(
        windows=(AccountUsageWindow("Current session", 41.5, RESET), AccountUsageWindow("Current week", 12.0, RESET),
                 AccountUsageWindow("Opus week", None, None, "no data")),
        details=("Extra usage: 3.00 / 20.00 USD",), credits=AccountCredits("USD", 17.0, 20.0),
        raw={"five_hour": {"utilization": 0.415}, "secret": MARKER})
    entry = view.entry_from_snapshot("anthropic", snapshot)
    assert set(entry) == ENTRY_KEYS
    assert entry["available"] is True and entry["unavailable_reason"] is None
    assert entry["fetched_at"] == "2026-10-05T12:00:00Z" and entry["plan"] is None
    assert [w["id"] for w in entry["windows"]] == ["current_session", "current_week", "opus_week"]
    assert all(set(w) == WINDOW_KEYS for w in entry["windows"])
    first = entry["windows"][0]
    assert first["used_percent"] == 41.5 and first["reset_at"] == "2026-10-05T18:30:00Z" and first["detail"] is None
    assert entry["windows"][2]["used_percent"] is None and entry["windows"][2]["detail"] == "no data"
    assert entry["credits"] == {"currency": "USD", "remaining": 17.0, "total": 20.0}
    assert entry["details"] == ["Extra usage: 3.00 / 20.00 USD"]
    assert MARKER not in json.dumps(entry) and "raw" not in entry


def test_codex_openrouter_and_nous_entries():
    codex = view.entry_from_snapshot("openai-codex", _snap(
        "openai-codex", plan="Plus", windows=(AccountUsageWindow("Session", 5.0, RESET), AccountUsageWindow("Weekly", 20.0)),
        details=("You have 1 reset banked - use /usage reset to activate",), credits=AccountCredits("USD", 4.2)))
    assert codex["plan"] == "Plus" and [w["id"] for w in codex["windows"]] == ["session", "weekly"]
    assert codex["credits"] == {"currency": "USD", "remaining": 4.2, "total": None}

    openrouter = view.entry_from_snapshot("openrouter", _snap(
        "openrouter", details=("Credits balance: $7.50",), credits=AccountCredits("USD", 7.5, 10.0),
        windows=(AccountUsageWindow("API key quota", 25.0, None, "$7.50 of $10.00 remaining"),)))
    assert openrouter["windows"][0]["id"] == "api_key_quota" and openrouter["credits"]["total"] == 10.0

    nous = view.entry_from_snapshot("nous", _snap(
        "nous", title="Nous credits", plan="pro", details=("Total usable: $9.00", "Top up: https://portal.example/t?x=1",
                                                          "(or run /topup)"),
        credits=AccountCredits("USD", 9.0)))
    # The text /usage's calls to action are not data about the account.
    assert nous["details"] == ["Total usable: $9.00"] and nous["title"] == "Nous credits" and nous["plan"] == "pro"
    for entry in (codex, openrouter, nous):
        assert set(entry) == ENTRY_KEYS and entry["available"] is True


def test_unavailable_entries_and_value_hygiene():
    assert view.entry_from_snapshot("anthropic", None)["unavailable_reason"] == \
        "Not signed in to this provider in this profile."
    oauth_only = view.entry_from_snapshot("anthropic", _snap(unavailable_reason="OAuth accounts only."))
    assert oauth_only["available"] is False and oauth_only["unavailable_reason"] == "OAuth accounts only."
    assert oauth_only["windows"] == [] and oauth_only["credits"] is None
    empty = view.entry_from_snapshot("anthropic", _snap())
    assert empty["available"] is False and empty["unavailable_reason"]
    odd = view.entry_from_snapshot("anthropic", _snap(
        windows=(AccountUsageWindow("Week", 250.0), AccountUsageWindow("Week", float("nan")),
                 AccountUsageWindow("Week", -5.0))))
    assert [w["used_percent"] for w in odd["windows"]] == [100.0, None, 0.0]
    assert [w["id"] for w in odd["windows"]] == ["week", "week_2", "week_3"]
    naive = view.entry_from_snapshot("anthropic", _snap(windows=(AccountUsageWindow("W", 1.0, datetime(2026, 1, 2, 3, 4, 5)),)))
    assert naive["windows"][0]["reset_at"] == "2026-01-02T03:04:05Z"


# ── no secret leaves ────────────────────────────────────────────────────────────────────────────


def test_credential_shaped_text_is_dropped_whole():
    entry = view.entry_from_snapshot("anthropic", _snap(
        plan=f"Max {MARKER}", unavailable_reason=f"Bearer {MARKER}", title="Authorization: Bearer abcdefghijklmnopqrstuvwx",
        windows=(AccountUsageWindow("Week", 1.0, None, f"token {MARKER}"), AccountUsageWindow(f"Bearer {MARKER}", 2.0),
                 AccountUsageWindow("Opus week", 3.0)),
        details=(f"key={MARKER}", "Extra usage: 1.00 / 2.00 USD")))
    blob = json.dumps(entry)
    assert MARKER not in blob and "abcdefghijklmnopqrstuvwx" not in blob
    # Nothing of the marker survives in another spelling either: the id is not a slug of a dropped label.
    assert "usageviewmarker" not in blob.lower() and "bearer" not in blob.lower()
    assert entry["plan"] is None and entry["windows"][0]["detail"] is None
    assert [(w["id"], w["label"]) for w in entry["windows"]] == [
        ("week", "Week"), ("window_2", "Usage window"), ("opus_week", "Opus week")]
    assert entry["details"] == ["Extra usage: 1.00 / 2.00 USD"] and entry["title"] == "Claude account limits"


def test_a_window_id_never_collides_with_a_dropped_labels_fallback():
    entry = view.entry_from_snapshot("anthropic", _snap(windows=(
        AccountUsageWindow("window_2", 1.0), AccountUsageWindow(f"token={MARKER}", 2.0))))
    assert [w["id"] for w in entry["windows"]] == ["window_2", "window_2_2"]


def test_a_long_run_of_letters_and_digits_is_credential_shaped():
    hex_key = "0123456789abcdef0123456789abcdef"                     # 32 hex, a key in free text
    for text in (f"key {hex_key}", f"Plan {hex_key[:24]}", f"see {hex_key.upper()} here", "Ab1" * 9):
        assert view._safe_text(text) is None, text
    for text in ("Current week", "Opus week", "Current session", "Max 20x", "default_claude_max_20x_plan",
                 "Renews: 2026-11-01", "2026-10-05T18:30:00Z", "Extra usage: 3.00 / 20.00 USD",
                 "Total usable: $9.00", "You have 1 reset banked - use /usage reset to activate",
                 "123456789012345678901234", "Pneumonoultramicroscopicsilico", "$7.50 of $10.00 remaining",
                 "Credits balance: $1234567.89", "abcdefghijklmnopqrstuv1"):
        assert view._safe_text(text) == text, text


def test_a_failed_fetch_is_a_fixed_sentence_never_the_exceptions_text():
    reasons = set()
    for exc in (RuntimeError(f"boom {MARKER}"), httpx.ConnectError(f"https://x.example/?token={MARKER}"),
                httpx.HTTPStatusError(f"401 for {MARKER}", request=httpx.Request("GET", "https://x.example/u"),
                                      response=httpx.Response(401, request=httpx.Request("GET", "https://x.example/u"))),
                httpx.HTTPStatusError("500", request=httpx.Request("GET", "https://x.example/u"),
                                      response=httpx.Response(500, request=httpx.Request("GET", "https://x.example/u")))):
        def fetch(provider, exc=exc):
            raise exc
        entry = view.provider_entry(f"home-{len(reasons)}", "anthropic", fetch=fetch)
        assert entry["available"] is False and MARKER not in json.dumps(entry)
        reasons.add(entry["unavailable_reason"])
    assert reasons == {"Could not read usage from the provider.", "Could not reach the provider.",
                       "The provider rejected this profile's credentials (HTTP 401).", "The provider answered HTTP 500."}


def _mock_http(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.parametrize("provider", ["anthropic", "openai-codex", "openrouter", "nous"])
def test_no_secret_leaves_for_any_provider_with_the_real_fetchers(monkeypatch, provider):
    """The marker is the credential the fetcher sends and also what the provider's body echoes back."""
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization", ""))
        path = request.url.path
        if "oauth/usage" in path:
            return httpx.Response(200, json={
                "five_hour": {"utilization": 0.4, "resets_at": "2026-10-05T18:00:00Z"}, "echo": MARKER,
                "extra_usage": {"is_enabled": True, "used_credits": 1.5, "monthly_limit": 10, "currency": "EUR"}})
        if path.endswith("/credits"):
            return httpx.Response(200, json={"data": {"total_credits": 10, "total_usage": 2.5}, "echo": MARKER})
        if path.endswith("/key"):
            return httpx.Response(200, json={"data": {"limit": 20, "limit_remaining": 15, "usage": 5, "echo": MARKER}})
        return httpx.Response(200, json={
            "plan_type": "plus", "echo": MARKER, "rate_limit": {"primary_window": {"used_percent": 30, "reset_at": 1790000000,
                                                                                   "limit_window_seconds": 18000}},
            "credits": {"has_credits": True, "balance": 3.5}})

    _mock_http(monkeypatch, handler)
    monkeypatch.setattr(account_usage, "resolve_anthropic_token", lambda: MARKER)
    monkeypatch.setattr(account_usage, "_resolve_codex_usage_credentials",
                        lambda *a, **k: (MARKER, "https://chatgpt.example/backend-api/codex", MARKER))
    monkeypatch.setattr(account_usage, "resolve_runtime_provider",
                        lambda **k: {"api_key": MARKER, "base_url": "https://openrouter.example/api/v1"})
    monkeypatch.setattr(account_usage, "_nous_logged_in", lambda: True)
    account = SimpleNamespace(
        logged_in=True, email=f"{MARKER}@example.com", paid_service_access=True,
        paid_service_access_info=SimpleNamespace(subscription_credits_remaining=4.0, purchased_credits_remaining=5.0,
                                                 total_usable_credits=9.0),
        subscription=SimpleNamespace(monthly_credits=10.0, credits_remaining=4.0, rollover_credits=0,
                                     current_period_end="2026-11-01", plan="pro"))
    monkeypatch.setattr(account_usage, "_fetch_portal_account", lambda timeout: account)
    import hermes_cli.nous_account as nous_account
    monkeypatch.setattr(nous_account, "nous_portal_topup_url", lambda info: f"https://portal.example/topup?token={MARKER}")

    entry = view.provider_entry("home", provider)
    blob = json.dumps(entry)
    assert entry["available"] is True, entry
    assert set(entry) == ENTRY_KEYS and all(set(w) == WINDOW_KEYS for w in entry["windows"])
    assert MARKER not in blob and "Bearer" not in blob and "token" not in blob.lower().replace("tokens", "")
    assert entry["credits"] is not None and entry["credits"]["remaining"] > 0
    if provider != "nous":
        assert any(MARKER in header for header in seen_auth)  # the fetch really carried it; none of it came back


# ── which providers ─────────────────────────────────────────────────────────────────────────────


def test_configured_providers_follow_the_model_then_the_fallback_chain(monkeypatch):
    monkeypatch.setattr(account_usage, "usage_supported", lambda name: name != "unsupported-one")
    cfg = {"model": {"provider": "claude", "default": "m"},
           "fallback_providers": [{"provider": "openrouter", "model": "a"}, {"provider": "custom:mine", "model": "b"},
                                  {"provider": "unsupported-one", "model": "c"}, {"provider": "anthropic", "model": "d"},
                                  {"provider": "nous", "model": "e"}],
           "fallback_model": {"provider": "openai-codex", "model": "f"}}
    assert view.configured_providers(cfg) == ["anthropic", "openrouter", "nous", "openai-codex"]
    assert view.configured_providers({"model": {"provider": "custom"}}) == []
    monkeypatch.setattr(view, "_resolve_auto", lambda: "")
    assert view.configured_providers({}) == []


def test_auto_provider_resolves_from_credentials(monkeypatch):
    monkeypatch.setattr(view, "_resolve_auto", lambda: "nous")
    monkeypatch.setattr(account_usage, "usage_supported", lambda name: True)
    assert view.configured_providers({"model": {"provider": "auto"}}) == ["nous"]
    assert view.configured_providers({"model": "just-a-model-name"}) == ["nous"]


def test_usage_supported_knows_the_built_in_sources():
    assert all(account_usage.usage_supported(name) for name in ("anthropic", "openai-codex", "openrouter", "nous"))
    assert not account_usage.usage_supported("") and not account_usage.usage_supported("no-such-provider-xyz")


# ── cache, refresh floor, single flight ─────────────────────────────────────────────────────────


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = _Clock()
    monkeypatch.setattr(view, "time", fake)
    return fake


def _counting_fetch(calls: list):
    def fetch(provider):
        calls.append(provider)
        return _snap(provider, windows=(AccountUsageWindow("Week", float(len(calls))),))
    return fetch


def test_entries_are_cached_for_a_minute_per_profile_and_provider(clock):
    calls: list = []
    fetch = _counting_fetch(calls)
    first = view.provider_entry("home-a", "anthropic", fetch=fetch)
    clock.now += 59
    again = view.provider_entry("home-a", "anthropic", fetch=fetch)
    assert len(calls) == 1 and again == first
    again["windows"].clear()  # a caller cannot damage the cache
    assert view.provider_entry("home-a", "anthropic", fetch=fetch) == first
    view.provider_entry("home-b", "anthropic", fetch=fetch)       # another profile: its own entry
    view.provider_entry("home-a", "openrouter", fetch=fetch)      # another provider: its own entry
    assert len(calls) == 3
    clock.now += 2                                                 # past 60 s since the first fetch
    view.provider_entry("home-a", "anthropic", fetch=fetch)
    assert len(calls) == 4


def test_refresh_bypasses_the_cache_at_most_once_per_fifteen_seconds(clock):
    calls: list = []
    fetch = _counting_fetch(calls)
    view.provider_entry("home", "anthropic", fetch=fetch)
    clock.now += 5
    view.provider_entry("home", "anthropic", refresh=True, fetch=fetch)   # inside the floor: served from cache
    assert len(calls) == 1
    clock.now += 11                                                        # 16 s after the fetch
    entry = view.provider_entry("home", "anthropic", refresh=True, fetch=fetch)
    assert len(calls) == 2 and entry["windows"][0]["used_percent"] == 2.0
    clock.now += 1
    for _ in range(5):                                                     # a refresh storm is one fetch at most
        view.provider_entry("home", "anthropic", refresh=True, fetch=fetch)
    assert len(calls) == 2
    clock.now += 15
    view.provider_entry("home", "anthropic", refresh=True, fetch=fetch)
    assert len(calls) == 3


def test_a_failed_fetch_is_remembered_briefly(clock):
    calls: list = []

    def fetch(provider):
        calls.append(provider)
        raise RuntimeError("down")
    view.provider_entry("home", "anthropic", fetch=fetch)
    clock.now += 14
    assert view.provider_entry("home", "anthropic", fetch=fetch)["available"] is False and len(calls) == 1
    clock.now += 2
    view.provider_entry("home", "anthropic", fetch=fetch)
    assert len(calls) == 2


def test_concurrent_callers_for_one_pair_share_one_fetch():
    calls: list = []

    def slow(provider):
        calls.append(provider)
        time.sleep(0.3)
        return _snap(provider, windows=(AccountUsageWindow("Week", 1.0),))
    results: list = []
    threads = [threading.Thread(target=lambda: results.append(view.provider_entry("home", "anthropic", fetch=slow)))
               for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(calls) == 1 and len(results) == 6 and all(r == results[0] for r in results)


def _blocked_fetch(entered: threading.Event, release: threading.Event, calls: list):
    def fetch(provider):
        calls.append(provider)
        entered.set()
        release.wait(10)
        return _snap(provider, windows=(AccountUsageWindow("Week", 99.0),))
    return fetch


def test_a_caller_behind_a_running_fetch_gets_the_stale_entry_at_once(clock):
    """The pair is being refetched (expired, so a fetch is running and holds the pair's lock): a second caller
    answers from the entry it has instead of holding an RPC worker until the fetch ends."""
    calls: list = []
    stale = view.provider_entry("home", "anthropic", fetch=_counting_fetch(calls))
    clock.now += 61
    entered, release = threading.Event(), threading.Event()
    fetching = threading.Thread(target=view.provider_entry, args=("home", "anthropic"),
                                kwargs={"fetch": _blocked_fetch(entered, release, calls)})
    fetching.start()
    try:
        assert entered.wait(5)
        started = time.monotonic()
        waiter = view.provider_entry("home", "anthropic", fetch=_counting_fetch(calls))
        assert time.monotonic() - started < 0.5 and waiter == stale and len(calls) == 2
    finally:
        release.set()
        fetching.join(5)
    assert view.provider_entry("home", "anthropic", fetch=_counting_fetch(calls))["windows"][0]["used_percent"] == 99.0


def test_a_caller_with_nothing_cached_waits_briefly_then_hears_it_is_refreshing(monkeypatch):
    monkeypatch.setattr(view, "WAITER_TIMEOUT_S", 0.2)
    calls: list = []
    entered, release = threading.Event(), threading.Event()
    fetching = threading.Thread(target=view.provider_entry, args=("home", "nous"),
                                kwargs={"fetch": _blocked_fetch(entered, release, calls)})
    fetching.start()
    try:
        assert entered.wait(5)
        started = time.monotonic()
        waiter = view.provider_entry("home", "nous", fetch=_counting_fetch(calls))
        assert time.monotonic() - started < 2 and len(calls) == 1
    finally:
        release.set()
        fetching.join(5)
    assert set(waiter) == ENTRY_KEYS and waiter["available"] is False and waiter["provider"] == "nous"
    assert waiter["unavailable_reason"] == view.REFRESHING_REASON
    # Not remembered: the next caller gets the real entry the running fetch stored.
    assert view.provider_entry("home", "nous", fetch=_counting_fetch(calls))["available"] is True and len(calls) == 1


def test_a_hung_fetch_is_abandoned_through_the_real_bound(monkeypatch):
    """The real ``run_bounded_sync``: the hung worker is left behind, the caller gets the timeout entry, the pair is
    free again at once, a caller in the meantime is not held for the whole bound, and the abandoned worker's late
    answer never lands in the cache."""
    from agent import deadline

    bounded: list[str] = []
    real_bound = deadline.run_bounded_sync

    def spy(fn, timeout, **kw):                 # passes straight through: only proves the real bound is the one used
        bounded.append(kw.get("label", ""))
        return real_bound(fn, timeout, **kw)
    monkeypatch.setattr(deadline, "run_bounded_sync", spy)
    monkeypatch.setattr(view, "PROVIDER_TIMEOUT_S", 0.5)
    monkeypatch.setattr(view, "WAITER_TIMEOUT_S", 0.1)
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    def hung(provider):
        entered.set()
        release.wait(10)
        returned.set()
        return _snap(provider, windows=(AccountUsageWindow("Week", 77.0),))
    results: dict = {}
    first = threading.Thread(target=lambda: results.setdefault("first", view.provider_entry("home", "openrouter", fetch=hung)))
    first.start()
    try:
        assert entered.wait(5)
        started = time.monotonic()
        results["waiter"] = view.provider_entry("home", "openrouter", fetch=hung)
        assert time.monotonic() - started < 0.4                        # the waiter did not sit out the bound
        first.join(5)
        assert not first.is_alive()
        assert results["first"]["unavailable_reason"] == "The provider did not answer within 0.5 seconds."
        assert results["waiter"]["unavailable_reason"] == view.REFRESHING_REASON
        started = time.monotonic()
        again = view.provider_entry("home", "openrouter", fetch=lambda p: pytest.fail("refetched inside the failure TTL"))
        assert time.monotonic() - started < 0.2 and again == results["first"]   # the lock was released
    finally:
        release.set()
    assert returned.wait(5)
    time.sleep(0.05)
    assert view._read(("home", "openrouter")).entry == results["first"]        # the late answer was dropped
    assert bounded == ["account-usage-openrouter"]


# ── timeout, parallelism ────────────────────────────────────────────────────────────────────────


def test_a_fetch_past_the_bound_is_unavailable_with_a_reason(monkeypatch):
    monkeypatch.setattr(view, "PROVIDER_TIMEOUT_S", 0.2)
    release = threading.Event()

    def hung(provider):
        release.wait(10)
        return _snap(provider, windows=(AccountUsageWindow("Week", 1.0),))
    started = time.monotonic()
    try:
        entry = view.provider_entry("home", "openai-codex", fetch=hung)
    finally:
        release.set()
    assert time.monotonic() - started < 3
    assert entry["available"] is False and entry["provider"] == "openai-codex"
    assert entry["unavailable_reason"] == "The provider did not answer within 0.2 seconds."
    assert entry["windows"] == [] and set(entry) == ENTRY_KEYS


def test_providers_are_fetched_side_by_side(monkeypatch):
    def slow(provider):
        time.sleep(0.4)
        return _snap(provider, windows=(AccountUsageWindow("Week", 1.0),))
    started = time.monotonic()
    entries = view.collect("home", ["anthropic", "openai-codex", "openrouter"], fetch=slow)
    assert time.monotonic() - started < 1.0
    assert [e["provider"] for e in entries] == ["anthropic", "openai-codex", "openrouter"]
    assert view.collect("home", []) == []


def test_one_provider_failing_does_not_take_the_others_with_it():
    def fetch(provider):
        if provider == "openrouter":
            raise RuntimeError("nope")
        return _snap(provider, windows=(AccountUsageWindow("Week", 1.0),))
    entries = {e["provider"]: e for e in view.collect("home", ["anthropic", "openrouter"], fetch=fetch)}
    assert entries["anthropic"]["available"] is True and entries["openrouter"]["available"] is False
