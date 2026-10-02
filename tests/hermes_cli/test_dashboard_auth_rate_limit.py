"""The per-address throttle behind password login and native revoke keeps its memory bounded."""
from __future__ import annotations

from hermes_cli.dashboard_auth import rate_limit
from hermes_cli.dashboard_auth.rate_limit import SlidingWindowLimiter, Verdict


def test_a_bucket_is_dropped_once_its_window_has_passed(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: now[0])
    limiter = SlidingWindowLimiter(2, 60.0)

    for i in range(500):  # one spoofed-looking key each
        assert limiter.check(f"10.0.{i // 250}.{i % 250}") is Verdict.ALLOWED
    assert len(limiter) == 500
    now[0] += 61.0
    assert limiter.check("192.0.2.1") is Verdict.ALLOWED

    assert len(limiter) == 1


def test_the_table_is_capped_and_the_least_recently_active_key_goes_first():
    limiter = SlidingWindowLimiter(1, 60.0, max_keys=3)
    for key in ("a", "b", "c"):
        limiter.check(key)
    assert limiter.check("a") is Verdict.REFUSED  # full, and stays: a refusal records nothing

    limiter.check("d")

    assert len(limiter) == 3
    assert limiter.check("a") is Verdict.ALLOWED  # evicted, so it starts again
    assert limiter.check("c") is Verdict.REFUSED


def test_a_key_is_told_it_was_refused_once_per_window(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: now[0])
    limiter = SlidingWindowLimiter(1, 60.0)
    limiter.check("k")

    verdicts = [limiter.check("k") for _ in range(3)]
    now[0] += 61.0
    later = [limiter.check("k"), limiter.check("k")]

    assert verdicts == [Verdict.REFUSED, Verdict.REFUSED_AGAIN, Verdict.REFUSED_AGAIN]
    assert later == [Verdict.ALLOWED, Verdict.REFUSED]
