"""``tui_gateway.request_limits.Limiter``: open-slot cap and send window per key, with the clock passed in."""

from __future__ import annotations

from tui_gateway.request_limits import ALREADY_PENDING, RATE_LIMITED, Limiter


def test_pending_cap_refuses_a_second_open_request_until_release():
    limiter = Limiter(max_pending=1, max_per_window=5, window_seconds=100.0)
    assert limiter.reserve("k", 0.0) == ""
    assert limiter.reserve("k", 1.0) == ALREADY_PENDING
    limiter.release("k", sent_at=1.0)
    assert limiter.reserve("k", 2.0) == ""


def test_pending_cap_above_one():
    limiter = Limiter(max_pending=2, max_per_window=10, window_seconds=100.0)
    assert limiter.reserve("k", 0.0) == ""
    assert limiter.reserve("k", 0.0) == ""
    assert limiter.reserve("k", 0.0) == ALREADY_PENDING


def test_window_limits_sent_requests_and_expires_with_the_injected_clock():
    limiter = Limiter(max_pending=1, max_per_window=2, window_seconds=100.0)
    for at in (0.0, 10.0):
        assert limiter.reserve("k", at) == ""
        limiter.release("k", sent_at=at)
    assert limiter.reserve("k", 50.0) == RATE_LIMITED
    # The oldest send leaves the window at 100 (a send exactly one window old no longer counts).
    assert limiter.reserve("k", 99.9) == RATE_LIMITED
    assert limiter.reserve("k", 100.0) == ""
    limiter.release("k", sent_at=100.0)
    assert limiter.reserve("k", 105.0) == RATE_LIMITED  # sends at 10 and 100 count
    assert limiter.reserve("k", 110.0) == ""  # 10 expired


def test_pending_is_checked_before_the_window():
    limiter = Limiter(max_pending=1, max_per_window=1, window_seconds=100.0)
    assert limiter.reserve("k", 0.0) == ""
    limiter.release("k", sent_at=0.0)
    assert limiter.reserve("k", 1.0) == RATE_LIMITED
    limiter2 = Limiter(max_pending=1, max_per_window=1, window_seconds=100.0)
    limiter2.release("k", sent_at=0.0)  # history without a pending slot
    assert limiter2.reserve("k", 1.0) == RATE_LIMITED
    assert limiter2.reserve("other", 1.0) == ""
    assert limiter2.reserve("other", 1.0) == ALREADY_PENDING


def test_release_without_sending_does_not_charge_the_window():
    limiter = Limiter(max_pending=1, max_per_window=1, window_seconds=100.0)
    for _ in range(5):
        assert limiter.reserve("k", 0.0) == ""
        limiter.release("k", sent_at=None)
    assert not limiter.sent and not limiter.pending


def test_keys_are_independent():
    limiter = Limiter(max_pending=1, max_per_window=1, window_seconds=100.0)
    assert limiter.reserve("a", 0.0) == ""
    assert limiter.reserve("b", 0.0) == ""
    assert limiter.reserve("a", 0.0) == ALREADY_PENDING
    limiter.release("a", sent_at=0.0)
    assert limiter.reserve("a", 1.0) == RATE_LIMITED
    assert limiter.reserve("c", 1.0) == ""
    limiter.release("b", sent_at=None)
    assert limiter.reserve("b", 1.0) == ""


def test_refusal_takes_no_slot_and_expired_history_is_dropped():
    limiter = Limiter(max_pending=1, max_per_window=1, window_seconds=10.0)
    assert limiter.reserve("k", 0.0) == ""
    assert limiter.reserve("k", 0.0) == ALREADY_PENDING
    limiter.release("k", sent_at=0.0)
    assert limiter.pending == {}
    assert limiter.reserve("k", 20.0) == ""
    assert "k" not in limiter.sent or not limiter.sent["k"]


def test_reset_forgets_every_key():
    limiter = Limiter(max_pending=1, max_per_window=1, window_seconds=100.0)
    limiter.reserve("a", 0.0)
    limiter.release("a", sent_at=0.0)
    limiter.reserve("b", 0.0)
    limiter.reset()
    assert limiter.reserve("a", 1.0) == ""
    assert limiter.reserve("b", 1.0) == ""
