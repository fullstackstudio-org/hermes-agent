"""Tests for the WS-upgrade ticket store (Phase 5 task 5.1).

The store is process-local and threading-safe. Tests run with xdist so
each worker has its own module instance — no cross-worker bleed — but we
call ``_reset_for_tests`` between tests to keep things deterministic.
"""

from __future__ import annotations

import threading

import pytest

from hermes_cli.dashboard_auth import ws_tickets
from hermes_cli.dashboard_auth.ws_tickets import (
    TTL_SECONDS,
    TicketInvalid,
    _reset_for_tests,
    consume_ticket,
    mint_ticket,
)


@pytest.fixture(autouse=True)
def _reset():
    _reset_for_tests()
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestMintAndConsume:
    def test_round_trip(self):
        ticket = mint_ticket(user_id="u1", provider="nous")
        info = consume_ticket(ticket)
        assert info["user_id"] == "u1"
        assert info["provider"] == "nous"
        assert "minted_at" in info

    def test_extra_cannot_override_the_minted_identity(self):
        """``extra`` is server-chosen context riding along; the identity the mint was asked for is the
        identity the ticket carries, whatever ``extra`` names (HERM-127)."""
        ticket = mint_ticket(
            user_id="u1", provider="stub", user_name="Sam", profile={"email": "sam@example.org"},
            extra={"user_id": "marker-other", "provider": "marker-provider", "user_name": "marker-name",
                   "minted_at": 0, "profile": {"email": "marker@example.org"}, "viewer_id": "v1"})
        info = consume_ticket(ticket)
        assert (info["user_id"], info["provider"], info["user_name"]) == ("u1", "stub", "Sam")
        assert info["minted_at"] > 0 and info["profile"] == {"email": "sam@example.org"}
        assert info["viewer_id"] == "v1"  # genuine extra context still rides along

    def test_extra_cannot_supply_a_profile_the_mint_did_not(self):
        info = consume_ticket(mint_ticket(user_id="u1", provider="stub", extra={"profile": {"email": "x@y.z"}}))
        assert "profile" not in info

    def test_ticket_has_minimum_length(self):
        # ``secrets.token_urlsafe(32)`` produces ~43 chars; enforce a floor
        # so a future refactor can't accidentally shrink the entropy.
        ticket = mint_ticket(user_id="u1", provider="nous")
        assert len(ticket) >= 32


# ---------------------------------------------------------------------------
# Single-use
# ---------------------------------------------------------------------------


class TestSingleUse:
    def test_second_consume_raises(self):
        ticket = mint_ticket(user_id="u1", provider="stub")
        consume_ticket(ticket)
        with pytest.raises(TicketInvalid, match="unknown"):
            consume_ticket(ticket)

    def test_unknown_ticket_rejected(self):
        with pytest.raises(TicketInvalid, match="unknown"):
            consume_ticket("nope-never-minted")


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------


class TestTTL:

    def test_expired_ticket_rejected(self, monkeypatch):
        # Mock time inside the ws_tickets module so mint and consume see
        # different clocks. We have to patch the symbol the module actually
        # binds; ``time`` is module-level there.
        clock = {"now": 1_000_000}

        def fake_time():
            return clock["now"]

        monkeypatch.setattr(ws_tickets.time, "time", fake_time)

        ticket = mint_ticket(user_id="u1", provider="stub")
        clock["now"] += TTL_SECONDS + 1
        with pytest.raises(TicketInvalid, match="expired"):
            consume_ticket(ticket)


# ---------------------------------------------------------------------------
# Truncated value in error message (secret hygiene)
# ---------------------------------------------------------------------------


class TestErrorMessages:
    def test_unknown_ticket_error_truncates_value(self):
        long_value = "a" * 100
        with pytest.raises(TicketInvalid) as exc_info:
            consume_ticket(long_value)
        # Never log more than the first 8 chars of an opaque ticket.
        message = str(exc_info.value)
        assert long_value not in message
        assert long_value[:8] in message


# ---------------------------------------------------------------------------
# Thread safety: mint + consume from many threads doesn't deadlock or
# return duplicates.
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_mint_and_consume_concurrent(self):
        results: list[dict] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def worker(i: int):
            try:
                t = mint_ticket(user_id=f"u{i}", provider="stub")
                info = consume_ticket(t)
                with lock:
                    results.append(info)
            except Exception as exc:  # noqa: BLE001 — collect for assert
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), "thread deadlocked"

        assert errors == []
        assert len(results) == 20
        # Every consume returns a distinct user_id (no cross-thread bleed).
        assert {r["user_id"] for r in results} == {f"u{i}" for i in range(20)}


# ---------------------------------------------------------------------------
# Per-PTY credentials (the Chat tab's terminal child). There is no process-wide credential.
# ---------------------------------------------------------------------------


class TestPtyCredential:

    def test_no_process_wide_credential_exists(self):
        assert not hasattr(ws_tickets, "internal_ws_credential")
        assert not hasattr(ws_tickets, "consume_internal_credential")

    def test_mint_consume_revoke(self):
        cred = ws_tickets.mint_pty_credential(user_id="u1", provider="nous")
        assert ws_tickets.consume_pty_credential(cred) == {"user_id": "u1", "provider": "nous"}
        assert ws_tickets.consume_pty_credential(cred)["user_id"] == "u1"  # multi-use for that terminal
        ws_tickets.revoke_pty_credential(cred)
        with pytest.raises(TicketInvalid):
            ws_tickets.consume_pty_credential(cred)

    def test_revoke_closes_every_socket_still_open_with_it(self):
        cred = ws_tickets.mint_pty_credential(user_id="u1", provider="nous")
        closed: list[str] = []
        assert ws_tickets.track_pty_socket(cred, lambda: closed.append("ws"))
        assert ws_tickets.track_pty_socket(cred, lambda: closed.append("pub"))
        ws_tickets.revoke_pty_credential(cred)
        assert sorted(closed) == ["pub", "ws"]
        # A socket that opens after the revoke is refused at once.
        assert ws_tickets.track_pty_socket(cred, lambda: closed.append("late")) is False

    def test_independent_of_ticket_store(self):
        cred = ws_tickets.mint_pty_credential(user_id="u2", provider="nous")
        ticket = mint_ticket(user_id="u1", provider="nous")
        ws_tickets.consume_pty_credential(cred)
        assert consume_ticket(ticket)["user_id"] == "u1"
