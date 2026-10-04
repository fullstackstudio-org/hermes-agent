"""The review register (``tui_gateway/review_register.py``): the approved text of a reviewed draft, kept in memory by
the gateway under a ``draft_id`` for one conversation. Pinned: the entry's id and hash, the time-to-live, the cap per
conversation (the oldest goes first), the cap on conversations, isolation between conversations, ``clear``, and that
nothing is ever written anywhere.
"""

from __future__ import annotations

import hashlib

import pytest

from tui_gateway import review_register as register


@pytest.fixture(autouse=True)
def clean():
    register.reset_for_tests()
    yield
    register.reset_for_tests()


def test_put_returns_an_entry_with_an_id_and_the_hash_of_the_text():
    entry = register.put("key-a", "Hello é Bram", edited=True, now=10.0)
    assert entry.draft_id.startswith("drf-") and len(entry.draft_id) == 16
    assert int(entry.draft_id[4:], 16) >= 0
    assert entry.sha256 == hashlib.sha256("Hello é Bram".encode()).hexdigest()
    assert entry.text == "Hello é Bram" and entry.edited is True
    assert register.get("key-a", entry.draft_id, now=11.0) == entry
    assert register.put("key-a", "Hello é Bram", now=12.0).draft_id != entry.draft_id


def test_an_entry_lives_for_the_ttl_and_not_a_moment_longer():
    entry = register.put("key-a", "text", now=100.0)
    assert register.get("key-a", entry.draft_id, now=100.0 + register.TTL_SECONDS - 0.001) is not None
    assert register.get("key-a", entry.draft_id, now=100.0 + register.TTL_SECONDS) is None
    assert register.count("key-a", now=100.0 + register.TTL_SECONDS) == 0
    assert register.TTL_SECONDS == 3_600


def test_a_put_drops_the_expired_entries_of_that_conversation():
    old = register.put("key-a", "old", now=0.0)
    fresh = register.put("key-a", "fresh", now=register.TTL_SECONDS + 5)
    assert register.get("key-a", old.draft_id, now=register.TTL_SECONDS + 6) is None
    assert register.get("key-a", fresh.draft_id, now=register.TTL_SECONDS + 6) is not None
    assert register.count("key-a", now=register.TTL_SECONDS + 6) == 1


def test_at_most_twenty_per_conversation_the_oldest_goes_first():
    entries = [register.put("key-a", f"draft {i}", now=float(i)) for i in range(register.MAX_PER_KEY + 5)]
    assert register.MAX_PER_KEY == 20 and register.count("key-a", now=100.0) == 20
    assert all(register.get("key-a", e.draft_id, now=100.0) is None for e in entries[:5])
    assert all(register.get("key-a", e.draft_id, now=100.0) is not None for e in entries[5:])


def test_conversations_are_isolated():
    mine = register.put("key-a", "mine", now=0.0)
    assert register.get("key-b", mine.draft_id, now=1.0) is None
    assert register.get("key-a", mine.draft_id, now=1.0) is not None
    register.clear("key-b")
    assert register.get("key-a", mine.draft_id, now=1.0) is not None


def test_clear_forgets_a_conversation_and_tolerates_nothing_to_clear():
    entry = register.put("key-a", "text", now=0.0)
    register.clear("key-a")
    assert register.get("key-a", entry.draft_id, now=1.0) is None
    register.clear("key-a")
    register.clear(None)
    register.clear("")


def test_an_unknown_or_malformed_id_finds_nothing():
    register.put("key-a", "text", now=0.0)
    for draft_id in ("", "drf-000000000000", "nope", "drf-"):
        assert register.get("key-a", draft_id, now=1.0) is None


def test_the_number_of_conversations_is_bounded_and_the_idlest_goes():
    for i in range(register.MAX_KEYS + 3):
        register.put(f"key-{i}", "text", now=float(i))
    assert register.count("key-0", now=1_000.0) == 0 and register.count("key-2", now=1_000.0) == 0
    assert register.count(f"key-{register.MAX_KEYS + 2}", now=1_000.0) == 1
    # a conversation that was just used outlives idle ones
    register.put("key-3", "again", now=1_001.0)
    register.put("another", "text", now=1_002.0)
    assert register.count("key-3", now=1_003.0) == 2


def test_the_register_is_memory_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = sorted(p.name for p in tmp_path.rglob("*"))
    register.put("key-a", "PRIVATE-DRAFT-MARKER", now=0.0)
    assert sorted(p.name for p in tmp_path.rglob("*")) == before
