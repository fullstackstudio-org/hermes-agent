"""The MCP grant registry: files, clients, consents, codes, grants, token rotation and reuse detection,
the per-person cap, chats, pruning, and the rules that must hold across connections."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from hermes_cli.dashboard_auth.mcp import store as store_mod
from hermes_cli.dashboard_auth.mcp.store import (
    BY_CLIENT, BY_CODE_REUSE, BY_REFRESH_REUSE, CHAT_IDLE_KEEP, CLIENT_UNUSED_TTL, CODE_TTL, CONSENT_TTL,
    CONSENTS_PER_ADDRESS, GRANT_KEEP_AFTER_END, LAST_USED_EVERY, METADATA_MAX_BYTES, OPERATOR,
    REFRESH_RACE_GRACE,
    TOKEN_KEEP_AFTER_EXPIRY, CodeInvalid, ConsentInvalid, LimitReached, MCPStore, Raced, Reused, StoreError,
    TokenInvalid, hash_secret)

ALICE = "self_hosted:alice"
BOB = "self_hosted:bob"
RESOURCE = "https://gw.example.invalid/mcp"
SCOPES = ["bots:read", "bots:prompt", "requests:read", "requests:clarify"]
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
TTL = dict(access_ttl=3600, refresh_ttl=30 * 86400)


class Clock:
    def __init__(self, t: float = 1_790_000_000):
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path, clock) -> MCPStore:
    return MCPStore(tmp_path / "dashboard_auth" / "mcp.db", clock=clock)


def _client(store: MCPStore, client_id: str = "client-1", *, secret: str | None = "s3cret-marker",
            ip: str = "203.0.113.5", name: str = "Example Agent") -> None:
    store.add_client(client_id=client_id, client_secret=secret, client_name=name,
                     redirect_uris=["http://127.0.0.1:33418/callback"],
                     token_endpoint_auth_method="client_secret_post" if secret else "none",
                     metadata={"client_name": name, "redirect_uris": ["http://127.0.0.1:33418/callback"]},
                     created_ip=ip)


def _params(**over) -> dict:
    p = {"scopes": SCOPES, "code_challenge": CHALLENGE, "redirect_uri": "http://127.0.0.1:33418/callback",
         "redirect_uri_provided_explicitly": True, "resource": RESOURCE, "state": "st-1"}
    p.update(over)
    return p


def _code(store: MCPStore, client_id: str = "client-1", user: str = ALICE, *, max_grants: int = 5,
          ip: str = "203.0.113.5") -> str:
    consent = store.open_consent(client_id=client_id, params=_params(), created_ip=ip)
    code, _ = store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=user, user_name="Alice",
                               provider="self_hosted", max_grants=max_grants)
    return code


def _grant(store: MCPStore, client_id: str = "client-1", user: str = ALICE, *, max_grants: int = 5):
    code = _code(store, client_id, user, max_grants=max_grants)
    taken = store.take_code(code, client_id=client_id)
    assert taken is not None
    return store.exchange_code(code=code, grant_id=taken.grant_id, client_id=client_id, grant_max_age=90 * 86400,
                               max_grants=max_grants, created_ip="198.51.100.7", created_user_agent="agent/1.0",
                               **TTL)


# ── files ──────────────────────────────────────────────────────────────────────────────────────────


def test_file_and_directory_modes_and_wal(store):
    _client(store)
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(store.path.parent).st_mode) == 0o700
    db = sqlite3.connect(store.path)
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "1"
    for side in ("-wal", "-shm"):
        p = store.path.with_name(store.path.name + side)
        if p.exists():
            assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_existing_file_with_loose_mode_is_tightened(tmp_path, clock):
    path = tmp_path / "dashboard_auth" / "mcp.db"
    path.parent.mkdir(mode=0o755)
    path.touch(mode=0o644)
    MCPStore(path, clock=clock).counts()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_symlink_and_non_file_are_store_errors(tmp_path, clock):
    target = tmp_path / "elsewhere.db"
    target.touch()
    link = tmp_path / "a" / "mcp.db"
    link.parent.mkdir()
    link.symlink_to(target)
    with pytest.raises(StoreError):
        MCPStore(link, clock=clock).counts()
    directory = tmp_path / "b" / "mcp.db"
    directory.mkdir(parents=True)
    with pytest.raises(StoreError):
        MCPStore(directory, clock=clock).counts()


def test_garbage_file_and_newer_schema_are_store_errors(tmp_path, clock):
    junk = tmp_path / "j" / "mcp.db"
    junk.parent.mkdir()
    junk.write_bytes(b"not a database, just a harmless marker" * 100)
    with pytest.raises(StoreError):
        MCPStore(junk, clock=clock).counts()
    newer = tmp_path / "n" / "mcp.db"
    MCPStore(newer, clock=clock).counts()
    db = sqlite3.connect(newer)
    db.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    db.commit()
    db.close()
    with pytest.raises(StoreError, match="schema 2"):
        MCPStore(newer, clock=clock).counts()


def test_removed_file_is_recreated_with_modes(store):
    _client(store)
    store.path.unlink()
    assert store.counts()["clients"] == 0
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600


# ── clients ────────────────────────────────────────────────────────────────────────────────────────


def test_client_secret_is_stored_as_hash_only(store):
    _client(store, secret="client-secret-marker-123")
    record = store.client("client-1")
    assert record is not None and record.client_secret_hash == hash_secret("client-secret-marker-123")
    assert store.client_secret_matches("client-1", "client-secret-marker-123")
    assert not store.client_secret_matches("client-1", "wrong")
    assert not store.client_secret_matches("client-1", "")
    assert not store.client_secret_matches("nobody", "client-secret-marker-123")
    assert b"client-secret-marker-123" not in store.path.read_bytes()


def test_public_client_has_no_secret(store):
    _client(store, secret=None)
    record = store.client("client-1")
    assert record is not None and record.client_secret_hash is None
    assert not store.client_secret_matches("client-1", "anything")


def test_metadata_over_8_kib_refused(store):
    with pytest.raises(ValueError):
        store.add_client(client_id="big", client_secret=None, client_name="x", redirect_uris=[],
                         token_endpoint_auth_method="none", metadata={"pad": "x" * METADATA_MAX_BYTES})
    assert store.client("big") is None


def test_client_cap_prunes_unused_then_refuses(store, clock, monkeypatch):
    monkeypatch.setattr(store_mod, "CLIENTS_MAX", 3)
    for i in range(3):
        _client(store, f"c{i}")
    with pytest.raises(LimitReached) as refused:
        _client(store, "c3")
    assert refused.value.reason == "clients_full"
    clock.t += CLIENT_UNUSED_TTL + 1  # the three never got a grant: dropped to make room
    _client(store, "c3")
    assert store.client("c0") is None and store.client("c3") is not None


def test_client_with_a_grant_is_never_pruned_for_room(store, clock, monkeypatch):
    monkeypatch.setattr(store_mod, "CLIENTS_MAX", 1)
    _client(store, "c0")
    _grant(store, "c0")
    clock.t += CLIENT_UNUSED_TTL + 1
    with pytest.raises(LimitReached):
        _client(store, "c1")


# ── consents ───────────────────────────────────────────────────────────────────────────────────────


def test_consent_opens_and_is_taken_once_with_its_nonce(store):
    _client(store)
    consent = store.open_consent(client_id="client-1", params=_params(), created_ip="203.0.113.5")
    assert store.consent(consent.txn_id) == consent
    with pytest.raises(ConsentInvalid):
        store.issue_code(txn_id=consent.txn_id, nonce="wrong", user_id=ALICE, user_name="", provider="p",
                         max_grants=5)
    assert store.consent(consent.txn_id) is not None  # a wrong nonce does not burn it
    code, taken = store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=ALICE, user_name="Alice",
                                   provider="self_hosted", max_grants=5)
    assert code and taken.txn_id == consent.txn_id
    assert store.consent(consent.txn_id) is None
    with pytest.raises(ConsentInvalid):
        store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=ALICE, user_name="", provider="p",
                         max_grants=5)
    with pytest.raises(ConsentInvalid):
        store.deny_consent(txn_id=consent.txn_id, nonce=consent.nonce)


def test_consent_expires(store, clock):
    _client(store)
    consent = store.open_consent(client_id="client-1", params=_params())
    clock.t += CONSENT_TTL
    assert store.consent(consent.txn_id) is None
    with pytest.raises(ConsentInvalid):
        store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=ALICE, user_name="", provider="p",
                         max_grants=5)


def test_consent_needs_a_known_client_and_an_identity(store):
    with pytest.raises(ConsentInvalid):
        store.open_consent(client_id="nobody", params=_params())
    _client(store)
    consent = store.open_consent(client_id="client-1", params=_params())
    with pytest.raises(ConsentInvalid):
        store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id="", user_name="", provider="",
                         max_grants=5)


def test_deny_takes_the_consent(store):
    _client(store)
    consent = store.open_consent(client_id="client-1", params=_params())
    assert store.deny_consent(txn_id=consent.txn_id, nonce=consent.nonce).txn_id == consent.txn_id
    assert store.consent(consent.txn_id) is None


def test_consents_per_address_and_total_caps(store, clock, monkeypatch):
    _client(store)
    for _ in range(CONSENTS_PER_ADDRESS):
        store.open_consent(client_id="client-1", params=_params(), created_ip="203.0.113.9")
    with pytest.raises(LimitReached) as per_address:
        store.open_consent(client_id="client-1", params=_params(), created_ip="203.0.113.9")
    assert per_address.value.reason == "consents_per_address"
    store.open_consent(client_id="client-1", params=_params(), created_ip="203.0.113.10")
    monkeypatch.setattr(store_mod, "CONSENTS_TOTAL", CONSENTS_PER_ADDRESS + 1)
    with pytest.raises(LimitReached) as total:
        store.open_consent(client_id="client-1", params=_params(), created_ip="203.0.113.11")
    assert total.value.reason == "consents_full"
    clock.t += CONSENT_TTL  # expired ones make room
    store.open_consent(client_id="client-1", params=_params(), created_ip="203.0.113.9")


# ── codes, grants, the per-person cap ──────────────────────────────────────────────────────────────


def test_only_hashes_of_codes_and_tokens_at_rest(store):
    _client(store)
    code = _code(store)
    taken = store.take_code(code, client_id="client-1")
    issued = store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1", grant_max_age=86400 * 90,
                                 max_grants=5, **TTL)
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    db = sqlite3.connect(store.path)
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    raw = store.path.read_bytes()
    for value in (code, issued.access_token, issued.refresh_token, rotated.access_token, rotated.refresh_token):
        assert value.encode() not in raw
    db = sqlite3.connect(store.path)
    hashes = {bytes(r[0]) for r in db.execute("SELECT token_hash FROM tokens")}
    assert hash_secret(issued.access_token) in hashes and hash_secret(rotated.refresh_token) in hashes
    assert bytes(db.execute("SELECT code_hash FROM codes").fetchone()[0]) == hash_secret(code)


def test_code_is_single_use_and_reuse_revokes_its_grant(store):
    _client(store)
    code = _code(store)
    taken = store.take_code(code, client_id="client-1")
    assert taken is not None and taken.user_id == ALICE and taken.resource == RESOURCE
    assert taken.scopes == tuple(SCOPES) and taken.code_challenge == CHALLENGE
    issued = store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1",
                                 grant_max_age=90 * 86400, max_grants=5, **TTL)
    assert store.verify_access(issued.access_token) is not None
    with pytest.raises(Reused) as reused:  # second presentation: the grant is revoked, and that is reported
        store.take_code(code, client_id="client-1")
    assert (reused.value.by, reused.value.grant.id, reused.value.reason) == (BY_CODE_REUSE, issued.grant.id, "reused")
    grant = store.grant(issued.grant.id)
    assert grant is not None and grant.revoked_by == BY_CODE_REUSE and not grant.live
    assert reused.value.grant.revoked_at == grant.revoked_at
    assert store.verify_access(issued.access_token) is None
    assert store.take_code(code, client_id="client-1") is None  # already revoked: nothing new to report


def test_a_code_presented_again_before_its_exchange_is_never_exchanged(store):
    # The taker's exchange is still running (between take_code and exchange_code) when the code shows up
    # again: there is no grant to revoke yet, so the exchange itself must refuse, and no grant is minted.
    _client(store)
    code = _code(store)
    taken = store.take_code(code, client_id="client-1")
    assert store.take_code(code, client_id="client-1") is None
    with pytest.raises(CodeInvalid):
        store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1", grant_max_age=86400,
                            max_grants=5, **TTL)
    assert store.grants(include_inactive=True) == []
    db = sqlite3.connect(store.path)
    assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0


def test_code_taken_then_failed_check_is_burnt(store):
    _client(store)
    code = _code(store)
    assert store.take_code(code, client_id="client-1") is not None  # the PKCE check then fails: no exchange
    assert store.take_code(code, client_id="client-1") is None
    assert store.grants(include_inactive=True) == []


def test_code_of_another_client_or_expired_is_refused_and_burnt(store, clock):
    _client(store)
    _client(store, "client-2")
    code = _code(store)
    assert store.take_code(code, client_id="client-2") is None
    assert store.take_code(code, client_id="client-1") is None
    late = _code(store)
    clock.t += CODE_TTL
    assert store.take_code(late, client_id="client-1") is None
    assert store.take_code("never-issued", client_id="client-1") is None
    assert store.take_code("", client_id="client-1") is None


def test_exchange_needs_the_taker_and_happens_once(store):
    _client(store)
    code = _code(store)
    with pytest.raises(CodeInvalid):  # never taken
        store.exchange_code(code=code, grant_id="made-up", client_id="client-1", grant_max_age=86400,
                            max_grants=5, **TTL)
    taken = store.take_code(code, client_id="client-1")
    with pytest.raises(CodeInvalid):  # another grant id than the one reserved
        store.exchange_code(code=code, grant_id="made-up", client_id="client-1", grant_max_age=86400,
                            max_grants=5, **TTL)
    with pytest.raises(CodeInvalid):  # another client
        store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-2", grant_max_age=86400,
                            max_grants=5, **TTL)
    store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1", grant_max_age=86400,
                        max_grants=5, **TTL)
    with pytest.raises(CodeInvalid):
        store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1", grant_max_age=86400,
                            max_grants=5, **TTL)
    assert len(store.grants(include_inactive=True)) == 1


def test_grant_and_token_family_are_one_transaction(store, monkeypatch):
    _client(store)
    code = _code(store)
    taken = store.take_code(code, client_id="client-1")

    def broken_mint(*_a, **_k):
        raise sqlite3.OperationalError("disk I/O error (simulated)")

    monkeypatch.setattr(MCPStore, "_mint", staticmethod(broken_mint))
    with pytest.raises(StoreError):
        store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1", grant_max_age=86400,
                            max_grants=5, **TTL)
    assert store.grants(include_inactive=True) == []
    db = sqlite3.connect(store.path)
    assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0


def test_grant_records_who_where_and_what(store, clock):
    _client(store)
    issued = _grant(store)
    g = issued.grant
    assert (g.user_id, g.user_name, g.provider, g.client_id, g.client_name) == \
        (ALICE, "Alice", "self_hosted", "client-1", "Example Agent")
    assert (g.created_at, g.created_ip, g.created_user_agent) == (int(clock.t), "198.51.100.7", "agent/1.0")
    assert g.scopes == tuple(SCOPES) and g.resource == RESOURCE and g.live
    assert g.expires_at == int(clock.t) + 90 * 86400
    assert issued.access_expires_at == int(clock.t) + 3600
    assert issued.refresh_expires_at == int(clock.t) + 30 * 86400
    assert store.client("client-1").last_used_at == int(clock.t)


def test_sixth_grant_per_person_refused_and_consent_stays_open(store):
    _client(store)
    for _ in range(5):
        _grant(store)
    consent = store.open_consent(client_id="client-1", params=_params())
    with pytest.raises(LimitReached) as refused:
        store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=ALICE, user_name="Alice",
                         provider="self_hosted", max_grants=5)
    assert refused.value.reason == "grants_per_user"
    assert store.consent(consent.txn_id) is not None
    _grant(store, user=BOB)  # another person is not affected
    store.revoke_grant(store.grants_for(ALICE)[0].id, by=ALICE, user_id=ALICE)
    store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=ALICE, user_name="Alice",
                     provider="self_hosted", max_grants=5)


def test_per_person_cap_rechecked_at_exchange(store):
    _client(store)
    codes = [_code(store) for _ in range(2)]  # two consents allowed while the person held 4
    for _ in range(4):
        _grant(store)
    takens = [store.take_code(c, client_id="client-1") for c in codes]
    store.exchange_code(code=codes[0], grant_id=takens[0].grant_id, client_id="client-1", grant_max_age=86400,
                        max_grants=5, **TTL)
    with pytest.raises(LimitReached):
        store.exchange_code(code=codes[1], grant_id=takens[1].grant_id, client_id="client-1", grant_max_age=86400,
                            max_grants=5, **TTL)
    assert len(store.grants_for(ALICE)) == 5


def test_dead_grants_do_not_count_against_the_cap(store, clock):
    _client(store)
    for _ in range(5):
        _grant(store)
    clock.t += 30 * 86400  # nobody refreshed for the sliding lifetime: every token is past its end
    assert store.grants_for(ALICE) == []
    assert len(store.grants(ALICE, include_inactive=True)) == 5
    _grant(store)


def test_two_concurrent_takes_of_one_code_one_wins(tmp_path, clock):
    path = tmp_path / "dashboard_auth" / "mcp.db"
    first = MCPStore(path, clock=clock)
    _client(first)
    code = _code(first)
    stores = [MCPStore(path, clock=clock) for _ in range(6)]
    results, barrier = [], threading.Barrier(len(stores))

    def take(s: MCPStore) -> None:
        barrier.wait()
        results.append(s.take_code(code, client_id="client-1"))

    threads = [threading.Thread(target=take, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [r for r in results if r is not None]
    assert len(winners) == 1 and len(results) == 6


# ── tokens ─────────────────────────────────────────────────────────────────────────────────────────


def test_access_token_verifies_until_it_expires(store, clock):
    _client(store)
    issued = _grant(store)
    found = store.verify_access(issued.access_token)
    assert found is not None and found.kind == "access" and found.grant.id == issued.grant.id
    assert found.scopes == tuple(SCOPES) and found.expires_at == issued.access_expires_at
    assert store.verify_access(issued.refresh_token) is None  # a refresh token is not an access token
    assert store.verify_access("") is None and store.verify_access("unknown") is None
    clock.t = issued.access_expires_at
    assert store.verify_access(issued.access_token) is None


def test_access_token_dies_with_its_grant(store, clock):
    _client(store)
    issued = _grant(store)
    store.revoke_grant(issued.grant.id, by=OPERATOR)
    assert store.verify_access(issued.access_token) is None


def test_last_used_is_bumped_at_most_once_a_minute(store, clock):
    _client(store)
    issued = _grant(store)
    start = int(clock.t)
    store.verify_access(issued.access_token, ip="192.0.2.1")
    g = store.grant(issued.grant.id)
    assert (g.last_used_at, g.last_used_ip) == (start, "192.0.2.1")
    db = sqlite3.connect(store.path)
    changes = db.execute("SELECT total_changes()").fetchone()[0]
    clock.t += LAST_USED_EVERY - 1
    store.verify_access(issued.access_token, ip="192.0.2.2")
    g = store.grant(issued.grant.id)
    assert (g.last_used_at, g.last_used_ip) == (start, "192.0.2.1")
    assert db.execute("SELECT total_changes()").fetchone()[0] == changes
    clock.t += 1
    store.verify_access(issued.access_token, ip="192.0.2.3")
    g = store.grant(issued.grant.id)
    assert (g.last_used_at, g.last_used_ip) == (start + LAST_USED_EVERY, "192.0.2.3")


def test_refresh_rotates_and_slides(store, clock):
    _client(store)
    issued = _grant(store)
    clock.t += 10 * 86400
    found = store.load_refresh(issued.refresh_token, client_id="client-1")
    assert found is not None and found.grant.id == issued.grant.id
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert rotated.grant.id == issued.grant.id
    assert rotated.refresh_expires_at == int(clock.t) + 30 * 86400  # sliding
    assert rotated.access_expires_at == int(clock.t) + 3600
    assert rotated.refresh_token != issued.refresh_token
    assert store.verify_access(rotated.access_token) is not None
    db = sqlite3.connect(store.path)
    families = {r[0] for r in db.execute("SELECT family FROM tokens")}
    assert len(families) == 1


def test_refresh_never_outlives_the_grant(store, clock):
    _client(store)
    code = _code(store)
    taken = store.take_code(code, client_id="client-1")
    issued = store.exchange_code(code=code, grant_id=taken.grant_id, client_id="client-1",
                                 grant_max_age=2 * 86400, max_grants=5, **TTL)
    assert issued.refresh_expires_at == issued.grant.expires_at
    clock.t += 86400
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert rotated.refresh_expires_at == issued.grant.expires_at
    clock.t = issued.grant.expires_at
    with pytest.raises(TokenInvalid) as expired:
        store.rotate_refresh(rotated.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert expired.value.reason == "expired"
    assert store.load_refresh(rotated.refresh_token, client_id="client-1") is None


def test_reuse_of_a_rotated_refresh_token_revokes_the_grant(store, clock):
    _client(store)
    issued = _grant(store)
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    clock.t += REFRESH_RACE_GRACE  # past the parallel-refresh grace
    with pytest.raises(Reused) as reused:
        store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert reused.value.reason == "reused" and reused.value.by == BY_REFRESH_REUSE
    g = store.grant(issued.grant.id)
    assert g.revoked_by == BY_REFRESH_REUSE and not g.live  # committed, despite the raise
    with pytest.raises(TokenInvalid) as again:  # already revoked: refused, nothing new to report
        store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert again.value.reason == "reused" and not isinstance(again.value, Reused)
    assert store.verify_access(rotated.access_token) is None
    assert store.load_refresh(rotated.refresh_token, client_id="client-1") is None


def test_loading_a_rotated_refresh_token_revokes_the_grant(store, clock):
    _client(store)
    issued = _grant(store)
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    clock.t += REFRESH_RACE_GRACE
    with pytest.raises(Reused) as reused:
        store.load_refresh(issued.refresh_token, client_id="client-1")
    assert (reused.value.by, reused.value.grant.id) == (BY_REFRESH_REUSE, issued.grant.id)
    assert store.grant(issued.grant.id).revoked_by == BY_REFRESH_REUSE
    assert store.verify_access(rotated.access_token) is None
    assert store.load_refresh(issued.refresh_token, client_id="client-1") is None  # reported once


@pytest.mark.parametrize("with_load", [False, True])
def test_two_parallel_refreshes_one_wins_and_the_grant_stays(tmp_path, clock, with_load):
    # A client whose two requests both found their access token expired refreshes twice with one refresh
    # token. That is not a theft: one rotation wins, the others are refused ("raced") and nothing is revoked.
    # with_load: as the SDK's token handler runs it (load, then rotate), so the late ones may fail at either.
    path = tmp_path / "dashboard_auth" / "mcp.db"
    first = MCPStore(path, clock=clock)
    _client(first)
    issued = _grant(first)
    stores = [MCPStore(path, clock=clock) for _ in range(4)]
    outcomes, barrier = [], threading.Barrier(len(stores))

    def refresh(s: MCPStore) -> None:
        barrier.wait()
        try:
            if with_load and s.load_refresh(issued.refresh_token, client_id="client-1") is None:
                outcomes.append("not loaded")
                return
            outcomes.append(s.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL))
        except TokenInvalid as exc:
            outcomes.append(exc.reason)

    threads = [threading.Thread(target=refresh, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    [winner] = [o for o in outcomes if not isinstance(o, str)]
    assert set(o for o in outcomes if isinstance(o, str)) <= {"raced", "not loaded"} and len(outcomes) == 4
    grant = first.grant(issued.grant.id)
    assert grant.revoked_at is None and grant.live
    assert first.verify_access(winner.access_token) is not None
    assert first.rotate_refresh(winner.refresh_token, client_id="client-1", scopes=None, **TTL).grant.live


def test_a_late_copy_is_refused_without_revoking_only_while_the_successor_is_unused(store, clock):
    _client(store)
    issued = _grant(store)
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    clock.t += REFRESH_RACE_GRACE - 1
    with pytest.raises(Raced):
        store.load_refresh(issued.refresh_token, client_id="client-1")
    with pytest.raises(TokenInvalid) as raced:
        store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert raced.value.reason == "raced" and store.grant(issued.grant.id).live
    # Once the successor has been used, the old token is a reuse even inside the window.
    store.rotate_refresh(rotated.refresh_token, client_id="client-1", scopes=None, **TTL)
    with pytest.raises(TokenInvalid) as reused:
        store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert reused.value.reason == "reused" and store.grant(issued.grant.id).revoked_by == BY_REFRESH_REUSE


@pytest.mark.parametrize("how", ["after_the_window", "another_client", "successor_revoked"])
def test_a_rotated_token_outside_the_grace_still_revokes(store, clock, how):
    _client(store)
    _client(store, "client-2")
    issued = _grant(store)
    rotated = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    presenter = "client-1"
    if how == "after_the_window":
        clock.t += REFRESH_RACE_GRACE
    elif how == "another_client":
        presenter = "client-2"
    else:
        db = sqlite3.connect(store.path)
        db.execute("UPDATE tokens SET revoked_at = ? WHERE token_hash = ?",
                   (int(clock.t), hash_secret(rotated.refresh_token)))
        db.commit()
        db.close()
    with pytest.raises(Reused):
        store.load_refresh(issued.refresh_token, client_id=presenter)
    assert store.grant(issued.grant.id).revoked_by == BY_REFRESH_REUSE


def test_a_file_without_the_added_columns_gains_them(tmp_path, clock):
    path = tmp_path / "dashboard_auth" / "mcp.db"
    MCPStore(path, clock=clock).counts()
    db = sqlite3.connect(path)
    db.execute("DROP INDEX tokens_parent")  # an older file had neither the column nor its index
    db.execute("ALTER TABLE tokens DROP COLUMN parent_hash")
    db.execute("ALTER TABLE codes DROP COLUMN reused_at")
    db.commit()
    db.close()
    store = MCPStore(path, clock=clock)
    _client(store)
    issued = _grant(store)
    store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    db = sqlite3.connect(path)
    assert db.execute("SELECT COUNT(*) FROM tokens WHERE parent_hash = ?",
                      (hash_secret(issued.refresh_token),)).fetchone()[0] == 1
    assert "reused_at" in {r[1] for r in db.execute("PRAGMA table_info(codes)")}
    assert db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "1"


@pytest.mark.parametrize("load", [True, False], ids=["load", "rotate"])
def test_a_late_copy_four_seconds_after_its_rotation_is_raced_with_its_grant(store, clock, load):
    """Plan D3 amendment: the window is 5 s, and a raced refusal names its grant (for the audit line)."""
    _client(store)
    issued = _grant(store)
    store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    clock.t += 4
    with pytest.raises(Raced) as raced:
        if load:
            store.load_refresh(issued.refresh_token, client_id="client-1")
        else:
            store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert (raced.value.reason, raced.value.grant_id, raced.value.user_id) == \
        ("raced", issued.grant.id, issued.grant.user_id)
    assert store.grant(issued.grant.id).live


@pytest.mark.parametrize("load", [True, False], ids=["load", "rotate"])
def test_a_late_copy_six_seconds_after_its_rotation_revokes(store, clock, load):
    _client(store)
    issued = _grant(store)
    store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    clock.t += 6
    with pytest.raises(Reused):
        if load:
            store.load_refresh(issued.refresh_token, client_id="client-1")
        else:
            store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert store.grant(issued.grant.id).revoked_by == BY_REFRESH_REUSE


def test_the_race_window_is_five_seconds():
    assert REFRESH_RACE_GRACE == 5


def test_a_successor_is_found_by_an_index_and_an_older_file_gains_it(tmp_path, clock):
    path = tmp_path / "dashboard_auth" / "mcp.db"
    MCPStore(path, clock=clock).counts()
    db = sqlite3.connect(path)
    plan = " ".join(str(r[-1]) for r in db.execute(
        "EXPLAIN QUERY PLAN SELECT 1 FROM tokens WHERE parent_hash = ? AND kind = 'refresh'", (b"x",)))
    assert "tokens_parent" in plan, plan
    db.execute("DROP INDEX tokens_parent")
    db.commit()
    db.close()
    MCPStore(path, clock=clock).counts()  # opened again: the index is back, the schema version unchanged
    db = sqlite3.connect(path)
    assert "tokens_parent" in {r[1] for r in db.execute("PRAGMA index_list(tokens)")}
    assert db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "1"
    db.close()


def test_refresh_scope_may_narrow_never_widen(store):
    _client(store)
    issued = _grant(store)
    narrowed = store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=["bots:read"], **TTL)
    assert narrowed.scopes == ("bots:read",)
    assert store.verify_access(narrowed.access_token).scopes == ("bots:read",)
    again = store.rotate_refresh(narrowed.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert again.scopes == tuple(SCOPES)  # the refresh token kept the grant's scopes
    with pytest.raises(TokenInvalid) as wider:
        store.rotate_refresh(again.refresh_token, client_id="client-1", scopes=["admin"], **TTL)
    assert wider.value.reason == "scope"
    assert store.grant(issued.grant.id).live  # a refused widening does not spend the token


def test_refresh_of_another_client_or_revoked_is_refused(store):
    _client(store)
    _client(store, "client-2")
    issued = _grant(store)
    assert store.load_refresh(issued.refresh_token, client_id="client-2") is None
    with pytest.raises(TokenInvalid) as other:
        store.rotate_refresh(issued.refresh_token, client_id="client-2", scopes=None, **TTL)
    assert other.value.reason == "client"
    store.revoke_grant(issued.grant.id, by=OPERATOR)
    assert store.load_refresh(issued.refresh_token, client_id="client-1") is None
    with pytest.raises(TokenInvalid) as revoked:
        store.rotate_refresh(issued.refresh_token, client_id="client-1", scopes=None, **TTL)
    assert revoked.value.reason == "revoked"
    with pytest.raises(TokenInvalid):
        store.rotate_refresh("never-issued", client_id="client-1", scopes=None, **TTL)


# ── grants ─────────────────────────────────────────────────────────────────────────────────────────


def test_revoke_grant_own_only(store):
    _client(store)
    issued = _grant(store)
    assert store.revoke_grant(issued.grant.id, by=BOB, user_id=BOB) is None  # not Bob's: no oracle
    assert store.grant(issued.grant.id).live
    revoked = store.revoke_grant(issued.grant.id, by=ALICE, user_id=ALICE)
    assert revoked is not None and revoked.revoked_by == ALICE and not revoked.live
    again = store.revoke_grant(issued.grant.id, by=OPERATOR)
    assert again is not None and again.revoked_by == ALICE  # the first revocation stands
    assert store.revoke_grant("no-such-grant", by=OPERATOR) is None
    assert store.load_refresh(issued.refresh_token, client_id="client-1") is None


def test_revoking_through_either_token_kind_revokes_the_grant(store):
    _client(store)
    for kind in ("access", "refresh"):
        issued = _grant(store)
        found = store.verify_access(issued.access_token) if kind == "access" else \
            store.load_refresh(issued.refresh_token, client_id="client-1")
        store.revoke_grant(found.grant.id, by=BY_CLIENT)
        assert store.verify_access(issued.access_token) is None
        assert store.load_refresh(issued.refresh_token, client_id="client-1") is None
        assert store.grant(issued.grant.id).revoked_by == BY_CLIENT


def test_revoke_grants_of_a_person(store):
    _client(store)
    a1, a2, b1 = _grant(store), _grant(store), _grant(store, user=BOB)
    revoked = store.revoke_grants_of(ALICE, by=OPERATOR)
    assert {g.id for g in revoked} == {a1.grant.id, a2.grant.id}
    assert store.grants_for(ALICE) == [] and [g.id for g in store.grants_for(BOB)] == [b1.grant.id]
    assert store.revoke_grants_of(ALICE, by=OPERATOR) == []


def test_grants_for_lists_live_own_grants_newest_first(store, clock):
    _client(store)
    first = _grant(store)
    clock.t += 10
    second = _grant(store)
    _grant(store, user=BOB)
    assert [g.id for g in store.grants_for(ALICE)] == [second.grant.id, first.grant.id]
    store.revoke_grant(first.grant.id, by=OPERATOR)
    assert [g.id for g in store.grants_for(ALICE)] == [second.grant.id]
    assert store.grants_for("") == []
    assert len(store.grants(include_inactive=True)) == 3


# ── chats ──────────────────────────────────────────────────────────────────────────────────────────


def test_record_chat_and_chats_for(store, clock):
    store.record_chat(user_id=ALICE, profile="default", session_key="s-1", grant_id="g-1")
    clock.t += 5
    store.record_chat(user_id=ALICE, profile="default", session_key="s-2", grant_id="g-1")
    store.record_chat(user_id=ALICE, profile="coder", session_key="s-3", grant_id="g-1")
    store.record_chat(user_id=BOB, profile="default", session_key="s-9", grant_id="g-2")
    clock.t += 5
    again = store.record_chat(user_id=ALICE, profile="default", session_key="s-1", grant_id="g-other")
    assert again.opened_by_grant == "g-1" and again.last_used_at == int(clock.t) and again.created_at < again.last_used_at
    assert [c.session_key for c in store.chats_for(ALICE, "default")] == ["s-1", "s-2"]
    assert {c.session_key for c in store.chats_for(ALICE)} == {"s-1", "s-2", "s-3"}
    assert [c.session_key for c in store.chats_for(BOB, "default")] == ["s-9"]
    assert store.has_chat(user_id=ALICE, profile="default", session_key="s-2")
    assert not store.has_chat(user_id=BOB, profile="default", session_key="s-2")
    assert not store.has_chat(user_id=ALICE, profile="coder", session_key="s-2")


# ── pruning ────────────────────────────────────────────────────────────────────────────────────────


def test_prune(store, clock):
    _client(store)  # will hold a grant
    _client(store, "unused")
    live = _grant(store)
    revoked = _grant(store)
    store.revoke_grant(revoked.grant.id, by=OPERATOR)
    store.open_consent(client_id="client-1", params=_params())
    _code(store)  # issued, never exchanged
    store.record_chat(user_id=ALICE, profile="default", session_key="old", grant_id=live.grant.id)
    t0 = int(clock.t)

    clock.t = t0 + CODE_TTL
    assert store.prune() == {"consents": 0, "codes": 3, "grants": 0, "tokens": 0, "chats": 0, "clients": 0}
    clock.t = t0 + CONSENT_TTL
    assert store.prune()["consents"] == 1
    clock.t = t0 + CLIENT_UNUSED_TTL
    assert store.prune()["clients"] == 1 and store.client("unused") is None
    clock.t = t0 + 3600 + TOKEN_KEEP_AFTER_EXPIRY + 1  # both access tokens a week past their end
    assert store.prune()["tokens"] == 2
    store.record_chat(user_id=ALICE, profile="default", session_key="fresh", grant_id=live.grant.id)
    clock.t = t0 + GRANT_KEEP_AFTER_END + 1
    counts = store.prune()
    assert counts["grants"] == 1 and store.grant(revoked.grant.id) is None
    assert store.grant(live.grant.id) is not None  # ended at 90 d, kept 90 more
    assert CHAT_IDLE_KEEP == 90 * 86400 + GRANT_KEEP_AFTER_END
    clock.t = t0 + CHAT_IDLE_KEEP + 1  # the live grant ended at 90 d and is kept 90 more: both go now
    counts = store.prune()
    assert (counts["chats"], counts["grants"], counts["clients"]) == (1, 1, 1)  # its last grant gone: the client too
    assert [c.session_key for c in store.chats_for(ALICE)] == ["fresh"]
    db = sqlite3.connect(store.path)
    assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0  # cascaded
    assert store.client("client-1") is None


def test_counts(store):
    _client(store)
    _grant(store)
    _grant(store, user=BOB)
    store.open_consent(client_id="client-1", params=_params())
    assert store.counts() == {"clients": 1, "consents": 1, "grants": 2, "users": 2, "chats": 0}


def test_default_path_is_under_hermes_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    assert store_mod.default_path() == Path(tmp_path) / "dashboard_auth" / "mcp.db"
