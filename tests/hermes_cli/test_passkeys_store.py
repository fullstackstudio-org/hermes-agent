"""The passkey store: identity, enrolment codes, registrations and step-ups, credentials, assertion commits,
receipts, and the properties that must hold across connections and processes."""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from hermes_cli.dashboard_auth.passkeys.challenge import GatewayContext, b64u, enrolment_code_hash, text_digest
from hermes_cli.dashboard_auth.passkeys.store import (
    CODE_TTL, OPERATOR, REGISTRATION_TTL, STEPUP_TTL, CodeInvalid, CommitRefused, CredentialExists,
    PasskeyStore, PendingInvalid, StoreError)
from hermes_cli.dashboard_auth.passkeys.webauthn import (
    AssertionOk, AssertionRequest, RegistrationOk, verify_assertion, verify_registration)
from tests.hermes_cli.passkey_soft_authenticator import SoftAuthenticator, web_authenticator

U = "self_hosted:alice"
V = "self_hosted:bob"
NATIVE_RP = "confirm.hermie.dev"
BASE = "https://gw.example.com"


class Clock:
    def __init__(self, t: float = 1_790_000_000):
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path, clock) -> PasskeyStore:
    return PasskeyStore(tmp_path / "dashboard_auth" / "passkeys.db", clock=clock)


def _reg(credential_id: bytes = b"\x01" * 32, rp_id: str = NATIVE_RP, *, pending=None, synced: bool = True,
         sign_count: int = 0) -> RegistrationOk:
    """A verified registration, bound to *pending* the way the verifier binds it."""
    return RegistrationOk(credential_id=credential_id, rp_id=rp_id, alg=-7, public_x=b"\x02" * 32,
                          public_y=b"\x03" * 32, sign_count=sign_count, backup_eligible=synced, backed_up=synced,
                          aaguid=b"\x00" * 16, transports=("internal",),
                          registration_id=pending.id if pending else "", user_id=pending.user_id if pending else U,
                          nonce=pending.nonce if pending else b"")


def _enrol(store: PasskeyStore, user: str = U, credential_id: bytes = b"\x01" * 32, **kw):
    pending = store.open_pending("register", user_id=user, rp_id=kw.get("rp_id", NATIVE_RP), base_url=BASE,
                                 subject="Phone")
    code = store.mint_code(user_id=user).code
    return store.add_credential(user_id=user, code=code, registration=_reg(credential_id, pending=pending, **kw))


_REQUESTS = itertools.count(1)


def _ok(credential_id: bytes, *, sign_count: int = 0, rp_id: str = NATIVE_RP, synced: bool = True, user: str = U,
        purpose: str = "confirm", request_id: str | None = None, nonce: bytes | None = None,
        digest: bytes = b"d" * 32) -> AssertionOk:
    """A verified answer for a request of its own (fresh request id and nonce unless given)."""
    return AssertionOk(credential_id=credential_id, rp_id=rp_id, base_url=BASE, sign_count=sign_count,
                       backup_eligible=synced, backed_up=synced, counter_warning=False, challenge=b"c" * 32,
                       text_digest=digest, authenticator_data=b"a" * 37, client_data_json=b"{}",
                       signature=b"s" * 70, user_id=user, purpose=purpose, session_id="s1",
                       request_id=request_id or f"srq-{next(_REQUESTS)}", nonce=nonce or os.urandom(32))


def _commit(store, cred, ok, *, snapshot=None, user_id=None, stepup_id=None):
    return store.commit_assertion(ok, user_id=user_id or cred.user_id, snapshot=snapshot or cred.stored(),
                                  stepup_id=stepup_id)


# ── files and identity ───────────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_directory_0700_file_0600_and_the_wal_files_too(store):
    store.identity()
    _enrol(store)
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    for path in store.path.parent.iterdir():
        assert path.name.startswith("passkeys.db")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_an_existing_loose_file_is_tightened(tmp_path, clock):
    path = tmp_path / "dashboard_auth" / "passkeys.db"
    path.parent.mkdir(mode=0o755)
    path.touch(mode=0o644)
    os.chmod(path, 0o644)
    PasskeyStore(path, clock=clock).identity()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_identity_is_minted_once_and_survives_reopening(store, tmp_path, clock):
    assert not store.exists()
    gateway_id, handle_key = store.identity()
    assert len(gateway_id) == 16 and len(handle_key) == 32
    again = PasskeyStore(store.path, clock=clock)
    assert again.identity() == (gateway_id, handle_key)
    other = PasskeyStore(tmp_path / "other" / "passkeys.db", clock=clock)
    assert other.identity()[0] != gateway_id


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_a_store_removed_under_a_running_process_starts_over_with_a_new_identity(store):
    old = store.identity()
    _enrol(store)
    for path in list(store.path.parent.iterdir()):
        path.unlink()
    assert store.identity() != old and store.credentials() == []
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_concurrent_first_use_mints_one_identity(store, clock):
    stores = [PasskeyStore(store.path, clock=clock) for _ in range(8)]
    seen, barrier = [], threading.Barrier(len(stores))

    def first_use(s):
        barrier.wait()
        seen.append(s.identity())

    threads = [threading.Thread(target=first_use, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(seen) == 8 and len(set(seen)) == 1


def test_a_symlink_or_a_directory_at_the_store_path_is_refused(tmp_path, clock):
    target = tmp_path / "elsewhere.db"
    target.touch()
    link = tmp_path / "a" / "passkeys.db"
    link.parent.mkdir()
    link.symlink_to(target)
    with pytest.raises(StoreError):
        PasskeyStore(link, clock=clock).identity()
    folder = tmp_path / "b" / "passkeys.db"
    folder.mkdir(parents=True)
    with pytest.raises(StoreError):
        PasskeyStore(folder, clock=clock).identity()


def test_a_file_that_is_not_a_database_is_a_store_error_on_every_path(tmp_path, clock):
    path = tmp_path / "c" / "passkeys.db"
    path.parent.mkdir()
    path.write_bytes(b"this is not a database" * 100)
    s = PasskeyStore(path, clock=clock)
    for call in (s.identity, s.credentials, s.counts, lambda: s.mint_code(), lambda: s.receipts()):
        with pytest.raises(StoreError):
            call()


def test_a_newer_schema_is_refused(store, clock):
    store.identity()
    db = sqlite3.connect(store.path)
    db.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    db.commit()
    db.close()
    with pytest.raises(StoreError, match="schema 99"):
        PasskeyStore(store.path, clock=clock).identity()


# ── enrolment codes ──────────────────────────────────────────────────────────────────────────────


def test_codes_are_stored_as_hashes_only(store):
    invite = store.mint_code(user_id=U)
    raw = store.path.read_bytes() + b"".join(
        p.read_bytes() for p in store.path.parent.iterdir() if p.name != store.path.name)
    canonical = invite.code.replace("-", "").encode()
    assert canonical not in raw and invite.code.encode() not in raw
    db = sqlite3.connect(store.path)
    assert db.execute("SELECT code_hash FROM invites").fetchone()[0] == enrolment_code_hash(invite.code)


def test_code_ttl_bounds_and_the_person_minted_code_is_bound_to_them(store, clock):
    assert store.mint_code().expires_at == clock() + CODE_TTL
    assert store.mint_code(ttl=24 * 3600).expires_at == clock() + 24 * 3600
    for bad in (59, 24 * 3600 + 1):
        with pytest.raises(ValueError):
            store.mint_code(ttl=bad)
    own = store.mint_code(by=U, ttl=24 * 3600)
    assert own.user_id == U and own.expires_at == clock() + CODE_TTL
    with pytest.raises(ValueError):
        store.mint_code(by=U, user_id=V)


@pytest.mark.parametrize("case", ["unknown", "garbage", "expired", "used", "wrong_user"])
def test_one_answer_for_every_bad_code_and_nothing_changes(store, clock, case):
    _enrol(store, credential_id=b"\x09" * 32)  # a used code exists
    code = store.mint_code(user_id=U).code
    if case == "unknown":
        code = "00000-00000-00000-00000"
    elif case == "garbage":
        code = "not a code"
    elif case == "expired":
        clock.t += CODE_TTL
    elif case == "used":
        p = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="x")
        store.add_credential(user_id=U, code=code, registration=_reg(b"\x07" * 32, pending=p))
    pending = store.open_pending("register", user_id=V if case == "wrong_user" else U, rp_id=NATIVE_RP,
                                 base_url=BASE, subject="x")
    before = sqlite3.connect(store.path).execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    with pytest.raises(CodeInvalid) as exc:
        store.add_credential(user_id=V if case == "wrong_user" else U, code=code,
                             registration=_reg(b"\x05" * 32, pending=pending))
    assert str(exc.value) == "code_invalid"
    assert sqlite3.connect(store.path).execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == before
    # The registration was not taken: the right code still works while it is open.
    user = V if case == "wrong_user" else U
    good = store.mint_code(user_id=user).code
    store.add_credential(user_id=user, code=good, registration=_reg(b"\x05" * 32, pending=pending))


def test_a_code_accepts_lower_case_and_confusables(store):
    invite = store.mint_code(user_id=U)
    typed = invite.code.lower().replace("-", " ").replace("0", "o").replace("1", "l")
    pending = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="x")
    assert store.add_credential(user_id=U, code=typed, registration=_reg(pending=pending)).active


def test_an_unbound_code_binds_to_whoever_redeems_it_once(store):
    code = store.mint_code().code
    p1 = store.open_pending("register", user_id=V, rp_id=NATIVE_RP, base_url=BASE, subject="x")
    cred = store.add_credential(user_id=V, code=code, registration=_reg(pending=p1))
    assert cred.user_id == V and cred.created_via == OPERATOR
    p2 = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="x")
    with pytest.raises(CodeInvalid):
        store.add_credential(user_id=U, code=code, registration=_reg(b"\x04" * 32, pending=p2))
    row = sqlite3.connect(store.path).execute("SELECT used_by FROM invites").fetchone()
    assert row[0] == V


def test_credential_exists_leaves_the_code_and_the_registration_unused(store):
    _enrol(store, credential_id=b"\x01" * 32)
    pending = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="x")
    code = store.mint_code(user_id=U).code
    with pytest.raises(CredentialExists):
        store.add_credential(user_id=U, code=code, registration=_reg(b"\x01" * 32, pending=pending))
    assert store.open_codes() == 1
    assert store.add_credential(user_id=U, code=code, registration=_reg(b"\x02" * 32, pending=pending))


def test_a_revoked_credential_id_stays_taken(store):
    cred = _enrol(store)
    store.revoke(cred.credential_id, by=OPERATOR)
    with pytest.raises(CredentialExists):
        _enrol(store, credential_id=cred.credential_id)


def test_concurrent_redemption_has_one_winner_across_connections(store, clock):
    code = store.mint_code(user_id=U).code
    pendings = [store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject=f"d{i}")
                for i in range(12)]
    results, barrier = [], threading.Barrier(len(pendings))

    def redeem(i, pending):
        own = PasskeyStore(store.path, clock=clock)  # its own connections, like another process
        barrier.wait()
        try:
            own.add_credential(user_id=U, code=code, registration=_reg(bytes([i]) * 32, pending=pending))
            results.append("won")
        except CodeInvalid:
            results.append("code_invalid")

    threads = [threading.Thread(target=redeem, args=(i, p)) for i, p in enumerate(pendings)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(results) == ["code_invalid"] * 11 + ["won"]
    assert len(store.credentials(U)) == 1


_REDEEM_SCRIPT = r"""
import sys
from hermes_cli.dashboard_auth.passkeys.store import CodeInvalid, PasskeyStore
from hermes_cli.dashboard_auth.passkeys.webauthn import RegistrationOk
path, code, registration_id, nonce, marker = sys.argv[1:6]
store = PasskeyStore(path)
reg = RegistrationOk(credential_id=bytes([int(marker)]) * 32, rp_id="confirm.hermie.dev", alg=-7,
                     public_x=b"\x02" * 32, public_y=b"\x03" * 32, sign_count=0, backup_eligible=True,
                     backed_up=True, aaguid=b"\x00" * 16, transports=(), registration_id=registration_id,
                     user_id="self_hosted:alice", nonce=bytes.fromhex(nonce))
try:
    store.add_credential(user_id="self_hosted:alice", code=code, registration=reg)
    print("won")
except CodeInvalid:
    print("code_invalid")
"""


def test_concurrent_redemption_has_one_winner_across_processes(tmp_path):
    store = PasskeyStore(tmp_path / "dashboard_auth" / "passkeys.db")  # real clock: the children use it too
    code = store.mint_code(user_id=U).code
    pendings = [store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject=f"d{i}")
                for i in range(6)]
    root = Path(__file__).resolve().parents[2]
    procs = [subprocess.Popen([sys.executable, "-c", _REDEEM_SCRIPT, str(store.path), code, p.id, p.nonce.hex(), str(i + 1)],
                              cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env={**os.environ, "PYTHONPATH": str(root)})
             for i, p in enumerate(pendings)]
    outputs = []
    for proc in procs:
        out, errs = proc.communicate(timeout=120)
        assert proc.returncode == 0, errs
        outputs.append(out.strip())
    assert sorted(outputs) == ["code_invalid"] * 5 + ["won"]
    assert len(store.credentials(U)) == 1


# ── registrations and step-ups ───────────────────────────────────────────────────────────────────


def test_registration_and_stepup_lifetimes(store, clock):
    reg = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="Phone")
    step = store.open_pending("invite", user_id=U, subject="invite")
    assert reg.expires_at - clock() == REGISTRATION_TTL and step.expires_at - clock() == STEPUP_TTL
    assert len(reg.nonce) == 32 and reg.id != step.id
    assert store.pending(reg.id, kind="register", user_id=U) == reg
    clock.t += STEPUP_TTL
    assert store.pending(step.id, kind="invite", user_id=U) is None
    with pytest.raises(PendingInvalid):
        store.take_pending(step.id, kind="invite", user_id=U)
    assert store.pending(reg.id, kind="register", user_id=U) is not None
    clock.t += REGISTRATION_TTL - STEPUP_TTL
    code = store.mint_code(user_id=U).code
    with pytest.raises(PendingInvalid):
        store.add_credential(user_id=U, code=code, registration=_reg(pending=reg))
    assert store.open_codes() == 1  # the code survived the refused enrolment


def test_a_pending_id_is_taken_once_and_only_by_its_user_and_kind(store):
    step = store.open_pending("revoke", user_id=U, subject="abc")
    for kind, user in (("invite", U), ("revoke", V), ("register", U)):
        with pytest.raises(PendingInvalid):
            store.take_pending(step.id, kind=kind, user_id=user)
    assert store.take_pending(step.id, kind="revoke", user_id=U) == step  # the wrong tries did not burn it
    with pytest.raises(PendingInvalid):
        store.take_pending(step.id, kind="revoke", user_id=U)


@pytest.mark.parametrize("case", ["other_registration", "other_nonce", "other_user"])
def test_an_enrolment_takes_only_the_registration_it_was_verified_for(store, case):
    mine = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="x")
    other = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="y")
    reg = _reg(pending=mine)
    if case == "other_registration":  # verified for one registration, spending another open one
        reg = dataclasses.replace(reg, registration_id=other.id)
    elif case == "other_nonce":
        reg = dataclasses.replace(reg, nonce=other.nonce)
    else:  # the caller is not the user the registration was verified for
        reg = dataclasses.replace(reg, user_id=V)
    code = store.mint_code(user_id=U).code
    with pytest.raises(PendingInvalid):
        store.add_credential(user_id=U, code=code, registration=reg)
    assert store.open_codes() == 1 and store.credentials() == []
    assert store.pending(mine.id, kind="register", user_id=U) and store.pending(other.id, kind="register", user_id=U)


def test_a_registration_cannot_enrol_for_another_rp(store):
    pending = store.open_pending("register", user_id=U, rp_id=NATIVE_RP, base_url=BASE, subject="x")
    code = store.mint_code(user_id=U).code
    with pytest.raises(PendingInvalid):
        store.add_credential(user_id=U, code=code, registration=_reg(rp_id="gw.example.com", pending=pending))
    assert store.open_codes() == 1 and store.pending(pending.id, kind="register", user_id=U)


# ── credentials ──────────────────────────────────────────────────────────────────────────────────


def test_the_store_never_returns_a_revoked_credential_as_active(store):
    a = _enrol(store, credential_id=b"\x0a" * 32)
    b = _enrol(store, credential_id=b"\x0b" * 32)
    assert store.revoke(a.credential_id, by=OPERATOR).revoked_by == OPERATOR
    assert [c.credential_id for c in store.credentials(U)] == [b.credential_id]
    assert [c.credential_id for c in store.snapshot(U)] == [b.credential_id]
    assert all(c.active for c in store.snapshot(U))
    assert store.find(a.id_b64u[:8]) == []
    assert [c.active for c in store.credentials(U, include_revoked=True)] == [False, True]
    assert store.credential(a.credential_id).active is False
    assert store.revoke(a.credential_id, by=OPERATOR) is None  # nothing to revoke twice


def test_revoke_is_scoped_to_a_user_when_asked(store):
    cred = _enrol(store, user=U)
    assert store.revoke(cred.credential_id, by=V, user_id=V) is None
    assert store.credential(cred.credential_id).active
    _enrol(store, user=U, credential_id=b"\x0c" * 32)
    _enrol(store, user=V, credential_id=b"\x0d" * 32)
    assert len(store.revoke_user(U, by=OPERATOR)) == 2
    assert store.credentials(U) == [] and len(store.credentials(V)) == 1


def test_the_stored_record_carries_what_the_contract_lists(store, clock):
    cred = _enrol(store)
    assert (cred.rp_id, cred.alg, cred.public_x, cred.public_y, cred.sign_count, cred.backup_eligible,
            cred.backed_up, cred.aaguid, cred.transports, cred.name, cred.created_at, cred.created_via) == (
        NATIVE_RP, -7, b"\x02" * 32, b"\x03" * 32, 0, True, True, b"\x00" * 16, ("internal",), "Phone",
        int(clock()), OPERATOR)
    own = store.mint_code(by=U).code
    p = store.open_pending("register", user_id=U, rp_id="gw.example.com", base_url=BASE, subject="Laptop")
    second = store.add_credential(user_id=U, code=own, created_ip="192.0.2.1",
                                  registration=_reg(b"\x0e" * 32, rp_id="gw.example.com", pending=p))
    assert (second.created_via, second.created_ip, second.name) == ("passkey", "192.0.2.1", "Laptop")


# ── assertion commits ────────────────────────────────────────────────────────────────────────────


def test_commit_updates_counter_and_last_used_and_writes_a_receipt(store, clock):
    cred = _enrol(store, synced=False, sign_count=3)
    clock.t += 10
    done = _commit(store, cred, _ok(cred.credential_id, sign_count=4, synced=False))
    assert done.credential.sign_count == 4 and done.credential.last_used_at == int(clock())
    assert not done.counter_warning
    (receipt,) = store.receipts()
    assert (receipt.id, receipt.purpose, receipt.user_id, receipt.credential_row, receipt.origin,
            receipt.text_digest, receipt.signature) == (done.receipt_id, "confirm", U, cred.row, BASE,
                                                         b"d" * 32, b"s" * 70)


def test_a_credential_revoked_while_the_request_was_open_is_refused_at_commit(store):
    cred = _enrol(store)
    snapshot = cred.stored()  # taken when the request opened
    store.revoke(cred.credential_id, by=OPERATOR)
    with pytest.raises(CommitRefused) as exc:
        _commit(store, cred, _ok(cred.credential_id), snapshot=snapshot)
    assert exc.value.reason == "revoked"
    assert store.receipts() == []


def test_commit_refuses_another_user_or_another_key(store):
    cred = _enrol(store)
    with pytest.raises(CommitRefused):
        _commit(store, cred, _ok(cred.credential_id), user_id=V)
    other = _reg(b"\x0f" * 32)
    forged = cred.stored().__class__(**{**cred.stored().__dict__, "public_x": other.public_y})
    with pytest.raises(CommitRefused):
        _commit(store, cred, _ok(cred.credential_id), snapshot=forged)
    with pytest.raises(CommitRefused):
        _commit(store, cred, _ok(cred.credential_id, rp_id="gw.example.com"))
    assert store.receipts() == [] and store.credential(cred.credential_id).last_used_at is None


def test_the_counter_rule_is_applied_to_the_value_stored_now_not_the_snapshot(store):
    """Two answers verified against the same snapshot (count 5): the first commits 7; the second, at 6,
    passed the verifier but is behind what is stored now and is refused for a device-bound credential."""
    cred = _enrol(store, synced=False, sign_count=5)
    snapshot = cred.stored()
    _commit(store, cred, _ok(cred.credential_id, sign_count=7, synced=False), snapshot=snapshot)
    with pytest.raises(CommitRefused) as exc:
        _commit(store, cred, _ok(cred.credential_id, sign_count=6, synced=False), snapshot=snapshot)
    assert exc.value.reason == "counter_regression"
    assert store.credential(cred.credential_id).sign_count == 7 and len(store.receipts()) == 1
    # Ahead of the stored value is fine even though the snapshot is stale.
    assert _commit(store, cred, _ok(cred.credential_id, sign_count=8, synced=False), snapshot=snapshot)


def test_a_synced_credential_going_down_commits_with_a_warning(store):
    cred = _enrol(store, synced=True, sign_count=9)
    done = _commit(store, cred, _ok(cred.credential_id, sign_count=2, synced=True))
    assert done.counter_warning and done.credential.sign_count == 2
    zero = _enrol(store, credential_id=b"\x10" * 32, synced=True, sign_count=0)
    assert not _commit(store, zero, _ok(zero.credential_id, sign_count=0, synced=True)).counter_warning


def test_concurrent_commits_of_one_device_bound_answer_count_once(store, clock):
    """The same counter value committed from many connections at once: one wins, the rest are behind."""
    cred = _enrol(store, synced=False, sign_count=1)
    snapshot, results = cred.stored(), []
    barrier = threading.Barrier(10)

    def commit():
        own = PasskeyStore(store.path, clock=clock)
        barrier.wait()
        try:
            _commit(own, cred, _ok(cred.credential_id, sign_count=2, synced=False), snapshot=snapshot)
            results.append("ok")
        except CommitRefused as exc:
            results.append(exc.reason)

    threads = [threading.Thread(target=commit) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(results) == ["counter_regression"] * 9 + ["ok"]
    assert len(store.receipts()) == 1


def _stepup_ok(cred, step, **kw):
    """An answer verified for the step-up *step* (its id is the request id, its nonce the nonce)."""
    return _ok(cred.credential_id, purpose=step.kind, request_id=step.id, nonce=step.nonce,
               digest=text_digest("", step.subject, ""), **kw)


def test_a_stepup_commit_takes_its_own_stepup_in_the_same_transaction(store):
    cred = _enrol(store)
    step = store.open_pending("invite", user_id=U, subject="invite")
    _commit(store, cred, _stepup_ok(cred, step), stepup_id=step.id)
    assert store.pending(step.id, kind="invite", user_id=U) is None
    assert [r.request_id for r in store.receipts()] == [step.id]


def test_one_stepup_ceremony_commits_once(store):
    """The double commit: the same verified answer (or a second answer for the same ceremony) cannot be
    committed again, so one step-up never yields two codes or two revokes."""
    cred = _enrol(store)
    step = store.open_pending("invite", user_id=U, subject="invite")
    ok = _stepup_ok(cred, step)
    _commit(store, cred, ok, stepup_id=step.id)
    for again in (ok, _stepup_ok(cred, step)):
        with pytest.raises(CommitRefused) as exc:
            _commit(store, cred, again, stepup_id=step.id)
        assert exc.value.reason == "stepup_invalid"
    assert len(store.receipts()) == 1


@pytest.mark.parametrize("case", ["no_stepup_id", "other_open_stepup", "other_nonce", "other_kind",
                                  "confirm_naming_a_stepup", "other_user", "other_subject"])
def test_a_stepup_is_bound_to_the_answer_verified_for_it(store, case):
    cred = _enrol(store)
    mine = store.open_pending("invite", user_id=U, subject="invite")
    other = store.open_pending("invite", user_id=U, subject="invite")
    revoke = store.open_pending("revoke", user_id=U, subject=cred.id_b64u)
    if case == "no_stepup_id":  # a step-up purpose committed as if it were a plain confirm
        ok, stepup_id = _stepup_ok(cred, mine), None
    elif case == "other_open_stepup":  # verified for one ceremony, spending another open one of the same user
        ok, stepup_id = _stepup_ok(cred, mine), other.id
    elif case == "other_nonce":  # the right id, but the answer was verified with another nonce
        ok, stepup_id = _ok(cred.credential_id, purpose="invite", request_id=mine.id, nonce=other.nonce), mine.id
    elif case == "other_kind":  # verified as an invite, spending a revoke step-up
        ok, stepup_id = _ok(cred.credential_id, purpose="invite", request_id=revoke.id, nonce=revoke.nonce), revoke.id
    elif case == "confirm_naming_a_stepup":
        ok, stepup_id = _ok(cred.credential_id, request_id=mine.id, nonce=mine.nonce), mine.id
    elif case == "other_user":  # verified for another user's request
        ok, stepup_id = _stepup_ok(cred, mine, user=V), mine.id
    else:  # the right id and nonce, but the person approved another text than the step-up's subject
        ok, stepup_id = _ok(cred.credential_id, purpose="invite", request_id=mine.id, nonce=mine.nonce,
                            digest=text_digest("", "revoke everything", "")), mine.id
    with pytest.raises(CommitRefused):
        _commit(store, cred, ok, stepup_id=stepup_id)
    for step in (mine, other, revoke):
        assert store.pending(step.id, kind=step.kind, user_id=U) is not None  # nothing was taken
    assert store.receipts() == [] and store.credential(cred.credential_id).last_used_at is None


@pytest.mark.parametrize("purpose", ["register", "admin", ""])
def test_only_confirm_invite_and_revoke_commit(store, purpose):
    cred = _enrol(store)
    with pytest.raises(CommitRefused) as exc:
        _commit(store, cred, _ok(cred.credential_id, purpose=purpose))
    assert exc.value.reason == "purpose_invalid" and store.receipts() == []


def test_a_confirm_commits_once_per_request_and_per_nonce(store):
    cred = _enrol(store)
    ok = _ok(cred.credential_id)
    _commit(store, cred, ok)
    same_request = _ok(cred.credential_id, request_id=ok.request_id)
    same_nonce = _ok(cred.credential_id, nonce=ok.nonce)
    for again in (ok, same_request, same_nonce):
        with pytest.raises(CommitRefused) as exc:
            _commit(store, cred, again)
        assert exc.value.reason == "replayed"
    assert len(store.receipts()) == 1


# ── receipts and housekeeping ────────────────────────────────────────────────────────────────────


def test_receipts_hold_digests_never_text(store):
    cred = _enrol(store)
    _commit(store, cred, _ok(cred.credential_id))
    columns = [r[1] for r in sqlite3.connect(store.path).execute("PRAGMA table_info(receipts)")]
    assert not {"title", "summary", "detail", "text"} & set(columns)


def test_pruning_drops_old_receipts_expired_codes_and_closed_pendings(store, clock):
    cred = _enrol(store)
    _commit(store, cred, _ok(cred.credential_id))
    store.mint_code(user_id=U)
    store.open_pending("invite", user_id=U, subject="invite")
    clock.t += 89 * 86400
    _commit(store, cred, _ok(cred.credential_id))
    assert store.prune(receipts_days=90) == {"receipts": 0, "invites": 2, "pending": 1}
    clock.t += 2 * 86400
    assert store.prune(receipts_days=90)["receipts"] == 1
    assert len(store.receipts()) == 1
    assert store.prune(receipts_days=1)["receipts"] == 1 and store.receipts() == []


def test_receipt_filters(store, clock):
    a = _enrol(store, user=U)
    b = _enrol(store, user=V, credential_id=b"\x11" * 32)
    _commit(store, a, _ok(a.credential_id))
    clock.t += 100
    _commit(store, b, _ok(b.credential_id, user=V))
    assert [r.user_id for r in store.receipts()] == [V, U]
    assert [r.user_id for r in store.receipts(user_id=U)] == [U]
    assert [r.user_id for r in store.receipts(since=int(clock()))] == [V]
    assert len(store.receipts(limit=1)) == 1


# ── end to end with the verifier and a software authenticator ────────────────────────────────────


def test_enrol_and_confirm_with_a_software_authenticator(store):
    gateway_id, handle_key = store.identity()
    ctx = GatewayContext(gateway_id=gateway_id, handle_key=handle_key, base_urls=(BASE,),
                         native_rps={NATIVE_RP: ("https://confirm.hermie.dev",)})
    for auth, rp_id in ((SoftAuthenticator(rp_id=NATIVE_RP, client_origin="https://confirm.hermie.dev"), NATIVE_RP),
                        (web_authenticator(BASE, synced=False), "gw.example.com")):
        pending = store.open_pending("register", user_id=U, rp_id=rp_id, base_url=BASE, subject="Device")
        finish = auth.register(gateway_id, pending.registration())
        reg = verify_registration(ctx, pending.registration(), finish)
        assert isinstance(reg, RegistrationOk), reg
        store.add_credential(user_id=U, code=store.mint_code(user_id=U).code, registration=reg)
        snapshot = store.snapshot(U)
        request = AssertionRequest(user_id=U, request_id=f"srq-{rp_id}", nonce=os.urandom(32), title="Delete",
                                   summary="the branch", detail="git branch -D x", session_id="s")
        answer = auth.assert_(gateway_id, handle_key, request, BASE)
        ok = verify_assertion(ctx, request, snapshot, answer)
        assert isinstance(ok, AssertionOk), ok
        used = next(c for c in snapshot if c.credential_id == ok.credential_id)
        done = store.commit_assertion(ok, user_id=U, snapshot=used)
        assert done.credential.sign_count == ok.sign_count
        receipt = store.receipts(limit=1)[0]
        assert receipt.text_digest == request.text_digest and receipt.signature == ok.signature
    assert len(store.credentials(U)) == 2


def test_status_counts(store):
    _enrol(store)
    store.mint_code()
    gone = _enrol(store, user=V, credential_id=b"\x12" * 32)
    store.revoke(gone.credential_id, by=OPERATOR)
    assert store.counts() == {"credentials": 1, "revoked": 1, "users": 1, "open_codes": 1, "receipts": 0}
    assert json.dumps(store.counts())  # plain ints
    assert b64u(store.gateway_id)
