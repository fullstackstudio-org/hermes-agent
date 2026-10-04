# Frozen copy of hermes_cli/dashboard_auth/passkeys/store.py at fork 1fdf876d68: the store as a build
# before re-authentication grants shipped. tests/hermes_cli/test_passkeys_store.py opens files written by
# the current store with it, so a rolled-back build is proven to still read them. Never edit it.
"""The passkey store: one SQLite file the gateway and the operator CLI share.

``$HERMES_HOME/dashboard_auth/passkeys.db`` (directory 0700, file 0600, WAL). It holds this gateway's
identity (``gateway_id``, 16 bytes, public; ``handle_key``, 32 bytes, secret; both minted once), the
credentials per ``<provider>:<user id>``, the enrolment codes (SHA-256 of the canonical code only), the
open registrations and step-ups, and the receipts of verified answers (digests and signed bytes, never
the confirmed text).

Every state change is one ``BEGIN IMMEDIATE`` transaction, so the rules hold across processes (the CLI
mints and revokes while the gateway redeems and commits):

- a code is redeemed at most once, by the user it is bound to, before it expires, and only together with
  the credential it enrols (a failed enrolment leaves the code and the registration unused);
- a registration or step-up id is taken at most once, by its user, before it expires, and only by the
  verified result made for exactly it (same id and nonce: a result carries what it was checked against);
- an assertion commit re-reads the credential: revoked meanwhile, another user's, another key → refused;
  the counter rule is re-applied to the value stored *now* (not the snapshot the verifier saw), the new
  value is written with compare-and-set, and the receipt is written in the same transaction. A second
  commit of one request or nonce is refused (unique receipts).

The store never returns a revoked credential as active and never deletes one (a revoked credential id
stays taken). Time comes from the ``clock`` given to the store, in whole Unix seconds. Every failure is a
:class:`StoreError` (database and file errors included).

For the ``confirm`` answer path (CP-5): call :meth:`PasskeyStore.prune` (receipts age out only then); map
:class:`CommitRefused` to ``unavailable (verification_failed)``; audit ``Committed.counter_warning``; and
treat any other :class:`StoreError` as ``unavailable``, never as consent.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

from hermes_cli.dashboard_auth.passkeys.challenge import (
    GATEWAY_ID_BYTES, HANDLE_KEY_BYTES, NONCE_BYTES, b64u, enrolment_code_display, enrolment_code_hash,
    text_digest)
from hermes_cli.dashboard_auth.passkeys.webauthn import (
    AssertionOk, PendingRegistration, RegistrationOk, StoredCredential)

SCHEMA_VERSION = 1
FILE_NAME = "passkeys.db"

OPERATOR = "operator"  # ``invites.minted_by`` / ``revoked_by`` for the operator CLI
CODE_TTL = 15 * 60
OPERATOR_CODE_TTL_MAX = 24 * 60 * 60
REGISTRATION_TTL = 300
STEPUP_TTL = 120
STEPUP_PURPOSES = ("invite", "revoke")
COMMIT_PURPOSES = ("confirm",) + STEPUP_PURPOSES
PENDING_KINDS = ("register",) + STEPUP_PURPOSES
INVITE_KEEP_AFTER_EXPIRY = 24 * 60 * 60
BUSY_TIMEOUT_S = 5.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id BLOB NOT NULL UNIQUE,
    rp_id TEXT NOT NULL,
    alg INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    backup_eligible INTEGER NOT NULL,
    backed_up INTEGER NOT NULL,
    aaguid BLOB NOT NULL,
    transports TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_via TEXT NOT NULL,
    created_ip TEXT NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER,
    revoked_by TEXT);
CREATE INDEX IF NOT EXISTS credentials_user ON credentials (user_id);
CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY,
    code_hash BLOB NOT NULL UNIQUE,
    user_id TEXT,
    minted_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    used_by TEXT);
CREATE TABLE IF NOT EXISTS pending (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    user_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    rp_id TEXT NOT NULL,
    base_url TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    user_id TEXT NOT NULL,
    credential_row INTEGER NOT NULL REFERENCES credentials (id),
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    session_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    text_digest BLOB NOT NULL,
    authenticator_data BLOB NOT NULL,
    client_data_json BLOB NOT NULL,
    signature BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS receipts_at ON receipts (at);
CREATE UNIQUE INDEX IF NOT EXISTS receipts_nonce ON receipts (nonce);
CREATE UNIQUE INDEX IF NOT EXISTS receipts_request ON receipts (purpose, request_id);
"""


class StoreError(Exception):
    """The store cannot be used (unreadable, a newer schema, not a regular file)."""


class CodeInvalid(StoreError):
    """One answer for an unknown, expired, used or wrong-user enrolment code."""


class PendingInvalid(StoreError):
    """The registration or step-up id is unknown, expired, used, of another kind or of another user."""


class CredentialExists(StoreError):
    """The credential id is already stored (active or revoked)."""


class CommitRefused(StoreError):
    """An assertion that verified cannot be committed. ``reason``: ``revoked`` (also unknown, another
    user, another key), ``counter_regression`` (against the value stored now), ``stepup_invalid`` (a
    step-up purpose without its own open step-up, a step-up for another request, or text other than the
    step-up's subject), ``purpose_invalid`` (not ``confirm``, ``invite`` or ``revoke``) or ``replayed``
    (this request or nonce was committed before)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CredentialRecord:
    row: int
    user_id: str
    credential_id: bytes
    rp_id: str
    alg: int
    public_x: bytes
    public_y: bytes
    sign_count: int
    backup_eligible: bool
    backed_up: bool
    aaguid: bytes
    transports: tuple[str, ...]
    name: str
    created_at: int
    created_via: str
    created_ip: str
    last_used_at: Optional[int]
    revoked_at: Optional[int]
    revoked_by: Optional[str]

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    @property
    def id_b64u(self) -> str:
        return b64u(self.credential_id)

    def stored(self) -> StoredCredential:
        """The verifier's view (a snapshot)."""
        return StoredCredential(credential_id=self.credential_id, user_id=self.user_id, rp_id=self.rp_id,
                                public_x=self.public_x, public_y=self.public_y, sign_count=self.sign_count,
                                backup_eligible=self.backup_eligible, active=self.active)


@dataclass(frozen=True)
class Invite:
    code: str  # the display form; shown once, never stored
    user_id: Optional[str]
    expires_at: int


@dataclass(frozen=True)
class Pending:
    id: str
    kind: str  # "register" | "invite" | "revoke"
    user_id: str
    nonce: bytes
    rp_id: str
    base_url: str
    subject: str  # the credential name (register), "invite", or the credential id (revoke)
    created_at: int
    expires_at: int

    def registration(self) -> PendingRegistration:
        """The verifier's view of an open registration."""
        if self.kind != "register":
            raise ValueError("not a registration")
        return PendingRegistration(registration_id=self.id, user_id=self.user_id, rp_id=self.rp_id,
                                   base_url=self.base_url, name=self.subject, nonce=self.nonce)


@dataclass(frozen=True)
class Receipt:
    id: int
    at: int
    purpose: str
    user_id: str
    credential_row: int
    rp_id: str
    origin: str
    session_id: str
    request_id: str
    nonce: bytes
    text_digest: bytes
    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes


@dataclass(frozen=True)
class Committed:
    credential: CredentialRecord  # after the commit
    receipt_id: int
    counter_warning: bool  # a synced credential's counter went down against the value stored now


def default_path() -> Path:
    from hermes_constants import get_hermes_home
    return get_hermes_home() / "dashboard_auth" / FILE_NAME


def _credential(row: sqlite3.Row) -> CredentialRecord:
    key = bytes(row["public_key"])
    return CredentialRecord(
        row=row["id"], user_id=row["user_id"], credential_id=bytes(row["credential_id"]), rp_id=row["rp_id"],
        alg=row["alg"], public_x=key[:32], public_y=key[32:], sign_count=row["sign_count"],
        backup_eligible=bool(row["backup_eligible"]), backed_up=bool(row["backed_up"]),
        aaguid=bytes(row["aaguid"]), transports=tuple(json.loads(row["transports"])), name=row["name"],
        created_at=row["created_at"], created_via=row["created_via"], created_ip=row["created_ip"],
        last_used_at=row["last_used_at"], revoked_at=row["revoked_at"], revoked_by=row["revoked_by"])


def _pending(row: sqlite3.Row) -> Pending:
    return Pending(id=row["id"], kind=row["kind"], user_id=row["user_id"], nonce=bytes(row["nonce"]),
                   rp_id=row["rp_id"], base_url=row["base_url"], subject=row["subject"],
                   created_at=row["created_at"], expires_at=row["expires_at"])


def _receipt(row: sqlite3.Row) -> Receipt:
    fields: dict = {k: (bytes(row[k]) if isinstance(row[k], (bytes, memoryview)) else row[k]) for k in row.keys()}
    return Receipt(**fields)


class PasskeyStore:
    """Open with a path (tests) or :meth:`default` (``$HERMES_HOME``). Cheap to construct: the file is
    created, and the identity minted, on first use. Safe to share between threads (one connection per
    operation) and between processes (SQLite locking, ``BEGIN IMMEDIATE`` for every write)."""

    def __init__(self, path: Path | str, *, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._clock = clock
        self._ready = False
        self._identity: Optional[tuple[bytes, bytes]] = None

    @classmethod
    def default(cls, **kwargs) -> "PasskeyStore":
        return cls(default_path(), **kwargs)

    def now(self) -> int:
        return int(self._clock())

    def exists(self) -> bool:
        return self.path.is_file()

    # ── files and connections ────────────────────────────────────────────────────────────────────

    def _prepare_files(self) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        if self.path.is_symlink():
            raise StoreError(f"{self.path} is a symbolic link")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StoreError(f"{self.path} is not a regular file")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)  # the file just checked, not whatever the path names a moment later
            else:
                os.chmod(self.path, 0o600)
        finally:
            os.close(fd)

    def _connect(self) -> sqlite3.Connection:
        if self._ready and not self.path.is_file():
            # Removed under a running process (an operator reset): start over with a new file and identity
            # rather than let SQLite recreate it with default permissions and no tables.
            self._ready, self._identity = False, None
        if not self._ready:
            self._prepare_files()
        db = sqlite3.connect(str(self.path), timeout=BUSY_TIMEOUT_S, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_S * 1000)}")
            db.execute("PRAGMA foreign_keys = ON")
            if not self._ready:
                db.execute("PRAGMA journal_mode = WAL")
                self._create(db)
                for suffix in ("-wal", "-shm"):
                    side = self.path.with_name(self.path.name + suffix)
                    if side.is_file() and not side.is_symlink():
                        os.chmod(side, 0o600)
                self._ready = True
        except BaseException:
            db.close()
            raise
        return db

    def _create(self, db: sqlite3.Connection) -> None:
        db.execute("BEGIN IMMEDIATE")
        try:
            for statement in filter(str.strip, _SCHEMA.split(";")):
                db.execute(statement)
            row = db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                db.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif int(row["value"]) > SCHEMA_VERSION:
                raise StoreError(f"{self.path} has schema {int(row['value'])}; this build reads {SCHEMA_VERSION}")
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    @staticmethod
    @contextlib.contextmanager
    def _errors() -> Iterator[None]:
        """Database and file errors as :class:`StoreError` (a caller catches one type; a non-database file
        at the path is a store error, not a traceback)."""
        try:
            yield
        except StoreError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise StoreError(f"passkey store: {exc}") from exc

    @contextlib.contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._errors():
            db = self._connect()
        try:
            with self._errors():
                db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException as exc:
                with contextlib.suppress(sqlite3.Error):
                    db.execute("ROLLBACK")
                if isinstance(exc, (sqlite3.Error, OSError)) and not isinstance(exc, StoreError):
                    raise StoreError(f"passkey store: {exc}") from exc
                raise
            with self._errors():
                db.execute("COMMIT")
        finally:
            db.close()

    @contextlib.contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        with self._errors():
            db = self._connect()
        try:
            with self._errors():
                db.execute("BEGIN")
                try:
                    yield db
                finally:
                    with contextlib.suppress(sqlite3.Error):
                        db.execute("ROLLBACK")
        finally:
            db.close()

    # ── identity ─────────────────────────────────────────────────────────────────────────────────

    def identity(self) -> tuple[bytes, bytes]:
        """``(gateway_id, handle_key)``, minted on first use and never changed (a new store, new identity)."""
        if self._identity is None or not self.path.is_file():
            with self._write() as db:
                for key, size in (("gateway_id", GATEWAY_ID_BYTES), ("handle_key", HANDLE_KEY_BYTES)):
                    db.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
                               (key, secrets.token_bytes(size)))
                values = dict(db.execute(
                    "SELECT key, value FROM meta WHERE key IN ('gateway_id', 'handle_key')").fetchall())
            self._identity = (bytes(values["gateway_id"]), bytes(values["handle_key"]))
        return self._identity

    @property
    def gateway_id(self) -> bytes:
        return self.identity()[0]

    # ── credentials ──────────────────────────────────────────────────────────────────────────────

    def credentials(self, user_id: Optional[str] = None, *, include_revoked: bool = False
                    ) -> list[CredentialRecord]:
        sql = "SELECT * FROM credentials WHERE 1 = 1"
        args: list = []
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        if not include_revoked:
            sql += " AND revoked_at IS NULL"
        with self._read() as db:
            return [_credential(r) for r in db.execute(sql + " ORDER BY id", args).fetchall()]

    def snapshot(self, user_id: str) -> tuple[StoredCredential, ...]:
        """*user_id*'s active credentials as the verifier takes them when a request opens."""
        return tuple(c.stored() for c in self.credentials(user_id))

    def credential(self, credential_id: bytes) -> Optional[CredentialRecord]:
        """The stored record (active or revoked), or None."""
        with self._read() as db:
            row = db.execute("SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)).fetchone()
        return _credential(row) if row else None

    def find(self, prefix: str, *, include_revoked: bool = False) -> list[CredentialRecord]:
        """Credentials whose base64url id starts with *prefix* (the operator's ``revoke <prefix>``)."""
        if not prefix:
            return []
        return [c for c in self.credentials(include_revoked=include_revoked) if c.id_b64u.startswith(prefix)]

    def add_credential(self, *, user_id: str, code: str, registration: RegistrationOk, created_ip: str = ""
                       ) -> CredentialRecord:
        """Enrol: take the open registration *registration* was verified against (its id, user and nonce),
        redeem the code and store the credential, all or nothing. *user_id* is the signed-in caller.

        Raises :class:`PendingInvalid`, :class:`CodeInvalid` or :class:`CredentialExists` (checked in that
        order); on any of them nothing changes, so the person can try again with the right code while the
        registration is open."""
        now = self.now()
        with self._write() as db:
            if registration.user_id != user_id:
                raise PendingInvalid("the registration belongs to another user")
            pending = self._take_pending(db, registration.registration_id, kind="register", user_id=user_id,
                                         now=now, nonce=registration.nonce)
            if pending.rp_id != registration.rp_id:
                raise PendingInvalid("the registration was opened for another RP")
            code_hash = enrolment_code_hash(code)
            invite = db.execute("SELECT * FROM invites WHERE code_hash = ?", (code_hash,)).fetchone() \
                if code_hash else None
            if invite is None or invite["used_at"] is not None or invite["expires_at"] <= now \
                    or invite["user_id"] not in (None, user_id):
                raise CodeInvalid("code_invalid")
            if db.execute("UPDATE invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL",
                          (now, user_id, invite["id"])).rowcount != 1:
                raise CodeInvalid("code_invalid")
            if db.execute("SELECT 1 FROM credentials WHERE credential_id = ?",
                          (registration.credential_id,)).fetchone():
                raise CredentialExists("credential_exists")
            created_via = OPERATOR if invite["minted_by"] == OPERATOR else "passkey"
            cursor = db.execute(
                "INSERT INTO credentials (user_id, credential_id, rp_id, alg, public_key, sign_count,"
                " backup_eligible, backed_up, aaguid, transports, name, created_at, created_via, created_ip)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, registration.credential_id, registration.rp_id, registration.alg,
                 registration.public_x + registration.public_y, registration.sign_count,
                 int(registration.backup_eligible), int(registration.backed_up), registration.aaguid,
                 json.dumps(list(registration.transports)), pending.subject, now, created_via, created_ip))
            return _credential(db.execute("SELECT * FROM credentials WHERE id = ?",
                                          (cursor.lastrowid,)).fetchone())

    def revoke(self, credential_id: bytes, *, by: str, user_id: Optional[str] = None
               ) -> Optional[CredentialRecord]:
        """Revoke one active credential (of *user_id* when given). None when there was nothing to revoke."""
        now = self.now()
        sql = "UPDATE credentials SET revoked_at = ?, revoked_by = ? WHERE credential_id = ? AND revoked_at IS NULL"
        args: list = [now, by, credential_id]
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        with self._write() as db:
            if db.execute(sql, args).rowcount != 1:
                return None
            return _credential(db.execute("SELECT * FROM credentials WHERE credential_id = ?",
                                          (credential_id,)).fetchone())

    def revoke_user(self, user_id: str, *, by: str) -> list[CredentialRecord]:
        """Revoke every active credential of *user_id*; returns what was revoked."""
        now = self.now()
        with self._write() as db:
            rows = [r["id"] for r in db.execute(
                "SELECT id FROM credentials WHERE user_id = ? AND revoked_at IS NULL", (user_id,)).fetchall()]
            db.executemany("UPDATE credentials SET revoked_at = ?, revoked_by = ? WHERE id = ?",
                           [(now, by, row) for row in rows])
            return [_credential(db.execute("SELECT * FROM credentials WHERE id = ?", (row,)).fetchone())
                    for row in rows]

    # ── enrolment codes ──────────────────────────────────────────────────────────────────────────

    def mint_code(self, *, user_id: Optional[str] = None, by: str = OPERATOR, ttl: Optional[int] = None
                  ) -> Invite:
        """A new single-use code. ``by`` is :data:`OPERATOR` (the CLI: optional user, ``ttl`` up to 24 h)
        or the user id of a person who passed an ``invite`` step-up (the code is then bound to them and
        lives :data:`CODE_TTL`)."""
        if by != OPERATOR:
            if user_id not in (None, by):
                raise ValueError("a person can mint a code only for themselves")
            user_id, ttl = by, CODE_TTL
        ttl = CODE_TTL if ttl is None else int(ttl)
        if not 60 <= ttl <= OPERATOR_CODE_TTL_MAX:
            raise ValueError(f"ttl must be between 60 s and {OPERATOR_CODE_TTL_MAX} s")
        if user_id is not None and not user_id.strip():
            raise ValueError("empty user id")
        now = self.now()
        code = enrolment_code_display(secrets.token_bytes(13))
        with self._write() as db:
            db.execute("INSERT INTO invites (code_hash, user_id, minted_by, created_at, expires_at)"
                       " VALUES (?, ?, ?, ?, ?)", (enrolment_code_hash(code), user_id, by, now, now + ttl))
        return Invite(code=code, user_id=user_id, expires_at=now + ttl)

    def open_codes(self) -> int:
        now = self.now()
        with self._read() as db:
            return db.execute("SELECT COUNT(*) FROM invites WHERE used_at IS NULL AND expires_at > ?",
                              (now,)).fetchone()[0]

    # ── registrations and step-ups ───────────────────────────────────────────────────────────────

    def open_pending(self, kind: str, *, user_id: str, rp_id: str = "", base_url: str = "", subject: str = ""
                     ) -> Pending:
        """Open a registration (``register``, :data:`REGISTRATION_TTL`) or a step-up (``invite`` /
        ``revoke``, :data:`STEPUP_TTL`) with a fresh id and nonce."""
        if kind not in PENDING_KINDS:
            raise ValueError(f"unknown kind {kind!r}")
        now = self.now()
        ttl = REGISTRATION_TTL if kind == "register" else STEPUP_TTL
        pending = Pending(id=b64u(secrets.token_bytes(16)), kind=kind, user_id=user_id,
                          nonce=secrets.token_bytes(NONCE_BYTES), rp_id=rp_id, base_url=base_url,
                          subject=subject, created_at=now, expires_at=now + ttl)
        with self._write() as db:
            db.execute("DELETE FROM pending WHERE expires_at <= ?", (now,))
            db.execute("INSERT INTO pending (id, kind, user_id, nonce, rp_id, base_url, subject, created_at,"
                       " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (pending.id, kind, user_id, pending.nonce, rp_id, base_url, subject, now,
                        pending.expires_at))
        return pending

    def pending(self, pending_id: str, *, kind: str, user_id: str) -> Optional[Pending]:
        """Look at an open registration or step-up without taking it (None when not usable)."""
        now = self.now()
        with self._read() as db:
            row = db.execute("SELECT * FROM pending WHERE id = ?", (str(pending_id),)).fetchone()
        if row is None or row["kind"] != kind or row["user_id"] != user_id or row["expires_at"] <= now:
            return None
        return _pending(row)

    @staticmethod
    def _take_pending(db: sqlite3.Connection, pending_id: str, *, kind: str, user_id: str, now: int,
                      nonce: Optional[bytes] = None, digest: Optional[bytes] = None) -> Pending:
        row = db.execute("SELECT * FROM pending WHERE id = ?", (str(pending_id),)).fetchone()
        # Anything that does not match is refused without taking the row: nobody can burn someone else's
        # ceremony, and a result verified for another ceremony (another nonce) cannot spend this one.
        if row is None or row["kind"] != kind or row["user_id"] != user_id or row["expires_at"] <= now \
                or (nonce is not None and not hmac.compare_digest(bytes(row["nonce"]), nonce)) \
                or (digest is not None and not hmac.compare_digest(text_digest("", row["subject"], ""), digest)):
            raise PendingInvalid("pending_invalid")
        if db.execute("DELETE FROM pending WHERE id = ?", (row["id"],)).rowcount != 1:
            raise PendingInvalid("pending_invalid")
        return _pending(row)

    def take_pending(self, pending_id: str, *, kind: str, user_id: str) -> Pending:
        """Take (consume) an open registration or step-up. Raises :class:`PendingInvalid`."""
        now = self.now()
        with self._write() as db:
            return self._take_pending(db, pending_id, kind=kind, user_id=user_id, now=now)

    # ── assertions ───────────────────────────────────────────────────────────────────────────────

    def commit_assertion(self, ok: AssertionOk, *, user_id: str, snapshot: StoredCredential,
                         stepup_id: Optional[str] = None) -> Committed:
        """The one side effect of a verified answer, in one transaction. *ok* names the request it was
        verified against (user, purpose, session, request id, nonce); *user_id* is the user the caller bound
        the request to and must be the same.

        - The credential is re-read and must still be *snapshot*'s (same user, RP and key) and active.
        - The purpose is ``confirm``, ``invite`` or ``revoke``. A step-up purpose needs *stepup_id*, which
          must be the request id the answer was verified for; the open step-up with that id, kind, user,
          nonce and subject (the text digest of ``("", subject, "")``) is taken. ``confirm`` must not name a
          step-up. So one ceremony commits at most once, only its own, and only for what it said.
        - The counter rule is applied to the value stored now; the new count and BS are written with
          compare-and-set; ``last_used_at`` is set; a receipt is written (unique per nonce and per request).

        Raises :class:`CommitRefused` and changes nothing when any of that fails."""
        now = self.now()
        if ok.purpose not in COMMIT_PURPOSES:  # "register" is never an assertion; anything else is unknown
            raise CommitRefused("purpose_invalid")
        step_up = ok.purpose in STEPUP_PURPOSES
        if ok.user_id != user_id:
            raise CommitRefused("revoked")  # verified for another user than the request is bound to
        if step_up != (stepup_id is not None) \
                or (step_up and not hmac.compare_digest(str(stepup_id).encode(), ok.request_id.encode())):
            raise CommitRefused("stepup_invalid")
        with self._write() as db:
            row = db.execute("SELECT * FROM credentials WHERE credential_id = ?", (ok.credential_id,)).fetchone()
            current = _credential(row) if row else None
            if current is None or not current.active or current.user_id != user_id \
                    or snapshot.credential_id != ok.credential_id or current.rp_id != ok.rp_id \
                    or (current.public_x, current.public_y) != (snapshot.public_x, snapshot.public_y):
                raise CommitRefused("revoked")
            if step_up:
                try:
                    # The text the person approved must be this step-up's subject ("invite", or the
                    # credential id being revoked), not some other summary signed under its id and nonce.
                    self._take_pending(db, ok.request_id, kind=ok.purpose, user_id=user_id, now=now, nonce=ok.nonce,
                                       digest=ok.text_digest)
                except PendingInvalid:
                    raise CommitRefused("stepup_invalid") from None
            count = ok.sign_count
            regressed = not (count == 0 and current.sign_count == 0) and count <= current.sign_count
            if regressed and not current.backup_eligible:
                raise CommitRefused("counter_regression")
            if db.execute("UPDATE credentials SET sign_count = ?, backed_up = ?, last_used_at = ?"
                          " WHERE id = ? AND sign_count = ? AND revoked_at IS NULL",
                          (count, int(ok.backed_up), now, current.row, current.sign_count)).rowcount != 1:
                raise CommitRefused("revoked")
            try:
                cursor = db.execute(
                    "INSERT INTO receipts (at, purpose, user_id, credential_row, rp_id, origin, session_id,"
                    " request_id, nonce, text_digest, authenticator_data, client_data_json, signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (now, ok.purpose, user_id, current.row, ok.rp_id, ok.base_url, ok.session_id, ok.request_id,
                     ok.nonce, ok.text_digest, ok.authenticator_data, ok.client_data_json, ok.signature))
            except sqlite3.IntegrityError:
                raise CommitRefused("replayed") from None
            after = _credential(db.execute("SELECT * FROM credentials WHERE id = ?", (current.row,)).fetchone())
            return Committed(credential=after, receipt_id=int(cursor.lastrowid or 0), counter_warning=regressed)

    # ── receipts and housekeeping ────────────────────────────────────────────────────────────────

    def receipts(self, *, user_id: Optional[str] = None, since: Optional[int] = None,
                 limit: Optional[int] = None) -> list[Receipt]:
        sql = "SELECT * FROM receipts WHERE 1 = 1"
        args: list = []
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        if since is not None:
            sql += " AND at >= ?"
            args.append(int(since))
        sql += " ORDER BY at DESC, id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(int(limit))
        with self._read() as db:
            return [_receipt(r) for r in db.execute(sql, args).fetchall()]

    def prune(self, *, receipts_days: int) -> dict[str, int]:
        """Drop receipts older than *receipts_days*, codes a day after they expired, closed pendings."""
        now = self.now()
        with self._write() as db:
            return {
                "receipts": db.execute("DELETE FROM receipts WHERE at < ?",
                                       (now - int(receipts_days) * 86400,)).rowcount,
                "invites": db.execute("DELETE FROM invites WHERE expires_at < ?",
                                      (now - INVITE_KEEP_AFTER_EXPIRY,)).rowcount,
                "pending": db.execute("DELETE FROM pending WHERE expires_at <= ?", (now,)).rowcount,
            }

    def counts(self) -> dict[str, int]:
        now = self.now()
        with self._read() as db:
            def one(sql: str, *args) -> int:
                return int(db.execute(sql, args).fetchone()[0])
            return {
                "credentials": one("SELECT COUNT(*) FROM credentials WHERE revoked_at IS NULL"),
                "revoked": one("SELECT COUNT(*) FROM credentials WHERE revoked_at IS NOT NULL"),
                "users": one("SELECT COUNT(DISTINCT user_id) FROM credentials WHERE revoked_at IS NULL"),
                "open_codes": one("SELECT COUNT(*) FROM invites WHERE used_at IS NULL AND expires_at > ?", now),
                "receipts": one("SELECT COUNT(*) FROM receipts"),
            }
