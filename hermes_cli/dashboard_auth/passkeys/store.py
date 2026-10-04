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

A re-authentication grant (self-enrolment without a code) is a third enrolment authority next to the two
kinds of code. A session opens it (``open``), a sign-in of the same person that the provider reports as
fresh completes it once (``fresh`` or ``failed``), and the enrolment it authorises spends it in the
credential insert's own transaction (``spent``): one grant, at most one credential, never after
:data:`GRANT_TTL`. The binding holds until the grant is spent, not only until it is completed: a web grant is
bound to the browser that opened it by a secret only its cookie holds, needed to complete it and again to use
it; a native grant is completed through the gateway's PKCE round trip, and the completion hands the app a
``use_secret`` that it needs to use it. Both are stored as SHA-256 only, so the grant id alone (which can end
up in an access log or a browser history) neither completes nor spends anything.

A credential enrolled with a cooling-off period (``usable_from`` in the future) is listed by
:meth:`PasskeyStore.credentials` and can be revoked, but it is in no :meth:`PasskeyStore.snapshot` and an
assertion with it is never committed until ``usable_from`` has passed.

The grants table and the ``usable_from`` column are added to an existing file in place, without a schema
version bump: a build from before them reads named columns, ignores the extra table and still opens the file.

The store never returns a revoked credential as active and never deletes one (a revoked credential id
stays taken). Time comes from the ``clock`` given to the store, in whole Unix seconds. Every failure is a
:class:`StoreError` (database and file errors included).

For the ``confirm`` answer path (CP-5): call :meth:`PasskeyStore.prune` (receipts age out only then); map
:class:`CommitRefused` to ``unavailable (verification_failed)``; audit ``Committed.counter_warning``; and
treat any other :class:`StoreError` as ``unavailable``, never as consent.
"""

from __future__ import annotations

import contextlib
import hashlib
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

SELF = "self"  # ``credentials.created_via`` for an enrolment authorised by a re-authentication grant
CREATED_VIA = (OPERATOR, "passkey", SELF)
GRANT_TTL = 600  # the PKCE cookie's own lifetime
GRANT_KEEP_AFTER_EXPIRY = 24 * 60 * 60
REAUTH_SKEW = 120  # a sign-in counts as fresh when ``auth_time >= grant.created_at - REAUTH_SKEW``
GRANT_CLIENTS = ("web", "native")
GRANT_STATES = ("open", "fresh", "failed", "spent")
GRANT_FAILURES = ("provider_mismatch", "user_mismatch", "auth_time_missing", "auth_not_fresh")

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
CREATE TABLE IF NOT EXISTS reauth_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    client TEXT NOT NULL,
    secret_hash BLOB,
    state TEXT NOT NULL,
    failure TEXT NOT NULL DEFAULT '',
    auth_time INTEGER,
    auth_time_assumed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    completed_at INTEGER,
    spent_at INTEGER,
    credential_row INTEGER,
    use_secret_hash BLOB);
CREATE INDEX IF NOT EXISTS reauth_grants_expires ON reauth_grants (expires_at);
"""

# Columns added to a table that schema 1 created, without a version bump: each is nullable, so a build that
# does not know it inserts by named columns and leaves it NULL. Added once, guarded by ``PRAGMA table_info``.
_ADDED_COLUMNS = (("credentials", "usable_from", "INTEGER"), ("reauth_grants", "use_secret_hash", "BLOB"))


class StoreError(Exception):
    """The store cannot be used (unreadable, a newer schema, not a regular file)."""


class CodeInvalid(StoreError):
    """One answer for an unknown, expired, used or wrong-user enrolment code."""


class PendingInvalid(StoreError):
    """The registration or step-up id is unknown, expired, used, of another kind or of another user."""


class CredentialExists(StoreError):
    """The credential id is already stored (active or revoked)."""


class GrantInvalid(StoreError):
    """A re-authentication grant cannot be used or completed; nothing changed.

    Using one (:meth:`PasskeyStore.fresh_grant`, :meth:`PasskeyStore.add_credential`): ``reason`` is
    ``unknown`` (no such grant for this user, expired, or presented without its use binding),
    ``not_fresh`` (still open), ``spent`` or ``failed`` (then ``failure`` is one of :data:`GRANT_FAILURES`).
    Completing one (:meth:`PasskeyStore.complete_grant`): ``unknown`` (no such grant, expired, the other kind
    of client, or a web grant without its secret) or ``not_open`` (completed before; ``state`` says how)."""

    def __init__(self, reason: str, *, failure: str = "", state: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.failure = failure
        self.state = state


class CommitRefused(StoreError):
    """An assertion that verified cannot be committed. ``reason``: ``revoked`` (also unknown, another
    user, another key, or a credential still in its cooling-off period), ``counter_regression`` (against the value stored now), ``stepup_invalid`` (a
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
    usable_from: Optional[int] = None  # a self-enrolled credential's cooling-off end; None: usable at once

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def usable(self, now: int) -> bool:
        """Active and past any cooling-off period: may answer a ``confirm`` or sign a step-up."""
        return self.active and (self.usable_from is None or self.usable_from <= now)

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
class Grant:
    """A re-authentication grant. The hashes of its web secret and native use secret stay in the store."""
    id: str
    user_id: str  # "<provider>:<user id>" of the session that opened it
    provider: str
    client: str  # "web" | "native"
    state: str  # "open" | "fresh" | "failed" | "spent"
    failure: str  # with "failed": one of GRANT_FAILURES; "" otherwise
    auth_time: Optional[int]  # what the provider reported at completion (0: it did not say)
    auth_time_assumed: bool  # fresh only because the operator accepts a missing auth_time
    created_at: int
    expires_at: int
    completed_at: Optional[int]
    spent_at: Optional[int]
    credential_row: Optional[int]  # the credential it enrolled


def reauth_secret_hash(secret: str) -> bytes:
    """What the store keeps of a web grant's cookie secret."""
    return hashlib.sha256(secret.encode("utf-8")).digest()


def new_reauth_secret() -> str:
    """A web grant's cookie secret (32 random bytes, base64url)."""
    return b64u(secrets.token_bytes(32))


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
        last_used_at=row["last_used_at"], revoked_at=row["revoked_at"], revoked_by=row["revoked_by"],
        usable_from=row["usable_from"])


def _grant(row: sqlite3.Row) -> Grant:
    return Grant(id=row["id"], user_id=row["user_id"], provider=row["provider"], client=row["client"],
                 state=row["state"], failure=row["failure"], auth_time=row["auth_time"],
                 auth_time_assumed=bool(row["auth_time_assumed"]), created_at=row["created_at"],
                 expires_at=row["expires_at"], completed_at=row["completed_at"], spent_at=row["spent_at"],
                 credential_row=row["credential_row"])


def _use_binding_holds(row: sqlite3.Row, secret: Optional[str]) -> bool:
    """Whether *secret* is the grant's use binding: a ``web`` grant's cookie secret, or the ``use_secret`` a
    ``native`` grant was given when it was completed fresh (none before that)."""
    stored = row["secret_hash"] if row["client"] == "web" else row["use_secret_hash"]
    return isinstance(secret, str) and bool(secret) and stored is not None \
        and hmac.compare_digest(bytes(stored), reauth_secret_hash(secret))


def _grant_unusable(row: Optional[sqlite3.Row], *, user_id: str, now: int, secret: Optional[str]
                    ) -> Optional[GrantInvalid]:
    """Why *row* cannot authorise an enrolment for *user_id*, who presents *secret*, now (None when it can).
    Without the binding the answer is ``unknown`` whatever the state: the grant id alone (which can end up in
    an access log or the browser history) proves nothing and reveals nothing."""
    if row is None or row["user_id"] != user_id or row["expires_at"] <= now or not _use_binding_holds(row, secret):
        return GrantInvalid("unknown")  # one answer: nobody learns whether another user's grant exists
    if row["state"] == "open":
        return GrantInvalid("not_fresh")
    if row["state"] == "spent":
        return GrantInvalid("spent")
    if row["state"] != "fresh":
        return GrantInvalid("failed", failure=row["failure"])
    return None


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
            for table, column, declaration in _ADDED_COLUMNS:
                if column not in {c["name"] for c in db.execute(f"PRAGMA table_info({table})").fetchall()}:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
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

    def credentials(self, user_id: Optional[str] = None, *, include_revoked: bool = False,
                    usable_only: bool = False) -> list[CredentialRecord]:
        """Active credentials (with *include_revoked*, revoked ones too), cooling-off ones included with
        their ``usable_from``. *usable_only*: only those that may answer or sign a step-up now (active and
        past any cooling-off; it overrides *include_revoked*)."""
        sql = "SELECT * FROM credentials WHERE 1 = 1"
        args: list = []
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        if usable_only:
            sql += " AND revoked_at IS NULL AND (usable_from IS NULL OR usable_from <= ?)"
            args.append(self.now())
        elif not include_revoked:
            sql += " AND revoked_at IS NULL"
        with self._read() as db:
            return [_credential(r) for r in db.execute(sql + " ORDER BY id", args).fetchall()]

    def snapshot(self, user_id: str) -> tuple[StoredCredential, ...]:
        """*user_id*'s usable credentials as the verifier takes them when a request opens (a credential in
        its cooling-off period is not one: it is no ``confirm`` target and cannot sign a step-up)."""
        return tuple(c.stored() for c in self.credentials(user_id, usable_only=True))

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

    def add_credential(self, *, user_id: str, registration: RegistrationOk, code: Optional[str] = None,
                       grant_id: Optional[str] = None, grant_secret: Optional[str] = None,
                       usable_from: Optional[int] = None, created_ip: str = "") -> CredentialRecord:
        """Enrol: take the open registration *registration* was verified against (its id, user and nonce),
        redeem the authority, and store the credential, all or nothing. *user_id* is the signed-in caller.

        The authority is exactly one of *code* (an enrolment code; ``created_via`` is ``operator`` or
        ``passkey`` by who minted it) or *grant_id* with its *grant_secret* (a ``fresh`` re-authentication
        grant of *user_id* and its use binding: the web cookie secret or the native ``use_secret``, checked and
        spent here in one transaction; ``created_via`` is ``self``). *usable_from* (Unix seconds, ignored unless in the future) starts
        a cooling-off period: the credential is listed but not usable until then.

        Raises :class:`PendingInvalid`, :class:`CodeInvalid` / :class:`GrantInvalid` or
        :class:`CredentialExists` (checked in that order); on any of them nothing changes, so the person can
        try again while the registration is open (and a refused grant is not spent)."""
        if (code is None) == (grant_id is None):
            raise ValueError("exactly one of code or grant_id")
        now = self.now()
        with self._write() as db:
            if registration.user_id != user_id:
                raise PendingInvalid("the registration belongs to another user")
            pending = self._take_pending(db, registration.registration_id, kind="register", user_id=user_id,
                                         now=now, nonce=registration.nonce)
            if pending.rp_id != registration.rp_id:
                raise PendingInvalid("the registration was opened for another RP")
            if grant_id is not None:
                self._spend_grant(db, str(grant_id), user_id=user_id, now=now, secret=grant_secret)
                created_via = SELF
            else:
                created_via = self._redeem_code(db, str(code), user_id=user_id, now=now)
            if db.execute("SELECT 1 FROM credentials WHERE credential_id = ?",
                          (registration.credential_id,)).fetchone():
                raise CredentialExists("credential_exists")
            cooling = int(usable_from) if usable_from is not None and int(usable_from) > now else None
            cursor = db.execute(
                "INSERT INTO credentials (user_id, credential_id, rp_id, alg, public_key, sign_count,"
                " backup_eligible, backed_up, aaguid, transports, name, created_at, created_via, created_ip,"
                " usable_from) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, registration.credential_id, registration.rp_id, registration.alg,
                 registration.public_x + registration.public_y, registration.sign_count,
                 int(registration.backup_eligible), int(registration.backed_up), registration.aaguid,
                 json.dumps(list(registration.transports)), pending.subject, now, created_via, created_ip,
                 cooling))
            if grant_id is not None:
                db.execute("UPDATE reauth_grants SET credential_row = ? WHERE id = ?", (cursor.lastrowid, grant_id))
            return _credential(db.execute("SELECT * FROM credentials WHERE id = ?",
                                          (cursor.lastrowid,)).fetchone())

    @staticmethod
    def _redeem_code(db: sqlite3.Connection, code: str, *, user_id: str, now: int) -> str:
        """Mark the code used by *user_id*; returns the ``created_via`` it gives. Raises :class:`CodeInvalid`."""
        code_hash = enrolment_code_hash(code)
        invite = db.execute("SELECT * FROM invites WHERE code_hash = ?", (code_hash,)).fetchone() \
            if code_hash else None
        if invite is None or invite["used_at"] is not None or invite["expires_at"] <= now \
                or invite["user_id"] not in (None, user_id):
            raise CodeInvalid("code_invalid")
        if db.execute("UPDATE invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL",
                      (now, user_id, invite["id"])).rowcount != 1:
            raise CodeInvalid("code_invalid")
        return OPERATOR if invite["minted_by"] == OPERATOR else "passkey"

    @staticmethod
    def _spend_grant(db: sqlite3.Connection, grant_id: str, *, user_id: str, now: int, secret: Optional[str]
                     ) -> None:
        """Spend *user_id*'s fresh grant, whose use binding is *secret* (compare-and-set on its state). Raises
        :class:`GrantInvalid`."""
        row = db.execute("SELECT * FROM reauth_grants WHERE id = ?", (grant_id,)).fetchone()
        refusal = _grant_unusable(row, user_id=user_id, now=now, secret=secret)
        if refusal is not None:
            raise refusal
        if db.execute("UPDATE reauth_grants SET state = 'spent', spent_at = ? WHERE id = ? AND state = 'fresh'",
                      (now, grant_id)).rowcount != 1:
            raise GrantInvalid("spent")

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

    # ── re-authentication grants ─────────────────────────────────────────────────────────────────

    def open_grant(self, user_id: str, provider: str, client: str, secret_hash: Optional[bytes] = None
                   ) -> Grant:
        """Open a grant for the signed-in *user_id* (``<provider>:<user id>``) of *provider*, lifetime
        :data:`GRANT_TTL`. A ``web`` grant needs *secret_hash* (:func:`reauth_secret_hash` of the cookie
        secret); a ``native`` grant has none."""
        if client not in GRANT_CLIENTS:
            raise ValueError(f"unknown client {client!r}")
        if not str(user_id).strip() or not str(provider).strip():
            raise ValueError("empty user id or provider")
        if client == "web" and not (isinstance(secret_hash, bytes) and len(secret_hash) == 32):
            raise ValueError("a web grant needs the 32-byte hash of its secret")
        if client == "native" and secret_hash is not None:
            raise ValueError("a native grant has no secret")
        now = self.now()
        grant = Grant(id=b64u(secrets.token_bytes(16)), user_id=user_id, provider=provider, client=client,
                      state="open", failure="", auth_time=None, auth_time_assumed=False, created_at=now,
                      expires_at=now + GRANT_TTL, completed_at=None, spent_at=None, credential_row=None)
        with self._write() as db:
            db.execute("INSERT INTO reauth_grants (id, user_id, provider, client, secret_hash, state, created_at,"
                       " expires_at) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)",
                       (grant.id, user_id, provider, client, secret_hash, now, grant.expires_at))
        return grant

    def grant(self, grant_id: str, *, user_id: str) -> Optional[Grant]:
        """*user_id*'s grant in whatever state, or None (unknown, another user's, or expired)."""
        now = self.now()
        with self._read() as db:
            row = db.execute("SELECT * FROM reauth_grants WHERE id = ?", (str(grant_id),)).fetchone()
        if row is None or row["user_id"] != user_id or row["expires_at"] <= now:
            return None
        return _grant(row)

    def fresh_grant(self, grant_id: str, *, user_id: str, secret: Optional[str]) -> Grant:
        """The grant when it can authorise an enrolment for *user_id*, who presents its use binding *secret*,
        now (``fresh``, unexpired, unspent); nothing is taken. Raises :class:`GrantInvalid` with the reason
        otherwise (``unknown`` without the binding)."""
        now = self.now()
        with self._read() as db:
            row = db.execute("SELECT * FROM reauth_grants WHERE id = ?", (str(grant_id),)).fetchone()
        refusal = _grant_unusable(row, user_id=user_id, now=now, secret=secret)
        if refusal is not None:
            raise refusal
        return _grant(row)

    def grant_for_login(self, grant_id: str, provider: str, secret: Optional[str]) -> Optional[Grant]:
        """The open, unexpired grant for a sign-in with *provider*, or None. The binding must hold: a ``web``
        grant needs its *secret* (the cookie), a ``native`` grant takes none (its binding is the PKCE round
        trip). Nothing changes."""
        now = self.now()
        with self._read() as db:
            row = db.execute("SELECT * FROM reauth_grants WHERE id = ?", (str(grant_id),)).fetchone()
        if row is None or row["state"] != "open" or row["expires_at"] <= now or row["provider"] != provider \
                or not self._binding_holds(row, secret):
            return None
        return _grant(row)

    @staticmethod
    def _binding_holds(row: sqlite3.Row, secret: Optional[str]) -> bool:
        if row["client"] == "native":
            return secret is None
        stored = row["secret_hash"]
        return secret is not None and stored is not None \
            and hmac.compare_digest(bytes(stored), reauth_secret_hash(secret))

    def complete_grant(self, grant_id: str, *, session_user: str, session_provider: str, auth_time: Optional[int],
                       client: str, secret: Optional[str] = None, use_secret_hash: Optional[bytes] = None,
                       now: Optional[int] = None, accept_missing: bool = False) -> Grant:
        """The one transition out of ``open``: the sign-in the grant asked for came back as *session_user*
        (``<provider>:<user id>``) of *session_provider*, who authenticated at *auth_time* (0 or None: the
        provider did not say). *client* is how it came back (``web``: the callback, with the cookie *secret*,
        which stays the grant's use binding; ``native``: the token route, with *use_secret_hash*, the hash of the
        ``use_secret`` handed to the app with the answer, stored only when the grant turns fresh). Returns the
        grant, now ``fresh`` or ``failed`` with its ``failure``:

        ``provider_mismatch``, ``user_mismatch`` (checked in that order), then ``auth_time_missing`` (unless
        *accept_missing*: then fresh with ``auth_time_assumed``) or ``auth_not_fresh`` (``auth_time <
        created_at - REAUTH_SKEW``).

        Raises :class:`GrantInvalid` and changes nothing when there is no such unexpired grant, when it comes
        back over the other kind of client or a web grant's *secret* does not match (whoever lacks the binding
        can neither complete nor fail the grant: ``unknown``), or when it was completed before
        (``not_open``)."""
        if client not in GRANT_CLIENTS:
            raise ValueError(f"unknown client {client!r}")
        if client == "native" and not (isinstance(use_secret_hash, bytes) and len(use_secret_hash) == 32):
            raise ValueError("a native completion needs the 32-byte hash of the use secret it hands out")
        now = self.now() if now is None else int(now)
        with self._write() as db:
            row = db.execute("SELECT * FROM reauth_grants WHERE id = ?", (str(grant_id),)).fetchone()
            if row is None or row["expires_at"] <= now or client != row["client"] \
                    or (row["client"] == "web" and not self._binding_holds(row, secret)):
                raise GrantInvalid("unknown")
            if row["state"] != "open":
                raise GrantInvalid("not_open", state=row["state"])
            assumed = False
            if session_provider != row["provider"]:
                failure = "provider_mismatch"
            elif session_user != row["user_id"]:
                failure = "user_mismatch"
            elif not auth_time or int(auth_time) <= 0:
                failure, assumed = ("", True) if accept_missing else ("auth_time_missing", False)
            elif int(auth_time) < row["created_at"] - REAUTH_SKEW:
                failure = "auth_not_fresh"
            else:
                failure = ""
            state = "failed" if failure else "fresh"
            reported = int(auth_time) if auth_time else 0
            use_hash = use_secret_hash if state == "fresh" and client == "native" else None
            if db.execute("UPDATE reauth_grants SET state = ?, failure = ?, auth_time = ?, auth_time_assumed = ?,"
                          " completed_at = ?, use_secret_hash = ? WHERE id = ? AND state = 'open'",
                          (state, failure, reported, int(assumed), now, use_hash, row["id"])).rowcount != 1:
                raise GrantInvalid("not_open")
            return _grant(db.execute("SELECT * FROM reauth_grants WHERE id = ?", (row["id"],)).fetchone())

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
            if current is None or not current.usable(now) or current.user_id != user_id \
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
        """Drop receipts older than *receipts_days*, codes and grants a day after they expired, closed
        pendings."""
        now = self.now()
        with self._write() as db:
            return {
                "receipts": db.execute("DELETE FROM receipts WHERE at < ?",
                                       (now - int(receipts_days) * 86400,)).rowcount,
                "invites": db.execute("DELETE FROM invites WHERE expires_at < ?",
                                      (now - INVITE_KEEP_AFTER_EXPIRY,)).rowcount,
                "pending": db.execute("DELETE FROM pending WHERE expires_at <= ?", (now,)).rowcount,
                "grants": db.execute("DELETE FROM reauth_grants WHERE expires_at < ?",
                                     (now - GRANT_KEEP_AFTER_EXPIRY,)).rowcount,
            }

    def counts(self) -> dict[str, int]:
        now = self.now()
        with self._read() as db:
            def one(sql: str, *args) -> int:
                return int(db.execute(sql, args).fetchone()[0])
            return {
                "credentials": one("SELECT COUNT(*) FROM credentials WHERE revoked_at IS NULL"),
                "cooling_off": one("SELECT COUNT(*) FROM credentials WHERE revoked_at IS NULL AND usable_from > ?",
                                   now),
                "revoked": one("SELECT COUNT(*) FROM credentials WHERE revoked_at IS NOT NULL"),
                "users": one("SELECT COUNT(DISTINCT user_id) FROM credentials WHERE revoked_at IS NULL"),
                "open_codes": one("SELECT COUNT(*) FROM invites WHERE used_at IS NULL AND expires_at > ?", now),
                "receipts": one("SELECT COUNT(*) FROM receipts"),
                "open_grants": one("SELECT COUNT(*) FROM reauth_grants WHERE state IN ('open', 'fresh')"
                                   " AND expires_at > ?", now),
            }
