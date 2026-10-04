"""The MCP grant registry: one SQLite file the gateway and the operator CLI share.

``$HERMES_HOME/dashboard_auth/mcp.db`` (directory 0700, file 0600, WAL), modelled on the passkey store.
It holds the clients registered through DCR (the secret as SHA-256 only), the open consent
transactions, the authorization codes, the grants (one per consent: who, which client, from where, last
used, until when), the access and refresh tokens of each grant, and the chats a person opened through
MCP. Codes and tokens are stored as SHA-256 of the value handed out, never the value.

Every state change is one ``BEGIN IMMEDIATE`` transaction, so the rules hold across connections and
processes (the CLI revokes while the gateway mints):

- a consent transaction is taken at most once, with its nonce, before it expires; a refusal leaves it
  open (the person can revoke a grant and press Allow again);
- a code is taken at most once (:meth:`MCPStore.take_code` marks it used before the caller checks the
  PKCE verifier, so a failed check burns it); a code presented again revokes the grant it minted, and is
  marked reused so that a grant not minted yet (the taker's exchange still running) never will be; the
  grant and its token family are minted together, once, by :meth:`MCPStore.exchange_code`;
- a person holds at most ``max_grants`` live grants, checked inside the transaction that would add one;
- a refresh token is rotated at most once; a rotated token presented again revokes its grant (reuse
  detection), whether at load or at rotation -- except a parallel refresh (:data:`REFRESH_RACE_GRACE`):
  the same client presenting it less than 30 s after it was rotated, while the token that replaced it has
  not been used, is refused without revoking anything;
- revoking a grant revokes every token of it.

A grant is *live* while it is not revoked, its absolute lifetime has not passed and it has at least one
unrevoked, unrotated, unexpired token (a grant nobody refreshed for the sliding lifetime is dead even
before it expires, and does not count against the person's cap).

Time comes from the ``clock`` given to the store, in whole Unix seconds. Every failure is a
:class:`StoreError` (database and file errors included).
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
from typing import Any, Callable, Iterator, Optional

SCHEMA_VERSION = 1
FILE_NAME = "mcp.db"
BUSY_TIMEOUT_S = 5.0

# ``grants.revoked_by``: who ended a grant. A person's own revoke stores their ``<provider>:<user id>``.
OPERATOR = "operator"
BY_CLIENT = "client"  # the client's own RFC 7009 revocation
BY_CODE_REUSE = "code_reuse"
BY_REFRESH_REUSE = "refresh_reuse"

CONSENT_TTL = 600
CONSENTS_PER_ADDRESS = 8
CONSENTS_TOTAL = 256
CODE_TTL = 120
CLIENTS_MAX = 500
CLIENT_UNUSED_TTL = 24 * 3600  # a registration without a grant this long after it is pruned
METADATA_MAX_BYTES = 8 * 1024
LAST_USED_EVERY = 60  # ``grants.last_used_*`` is written at most once a minute per grant
# A client that refreshes twice in parallel with one refresh token (two requests that each found their
# access token expired) is not a thief: within this many seconds of the rotation, by the same client, while
# the successor refresh token is unused, the late request is refused (``raced``) and the grant stays.
REFRESH_RACE_GRACE = 30
TOKEN_KEEP_AFTER_EXPIRY = 7 * 86400
GRANT_KEEP_AFTER_END = 90 * 86400
CHAT_IDLE_KEEP = 180 * 86400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash BLOB,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_ip TEXT NOT NULL,
    last_used_at INTEGER);
CREATE TABLE IF NOT EXISTS consents (
    txn_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    params TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_ip TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS consents_expires ON consents (expires_at);
CREATE TABLE IF NOT EXISTS codes (
    code_hash BLOB PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    provider TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    grant_id TEXT,
    reused_at INTEGER);
CREATE INDEX IF NOT EXISTS codes_expires ON codes (expires_at);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    provider TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_name TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_ip TEXT NOT NULL,
    created_user_agent TEXT NOT NULL,
    last_used_at INTEGER,
    last_used_ip TEXT,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_by TEXT,
    resource TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS grants_user ON grants (user_id);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash BLOB PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    grant_id TEXT NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    family TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    rotated_at INTEGER,
    revoked_at INTEGER,
    scopes TEXT NOT NULL,
    parent_hash BLOB);
CREATE INDEX IF NOT EXISTS tokens_grant ON tokens (grant_id);
CREATE TABLE IF NOT EXISTS mcp_chats (
    user_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    session_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    opened_by_grant TEXT NOT NULL,
    PRIMARY KEY (user_id, profile, session_key))
"""

# A grant that can still be used: not revoked, not past its absolute lifetime, and holding a token that
# is neither revoked, rotated nor expired. ``g`` is the grants row; ``:now`` the store's time.
_LIVE = ("(g.revoked_at IS NULL AND g.expires_at > :now AND EXISTS (SELECT 1 FROM tokens t WHERE "
         "t.grant_id = g.id AND t.revoked_at IS NULL AND t.rotated_at IS NULL AND t.expires_at > :now))")


# Columns added after a file may have been created; ``_create`` adds any that are missing (additive only, so
# the schema version stays and an older build still reads the file). ``tokens.parent_hash``: the refresh
# token a rotation replaced (its successor's link back, for :data:`REFRESH_RACE_GRACE`); ``codes.reused_at``:
# when a taken code was presented again (its exchange is then refused).
_ADDED_COLUMNS = (("tokens", "parent_hash", "BLOB"), ("codes", "reused_at", "INTEGER"))


class StoreError(Exception):
    """The store cannot be used (unreadable, a newer schema, not a regular file), or a rule refused."""


class LimitReached(StoreError):
    """A cap is full. ``reason``: ``clients_full`` (CLIENTS_MAX registrations), ``consents_full``
    (CONSENTS_TOTAL open consents), ``consents_per_address`` (CONSENTS_PER_ADDRESS from one address) or
    ``grants_per_user`` (the person holds ``max_grants`` live grants)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ConsentInvalid(StoreError):
    """The consent transaction is unknown, expired, already decided, of a vanished client, or the nonce
    does not match."""


class CodeInvalid(StoreError):
    """The taken code cannot be exchanged (not taken by this caller, already exchanged, presented again
    since it was taken, client gone)."""


class TokenInvalid(StoreError):
    """A refresh token cannot be rotated. ``reason``: ``unknown``, ``expired``, ``revoked`` (the token or
    its grant), ``client`` (another client's), ``scope`` (asks for more than the token holds) or
    ``reused`` (rotated before: the grant has now been revoked) or ``raced`` (rotated moments ago by a
    parallel refresh of the same client: refused, nothing revoked)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    client_secret_hash: Optional[bytes]
    client_name: str
    redirect_uris: tuple[str, ...]
    token_endpoint_auth_method: str
    metadata: dict
    created_at: int
    created_ip: str
    last_used_at: Optional[int]


@dataclass(frozen=True)
class Consent:
    txn_id: str
    client_id: str
    params: dict  # scopes, code_challenge, redirect_uri, redirect_uri_provided_explicitly, resource, state
    nonce: str
    created_at: int
    expires_at: int
    created_ip: str


@dataclass(frozen=True)
class TakenCode:
    """A code marked used by :meth:`MCPStore.take_code`, carrying what the exchange needs."""
    code_hash: bytes
    grant_id: str  # the id the exchange will give the grant (reserved when the code was taken)
    client_id: str
    user_id: str
    user_name: str
    provider: str
    scopes: tuple[str, ...]
    code_challenge: str
    redirect_uri: str
    resource: str
    created_at: int
    expires_at: int


@dataclass(frozen=True)
class Grant:
    id: str
    user_id: str  # ``<provider>:<user id>``
    user_name: str
    provider: str
    client_id: str
    client_name: str
    scopes: tuple[str, ...]
    created_at: int
    created_ip: str
    created_user_agent: str
    last_used_at: Optional[int]
    last_used_ip: Optional[str]
    expires_at: int
    revoked_at: Optional[int]
    revoked_by: Optional[str]
    resource: str
    live: bool


@dataclass(frozen=True)
class Issued:
    """A token pair handed out once; only the hashes stay in the store."""
    grant: Grant
    issued_at: int
    access_token: str
    access_expires_at: int
    refresh_token: str
    refresh_expires_at: int
    scopes: tuple[str, ...]  # of the access token


@dataclass(frozen=True)
class TokenGrant:
    """A token that verified, with the grant it belongs to."""
    kind: str
    scopes: tuple[str, ...]
    expires_at: int
    family: str
    grant: Grant


@dataclass(frozen=True)
class Chat:
    user_id: str
    profile: str
    session_key: str
    created_at: int
    last_used_at: int
    opened_by_grant: str


def default_path() -> Path:
    from hermes_constants import get_hermes_home
    return get_hermes_home() / "dashboard_auth" / FILE_NAME


def hash_secret(value: str) -> bytes:
    """SHA-256 of a code, token or client secret: what the store keeps instead of the value."""
    return hashlib.sha256(value.encode("utf-8")).digest()


def _new_secret() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def _new_id() -> str:
    return secrets.token_urlsafe(18)


def _scopes(text: str) -> tuple[str, ...]:
    return tuple(s for s in text.split(" ") if s)


def _client(row: sqlite3.Row) -> ClientRecord:
    secret_hash = row["client_secret_hash"]
    return ClientRecord(
        client_id=row["client_id"], client_secret_hash=bytes(secret_hash) if secret_hash is not None else None,
        client_name=row["client_name"], redirect_uris=tuple(json.loads(row["redirect_uris"])),
        token_endpoint_auth_method=row["token_endpoint_auth_method"], metadata=json.loads(row["metadata"]),
        created_at=row["created_at"], created_ip=row["created_ip"], last_used_at=row["last_used_at"])


def _consent(row: sqlite3.Row) -> Consent:
    return Consent(txn_id=row["txn_id"], client_id=row["client_id"], params=json.loads(row["params"]),
                   nonce=row["nonce"], created_at=row["created_at"], expires_at=row["expires_at"],
                   created_ip=row["created_ip"])


def _grant(row: sqlite3.Row) -> Grant:
    return Grant(
        id=row["id"], user_id=row["user_id"], user_name=row["user_name"], provider=row["provider"],
        client_id=row["client_id"], client_name=row["client_name"], scopes=_scopes(row["scopes"]),
        created_at=row["created_at"], created_ip=row["created_ip"], created_user_agent=row["created_user_agent"],
        last_used_at=row["last_used_at"], last_used_ip=row["last_used_ip"], expires_at=row["expires_at"],
        revoked_at=row["revoked_at"], revoked_by=row["revoked_by"], resource=row["resource"],
        live=bool(row["live"]))


def _chat(row: sqlite3.Row) -> Chat:
    return Chat(user_id=row["user_id"], profile=row["profile"], session_key=row["session_key"],
                created_at=row["created_at"], last_used_at=row["last_used_at"],
                opened_by_grant=row["opened_by_grant"])


class MCPStore:
    """Open with a path (tests) or :meth:`default` (``$HERMES_HOME``). Cheap to construct: the file is
    created on first use. Safe to share between threads (one connection per operation) and between
    processes (SQLite locking, ``BEGIN IMMEDIATE`` for every write)."""

    def __init__(self, path: Path | str, *, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._clock = clock
        self._ready = False

    @classmethod
    def default(cls, **kwargs) -> "MCPStore":
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
            # Removed under a running process (an operator reset): start over with a new file rather than
            # let SQLite recreate it with default permissions and no tables.
            self._ready = False
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
            for table, column, kind in _ADDED_COLUMNS:
                if column not in {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
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
        try:
            yield
        except StoreError:
            raise
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise StoreError(f"mcp store: {exc}") from exc

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
                    raise StoreError(f"mcp store: {exc}") from exc
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

    # ── helpers inside a transaction ─────────────────────────────────────────────────────────────

    @staticmethod
    def _grant_row(db: sqlite3.Connection, grant_id: str, now: int) -> Optional[Grant]:
        row = db.execute(f"SELECT g.*, {_LIVE} AS live FROM grants g WHERE g.id = :id",
                         {"id": grant_id, "now": now}).fetchone()
        return _grant(row) if row else None

    @staticmethod
    def _live_grants(db: sqlite3.Connection, user_id: str, now: int) -> int:
        return int(db.execute(f"SELECT COUNT(*) FROM grants g WHERE g.user_id = :user AND {_LIVE}",
                              {"user": user_id, "now": now}).fetchone()[0])

    @staticmethod
    def _revoke(db: sqlite3.Connection, grant_id: str, by: str, now: int) -> bool:
        """Revoke the grant and every token of it; True when the grant was not revoked before."""
        changed = db.execute("UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL",
                             (now, by, grant_id)).rowcount == 1
        db.execute("UPDATE tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL", (now, grant_id))
        return changed

    @staticmethod
    def _mint(db: sqlite3.Connection, *, grant_id: str, family: str, now: int, ends_at: int,
              access_scopes: tuple[str, ...], refresh_scopes: tuple[str, ...], access_ttl: int,
              refresh_ttl: int, parent_hash: Optional[bytes] = None) -> tuple[str, int, str, int]:
        access, refresh = _new_secret(), _new_secret()
        access_exp = min(now + int(access_ttl), ends_at)
        refresh_exp = min(now + int(refresh_ttl), ends_at)
        for value, kind, expires_at, scopes, parent in (
                (access, "access", access_exp, access_scopes, None),
                (refresh, "refresh", refresh_exp, refresh_scopes, parent_hash)):
            db.execute("INSERT INTO tokens (token_hash, kind, grant_id, family, created_at, expires_at, scopes, "
                       "parent_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (hash_secret(value), kind, grant_id, family, now, expires_at, " ".join(scopes), parent))
        return access, access_exp, refresh, refresh_exp

    @staticmethod
    def _raced(db: sqlite3.Connection, row: sqlite3.Row, client_id: str, now: int) -> bool:
        """True when the rotated refresh token *row*, presented by *client_id*, is a parallel refresh rather
        than a reuse: rotated less than REFRESH_RACE_GRACE seconds ago, of a grant of that client, and the
        refresh token that replaced it has been neither rotated nor revoked since."""
        if row["rotated_at"] is None or now - int(row["rotated_at"]) >= REFRESH_RACE_GRACE:
            return False
        if db.execute("SELECT 1 FROM grants WHERE id = ? AND client_id = ? AND revoked_at IS NULL",
                      (row["grant_id"], client_id)).fetchone() is None:
            return False
        return db.execute("SELECT 1 FROM tokens WHERE parent_hash = ? AND kind = 'refresh' AND rotated_at IS NULL "
                          "AND revoked_at IS NULL", (bytes(row["token_hash"]),)).fetchone() is not None

    # ── clients (RFC 7591) ───────────────────────────────────────────────────────────────────────

    def add_client(self, *, client_id: str, client_secret: Optional[str], client_name: str,
                   redirect_uris: list[str], token_endpoint_auth_method: str, metadata: dict,
                   created_ip: str = "") -> ClientRecord:
        """Store a registration (the secret as its hash). Refuses metadata over METADATA_MAX_BYTES
        (``ValueError``) and a full registry (:class:`LimitReached` ``clients_full``, after dropping
        registrations that never got a grant within CLIENT_UNUSED_TTL)."""
        text = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
        if len(text.encode("utf-8")) > METADATA_MAX_BYTES:
            raise ValueError("client metadata is larger than 8 KiB")
        now = self.now()
        with self._write() as db:
            if int(db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]) >= CLIENTS_MAX:
                self._prune_clients(db, now)
                if int(db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]) >= CLIENTS_MAX:
                    raise LimitReached("clients_full")
            db.execute(
                "INSERT INTO clients (client_id, client_secret_hash, client_name, redirect_uris, "
                "token_endpoint_auth_method, metadata, created_at, created_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (client_id, hash_secret(client_secret) if client_secret else None, client_name,
                 json.dumps(list(redirect_uris)), token_endpoint_auth_method, text, now, created_ip or ""))
            return _client(db.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone())

    def client(self, client_id: str) -> Optional[ClientRecord]:
        with self._read() as db:
            row = db.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return _client(row) if row else None

    def client_secret_matches(self, client_id: str, client_secret: str) -> bool:
        """True when *client_secret* is the secret registered for *client_id* (hash, constant-time)."""
        record = self.client(client_id)
        if record is None or record.client_secret_hash is None or not client_secret:
            return False
        return hmac.compare_digest(record.client_secret_hash, hash_secret(client_secret))

    # ── consent transactions ─────────────────────────────────────────────────────────────────────

    def open_consent(self, *, client_id: str, params: dict, created_ip: str = "") -> Consent:
        """Open a consent transaction for the person to decide on (CONSENT_TTL). Caps: CONSENTS_TOTAL
        open, CONSENTS_PER_ADDRESS from one known address (:class:`LimitReached`)."""
        now = self.now()
        with self._write() as db:
            if db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone() is None:
                raise ConsentInvalid("unknown client")
            db.execute("DELETE FROM consents WHERE expires_at <= ?", (now,))
            if int(db.execute("SELECT COUNT(*) FROM consents").fetchone()[0]) >= CONSENTS_TOTAL:
                raise LimitReached("consents_full")
            if created_ip and int(db.execute("SELECT COUNT(*) FROM consents WHERE created_ip = ?",
                                             (created_ip,)).fetchone()[0]) >= CONSENTS_PER_ADDRESS:
                raise LimitReached("consents_per_address")
            consent = Consent(txn_id=_new_secret(), client_id=client_id, params=dict(params), nonce=_new_secret(),
                              created_at=now, expires_at=now + CONSENT_TTL, created_ip=created_ip or "")
            db.execute("INSERT INTO consents (txn_id, client_id, params, nonce, created_at, expires_at, created_ip) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (consent.txn_id, client_id, json.dumps(consent.params, sort_keys=True), consent.nonce, now,
                        consent.expires_at, consent.created_ip))
            return consent

    def consent(self, txn_id: str) -> Optional[Consent]:
        """The open, unexpired transaction, or None."""
        if not txn_id:
            return None
        with self._read() as db:
            row = db.execute("SELECT * FROM consents WHERE txn_id = ? AND expires_at > ?",
                             (txn_id, self.now())).fetchone()
        return _consent(row) if row else None

    def _take_consent(self, db: sqlite3.Connection, txn_id: str, nonce: str, now: int) -> Consent:
        row = db.execute("SELECT * FROM consents WHERE txn_id = ?", (txn_id or "",)).fetchone()
        if row is None or row["expires_at"] <= now or not nonce \
                or not hmac.compare_digest(row["nonce"].encode(), nonce.encode()):
            raise ConsentInvalid("consent_invalid")
        if db.execute("DELETE FROM consents WHERE txn_id = ?", (txn_id,)).rowcount != 1:
            raise ConsentInvalid("consent_invalid")
        return _consent(row)

    def issue_code(self, *, txn_id: str, nonce: str, user_id: str, user_name: str, provider: str,
                   max_grants: int) -> tuple[str, Consent]:
        """The person allowed: take the transaction and mint a code (CODE_TTL) bound to its client, PKCE
        challenge, redirect URI, resource and scopes and to the person. Returns ``(code, consent)``; the
        code is handed out once and stored as its hash.

        Raises :class:`ConsentInvalid`, or :class:`LimitReached` ``grants_per_user`` when the person
        already holds *max_grants* live grants (the transaction stays open)."""
        if not user_id:
            raise ConsentInvalid("no_identity")
        now = self.now()
        with self._write() as db:
            consent = self._take_consent(db, txn_id, nonce, now)
            if db.execute("SELECT 1 FROM clients WHERE client_id = ?", (consent.client_id,)).fetchone() is None:
                raise ConsentInvalid("unknown client")
            if self._live_grants(db, user_id, now) >= int(max_grants):
                raise LimitReached("grants_per_user")
            p = consent.params
            code = _new_secret()
            db.execute(
                "INSERT INTO codes (code_hash, client_id, user_id, user_name, provider, scopes, code_challenge, "
                "redirect_uri, resource, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (hash_secret(code), consent.client_id, user_id, user_name or "", provider or "",
                 " ".join(p["scopes"]), p["code_challenge"], p["redirect_uri"], p["resource"], now,
                 now + CODE_TTL))
            return code, consent

    def deny_consent(self, *, txn_id: str, nonce: str) -> Consent:
        """The person refused: take the transaction (:class:`ConsentInvalid` as for :meth:`issue_code`)."""
        now = self.now()
        with self._write() as db:
            return self._take_consent(db, txn_id, nonce, now)

    # ── codes and grants ─────────────────────────────────────────────────────────────────────────

    def take_code(self, code: str, *, client_id: str) -> Optional[TakenCode]:
        """Mark the code used and return it for the exchange, or None. Any presentation consumes it (a
        code presented by another client, or after it expired, is burnt as well). A code presented again
        after it was taken is marked reused (:meth:`exchange_code` then refuses it, so a grant its taker
        has not minted yet never is), revokes the grant it minted if there is one (``code_reuse``), and
        returns None."""
        if not code:
            return None
        code_hash = hash_secret(code)
        now = self.now()
        with self._write() as db:
            row = db.execute("SELECT * FROM codes WHERE code_hash = ?", (code_hash,)).fetchone()
            if row is None or not hmac.compare_digest(bytes(row["code_hash"]), code_hash):
                return None
            if row["used_at"] is not None:
                db.execute("UPDATE codes SET reused_at = ? WHERE code_hash = ? AND reused_at IS NULL", (now, code_hash))
                if row["grant_id"]:
                    self._revoke(db, row["grant_id"], BY_CODE_REUSE, now)
                return None
            grant_id = _new_id()
            db.execute("UPDATE codes SET used_at = ?, grant_id = ? WHERE code_hash = ? AND used_at IS NULL",
                       (now, grant_id, code_hash))
            if row["expires_at"] <= now or row["client_id"] != client_id:
                return None
            return TakenCode(
                code_hash=code_hash, grant_id=grant_id, client_id=row["client_id"], user_id=row["user_id"],
                user_name=row["user_name"], provider=row["provider"], scopes=_scopes(row["scopes"]),
                code_challenge=row["code_challenge"], redirect_uri=row["redirect_uri"], resource=row["resource"],
                created_at=row["created_at"], expires_at=row["expires_at"])

    def exchange_code(self, *, code: str, grant_id: str, client_id: str, access_ttl: int, refresh_ttl: int,
                      grant_max_age: int, max_grants: int, created_ip: str = "",
                      created_user_agent: str = "") -> Issued:
        """Mint the grant and its token family for a code :meth:`take_code` returned (*grant_id* is the id
        it reserved), in one transaction. Everything the grant holds is read from the stored code, not
        from the caller.

        Raises :class:`CodeInvalid` (not taken, taken by another call, exchanged before, presented again
        since it was taken, another client's, the client gone) or :class:`LimitReached` ``grants_per_user`` (re-checked here: two consents may
        have raced)."""
        now = self.now()
        with self._write() as db:
            row = db.execute("SELECT * FROM codes WHERE code_hash = ?", (hash_secret(code or ""),)).fetchone()
            if row is None or row["used_at"] is None or not grant_id or row["grant_id"] != grant_id \
                    or row["client_id"] != client_id or row["reused_at"] is not None:
                raise CodeInvalid("code_invalid")
            if db.execute("SELECT 1 FROM grants WHERE id = ?", (grant_id,)).fetchone() is not None:
                raise CodeInvalid("code_invalid")
            client = db.execute("SELECT client_name FROM clients WHERE client_id = ?", (client_id,)).fetchone()
            if client is None:
                raise CodeInvalid("unknown client")
            if self._live_grants(db, row["user_id"], now) >= int(max_grants):
                raise LimitReached("grants_per_user")
            scopes = _scopes(row["scopes"])
            ends_at = now + int(grant_max_age)
            db.execute(
                "INSERT INTO grants (id, user_id, user_name, provider, client_id, client_name, scopes, created_at, "
                "created_ip, created_user_agent, expires_at, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (grant_id, row["user_id"], row["user_name"], row["provider"], client_id, client["client_name"],
                 row["scopes"], now, created_ip or "", (created_user_agent or "")[:256], ends_at, row["resource"]))
            access, access_exp, refresh, refresh_exp = self._mint(
                db, grant_id=grant_id, family=_new_id(), now=now, ends_at=ends_at, access_scopes=scopes,
                refresh_scopes=scopes, access_ttl=access_ttl, refresh_ttl=refresh_ttl)
            db.execute("UPDATE clients SET last_used_at = ? WHERE client_id = ?", (now, client_id))
            grant = self._grant_row(db, grant_id, now)
            assert grant is not None
            return Issued(grant=grant, issued_at=now, access_token=access, access_expires_at=access_exp,
                          refresh_token=refresh, refresh_expires_at=refresh_exp, scopes=scopes)

    # ── tokens ───────────────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _token_row(db: sqlite3.Connection, token: str, kind: str) -> Optional[sqlite3.Row]:
        token_hash = hash_secret(token)
        row = db.execute("SELECT * FROM tokens WHERE token_hash = ? AND kind = ?", (token_hash, kind)).fetchone()
        if row is None or not hmac.compare_digest(bytes(row["token_hash"]), token_hash):
            return None
        return row

    def load_refresh(self, token: str, *, client_id: str) -> Optional[TokenGrant]:
        """The refresh token if it can be rotated by *client_id*, else None. A rotated token presented
        again revokes its grant (``refresh_reuse``), unless it is a parallel refresh (:meth:`_raced`)."""
        if not token:
            return None
        now = self.now()
        with self._write() as db:
            row = self._token_row(db, token, "refresh")
            if row is None:
                return None
            if row["rotated_at"] is not None:
                if not self._raced(db, row, client_id, now):
                    self._revoke(db, row["grant_id"], BY_REFRESH_REUSE, now)
                return None
            grant = self._grant_row(db, row["grant_id"], now)
            if grant is None or grant.client_id != client_id or row["revoked_at"] is not None \
                    or row["expires_at"] <= now or grant.revoked_at is not None or grant.expires_at <= now:
                return None
            return TokenGrant(kind="refresh", scopes=_scopes(row["scopes"]), expires_at=row["expires_at"],
                              family=row["family"], grant=grant)

    def rotate_refresh(self, token: str, *, client_id: str, scopes: Optional[list[str]], access_ttl: int,
                       refresh_ttl: int) -> Issued:
        """Rotate: the presented refresh token is spent, a new access token (with *scopes*, a subset of the
        token's; None = all of them) and a new refresh token (the token's scopes, the sliding lifetime
        again, never past the grant's end) are minted in the same family.

        Raises :class:`TokenInvalid`; with ``reused`` the grant has been revoked (and that is committed); with
        ``raced`` (a parallel refresh, :meth:`_raced`) nothing changed."""
        now = self.now()
        reused = False
        with self._write() as db:
            row = self._token_row(db, token, "refresh") if token else None
            if row is None:
                raise TokenInvalid("unknown")
            if row["rotated_at"] is not None:
                if self._raced(db, row, client_id, now):
                    raise TokenInvalid("raced")
                self._revoke(db, row["grant_id"], BY_REFRESH_REUSE, now)
                reused = True
            else:
                grant = self._grant_row(db, row["grant_id"], now)
                if grant is None or grant.client_id != client_id:
                    raise TokenInvalid("client")
                if row["revoked_at"] is not None or grant.revoked_at is not None:
                    raise TokenInvalid("revoked")
                if row["expires_at"] <= now or grant.expires_at <= now:
                    raise TokenInvalid("expired")
                held = _scopes(row["scopes"])
                wanted = tuple(scopes) if scopes else held
                if not set(wanted) <= set(held):
                    raise TokenInvalid("scope")
                if db.execute("UPDATE tokens SET rotated_at = ? WHERE token_hash = ? AND rotated_at IS NULL",
                              (now, row["token_hash"])).rowcount != 1:
                    raise TokenInvalid("unknown")
                access, access_exp, refresh, refresh_exp = self._mint(
                    db, grant_id=grant.id, family=row["family"], now=now, ends_at=grant.expires_at,
                    access_scopes=wanted, refresh_scopes=held, access_ttl=access_ttl, refresh_ttl=refresh_ttl,
                    parent_hash=bytes(row["token_hash"]))
                db.execute("UPDATE clients SET last_used_at = ? WHERE client_id = ?", (now, grant.client_id))
                after = self._grant_row(db, grant.id, now)
                assert after is not None
                return Issued(grant=after, issued_at=now, access_token=access, access_expires_at=access_exp,
                              refresh_token=refresh, refresh_expires_at=refresh_exp, scopes=wanted)
        if reused:
            raise TokenInvalid("reused")
        raise TokenInvalid("unknown")  # unreachable

    def verify_access(self, token: str, *, ip: str = "") -> Optional[TokenGrant]:
        """The access token if it is valid now (known, unrevoked, unexpired, its grant unrevoked and within
        its lifetime), else None. Records the use on the grant (``last_used_at`` / ``last_used_ip``) at
        most once every LAST_USED_EVERY seconds."""
        if not token:
            return None
        now = self.now()
        with self._read() as db:
            row = self._token_row(db, token, "access")
            if row is None or row["revoked_at"] is not None or row["expires_at"] <= now:
                return None
            grant = self._grant_row(db, row["grant_id"], now)
            if grant is None or grant.revoked_at is not None or grant.expires_at <= now:
                return None
            found = TokenGrant(kind="access", scopes=_scopes(row["scopes"]), expires_at=row["expires_at"],
                               family=row["family"], grant=grant)
        if grant.last_used_at is None or grant.last_used_at <= now - LAST_USED_EVERY:
            with self._write() as db:
                db.execute("UPDATE grants SET last_used_at = ?, last_used_ip = ? WHERE id = ? AND "
                           "(last_used_at IS NULL OR last_used_at <= ?)",
                           (now, ip or "", grant.id, now - LAST_USED_EVERY))
        return found

    # ── grants ───────────────────────────────────────────────────────────────────────────────────

    def grant(self, grant_id: str) -> Optional[Grant]:
        with self._read() as db:
            return self._grant_row(db, grant_id, self.now())

    def grants(self, user_id: Optional[str] = None, *, include_inactive: bool = False) -> list[Grant]:
        """Grants, newest first: live ones only unless *include_inactive*; of *user_id* when given."""
        sql = f"SELECT g.*, {_LIVE} AS live FROM grants g WHERE 1 = 1"
        args: dict[str, Any] = {"now": self.now()}
        if user_id is not None:
            sql += " AND g.user_id = :user"
            args["user"] = user_id
        if not include_inactive:
            sql += f" AND {_LIVE}"
        with self._read() as db:
            return [_grant(r) for r in db.execute(sql + " ORDER BY g.created_at DESC, g.id", args).fetchall()]

    def grants_for(self, user_id: str) -> list[Grant]:
        """*user_id*'s live grants, newest first (what Settings › MCP lists)."""
        return self.grants(user_id) if user_id else []

    def revoke_grant(self, grant_id: str, *, by: str, user_id: Optional[str] = None,
                     live_only: bool = False) -> Optional[Grant]:
        """Revoke the grant and every token of it. With *user_id*, only that person's grant; with
        *live_only*, only a grant that is live now (not revoked, not ended). Returns the grant after the
        call (``revoked_by`` tells who revoked it, if it was already), or None when there is no such grant
        (of that person, live): the caller answers all of those the same way. The check and the revoke are
        one transaction, so of two parallel revokes of one live grant exactly one gets it back."""
        now = self.now()
        with self._write() as db:
            grant = self._grant_row(db, grant_id or "", now)
            if grant is None or (user_id is not None and grant.user_id != user_id) \
                    or (live_only and not grant.live):
                return None
            self._revoke(db, grant.id, by, now)
            return self._grant_row(db, grant.id, now)

    def revoke_grants_of(self, user_id: str, *, by: str) -> list[Grant]:
        """Revoke every unrevoked grant of *user_id* (the operator's recovery); the grants revoked now."""
        now = self.now()
        with self._write() as db:
            ids = [r["id"] for r in db.execute("SELECT id FROM grants WHERE user_id = ? AND revoked_at IS NULL",
                                               (user_id,)).fetchall()]
            for grant_id in ids:
                self._revoke(db, grant_id, by, now)
            return [g for g in (self._grant_row(db, i, now) for i in ids) if g is not None]

    # ── chats opened through MCP ─────────────────────────────────────────────────────────────────

    def record_chat(self, *, user_id: str, profile: str, session_key: str, grant_id: str) -> Chat:
        """Remember that *user_id* opened (or used) this chat through MCP; the first grant is kept."""
        now = self.now()
        with self._write() as db:
            db.execute(
                "INSERT INTO mcp_chats (user_id, profile, session_key, created_at, last_used_at, opened_by_grant) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (user_id, profile, session_key) "
                "DO UPDATE SET last_used_at = excluded.last_used_at",
                (user_id, profile, session_key, now, now, grant_id))
            return _chat(db.execute("SELECT * FROM mcp_chats WHERE user_id = ? AND profile = ? AND session_key = ?",
                                    (user_id, profile, session_key)).fetchone())

    def chats_for(self, user_id: str, profile: Optional[str] = None) -> list[Chat]:
        """*user_id*'s MCP chats (of *profile* when given), most recently used first."""
        sql, args = "SELECT * FROM mcp_chats WHERE user_id = ?", [user_id]
        if profile is not None:
            sql += " AND profile = ?"
            args.append(profile)
        with self._read() as db:
            return [_chat(r) for r in db.execute(sql + " ORDER BY last_used_at DESC, session_key", args).fetchall()]

    def has_chat(self, *, user_id: str, profile: str, session_key: str) -> bool:
        with self._read() as db:
            return db.execute("SELECT 1 FROM mcp_chats WHERE user_id = ? AND profile = ? AND session_key = ?",
                              (user_id, profile, session_key)).fetchone() is not None

    # ── housekeeping ─────────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _prune_clients(db: sqlite3.Connection, now: int) -> int:
        return db.execute(
            "DELETE FROM clients WHERE created_at <= ? AND NOT EXISTS "
            "(SELECT 1 FROM grants g WHERE g.client_id = clients.client_id) AND NOT EXISTS "
            "(SELECT 1 FROM codes c WHERE c.client_id = clients.client_id AND c.expires_at > ?) AND NOT EXISTS "
            "(SELECT 1 FROM consents s WHERE s.client_id = clients.client_id AND s.expires_at > ?)",
            (now - CLIENT_UNUSED_TTL, now, now)).rowcount

    def prune(self) -> dict[str, int]:
        """Drop expired consents and codes, tokens a week after they expired, grants 90 days after they
        were revoked or ended (with their tokens), registrations with no grant a day after they were made,
        and MCP chats idle for 180 days. Counts per table."""
        now = self.now()
        with self._write() as db:
            counts = {
                "consents": db.execute("DELETE FROM consents WHERE expires_at <= ?", (now,)).rowcount,
                "codes": db.execute("DELETE FROM codes WHERE expires_at <= ?", (now,)).rowcount,
                "grants": db.execute(
                    "DELETE FROM grants WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR expires_at < ?",
                    (now - GRANT_KEEP_AFTER_END, now - GRANT_KEEP_AFTER_END)).rowcount,
                "tokens": db.execute("DELETE FROM tokens WHERE expires_at < ?",
                                     (now - TOKEN_KEEP_AFTER_EXPIRY,)).rowcount,
                "chats": db.execute("DELETE FROM mcp_chats WHERE last_used_at < ?", (now - CHAT_IDLE_KEEP,)).rowcount,
            }
            counts["clients"] = self._prune_clients(db, now)
            return counts

    def counts(self) -> dict[str, int]:
        now = self.now()
        with self._read() as db:
            def one(sql: str, args: Any = ()) -> int:
                return int(db.execute(sql, args).fetchone()[0])
            return {
                "clients": one("SELECT COUNT(*) FROM clients"),
                "consents": one("SELECT COUNT(*) FROM consents WHERE expires_at > ?", (now,)),
                "grants": one(f"SELECT COUNT(*) FROM grants g WHERE {_LIVE}", {"now": now}),
                "users": one(f"SELECT COUNT(DISTINCT g.user_id) FROM grants g WHERE {_LIVE}", {"now": now}),
                "chats": one("SELECT COUNT(*) FROM mcp_chats"),
            }
