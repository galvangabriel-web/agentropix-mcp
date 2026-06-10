"""SQLite-backed token registry for the Step-2 evidence gate.

Solves the four properties the Step-1 stub left open (SIFT-W-A11):

  1. **Replay protection** — `verify_and_spend` updates `spent_ts` in
     the same transaction it reads it; a second call sees the row as
     spent and raises TokenAlreadySpent.
  2. **Expiry** — every token carries `created_ts + ttl_seconds`;
     expired tokens raise TokenExpired without consuming the row.
  3. **Revocation** — `revoke()` sets `revoked_ts`; subsequent verifies
     raise TokenRevoked.
  4. **Atomic verify+spend** — single SQL UPDATE in a serialized
     transaction (SQLite's default isolation is SERIALIZABLE for
     write transactions, which is exactly what we need).

Token format: `egt_<26-char-base32-ULID>` (preserved from Step-1 stub
so wazuh.evidence_gate.verify_evidence_token's structural check still
applies before we ever touch the DB).

Storage layout:
  Path: env `AGENTROPIX_EVIDENCE_GATE_DB`
        default: `~/.agentropix/evidence-gate.sqlite`
  Mode: 0o600 on the DB file (best-effort).

Schema:
  tokens(token_id PK, token_hash, scope, created_ts, ttl_seconds,
         spent_ts, spent_run_id, revoked_ts, operator)

Note we store the *hash* of the full token string, not the token
itself — anyone who reads the DB cannot reconstruct the bearer secret.
The token_id (the ULID portion) is stored in the clear because the
operator needs a non-secret handle to revoke / list.

Threading: SQLite connections are not thread-safe by default.
TokenRegistry creates its connection lazily and uses
`check_same_thread=False`; concurrent writers serialise via SQLite's
own locking. Multi-process safety is provided by SQLite's WAL mode.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import sqlite3
import string
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .errors import (
    RegistryUnavailable,
    TokenAlreadySpent,
    TokenExpired,
    TokenFormatInvalid,
    TokenNotFound,
    TokenRevoked,
    TokenScopeMismatch,
)

logger = logging.getLogger(__name__)

_TOKEN_PATTERN = re.compile(r"^egt_([0-9A-Z]{26})$")
_DB_ENV = "AGENTROPIX_EVIDENCE_GATE_DB"
_DEFAULT_DB_PATH = Path.home() / ".agentropix" / "evidence-gate.sqlite"
# Crockford base32 alphabet (same as ULID).
_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


# ---------------------------------------------------------------------------
# Token format helpers
# ---------------------------------------------------------------------------


def _new_token_id() -> str:
    """Generate a 26-char Crockford-base32 ULID-shaped identifier.

    We don't use a real ULID encoding (timestamp prefix) because that
    would let an observer infer mint time from the token. Pure entropy
    is fine here; the registry stores the timestamp separately.
    """
    return "".join(secrets.choice(_BASE32) for _ in range(26))


def _parse_token(token: str) -> str:
    """Validate format and return the ULID portion (token_id).

    Raises TokenFormatInvalid on any structural problem.
    """
    if not isinstance(token, str):
        raise TokenFormatInvalid("token must be a string")
    m = _TOKEN_PATTERN.match(token.strip())
    if not m:
        raise TokenFormatInvalid(
            f"token {token[:20]!r} does not match egt_<26-char-base32> format"
        )
    return m.group(1)


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenRow:
    token_id: str
    scope: str
    created_ts: float
    ttl_seconds: int
    spent_ts: float | None
    spent_run_id: str | None
    revoked_ts: float | None
    operator: str | None

    def status(self, now: float) -> str:
        if self.revoked_ts is not None:
            return "revoked"
        if self.spent_ts is not None:
            return "spent"
        if now > self.created_ts + self.ttl_seconds:
            return "expired"
        return "live"


class TokenRegistry:
    """SQLite-backed token registry."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else self._default_db_path()
        self._conn: sqlite3.Connection | None = None

    @staticmethod
    def _default_db_path() -> Path:
        env_path = os.environ.get(_DB_ENV)
        if env_path:
            return Path(env_path)
        return _DEFAULT_DB_PATH

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _open(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RegistryUnavailable(
                f"cannot create parent dir for {self._db_path}: {exc}"
            ) from exc
        try:
            conn = sqlite3.connect(
                self._db_path,
                isolation_level=None,  # autocommit; we manage txns explicitly
                check_same_thread=False,
                timeout=30.0,
            )
        except sqlite3.Error as exc:
            raise RegistryUnavailable(
                f"cannot open registry at {self._db_path}: {exc}"
            ) from exc
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
                token_id     TEXT PRIMARY KEY,
                token_hash   BLOB NOT NULL,
                scope        TEXT NOT NULL,
                created_ts   REAL NOT NULL,
                ttl_seconds  INTEGER NOT NULL,
                spent_ts     REAL,
                spent_run_id TEXT,
                revoked_ts   REAL,
                operator     TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scope ON tokens(scope)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created ON tokens(created_ts)"
        )
        # Best-effort restrictive perms on the file.
        try:
            os.chmod(self._db_path, 0o600)
        except OSError:
            pass
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> TokenRegistry:
        self._open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
        conn = self._open()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    def mint(
        self,
        *,
        scope: str,
        ttl_seconds: int,
        operator: str | None = None,
        now: float | None = None,
    ) -> str:
        """Mint a new token and persist it. Returns the bearer secret."""
        if not isinstance(scope, str) or not scope:
            raise ValueError("scope must be a non-empty string")
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive int")
        if ttl_seconds > 7 * 24 * 3600:
            raise ValueError("ttl_seconds may not exceed 7 days (604800)")

        token_id = _new_token_id()
        token = f"egt_{token_id}"
        now = now if now is not None else time.time()

        with self._txn() as conn:
            conn.execute(
                """
                INSERT INTO tokens
                  (token_id, token_hash, scope, created_ts, ttl_seconds, operator)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_id, _hash_token(token), scope, now, ttl_seconds, operator),
            )
        logger.info(
            "evidence_gate.mint: token_id=%s scope=%s ttl=%ds operator=%s",
            token_id, scope, ttl_seconds, operator,
        )
        return token

    def verify_and_spend(
        self,
        token: str,
        *,
        op: str,
        run_id: str | None = None,
        now: float | None = None,
    ) -> TokenRow:
        """Atomically verify the token and mark it spent.

        Raises one of:
          TokenFormatInvalid / TokenNotFound / TokenExpired /
          TokenRevoked / TokenAlreadySpent / TokenScopeMismatch
        """
        token_id = _parse_token(token)
        token_hash = _hash_token(token)
        now = now if now is not None else time.time()

        with self._txn() as conn:
            cur = conn.execute(
                "SELECT token_id, token_hash, scope, created_ts, ttl_seconds, "
                "       spent_ts, spent_run_id, revoked_ts, operator "
                "FROM tokens WHERE token_id = ?",
                (token_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise TokenNotFound(f"token {token_id} not in registry")
            (db_id, db_hash, db_scope, db_created, db_ttl,
             db_spent, db_spent_run, db_revoked, db_operator) = row
            # Constant-time compare on hash to avoid leaking via timing
            # whether the token_id collided with a real entry but the
            # secret didn't match.
            if not secrets.compare_digest(bytes(db_hash), token_hash):
                # Treat as not-found from the caller's perspective — never
                # leak that token_id exists with a different secret.
                raise TokenNotFound(f"token {token_id} not in registry")
            if db_revoked is not None:
                raise TokenRevoked(f"token {token_id} was revoked")
            if db_spent is not None:
                raise TokenAlreadySpent(f"token {token_id} already spent")
            if now > db_created + db_ttl:
                raise TokenExpired(f"token {token_id} expired")
            if db_scope != op:
                raise TokenScopeMismatch(
                    f"token {token_id} scope={db_scope!r} != requested op={op!r}"
                )
            conn.execute(
                "UPDATE tokens SET spent_ts = ?, spent_run_id = ? WHERE token_id = ?",
                (now, run_id, token_id),
            )

        logger.info(
            "evidence_gate.verify_and_spend: token_id=%s scope=%s run_id=%s",
            token_id, op, run_id,
        )
        return TokenRow(
            token_id=db_id, scope=db_scope, created_ts=db_created,
            ttl_seconds=db_ttl, spent_ts=now, spent_run_id=run_id,
            revoked_ts=None, operator=db_operator,
        )

    def revoke(self, token: str, *, now: float | None = None) -> bool:
        """Revoke a token. Returns True if the row existed (and is now
        revoked or already-revoked); False if no such token_id."""
        token_id = _parse_token(token)
        now = now if now is not None else time.time()

        with self._txn() as conn:
            cur = conn.execute(
                "SELECT token_hash, revoked_ts FROM tokens WHERE token_id = ?",
                (token_id,),
            )
            row = cur.fetchone()
            if row is None:
                return False
            db_hash, db_revoked = row
            if not secrets.compare_digest(bytes(db_hash), _hash_token(token)):
                return False  # don't leak existence
            if db_revoked is None:
                conn.execute(
                    "UPDATE tokens SET revoked_ts = ? WHERE token_id = ?",
                    (now, token_id),
                )
                logger.info("evidence_gate.revoke: token_id=%s now revoked", token_id)
        return True

    def revoke_by_id(self, token_id: str, *, now: float | None = None) -> bool:
        """Operator-emergency revoke by ULID (NO secret required).

        Useful when an operator only knows the token_id and needs to
        kill a token immediately (suspected compromise). Returns True
        if the row existed.
        """
        if not re.match(r"^[0-9A-Z]{26}$", token_id):
            raise TokenFormatInvalid(f"token_id {token_id!r} not a 26-char base32 ULID")
        now = now if now is not None else time.time()
        with self._txn() as conn:
            cur = conn.execute(
                "SELECT 1 FROM tokens WHERE token_id = ?", (token_id,),
            )
            if cur.fetchone() is None:
                return False
            conn.execute(
                "UPDATE tokens SET revoked_ts = COALESCE(revoked_ts, ?) WHERE token_id = ?",
                (now, token_id),
            )
        logger.info("evidence_gate.revoke_by_id: token_id=%s now revoked", token_id)
        return True

    def list_tokens(
        self,
        *,
        scope: str | None = None,
        include_spent: bool = True,
        include_revoked: bool = True,
        include_expired: bool = True,
        now: float | None = None,
    ) -> list[TokenRow]:
        now = now if now is not None else time.time()
        sql = (
            "SELECT token_id, token_hash, scope, created_ts, ttl_seconds, "
            "       spent_ts, spent_run_id, revoked_ts, operator "
            "FROM tokens"
        )
        params: list = []
        if scope is not None:
            sql += " WHERE scope = ?"
            params.append(scope)
        sql += " ORDER BY created_ts DESC"
        rows: list[TokenRow] = []
        for r in self._open().execute(sql, params).fetchall():
            tr = TokenRow(
                token_id=r[0], scope=r[2], created_ts=r[3],
                ttl_seconds=r[4], spent_ts=r[5], spent_run_id=r[6],
                revoked_ts=r[7], operator=r[8],
            )
            status = tr.status(now)
            if status == "spent" and not include_spent:
                continue
            if status == "revoked" and not include_revoked:
                continue
            if status == "expired" and not include_expired:
                continue
            rows.append(tr)
        return rows
