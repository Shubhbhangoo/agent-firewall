from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Optional


class RevocationStoreError(Exception):
    """Base persistent revocation-store error."""


class StoreAlreadyRevokedError(
    RevocationStoreError
):
    """Raised when a fingerprint is already revoked."""


class StoreInvalidFingerprintError(
    RevocationStoreError
):
    """Raised for invalid fingerprints."""


@dataclass(frozen=True)
class StoredRevocation:
    fingerprint: str
    revoked_at: float
    reason: str = ""


class SQLiteRevocationStore:
    """
    Persistent, one-way capability revocation store.

    Revocations are stored in SQLite and survive process
    restarts. There is intentionally no unrevoke operation.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock=None,
    ):
        self.path = str(path)
        self._clock = (
            clock
            if clock is not None
            else time.time
        )
        self._lock = RLock()

        self._connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
        )

        self._connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        self._connection.execute(
            "PRAGMA journal_mode = WAL"
        )

        self._connection.execute(
            "PRAGMA synchronous = FULL"
        )

        self._initialize()

    # ========================================================
    # Initialization
    # ========================================================

    def _initialize(self) -> None:
        with self._lock:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS revocations (
                    fingerprint TEXT PRIMARY KEY,
                    revoked_at REAL NOT NULL,
                    reason TEXT NOT NULL DEFAULT ''
                )
                """
            )

            self._connection.commit()

    # ========================================================
    # Validation
    # ========================================================

    @staticmethod
    def _validate_fingerprint(
        fingerprint: str,
    ) -> str:
        if not isinstance(
            fingerprint,
            str,
        ):
            raise StoreInvalidFingerprintError(
                "fingerprint must be a string"
            )

        fingerprint = fingerprint.strip()

        if not fingerprint:
            raise StoreInvalidFingerprintError(
                "fingerprint cannot be empty"
            )

        return fingerprint

    # ========================================================
    # Revoke
    # ========================================================

    def revoke(
        self,
        fingerprint: str,
        *,
        reason: str = "",
    ) -> StoredRevocation:
        fingerprint = self._validate_fingerprint(
            fingerprint
        )

        with self._lock:
            try:
                revoked_at = float(
                    self._clock()
                )

                self._connection.execute(
                    """
                    INSERT INTO revocations (
                        fingerprint,
                        revoked_at,
                        reason
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        fingerprint,
                        revoked_at,
                        str(reason),
                    ),
                )

                self._connection.commit()

            except sqlite3.IntegrityError:
                self._connection.rollback()

                raise StoreAlreadyRevokedError(
                    "capability is already revoked"
                )

            except Exception:
                self._connection.rollback()
                raise

            return StoredRevocation(
                fingerprint=fingerprint,
                revoked_at=revoked_at,
                reason=str(reason),
            )

    # ========================================================
    # Lookup
    # ========================================================

    def get(
        self,
        fingerprint: str,
    ) -> Optional[
        StoredRevocation
    ]:
        fingerprint = self._validate_fingerprint(
            fingerprint
        )

        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    fingerprint,
                    revoked_at,
                    reason
                FROM revocations
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()

        if row is None:
            return None

        return StoredRevocation(
            fingerprint=row[0],
            revoked_at=float(row[1]),
            reason=row[2],
        )

    # ========================================================
    # Check
    # ========================================================

    def is_revoked(
        self,
        fingerprint: str,
    ) -> bool:
        return (
            self.get(fingerprint)
            is not None
        )

    # ========================================================
    # Snapshot
    # ========================================================

    def records(
        self,
    ) -> tuple[
        StoredRevocation,
        ...,
    ]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    fingerprint,
                    revoked_at,
                    reason
                FROM revocations
                ORDER BY revoked_at ASC, fingerprint ASC
                """
            ).fetchall()

        return tuple(
            StoredRevocation(
                fingerprint=row[0],
                revoked_at=float(row[1]),
                reason=row[2],
            )
            for row in rows
        )

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM revocations"
            ).fetchone()

        return int(row[0])

    # ========================================================
    # Close
    # ========================================================

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    # ========================================================
    # Context manager
    # ========================================================

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()