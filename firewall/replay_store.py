from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock


class ReplayStoreError(Exception):
    """Base persistent replay-store error."""


@dataclass(frozen=True)
class StoredNonce:
    key: str
    expires_at: float


class SQLiteReplayStore:
    """
    Persistent replay/nonce store.

    A consumed nonce remains consumed across normal SDK
    restarts until its associated capability expires.
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

        try:
            self._connection = sqlite3.connect(
                self.path,
                check_same_thread=False,
            )

            self._connection.execute(
                "PRAGMA journal_mode = WAL"
            )

            self._connection.execute(
                "PRAGMA synchronous = FULL"
            )

            self._initialize()

        except Exception as exc:
            try:
                self._connection.close()
            except Exception:
                pass

            raise ReplayStoreError(
                "failed to initialize replay store"
            ) from exc

    # ========================================================
    # Initialization
    # ========================================================

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS nonces (
                        replay_key TEXT PRIMARY KEY,
                        expires_at REAL NOT NULL
                    )
                    """
                )

                self._connection.commit()

            except sqlite3.DatabaseError as exc:
                self._connection.rollback()

                raise ReplayStoreError(
                    "failed to initialize replay store"
                ) from exc

    # ========================================================
    # Connection
    # ========================================================

    def _require_connection(
        self,
    ) -> sqlite3.Connection:
        if self._connection is None:
            raise ReplayStoreError(
                "replay store is closed"
            )

        return self._connection

    # ========================================================
    # Consume
    # ========================================================

    def consume(
        self,
        replay_key: str,
        expires_at: float,
    ) -> bool:
        if not isinstance(
            replay_key,
            str,
        ):
            raise TypeError(
                "replay_key must be a string"
            )

        if not replay_key:
            raise ValueError(
                "replay_key cannot be empty"
            )

        try:
            expires_at = float(
                expires_at
            )
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "expires_at must be numeric"
            ) from exc

        connection = (
            self._require_connection()
        )

        with self._lock:
            try:
                now = float(
                    self._clock()
                )

                # Expired replay entries are no longer needed.
                connection.execute(
                    """
                    DELETE FROM nonces
                    WHERE expires_at <= ?
                    """,
                    (now,),
                )

                connection.execute(
                    """
                    INSERT INTO nonces (
                        replay_key,
                        expires_at
                    )
                    VALUES (?, ?)
                    """,
                    (
                        replay_key,
                        expires_at,
                    ),
                )

                connection.commit()

                return True

            except sqlite3.IntegrityError:
                connection.rollback()

                return False

            except sqlite3.DatabaseError as exc:
                connection.rollback()

                raise ReplayStoreError(
                    "failed to persist replay state"
                ) from exc

    # ========================================================
    # Lookup
    # ========================================================

    def contains(
        self,
        replay_key: str,
    ) -> bool:
        if not isinstance(
            replay_key,
            str,
        ):
            raise TypeError(
                "replay_key must be a string"
            )

        if not replay_key:
            raise ValueError(
                "replay_key cannot be empty"
            )

        connection = (
            self._require_connection()
        )

        with self._lock:
            try:
                now = float(
                    self._clock()
                )

                row = connection.execute(
                    """
                    SELECT replay_key
                    FROM nonces
                    WHERE replay_key = ?
                      AND expires_at > ?
                    """,
                    (
                        replay_key,
                        now,
                    ),
                ).fetchone()

            except sqlite3.DatabaseError as exc:
                raise ReplayStoreError(
                    "failed to read replay state"
                ) from exc

        return row is not None

    # ========================================================
    # Snapshot
    # ========================================================

    def records(
        self,
    ) -> tuple[StoredNonce, ...]:
        connection = (
            self._require_connection()
        )

        with self._lock:
            try:
                now = float(
                    self._clock()
                )

                rows = connection.execute(
                    """
                    SELECT
                        replay_key,
                        expires_at
                    FROM nonces
                    WHERE expires_at > ?
                    ORDER BY replay_key
                    """,
                    (now,),
                ).fetchall()

            except sqlite3.DatabaseError as exc:
                raise ReplayStoreError(
                    "failed to read replay state"
                ) from exc

        return tuple(
            StoredNonce(
                key=str(row[0]),
                expires_at=float(row[1]),
            )
            for row in rows
        )

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        return len(
            self.records()
        )

    # ========================================================
    # Close
    # ========================================================

    def close(
        self,
    ) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(
        self,
    ):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()