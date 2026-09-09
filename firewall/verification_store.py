"""Persistent backend for the verification journal.

Without persistence a verification journal dies with the process that
recorded it, which is a defined crash outcome but not a recoverable one:
after a restart the operator needs to know whether the recorded claim was
verified before an execution completed. This module stores each
:class:`~firewall.effect_verification.VerificationRecord` as one row,
keyed by its natural id (``verification_id``, the digest of the
binding), so the one-row-per-claim property holds across processes.

The table is deliberately independent of the ``side_effect_journal`` and
``execution_leases`` tables: the verification journal is a third journal
beside them, and keeping it apart is what lets an operator archive or
discard verification claims without rewriting the state they describe.
Pass the same file path the execution/effect stores use to keep all three
durable in one database.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.effect_verification import (
    VerificationJournalError,
    VerificationRecord,
)


class SQLiteVerificationJournal:
    """SQLite-backed persistence for verification claims.

    Mirrors the shape of
    :class:`firewall.execution_store.SQLiteExecutionLeaseStore` and
    :class:`firewall.effect_store.SQLiteEffectJournal`: WAL journaling, a
    per-instance ``RLock`` for the connection, and every raising path
    rolled back and re-raised as a
    :class:`~firewall.effect_verification.VerificationJournalError` so a
    caller can treat unreadable state as a denial.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock=None,
    ):
        self.path = str(path)
        self._clock = clock if clock is not None else time.time
        self._lock = RLock()

        try:
            self._connection = sqlite3.connect(
                self.path,
                check_same_thread=False,
            )
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA busy_timeout = 10000")
            self._initialize()
        except Exception as exc:
            try:
                self._connection.close()
            except Exception:  # noqa: BLE001 - best effort on teardown
                pass
            raise VerificationJournalError(
                "failed to initialize verification journal"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS verification_journal (
                        verification_id TEXT PRIMARY KEY,
                        effect_id TEXT NOT NULL,
                        attempt_id TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_verification_effect
                    ON verification_journal (effect_id)
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise VerificationJournalError(
                    "failed to initialize verification journal"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise VerificationJournalError("verification journal is closed")
        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> tuple[VerificationRecord, ...]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM verification_journal
                    ORDER BY verification_id
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise VerificationJournalError(
                    "failed to read verification journal"
                ) from exc

        records: list[VerificationRecord] = []
        for (payload,) in rows:
            try:
                records.append(
                    VerificationRecord.from_dict(json.loads(payload))
                )
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise VerificationJournalError(
                    "verification journal holds a corrupt record: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(records)

    def load_one(
        self,
        verification_id: str,
    ) -> Optional[VerificationRecord]:
        """The current row for one claim, or ``None`` when absent."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM verification_journal
                    WHERE verification_id = ?
                    """,
                    (verification_id,),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise VerificationJournalError(
                    "failed to read verification record"
                ) from exc

        if not rows:
            return None

        try:
            return VerificationRecord.from_dict(json.loads(rows[0][0]))
        except Exception as exc:  # noqa: BLE001 - a corrupt row
            raise VerificationJournalError(
                "verification journal holds a corrupt record: "
                f"{type(exc).__name__}"
            ) from exc

    # ========================================================
    # Insert (record)
    # ========================================================

    def insert(
        self,
        record: VerificationRecord,
    ) -> None:
        connection = self._require_connection()

        if not isinstance(record, VerificationRecord):
            raise TypeError("record must be a VerificationRecord")

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO verification_journal (
                        verification_id,
                        effect_id,
                        attempt_id,
                        outcome,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record.verification_id,
                        record.effect_id,
                        record.attempt_id,
                        record.outcome.value,
                        json.dumps(record.to_dict(), sort_keys=True),
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise VerificationJournalError(
                    "verification claim already recorded"
                ) from exc
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise VerificationJournalError(
                    "failed to persist verification claim"
                ) from exc

    # ========================================================
    # Snapshot / close
    # ========================================================

    def records(self) -> tuple[VerificationRecord, ...]:
        return self.load()

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM verification_journal
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise VerificationJournalError(
                    "failed to count verification records"
                ) from exc

        return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> "SQLiteVerificationJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
