"""Persistent backend for the side-effect journal.

Without persistence a side-effect journal dies with the process that
recorded it, which is a defined crash outcome but not a recoverable one:
after a restart the operator needs to know that an effect was prepared,
attempted, or left mid-flight. This module stores each
:class:`~firewall.effect.SideEffectRecord` as one row, keyed by
``effect_id``, with the state held in its own column so that a
compare-and-set across processes can be expressed as a single
``UPDATE ... WHERE effect_id = ? AND state = ?``.

The row is the journal. Two constraints carry the load:

* ``effect_id TEXT PRIMARY KEY`` -- one row per record.
* ``lease_id`` has a unique index -- one execution lease may carry
  exactly one side-effect row, so two processes racing to prepare an
  effect for the same lease admit exactly one writer and the loser
  receives the existing row (idempotent reuse) or an ``effect_mismatch``
  refusal, never a second row.

The table is deliberately independent of the ``execution_leases`` table:
the lease journal and the side-effect journal are two journals over one
database, and keeping them apart is what keeps state from looking like
history. Pass the same file path the execution store uses to keep both
durable in one file.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.effect import (
    EffectAlreadyBoundError,
    EffectJournalError,
    EffectState,
    SideEffectRecord,
)


class SQLiteEffectJournal:
    """SQLite-backed persistence for side-effect journal rows.

    Mirrors the shape of :class:`firewall.execution_store.SQLiteExecutionLeaseStore`:
    WAL journaling, a per-instance ``RLock`` for the connection, and every
    raising path rolled back and re-raised as an
    :class:`~firewall.effect.EffectJournalError` so a caller can treat
    unreadable state as a denial.
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
            raise EffectJournalError(
                "failed to initialize side-effect journal"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS side_effect_journal (
                        effect_id TEXT PRIMARY KEY,
                        lease_id TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        state TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_effect_lease
                    ON side_effect_journal (lease_id)
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_effect_state
                    ON side_effect_journal (state)
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise EffectJournalError(
                    "failed to initialize side-effect journal"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise EffectJournalError("side-effect journal is closed")
        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> tuple[SideEffectRecord, ...]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM side_effect_journal
                    ORDER BY effect_id
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise EffectJournalError(
                    "failed to read side-effect journal"
                ) from exc

        records: list[SideEffectRecord] = []
        for (payload,) in rows:
            try:
                records.append(
                    SideEffectRecord.from_dict(json.loads(payload))
                )
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise EffectJournalError(
                    "side-effect journal holds a corrupt record: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(records)

    def load_one(
        self,
        effect_id: str,
    ) -> Optional[SideEffectRecord]:
        """The current row for one effect, or ``None`` when absent."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM side_effect_journal
                    WHERE effect_id = ?
                    """,
                    (effect_id,),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise EffectJournalError(
                    "failed to read side-effect record"
                ) from exc

        if not rows:
            return None

        try:
            return SideEffectRecord.from_dict(json.loads(rows[0][0]))
        except Exception as exc:  # noqa: BLE001 - a corrupt row
            raise EffectJournalError(
                "side-effect journal holds a corrupt record: "
                f"{type(exc).__name__}"
            ) from exc

    # ========================================================
    # Insert (prepare)
    # ========================================================

    def insert(
        self,
        record: SideEffectRecord,
    ) -> None:
        connection = self._require_connection()

        if not isinstance(record, SideEffectRecord):
            raise TypeError("record must be a SideEffectRecord")

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO side_effect_journal (
                        effect_id,
                        lease_id,
                        idempotency_key,
                        state,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record.effect_id,
                        record.lease_id,
                        record.idempotency_key,
                        record.state.value,
                        json.dumps(record.to_dict(), sort_keys=True),
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise EffectAlreadyBoundError(
                    "lease already carries a side-effect row"
                ) from exc
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise EffectJournalError(
                    "failed to persist side-effect record"
                ) from exc

    # ========================================================
    # Compare-and-set (transition)
    # ========================================================

    def cas(
        self,
        effect_id: str,
        expected_state: EffectState,
        record: SideEffectRecord,
    ) -> bool:
        """Move one row from ``expected_state`` to ``record.state``.

        Returns whether a row matched. ``False`` means another process
        advanced the row first; the caller must treat that as a refusal
        and re-read the row.
        """

        connection = self._require_connection()

        if not isinstance(record, SideEffectRecord):
            raise TypeError("record must be a SideEffectRecord")

        try:
            expected = EffectState(expected_state)
        except (TypeError, ValueError):
            raise EffectJournalError(
                "expected state is not a phase"
            ) from None

        with self._lock:
            try:
                cursor = connection.execute(
                    """
                    UPDATE side_effect_journal
                    SET state = ?,
                        payload = ?
                    WHERE effect_id = ? AND state = ?
                    """,
                    (
                        record.state.value,
                        json.dumps(record.to_dict(), sort_keys=True),
                        effect_id,
                        expected.value,
                    ),
                )
                connection.commit()
                return cursor.rowcount > 0
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise EffectJournalError(
                    "failed to persist side-effect transition"
                ) from exc

    # ========================================================
    # Snapshot / close
    # ========================================================

    def records(self) -> tuple[SideEffectRecord, ...]:
        return self.load()

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM side_effect_journal
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise EffectJournalError(
                    "failed to count side-effect records"
                ) from exc

        return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> "SQLiteEffectJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
