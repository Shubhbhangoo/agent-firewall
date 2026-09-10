"""Persistent backend for the execution lease store.

Without persistence an execution lease dies with the process that issued
it, which is a defined crash outcome but not an auditable one: an
operator who needs to know that an execution was reserved, started, or
left mid-flight after a restart must be able to read the record. This
module stores each :class:`~firewall.execution_lease.ExecutionLease` as
one row, keyed by ``lease_id``, with the state held in its own column so
that a compare-and-set across processes can be expressed as a single
``UPDATE ... WHERE lease_id = ? AND state = ?``.

The row is the journal. State transitions are atomic in SQLite
transactions, so two SDK instances over one file observe the same
exactly-once property the in-memory store provides within one process --
the guarantee belongs to the row, not to a per-instance lock. Three
constraints carry the load:

* ``lease_id TEXT PRIMARY KEY`` -- one row per lease; a second process
  trying to issue the same id (a 128-bit collision, i.e. never) fails.
* ``state`` compared inside every ``UPDATE`` -- a transition applies
  only to the phase the caller read, so a lease two processes race to
  reserve admits exactly one winner.
* a partial unique index on live ``execution_id`` -- one execution
  identity may name one non-terminal lease, so two processes cannot
  reserve two different leases against the same running execution.
  Terminal rows leave the index, which is what lets an execution
  identity be reused after the previous execution finished.

A ``cas`` that matches no row is a *refusal*, reported to the in-memory
store so it can refresh its copy; it is never retried into success.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.execution_lease import (
    ExecutionLease,
    ExecutionLeaseError,
    ExecutionState,
)


class SQLiteExecutionLeaseStore:
    """SQLite-backed persistence for execution lease records.

    Mirrors the shape of :class:`firewall.replay_store.SQLiteReplayStore`
    and :class:`firewall.lifecycle_store.SQLiteLifecycleStore`: WAL
    journaling, a per-instance ``RLock`` for the connection, and every
    raising path rolled back and re-raised as an
    :class:`ExecutionLeaseError` so a caller can treat unreadable state
    as a denial.
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
            self._connection.execute(
                "PRAGMA journal_mode = WAL"
            )
            self._connection.execute(
                "PRAGMA synchronous = FULL"
            )
            self._connection.execute(
                "PRAGMA busy_timeout = 10000"
            )
            self._initialize()
        except Exception as exc:
            try:
                self._connection.close()
            except Exception:  # noqa: BLE001 - best effort on teardown
                pass
            raise ExecutionLeaseError(
                "failed to initialize execution lease store"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS execution_leases (
                        lease_id TEXT PRIMARY KEY,
                        state TEXT NOT NULL,
                        execution_id TEXT,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_leases_state
                    ON execution_leases (state)
                    """
                )
                self._connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_execution
                    ON execution_leases (execution_id)
                    WHERE execution_id IS NOT NULL
                      AND state NOT IN (
                          'completed', 'aborted', 'denied',
                          'expired', 'revoked'
                      )
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise ExecutionLeaseError(
                    "failed to initialize execution lease store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise ExecutionLeaseError(
                "execution lease store is closed"
            )
        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> tuple[ExecutionLease, ...]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM execution_leases
                    ORDER BY lease_id
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise ExecutionLeaseError(
                    "failed to read execution leases"
                ) from exc

        records: list[ExecutionLease] = []
        for (payload,) in rows:
            try:
                records.append(
                    ExecutionLease.from_dict(json.loads(payload))
                )
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise ExecutionLeaseError(
                    "execution lease store holds a corrupt record: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(records)

    def load_one(
        self,
        lease_id: str,
    ) -> Optional[ExecutionLease]:
        """The current row for one lease, or ``None`` when it is absent."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM execution_leases
                    WHERE lease_id = ?
                    """,
                    (lease_id,),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise ExecutionLeaseError(
                    "failed to read execution lease"
                ) from exc

        if not rows:
            return None

        try:
            return ExecutionLease.from_dict(
                json.loads(rows[0][0])
            )
        except Exception as exc:  # noqa: BLE001 - a corrupt row
            raise ExecutionLeaseError(
                "execution lease store holds a corrupt record: "
                f"{type(exc).__name__}"
            ) from exc

    # ========================================================
    # Insert (issue)
    # ========================================================

    def insert(
        self,
        record: ExecutionLease,
    ) -> None:
        connection = self._require_connection()

        if not isinstance(record, ExecutionLease):
            raise TypeError("record must be an ExecutionLease")

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO execution_leases (
                        lease_id,
                        state,
                        execution_id,
                        payload
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        record.lease_id,
                        record.state.value,
                        record.execution_id,
                        json.dumps(record.to_dict(), sort_keys=True),
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ExecutionLeaseError(
                    "execution identity is already bound to another "
                    "lease"
                ) from exc
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise ExecutionLeaseError(
                    "failed to persist execution lease"
                ) from exc

    # ========================================================
    # Compare-and-set (transition)
    # ========================================================

    def cas(
        self,
        lease_id: str,
        expected_state: ExecutionState,
        record: ExecutionLease,
    ) -> bool:
        """Move one row from ``expected_state`` to ``record.state``.

        Returns whether a row matched. ``False`` means another process
        advanced the lease first; the caller must treat that as a
        refusal and re-read the row. An ``IntegrityError`` from the live
        ``execution_id`` index is re-raised as an
        :class:`ExecutionLeaseError` naming the identity conflict.
        """

        connection = self._require_connection()

        if not isinstance(record, ExecutionLease):
            raise TypeError("record must be an ExecutionLease")

        try:
            expected = ExecutionState(expected_state)
        except (TypeError, ValueError):
            raise ExecutionLeaseError(
                "expected state is not a phase"
            ) from None

        with self._lock:
            try:
                cursor = connection.execute(
                    """
                    UPDATE execution_leases
                    SET state = ?,
                        execution_id = ?,
                        payload = ?
                    WHERE lease_id = ? AND state = ?
                    """,
                    (
                        record.state.value,
                        record.execution_id,
                        json.dumps(record.to_dict(), sort_keys=True),
                        lease_id,
                        expected.value,
                    ),
                )
                connection.commit()
                return cursor.rowcount > 0
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ExecutionLeaseError(
                    "execution identity is already bound to another "
                    "lease"
                ) from exc
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise ExecutionLeaseError(
                    "failed to persist execution lease transition"
                ) from exc

    # ========================================================
    # Snapshot
    # ========================================================

    def records(
        self,
    ) -> tuple[ExecutionLease, ...]:
        return self.load()

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM execution_leases
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise ExecutionLeaseError(
                    "failed to count execution leases"
                ) from exc

        return int(row[0]) if row else 0

    # ========================================================
    # Close
    # ========================================================

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> "SQLiteExecutionLeaseStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
