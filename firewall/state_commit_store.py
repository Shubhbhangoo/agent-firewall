"""Persistent backend for the security state-commitment chain.

Without persistence the commitment chain dies with the process that
recorded it, which leaves the v3.0 guarantee at the same boundary the
epoch has always had: tampering a store file between restarts is only
caught if the firewall has a record of what the store used to say. This
module stores each :class:`~firewall.state_commit.StateCommitRecord` as
one row, ordered by height, so a restart can load the chain and demand
that the booted state prove itself against the recorded head.

The table is deliberately separate from the store files it attests. The
whole point of a commitment is to live somewhere a rollback of the
attested store does not reach: pass a different file path from the
revocation/key/delegation databases, so a single-file rollback leaves
the chain intact and the divergence is detected.

The chain is append-only by construction: a row is keyed by height and
inserting a height that exists is an error, so a replay of an earlier
record cannot overwrite a later one. Deleting rows is still possible at
the SQL level -- this store raises the bar for a *store-file* attack, it
does not defend a host with write access to the journal itself -- and a
truncated or edited chain fails verification when it is loaded, which
surfaces as a denial rather than a silent pass.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.state_commit import StateCommitError, StateCommitRecord


class SQLiteStateCommitStore:
    """SQLite-backed persistence for the state-commitment chain.

    Mirrors the shape of the other SQLite stores in the package: WAL
    journaling, a per-instance ``RLock`` for the connection, and every
    raising path rolled back and re-raised as a
    :class:`~firewall.state_commit.StateCommitError` so a caller can
    treat unreadable state as a denial.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = RLock()
        self._connection: Optional[sqlite3.Connection] = None

        try:
            connection = sqlite3.connect(
                self.path,
                check_same_thread=False,
            )
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 10000")
            self._connection = connection
            self._initialize()
        except Exception as exc:
            try:
                if self._connection is not None:
                    self._connection.close()
            except Exception:  # noqa: BLE001 - best effort on teardown
                pass
            self._connection = None
            raise StateCommitError(
                "failed to initialize the state-commit store"
            ) from exc

    def _initialize(self) -> None:
        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS state_commit_chain (
                        height INTEGER PRIMARY KEY,
                        parent_digest TEXT NOT NULL,
                        state_digest TEXT NOT NULL,
                        component_digests TEXT NOT NULL,
                        epoch TEXT,
                        source TEXT NOT NULL,
                        committed_at REAL NOT NULL,
                        genesis INTEGER NOT NULL
                    )
                    """
                )
                connection.commit()
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise StateCommitError(
                    "failed to initialize the state-commit store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise StateCommitError("state-commit store is closed")
        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> tuple[StateCommitRecord, ...]:
        """Every recorded commitment, in chain order."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT height
                    FROM state_commit_chain
                    ORDER BY height
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise StateCommitError(
                    "failed to read the state-commit chain"
                ) from exc

        return tuple(self.load_one(int(row[0])) for row in rows)

    def load_one(self, height: int) -> StateCommitRecord:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT parent_digest,
                           state_digest,
                           component_digests,
                           epoch,
                           source,
                           committed_at,
                           genesis
                    FROM state_commit_chain
                    WHERE height = ?
                    """,
                    (height,),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise StateCommitError(
                    f"failed to read state-commit record {height}"
                ) from exc

        if not rows:
            raise StateCommitError(
                f"state-commit chain is not contiguous: no record at "
                f"height {height}"
            )

        row = rows[0]
        return StateCommitRecord(
            height=height,
            parent_digest=str(row[0]),
            state_digest=str(row[1]),
            component_digests=self._decode_components(str(row[2])),
            epoch=self._decode_epoch(row[3]),
            source=str(row[4]),
            committed_at=float(row[5]),
            genesis=bool(row[6]),
        )

    @staticmethod
    def _decode_components(payload: str) -> dict[str, str]:
        import json

        try:
            raw = json.loads(payload)
        except (ValueError, TypeError) as exc:
            raise StateCommitError(
                "a state-commit row holds corrupt component digests"
            ) from exc

        return {str(k): str(v) for k, v in raw.items()}

    @staticmethod
    def _decode_epoch(payload: Optional[str]) -> Optional[tuple[int, int]]:
        if payload is None:
            return None

        import json

        try:
            raw = json.loads(payload)
        except (ValueError, TypeError) as exc:
            raise StateCommitError(
                "a state-commit row holds a corrupt epoch sample"
            ) from exc

        return (int(raw[0]), int(raw[1]))

    # ========================================================
    # Insert
    # ========================================================

    def insert(self, record: StateCommitRecord) -> None:
        """Append one commitment. Re-inserting a height is an error."""

        connection = self._require_connection()

        if not isinstance(record, StateCommitRecord):
            raise TypeError("record must be a StateCommitRecord")

        import json

        epoch = (
            json.dumps([record.epoch[0], record.epoch[1]])
            if record.epoch is not None
            else None
        )

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO state_commit_chain (
                        height,
                        parent_digest,
                        state_digest,
                        component_digests,
                        epoch,
                        source,
                        committed_at,
                        genesis
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.height,
                        record.parent_digest,
                        record.state_digest,
                        json.dumps(
                            record.component_digests, sort_keys=True
                        ),
                        epoch,
                        record.source,
                        record.committed_at,
                        1 if record.genesis else 0,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StateCommitError(
                    f"state-commit height {record.height} is already "
                    "recorded; the chain is append-only"
                ) from exc
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise StateCommitError(
                    "failed to persist a state commitment"
                ) from exc

    # ========================================================
    # Size / close
    # ========================================================

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM state_commit_chain
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise StateCommitError(
                    "failed to count state-commit records"
                ) from exc

        return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> "SQLiteStateCommitStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
