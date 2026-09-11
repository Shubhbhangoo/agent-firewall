"""Persistent backend for the external anchor journal.

Without persistence an anchor checkpoint dies with the process that took it,
and the whole point of the layer is that a *later* process can compare its
local anchor against something the current one did not write. This module
stores each :class:`~firewall.anchor.AnchorCheckpoint` as one row so the
confirmed set survives a restart, which is what makes
``EXTERNAL_ANCHOR_SOUNDNESS`` checkable across a process generation rather
than only within one.

**The primary key is structural, and that is the security decision.**
``(anchor_kind, anchor_id, sequence)`` -- not the checkpoint's declared
``checkpoint_id``. The same reasoning as the lineage store, for the same
reason: a position is claimed by writing at that position rather than by
asserting an id, so a forged ``checkpoint_id`` can neither collide with nor
displace a real checkpoint. A checkpoint discovered to have the wrong id is
one that *fails the journal's own verification*, which the enforcement path
turns into a refusal and the invariant reports -- rather than a row the
database silently rejected and nobody noticed.

**One position holds one claim.** A second, *different* checkpoint at a
position that is already taken raises
:class:`~firewall.anchor.AnchorRewindError`. That is the rewind attack
arriving at the storage layer: an older snapshot restored under a sequence
the witness already confirmed cannot coexist with the confirmed row, so two
processes racing one anchor cannot each believe they won.

**Publish and confirm are the same row.** A checkpoint is written once, when
it is published, and ``confirm`` flips its ``confirmed`` flag. Two rows would
be two accounts of one statement, and the invariant would have to decide
which one it believed.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.anchor import (
    AnchorCheckpoint,
    AnchorJournalError,
    AnchorKind,
    AnchorRewindError,
    anchor_kind_of,
)


class SQLiteAnchorStore:
    """SQLite-backed persistence for anchor checkpoints and their receipts.

    Mirrors the shape of the other stores in this package -- WAL journaling,
    ``synchronous = FULL`` so a checkpoint reported written survives a crash,
    a per-instance ``RLock`` for the connection, and errors re-raised as the
    anchor module's own error types.
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
        self._connection: Optional[sqlite3.Connection] = None

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
                if self._connection is not None:
                    self._connection.close()
            except Exception:  # noqa: BLE001 - best effort on teardown
                pass
            raise AnchorJournalError(
                "failed to initialize the external anchor store"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS anchor_checkpoints (
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        checkpoint_id TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        issued_at REAL NOT NULL,
                        witness_key_id TEXT NOT NULL,
                        confirmed INTEGER NOT NULL DEFAULT 0,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (anchor_kind, anchor_id, sequence)
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_anchor_confirmed
                    ON anchor_checkpoints (anchor_kind, anchor_id, confirmed)
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise AnchorJournalError(
                    "failed to initialize the external anchor store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise AnchorJournalError("the external anchor store is closed")

        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(
        self,
        *,
        confirmed_only: bool = False,
    ) -> tuple[AnchorCheckpoint, ...]:
        """Every checkpoint, grouped by anchor and sequence-ordered.

        Ordered by ``(anchor_kind, anchor_id, sequence)`` so a caller
        receives each anchor's history in order without needing to sort.
        """

        connection = self._require_connection()

        query = (
            "SELECT payload FROM anchor_checkpoints "
            + ("WHERE confirmed = 1 " if confirmed_only else "")
            + "ORDER BY anchor_kind, anchor_id, sequence"
        )

        with self._lock:
            try:
                rows = connection.execute(query).fetchall()
            except sqlite3.DatabaseError as exc:
                raise AnchorJournalError(
                    "failed to read anchor checkpoints"
                ) from exc

        return tuple(
            self._decode(payload) for (payload,) in rows
        )

    @staticmethod
    def _decode(payload: str) -> AnchorCheckpoint:
        try:
            return AnchorCheckpoint.from_dict(json.loads(payload))
        except Exception as exc:  # noqa: BLE001 - a corrupt row
            raise AnchorJournalError(
                "the external anchor store holds a corrupt checkpoint: "
                f"{type(exc).__name__}"
            ) from exc

    def _read_row(
        self,
        kind: AnchorKind,
        anchor_id: str,
        sequence: int,
    ) -> Optional[tuple[AnchorCheckpoint, bool]]:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT payload, confirmed
                    FROM anchor_checkpoints
                    WHERE anchor_kind = ? AND anchor_id = ? AND sequence = ?
                    """,
                    (kind.value, anchor_id, int(sequence)),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise AnchorJournalError(
                    "failed to read an anchor checkpoint"
                ) from exc

        if row is None:
            return None

        payload, confirmed = row

        return self._decode(payload), bool(confirmed)

    def latest(
        self,
        kind: AnchorKind,
        anchor_id: str,
        *,
        confirmed: Optional[bool] = None,
    ) -> Optional[AnchorCheckpoint]:
        """The checkpoint at the highest sequence for one anchor.

        ``confirmed`` selects the published set (``False``), the confirmed
        set (``True``), or whichever is highest (``None``).
        """

        resolved = anchor_kind_of(kind)

        if resolved is None or not isinstance(anchor_id, str):
            return None

        connection = self._require_connection()

        query = (
            "SELECT payload FROM anchor_checkpoints "
            "WHERE anchor_kind = ? AND anchor_id = ? "
        )
        params: list[Any] = [resolved.value, anchor_id]

        if confirmed is not None:
            query += "AND confirmed = ? "
            params.append(1 if confirmed else 0)

        query += "ORDER BY sequence DESC LIMIT 1"

        with self._lock:
            try:
                row = connection.execute(query, tuple(params)).fetchone()
            except sqlite3.DatabaseError as exc:
                raise AnchorJournalError(
                    "failed to read an anchor checkpoint"
                ) from exc

        return self._decode(row[0]) if row else None

    # ========================================================
    # Insert
    # ========================================================

    def insert(
        self,
        checkpoint: AnchorCheckpoint,
        *,
        confirmed: bool = False,
    ) -> None:
        """Persist one checkpoint, or flip an existing one to confirmed.

        Three outcomes:

        * the position is free -- the row is written;
        * the position holds the **identical** checkpoint -- a retry after a
          crash between the write and the confirm resumes rather than fails;
        * the position holds a **different** claim -- an
          :class:`~firewall.anchor.AnchorRewindError`, because two claims
          about one position is the attack this store exists to make
          impossible.
        """

        connection = self._require_connection()

        if not isinstance(checkpoint, AnchorCheckpoint):
            raise TypeError("checkpoint must be an AnchorCheckpoint")

        if checkpoint.rederived_id() != checkpoint.checkpoint_id:
            # Refused before the write: a checkpoint whose id does not
            # describe its own fields would be stored under a key nothing
            # can re-derive, which is exactly the forgery the invariant
            # looks for.
            raise AnchorJournalError(
                "refusing to store a checkpoint whose id does not re-derive "
                "from its own fields"
            )

        payload = json.dumps(checkpoint.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO anchor_checkpoints (
                        anchor_kind,
                        anchor_id,
                        sequence,
                        checkpoint_id,
                        digest,
                        issued_at,
                        witness_key_id,
                        confirmed,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        checkpoint.kind.value,
                        checkpoint.anchor_id,
                        int(checkpoint.sequence),
                        checkpoint.checkpoint_id,
                        checkpoint.digest,
                        float(checkpoint.issued_at),
                        checkpoint.witness_key_id,
                        1 if confirmed else 0,
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                self._resolve_conflict(checkpoint, confirmed)
                return
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise AnchorJournalError(
                    "failed to persist an anchor checkpoint"
                ) from exc

    def _resolve_conflict(
        self,
        checkpoint: AnchorCheckpoint,
        confirmed: bool,
    ) -> None:
        """Decide whether a rejected insert was a retry or a rewind."""

        existing = self._read_row(
            checkpoint.kind,
            checkpoint.anchor_id,
            checkpoint.sequence,
        )

        if existing is None:
            # The constraint that fired was not the primary key, and the
            # row it belongs to is unreadable. Unreadable anchor state is a
            # denial, never a pass.
            raise AnchorJournalError(
                "a checkpoint was refused but the row could not be read"
            )

        stored, already_confirmed = existing

        if stored.checkpoint_id != checkpoint.checkpoint_id:
            raise AnchorRewindError(
                f"a different checkpoint is already stored for "
                f"{checkpoint.kind.value} at sequence "
                f"{checkpoint.sequence} of "
                f"{checkpoint.anchor_id[:8]}..."
            )

        if not confirmed or already_confirmed:
            # An identical row: the retry case. Nothing to do.
            return

        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    UPDATE anchor_checkpoints
                    SET confirmed = 1
                    WHERE anchor_kind = ? AND anchor_id = ? AND sequence = ?
                    """,
                    (
                        checkpoint.kind.value,
                        checkpoint.anchor_id,
                        int(checkpoint.sequence),
                    ),
                )
                connection.commit()
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise AnchorJournalError(
                    "failed to confirm an anchor checkpoint"
                ) from exc

    # ========================================================
    # Snapshot
    # ========================================================

    def records(self) -> tuple[AnchorCheckpoint, ...]:
        return self.load()

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT COUNT(*) FROM anchor_checkpoints"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise AnchorJournalError(
                    "failed to count anchor checkpoints"
                ) from exc

        return int(row[0]) if row else 0

    def anchor_count(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*) FROM (
                        SELECT DISTINCT anchor_kind, anchor_id
                        FROM anchor_checkpoints
                    )
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise AnchorJournalError(
                    "failed to count anchored values"
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

    def __enter__(self) -> "SQLiteAnchorStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


__all__ = ["SQLiteAnchorStore"]
