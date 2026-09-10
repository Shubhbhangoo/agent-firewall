"""Persistent backend for the execution lineage journal.

Without persistence an execution's chain of custody dies with the process
that built it, which is a defined crash outcome but not a recoverable one: a
lease store that survives a restart and a lineage that does not leaves the
firewall holding an execution it can no longer say anything provable about.
This module stores each :class:`~firewall.lineage.LineageLink` as one row so
that the chain survives, which is what makes ``EXECUTION_LINEAGE_SOUNDNESS``
checkable across a restart rather than only within one process generation.

**The primary key is structural, and that is the security decision.**
``(lineage_id, sequence)`` -- not the link's declared ``commitment_id``. Two
consequences, both deliberate:

* a forged ``commitment_id`` can neither collide with nor displace a real
  link, because the key the database enforces is the position in the chain,
  and a position is claimed by writing at that position rather than by
  asserting an id;
* a link discovered to have the wrong id is a link that *fails the journal's
  own verification*, which the enforcement path turns into a refusal and the
  invariant reports -- rather than a row the database silently rejected and
  nobody noticed.

**Insert is idempotent at one position, and only for the same link.** A
retry after a crash between the write and the publish re-inserts the identical
row and receives it back. A *different* claim at a position that is already
taken raises
:class:`~firewall.lineage.LineageForkError` -- the fork is refused at the
storage layer as well as in memory, so two processes racing one chain cannot
each believe they won.

Every raising path rolls back and re-raises as a
:class:`~firewall.lineage.LineageJournalError` (or the fork error, which is a
distinct and more informative refusal), so a caller can treat unreadable
lineage state as a denial.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.lineage import (
    LINEAGE_ANCHOR,
    ExecutionLineage,
    LineageForkError,
    LineageJournalError,
    LineageLink,
    LineageStage,
    STAGE_ORDINAL,
    link_id,
)


class SQLiteLineageStore:
    """SQLite-backed persistence for execution lineage links.

    Mirrors the shape of the other stores in this package -- WAL journaling,
    ``synchronous = FULL`` so a link reported written survives a crash, a
    per-instance ``RLock`` for the connection, and errors re-raised as the
    lineage module's own error types -- and adds one thing the others do not
    need: a uniqueness constraint on the *stage position* within a lineage,
    which is what makes "one commitment per stage" a property of the database
    rather than of the process that happens to be holding the journal.
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
            raise LineageJournalError(
                "failed to initialize the execution lineage store"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS execution_lineage (
                        lineage_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        commitment_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        stage TEXT,
                        ordinal INTEGER,
                        parent_digest TEXT NOT NULL,
                        lease_id TEXT,
                        execution_id TEXT,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (lineage_id, sequence)
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_lineage_lease
                    ON execution_lineage (lease_id)
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_lineage_execution
                    ON execution_lineage (execution_id)
                    """
                )
                # One commitment per stage per lineage, enforced by the
                # database: a partial index, so the seal links (which carry
                # no stage) are unaffected and may follow one another only in
                # the journal's own terms.
                self._connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_lineage_stage
                    ON execution_lineage (lineage_id, stage)
                    WHERE stage IS NOT NULL
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise LineageJournalError(
                    "failed to initialize the execution lineage store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise LineageJournalError(
                "the execution lineage store is closed"
            )
        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> tuple[LineageLink, ...]:
        """Every link in the store, grouped by lineage and chain-ordered.

        Ordered by ``(lineage_id, sequence)`` so the caller receives each
        chain in order without needing to sort, and so a chain rebuilt from
        the store is byte-identical to the chain that was written.
        """

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM execution_lineage
                    ORDER BY lineage_id, sequence
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise LineageJournalError(
                    "failed to read execution lineages"
                ) from exc

        links: list[LineageLink] = []

        for (payload,) in rows:
            try:
                links.append(LineageLink.from_dict(json.loads(payload)))
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise LineageJournalError(
                    "the execution lineage store holds a corrupt link: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(links)

    def load_one(
        self,
        lineage_id: str,
    ) -> Optional[tuple[LineageLink, ...]]:
        """One lineage's chain, in order, or ``None`` when it is absent."""

        if not isinstance(lineage_id, str) or not lineage_id:
            return None

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM execution_lineage
                    WHERE lineage_id = ?
                    ORDER BY sequence
                    """,
                    (lineage_id,),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise LineageJournalError(
                    "failed to read an execution lineage"
                ) from exc

        if not rows:
            return None

        links: list[LineageLink] = []

        for (payload,) in rows:
            try:
                links.append(LineageLink.from_dict(json.loads(payload)))
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise LineageJournalError(
                    "the execution lineage store holds a corrupt link: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(links)

    def lineage_for_lease(self, lease_id: str) -> Optional[str]:
        """The id of the lineage bound to one lease, or ``None``.

        Lets the journal detect a *second* genesis for a lease after a
        restart, which is the fork case that survives a process generation
        and therefore cannot be caught in memory alone.
        """

        if not isinstance(lease_id, str) or not lease_id:
            return None

        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT lineage_id
                    FROM execution_lineage
                    WHERE lease_id = ?
                    ORDER BY sequence
                    LIMIT 1
                    """,
                    (lease_id,),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise LineageJournalError(
                    "failed to read a lineage binding"
                ) from exc

        return str(row[0]) if row else None

    # ========================================================
    # Insert
    # ========================================================

    def insert(
        self,
        link: LineageLink,
    ) -> Optional[LineageLink]:
        """Persist one link; return the stored twin, or raise on a fork.

        Three outcomes, and the middle one is the reason this method has a
        return value at all:

        * the position is free -- the row is written and ``None`` is
          returned, so the caller publishes the link it built;
        * the position holds the **identical** link (same id, same evidence,
          same parent) -- the stored row is returned, because a retry after a
          crash between the write and the publish must resume rather than
          fail;
        * the position holds a **different** claim -- a
          :class:`~firewall.lineage.LineageForkError`, because two branches
          of one execution is the attack this store exists to make
          impossible.
        """

        connection = self._require_connection()

        if not isinstance(link, LineageLink):
            raise TypeError("link must be a LineageLink")

        if link.rederived_id() != link.commitment_id:
            # Refused before the write: a link whose id does not describe its
            # own fields would be stored under a key nothing can re-derive,
            # which is exactly the forgery the invariant looks for.
            raise LineageJournalError(
                "refusing to store a link whose id does not re-derive from "
                "its own fields"
            )

        payload = json.dumps(link.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO execution_lineage (
                        lineage_id,
                        sequence,
                        commitment_id,
                        kind,
                        stage,
                        ordinal,
                        parent_digest,
                        lease_id,
                        execution_id,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        link.lineage_id,
                        int(link.sequence),
                        link.commitment_id,
                        link.kind.value,
                        link.stage.value if link.stage is not None else None,
                        link.ordinal,
                        link.parent_digest,
                        link.binding.get("lease_id"),
                        link.binding.get("execution_id"),
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                return self._resolve_conflict(link)
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise LineageJournalError(
                    "failed to persist a lineage link"
                ) from exc

        return None

    def _resolve_conflict(self, link: LineageLink) -> LineageLink:
        """Decide whether a rejected insert was a retry or a fork."""

        existing = self.load_one(link.lineage_id)

        if existing is None:
            # The unique constraint that fired was the stage index, and the
            # chain it belongs to is unreadable. Unreadable lineage state is
            # a denial, never a pass.
            raise LineageJournalError(
                "a lineage link was refused but the chain could not be read"
            )

        at_position = None

        for candidate in existing:
            if candidate.sequence == link.sequence:
                at_position = candidate
                break

        if at_position is None:
            # The *stage* index fired: this lineage already holds a different
            # stage at another position, which means the ordinal was reused.
            for candidate in existing:
                if candidate.stage is link.stage:
                    return self._retry_or_fork(candidate, link)

            raise LineageJournalError(
                "a lineage link was refused but no conflicting row is "
                "readable"
            )

        return self._retry_or_fork(at_position, link)

    @staticmethod
    def _retry_or_fork(
        stored: LineageLink,
        presented: LineageLink,
    ) -> LineageLink:
        identical = (
            stored.commitment_id == presented.commitment_id
            and stored.evidence_digest == presented.evidence_digest
            and stored.parent_digest == presented.parent_digest
        )

        if identical:
            return stored

        raise LineageForkError(
            f"a different claim is already stored for "
            f"{presented.stage.value if presented.stage else 'seal'} at "
            f"sequence {presented.sequence} of lineage "
            f"{presented.lineage_id[:8]}..."
        )

    # ========================================================
    # Snapshot
    # ========================================================

    def records(self) -> tuple[LineageLink, ...]:
        return self.load()

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT COUNT(*) FROM execution_lineage"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise LineageJournalError(
                    "failed to count lineage links"
                ) from exc

        return int(row[0]) if row else 0

    def lineage_count(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(DISTINCT lineage_id)
                    FROM execution_lineage
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise LineageJournalError(
                    "failed to count execution lineages"
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

    def __enter__(self) -> "SQLiteLineageStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


__all__ = ["SQLiteLineageStore"]
