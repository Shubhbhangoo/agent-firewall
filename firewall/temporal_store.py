"""Durable per-source time watermarks.

A wall-clock regression is detectable inside one process by comparing a
reading against the highest reading that process has already seen. Across
a restart there is no such history, which is precisely the case the
time-machine attack aims at: stop the process, set the clock back, start
it again, and every window measured against wall time is longer than the
deployment asked for -- including windows on records written by the
generation before.

This module is the floor that survives that restart. It stores, per named
time source, the highest wall reading and the highest monotonic reading
ever recorded, with the generation and sample counter they came from. On
boot the guard reads them and refuses to believe a clock that is behind
the previous generation's high-water.

Two things worth stating plainly, because they bound what this store can
do:

* The **monotonic** watermark is stored for forensics, not for
  comparison. A monotonic clock is per-boot; subtracting across
  generations would compare readings from different zeros. Only the wall
  high-water is a floor across a restart.
* The store is **not tamper-proof**. An attacker who can rewrite both
  this file and the clock can present a consistent lie, exactly as the
  v3.0 state-commitment chain can be rewritten by an attacker who can
  rewrite the chain and the stores together. The documented lever is
  where this file lives, not whether the check happens.

Every raising path rolls back and re-raises as a
:class:`~firewall.temporal.TemporalError`, so a caller can treat an
unreadable watermark as a denial.
"""

from __future__ import annotations

import math
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.temporal import temporal_of


class SQLiteTemporalStore:
    """SQLite-backed persistence for per-source time watermarks.

    Mirrors the shape of the other stores in this package: WAL
    journaling, ``synchronous = FULL`` so a watermark that is reported
    written survives a crash, a per-instance ``RLock`` for the connection,
    and every error re-raised as a
    :class:`~firewall.temporal.TemporalError`.
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
            raise _error(
                "failed to initialize the temporal watermark store"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS temporal_watermarks (
                        name TEXT PRIMARY KEY,
                        wall_high_water REAL NOT NULL,
                        monotonic_high_water REAL,
                        generation TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise _error(
                    "failed to initialize the temporal watermark store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise _error("the temporal watermark store is closed")
        return self._connection

    # ========================================================
    # Watermarks
    # ========================================================

    def load_watermarks(self) -> tuple[dict[str, Any], ...]:
        """Every source's recorded high-water mark, in name order."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT
                        name,
                        wall_high_water,
                        monotonic_high_water,
                        generation,
                        sequence,
                        updated_at
                    FROM temporal_watermarks
                    ORDER BY name
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise _error(
                    "failed to read the temporal watermark store"
                ) from exc

        return tuple(
            {
                "name": row[0],
                "wall_high_water": row[1],
                "monotonic_high_water": row[2],
                "generation": row[3],
                "sequence": row[4],
                "updated_at": row[5],
            }
            for row in rows
        )

    def save_watermark(
        self,
        *,
        name: str,
        wall_high_water: Optional[float],
        monotonic_high_water: Optional[float],
        generation: str,
        sequence: int,
    ) -> None:
        """Record one source's high-water mark, keeping the maximum.

        The upsert takes ``MAX`` on both readings rather than overwriting
        with the new sample. A sample that regressed is still a sample,
        and letting it lower the stored floor would mean a single
        manipulated reading could erase the evidence that the clock moved
        -- turning the detection mechanism into the attack's accomplice.
        """

        if not isinstance(name, str) or not name:
            raise _error("a watermark needs a source name")

        if isinstance(wall_high_water, bool) or not isinstance(
            wall_high_water, (int, float)
        ):
            raise _error("wall_high_water must be numeric")

        if not math.isfinite(float(wall_high_water)):
            raise _error("wall_high_water must be finite")

        monotonic_value = None

        if monotonic_high_water is not None:
            if isinstance(monotonic_high_water, bool) or not isinstance(
                monotonic_high_water, (int, float)
            ):
                raise _error("monotonic_high_water must be numeric or None")
            if not math.isfinite(float(monotonic_high_water)):
                raise _error("monotonic_high_water must be finite")
            monotonic_value = float(monotonic_high_water)

        if not isinstance(generation, str) or not generation:
            raise _error("a watermark needs a generation label")

        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise _error("a watermark needs an integer sequence")

        try:
            updated_at = float(self._clock())
        except Exception as exc:  # noqa: BLE001 - unreadable is a denial
            raise _error(
                "the watermark store clock could not be read"
            ) from exc

        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO temporal_watermarks (
                        name,
                        wall_high_water,
                        monotonic_high_water,
                        generation,
                        sequence,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        wall_high_water = MAX(
                            temporal_watermarks.wall_high_water,
                            excluded.wall_high_water
                        ),
                        monotonic_high_water = CASE
                            WHEN temporal_watermarks.monotonic_high_water
                                 IS NULL
                                THEN excluded.monotonic_high_water
                            WHEN excluded.monotonic_high_water IS NULL
                                THEN temporal_watermarks.monotonic_high_water
                            ELSE MAX(
                                temporal_watermarks.monotonic_high_water,
                                excluded.monotonic_high_water
                            )
                        END,
                        generation = excluded.generation,
                        sequence = excluded.sequence,
                        updated_at = excluded.updated_at
                    """,
                    (
                        name,
                        float(wall_high_water),
                        monotonic_value,
                        generation,
                        int(sequence),
                        updated_at,
                    ),
                )
                connection.commit()
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise _error(
                    "failed to persist a temporal watermark"
                ) from exc

    def high_water(self, name: str) -> Optional[float]:
        """The recorded wall floor for one source, or ``None``."""

        if not isinstance(name, str) or not name:
            return None

        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT wall_high_water
                    FROM temporal_watermarks
                    WHERE name = ?
                    """,
                    (name,),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise _error(
                    "failed to read a temporal watermark"
                ) from exc

        return float(row[0]) if row else None

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT COUNT(*) FROM temporal_watermarks"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise _error(
                    "failed to count temporal watermarks"
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

    def __enter__(self) -> "SQLiteTemporalStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _error(message: str):
    """The exception type to raise. Imported lazily to keep the module
    importable in a bare process, and returned rather than raised so the
    call sites read as ``raise _error(...) from exc``."""

    from firewall.temporal import TemporalError

    return TemporalError(message)


__all__ = ["SQLiteTemporalStore"]
