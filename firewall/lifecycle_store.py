from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any, Iterable, Optional

from firewall.lifecycle import (
    LifecycleEvent,
    LifecycleEventType,
)


class LifecycleStoreError(Exception):
    """Base lifecycle persistence error."""


class LifecycleStoreClosedError(
    LifecycleStoreError
):
    """Raised when using a closed lifecycle store."""


class LifecycleStore:
    """
    Abstract lifecycle persistence interface.
    """

    def append(
        self,
        event: LifecycleEvent,
    ) -> None:
        raise NotImplementedError

    def events(
        self,
    ) -> tuple[LifecycleEvent, ...]:
        raise NotImplementedError

    def for_fingerprint(
        self,
        fingerprint: str,
    ) -> tuple[LifecycleEvent, ...]:
        raise NotImplementedError

    def of_type(
        self,
        event_type: LifecycleEventType,
    ) -> tuple[LifecycleEvent, ...]:
        raise NotImplementedError

    def size(self) -> int:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class SQLiteLifecycleStore(
    LifecycleStore
):
    """
    SQLite-backed append-only lifecycle store.

    Guarantees:

    - events survive process restart
    - insertion order is preserved
    - events are immutable after insertion
    - concurrent writes are serialized
    - invalid rows are rejected during decoding
    """

    def __init__(
        self,
        path: str | Path,
        *,
        timeout: float = 30.0,
    ):
        self.path = Path(path)

        if self.path.parent:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._lock = RLock()
        self._closed = False

        try:
            self._connection = sqlite3.connect(
                str(self.path),
                timeout=timeout,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise LifecycleStoreError(
                "failed to open lifecycle database"
            ) from exc

        self._connection.execute(
            "PRAGMA journal_mode=WAL"
        )

        self._connection.execute(
            "PRAGMA foreign_keys=ON"
        )

        self._initialize()

    # ========================================================
    # Initialization
    # ========================================================

    def _initialize(self) -> None:
        self._require_open()

        try:
            with self._connection:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lifecycle_events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        agent_id TEXT,
                        capability TEXT,
                        issuer TEXT,
                        reason TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        details_json TEXT
                    )
                    """
                )

                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_lifecycle_fingerprint
                    ON lifecycle_events(fingerprint)
                    """
                )

                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_lifecycle_event_type
                    ON lifecycle_events(event_type)
                    """
                )

        except sqlite3.Error as exc:
            raise LifecycleStoreError(
                "failed to initialize lifecycle database"
            ) from exc

    # ========================================================
    # Validation
    # ========================================================

    @staticmethod
    def _validate_event(
        event: LifecycleEvent,
    ) -> None:
        if not isinstance(
            event,
            LifecycleEvent,
        ):
            raise TypeError(
                "event must be a LifecycleEvent"
            )

        if not isinstance(
            event.event_type,
            LifecycleEventType,
        ):
            raise TypeError(
                "event.event_type must be a LifecycleEventType"
            )

        if not isinstance(
            event.fingerprint,
            str,
        ):
            raise TypeError(
                "event.fingerprint must be a string"
            )

        if not event.fingerprint.strip():
            raise ValueError(
                "event.fingerprint cannot be empty"
            )

        if not isinstance(
            event.timestamp,
            (int, float),
        ):
            raise TypeError(
                "event.timestamp must be numeric"
            )

    @staticmethod
    def _encode_details(
        details: Optional[
            dict[str, Any]
        ],
    ) -> Optional[str]:
        if details is None:
            return None

        if not isinstance(
            details,
            dict,
        ):
            raise TypeError(
                "event.details must be a dictionary"
            )

        try:
            return json.dumps(
                details,
                sort_keys=True,
                separators=(
                    ",",
                    ":",
                ),
                ensure_ascii=False,
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise LifecycleStoreError(
                "event details are not JSON serializable"
            ) from exc

    @staticmethod
    def _decode_details(
        value: Optional[str],
    ) -> Optional[dict[str, Any]]:
        if value is None:
            return None

        try:
            decoded = json.loads(
                value
            )
        except json.JSONDecodeError as exc:
            raise LifecycleStoreError(
                "stored lifecycle details are invalid JSON"
            ) from exc

        if not isinstance(
            decoded,
            dict,
        ):
            raise LifecycleStoreError(
                "stored lifecycle details must be a dictionary"
            )

        return decoded

    # ========================================================
    # Row conversion
    # ========================================================

    @classmethod
    def _row_to_event(
        cls,
        row: tuple,
    ) -> LifecycleEvent:

        (
            sequence,
            event_type,
            fingerprint,
            timestamp,
            agent_id,
            capability,
            issuer,
            reason,
            request_id,
            details_json,
        ) = row

        try:
            parsed_type = (
                LifecycleEventType(
                    event_type
                )
            )
        except ValueError as exc:
            raise LifecycleStoreError(
                f"unknown lifecycle event type: {event_type}"
            ) from exc

        details = cls._decode_details(
            details_json
        )

        # Sequence is deliberately read from the DB
        # but is not included in LifecycleEvent because
        # it is storage metadata rather than event data.
        _ = sequence

        return LifecycleEvent(
            event_type=parsed_type,
            fingerprint=fingerprint,
            timestamp=float(timestamp),
            agent_id=agent_id,
            capability=capability,
            issuer=issuer,
            reason=str(reason),
            request_id=str(request_id),
            details=details,
        )

    def _fetch_events(
        self,
        query: str,
        parameters: Iterable[Any] = (),
    ) -> tuple[
        LifecycleEvent,
        ...
    ]:
        self._require_open()

        try:
            cursor = self._connection.execute(
                query,
                tuple(parameters),
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:
            raise LifecycleStoreError(
                "failed to read lifecycle events"
            ) from exc

        return tuple(
            self._row_to_event(
                row
            )
            for row in rows
        )

    # ========================================================
    # Append
    # ========================================================

    def append(
        self,
        event: LifecycleEvent,
    ) -> None:
        self._validate_event(
            event
        )

        details_json = (
            self._encode_details(
                event.details
            )
        )

        with self._lock:
            self._require_open()

            try:
                self._connection.execute(
                    """
                    INSERT INTO lifecycle_events (
                        event_type,
                        fingerprint,
                        timestamp,
                        agent_id,
                        capability,
                        issuer,
                        reason,
                        request_id,
                        details_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_type.value,
                        event.fingerprint,
                        float(
                            event.timestamp
                        ),
                        event.agent_id,
                        event.capability,
                        event.issuer,
                        event.reason,
                        event.request_id,
                        details_json,
                    ),
                )

            except sqlite3.Error as exc:
                raise LifecycleStoreError(
                    "failed to persist lifecycle event"
                ) from exc

    # ========================================================
    # Query
    # ========================================================

    def events(
        self,
    ) -> tuple[
        LifecycleEvent,
        ...
    ]:
        with self._lock:
            return self._fetch_events(
                """
                SELECT
                    sequence,
                    event_type,
                    fingerprint,
                    timestamp,
                    agent_id,
                    capability,
                    issuer,
                    reason,
                    request_id,
                    details_json
                FROM lifecycle_events
                ORDER BY sequence ASC
                """
            )

    def for_fingerprint(
        self,
        fingerprint: str,
    ) -> tuple[
        LifecycleEvent,
        ...
    ]:
        if not isinstance(
            fingerprint,
            str,
        ):
            raise TypeError(
                "fingerprint must be a string"
            )

        fingerprint = fingerprint.strip()

        if not fingerprint:
            raise ValueError(
                "fingerprint cannot be empty"
            )

        with self._lock:
            return self._fetch_events(
                """
                SELECT
                    sequence,
                    event_type,
                    fingerprint,
                    timestamp,
                    agent_id,
                    capability,
                    issuer,
                    reason,
                    request_id,
                    details_json
                FROM lifecycle_events
                WHERE fingerprint = ?
                ORDER BY sequence ASC
                """,
                (fingerprint,),
            )

    def of_type(
        self,
        event_type: LifecycleEventType,
    ) -> tuple[
        LifecycleEvent,
        ...
    ]:
        if not isinstance(
            event_type,
            LifecycleEventType,
        ):
            raise TypeError(
                "event_type must be a LifecycleEventType"
            )

        with self._lock:
            return self._fetch_events(
                """
                SELECT
                    sequence,
                    event_type,
                    fingerprint,
                    timestamp,
                    agent_id,
                    capability,
                    issuer,
                    reason,
                    request_id,
                    details_json
                FROM lifecycle_events
                WHERE event_type = ?
                ORDER BY sequence ASC
                """,
                (
                    event_type.value,
                ),
            )

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        with self._lock:
            self._require_open()

            try:
                cursor = self._connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM lifecycle_events
                    """
                )

                row = cursor.fetchone()

            except sqlite3.Error as exc:
                raise LifecycleStoreError(
                    "failed to count lifecycle events"
                ) from exc

            return int(
                row[0]
            )

    # ========================================================
    # Close
    # ========================================================

    def close(self) -> None:
        with self._lock:

            if self._closed:
                return

            try:
                self._connection.close()

            except sqlite3.Error as exc:
                raise LifecycleStoreError(
                    "failed to close lifecycle database"
                ) from exc

            finally:
                self._closed = True

    # ========================================================
    # State
    # ========================================================

    @property
    def closed(self) -> bool:
        return self._closed

    # ========================================================
    # Guard
    # ========================================================

    def _require_open(self) -> None:
        if self._closed:
            raise LifecycleStoreClosedError(
                "lifecycle store is closed"
            )

    # ========================================================
    # Context manager
    # ========================================================

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()