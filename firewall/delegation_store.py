from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class SQLiteDelegationStore:
    """
    Persistent storage for delegation lineage metadata and the
    public signed capability records needed to rehydrate authority.

    Private signing keys are never stored here.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS capabilities (
                fingerprint TEXT PRIMARY KEY,
                capability_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lineage (
                child_fingerprint TEXT PRIMARY KEY,
                parent_fingerprint TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def save_capability(
        self,
        fingerprint: str,
        capability: dict[str, Any],
    ) -> None:
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError(
                "fingerprint must be a non-empty string"
            )

        if not isinstance(capability, dict):
            raise TypeError(
                "capability must be a dictionary"
            )

        encoded = json.dumps(
            capability,
            sort_keys=True,
            separators=(",", ":"),
        )

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO capabilities(
                    fingerprint,
                    capability_json
                )
                VALUES(?, ?)
                ON CONFLICT(fingerprint)
                DO UPDATE SET
                    capability_json=excluded.capability_json
                """,
                (fingerprint, encoded),
            )
            self._conn.commit()

    def save_lineage(
        self,
        child_fingerprint: str,
        parent_fingerprint: str,
    ) -> None:
        if not child_fingerprint or not parent_fingerprint:
            raise ValueError(
                "lineage fingerprints must be non-empty"
            )

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO lineage(
                    child_fingerprint,
                    parent_fingerprint
                )
                VALUES(?, ?)
                ON CONFLICT(child_fingerprint)
                DO UPDATE SET
                    parent_fingerprint=excluded.parent_fingerprint
                """,
                (
                    child_fingerprint,
                    parent_fingerprint,
                ),
            )
            self._conn.commit()

    def load(self) -> dict[str, list[dict[str, Any]]]:
        with self._lock:
            capability_rows = self._conn.execute(
                """
                SELECT capability_json
                FROM capabilities
                ORDER BY fingerprint
                """
            ).fetchall()

            lineage_rows = self._conn.execute(
                """
                SELECT child_fingerprint,
                       parent_fingerprint
                FROM lineage
                ORDER BY child_fingerprint
                """
            ).fetchall()

        capabilities = [
            json.loads(row[0])
            for row in capability_rows
        ]

        lineage = [
            {
                "child_fingerprint": row[0],
                "parent_fingerprint": row[1],
            }
            for row in lineage_rows
        ]

        return {
            "capabilities": capabilities,
            "lineage": lineage,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
