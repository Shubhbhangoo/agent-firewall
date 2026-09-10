"""Persistent backend for the external attestation journal.

Without persistence an attestation journal dies with the process that
recorded it, which is a defined crash outcome but not a recoverable one:
after a restart the operator needs to know whether an external system's
statement was accepted before an execution completed. This module stores
each :class:`~firewall.external_attestation.AttestationRecord` as one row,
keyed by its natural id (``attestation_id``, the digest of the binding), so
the one-row-per-claim property holds across processes.

It stores the **nonce ledger** as a second table, and that half matters
more than the first. Replay protection is only replay protection if it
survives a restart: an envelope accepted before a crash, whose nonce was
forgotten, would be accepted again afterwards as fresh evidence -- and
"the same signed statement about the same effect was counted twice" is
exactly the property this release exists to make impossible. The primary
key is ``(issuer_id, nonce)``, so the property is enforced by the database
rather than by the process that happens to be holding the journal.

The tables are deliberately independent of the ``side_effect_journal``,
``execution_leases`` and ``verification_journal`` tables: the attestation
journal is a fourth journal beside them, and keeping it apart is what lets
an operator archive or discard external statements without rewriting the
state they describe. Pass the same file path the execution/effect/
verification stores use to keep all four durable in one database.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.external_attestation import (
    AttestationJournalError,
    AttestationRecord,
    NonceClaim,
)


class SQLiteExternalAttestationStore:
    """SQLite-backed persistence for attestation records and nonces.

    Mirrors the shape of
    :class:`firewall.verification_store.SQLiteVerificationJournal`: WAL
    journaling, a per-instance ``RLock`` for the connection, and every
    raising path rolled back and re-raised as an
    :class:`~firewall.external_attestation.AttestationJournalError` so a
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
            raise AttestationJournalError(
                "failed to initialize external attestation store"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS external_attestations (
                        attestation_id TEXT PRIMARY KEY,
                        effect_id TEXT NOT NULL,
                        attempt_id TEXT NOT NULL,
                        issuer_id TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_external_attestation_effect
                    ON external_attestations (effect_id)
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS external_attestation_nonces (
                        issuer_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        envelope_id TEXT NOT NULL,
                        effect_id TEXT NOT NULL,
                        attempt_id TEXT NOT NULL,
                        claimed_at REAL NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (issuer_id, nonce)
                    )
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise AttestationJournalError(
                    "failed to initialize external attestation store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise AttestationJournalError(
                "external attestation store is closed"
            )
        return self._connection

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> tuple[AttestationRecord, ...]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM external_attestations
                    ORDER BY attestation_id
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise AttestationJournalError(
                    "failed to read external attestations"
                ) from exc

        records: list[AttestationRecord] = []
        for (payload,) in rows:
            try:
                records.append(
                    AttestationRecord.from_dict(json.loads(payload))
                )
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise AttestationJournalError(
                    "external attestation store holds a corrupt record: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(records)

    def load_one(
        self,
        attestation_id: str,
    ) -> Optional[AttestationRecord]:
        """The current row for one claim, or ``None`` when absent."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM external_attestations
                    WHERE attestation_id = ?
                    """,
                    (attestation_id,),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise AttestationJournalError(
                    "failed to read external attestation record"
                ) from exc

        if not rows:
            return None

        try:
            return AttestationRecord.from_dict(json.loads(rows[0][0]))
        except Exception as exc:  # noqa: BLE001 - a corrupt row
            raise AttestationJournalError(
                "external attestation store holds a corrupt record: "
                f"{type(exc).__name__}"
            ) from exc

    def load_nonces(self) -> tuple[NonceClaim, ...]:
        """Every accepted ``(issuer, nonce)`` claim, in key order."""

        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM external_attestation_nonces
                    ORDER BY issuer_id, nonce
                    """
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise AttestationJournalError(
                    "failed to read the attestation nonce ledger"
                ) from exc

        claims: list[NonceClaim] = []
        for (payload,) in rows:
            try:
                claims.append(NonceClaim.from_dict(json.loads(payload)))
            except Exception as exc:  # noqa: BLE001 - a corrupt row
                raise AttestationJournalError(
                    "the attestation nonce ledger holds a corrupt claim: "
                    f"{type(exc).__name__}"
                ) from exc

        return tuple(claims)

    # ========================================================
    # Insert (record)
    # ========================================================

    def insert(
        self,
        record: AttestationRecord,
    ) -> Optional[AttestationRecord]:
        """Persist one claim; return the existing row on an identical retry.

        The primary key is the claim's natural id, so a duplicate is
        necessarily the *identical* claim -- from a crash-safe retry in
        this process, or from a second process presenting the same
        envelope. Both are answered with the stored row rather than an
        error, because refusing a duplicate of a claim already on record
        would turn a safe retry into a failure an operator has to explain.
        """

        connection = self._require_connection()

        if not isinstance(record, AttestationRecord):
            raise TypeError("record must be an AttestationRecord")

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO external_attestations (
                        attestation_id,
                        effect_id,
                        attempt_id,
                        issuer_id,
                        outcome,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.attestation_id,
                        record.effect_id,
                        record.attempt_id,
                        record.issuer_id,
                        record.outcome.value,
                        json.dumps(record.to_dict(), sort_keys=True),
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                return self.load_one(record.attestation_id)
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise AttestationJournalError(
                    "failed to persist external attestation"
                ) from exc

        return None

    # ========================================================
    # Nonce ledger
    # ========================================================

    def claim_nonce(
        self,
        claim: NonceClaim,
    ) -> tuple[bool, Optional[NonceClaim]]:
        """Claim one nonce in the durable ledger; ``(claimed, existing)``.

        The database decides, not the process: ``(issuer_id, nonce)`` is the
        primary key, so an ``INSERT`` that violates it is a claim somebody
        else already holds and the row is returned for the caller to compare
        against what it presented.
        """

        connection = self._require_connection()

        if not isinstance(claim, NonceClaim):
            raise TypeError("claim must be a NonceClaim")

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO external_attestation_nonces (
                        issuer_id,
                        nonce,
                        envelope_id,
                        effect_id,
                        attempt_id,
                        claimed_at,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim.issuer_id,
                        claim.nonce,
                        claim.envelope_id,
                        claim.effect_id,
                        claim.attempt_id,
                        float(claim.claimed_at),
                        json.dumps(claim.to_dict(), sort_keys=True),
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                existing = self._load_nonce(
                    claim.issuer_id, claim.nonce
                )
                return False, existing
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise AttestationJournalError(
                    "failed to claim an attestation nonce"
                ) from exc

        return True, claim

    def _load_nonce(
        self,
        issuer_id: str,
        nonce: str,
    ) -> Optional[NonceClaim]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM external_attestation_nonces
                    WHERE issuer_id = ? AND nonce = ?
                    """,
                    (issuer_id, nonce),
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise AttestationJournalError(
                    "failed to read an attestation nonce"
                ) from exc

        if not rows:
            return None

        try:
            return NonceClaim.from_dict(json.loads(rows[0][0]))
        except Exception as exc:  # noqa: BLE001 - a corrupt row
            raise AttestationJournalError(
                "the attestation nonce ledger holds a corrupt claim: "
                f"{type(exc).__name__}"
            ) from exc

    # ========================================================
    # Snapshot / close
    # ========================================================

    def records(self) -> tuple[AttestationRecord, ...]:
        return self.load()

    def nonces(self) -> tuple[NonceClaim, ...]:
        return self.load_nonces()

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM external_attestations
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise AttestationJournalError(
                    "failed to count external attestations"
                ) from exc

        return int(row[0]) if row else 0

    def nonce_size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM external_attestation_nonces
                    """
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise AttestationJournalError(
                    "failed to count attestation nonce claims"
                ) from exc

        return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> "SQLiteExternalAttestationStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


__all__ = ["SQLiteExternalAttestationStore"]
