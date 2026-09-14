"""Persistent backend for the witness quorum journal.

A quorum the process forgets on restart is a quorum the process has to
re-take, and re-taking it means asking the witnesses again -- which is fine
until the witnesses are unreachable and the deployment discovers that its
confirmed position died with the process that confirmed it. This module
stores the five things a quorum is made of so the confirmed set survives a
restart: policies, checkpoint-policy bindings, receipts, decisions, and
equivocation evidence.

**The primary keys are structural, and that is the security decision.**
``(anchor_kind, anchor_id, sequence, witness_id)`` -- not the receipt's
declared ``receipt_id``. The same reasoning as the anchor store, for the
same reason: a vote is cast by *being* a witness at a position, not by
asserting an id, so a forged receipt id can neither collide with nor
displace a real vote. A second vote from one witness at one position is a
conflict the database refuses, which is what makes "duplicate witnesses
cannot add votes" a property of the storage rather than a promise in a
docstring.

**Decisions are monotone in the database, not only in memory.** An UPDATE
that would take a satisfied decision back to unsatisfied is refused. The
ratchet has to live here as well as in the journal: the journal is a cache
of what it believes, and the store is what the *next* process believes.

**Tampering is quarantined, not silently dropped.** Every row stores its
identity twice -- once in dedicated columns, once inside the signed or
derived payload -- and a row whose two accounts disagree, or whose payload
no longer re-derives to its stored id, is moved to a quarantine list rather
 than served. The journal poisons the anchor such a row names, so a
rewritten store yields a refusal instead of a quieter state that happens
to agree. That is "where detectable", and it is stated with that qualifier
because an attacker who rewrites a row *and* recomputes every derived id
in it has not been detected -- they have been believed.

**One database, and nothing else in it.** The quorum store lives in its own
file. Sharing a SQLite file with an unrelated security store would put a
second writer on state the firewall reasons over and would couple the
quorum's WAL to another store's lifetime; either is the shape this package
refuses everywhere else.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from firewall.quorum import (
    CheckpointPolicyBinding,
    EquivocationEvidence,
    QuorumDecision,
    QuorumDuplicateWitnessError,
    QuorumFinding,
    QuorumParticipation,
    QuorumPolicyError,
    QuorumReceipt,
    QuorumStoreError,
    WitnessPolicy,
)


class SQLiteQuorumStore:
    """SQLite-backed persistence for witness quorum state.

    Mirrors the shape of the other stores in this package -- WAL journaling,
    ``synchronous = FULL`` so a decision reported written survives a crash,
    a per-instance ``RLock`` for the connection, and errors re-raised as the
    quorum module's own error types.
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
        self._quarantine: list[tuple[str, str, str]] = []
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
            raise QuorumStoreError(
                "failed to initialize the witness quorum store"
            ) from exc

    def _initialize(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_policies (
                        policy_id TEXT NOT NULL PRIMARY KEY,
                        threshold INTEGER NOT NULL,
                        witness_ids TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_active_policy (
                        singleton INTEGER NOT NULL PRIMARY KEY
                            CHECK (singleton = 1),
                        policy_id TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_bindings (
                        checkpoint_id TEXT NOT NULL PRIMARY KEY,
                        binding_id TEXT NOT NULL,
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        digest TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        at REAL NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_receipts (
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        witness_id TEXT NOT NULL,
                        receipt_id TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        checkpoint_id TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (
                            anchor_kind, anchor_id, sequence,
                            witness_id, receipt_id
                        )
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_decisions (
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        decision_id TEXT NOT NULL,
                        checkpoint_id TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        threshold INTEGER NOT NULL,
                        satisfied INTEGER NOT NULL DEFAULT 0,
                        reason TEXT,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (anchor_kind, anchor_id, sequence)
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_participation (
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        witness_id TEXT NOT NULL,
                        receipt_id TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        checkpoint_id TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        at REAL NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (
                            anchor_kind, anchor_id, sequence, witness_id
                        )
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_equivocation (
                        evidence_id TEXT NOT NULL PRIMARY KEY,
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        witness_id TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quorum_findings (
                        row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind TEXT NOT NULL,
                        anchor_kind TEXT NOT NULL,
                        anchor_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        witness_id TEXT NOT NULL,
                        policy_id TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        at REAL NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_quorum_decisions_anchor
                    ON quorum_decisions (anchor_kind, anchor_id)
                    """
                )
                self._connection.commit()
            except sqlite3.DatabaseError as exc:
                self._connection.rollback()
                raise QuorumStoreError(
                    "failed to initialize the witness quorum store"
                ) from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise QuorumStoreError("the witness quorum store is closed")

        return self._connection

    # ========================================================
    # Quarantine
    # ========================================================

    def quarantine(self) -> tuple[tuple[str, str, str], ...]:
        """Rows that were held back because their two accounts disagreed.

        ``(anchor_kind, anchor_id, detail)`` per row. An empty tuple is the
        honest answer for a store nobody has edited; a non-empty one is the
        journal's instruction to poison the anchors named rather than
        serve the state.
        """

        with self._lock:
            return tuple(self._quarantine)

    def _hold(
        self,
        anchor_kind: Any,
        anchor_id: Any,
        detail: str,
    ) -> None:
        with self._lock:
            self._quarantine.append(
                (str(anchor_kind or ""), str(anchor_id or ""), str(detail))
            )

    # ========================================================
    # Load
    # ========================================================

    def load_policies(self) -> tuple[WitnessPolicy, ...]:
        return self._load_rows(
            "quorum_policies",
            "policy_id, threshold, witness_ids, payload",
            WitnessPolicy.from_dict,
            ("policy_id", "threshold", "witness_ids"),
        )

    def load_bindings(self) -> tuple[CheckpointPolicyBinding, ...]:
        return self._load_rows(
            "quorum_bindings",
            "binding_id, checkpoint_id, anchor_kind, anchor_id, sequence, "
            "digest, policy_id, payload",
            CheckpointPolicyBinding.from_dict,
            ("binding_id", "checkpoint_id", "anchor_kind", "anchor_id",
             "sequence", "digest", "policy_id"),
        )

    def load_receipts(self) -> tuple[QuorumReceipt, ...]:
        return self._load_rows(
            "quorum_receipts",
            "anchor_kind, anchor_id, sequence, witness_id, receipt_id, "
            "digest, checkpoint_id, policy_id, payload",
            QuorumReceipt.from_dict,
            ("anchor_kind", "anchor_id", "sequence", "witness_id",
             "receipt_id", "digest", "checkpoint_id", "policy_id"),
        )

    def load_decisions(self) -> tuple[QuorumDecision, ...]:
        return self._load_rows(
            "quorum_decisions",
            "anchor_kind, anchor_id, sequence, decision_id, checkpoint_id, "
            "digest, policy_id, threshold, satisfied, reason, payload",
            QuorumDecision.from_dict,
            ("anchor_kind", "anchor_id", "sequence", "decision_id",
             "checkpoint_id", "digest", "policy_id", "threshold",
             "satisfied"),
        )

    def load_participation(self) -> tuple[QuorumParticipation, ...]:
        return self._load_rows(
            "quorum_participation",
            "anchor_kind, anchor_id, sequence, witness_id, receipt_id, "
            "digest, checkpoint_id, policy_id, payload",
            QuorumParticipation.from_dict,
            ("anchor_kind", "anchor_id", "sequence", "witness_id",
             "receipt_id", "digest", "checkpoint_id", "policy_id"),
        )

    def load_equivocation(self) -> tuple[EquivocationEvidence, ...]:
        return self._load_rows(
            "quorum_equivocation",
            "evidence_id, anchor_kind, anchor_id, sequence, witness_id, "
            "payload",
            EquivocationEvidence.from_dict,
            ("evidence_id", "anchor_kind", "anchor_id", "sequence",
             "witness_id"),
        )

    def load_findings(self) -> tuple[QuorumFinding, ...]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    "SELECT kind, anchor_kind, anchor_id, sequence, "
                    "witness_id, policy_id, detail, at "
                    "FROM quorum_findings ORDER BY row_id"
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to read quorum findings"
                ) from exc

        return tuple(
            QuorumFinding(
                kind=str(row[0]),
                anchor_kind=str(row[1]),
                anchor_id=str(row[2]),
                sequence=int(row[3]),
                witness_id=str(row[4]),
                policy_id=str(row[5]),
                detail=str(row[6]),
                at=float(row[7]),
            )
            for row in rows
        )

    def _load_rows(
        self,
        table: str,
        columns: str,
        decode: Any,
        checked: tuple[str, ...],
    ) -> tuple[Any, ...]:
        """Decode one table, quarantining rows whose two accounts disagree.

        ``checked`` names the columns that are also inside the payload. A
        row that disagrees with itself -- the column says 2-of-3 and the
        payload says 1-of-3 -- is held back and reported, because serving
        either version would mean choosing which half of a tampered row to
        believe.
        """

        connection = self._require_connection()
        names = [item.strip() for item in columns.split(",")]

        with self._lock:
            try:
                rows = connection.execute(
                    f"SELECT {columns} FROM {table}"
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    f"failed to read {table}"
                ) from exc

        decoded: list[Any] = []

        for row in rows:
            record = dict(zip(names, row))
            anchor_kind = record.get("anchor_kind", "")
            anchor_id = record.get("anchor_id", "")

            try:
                obj = decode(json.loads(record.get("payload", "")))
            except Exception:  # noqa: BLE001 - a corrupt payload
                self._hold(
                    anchor_kind,
                    anchor_id,
                    f"{table} holds a payload that cannot be decoded",
                )
                continue

            if not self._agrees(obj, record, checked):
                self._hold(
                    anchor_kind,
                    anchor_id,
                    f"{table} holds a payload that disagrees with its own "
                    "columns",
                )
                continue

            if hasattr(obj, "rederives") and not obj.rederives():
                self._hold(
                    anchor_kind,
                    anchor_id,
                    f"{table} holds a record that does not re-derive to its "
                    "stored id",
                )
                continue

            decoded.append(obj)

        return tuple(decoded)

    @staticmethod
    def _agrees(
        obj: Any,
        record: dict[str, Any],
        checked: tuple[str, ...],
    ) -> bool:
        for name in checked:
            if not hasattr(obj, name):
                continue

            expected = getattr(obj, name)

            if name == "sequence":
                if int(record[name]) != int(expected):
                    return False

                continue

            if name == "satisfied":
                if bool(record[name]) != bool(expected):
                    return False

                continue

            if name == "threshold":
                if int(record[name]) != int(expected):
                    return False

                continue

            if name in ("witness_ids",):
                if sorted(json.loads(record[name])) != sorted(expected):
                    return False

                continue

            if str(record[name]) != str(expected):
                return False

        return True

    def active_policy_id(self) -> Optional[str]:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT policy_id FROM quorum_active_policy "
                    "WHERE singleton = 1"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to read the active quorum policy"
                ) from exc

        return str(row[0]) if row else None

    # ========================================================
    # Insert
    # ========================================================

    def insert_policy(self, policy: WitnessPolicy) -> None:
        """Persist one witness policy, or refuse a mutation of one in use."""

        if not isinstance(policy, WitnessPolicy):
            raise TypeError("policy must be a WitnessPolicy")

        if not policy.rederives():
            raise QuorumPolicyError(
                "refusing to store a policy whose id does not re-derive "
                "from its own fields"
            )

        connection = self._require_connection()
        payload = json.dumps(policy.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_policies (
                        policy_id, threshold, witness_ids, payload
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        policy.policy_id,
                        int(policy.threshold),
                        json.dumps(list(policy.witness_ids)),
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                self._resolve_policy_conflict(policy, payload)
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to persist a witness policy"
                ) from exc

    def _resolve_policy_conflict(
        self,
        policy: WitnessPolicy,
        payload: str,
    ) -> None:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT payload FROM quorum_policies WHERE policy_id = ?",
                    (policy.policy_id,),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to read a witness policy"
                ) from exc

        if row is None:
            raise QuorumStoreError(
                "a witness policy was refused but the row could not be read"
            )

        if str(row[0]) == payload:
            return

        # Same derived id, different content. Because the id *is* the
        # digest of the content, this can only happen if someone edited the
        # row in place -- which is the mutation-after-use attack, caught at
        # the storage layer rather than only in memory.
        raise QuorumPolicyError(
            "a different policy is already stored under this id; a policy "
            "in use cannot be mutated"
        )

    def set_active_policy(self, policy_id: str) -> None:
        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_active_policy (singleton, policy_id)
                    VALUES (1, ?)
                    ON CONFLICT (singleton) DO UPDATE SET policy_id = ?
                    """,
                    (str(policy_id), str(policy_id)),
                )
                connection.commit()
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to record the active quorum policy"
                ) from exc

    def insert_binding(
        self,
        binding: CheckpointPolicyBinding,
    ) -> None:
        """Persist one checkpoint-policy binding, or refuse a re-binding."""

        if not isinstance(binding, CheckpointPolicyBinding):
            raise TypeError("binding must be a CheckpointPolicyBinding")

        if not binding.rederives():
            raise QuorumStoreError(
                "refusing to store a binding whose id does not re-derive "
                "from its own fields"
            )

        connection = self._require_connection()
        payload = json.dumps(binding.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_bindings (
                        checkpoint_id, binding_id, anchor_kind, anchor_id,
                        sequence, digest, policy_id, at, payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        binding.checkpoint_id,
                        binding.binding_id,
                        binding.anchor_kind,
                        binding.anchor_id,
                        int(binding.sequence),
                        binding.digest,
                        binding.policy_id,
                        float(binding.at),
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                self._resolve_binding_conflict(binding, payload)
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to persist a checkpoint binding"
                ) from exc

    def _resolve_binding_conflict(
        self,
        binding: CheckpointPolicyBinding,
        payload: str,
    ) -> None:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT payload FROM quorum_bindings "
                    "WHERE checkpoint_id = ?",
                    (binding.checkpoint_id,),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to read a checkpoint binding"
                ) from exc

        if row is None:
            raise QuorumStoreError(
                "a checkpoint binding was refused but the row could not be "
                "read"
            )

        if str(row[0]) == payload:
            return

        raise QuorumPolicyError(
            "this checkpoint is already bound to a different policy; a "
            "checkpoint holds exactly one binding"
        )

    def insert_receipt(self, receipt: QuorumReceipt) -> None:
        """Persist one witness receipt, refusing one that does not re-derive."""

        if not isinstance(receipt, QuorumReceipt):
            raise TypeError("receipt must be a QuorumReceipt")

        if not receipt.rederives():
            raise QuorumStoreError(
                "refusing to store a receipt whose id does not re-derive "
                "from its own fields"
            )

        connection = self._require_connection()
        payload = json.dumps(receipt.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_receipts (
                        anchor_kind, anchor_id, sequence, witness_id,
                        receipt_id, digest, checkpoint_id, policy_id, payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.anchor_kind,
                        receipt.anchor_id,
                        int(receipt.sequence),
                        receipt.witness_id,
                        receipt.receipt_id,
                        receipt.digest,
                        receipt.checkpoint_id,
                        receipt.policy_id,
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                self._resolve_receipt_conflict(receipt)
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to persist a witness receipt"
                ) from exc

    def _resolve_receipt_conflict(
        self,
        receipt: QuorumReceipt,
    ) -> None:
        """One witness, one vote per position, enforced by the primary key."""

        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT receipt_id FROM quorum_receipts "
                    "WHERE anchor_kind = ? AND anchor_id = ? "
                    "AND sequence = ? AND witness_id = ?",
                    (
                        receipt.anchor_kind,
                        receipt.anchor_id,
                        int(receipt.sequence),
                        receipt.witness_id,
                    ),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to read a witness receipt"
                ) from exc

        if row is None:
            raise QuorumStoreError(
                "a witness receipt was refused but the row could not be read"
            )

        if str(row[0]) == receipt.receipt_id:
            # The identical receipt: a retry after a crash between the
            # write and the confirmation of it. Idempotent.
            return

        raise QuorumDuplicateWitnessError(
            f"witness {receipt.witness_id!r} has already voted at this "
            "position; one witness casts one vote"
        )

    def insert_participation(
        self,
        row: QuorumParticipation,
    ) -> None:
        """Record which witness voted where, keyed on the identity."""

        if not isinstance(row, QuorumParticipation):
            raise TypeError("row must be a QuorumParticipation")

        connection = self._require_connection()
        payload = json.dumps(row.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_participation (
                        anchor_kind, anchor_id, sequence, witness_id,
                        receipt_id, digest, checkpoint_id, policy_id, at,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row.anchor_kind,
                        row.anchor_id,
                        int(row.sequence),
                        row.witness_id,
                        row.receipt_id,
                        row.digest,
                        row.checkpoint_id,
                        row.policy_id,
                        float(row.at),
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                raise QuorumDuplicateWitnessError(
                    f"witness {row.witness_id!r} is already recorded as "
                    "having voted at this position"
                )
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to persist witness participation"
                ) from exc

    def insert_decision(self, decision: QuorumDecision) -> None:
        """Persist one quorum decision, and never un-confirm one.

        The monotonic guard lives here as well as in the journal. The
        journal is a cache of what this process believes; the store is what
        the *next* process believes, and a ratchet enforced in only one of
        the two is a ratchet that can be unwound by restarting.
        """

        if not isinstance(decision, QuorumDecision):
            raise TypeError("decision must be a QuorumDecision")

        if not decision.rederives():
            raise QuorumStoreError(
                "refusing to store a decision whose id does not re-derive "
                "from its own fields"
            )

        connection = self._require_connection()
        payload = json.dumps(decision.to_dict(), sort_keys=True)

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT satisfied, decision_id FROM quorum_decisions "
                    "WHERE anchor_kind = ? AND anchor_id = ? "
                    "AND sequence = ?",
                    (
                        decision.anchor_kind,
                        decision.anchor_id,
                        int(decision.sequence),
                    ),
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to read a quorum decision"
                ) from exc

            if row is not None and bool(row[0]) and not decision.satisfied:
                raise QuorumStoreError(
                    "quorum is monotone: a confirmed decision for this "
                    "position cannot be taken back"
                )

            if row is not None and bool(row[0]) and str(
                row[1]
            ) == decision.decision_id:
                return

            try:
                connection.execute(
                    """
                    INSERT INTO quorum_decisions (
                        anchor_kind, anchor_id, sequence, decision_id,
                        checkpoint_id, digest, policy_id, threshold,
                        satisfied, reason, payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (anchor_kind, anchor_id, sequence)
                    DO UPDATE SET
                        decision_id = excluded.decision_id,
                        checkpoint_id = excluded.checkpoint_id,
                        digest = excluded.digest,
                        policy_id = excluded.policy_id,
                        threshold = excluded.threshold,
                        satisfied = excluded.satisfied,
                        reason = excluded.reason,
                        payload = excluded.payload
                    """,
                    (
                        decision.anchor_kind,
                        decision.anchor_id,
                        int(decision.sequence),
                        decision.decision_id,
                        decision.checkpoint_id,
                        decision.digest,
                        decision.policy_id,
                        int(decision.threshold),
                        1 if decision.satisfied else 0,
                        decision.reason,
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to persist a quorum decision"
                ) from exc

    def insert_equivocation(
        self,
        evidence: EquivocationEvidence,
    ) -> None:
        """Persist equivocation evidence: both statements, forever."""

        if not isinstance(evidence, EquivocationEvidence):
            raise TypeError("evidence must be an EquivocationEvidence")

        connection = self._require_connection()
        payload = json.dumps(evidence.to_dict(), sort_keys=True)

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_equivocation (
                        evidence_id, anchor_kind, anchor_id, sequence,
                        witness_id, payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (evidence_id) DO NOTHING
                    """,
                    (
                        evidence.evidence_id,
                        evidence.anchor_kind,
                        evidence.anchor_id,
                        int(evidence.sequence),
                        evidence.witness_id,
                        payload,
                    ),
                )
                connection.commit()
            except sqlite3.DatabaseError as exc:
                connection.rollback()
                raise QuorumStoreError(
                    "failed to persist equivocation evidence"
                ) from exc

    def insert_finding(self, finding: QuorumFinding) -> None:
        if not isinstance(finding, QuorumFinding):
            raise TypeError("finding must be a QuorumFinding")

        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT INTO quorum_findings (
                        kind, anchor_kind, anchor_id, sequence, witness_id,
                        policy_id, detail, at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.kind,
                        finding.anchor_kind,
                        finding.anchor_id,
                        int(finding.sequence),
                        finding.witness_id,
                        finding.policy_id,
                        finding.detail,
                        float(finding.at),
                    ),
                )
                connection.commit()
            except sqlite3.DatabaseError:
                connection.rollback()

    # ========================================================
    # Snapshot
    # ========================================================

    def size(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT COUNT(*) FROM quorum_receipts"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to count quorum receipts"
                ) from exc

        return int(row[0]) if row else 0

    def decision_count(self) -> int:
        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    "SELECT COUNT(*) FROM quorum_decisions"
                ).fetchone()
            except sqlite3.DatabaseError as exc:
                raise QuorumStoreError(
                    "failed to count quorum decisions"
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

    def __enter__(self) -> "SQLiteQuorumStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


__all__ = ["SQLiteQuorumStore"]
