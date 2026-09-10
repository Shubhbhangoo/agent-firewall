"""Effect verification: whether a recorded side-effect claim can be trusted.

v2.8 recorded the side-effect protocol as a journal of phases
(``INTENT_RECORDED -> ATTEMPT_STARTED -> SUCCEEDED / FAILED / UNKNOWN``)
and was careful about one direction only: a receipt is an observation,
never a permission, and ``receipt != proof`` unless the integration
authenticates the provider. What v2.8 deliberately did **not** do is
decide whether an observation that is already in the journal deserves to
be *trusted* for completion. Its ``commit_effect`` closed the execution
as ``COMPLETED`` over a succeeded receipt whose authority flag was valid,
whatever the evidence kind -- a ``caller_assertion`` and an authenticated
``provider_evidence`` claim completed identically.

v2.9 draws the separator that release could not:

.. code-block:: text

    AUTHORIZED  =/=  EXECUTED  =/=  OBSERVED  =/=  VERIFIED  =/=  COMPLETED

AUTHORIZED is the canonical allow. EXECUTED is the lease leaving
``STARTED``. OBSERVED is a three-way outcome recorded in the side-effect
journal by whoever claimed it (caller, handler, provider). VERIFIED is a
new, separately journaled claim: that the *recorded* observation --
exactly the row in the side-effect journal, bound to exactly that
attempt -- was independently checked and held up. COMPLETED is the lease
closing cleanly, and from v2.9 on it requires the verified claim, not
merely the observed one.

This module is that layer, and it states its own limits first.

**What verification establishes, and what it does not.** The verifier is
a function the deployment supplies (an authenticator that checks the
provider's status API, a webhook signature check, an internal auditor),
or the built-in structural verifier when none is supplied. Whatever it
is, its verdict is recorded about the *recorded claim*, never about the
world: the firewall cannot know what an uncontrolled external system
did. A ``VERIFIED`` verdict means the recorded observation survived the
check the deployment configured -- and the record says exactly which
method performed that check, so nobody can read more into it than the
deployment actually established. In particular the built-in structural
verifier establishes only that the claim is internally consistent,
correctly bound, and recorded under currently valid authority; it never
returns ``VERIFIED`` for evidence that *labels itself* ``provider_evidence``,
because a label is not proof -- only an authenticating verifier may
confirm provider evidence.

**Verification cannot become authorization.** Nothing here can make an
``authorize`` allow, and nothing here writes to the lease journal or the
side-effect journal. The verification journal is a third journal beside
them: an operator may archive it, throw it away, or keep it without
rewriting either of the other two. Its only effect on the rest of the
system is a refusal -- ``complete_execution`` refuses a clean
``COMPLETED`` over a side effect that has no *current* verified claim --
and refusals can never widen authority.

**The binding is everything.** A verification record is keyed to exactly
one (effect, attempt, evidence snapshot):

* ``effect_id`` + ``lease_id`` + ``execution_id`` pin it to the one
  external effect of the one execution that adopted the protocol;
* ``attempt_id`` pins it to the one atomic attempt that crossed the
  boundary -- a verification recorded for an earlier attempt can never
  speak for a later one;
* the evidence snapshot (state, observed outcome, evidence kind,
  correlation ids, authority flag, observation time) is captured from
  the *journal row at verification time* and digested into the record,
  so a verified claim can never be moved onto different evidence;
* the record's own id is the digest of that binding, so a forged, edited
  or replayed row disagrees with the id it claims and is refused, and a
  duplicate of the identical claim cannot be inserted twice.

A verification that is not current is refused by the completion gate,
never silently reused: if the side-effect row's evidence changed after
verification (a later reconciliation re-stamped the outcome), the old
snapshot no longer matches and the claim is stale -- the caller must
verify the new evidence before the execution can complete. Contradictory
evidence is never resolved by rewriting: a later ``CONTRADICTED`` verdict
for the same snapshot is preserved alongside any earlier claim, and the
completion gate trusts only the *latest* verdict for the *current*
snapshot.

**Restart safety.** Like the effect journal and the lease store, the
journal holds state and persists through an optional SQLite backend
(:class:`firewall.verification_store.SQLiteVerificationJournal`); rows
are written before they are published in memory, and a restart recovers
both journals from the one database. A crash between the side-effect
receipt and the verification leaves a row that is observed but not
verified -- which is exactly what the record says, never a guess that
verification happened.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from firewall.effect import (
    EffectOutcome,
    EffectState,
    ReceiptKind,
)

#: The method id reserved for the built-in structural verifier.
#:
#: A deployment's authenticator must name itself something else: the
#: census of what "verified" may mean is that the record's method is
#: either this structural id (internal consistency only) or a
#: deployment-named integration that actually authenticated the claim.
#: Provider evidence may only be confirmed by a non-structural method --
#: see the module docstring.
STRUCTURAL_METHOD = "structural"


class VerificationOutcome(str, Enum):
    """What one verification attempt concluded about one recorded claim.

    Three verdicts, and the asymmetry between them is load-bearing.
    ``VERIFIED`` is the only one a completion may rely on, and it may
    only be *recorded* while the execution's authority basis still holds.
    ``NOT_VERIFIED`` and ``CONTRADICTED`` are recorded truthfully whenever
    they are what the check produced -- they can only refuse, so no
    authority check is needed to preserve them -- but ``CONTRADICTED``
    says more than ``NOT_VERIFIED`` and is preserved as the explicit
    record that the evidence was actively contradicted, never overwritten
    and never resolved away.
    """

    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    CONTRADICTED = "contradicted"


def verification_outcome_of(value: Any) -> Optional["VerificationOutcome"]:
    """``VerificationOutcome`` from a member or its value; ``None`` otherwise."""

    try:
        return VerificationOutcome(value)
    except (TypeError, ValueError):
        return None


def canonical_evidence_snapshot(row: Any) -> dict[str, Any]:
    """The evidence snapshot of one side-effect journal row.

    The snapshot is the *recorded observation* a verification speaks
    about: the row's state, its observed three-way outcome, who reported
    it (the evidence kind), the external correlation id and provider, the
    receipt's authority flag, and the moment it was observed. It is read
    from the journal row object -- never assembled from caller-supplied
    strings -- so verification can never be pointed at evidence the
    journal does not hold. A later reconciliation changes the row and
    therefore the snapshot, which is exactly what makes an earlier
    verification stale.

    ``observed_at`` is included as raw seconds. Floats that round-trip
    through ``json.dumps`` are deterministic, and the snapshot is always
    re-derived from a row in the same process generation, so two
    derivations of one row agree byte for byte.
    """

    snapshot = {
        "state": row.state.value,
        "observed_outcome": (
            row.observed_outcome.value
            if row.observed_outcome is not None
            else None
        ),
        "observed_at": (
            float(row.observed_at)
            if row.observed_at is not None
            else None
        ),
        "evidence_kind": (
            row.evidence_kind.value
            if row.evidence_kind is not None
            else None
        ),
        "external_request_id": row.external_request_id,
        "provider": row.provider,
        "receipt_authority_valid": row.receipt_authority_valid,
    }
    return snapshot


def canonical_snapshot_digest(snapshot: dict[str, Any]) -> str:
    """A stable digest of one evidence snapshot, from the snapshot itself.

    Recomputable from a stored snapshot dict, which is what lets a
    record's ``snapshot_digest`` field be re-verified against its own
    ``snapshot`` without holding the original side-effect row.
    """

    payload = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def canonical_evidence_digest(row: Any) -> str:
    """A stable digest of one side-effect row's evidence snapshot.

    The verification record binds itself to this digest, so a verified
    claim can never be moved onto other evidence: presenting a different
    row, or the same row after a reconciliation, produces a different
    digest and the old claim is stale rather than reusable.
    """

    return canonical_snapshot_digest(canonical_evidence_snapshot(row))


def verification_binding_digest(
    *,
    effect_id: str,
    attempt_id: str,
    snapshot_digest: str,
    outcome: VerificationOutcome,
    method: str,
) -> str:
    """The natural id of one verification claim.

    The id is the digest of everything the claim is bound to: the exact
    effect, the exact attempt, the exact evidence snapshot, the verdict,
    and the method that produced it. A record whose stored fields do not
    re-derive to its own id is a forged record -- the invariant
    ``EFFECT_VERIFICATION_SOUNDNESS`` checks exactly that on every row.
    Re-deriving also makes a duplicate of the identical claim collide at
    the store (one row per claim), while a genuinely new claim -- a
    contradiction recorded later against the same snapshot, a verdict on
    a newer snapshot -- necessarily carries a different id and is stored
    beside the old one.
    """

    payload = json.dumps(
        {
            "effect_id": effect_id,
            "attempt_id": attempt_id,
            "snapshot_digest": snapshot_digest,
            "outcome": outcome.value,
            "method": method,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def evidence_package(
    row: Any,
    *,
    snapshot: Optional[dict[str, Any]] = None,
    snapshot_digest: Optional[str] = None,
) -> dict[str, Any]:
    """The read-only evidence package handed to a verifier.

    Contains the row's binding fields (which effect, lease, execution and
    attempt the claim belongs to) and its recorded observation (the
    evidence snapshot). The verifier receives a copy of the recorded
    values -- never the caller's -- so a verifier that inspects
    ``external_request_id`` or ``provider`` inspects what the journal
    actually recorded.
    """

    snapshot = snapshot if snapshot is not None else canonical_evidence_snapshot(row)
    digest = (
        snapshot_digest
        if snapshot_digest is not None
        else canonical_evidence_digest(row)
    )

    return {
        "effect_id": row.effect_id,
        "lease_id": row.lease_id,
        "execution_id": row.execution_id,
        "attempt_id": row.attempt_id,
        "effect_type": row.effect_type,
        "effect_digest": row.effect_digest,
        "capability_fingerprint": row.capability_fingerprint,
        "agent_id": row.agent_id,
        "action": row.action,
        "snapshot": dict(snapshot),
        "snapshot_digest": digest,
    }


@dataclass(frozen=True)
class VerifierVerdict:
    """The answer one verification check produced.

    ``outcome`` is the verdict; ``method`` names what performed the check
    (``STRUCTURAL_METHOD`` for the built-in verifier, or the
    deployment-named authenticator otherwise); ``note`` carries a
    human-readable reason. A verdict is data -- the SDK decides what may
    be recorded from it, and the record decides what may complete.
    """

    outcome: VerificationOutcome
    method: str
    note: Optional[str] = None


def structural_verifier(evidence: Any) -> VerifierVerdict:
    """The built-in verifier: internal soundness, never a world claim.

    Establishes exactly what the firewall's own records can support:

    * the claim names an effect, an attempt and an observation, and the
      observation was recorded under currently valid authority
      (``receipt_authority_valid`` is ``True``) -- a record made after
      authority was lost says the effect happened, not that it may be
      trusted;
    * the evidence is a handler observation or a caller assertion, i.e.
      a claim the firewall itself recorded faithfully -- for these, a
      structurally consistent, correctly bound, authority-valid record
      is what "verified" can honestly mean in-process;
    * evidence that labels itself ``provider_evidence`` is **not**
      confirmed here. A label is not proof; only an authenticating
      verifier the deployment wired may return ``VERIFIED`` for provider
      evidence.

    The package it inspects is derived from the journal row by
    :func:`evidence_package`; nothing caller-supplied reaches it.
    """

    snapshot = evidence.get("snapshot", {}) if isinstance(evidence, dict) else {}
    kind = snapshot.get("evidence_kind")
    outcome = snapshot.get("observed_outcome")

    if (
        isinstance(snapshot.get("receipt_authority_valid"), bool)
        and not snapshot["receipt_authority_valid"]
    ):
        return VerifierVerdict(
            outcome=VerificationOutcome.NOT_VERIFIED,
            method=STRUCTURAL_METHOD,
            note="the observation was recorded after authority was lost, "
            "so it cannot be trusted for completion",
        )

    if outcome is None:
        return VerifierVerdict(
            outcome=VerificationOutcome.NOT_VERIFIED,
            method=STRUCTURAL_METHOD,
            note="the row carries no observed outcome to verify",
        )

    if kind == ReceiptKind.PROVIDER_EVIDENCE.value:
        return VerifierVerdict(
            outcome=VerificationOutcome.NOT_VERIFIED,
            method=STRUCTURAL_METHOD,
            note="provider evidence requires an authenticating verifier; "
            "a label is not proof",
        )

    if kind not in (
        ReceiptKind.CALLER_ASSERTION.value,
        ReceiptKind.HANDLER_OBSERVATION.value,
    ):
        return VerifierVerdict(
            outcome=VerificationOutcome.NOT_VERIFIED,
            method=STRUCTURAL_METHOD,
            note="the recorded evidence kind is not one the structural "
            "verifier can confirm",
        )

    return VerifierVerdict(
        outcome=VerificationOutcome.VERIFIED,
        method=STRUCTURAL_METHOD,
        note="the recorded claim is internally consistent, correctly "
        "bound to this effect and attempt, and was observed under "
        "currently valid authority; no external-world claim is made",
    )


@dataclass(frozen=True)
class VerificationRecord:
    """One immutable verification claim about one recorded observation.

    The journal row is the authority on verification state, exactly as
    the lease record is the authority on lease state: a forged, copied or
    edited record is refused because it disagrees with the id it claims.
    Every field below the binding fields is fixed at creation -- a
    verification claim, once recorded, is never amended. Contradiction is
    handled by recording a *second* claim beside it, never by editing the
    first.

    The binding fields (effect/lease/execution/attempt, snapshot digest,
    outcome, method) are what ``verification_id`` digests; ``note`` and
    ``recorded_at`` are commentary and do not participate in the id, so
    re-recording the identical claim (a crash-safe retry of the same
    verification) collides and returns the original instead of creating a
    second row.
    """

    verification_id: str
    effect_id: str
    lease_id: str
    execution_id: Optional[str]
    attempt_id: str
    outcome: VerificationOutcome
    method: str
    snapshot: dict[str, Any]
    snapshot_digest: str
    #: What the side-effect row recorded at verification time, so an
    #: auditor can read the claim without cross-referencing two journals
    #: and so a record can never silently bless a different observation.
    observed_outcome: Optional[EffectOutcome]
    evidence_kind: Optional[ReceiptKind]
    receipt_authority_valid: bool
    note: Optional[str] = None
    recorded_at: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "effect_id": self.effect_id,
            "lease_id": self.lease_id,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "outcome": self.outcome.value,
            "method": self.method,
            "snapshot": dict(self.snapshot),
            "snapshot_digest": self.snapshot_digest,
            "observed_outcome": (
                self.observed_outcome.value
                if self.observed_outcome is not None
                else None
            ),
            "evidence_kind": (
                self.evidence_kind.value
                if self.evidence_kind is not None
                else None
            ),
            "receipt_authority_valid": self.receipt_authority_valid,
            "note": self.note,
            "recorded_at": self.recorded_at,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "VerificationRecord":
        """Reconstruct a verification record from its serialized form.

        Reconstruction is deliberately not trust: the enforcement path
        still re-derives the id from the binding fields and refuses a
        record that does not match the id it claims. Malformed input is
        refused loudly -- a store row that cannot be reconstructed is a
        corrupt row.
        """

        if not isinstance(data, dict):
            raise TypeError("verification record data must be a dictionary")

        def _need_str(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"verification field {key!r} must be a non-empty string"
                )
            return value

        def _need_finite(key: str) -> float:
            value = data.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"verification field {key!r} must be numeric"
                )
            result = float(value)
            if not math.isfinite(result):
                raise ValueError(
                    f"verification field {key!r} must be finite"
                )
            return result

        outcome = verification_outcome_of(data.get("outcome"))
        if outcome is None:
            raise ValueError(
                f"verification field 'outcome' is not a verdict: "
                f"{data.get('outcome')!r}"
            )

        observed_value = data.get("observed_outcome")
        try:
            observed_outcome = (
                EffectOutcome(observed_value)
                if observed_value is not None
                else None
            )
        except (TypeError, ValueError):
            raise ValueError(
                "verification field 'observed_outcome' is not an outcome: "
                f"{observed_value!r}"
            ) from None

        kind_value = data.get("evidence_kind")
        try:
            evidence_kind = (
                ReceiptKind(kind_value)
                if kind_value is not None
                else None
            )
        except (TypeError, ValueError):
            raise ValueError(
                "verification field 'evidence_kind' is not a receipt kind: "
                f"{kind_value!r}"
            ) from None

        snapshot = data.get("snapshot")
        if not isinstance(snapshot, dict):
            raise ValueError(
                "verification field 'snapshot' must be an object"
            )

        authority_valid = data.get("receipt_authority_valid")
        if not isinstance(authority_valid, bool):
            raise ValueError(
                "verification field 'receipt_authority_valid' must be "
                "a boolean"
            )

        note = data.get("note")
        if note is not None and not isinstance(note, str):
            raise ValueError("verification field 'note' must be a string or None")

        method = _need_str("method")
        if method != STRUCTURAL_METHOD and not method.strip():
            raise ValueError("verification method must not be blank")

        return cls(
            verification_id=_need_str("verification_id"),
            effect_id=_need_str("effect_id"),
            lease_id=_need_str("lease_id"),
            execution_id=data.get("execution_id"),
            attempt_id=_need_str("attempt_id"),
            outcome=outcome,
            method=method,
            snapshot=dict(snapshot),
            snapshot_digest=_need_str("snapshot_digest"),
            observed_outcome=observed_outcome,
            evidence_kind=evidence_kind,
            receipt_authority_valid=authority_valid,
            note=note,
            recorded_at=_need_finite("recorded_at"),
            details=dict(data.get("details", {}) or {}),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"VerificationRecord(verification_id={self.verification_id[:8]}..., "
            f"outcome={self.outcome.value}, method={self.method!r}, "
            f"effect={self.effect_id[:8]}...)"
        )


class VerificationJournalError(Exception):
    """Base error for the verification journal."""


class VerificationIdMismatchError(VerificationJournalError):
    """A record's stored id does not match the id its binding re-derives.

    Raised before anything is written: a forged or edited record that
    claims an id it does not own must never reach the journal.
    """


@dataclass(frozen=True)
class VerificationResult:
    """The answer one verification protocol operation returns.

    ``allowed`` is true only when a ``VERIFIED`` claim is on record for
    the exact effect, attempt and evidence snapshot the caller asked to
    verify. Every refusal is a verdict-shaped ``False`` with a reason --
    never an exception -- and carries the record that *was* written when
    the verdict was a truthful ``NOT_VERIFIED`` or ``CONTRADICTED`` (both
    are preserved, and neither grants anything).

    ``record`` is the authoritative journal record after the attempt, or
    ``None`` when the presented effect did not name a row at all.
    """

    allowed: bool
    reason: str
    outcome: Optional[VerificationOutcome]
    record: Optional[VerificationRecord] = None

    @classmethod
    def refused(cls, reason: str) -> "VerificationResult":
        return cls(
            allowed=False,
            reason=reason,
            outcome=None,
            record=None,
        )


class VerificationJournal:
    """The authority on verification claims.

    One row per distinct claim, where a claim is identified by its
    natural id -- the digest of (effect, attempt, snapshot, verdict,
    method). Inserting the identical claim twice returns the existing row
    (a crash-safe retry is idempotent); inserting a genuinely different
    claim -- a contradiction, a verdict on a newer snapshot -- stores it
    beside the first, so contradictory evidence is preserved rather than
    resolved. The journal decides *what was recorded*, never *what may
    complete*: it has no reference to any authority store and constructs
    no verdict of its own beyond the records handed to it.

    An optional persistent backend (see
    :class:`firewall.verification_store.SQLiteVerificationJournal`) makes
    rows survive a process restart; the natural-id primary key makes the
    one-row-per-claim property hold across processes too.
    """

    def __init__(
        self,
        *,
        clock=None,
        backend: Optional[Any] = None,
    ):
        self._clock = clock if clock is not None else time.time
        self._backend = backend
        self._lock = threading.RLock()
        self._records: dict[str, VerificationRecord] = {}
        self._by_effect: dict[str, list[str]] = {}

        if backend is not None:
            for record in backend.load():
                self._records[record.verification_id] = record
                self._by_effect.setdefault(
                    record.effect_id, []
                ).append(record.verification_id)

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock is failure
            raise VerificationJournalError(
                "verification journal clock could not be read"
            ) from None

    def now(self) -> float:
        """The journal's own clock reading, for deadline comparison."""

        return self._now()

    # ========================================================
    # Record
    # ========================================================

    def record(
        self,
        *,
        effect_id: str,
        lease_id: str,
        execution_id: Optional[str],
        attempt_id: str,
        outcome: VerificationOutcome,
        method: str,
        snapshot: dict[str, Any],
        snapshot_digest: str,
        observed_outcome: Optional[EffectOutcome],
        evidence_kind: Optional[ReceiptKind],
        receipt_authority_valid: bool,
        note: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> VerificationRecord:
        """Record one verification claim, or return its identical twin.

        The record's id is re-derived from the binding fields and must
        match; a mismatched id is refused before anything is written.
        Returns the existing record when the identical claim is already
        on the journal (idempotent retry), and the freshly written record
        otherwise. Raises :class:`VerificationJournalError` when the row
        cannot be persisted -- a claim must not be reported recorded when
        the journal could not write it.
        """

        for label, value in (
            ("effect_id", effect_id),
            ("lease_id", lease_id),
            ("attempt_id", attempt_id),
            ("method", method),
            ("snapshot_digest", snapshot_digest),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be a non-empty string")

        if not isinstance(outcome, VerificationOutcome):
            raise TypeError("outcome must be a VerificationOutcome")

        if not isinstance(snapshot, dict):
            raise TypeError("snapshot must be a dictionary")

        if not isinstance(receipt_authority_valid, bool):
            raise TypeError("receipt_authority_valid must be a boolean")

        if note is not None and not isinstance(note, str):
            raise TypeError("note must be a string or None")

        if execution_id is not None and (
            not isinstance(execution_id, str) or not execution_id
        ):
            raise ValueError(
                "execution_id must be a non-empty string or None"
            )

        verification_id = verification_binding_digest(
            effect_id=effect_id,
            attempt_id=attempt_id,
            snapshot_digest=snapshot_digest,
            outcome=outcome,
            method=method,
        )

        record = VerificationRecord(
            verification_id=verification_id,
            effect_id=effect_id,
            lease_id=lease_id,
            execution_id=execution_id,
            attempt_id=attempt_id,
            outcome=outcome,
            method=method,
            snapshot=dict(snapshot),
            snapshot_digest=snapshot_digest,
            observed_outcome=observed_outcome,
            evidence_kind=evidence_kind,
            receipt_authority_valid=receipt_authority_valid,
            note=note,
            recorded_at=self._now(),
            details=dict(details or {}),
        )

        with self._lock:
            existing = self._records.get(verification_id)

            if existing is not None:
                return existing

            self._write_backend(record)
            self._records[verification_id] = record
            self._by_effect.setdefault(effect_id, []).append(
                verification_id
            )

        return record

    # ========================================================
    # Lookup
    # ========================================================

    def get(self, verification_id: str) -> Optional[VerificationRecord]:
        """The authoritative row for ``verification_id``, or ``None``."""

        if not isinstance(verification_id, str) or not verification_id:
            return None
        with self._lock:
            return self._records.get(verification_id)

    def by_effect(self, effect_id: str) -> tuple[VerificationRecord, ...]:
        """Every verification claim recorded about one effect.

        Ordered oldest first -- insertion order. The *latest* claim about
        the *current* evidence snapshot is the one the completion gate
        may trust; anything else is stale, superseded, or about other
        evidence.
        """

        if not isinstance(effect_id, str) or not effect_id:
            return ()
        with self._lock:
            ids = self._by_effect.get(effect_id, ())
            return tuple(
                self._records[vid]
                for vid in ids
                if vid in self._records
            )

    def records(self) -> tuple[VerificationRecord, ...]:
        """Every verification claim, in insertion order."""

        with self._lock:
            return tuple(self._records.values())

    # ========================================================
    # Backend persistence
    # ========================================================

    def _write_backend(self, record: VerificationRecord) -> None:
        if self._backend is None:
            return
        self._backend.insert(record)

    # ========================================================
    # Inspection
    # ========================================================

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()

    def __enter__(self) -> "VerificationJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


__all__ = [
    "STRUCTURAL_METHOD",
    "canonical_snapshot_digest",
    "VerificationJournal",
    "VerificationJournalError",
    "VerificationOutcome",
    "VerificationRecord",
    "VerificationResult",
    "VerifierVerdict",
    "VerificationIdMismatchError",
    "canonical_evidence_digest",
    "canonical_evidence_snapshot",
    "evidence_package",
    "structural_verifier",
    "verification_binding_digest",
    "verification_outcome_of",
]
