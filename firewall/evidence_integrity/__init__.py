"""v2.2 Evidence Integrity Hardening (firewall.evidence_integrity).

Verifies an :class:`~firewall.evidence_graph.EvidenceGraph` and reports
three things separately: what was proven tampered, what could not be
checked at all, and what passed. The distinction is the point. A report
that folds "no tampering found" together with "the check never ran"
states a guarantee it does not hold, and every earlier version of this
module did exactly that: ``_verify_checkpoints`` and
``_verify_signer_consistency`` returned ``True`` unconditionally, so
``checkpoint_verified`` and ``signer_verified`` were decoration, and the
truncation test compared ``len(events)`` against ``events[-1].seq``,
which are equal by construction for any graph built by ``append`` and
shrink together when the tail is deleted.

What is detected, and by what mechanism:

- an edit to any signed field -> ``HASH_MISMATCH`` (the id no longer
  matches the content) and/or ``BAD_SIGNATURE`` (the signature no longer
  matches the bytes)
- deletion from the middle, insertion, reordering -> ``BROKEN_LINK`` and
  ``ORDERING_VIOLATION``, because the hash link and the sequence both
  break at the seam
- duplication -> ``DUPLICATE_EVENT``
- a dangling causal reference -> ``MISSING_CAUSAL_PARENT``
- an unsigned event where signatures are required -> ``UNSIGNED_EVENT``
- a backwards timestamp beyond the drift allowance -> ``TIME_TRAVEL``
- deletion of the *tail* -> ``TRUNCATED_CHAIN``, but only against a
  signed anchor. Nothing inside a truncated chain reveals the
  truncation: the attacker keeps a shorter, internally consistent chain.
- an event replaced at an anchored position -> ``ANCHOR_MISMATCH``
- a forged, substituted, reordered or removed anchor ->
  ``REPLACED_CHECKPOINT``
- an event signed after its signer's key was revoked ->
  ``SIGNER_REVOKED``

Findings here are evidence. They are not authorization: nothing in this
module grants, widens, or removes authority, and
``FirewallSDK.authorize`` never consults it.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional

from firewall.evidence_graph import (
    GENESIS_HASH,
    EvidenceGraph,
    EvidenceSigner,
)
from firewall.ident import IdentityRegistry
from firewall.security_memory import EvidenceCheckpoint

#: Report statuses, worst first. ``failed`` is proof of tampering;
#: ``unverifiable`` means at least one event's authenticity is unknown;
#: ``incomplete`` means authenticity held but some check could not be
#: performed; ``verified`` means every check ran and passed.
INTEGRITY_STATUSES = ("failed", "unverifiable", "incomplete", "verified")


class TamperType(str, Enum):
    """Findings this verifier can actually produce.

    Every member is emitted by :meth:`EvidenceIntegrityVerifier.verify`
    on some input, and every member has a test that produces it in
    ``tests/test_v2_2_evidence_integrity.py``. Members that named a
    detection this verifier cannot perform were removed rather than left
    as an advertised capability:

    ``modified_payload``, ``modified_causal_parent``, ``modified_signer``
        An edit to any of those fields changes ``compute_hash()`` and the
        signed bytes, so it surfaces as ``HASH_MISMATCH`` and/or
        ``BAD_SIGNATURE``. Naming the *field* that changed needs a
        trusted prior copy of the event. An anchor pins a hash, not
        fields, so the verifier can prove an event was replaced
        (``ANCHOR_MISMATCH``) but never which part of it changed.
    ``replayed_event``
        In a list of events, a replay is a duplicate id: there is no
        observable difference from ``DUPLICATE_EVENT``. Two names for one
        detection would be two representations of one property.
    ``signer_rotated``
        :meth:`firewall.ident.IdentityRegistry.rotate` replaces the
        identity record in place and keeps no superseded fingerprints, so
        a rotated-out key is indistinguishable from a key that never
        existed. Both are reported as a gap, not as tampering -- see
        :meth:`EvidenceIntegrityVerifier._signer_findings`.
    """

    HASH_MISMATCH = "hash_mismatch"
    BROKEN_LINK = "broken_link"
    ORDERING_VIOLATION = "ordering_violation"
    MISSING_CAUSAL_PARENT = "missing_causal_parent"
    BAD_SIGNATURE = "bad_signature"
    UNSIGNED_EVENT = "unsigned_event"
    DUPLICATE_EVENT = "duplicate_event"
    TRUNCATED_CHAIN = "truncated_chain"
    ANCHOR_MISMATCH = "anchor_mismatch"
    REPLACED_CHECKPOINT = "replaced_checkpoint"
    SIGNER_REVOKED = "signer_revoked"
    TIME_TRAVEL = "time_travel"


@dataclass(frozen=True)
class TamperEvidence:
    """Evidence of a specific tampering attempt.

    ``severity`` is a triage hint for a human reader. It is deliberately
    *not* consulted when deciding the report status: the previous version
    mapped non-critical findings to ``unverifiable``, so a proven
    reordering or a proven truncation was reported as merely unchecked.
    Any finding at all now means ``failed``.
    """

    tamper_type: TamperType
    sequence_number: int
    event_id: str
    expected: Optional[str] = None
    actual: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    severity: str = "critical"  # critical, high, medium, low
    detected_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tamper_type": self.tamper_type.value,
            "sequence_number": self.sequence_number,
            "event_id": self.event_id,
            "expected": self.expected,
            "actual": self.actual,
            "details": dict(self.details),
            "severity": self.severity,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True)
class IntegrityReport:
    """Complete integrity verification report.

    ``checkpoint_verified`` and ``signer_verified`` are three-valued.
    ``None`` means "not established" -- no anchor was supplied, or no
    identity registry was configured -- and is the reason they default to
    ``None`` rather than ``False``: a bare ``False`` reads as "the check
    ran and failed", which is a different claim.

    ``gaps`` lists, in words, every check that could not be performed.
    A report with gaps is never ``verified``.
    """

    status: str
    total_events: int
    verified_events: int
    tamper_evidence: tuple[TamperEvidence, ...] = ()
    gaps: tuple[str, ...] = ()
    checkpoint_verified: Optional[bool] = None
    signer_verified: Optional[bool] = None
    anchors_examined: int = 0
    verified_at: float = 0.0

    def __post_init__(self) -> None:
        if self.status not in INTEGRITY_STATUSES:
            raise ValueError(f"unknown integrity status: {self.status!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "total_events": self.total_events,
            "verified_events": self.verified_events,
            "tamper_evidence": [e.to_dict() for e in self.tamper_evidence],
            "gaps": list(self.gaps),
            "checkpoint_verified": self.checkpoint_verified,
            "signer_verified": self.signer_verified,
            "anchors_examined": self.anchors_examined,
            "verified_at": self.verified_at,
        }


class EvidenceIntegrityVerifier:
    """Hardened evidence integrity verification.

    Anchors are :class:`firewall.security_memory.EvidenceCheckpoint` values
    rather than a checkpoint type of this module's own. There is one
    signed-anchor concept in the codebase and it already has a canonical
    byte encoding, a signature, and a hash chain between successive
    anchors; a second one would have been a second representation of the
    same security concept, and the two would have drifted.

    An anchor's ``sequence_number`` is read as the 1-based position of
    the event it pins. For a graph that position and ``event.seq``
    coincide, because :meth:`EvidenceGraph.append` assigns
    ``seq = len(events) + 1``; the verifier checks both and reports a
    mismatch instead of assuming they agree.
    """

    def __init__(
        self,
        graph: EvidenceGraph,
        *,
        identity_registry: Optional[IdentityRegistry] = None,
        checkpoints: Optional[Iterable[EvidenceCheckpoint]] = None,
        anchor_signer: Optional[EvidenceSigner] = None,
        anchor_chain_id: Optional[str] = None,
        clock: Optional[Callable[[], float]] = None,
        require_signed_events: bool = True,
        allow_unsigned_genesis: bool = True,
        max_time_drift: float = 300.0,  # 5 minutes
    ) -> None:
        self._graph = graph
        self._identity_registry = identity_registry
        self._checkpoints: tuple[EvidenceCheckpoint, ...] = tuple(checkpoints or ())
        self._anchor_signer = anchor_signer
        self._anchor_chain_id = anchor_chain_id
        self._clock = clock or time.time
        self._require_signed_events = require_signed_events
        self._allow_unsigned_genesis = allow_unsigned_genesis
        self._max_time_drift = float(max_time_drift)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> IntegrityReport:
        """Verify the graph and report findings, gaps, and passes.

        ``verified_events`` counts events against which every applicable
        check ran and passed. An event whose signature could not be
        checked is not counted: unverified is not verified.
        """

        timestamp = float(self._clock())
        tamper: list[TamperEvidence] = []
        authenticity_gaps: list[str] = []

        with self._lock:
            events = self._graph.events()
            total_events = len(events)

            if total_events == 0:
                return IntegrityReport(
                    status="incomplete",
                    total_events=0,
                    verified_events=0,
                    gaps=(
                        "graph holds no events: there is nothing to "
                        "verify, and an empty graph is indistinguishable "
                        "from one whose every event was deleted",
                    ),
                    verified_at=timestamp,
                )

            prev_hash = GENESIS_HASH
            prev_seq = 0
            prev_timestamp = 0.0
            seen_event_ids: set[str] = set()
            verified_events = 0
            signers_resolved = 0
            signers_unresolved = 0

            for event in events:
                findings = self._structural_findings(
                    event,
                    prev_hash=prev_hash,
                    prev_seq=prev_seq,
                    prev_timestamp=prev_timestamp,
                    seen_event_ids=seen_event_ids,
                    timestamp=timestamp,
                )
                seen_event_ids.add(event.event_id)

                id_findings, id_gaps, resolved = self._signer_findings(
                    event, timestamp
                )
                findings.extend(id_findings)
                if resolved is True:
                    signers_resolved += 1
                elif resolved is False:
                    signers_unresolved += 1

                sig_findings, sig_gaps = self._signature_findings(
                    event, timestamp, signer_active=resolved
                )
                findings.extend(sig_findings)

                gaps = sig_gaps + id_gaps
                tamper.extend(findings)
                authenticity_gaps.extend(gaps)

                if not findings and not gaps:
                    verified_events += 1

                prev_hash = event.event_id
                prev_seq = event.seq
                prev_timestamp = event.timestamp

            anchor_findings, anchor_gaps, checkpoint_verified = (
                self._anchor_findings(events, timestamp)
            )
            tamper.extend(anchor_findings)

            if self._identity_registry is None:
                signer_verified: Optional[bool] = None
            else:
                signer_verified = (
                    signers_unresolved == 0 and signers_resolved > 0
                )
                if signers_resolved == 0 and signers_unresolved == 0:
                    # A registry was configured but no event carried a
                    # signer fingerprint to look up. Nothing was checked,
                    # so nothing is established.
                    signer_verified = None

            gaps_all = tuple(authenticity_gaps) + tuple(anchor_gaps)

            if tamper:
                status = "failed"
            elif authenticity_gaps:
                status = "unverifiable"
            elif gaps_all:
                status = "incomplete"
            else:
                status = "verified"

            return IntegrityReport(
                status=status,
                total_events=total_events,
                verified_events=verified_events,
                tamper_evidence=tuple(tamper),
                gaps=gaps_all,
                checkpoint_verified=checkpoint_verified,
                signer_verified=signer_verified,
                anchors_examined=len(self._checkpoints),
                verified_at=timestamp,
            )

    # ------------------------------------------------------------------
    # Per-event checks
    # ------------------------------------------------------------------

    def _structural_findings(
        self,
        event,
        *,
        prev_hash: str,
        prev_seq: int,
        prev_timestamp: float,
        seen_event_ids: set[str],
        timestamp: float,
    ) -> list[TamperEvidence]:
        """Checks that need no key: hash, link, order, parents, replay."""

        findings: list[TamperEvidence] = []

        computed_hash = event.compute_hash()
        if event.event_id != computed_hash:
            findings.append(TamperEvidence(
                tamper_type=TamperType.HASH_MISMATCH,
                sequence_number=event.seq,
                event_id=event.event_id,
                expected=computed_hash,
                actual=event.event_id,
                severity="critical",
                detected_at=timestamp,
            ))

        if event.prev_hash != prev_hash:
            findings.append(TamperEvidence(
                tamper_type=TamperType.BROKEN_LINK,
                sequence_number=event.seq,
                event_id=event.event_id,
                expected=prev_hash,
                actual=event.prev_hash,
                severity="critical",
                detected_at=timestamp,
            ))

        if event.seq != prev_seq + 1:
            findings.append(TamperEvidence(
                tamper_type=TamperType.ORDERING_VIOLATION,
                sequence_number=event.seq,
                event_id=event.event_id,
                expected=str(prev_seq + 1),
                actual=str(event.seq),
                severity="high",
                detected_at=timestamp,
            ))

        for parent in event.causal_parents:
            if parent == GENESIS_HASH:
                continue
            if self._graph.by_id(parent) is None:
                findings.append(TamperEvidence(
                    tamper_type=TamperType.MISSING_CAUSAL_PARENT,
                    sequence_number=event.seq,
                    event_id=event.event_id,
                    actual=parent,
                    severity="high",
                    detected_at=timestamp,
                ))

        if event.event_id in seen_event_ids:
            findings.append(TamperEvidence(
                tamper_type=TamperType.DUPLICATE_EVENT,
                sequence_number=event.seq,
                event_id=event.event_id,
                severity="high",
                detected_at=timestamp,
            ))

        if (
            prev_timestamp > 0
            and event.timestamp < prev_timestamp - self._max_time_drift
        ):
            findings.append(TamperEvidence(
                tamper_type=TamperType.TIME_TRAVEL,
                sequence_number=event.seq,
                event_id=event.event_id,
                expected=f">{prev_timestamp - self._max_time_drift}",
                actual=str(event.timestamp),
                severity="medium",
                detected_at=timestamp,
            ))

        return findings

    def _signature_findings(
        self,
        event,
        timestamp: float,
        *,
        signer_active: Optional[bool] = None,
    ) -> tuple[list[TamperEvidence], list[str]]:
        """Signature checks, split into proof and gap.

        A failed verification is proof of forgery only when the verifier
        holds the key that was supposed to have produced it. Ed25519
        cannot distinguish "signed by a key I do not hold" from "forged",
        so an event whose ``signer`` fingerprint is not the configured
        signer's is reported as a gap instead.

        That is not a loophole. Rewriting ``signer`` changes
        ``signed_block()`` and therefore ``compute_hash()``, which raises
        ``HASH_MISMATCH``; recomputing the id to hide that breaks the next
        event's ``prev_hash``. The only position where the substitution
        leaves no internal trace is the tail, which is exactly what an
        anchor covers.

        ``signer_active`` is the identity outcome from
        :meth:`_signer_findings`. When it is ``False`` a verification
        failure is also a gap:
        :meth:`firewall.ident.IdentityRegistry.verify` refuses signatures
        from revoked, retired and unknown identities on purpose, so an
        :class:`~firewall.evidence_graph.IdentityEvidenceSigner` reports
        every event signed before a revocation as unverifiable. Calling
        that a forgery would let one revocation retroactively brand an
        authentic history as tampered.
        """

        findings: list[TamperEvidence] = []
        gaps: list[str] = []
        # The graph owns the key its events were signed with; there is no
        # public accessor, and inventing a parallel signer registry here
        # would be a second answer to "who signs this graph".
        signer = self._graph._signer

        if not event.signature:
            if self._allow_unsigned_genesis and event.seq == 1:
                gaps.append(
                    f"event {event.seq} is unsigned by configuration "
                    "(allow_unsigned_genesis): it is unattributable"
                )
            elif self._require_signed_events:
                findings.append(TamperEvidence(
                    tamper_type=TamperType.UNSIGNED_EVENT,
                    sequence_number=event.seq,
                    event_id=event.event_id,
                    severity="high",
                    detected_at=timestamp,
                ))
            else:
                gaps.append(
                    f"event {event.seq} is unsigned and signatures are "
                    "not required: it is unattributable"
                )
            return findings, gaps

        if signer is None:
            gaps.append(
                f"event {event.seq} carries a signature but no signer is "
                "configured to check it"
            )
            return findings, gaps

        try:
            verified = bool(
                signer.verify(event.signed_bytes(), event.signature)
            )
        except Exception:
            verified = False

        if verified:
            return findings, gaps

        try:
            expected_fingerprint = signer.fingerprint()
        except Exception:
            expected_fingerprint = ""

        if signer_active is False:
            gaps.append(
                f"event {event.seq} carries a signature that the "
                "configured signer will not verify because the signing "
                "identity is no longer active: authenticity can no longer "
                "be re-established, and that is not proof of forgery"
            )
            return findings, gaps

        if event.signer and event.signer != expected_fingerprint:
            gaps.append(
                f"event {event.seq} is signed by {event.signer} but the "
                "configured signer is "
                f"{expected_fingerprint or 'unidentified'}: a signature "
                "made by a key this verifier does not hold cannot be "
                "distinguished from a forged one"
            )
            return findings, gaps

        findings.append(TamperEvidence(
            tamper_type=TamperType.BAD_SIGNATURE,
            sequence_number=event.seq,
            event_id=event.event_id,
            expected=expected_fingerprint or None,
            actual=event.signer or None,
            severity="critical",
            detected_at=timestamp,
        ))
        return findings, gaps

    def _signer_findings(
        self,
        event,
        timestamp: float,
    ) -> tuple[list[TamperEvidence], list[str], Optional[bool]]:
        """Lifecycle checks on the key that signed an event.

        The third element is whether the fingerprint resolved to an
        active identity -- ``True``, ``False``, or ``None`` when there was
        nothing to resolve. The old version of this check returned
        ``True`` for an unusable registry ("can't verify, assume valid")
        and reported an unknown fingerprint as ``SIGNER_REVOKED``, so a
        key that was never issued and a key that was deliberately
        withdrawn produced the same finding.

        Revocation is not tampering. Evidence signed before its key was
        revoked is still authentic, and treating it as forged would let a
        routine revocation retroactively rewrite an entire history as
        tampered. It is a finding only when the event was signed *after*
        revocation, which needs the ``revoked_at`` timestamp that
        :meth:`firewall.ident.IdentityRegistry.revoke` records. Without
        it -- and for a retired identity, since ``retire`` records no
        timestamp at all -- the outcome is a gap: the evidence cannot be
        relied on, and it cannot be shown to be forged either.
        """

        if self._identity_registry is None or not event.signer:
            return [], [], None

        identity = None
        for candidate in self._identity_registry.all():
            if candidate.key_fingerprint == event.signer:
                identity = candidate
                break

        if identity is None:
            return [], [
                f"event {event.seq} is signed by {event.signer}, which no "
                "identity in the registry holds: it may be a key that was "
                "rotated out (rotation keeps no superseded fingerprint) or "
                "one that was never issued -- the two are indistinguishable"
            ], False

        if identity.status == "active":
            return [], [], True

        revoked_at = identity.metadata.get("revoked_at")
        signed_after_revocation = (
            identity.status == "revoked"
            and isinstance(revoked_at, (int, float))
            and not isinstance(revoked_at, bool)
            and event.timestamp > float(revoked_at)
        )

        if signed_after_revocation:
            return [TamperEvidence(
                tamper_type=TamperType.SIGNER_REVOKED,
                sequence_number=event.seq,
                event_id=event.event_id,
                expected=f"<={revoked_at}",
                actual=str(event.timestamp),
                details={
                    "signer_fingerprint": event.signer,
                    "agent_id": identity.agent_id,
                    "reason": "event was signed after the key was revoked",
                },
                severity="critical",
                detected_at=timestamp,
            )], [], False

        return [], [
            f"event {event.seq} is signed by the key of "
            f"{identity.agent_id}, whose identity is {identity.status}: "
            "the signature is authentic but the key is no longer trusted"
        ], False

    # ------------------------------------------------------------------
    # Anchors
    # ------------------------------------------------------------------

    def _anchor_findings(
        self,
        events,
        timestamp: float,
    ) -> tuple[list[TamperEvidence], list[str], Optional[bool]]:
        """Verify signed anchors, and use them to detect truncation.

        Truncation of the tail is invisible from inside the chain: an
        attacker who drops the last k events keeps a shorter chain whose
        hashes, sequence numbers and signatures all still agree. The check
        this replaces compared ``len(events)`` with ``events[-1].seq``,
        two quantities that move together under exactly that attack, so
        it could not fire on any input. Detecting truncation requires a
        statement made outside the chain and signed -- an anchor.
        """

        if not self._checkpoints:
            return [], [
                "no signed anchor was supplied: deletion of the most "
                "recent events cannot be ruled out, because a truncated "
                "chain is internally consistent"
            ], None

        if self._anchor_signer is None:
            return [], [
                f"{len(self._checkpoints)} anchor(s) supplied without a "
                "signer: an anchor whose signature is not checked is an "
                "assertion, not an anchor"
            ], False

        findings: list[TamperEvidence] = []
        gaps: list[str] = []
        ordered = sorted(
            self._checkpoints, key=lambda cp: cp.sequence_number
        )
        expected_chain_id = self._anchor_chain_id or ordered[0].chain_id
        expected_previous = GENESIS_HASH
        previous_sequence = 0
        highest_anchored = 0

        for checkpoint in ordered:
            trusted = True

            try:
                signature_ok = bool(
                    self._anchor_signer.verify(
                        checkpoint.canonical_bytes(),
                        checkpoint.signature,
                    )
                )
            except Exception:
                signature_ok = False

            if not signature_ok:
                trusted = False
                findings.append(self._anchor_finding(
                    checkpoint,
                    timestamp,
                    "anchor signature does not verify",
                ))

            if checkpoint.chain_id != expected_chain_id:
                trusted = False
                findings.append(self._anchor_finding(
                    checkpoint,
                    timestamp,
                    "anchor belongs to a different chain",
                    expected=expected_chain_id,
                    actual=checkpoint.chain_id,
                ))

            if checkpoint.sequence_number <= previous_sequence:
                trusted = False
                findings.append(self._anchor_finding(
                    checkpoint,
                    timestamp,
                    "anchor sequence is not strictly increasing",
                    expected=f">{previous_sequence}",
                    actual=str(checkpoint.sequence_number),
                ))

            if checkpoint.sequence_number < 1:
                # Malformed in itself, whatever order it arrived in: an
                # anchor has to name a position to anchor anything.
                trusted = False
                findings.append(self._anchor_finding(
                    checkpoint,
                    timestamp,
                    "anchor sequence number identifies no event position",
                    expected=">=1",
                    actual=str(checkpoint.sequence_number),
                ))

            if checkpoint.previous_checkpoint_hash != expected_previous:
                trusted = False
                findings.append(self._anchor_finding(
                    checkpoint,
                    timestamp,
                    "anchor does not link to the previous anchor: one was "
                    "removed or replaced",
                    expected=expected_previous,
                    actual=checkpoint.previous_checkpoint_hash,
                ))

            previous_sequence = checkpoint.sequence_number
            expected_previous = hashlib.sha256(
                checkpoint.canonical_bytes()
            ).hexdigest()

            if not trusted:
                # A forged or misplaced anchor is not allowed to make a
                # claim about the events themselves. Its own finding stands.
                continue

            position = checkpoint.sequence_number - 1

            if position >= len(events):
                findings.append(TamperEvidence(
                    tamper_type=TamperType.TRUNCATED_CHAIN,
                    sequence_number=checkpoint.sequence_number,
                    event_id=checkpoint.event_hash,
                    expected=str(checkpoint.sequence_number),
                    actual=str(len(events)),
                    details={
                        "checkpoint_id": checkpoint.checkpoint_id,
                        "reason": (
                            "an anchor pins an event at a position the "
                            "graph no longer reaches"
                        ),
                    },
                    severity="critical",
                    detected_at=timestamp,
                ))
                continue

            anchored = events[position]
            highest_anchored = max(
                highest_anchored, checkpoint.sequence_number
            )

            if anchored.event_id != checkpoint.event_hash:
                findings.append(TamperEvidence(
                    tamper_type=TamperType.ANCHOR_MISMATCH,
                    sequence_number=checkpoint.sequence_number,
                    event_id=anchored.event_id,
                    expected=checkpoint.event_hash,
                    actual=anchored.event_id,
                    details={
                        "checkpoint_id": checkpoint.checkpoint_id,
                        "reason": (
                            "the event at the anchored position is not the "
                            "event the anchor pinned"
                        ),
                    },
                    severity="critical",
                    detected_at=timestamp,
                ))

            if anchored.seq != checkpoint.sequence_number:
                findings.append(TamperEvidence(
                    tamper_type=TamperType.ANCHOR_MISMATCH,
                    sequence_number=checkpoint.sequence_number,
                    event_id=anchored.event_id,
                    expected=str(checkpoint.sequence_number),
                    actual=str(anchored.seq),
                    details={
                        "checkpoint_id": checkpoint.checkpoint_id,
                        "reason": (
                            "the event at the anchored position does not "
                            "carry the anchored sequence number"
                        ),
                    },
                    severity="high",
                    detected_at=timestamp,
                ))

        if highest_anchored < len(events):
            gaps.append(
                f"events after position {highest_anchored} are covered by "
                f"no anchor: the {len(events) - highest_anchored} trailing "
                "event(s) could be deleted without leaving a trace"
            )

        return findings, gaps, not findings

    @staticmethod
    def _anchor_finding(
        checkpoint: EvidenceCheckpoint,
        timestamp: float,
        reason: str,
        *,
        expected: Optional[str] = None,
        actual: Optional[str] = None,
    ) -> TamperEvidence:
        return TamperEvidence(
            tamper_type=TamperType.REPLACED_CHECKPOINT,
            sequence_number=checkpoint.sequence_number,
            event_id=checkpoint.event_hash,
            expected=expected,
            actual=actual,
            details={
                "checkpoint_id": checkpoint.checkpoint_id,
                "reason": reason,
            },
            severity="critical",
            detected_at=timestamp,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def detect_specific_tamper(
        self,
        tamper_type: TamperType,
    ) -> list[TamperEvidence]:
        """Run verification and return only findings of one type.

        Absence of a type here is not a clean bill of health: consult
        :attr:`IntegrityReport.gaps` for the checks that never ran.
        """

        report = self.verify()
        return [
            e for e in report.tamper_evidence
            if e.tamper_type == tamper_type
        ]


def summarize_integrity(
    graph: EvidenceGraph,
    *,
    identity_registry: Optional[IdentityRegistry] = None,
    checkpoints: Optional[Iterable[EvidenceCheckpoint]] = None,
    anchor_signer: Optional[EvidenceSigner] = None,
) -> dict[str, Any]:
    """Verify a graph and summarize the report by finding type.

    This replaces ``run_tamper_detection_tests`` and
    ``create_tamper_test_cases``. The first ran no tests -- it called
    ``verify()`` once and returned an always-empty ``test_cases`` list --
    and the second returned a catalogue of tamper scenarios that nothing
    executed, several of which named detections the verifier could not
    perform. The real tamper scenarios live in
    ``tests/test_v2_2_evidence_integrity.py``, where they are executed.
    """

    verifier = EvidenceIntegrityVerifier(
        graph,
        identity_registry=identity_registry,
        checkpoints=checkpoints,
        anchor_signer=anchor_signer,
    )
    report = verifier.verify()

    by_type: dict[str, int] = {}
    for evidence in report.tamper_evidence:
        key = evidence.tamper_type.value
        by_type[key] = by_type.get(key, 0) + 1

    return {
        "status": report.status,
        "total_events": report.total_events,
        "verified_events": report.verified_events,
        "total_findings": len(report.tamper_evidence),
        "findings_by_type": by_type,
        "gaps": list(report.gaps),
        "checkpoint_verified": report.checkpoint_verified,
        "signer_verified": report.signer_verified,
    }
