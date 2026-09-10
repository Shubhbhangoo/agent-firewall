"""Execution lineage integrity: one execution, one provable chain of custody.

v2.7 recorded the continuation of an allow as a lease with a state machine
(``AUTHORIZED -> LEASE_ISSUED -> RESERVED -> STARTED -> COMPLETED``). v2.8
added the side-effect journal beside it. v2.9 added a verification journal,
v3.1 an attestation journal, v3.2 the temporal context each of those is
valid in. What none of them established is the thing that ties them
together: that the *execution* those records belong to is one execution,
that the stages it passed through are the stages it actually passed
through, and that nothing was quietly grafted, branched or re-ordered along
the way.

Every journal in this package answers a question about one stage. This
module answers a question about the sequence:

.. code-block:: text

    AUTHORIZED -> EXECUTED -> OBSERVED -> VERIFIED -> ATTESTED -> COMPLETED

An **execution lineage** is an append-only, hash-chained commitment to that
sequence for exactly one execution identity. One lineage per execution; one
commitment per stage; each commitment chains to the one before it and
carries a digest of the evidence that justified that stage. The chain is
what makes the sequence tamper-evident, and the binding is what makes it
*this* execution's sequence rather than a plausible-looking reassembly of
somebody else's.

**The four properties, and what each one answers.**

* **Intact** -- the chain verifies from its genesis anchor: every link's id
  re-derives from its own fields, every link's parent is the link before it,
  the sequence and stage ordinals are contiguous, and the accumulated
  subject binding never changes once a field is known. A torn tail, an
  edited record, a deleted middle and a re-ordered pair are all *named*
  findings rather than a longer or shorter chain nobody looks at twice.
* **Unique** -- one lineage per lease, one per execution identity, and one
  commitment per stage. A second genesis for a lease, a second lineage bound
  to an execution identity, or a second commitment at an ordinal that
  already holds a *different* claim is a fork, and a fork is refused and
  recorded. The same claim presented twice is not a fork: it is a crash-safe
  retry, and it returns the commitment that is already there.
* **Correctly bound** -- every commitment carries the subject binding the
  lineage was opened under (lease, execution, capability, agent, action,
  request digest, policy version, chain), and each stage adds the fields
  that become known later (the effect, the attempt, the idempotency key,
  the provider). A field that is known may never change and may never
  disappear; a binding that disagrees is a *cross-execution substitution*
  attempt and is refused by name.
* **Tamper-evident** -- the evidence digest on each commitment is a digest
  of the journal row that justified that stage, so the invariant can
  re-derive the whole chain from the four journals and check that the
  execution it describes is the execution those journals describe.

**What the layer is not.** It is not a fifth authority and not a second
authorization path: nothing here can make an ``authorize`` allow, and the
release's invariant checks that no function which decides an authorization
outcome references a lineage. It is not a replacement for the lease store,
the effect journal, the verification journal or the attestation journal --
it commits to *them*, and it refuses to progress when it cannot. And it does
not decide what happened: it records which stage the execution reached, with
which evidence, and refuses when the record of that is no longer provable.
Its only effect on the rest of the system is a refusal.

**Failing closed.** Every refusal in this module is a named
:class:`LineageError`: a missing lineage, a broken chain, a fork, a subject
mismatch, an out-of-order or skipped stage, an append to a sealed lineage,
or an unreadable journal. A refusal never raises where a *verdict* belongs
-- the enforcement path turns each into a refusal outcome -- and no refusal
can widen anything: an execution that cannot prove its lineage does not
progress, which is the direction that cannot grant authority.

**Crash safety.** Links are written to the backend before they are
published in memory, and the backend's primary key is the structural
``(lineage_id, sequence)`` pair rather than the declared id -- so a forged
``commitment_id`` can neither collide with nor displace a real link. A
crash between the write and the publish leaves a link the store holds and
the process does not; the next append refreshes from the store and either
resumes from the verified head or refuses by name. A crash *mid-write*
leaves no link at all, and the next append writes it. The one state the
layer will not paper over is a *torn* chain: a lineage whose links do not
verify is refused on every progression and reported as a violation by the
invariant, because resuming from a head nobody can verify is exactly the
guess this release exists to refuse.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional

#: Fixed domain prefix so digests from unrelated deployments or versions can
#: never accidentally agree. Every link id and the genesis anchor begin with
#: this literal.
LINEAGE_DOMAIN = "agent-firewall/execution-lineage/v1"

#: The digest a genesis link chains from. A constant anchor rather than a
#: zero string, so a forged link cannot claim "no predecessor" by pointing
#: at all zeros -- forging it means recomputing the anchor literal, which is
#: the same bar as forging a digest.
LINEAGE_ANCHOR = hashlib.sha256(
    (LINEAGE_DOMAIN + "/genesis").encode("utf-8")
).hexdigest()

#: The seal link's parent-free shape is not special-cased anywhere: a seal
#: chains to the head like every other link, so removing one breaks the
#: chain that follows it (or, if it is last, leaves the lineage extending
#: past a seal it cannot account for).


class LineageStage(str, Enum):
    """The six stages one execution passes through, in order.

    The order is the whole point, so it is a total order rather than a set:
    ``ORDINAL`` maps each stage to its position, and every append must land
    on ``head + 1``. A stage that is skipped, repeated, or re-ordered is a
    named refusal.
    """

    AUTHORIZED = "authorized"
    EXECUTED = "executed"
    OBSERVED = "observed"
    VERIFIED = "verified"
    ATTESTED = "attested"
    COMPLETED = "completed"


#: The stages in order. Any code iterating the pipeline iterates this.
STAGE_ORDER: tuple[LineageStage, ...] = (
    LineageStage.AUTHORIZED,
    LineageStage.EXECUTED,
    LineageStage.OBSERVED,
    LineageStage.VERIFIED,
    LineageStage.ATTESTED,
    LineageStage.COMPLETED,
)

#: ``stage -> ordinal``. Total over :class:`LineageStage`.
STAGE_ORDINAL: dict[LineageStage, int] = {
    stage: index for index, stage in enumerate(STAGE_ORDER)
}

#: The stages a completion must have *adopted* when the execution adopted the
#: side-effect protocol at all: an effect was claimed, so its observation and
#: its verification must exist and must have succeeded.
SIDE_EFFECT_STAGES: tuple[LineageStage, ...] = (
    LineageStage.OBSERVED,
    LineageStage.VERIFIED,
)

#: The stages before COMPLETED, in order. A completion fills any of these it
#: never performed as ``NOT_ADOPTED``, so a completed lineage is always the
#: full six.
PRIOR_STAGES: tuple[LineageStage, ...] = STAGE_ORDER[:-1]


class LineageOutcome(str, Enum):
    """What one stage's evidence said when the stage was committed.

    The three values are not decoration: a completed lineage may contain no
    ``REFUSED`` stage, and a stage the protocol *required* may not be
    ``NOT_ADOPTED``. Recording that distinction is what lets the invariant
    re-derive "this execution never adopted the side-effect protocol" from
    the lineage alone, instead of inferring it from an absent row.
    """

    #: The stage's evidence exists and supported the progression.
    ADOPTED = "adopted"
    #: The stage's evidence exists and did *not* support the progression.
    #: An execution that progresses past this cannot complete.
    REFUSED = "refused"
    #: The execution's protocol never performed this stage. Recorded so that
    #: "did not adopt" is a fact in the chain rather than an absence.
    NOT_ADOPTED = "not_adopted"


def lineage_stage_of(value: Any) -> Optional[LineageStage]:
    """``LineageStage`` from a member or its value; ``None`` otherwise."""

    try:
        return LineageStage(value)
    except (TypeError, ValueError):
        return None


def lineage_outcome_of(value: Any) -> Optional[LineageOutcome]:
    """``LineageOutcome`` from a member or its value; ``None`` otherwise."""

    try:
        return LineageOutcome(value)
    except (TypeError, ValueError):
        return None


class LineageKind(str, Enum):
    """The two kinds of link a chain holds.

    A ``COMMITMENT`` advances the stage pipeline by exactly one ordinal. A
    ``SEAL`` ends the lineage: it carries the reason the execution stopped
    and no stage at all. Both are links on the same chain, so a seal cannot
    be removed, re-ordered or forged any more easily than a stage.
    """

    COMMITMENT = "commitment"
    SEAL = "seal"


# =====================================================================
# Canonical encoding
# =====================================================================


def _canonical_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding of a digested or chained structure.

    One encoding for every digest and every link id in this module, for the
    same reason the other journals have one: a value that re-derives to a
    digest on one side must re-derive to the same digest on the other, and
    ``sort_keys`` plus compact separators is what makes that true
    independently of insertion order and whitespace.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_evidence_digest(evidence: Any) -> str:
    """A stable digest of the evidence that justified one stage.

    The evidence is the journal row that carried the progression -- a lease
    record, an effect row, a verification claim, an attestation claim -- or a
    small dict summarising it plus the reason a stage was *not* adopted. It
    is digested rather than stored so the lineage holds no copy of another
    journal's contents, and so a later change to that row is visible as a
    disagreement between the two.

    Anything unserialisable has no stable digest, and the caller is refused
    rather than committed to a value it cannot name.
    """

    try:
        payload = _canonical_bytes(evidence if evidence is not None else {})
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"lineage evidence has no stable digest: {type(exc).__name__}"
        ) from exc

    return hashlib.sha256(payload).hexdigest()


#: The binding fields every lineage must carry, in the order they appear in
#: the digest payload. Required at genesis; the optional ones below may
#: arrive later and then never change.
REQUIRED_BINDING_FIELDS: tuple[str, ...] = (
    "lease_id",
    "capability_fingerprint",
    "agent_id",
    "capability",
    "action",
    "request_digest",
    "policy_version",
)

#: Binding fields that become known as the execution progresses. A field may
#: be absent early and present later -- the effect id does not exist until the
#: effect is prepared -- but once present it is fixed.
OPTIONAL_BINDING_FIELDS: tuple[str, ...] = (
    "execution_id",
    "chain_id",
    "issuer",
    "tool",
    "effect_id",
    "attempt_id",
    "idempotency_key",
    "provider",
)

BINDING_FIELDS: tuple[str, ...] = (
    REQUIRED_BINDING_FIELDS + OPTIONAL_BINDING_FIELDS
)

#: Names that may not appear in a binding field's *value* when that value is
#: joined into a digest payload, for the same reason the state-commitment
#: journal reserves a set: a label that can contain the separator can make two
#: different bindings encode identically.
_RESERVED_VALUE_CHARS = frozenset("\x00\x1f\n")


def canonical_binding(fields: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize one subject binding.

    Returns the binding with unknown keys dropped and absent optional fields
    set to ``None``, so two bindings that say the same thing encode
    identically whatever order they were assembled in. Raises
    :class:`LineageBindingError` for a missing required field, a non-string
    value, an empty string, or a value carrying a reserved character.
    """

    if not isinstance(fields, dict):
        raise LineageBindingError("a lineage binding must be a dictionary")

    canonical: dict[str, Any] = {}

    for name in BINDING_FIELDS:
        value = fields.get(name)

        if value is None:
            if name in REQUIRED_BINDING_FIELDS:
                raise LineageBindingError(
                    f"a lineage binding must name {name!r}"
                )
            canonical[name] = None
            continue

        if not isinstance(value, str):
            raise LineageBindingError(
                f"lineage binding field {name!r} must be a string or None"
            )

        if not value:
            if name in REQUIRED_BINDING_FIELDS:
                raise LineageBindingError(
                    f"lineage binding field {name!r} may not be empty"
                )
            canonical[name] = None
            continue

        if _RESERVED_VALUE_CHARS & set(value):
            raise LineageBindingError(
                f"lineage binding field {name!r} may not contain a control "
                "character"
            )

        canonical[name] = value

    return canonical


def binding_digest(binding: dict[str, Any]) -> str:
    """A stable digest of one subject binding."""

    return hashlib.sha256(
        (LINEAGE_DOMAIN + "\x00binding\x00").encode("utf-8")
        + _canonical_bytes(binding)
    ).hexdigest()


def merge_binding(
    known: dict[str, Any],
    presented: dict[str, Any],
) -> tuple[dict[str, Any], Optional[str]]:
    """``(merged, mismatched_field)`` -- the accumulation rule.

    A binding *grows*: the effect id does not exist until the effect is
    prepared, so a field may be absent early and present later. What it may
    never do is change value or disappear:

    * a field known and different in ``presented`` is a mismatch -- that is
      the cross-execution substitution this rule exists to catch;
    * a field known and *absent* in ``presented`` is the same mismatch, from
      the other side, because a binding that can lose a field can be made to
      look like a different execution's;
    * a field newly present is merged in and fixed from then on.

    Returns the merged binding and the name of the first offending field, or
    ``(merged, None)``.
    """

    merged = dict(known)

    for name in BINDING_FIELDS:
        old = known.get(name)
        new = presented.get(name)

        if old is None:
            if new is not None:
                merged[name] = new
            continue

        if new != old:
            return merged, name

    return merged, None


# =====================================================================
# Link identity
# =====================================================================


def link_id(
    *,
    lineage_id: str,
    sequence: int,
    kind: LineageKind,
    stage: Optional[LineageStage],
    ordinal: Optional[int],
    outcome: Optional[LineageOutcome],
    evidence_digest: str,
    binding_digest: str,
    parent_digest: str,
) -> str:
    """The natural id of one link: the digest of everything it is bound to.

    Deliberately built from *structural* fields only -- the lineage, the
    position, the kind, the stage and outcome, the evidence, the binding and
    the parent. ``recorded_at`` and the free-text ``details`` are commentary
    and are not digested, so an identical claim presented twice by a retry
    produces the identical id and the store answers with the row it already
    has rather than a near-duplicate.

    A link whose stored id does not re-derive from these fields is a forged
    or edited link, which is exactly what the invariant reports.
    """

    payload = _canonical_bytes(
        {
            "domain": LINEAGE_DOMAIN,
            "lineage_id": lineage_id,
            "sequence": int(sequence),
            "kind": kind.value,
            "stage": stage.value if stage is not None else None,
            "ordinal": ordinal,
            "outcome": outcome.value if outcome is not None else None,
            "evidence_digest": evidence_digest,
            "binding_digest": binding_digest,
            "parent_digest": parent_digest,
        }
    )

    return hashlib.sha256(payload).hexdigest()


def lineage_id_for(
    *,
    lease_id: str,
    execution_id: Optional[str],
    binding_digest_value: str,
    nonce: Optional[str] = None,
) -> str:
    """The id of one lineage.

    Carries a random nonce rather than being a pure function of the lease, so
    that *two* lineages claiming one lease are two distinguishable ids rather
    than one id that silently agrees with itself. That is what lets fork
    detection be a lookup instead of a guess: a second genesis for a lease
    that already has one is a conflict rather than a re-open.
    """

    payload = _canonical_bytes(
        {
            "domain": LINEAGE_DOMAIN,
            "lease_id": lease_id,
            "execution_id": execution_id,
            "binding_digest": binding_digest_value,
            "nonce": nonce if nonce is not None else uuid.uuid4().hex,
        }
    )

    return hashlib.sha256(payload).hexdigest()


# =====================================================================
# Errors
# =====================================================================


class LineageError(Exception):
    """Base error for the execution lineage journal.

    Every subclass names one way a lineage can fail to be provable, so an
    enforcement path can turn it into a refusal reason without inventing
    one -- and so an operator reading the audit trail sees which property
    was broken rather than that "something went wrong".
    """

    #: The refusal-reason fragment this error maps to on the boundary.
    reason = "lineage_error"


class LineageBindingError(LineageError):
    """A subject binding is malformed or disagrees with the lineage's."""

    reason = "lineage_binding_invalid"


class LineageUnknownError(LineageError):
    """No lineage exists for the lease or id asked about."""

    reason = "lineage_missing"


class LineageConflictError(LineageError):
    """A lineage already exists for this lease or execution identity."""

    reason = "lineage_conflict"


class LineageForkError(LineageError):
    """Two different claims about one stage, or two lineages for one execution.

    The fork is the attack this release is built around: a second branch
    that continues the execution while carving off a different history. It is
    refused *and recorded*, so the attempt is visible in the journal even
    though nothing progressed.
    """

    reason = "lineage_fork"


class LineageSubjectMismatchError(LineageError):
    """A commitment's binding does not describe the lineage's execution.

    Cross-execution substitution: evidence from one execution offered as
    another's. The stage is refused and the attempted field is recorded.
    """

    reason = "lineage_subject_mismatch"


class LineageStageOrderError(LineageError):
    """A stage was skipped, repeated or re-ordered."""

    reason = "lineage_stage_out_of_order"


class LineageSealedError(LineageError):
    """The lineage has ended; it accepts no further links."""

    reason = "lineage_sealed"


class LineageBrokenError(LineageError):
    """The lineage's chain does not verify, so its head attests nothing."""

    reason = "lineage_broken"


class LineageJournalError(LineageError):
    """The journal could not read or persist what it was asked to."""

    reason = "lineage_store_error"


# =====================================================================
# Findings
# =====================================================================


@dataclass(frozen=True)
class LineageFinding:
    """One refused lineage operation, kept as evidence of the attempt.

    A finding is not a violation: it is the mechanism working. It is
    recorded so that an operator can see that something tried to fork a
    lineage or graft another execution's binding onto it, and so the
    invariant can distinguish "an attack was attempted and refused" from "the
    chain says something untrue".

    ``kind`` is one of :data:`FINDING_KINDS`.
    """

    kind: str
    lineage_id: str
    sequence: int
    detail: str
    at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "lineage_id": self.lineage_id,
            "sequence": self.sequence,
            "detail": self.detail,
            "at": self.at,
        }


#: The finding kinds this release produces. Anything else is a finding the
#: invariant cannot explain, which it reports rather than ignoring.
FINDING_KINDS: frozenset[str] = frozenset(
    {
        #: A second genesis for a lease, or a second lineage for an
        #: execution identity.
        "fork",
        #: A second commitment at an ordinal holding a different claim.
        "branch",
        #: A binding that disagrees with the lineage's accumulated one.
        "subject_mismatch",
        #: A stage presented out of order, skipped or repeated.
        "stage_out_of_order",
        #: An append to a lineage that has ended.
        "sealed",
        #: A link the backend refused, or a chain that does not verify.
        "unverifiable",
    }
)


# =====================================================================
# Links
# =====================================================================


@dataclass(frozen=True)
class LineageLink:
    """One link in one execution's chain.

    The object is the authority on nothing by itself: a link is a *reference*
    to what the journal holds, exactly as a lease object is a reference to
    its store record. A forged, copied or edited link is refused because it
    disagrees with the id it claims, which
    :func:`link_id` re-derives and the invariant re-checks.
    """

    commitment_id: str
    lineage_id: str
    #: Position in the chain. Structural, contiguous, and the backend's
    #: primary key together with ``lineage_id`` -- deliberately *not* the
    #: declared ``commitment_id``, so a forged id can neither collide with
    #: nor displace a real link.
    sequence: int
    kind: LineageKind
    #: Present on a commitment, ``None`` on a seal.
    stage: Optional[LineageStage]
    ordinal: Optional[int]
    outcome: Optional[LineageOutcome]
    evidence_digest: str
    parent_digest: str
    binding: dict[str, Any]
    binding_digest: str
    #: The digest of the lease record this stage progressed, so a lease that
    #: was edited after the fact is visible as a disagreement.
    lease_digest: str
    recorded_at: float = 0.0
    #: Why the lineage ended, on a seal link.
    seal_reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "lineage_id": self.lineage_id,
            "sequence": self.sequence,
            "kind": self.kind.value,
            "stage": self.stage.value if self.stage is not None else None,
            "ordinal": self.ordinal,
            "outcome": (
                self.outcome.value if self.outcome is not None else None
            ),
            "evidence_digest": self.evidence_digest,
            "parent_digest": self.parent_digest,
            "binding": dict(self.binding),
            "binding_digest": self.binding_digest,
            "lease_digest": self.lease_digest,
            "recorded_at": self.recorded_at,
            "seal_reason": self.seal_reason,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "LineageLink":
        """Reconstruct a link, refusing anything malformed.

        Reconstruction is deliberately not trust: the journal re-derives
        ``commitment_id`` from the other fields before believing it, and the
        invariant does the same on every stored link. A row that cannot be
        reconstructed is a corrupt row, reported rather than coerced.
        """

        if not isinstance(data, dict):
            raise LineageJournalError("a lineage link must be an object")

        def _need_str(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise LineageJournalError(
                    f"lineage link field {key!r} must be a non-empty string"
                )
            return value

        def _finite(key: str) -> float:
            value = data.get(key, 0.0)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise LineageJournalError(
                    f"lineage link field {key!r} must be numeric"
                )
            result = float(value)
            if not math.isfinite(result):
                raise LineageJournalError(
                    f"lineage link field {key!r} must be finite"
                )
            return result

        kind_value = data.get("kind")

        try:
            kind = LineageKind(kind_value)
        except (TypeError, ValueError):
            raise LineageJournalError(
                f"lineage link field 'kind' is not a link kind: "
                f"{kind_value!r}"
            ) from None

        stage_value = data.get("stage")
        stage = None

        if stage_value is not None:
            stage = lineage_stage_of(stage_value)

            if stage is None:
                raise LineageJournalError(
                    f"lineage link field 'stage' is not a stage: "
                    f"{stage_value!r}"
                )

        outcome_value = data.get("outcome")
        outcome = None

        if outcome_value is not None:
            outcome = lineage_outcome_of(outcome_value)

            if outcome is None:
                raise LineageJournalError(
                    f"lineage link field 'outcome' is not an outcome: "
                    f"{outcome_value!r}"
                )

        ordinal = data.get("ordinal")

        if ordinal is not None:
            if isinstance(ordinal, bool) or not isinstance(ordinal, int):
                raise LineageJournalError(
                    "lineage link field 'ordinal' must be an integer or None"
                )

        binding = data.get("binding")

        if binding is None:
            raise LineageJournalError(
                "lineage link field 'binding' is required"
            )

        binding = canonical_binding(dict(binding))

        sequence = data.get("sequence")

        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise LineageJournalError(
                "lineage link field 'sequence' must be an integer"
            )

        seal_reason = data.get("seal_reason", "")

        if not isinstance(seal_reason, str):
            raise LineageJournalError(
                "lineage link field 'seal_reason' must be a string"
            )

        details = data.get("details", {})

        if not isinstance(details, dict):
            raise LineageJournalError(
                "lineage link field 'details' must be an object"
            )

        return cls(
            commitment_id=_need_str("commitment_id"),
            lineage_id=_need_str("lineage_id"),
            sequence=sequence,
            kind=kind,
            stage=stage,
            ordinal=ordinal,
            outcome=outcome,
            evidence_digest=_need_str("evidence_digest"),
            parent_digest=_need_str("parent_digest"),
            binding=binding,
            binding_digest=_need_str("binding_digest"),
            lease_digest=str(data.get("lease_digest", "")),
            recorded_at=_finite("recorded_at"),
            seal_reason=seal_reason,
            details=dict(details),
        )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def rederived_id(self) -> str:
        """The id this link's own fields actually produce."""

        return link_id(
            lineage_id=self.lineage_id,
            sequence=self.sequence,
            kind=self.kind,
            stage=self.stage,
            ordinal=self.ordinal,
            outcome=self.outcome,
            evidence_digest=self.evidence_digest,
            binding_digest=self.binding_digest,
            parent_digest=self.parent_digest,
        )

    @property
    def is_commitment(self) -> bool:
        return self.kind is LineageKind.COMMITMENT

    @property
    def is_seal(self) -> bool:
        return self.kind is LineageKind.SEAL

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        label = self.stage.value if self.stage is not None else "seal"
        return (
            f"LineageLink(seq={self.sequence}, kind={self.kind.value}, "
            f"{label}, lineage={self.lineage_id[:8]}...)"
        )


# =====================================================================
# The chain
# =====================================================================


@dataclass(frozen=True)
class ExecutionLineage:
    """One execution's chain of custody, as a value.

    Immutable, so a caller can hold a lineage and audit it without the
    journal changing underneath: an append produces a *new*
    ``ExecutionLineage`` and the old one still describes what the chain said
    at that moment.
    """

    lineage_id: str
    lease_id: str
    execution_id: Optional[str]
    links: tuple[LineageLink, ...]
    #: Whether the SDK created this lineage itself (``False``) or adopted a
    #: lease it did not issue (``True``). An adopted lineage is legitimate --
    #: a caller-supplied lease store is a supported configuration -- and it is
    #: recorded, so an operator can tell the firewall's own executions from
    #: the ones it inherited.
    adopted: bool = False
    opened_at: float = 0.0

    # ------------------------------------------------------------------
    # Shape
    # ------------------------------------------------------------------

    @property
    def head(self) -> Optional[LineageLink]:
        """The last link, or ``None`` for an empty chain."""

        return self.links[-1] if self.links else None

    @property
    def genesis(self) -> Optional[LineageLink]:
        return self.links[0] if self.links else None

    @property
    def sealed(self) -> bool:
        head = self.head
        return head is not None and head.is_seal

    @property
    def seal_reason(self) -> str:
        head = self.head

        if head is not None and head.is_seal:
            return head.seal_reason

        return ""

    @property
    def binding(self) -> dict[str, Any]:
        """The accumulated subject binding.

        Accumulated rather than per-link so a caller can ask "which execution
        is this?" once and get the most complete answer the chain supports.
        """

        merged: dict[str, Any] = {
            name: None for name in BINDING_FIELDS
        }
        merged["lease_id"] = self.lease_id

        for link in self.links:
            for name in BINDING_FIELDS:
                value = link.binding.get(name)

                if value is not None:
                    merged[name] = value

        return merged

    @property
    def stages(self) -> tuple[LineageStage, ...]:
        """The stages committed so far, in chain order."""

        return tuple(
            link.stage
            for link in self.links
            if link.is_commitment and link.stage is not None
        )

    @property
    def ordinal(self) -> int:
        """The highest ordinal committed, or ``-1`` before the genesis."""

        ordinals = [
            link.ordinal
            for link in self.links
            if link.is_commitment and link.ordinal is not None
        ]

        return max(ordinals) if ordinals else -1

    @property
    def completed(self) -> bool:
        """Whether the chain records a clean COMPLETED stage.

        Asks about the COMPLETED *commitment* rather than about the head,
        because a completed execution is sealed immediately afterwards and
        the head is then the seal. Reading the head would report a finished
        execution as unfinished, which is exactly the kind of
        almost-right-but-inverted predicate this package's invariants exist
        to catch in other people's code.
        """

        link = self.link_for(LineageStage.COMPLETED)

        return (
            link is not None
            and link.outcome is LineageOutcome.ADOPTED
        )

    def link_for(self, stage: LineageStage) -> Optional[LineageLink]:
        """The commitment holding ``stage``, if the chain has one."""

        for link in self.links:
            if link.is_commitment and link.stage is stage:
                return link

        return None

    def outcome_of(self, stage: LineageStage) -> Optional[LineageOutcome]:
        link = self.link_for(stage)
        return link.outcome if link is not None else None

    def missing_stages(self) -> tuple[LineageStage, ...]:
        """Stages the chain does not hold, in order."""

        present = set(self.stages)
        return tuple(
            stage for stage in STAGE_ORDER if stage not in present
        )

    def evidence_for(self, stage: LineageStage) -> Optional[str]:
        link = self.link_for(stage)
        return link.evidence_digest if link is not None else None

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> tuple[str, ...]:
        """Every reason this chain does not attest its own sequence.

        Empty means the chain verifies: genesis-anchored, contiguous,
        correctly ordered, self-consistent in its ids and bindings, and
        ended by a seal only if the seal is the last link. Any non-empty
        result makes the lineage *broken*, which the enforcement path turns
        into a refusal and the invariant reports as a violation -- a chain
        that does not verify cannot say what the execution did.
        """

        problems: list[str] = []

        if not self.links:
            return ("the lineage holds no links",)

        genesis = self.links[0]

        if genesis.parent_digest != LINEAGE_ANCHOR:
            problems.append(
                "the genesis link does not chain from the lineage anchor"
            )

        if genesis.sequence != 0:
            problems.append(
                "the genesis link is not at sequence 0"
            )

        if genesis.kind is not LineageKind.COMMITMENT or (
            genesis.stage is not LineageStage.AUTHORIZED
        ):
            problems.append(
                "the genesis link is not the AUTHORIZED commitment"
            )

        expected_ordinal = -1
        previous: Optional[LineageLink] = None
        known: dict[str, Any] = {
            name: None for name in BINDING_FIELDS
        }
        known["lease_id"] = self.lease_id
        sealed_at: Optional[int] = None

        for index, link in enumerate(self.links):
            label = f"link {index} (sequence {link.sequence})"

            if link.lineage_id != self.lineage_id:
                problems.append(
                    f"{label}: names lineage {link.lineage_id[:8]}..., not "
                    "this chain's"
                )

            if link.sequence != index:
                problems.append(
                    f"{label}: its sequence is not contiguous"
                )

            if link.rederived_id() != link.commitment_id:
                problems.append(
                    f"{label}: its id does not re-derive from its own "
                    "fields; the link is forged or edited"
                )

            if previous is None:
                if link.parent_digest != LINEAGE_ANCHOR:
                    problems.append(
                        f"{label}: its parent is not the lineage anchor"
                    )
            elif link.parent_digest != previous.commitment_id:
                problems.append(
                    f"{label}: its parent is not the link before it; the "
                    "chain is broken or a link was removed"
                )

            if link.binding_digest != binding_digest(link.binding):
                problems.append(
                    f"{label}: its binding digest does not match its own "
                    "binding"
                )

            merged, mismatched = merge_binding(known, link.binding)

            if mismatched is not None:
                problems.append(
                    f"{label}: its binding changes {mismatched!r}, which "
                    "the chain had already fixed; the stage describes "
                    "another execution"
                )
            else:
                known = merged

            if link.is_commitment:
                if sealed_at is not None:
                    problems.append(
                        f"{label}: a commitment follows the seal at "
                        f"sequence {sealed_at}; the lineage was extended "
                        "after it ended"
                    )

                if link.stage is None or link.ordinal is None:
                    problems.append(
                        f"{label}: a commitment with no stage"
                    )
                else:
                    if link.ordinal != STAGE_ORDINAL[link.stage]:
                        problems.append(
                            f"{label}: stage {link.stage.value} carries "
                            f"ordinal {link.ordinal}, which is not its "
                            "position in the pipeline"
                        )

                    if link.ordinal == expected_ordinal:
                        problems.append(
                            f"{label}: stage {link.stage.value} repeats an "
                            "ordinal already committed; the lineage forked"
                        )
                    elif link.ordinal != expected_ordinal + 1:
                        problems.append(
                            f"{label}: stage {link.stage.value} at ordinal "
                            f"{link.ordinal} does not follow ordinal "
                            f"{expected_ordinal}; a stage was skipped or "
                            "re-ordered"
                        )

                    expected_ordinal = link.ordinal

            elif link.is_seal:
                if sealed_at is not None:
                    problems.append(
                        f"{label}: a second seal; the lineage was sealed "
                        f"at sequence {sealed_at}"
                    )
                elif link.stage is not None or link.ordinal is not None:
                    problems.append(
                        f"{label}: a seal carrying a stage"
                    )
                sealed_at = link.sequence

            previous = link

        if previous is not None and previous.is_seal:
            if previous.sequence != len(self.links) - 1:
                problems.append(
                    "the chain continues past its seal"
                )

        return tuple(problems)

    def first_problem(self) -> Optional[str]:
        problems = self.verify()
        return problems[0] if problems else None

    @property
    def intact(self) -> bool:
        return self.first_problem() is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "lineage_id": self.lineage_id,
            "lease_id": self.lease_id,
            "execution_id": self.execution_id,
            "adopted": self.adopted,
            "opened_at": self.opened_at,
            "stages": [stage.value for stage in self.stages],
            "sealed": self.sealed,
            "links": [link.to_dict() for link in self.links],
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"ExecutionLineage(lease={self.lease_id[:8]}..., "
            f"links={len(self.links)}, stages={[s.value for s in self.stages]}, "
            f"sealed={self.sealed})"
        )


# =====================================================================
# The journal
# =====================================================================


class LineageJournal:
    """The authority on execution lineages.

    One lineage per lease, one chain per lineage, one commitment per stage,
    and every append conditional on the chain's current head -- so a second
    claim about a stage is a fork the journal refuses and records, while the
    *same* claim presented twice (a crash-safe retry) is answered with the
    link already written.

    The journal decides *what was committed*, never *what may execute*. It
    holds no reference to any authority store and constructs no verdict: the
    SDK -- and only the SDK -- decides whether an execution may progress and
    then asks the journal to make the commitment durable.
    """

    def __init__(
        self,
        *,
        clock=None,
        backend: Optional[Any] = None,
    ) -> None:
        self._clock = clock if clock is not None else time.time
        self._backend = backend
        self._lock = threading.RLock()
        self._links: dict[str, list[LineageLink]] = {}
        self._lineages: dict[str, ExecutionLineage] = {}
        self._by_lease: dict[str, str] = {}
        self._by_execution: dict[str, str] = {}
        self._findings: list[LineageFinding] = []

        if backend is not None:
            self._restore()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _now(self) -> float:
        try:
            return float(self._clock())
        except Exception:  # noqa: BLE001 - an unreadable clock is failure
            raise LineageJournalError(
                "the lineage journal's clock could not be read"
            ) from None

    def _restore(self) -> None:
        """Load persisted links, in chain order, without trusting them.

        The backend returns links keyed by the structural
        ``(lineage_id, sequence)`` pair, so a forged ``commitment_id`` cannot
        place itself at a position it does not own. Reconstruction failure is
        reported: a store holding a row this release cannot read is a store
        whose lineages cannot be proved, and the SDK treats that as a
        refusal rather than as an empty journal.
        """

        try:
            links = self._backend.load()
        except Exception as exc:  # noqa: BLE001 - unreadable is a failure
            raise LineageJournalError(
                "the lineage store could not be read: "
                f"{type(exc).__name__}"
            ) from exc

        for link in links:
            self._links.setdefault(link.lineage_id, []).append(link)

        for lineage_id, chain in self._links.items():
            chain.sort(key=lambda item: item.sequence)
            self._rebuild(lineage_id, chain[0].binding.get("lease_id"))

    def _rebuild(
        self,
        lineage_id: str,
        lease_id: Optional[str],
    ) -> ExecutionLineage:
        """Publish the lineage for one chain, refreshing the indexes."""

        chain = tuple(self._links.get(lineage_id, ()))

        binding: dict[str, Any] = {
            name: None for name in BINDING_FIELDS
        }
        adopted = False

        for link in chain:
            for name in BINDING_FIELDS:
                value = link.binding.get(name)

                if value is not None:
                    binding[name] = value

            if link.details.get("adopted") is True:
                adopted = True

        execution_id = binding.get("execution_id")

        resolved_lease = lease_id or binding.get("lease_id") or ""

        lineage = ExecutionLineage(
            lineage_id=lineage_id,
            lease_id=resolved_lease,
            execution_id=execution_id,
            links=chain,
            adopted=adopted,
            opened_at=chain[0].recorded_at if chain else 0.0,
        )

        self._lineages[lineage_id] = lineage

        if resolved_lease:
            self._by_lease.setdefault(resolved_lease, lineage_id)

        if execution_id:
            self._by_execution.setdefault(execution_id, lineage_id)

        return lineage

    def _current(
        self,
        lineage_id: str,
    ) -> Optional[ExecutionLineage]:
        """The chain as the journal holds it *now*, or ``None``.

        The single place that answers "what is this lineage?", used by every
        reader and by both enforcement methods. The distinction is load
        bearing rather than tidy: `_lineages` is an index of what has been
        *opened*, and a value derived from it is a second account of the
        chain; a second account can disagree with the links, and a writer
        that trusted the account would accept a commitment the links had
        already outgrown (or refuse to see that they had been rewritten).
        Deriving on every use means a rewritten link refuses at the write
        path as well as at the read path.
        """

        known = self._lineages.get(lineage_id)

        if known is None:
            return None

        return self._rebuild(lineage_id, known.lease_id)

    def _finding(
        self,
        kind: str,
        lineage_id: str,
        sequence: int,
        detail: str,
    ) -> None:
        """Record one refused operation, so the attempt is evidence."""

        try:
            at = self._now()
        except LineageJournalError:
            at = 0.0

        self._findings.append(
            LineageFinding(
                kind=kind,
                lineage_id=lineage_id,
                sequence=sequence,
                detail=detail,
                at=at,
            )
        )

    def _persist(self, link: LineageLink) -> Optional[LineageLink]:
        """Persist a link; return the stored twin when one is already there.

        The backend's key is ``(lineage_id, sequence)``, so a duplicate can
        only be the *same position* being written twice -- a crash-safe retry
        or a concurrent writer. Returning the stored link lets the caller
        publish the authoritative row instead of failing a safe retry.
        """

        if self._backend is None:
            return None

        return self._backend.insert(link)

    def _refresh(self, lineage_id: str) -> Optional[ExecutionLineage]:
        """Re-read one chain from the backend, or ``None`` if unreadable."""

        if self._backend is None:
            return None

        try:
            chain = self._backend.load_one(lineage_id)
        except Exception:  # noqa: BLE001 - a refresh is best effort
            return None

        if chain is None:
            return None

        self._links[lineage_id] = list(chain)
        return self._rebuild(lineage_id, chain[0].binding.get("lease_id") if chain else None)

    # ------------------------------------------------------------------
    # Open
    # ------------------------------------------------------------------

    def open(
        self,
        *,
        lease_id: str,
        execution_id: Optional[str],
        binding: dict[str, Any],
        lease_digest: str,
        adopted: bool = False,
        note: Optional[str] = None,
    ) -> ExecutionLineage:
        """Open a lineage with its AUTHORIZED genesis, or return the existing one.

        The genesis is the AUTHORIZED commitment: the execution exists
        because an allow produced a lease, and the lineage begins there. A
        second genesis for a lease that already has a lineage is a **fork**
        (two chains for one execution) and is refused; a second genesis for an
        execution identity already bound elsewhere is the same fork from the
        other side. Both are recorded as findings.

        Idempotence is deliberate: the SDK's own issue path calls this once
        per lease, and a retry after a crash between the backend write and
        the publish must return the chain that is already there rather than
        creating a second one. What is *not* idempotent is a differently
        bound genesis for the same lease -- that is the substitution case and
        it is refused.
        """

        canonical = canonical_binding(binding)

        if canonical["lease_id"] != lease_id:
            raise LineageBindingError(
                "the binding's lease_id disagrees with the lineage's"
            )

        if execution_id is not None and (
            not isinstance(execution_id, str) or not execution_id
        ):
            raise LineageBindingError(
                "execution_id must be a non-empty string or None"
            )

        # The parameter is merged into the binding rather than merely used
        # for the lineage's own value. An execution identity that the chain
        # does not carry is an identity nobody can check a future claim
        # against, which is how two lineages end up bound to one execution.
        if execution_id is not None:
            declared = canonical.get("execution_id")

            if declared is not None and declared != execution_id:
                raise LineageBindingError(
                    "the binding's execution_id disagrees with the lineage's"
                )

            canonical["execution_id"] = execution_id

        if not isinstance(lease_digest, str):
            raise LineageBindingError("lease_digest must be a string")

        with self._lock:
            existing_id = self._by_lease.get(lease_id)

            if existing_id is not None:
                existing = self._lineages[existing_id]
                merged, mismatched = merge_binding(
                    existing.binding, canonical
                )

                if mismatched is not None:
                    self._finding(
                        "subject_mismatch",
                        existing_id,
                        0,
                        f"a second genesis for lease {lease_id[:8]}... "
                        f"changes {mismatched!r}",
                    )
                    raise LineageSubjectMismatchError(
                        "a lineage already exists for this lease under a "
                        f"different {mismatched}"
                    )

                return existing

            if execution_id is not None:
                bound = self._by_execution.get(execution_id)

                if bound is not None:
                    self._finding(
                        "fork",
                        bound,
                        0,
                        f"execution identity {execution_id!r} is already "
                        "bound to another lineage",
                    )
                    raise LineageConflictError(
                        f"execution identity {execution_id!r} already names "
                        "another lineage"
                    )

            digest = binding_digest(canonical)
            new_id = lineage_id_for(
                lease_id=lease_id,
                execution_id=execution_id,
                binding_digest_value=digest,
            )

            genesis = LineageLink(
                commitment_id=link_id(
                    lineage_id=new_id,
                    sequence=0,
                    kind=LineageKind.COMMITMENT,
                    stage=LineageStage.AUTHORIZED,
                    ordinal=STAGE_ORDINAL[LineageStage.AUTHORIZED],
                    outcome=LineageOutcome.ADOPTED,
                    evidence_digest=canonical_evidence_digest(
                        {
                            "stage": LineageStage.AUTHORIZED.value,
                            "lease": lease_digest,
                            "note": note or "lease_issued",
                        }
                    ),
                    binding_digest=digest,
                    parent_digest=LINEAGE_ANCHOR,
                ),
                lineage_id=new_id,
                sequence=0,
                kind=LineageKind.COMMITMENT,
                stage=LineageStage.AUTHORIZED,
                ordinal=STAGE_ORDINAL[LineageStage.AUTHORIZED],
                outcome=LineageOutcome.ADOPTED,
                evidence_digest=canonical_evidence_digest(
                    {
                        "stage": LineageStage.AUTHORIZED.value,
                        "lease": lease_digest,
                        "note": note or "lease_issued",
                    }
                ),
                parent_digest=LINEAGE_ANCHOR,
                binding=canonical,
                binding_digest=digest,
                lease_digest=lease_digest,
                recorded_at=self._now(),
                details={
                    "adopted": bool(adopted),
                    "note": note,
                },
            )

            stored = self._persist(genesis)

            if stored is not None:
                # Another writer got there first with the identical genesis.
                # The stored link is the authority, so publish it.
                self._links.setdefault(stored.lineage_id, []).append(stored)
                lineage = self._rebuild(
                    stored.lineage_id, stored.binding.get("lease_id")
                )
                return lineage

            self._links.setdefault(new_id, []).append(genesis)
            lineage = self._rebuild(new_id, lease_id)

        return lineage

    # ------------------------------------------------------------------
    # Advance
    # ------------------------------------------------------------------

    def advance(
        self,
        *,
        lineage_id: str,
        stage: LineageStage,
        outcome: LineageOutcome,
        evidence: Any,
        binding: dict[str, Any],
        lease_digest: str,
        details: Optional[dict[str, Any]] = None,
    ) -> ExecutionLineage:
        """Commit one stage, or refuse with a named :class:`LineageError`.

        The four properties are enforced here, in the order that makes the
        answer most specific:

        1. the lineage exists, is not sealed, and its chain verifies -- a
           broken chain refuses before anything else is considered;
        2. the stage lands on ``head + 1`` -- a skip or a repeat is refused;
        3. the binding agrees with the accumulated one -- a substitution is
           refused and the offending field is named;
        4. the ordinal is not already held by a *different* claim -- that is
           a fork. The identical claim is answered with the link already on
           the chain, which is what makes a crash-safe retry safe.

        The link is persisted before it is published, so a failed write never
        leaves an in-memory head the store does not hold.
        """

        if not isinstance(stage, LineageStage):
            raise LineageStageOrderError("stage must be a LineageStage")

        if not isinstance(outcome, LineageOutcome):
            raise LineageBindingError("outcome must be a LineageOutcome")

        canonical = canonical_binding(binding)

        try:
            evidence_digest = canonical_evidence_digest(evidence)
        except ValueError as exc:
            raise LineageBindingError(str(exc)) from exc

        with self._lock:
            lineage = self._current(lineage_id)

            if lineage is None:
                raise LineageUnknownError(
                    f"no lineage {lineage_id[:8]}... is open"
                )

            problem = lineage.first_problem()

            if problem is not None:
                self._finding(
                    "unverifiable",
                    lineage_id,
                    len(lineage.links),
                    problem,
                )
                raise LineageBrokenError(problem)

            if lineage.sealed:
                self._finding(
                    "sealed",
                    lineage_id,
                    len(lineage.links),
                    f"the lineage ended: {lineage.seal_reason}",
                )
                raise LineageSealedError(
                    "the lineage has ended "
                    f"({lineage.seal_reason or 'sealed'})"
                )

            head = lineage.head
            ordinal = STAGE_ORDINAL[stage]

            if head is None:
                raise LineageUnknownError(
                    f"lineage {lineage_id[:8]}... holds no links"
                )

            # ---- idempotent retry, or a fork ---------------------------
            if head.is_commitment and head.ordinal == ordinal:
                same_claim = (
                    head.evidence_digest == evidence_digest
                    and head.binding_digest == binding_digest(canonical)
                )

                if same_claim:
                    return lineage

                self._finding(
                    "branch",
                    lineage_id,
                    head.sequence,
                    f"a second claim about {stage.value} at ordinal "
                    f"{ordinal}",
                )
                raise LineageForkError(
                    f"the lineage already holds a different claim about "
                    f"{stage.value}"
                )

            expected = (head.ordinal + 1) if head.is_commitment else 0

            if ordinal != expected:
                self._finding(
                    "stage_out_of_order",
                    lineage_id,
                    head.sequence,
                    f"{stage.value} presented at ordinal {ordinal}, "
                    f"expected {expected}",
                )
                raise LineageStageOrderError(
                    f"{stage.value} does not follow the committed stage "
                    f"(expected ordinal {expected}, got {ordinal})"
                )

            merged, mismatched = merge_binding(lineage.binding, canonical)

            if mismatched is not None:
                self._finding(
                    "subject_mismatch",
                    lineage_id,
                    head.sequence,
                    f"{stage.value} changes {mismatched!r}",
                )
                raise LineageSubjectMismatchError(
                    f"the {stage.value} commitment changes "
                    f"{mismatched!r}, which this lineage has already fixed"
                )

            digest = binding_digest(merged)
            sequence = len(lineage.links)
            parent = head.commitment_id

            link = LineageLink(
                commitment_id=link_id(
                    lineage_id=lineage_id,
                    sequence=sequence,
                    kind=LineageKind.COMMITMENT,
                    stage=stage,
                    ordinal=ordinal,
                    outcome=outcome,
                    evidence_digest=evidence_digest,
                    binding_digest=digest,
                    parent_digest=parent,
                ),
                lineage_id=lineage_id,
                sequence=sequence,
                kind=LineageKind.COMMITMENT,
                stage=stage,
                ordinal=ordinal,
                outcome=outcome,
                evidence_digest=evidence_digest,
                parent_digest=parent,
                binding=merged,
                binding_digest=digest,
                lease_digest=lease_digest,
                recorded_at=self._now(),
                details=dict(details or {}),
            )

            stored = self._persist(link)

            if stored is not None:
                if (
                    stored.commitment_id != link.commitment_id
                    or stored.evidence_digest != link.evidence_digest
                ):
                    # Somebody else wrote a *different* claim at this
                    # position. That is a fork at the storage layer, and the
                    # in-memory chain is refreshed from the authoritative row
                    # rather than keeping the loser.
                    self._finding(
                        "fork",
                        lineage_id,
                        sequence,
                        f"another writer holds {stage.value} at sequence "
                        f"{sequence}",
                    )
                    self._refresh(lineage_id)
                    raise LineageForkError(
                        f"another writer committed a different "
                        f"{stage.value} at this position"
                    )

                self._links.setdefault(lineage_id, []).append(stored)
                lineage = self._rebuild(
                    lineage_id, lineage.lease_id
                )
                return lineage

            self._links.setdefault(lineage_id, []).append(link)
            lineage = self._rebuild(lineage_id, lineage.lease_id)

        return lineage

    # ------------------------------------------------------------------
    # Seal
    # ------------------------------------------------------------------

    def seal(
        self,
        *,
        lineage_id: str,
        reason: str,
        binding: Optional[dict[str, Any]] = None,
        lease_digest: str = "",
    ) -> ExecutionLineage:
        """End a lineage: no further commitment is accepted.

        A seal is a link on the same chain, so it cannot be removed without
        breaking the link that follows it -- and there can be no link that
        follows it, because the journal refuses every append to a sealed
        lineage. That is what makes "this execution stopped here, for this
        reason" provable rather than inferred from the absence of a
        COMPLETED stage.

        Sealing is idempotent for the identical reason and refuses a
        *different* reason, for the same argument that governs stage claims:
        a second, different account of why an execution ended is a fork in
        the record of what happened.
        """

        if not isinstance(reason, str) or not reason:
            raise LineageBindingError("a seal needs a reason")

        digest = canonical_evidence_digest(
            {"seal": reason, "lease": lease_digest}
        )

        with self._lock:
            lineage = self._current(lineage_id)

            if lineage is None:
                raise LineageUnknownError(
                    f"no lineage {lineage_id[:8]}... is open"
                )

            if lineage.sealed:
                if lineage.head is not None and (
                    lineage.head.evidence_digest == digest
                ):
                    return lineage

                self._finding(
                    "branch",
                    lineage_id,
                    len(lineage.links),
                    f"a second seal with a different reason ({reason})",
                )
                raise LineageForkError(
                    "the lineage is already sealed with a different reason"
                )

            head = lineage.head

            if head is None:
                raise LineageUnknownError(
                    f"lineage {lineage_id[:8]}... holds no links"
                )

            merged = dict(lineage.binding)

            if binding is not None:
                canonical = canonical_binding(binding)
                merged, mismatched = merge_binding(merged, canonical)

                if mismatched is not None:
                    self._finding(
                        "subject_mismatch",
                        lineage_id,
                        head.sequence,
                        f"a seal changes {mismatched!r}",
                    )
                    raise LineageSubjectMismatchError(
                        f"the seal changes {mismatched!r}"
                    )

            sequence = len(lineage.links)

            link = LineageLink(
                commitment_id=link_id(
                    lineage_id=lineage_id,
                    sequence=sequence,
                    kind=LineageKind.SEAL,
                    stage=None,
                    ordinal=None,
                    outcome=None,
                    evidence_digest=digest,
                    binding_digest=binding_digest(merged),
                    parent_digest=head.commitment_id,
                ),
                lineage_id=lineage_id,
                sequence=sequence,
                kind=LineageKind.SEAL,
                stage=None,
                ordinal=None,
                outcome=None,
                evidence_digest=digest,
                parent_digest=head.commitment_id,
                binding=merged,
                binding_digest=binding_digest(merged),
                lease_digest=lease_digest or head.lease_digest,
                recorded_at=self._now(),
                seal_reason=reason,
            )

            stored = self._persist(link)

            if stored is not None:
                if stored.evidence_digest != digest:
                    self._finding(
                        "fork",
                        lineage_id,
                        sequence,
                        "another writer sealed this lineage differently",
                    )
                    self._refresh(lineage_id)
                    raise LineageForkError(
                        "another writer sealed this lineage with a "
                        "different reason"
                    )

                self._links.setdefault(lineage_id, []).append(stored)
                return self._rebuild(lineage_id, lineage.lease_id)

            self._links.setdefault(lineage_id, []).append(link)
            lineage = self._rebuild(lineage_id, lineage.lease_id)

        return lineage

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, lineage_id: str) -> Optional[ExecutionLineage]:
        """The lineage for ``lineage_id``, or ``None``.

        ``None`` is the fail-closed answer for an unknown, absent or
        unopenable lineage: a lineage nobody can produce cannot say what an
        execution did.

        The value is **re-derived from the links the journal holds** on every
        read, and that is a security decision rather than a caching choice.
        A cached value is a second account of the chain, and a second account
        can disagree with the first: an edit to the stored links would leave
        every reader of the cache seeing a chain that still verifies, so the
        enforcement path would keep progressing an execution whose record was
        rewritten while the audit reported it. Deriving the value from the
        links means there is exactly one account, and a rewritten link refuses
        at the gate as well as being a finding.
        """

        if not isinstance(lineage_id, str) or not lineage_id:
            return None

        with self._lock:
            known = self._lineages.get(lineage_id)

            if known is None:
                return None

            return self._rebuild(lineage_id, known.lease_id)

    def for_lease(self, lease_id: str) -> Optional[ExecutionLineage]:
        """The lineage bound to one lease, or ``None``."""

        if not isinstance(lease_id, str) or not lease_id:
            return None

        with self._lock:
            lineage_id = self._by_lease.get(lease_id)

            if lineage_id is None:
                # The index is a cache of the bindings; a chain whose lease
                # is only named inside its links is still this lease's chain.
                for candidate in sorted(self._lineages):
                    if self._lineages[candidate].lease_id == lease_id:
                        lineage_id = candidate
                        break

            if lineage_id is None:
                return None

            return self._rebuild(lineage_id, lease_id)

    def by_execution(
        self,
        execution_id: str,
    ) -> Optional[ExecutionLineage]:
        """The lineage bound to one execution identity, or ``None``."""

        if not isinstance(execution_id, str) or not execution_id:
            return None

        with self._lock:
            lineage_id = self._by_execution.get(execution_id)

            if lineage_id is None:
                for candidate in sorted(self._lineages):
                    if (
                        self._lineages[candidate].execution_id
                        == execution_id
                    ):
                        lineage_id = candidate
                        break

            if lineage_id is None:
                return None

            known = self._lineages.get(lineage_id)

            if known is None:
                return None

            return self._rebuild(lineage_id, known.lease_id)

    def lineages(self) -> tuple[ExecutionLineage, ...]:
        """Every open lineage, in open order, derived from the stored links."""

        with self._lock:
            return tuple(
                self._rebuild(lineage_id, self._lineages[lineage_id].lease_id)
                for lineage_id in self._lineages
            )

    def links(self) -> tuple[LineageLink, ...]:
        """Every link in every chain, in chain order."""

        with self._lock:
            return tuple(
                link
                for lineage_id in self._lineages
                for link in self._links.get(lineage_id, ())
            )

    def findings(self) -> tuple[LineageFinding, ...]:
        """Every refused lineage operation, oldest first."""

        with self._lock:
            return tuple(self._findings)

    def record_finding(
        self,
        kind: str,
        lineage_id: str,
        sequence: int,
        detail: str,
    ) -> None:
        """Record one refused lineage operation from outside this module.

        Exists so the enforcement path can record *its own* refusals -- a
        progression halted because no lineage exists, say -- in the same
        audit trail as the journal's, instead of leaving them only in the
        caller's return value. The kind is validated against
        :data:`FINDING_KINDS` so an operator cannot be handed a finding the
        invariant has no rule for.
        """

        if kind not in FINDING_KINDS:
            raise LineageBindingError(
                f"unknown lineage finding kind: {kind!r}"
            )

        with self._lock:
            self._finding(kind, lineage_id, sequence, detail)

    def verify(self, lineage_id: str) -> tuple[str, ...]:
        """Every reason one chain does not attest its own sequence."""

        lineage = self.get(lineage_id)

        if lineage is None:
            return (f"no lineage {lineage_id[:8]}... is open",)

        return lineage.verify()

    def broken(self) -> tuple[tuple[str, str], ...]:
        """``(lineage_id, first problem)`` for every chain that fails."""

        with self._lock:
            return tuple(
                (lineage_id, problem)
                for lineage_id in sorted(self._lineages)
                for problem in (
                    self._lineages[lineage_id].first_problem(),
                )
                if problem is not None
            )

    def size(self) -> int:
        with self._lock:
            return len(self._lineages)

    def link_count(self) -> int:
        with self._lock:
            return sum(len(chain) for chain in self._links.values())

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()

    def __enter__(self) -> "LineageJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# =====================================================================
# Completeness
# =====================================================================


def completeness_problems(
    lineage: ExecutionLineage,
    *,
    side_effect_adopted: bool,
    attestation_required: bool,
    expect_completed: bool = True,
) -> tuple[str, ...]:
    """Why a lineage does not justify a clean COMPLETED, or ``()``.

    The gate and the invariant ask one question one way, so the rule lives
    here rather than in either of them -- and which stages it demands is the
    only thing that differs between the two callers, which is why it is a
    parameter rather than a second function. The invariant audits a
    *finished* chain (``expect_completed=True``, the default); the completion
    gate audits a chain that is one commitment short of finishing, because
    COMPLETED is the stage it is about to commit.

    Two requirements, and the second is what makes the check independent of
    the configuration:

    * **The sequence is complete.** Every stage up to and including the last
      one demanded is present and in order, because a completion fills any
      stage the protocol did not perform as ``NOT_ADOPTED``; a chain missing
      one of them is not a completed execution, whatever the lease store
      says.
    * **Nothing that was required was refused.** No stage may be
      ``REFUSED`` -- a refused stage is an observation that did not support
      progression, and an execution cannot carry one and also claim it
      completed cleanly. When the execution adopted the side-effect protocol,
      ``OBSERVED`` and ``VERIFIED`` must be ``ADOPTED``; when attestation was
      required, ``ATTESTED`` must be ``ADOPTED``.

    ``NOT_ADOPTED`` is accepted for a stage the protocol genuinely did not
    perform, which is why the two switches exist: they say what *this*
    execution's protocol committed to, and the invariant re-derives them from
    the other journals rather than taking a caller's word for it.
    """

    problems: list[str] = []

    required_stages = (
        STAGE_ORDER if expect_completed else PRIOR_STAGES
    )
    present = set(lineage.stages)
    missing = tuple(
        stage for stage in required_stages if stage not in present
    )

    if missing:
        problems.append(
            "the lineage is missing "
            + ", ".join(stage.value for stage in missing)
        )

    for stage in required_stages:
        outcome = lineage.outcome_of(stage)

        if outcome is LineageOutcome.REFUSED:
            problems.append(
                f"the lineage records {stage.value} as refused"
            )

    required = []

    if side_effect_adopted:
        required.extend(SIDE_EFFECT_STAGES)

    if attestation_required:
        required.append(LineageStage.ATTESTED)

    for stage in required:
        outcome = lineage.outcome_of(stage)

        if outcome is not LineageOutcome.ADOPTED:
            problems.append(
                f"the lineage does not record {stage.value} as adopted "
                f"({outcome.value if outcome is not None else 'absent'})"
            )

    return tuple(problems)


__all__ = [
    "BINDING_FIELDS",
    "FINDING_KINDS",
    "LINEAGE_ANCHOR",
    "LINEAGE_DOMAIN",
    "OPTIONAL_BINDING_FIELDS",
    "PRIOR_STAGES",
    "REQUIRED_BINDING_FIELDS",
    "SIDE_EFFECT_STAGES",
    "STAGE_ORDER",
    "STAGE_ORDINAL",
    "ExecutionLineage",
    "LineageBindingError",
    "LineageBrokenError",
    "LineageConflictError",
    "LineageError",
    "LineageFinding",
    "LineageForkError",
    "LineageJournal",
    "LineageJournalError",
    "LineageKind",
    "LineageLink",
    "LineageOutcome",
    "LineageSealedError",
    "LineageStage",
    "LineageStageOrderError",
    "LineageSubjectMismatchError",
    "LineageUnknownError",
    "binding_digest",
    "canonical_binding",
    "canonical_evidence_digest",
    "completeness_problems",
    "lineage_id_for",
    "lineage_outcome_of",
    "lineage_stage_of",
    "link_id",
    "merge_binding",
]
