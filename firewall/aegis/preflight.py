"""Pre-authorization analysis. A pipeline that ends *before* the decision.

§7 asks for a pipeline: requested authority -> simulation -> attack graph
-> delegation -> policy -> blast radius -> evidence -> canonical
``authorize()``. The arrow into ``authorize()`` is the important one: this
module is everything to the left of it and nothing to the right.

Three shapes make that structural rather than aspirational.

**The result cannot be read as permission.** :class:`Preflight` has no
``allowed`` field and raises on ``bool()``. The strongest thing it can say
is ``ALLOW``, and ``ALLOW`` here means *preflight found nothing to
object to* -- the boundary has not been consulted and preflight cannot
consult it. Nothing in this module imports ``firewall.sdk`` or constructs
an :class:`~firewall.authorization.AuthorizationResult`, which
AUTHORIZATION_UNIQUENESS machine-checks.

**Uncertainty cannot be laundered into endorsement.** The recommendation
is a join over stage findings, ordered

    ALLOW  <  REVIEW  <  NARROW  <  SUSPEND  <  DENY

with ``REVIEW`` sitting directly above ``ALLOW`` precisely so that "we
could not establish this" outranks "we found nothing wrong". An impact of
``UNKNOWN`` or ``UNANALYZABLE`` contributes ``REVIEW``, so no combination
of inputs produces ``(UNKNOWN, ALLOW)``. That is checked exhaustively over
the finite cross-product by the UNKNOWN_NON_AUTHORIZATION invariant rather
than argued for here.

**``ALLOW`` requires positive evidence.** It is the identity of the join,
so silence would otherwise mean endorsement. :func:`_allow_is_established`
gates it: at least one stage must have run, every stage that ran must have
*established* its property, and the impact must be a size class rather
than an absence of one.

The pipeline is a pure function
-------------------------------

:func:`preflight` takes findings that were already computed -- an
envelope, a restriction answer, a blast radius, a simulation report,
evidence findings -- and combines them. It performs no I/O, resolves no
chains, and holds no locks, so it cannot observe a different state than
the caller did and cannot introduce a TOCTOU window of its own. Gathering
the inputs is the caller's job, and the caller is the controller or the
SDK, both of which already hold the state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Optional

from firewall.aegis.blast import BlastRadius


class Impact(str, Enum):
    """How much a request could affect, if it were performed.

    ``UNANALYZABLE`` and ``UNKNOWN`` are distinct and both are kept.
    ``UNANALYZABLE`` means analysis was attempted and could not finish --
    a cap was hit, a dependency raised. ``UNKNOWN`` means it was never
    attempted, because the input was not supplied. Collapsing them would
    lose the difference between "blind" and "did not look", which is
    exactly the difference an operator needs in order to fix it.
    """

    LOW_IMPACT = "low_impact"
    BOUNDED = "bounded"
    HIGH_IMPACT = "high_impact"
    UNANALYZABLE = "unanalyzable"
    UNKNOWN = "unknown"


#: Impact classes that describe a size. The other two describe an absence
#: of knowledge, and :func:`_allow_is_established` requires membership
#: here -- so a class added later is excluded until someone adds it
#: deliberately.
SIZED_IMPACTS = frozenset({Impact.LOW_IMPACT, Impact.BOUNDED})


class Recommendation(str, Enum):
    """What preflight suggests. Never what the system does."""

    ALLOW = "allow"
    REVIEW = "review"
    NARROW = "narrow"
    SUSPEND = "suspend"
    DENY = "deny"


#: The lattice. ``REVIEW`` above ``ALLOW`` is the load-bearing choice.
RECOMMENDATION_SEVERITY: Mapping[Recommendation, int] = {
    Recommendation.ALLOW: 0,
    Recommendation.REVIEW: 1,
    Recommendation.NARROW: 2,
    Recommendation.SUSPEND: 3,
    Recommendation.DENY: 4,
}


def severity(recommendation: Recommendation) -> int:
    return RECOMMENDATION_SEVERITY[recommendation]


def join(*recommendations: Recommendation) -> Recommendation:
    """The maximum. With no arguments, the identity ``ALLOW``."""

    result = Recommendation.ALLOW

    for recommendation in recommendations:
        if severity(recommendation) > severity(result):
            result = recommendation

    return result


class StageStatus(str, Enum):
    """Whether a stage established its property.

    ``NOT_ESTABLISHED`` is a positive finding -- the stage looked and the
    property does not hold. ``UNAVAILABLE`` is the absence of a finding.
    Both are non-``ESTABLISHED``, and only ``ESTABLISHED`` can contribute
    to an ``ALLOW``.
    """

    ESTABLISHED = "established"
    NOT_ESTABLISHED = "not_established"
    UNAVAILABLE = "unavailable"


#: Pipeline order, exactly as §7 specifies it. Recorded as data so a
#: report can show which stages ran and in what order without the order
#: being implicit in the code that happens to run them.
STAGE_ORDER = (
    "requested_authority",
    "simulation",
    "delegation",
    "policy",
    "blast_radius",
    "evidence",
)
@dataclass(frozen=True)
class Stage:
    """One pipeline stage's finding."""

    name: str
    status: StageStatus
    recommendation: Recommendation
    detail: str

    def describe(self) -> dict:
        return {
            "stage": self.name,
            "status": self.status.value,
            "recommendation": self.recommendation.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Preflight:
    """The pipeline's output. Analysis, ordered, and explicitly not a verdict."""

    impact: Impact
    recommendation: Recommendation
    stages: tuple[Stage, ...] = ()
    blast: Optional[BlastRadius] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        raise TypeError(
            "a Preflight is not a decision; it is analysis performed before "
            "one. Read .recommendation, and call FirewallSDK.authorize() to "
            "decide"
        )

    @property
    def established(self) -> bool:
        """Did every stage that ran establish its property?"""

        return bool(self.stages) and all(
            stage.status is StageStatus.ESTABLISHED for stage in self.stages
        )

    @property
    def objects(self) -> bool:
        """Does preflight object to the request in any way?"""

        return self.recommendation is not Recommendation.ALLOW

    def describe(self) -> dict:
        return {
            "impact": self.impact.value,
            "recommendation": self.recommendation.value,
            "established": self.established,
            "stages": [stage.describe() for stage in self.stages],
            "blast_radius": None if self.blast is None else self.blast.describe(),
            "details": dict(self.details),
        }


def classify_impact(
    blast: Optional[BlastRadius],
    *,
    bounded_reach: int = 8,
) -> tuple[Impact, str]:
    """Classify reach into an impact class, and say why.

    ``bounded_reach`` only ever *escalates*: a larger estate produces a
    more severe class, which produces a more severe recommendation, which
    can only subtract authority. There is no comparison anywhere in this
    module of the forbidden shape ``measure < threshold -> permit``; the
    inequality runs the other way and its consequences run the other way
    too.
    """

    if blast is None:
        return (
            Impact.UNKNOWN,
            "no blast radius was supplied, so reach was never computed",
        )

    if not isinstance(blast, BlastRadius):
        return (
            Impact.UNANALYZABLE,
            f"blast radius is a {type(blast).__name__}, not a BlastRadius",
        )

    if not blast.complete:
        kinds = sorted({item.kind for item in blast.unanalyzable})
        return (
            Impact.UNANALYZABLE,
            (
                "the traversal did not finish ("
                + ", ".join(kinds)
                + "), so the true reach is larger than what was computed"
            ),
        )

    if blast.touches_sensitive:
        return (
            Impact.HIGH_IMPACT,
            (
                "the subtree reaches labels the attack graph flags as "
                "sensitive: " + ", ".join(blast.sensitive_targets)
            ),
        )

    reach = blast.reach

    if reach <= 1:
        return (
            Impact.LOW_IMPACT,
            f"reach is {reach}: the grant has no analysed descendants",
        )

    if reach <= max(1, int(bounded_reach)):
        return (
            Impact.BOUNDED,
            f"reach is {reach}, within the bounded reach of {bounded_reach}",
        )

    return (
        Impact.HIGH_IMPACT,
        f"reach is {reach}, above the bounded reach of {bounded_reach}",
    )


#: Impact -> the recommendation that impact alone contributes. Note that
#: neither ``UNKNOWN`` nor ``UNANALYZABLE`` maps to ``ALLOW``, and that
#: this is a total mapping over the enum.
IMPACT_RECOMMENDATION: Mapping[Impact, Recommendation] = {
    Impact.LOW_IMPACT: Recommendation.ALLOW,
    Impact.BOUNDED: Recommendation.ALLOW,
    Impact.HIGH_IMPACT: Recommendation.NARROW,
    Impact.UNANALYZABLE: Recommendation.REVIEW,
    Impact.UNKNOWN: Recommendation.REVIEW,
}

MISSING_IMPACT_RECOMMENDATIONS = tuple(
    impact.value for impact in Impact if impact not in IMPACT_RECOMMENDATION
)
def _requested_authority_stage(
    envelope: Any,
    action: str,
    request: Any,
    now: Optional[float],
) -> Stage:
    """Does the requested authority fall inside the grant's envelope?

    Uses the envelope's *sound* direction only. ``excludes`` returning a
    reason means the boundary will deny, so ``DENY`` is a faithful
    recommendation. ``excludes`` returning ``None`` establishes nothing
    about admission -- it means the envelope has no objection -- so the
    stage records ``ESTABLISHED`` for "no bound is violated", never
    "authorized".
    """

    if envelope is None:
        return Stage(
            name="requested_authority",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail="no authority envelope was supplied",
        )

    reader = getattr(envelope, "excludes", None)

    if not callable(reader):
        return Stage(
            name="requested_authority",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail=f"{type(envelope).__name__} does not expose excludes()",
        )

    try:
        reason = reader(action, request, now)
    except Exception as error:  # noqa: BLE001 - recorded, never raised
        return Stage(
            name="requested_authority",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail=f"{type(error).__name__} computing the envelope bound",
        )

    if reason is not None:
        return Stage(
            name="requested_authority",
            status=StageStatus.NOT_ESTABLISHED,
            recommendation=Recommendation.DENY,
            detail=f"the envelope excludes this request: {reason}",
        )

    return Stage(
        name="requested_authority",
        status=StageStatus.ESTABLISHED,
        recommendation=Recommendation.ALLOW,
        detail=(
            "the request violates no envelope bound; admission is still the "
            "boundary's to decide"
        ),
    )


def _simulation_stage(report: Any) -> Stage:
    """Fold a :class:`~firewall.simulation.SimulationReport`.

    A case that the simulator could not reproduce faithfully does not
    count -- that is already the report's own rule (``CaseOutcome.
    counted``) and Aegis does not soften it. An uncounted case means the
    simulation established nothing, so the stage is ``UNAVAILABLE`` and
    contributes ``REVIEW``.
    """

    if report is None:
        return Stage(
            name="simulation",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail="no simulation was run",
        )

    outcomes = getattr(report, "outcomes", None)
    counted = getattr(report, "counted_outcomes", None)

    if outcomes is None:
        return Stage(
            name="simulation",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail=f"{type(report).__name__} is not a simulation report",
        )

    if counted is None:
        counted = tuple(
            outcome for outcome in outcomes if getattr(outcome, "counted", False)
        )

    if not counted:
        return Stage(
            name="simulation",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail=(
                f"{len(tuple(outcomes))} cases were simulated and none was "
                f"both reproducible and faithful, so the simulation "
                f"established nothing"
            ),
        )

    widened = tuple(
        outcome
        for outcome in counted
        if getattr(outcome, "before_allowed", None) is False
        and getattr(outcome, "after_allowed", None) is True
    )

    if widened:
        return Stage(
            name="simulation",
            status=StageStatus.NOT_ESTABLISHED,
            recommendation=Recommendation.REVIEW,
            detail=(
                f"{len(widened)} simulated case(s) turn a denial into an "
                f"allow; a widening must be reviewed, and simulation cannot "
                f"authorize it"
            ),
        )

    return Stage(
        name="simulation",
        status=StageStatus.ESTABLISHED,
        recommendation=Recommendation.ALLOW,
        detail=(
            f"{len(counted)} reproducible, faithful case(s) show no simulated "
            f"widening"
        ),
    )


def _delegation_stage(
    chain_resolved: Optional[bool],
    depth: Optional[int],
    depth_ceiling: Optional[int],
) -> Stage:
    if chain_resolved is None:
        return Stage(
            name="delegation",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail="the delegation chain was not resolved for this preflight",
        )

    if not chain_resolved:
        return Stage(
            name="delegation",
            status=StageStatus.NOT_ESTABLISHED,
            recommendation=Recommendation.DENY,
            detail="the delegation chain does not resolve",
        )

    if (
        isinstance(depth, int)
        and isinstance(depth_ceiling, int)
        and depth > depth_ceiling
    ):
        return Stage(
            name="delegation",
            status=StageStatus.NOT_ESTABLISHED,
            recommendation=Recommendation.DENY,
            detail=f"depth {depth} exceeds the ceiling of {depth_ceiling}",
        )

    return Stage(
        name="delegation",
        status=StageStatus.ESTABLISHED,
        recommendation=Recommendation.ALLOW,
        detail=(
            "the chain resolves"
            + ("" if depth is None else f" at depth {depth}")
        ),
    )


def _restriction_stage(restriction_reason: Optional[str]) -> Stage:
    """The active-restriction stage, folded into "policy" per §7's order."""

    if restriction_reason is None:
        return Stage(
            name="policy",
            status=StageStatus.ESTABLISHED,
            recommendation=Recommendation.ALLOW,
            detail="no active Aegis restriction objects to this request",
        )

    if restriction_reason.startswith("aegis_suspended"):
        return Stage(
            name="policy",
            status=StageStatus.NOT_ESTABLISHED,
            recommendation=Recommendation.SUSPEND,
            detail=f"the grant is suspended: {restriction_reason}",
        )

    return Stage(
        name="policy",
        status=StageStatus.NOT_ESTABLISHED,
        recommendation=Recommendation.DENY,
        detail=f"an active restriction refuses this request: {restriction_reason}",
    )


def _evidence_stage(findings: Optional[Iterable[str]]) -> Stage:
    if findings is None:
        return Stage(
            name="evidence",
            status=StageStatus.UNAVAILABLE,
            recommendation=Recommendation.REVIEW,
            detail="no evidence-integrity findings were supplied",
        )

    collected = tuple(str(item) for item in findings)

    if collected:
        return Stage(
            name="evidence",
            status=StageStatus.NOT_ESTABLISHED,
            recommendation=Recommendation.SUSPEND,
            detail="evidence integrity is in question: " + ", ".join(collected),
        )

    return Stage(
        name="evidence",
        status=StageStatus.ESTABLISHED,
        recommendation=Recommendation.ALLOW,
        detail="evidence integrity reported no findings",
    )
def _allow_is_established(
    impact: Impact,
    stages: tuple[Stage, ...],
) -> bool:
    """Every condition ``ALLOW`` requires, in one place.

    Mirrors :func:`firewall.aegis.response._keep_is_established`: the
    identity of a join must never be reachable by silence.
    """

    if not stages:
        return False

    if impact not in SIZED_IMPACTS:
        return False

    return all(stage.status is StageStatus.ESTABLISHED for stage in stages)


def preflight(
    action: str,
    request: Any,
    *,
    envelope: Any = None,
    now: Optional[float] = None,
    restriction_reason: Optional[str] = None,
    chain_resolved: Optional[bool] = None,
    depth: Optional[int] = None,
    depth_ceiling: Optional[int] = None,
    blast: Optional[BlastRadius] = None,
    simulation: Any = None,
    evidence_findings: Optional[Iterable[str]] = None,
    bounded_reach: int = 8,
) -> Preflight:
    """Run the §7 pipeline over already-gathered findings.

    Pure, total, and never raises. Every stage that cannot answer records
    ``UNAVAILABLE`` and contributes ``REVIEW``, so an absent input makes
    the recommendation weaker rather than stronger -- and can never make
    it ``ALLOW``.
    """

    impact, impact_detail = classify_impact(blast, bounded_reach=bounded_reach)

    stages = (
        _requested_authority_stage(envelope, action, request, now),
        _simulation_stage(simulation),
        _delegation_stage(chain_resolved, depth, depth_ceiling),
        _restriction_stage(restriction_reason),
        Stage(
            name="blast_radius",
            status=(
                StageStatus.ESTABLISHED
                if impact in SIZED_IMPACTS
                else StageStatus.UNAVAILABLE
                if impact is Impact.UNKNOWN
                else StageStatus.NOT_ESTABLISHED
            ),
            recommendation=IMPACT_RECOMMENDATION.get(impact, Recommendation.REVIEW),
            detail=impact_detail,
        ),
        _evidence_stage(evidence_findings),
    )

    # The stages are built in §7's order; assert it rather than trust it,
    # because a reordering would silently change which detail a reader
    # sees first in an explanation.
    ordered = tuple(stage.name for stage in stages)
    order_matches = ordered == STAGE_ORDER

    recommendation = join(*(stage.recommendation for stage in stages))

    if recommendation is Recommendation.ALLOW and not _allow_is_established(
        impact,
        stages,
    ):
        recommendation = Recommendation.REVIEW

    return Preflight(
        impact=impact,
        recommendation=recommendation,
        stages=stages,
        blast=blast,
        details={
            "action": action,
            "impact_detail": impact_detail,
            "bounded_reach": bounded_reach,
            "stage_order_matches_specification": order_matches,
            "stages_established": sum(
                1 for stage in stages if stage.status is StageStatus.ESTABLISHED
            ),
            "stages_unavailable": sum(
                1 for stage in stages if stage.status is StageStatus.UNAVAILABLE
            ),
        },
    )
