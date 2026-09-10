"""Project Aegis: an adaptive authority control plane.

Aegis answers a question the v2.3 control plane could not: *what should
happen to an authority that was legitimately granted, when the world it
was granted in changes?* Its answer is always one of five, and four of
them reduce authority:

    KEEP        nothing established a change
    REVALIDATE  ask the canonical boundary again
    NARROW      write a restriction the boundary will enforce
    SUSPEND     write a restriction that refuses everything
    REVOKE      hand the revocation registry a revocation

There is no sixth response, and in particular no ``WIDEN``. That is the
whole architectural claim of this package, and it is structural rather
than aspirational:

* No module here constructs an
  :class:`~firewall.authorization.AuthorizationResult`. Two files in the
  repository may -- ``firewall/authorization.py`` and ``firewall/sdk.py``
  -- and AUTHORIZATION_UNIQUENESS fails the build if a third ever does.
* Nothing here imports ``firewall.sdk``, so no module here can call
  ``authorize()`` and pass the answer off as its own.
* The only state the authorization boundary reads from Aegis is a
  :class:`~firewall.aegis.restriction.Restriction`, whose sole effect is
  to produce a deny reason. There is no shape a restriction can take that
  causes an allow.
* Every analysis type -- :class:`~firewall.aegis.envelope.AuthorityEnvelope`,
  :class:`~firewall.aegis.blast.BlastRadius`,
  :class:`~firewall.aegis.preflight.Preflight`,
  :class:`~firewall.aegis.response.Classification`,
  :class:`~firewall.aegis.state.AegisGrant` -- raises ``TypeError`` from
  ``__bool__``. None of them can appear in an ``if``, so none of them can
  quietly become a policy.
* The one edge that increases a grant's residual authority,
  ``REVALIDATING -> ACTIVE``, requires an ``AuthorizationResult`` that
  allowed, naming that grant's own fingerprint. Aegis cannot manufacture
  one, so the edge can only be traversed with evidence the boundary
  produced.

Reading order
-------------

``envelope`` is the mathematics: what bounded authority *is*, and why a
child's is a subset of its parent's. ``state`` is the machine: seven
states ordered by residual authority, with the illegal transitions
unrepresentable rather than merely untested. ``restriction`` is the only
part the boundary reads. ``response`` classifies a change; ``preflight``
classifies a request; ``blast`` bounds what a grant could reach;
``decay`` schedules a reduction an operator wrote; ``explain`` answers
§17's six questions from structured state. ``controller`` holds the
mutable pieces together and is the only object ``FirewallSDK`` needs.
"""

from firewall.aegis.blast import (
    MAX_DEPTH,
    MAX_FRONTIER,
    MAX_NODES,
    BlastRadius,
    Unanalyzable,
    blast_radius,
)
from firewall.aegis.controller import (
    NARROW_KEY_PREFIX,
    SUSPEND_KEY_PREFIX,
    AegisController,
    ExecutionRecord,
)
from firewall.aegis.decay import (
    DECAY_STAGE_SEVERITY,
    DecaySchedule,
    DecayStage,
    stages_are_monotone,
)
from firewall.aegis.envelope import (
    AuthorityEnvelope,
    BudgetBound,
    ConstraintBound,
    bottom_envelope,
    chain_envelope,
    local_constraint_bound,
    local_envelope,
    meet,
    meet_constraint_bounds,
)
from firewall.aegis.explain import Explanation, explain
from firewall.aegis.preflight import (
    IMPACT_RECOMMENDATION,
    MISSING_IMPACT_RECOMMENDATIONS,
    RECOMMENDATION_SEVERITY,
    SIZED_IMPACTS,
    STAGE_ORDER,
    Impact,
    Preflight,
    Recommendation,
    Stage,
    StageStatus,
    classify_impact,
    preflight,
)
from firewall.aegis.response import (
    MISSING_TRIGGER_MAPPINGS,
    RESPONSE_SEVERITY,
    TRIGGER_RESPONSE,
    UNKNOWN_TRIGGER_RESPONSE,
    AdaptiveResponse,
    Classification,
    Contribution,
    classify,
)
from firewall.aegis.restriction import (
    CAP_ESCALATION_KEY,
    MAX_RESTRICTIONS_PER_GRANT,
    Restriction,
    RestrictionKind,
    RestrictionStore,
    narrow,
    suspend,
)
from firewall.aegis.state import (
    EVIDENCED_EDGES,
    LIFT_EDGES,
    RESIDUAL_AUTHORITY,
    TERMINAL_STATES,
    AegisGrant,
    AegisState,
    IllegalTransition,
    Transition,
    canonical_allow_for,
    history_violations,
    residual_authority,
    transition_is_legal,
)

__all__ = [
    # controller
    "AegisController",
    "ExecutionRecord",
    "NARROW_KEY_PREFIX",
    "SUSPEND_KEY_PREFIX",
    # envelope
    "AuthorityEnvelope",
    "BudgetBound",
    "ConstraintBound",
    "bottom_envelope",
    "chain_envelope",
    "local_constraint_bound",
    "local_envelope",
    "meet",
    "meet_constraint_bounds",
    # state
    "AegisGrant",
    "AegisState",
    "IllegalTransition",
    "Transition",
    "EVIDENCED_EDGES",
    "LIFT_EDGES",
    "RESIDUAL_AUTHORITY",
    "TERMINAL_STATES",
    "canonical_allow_for",
    "history_violations",
    "residual_authority",
    "transition_is_legal",
    # restriction
    "Restriction",
    "RestrictionKind",
    "RestrictionStore",
    "CAP_ESCALATION_KEY",
    "MAX_RESTRICTIONS_PER_GRANT",
    "narrow",
    "suspend",
    # response
    "AdaptiveResponse",
    "Classification",
    "Contribution",
    "MISSING_TRIGGER_MAPPINGS",
    "RESPONSE_SEVERITY",
    "TRIGGER_RESPONSE",
    "UNKNOWN_TRIGGER_RESPONSE",
    "classify",
    # preflight
    "Impact",
    "Preflight",
    "Recommendation",
    "Stage",
    "StageStatus",
    "IMPACT_RECOMMENDATION",
    "MISSING_IMPACT_RECOMMENDATIONS",
    "RECOMMENDATION_SEVERITY",
    "SIZED_IMPACTS",
    "STAGE_ORDER",
    "classify_impact",
    "preflight",
    # blast
    "BlastRadius",
    "Unanalyzable",
    "MAX_DEPTH",
    "MAX_FRONTIER",
    "MAX_NODES",
    "blast_radius",
    # decay
    "DecaySchedule",
    "DecayStage",
    "DECAY_STAGE_SEVERITY",
    "stages_are_monotone",
    # explain
    "Explanation",
    "explain",
]
