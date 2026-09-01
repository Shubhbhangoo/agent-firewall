"""v2.2 Continuous Authorization (firewall.continuous_auth).

A capability valid at time T1 must not automatically remain valid at T2 when
security-relevant state has materially changed.

This module implements deterministic re-evaluation of authorization decisions
based on changes to:

* identity state (revoked, rotated, retired)
* task state (revoked, expired, narrowed)
* capability state (revoked, expired, attenuated)
* delegation state (revoked, ancestor revoked, chain broken)
* provenance (component revoked, integrity failed)
* posture (state transition to compromised/contained/high_risk)
* risk (critical risk recorded, threshold exceeded)
* trust (score collapse, relationship revoked)
* policy version (policy changed, rules added/removed)
* environment (environment markers changed)
* resource state (resource revoked, sensitivity changed)
* incident state (incident opened/closed, severity)
* time (capability/task/delegation expiration)

The continuous authorization subsystem feeds the canonical SDK authorization
path - it does not create a second authorization engine.
"""

from firewall.continuous_auth.engine import (
    PROBE_FAILED,
    UNKNOWN,
    UNTHROTTLED_TRIGGERS,
    ContinuousAuthorizationEngine,
    RevalidationTrigger,
    RevalidationResult,
    SecurityContextSnapshot,
)

from firewall.continuous_auth.monitor import (
    ContinuousAuthorizationMonitor,
    MonitoredDecision,
    MonitoringConfig,
    RevalidationAttempt,
    RevalidationOutcome,
)

from firewall.continuous_auth.predicates import (
    MonotonicityResult,
    is_narrower_than,
    authority_monotonicity_check,
    delegation_monotonicity_check,
    revocation_monotonicity_check,
    recovery_monotonicity_check,
    policy_transformation_monotonicity_check,
)

__all__ = [
    "PROBE_FAILED",
    "UNKNOWN",
    "UNTHROTTLED_TRIGGERS",
    "ContinuousAuthorizationEngine",
    "RevalidationTrigger",
    "RevalidationResult",
    "SecurityContextSnapshot",
    "ContinuousAuthorizationMonitor",
    "MonitoredDecision",
    "MonitoringConfig",
    "RevalidationAttempt",
    "RevalidationOutcome",
    "MonotonicityResult",
    "is_narrower_than",
    "authority_monotonicity_check",
    "delegation_monotonicity_check",
    "revocation_monotonicity_check",
    "recovery_monotonicity_check",
    "policy_transformation_monotonicity_check",
]