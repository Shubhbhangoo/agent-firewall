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
    ContinuousAuthorizationEngine,
    RevalidationTrigger,
    RevalidationResult,
    SecurityContextSnapshot,
)

from firewall.continuous_auth.monitor import (
    ContinuousAuthorizationMonitor,
    MonitoringConfig,
)

from firewall.continuous_auth.predicates import (
    is_narrower_than,
    authority_monotonicity_check,
    delegation_monotonicity_check,
    revocation_monotonicity_check,
)

__all__ = [
    "ContinuousAuthorizationEngine",
    "RevalidationTrigger",
    "RevalidationResult",
    "SecurityContextSnapshot",
    "ContinuousAuthorizationMonitor",
    "MonitoringConfig",
    "is_narrower_than",
    "authority_monotonicity_check",
    "delegation_monotonicity_check",
    "revocation_monotonicity_check",
]