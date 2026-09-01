"""Machine-checkable security invariants for Agent Firewall v2.2.

Eleven properties that must hold of every execution. Three are claims
about the source tree, so they are checked by reading it; the rest are
claims about a running system, so they are checked by probing one.

    from firewall.invariants import assert_all

    assert_all(sdk, policy_history=history)

The suite is not an authorization authority and cannot become one. It
produces :class:`InvariantResult` findings; ``FirewallSDK.authorize``
remains the only thing that decides. A ``VIOLATED`` report does not
revoke anything and a ``HOLDS`` report does not grant anything --
AUTHORIZATION_UNIQUENESS, which this package ships, is what keeps that
true of the package itself.

``UNVERIFIABLE`` is not a pass. :attr:`InvariantReport.holds` is false
whenever any invariant could not be established, and :func:`assert_all`
raises on it, because a suite that quietly passes when its evidence is
missing converts absent verification into a security claim.
"""

from __future__ import annotations

from firewall.invariants.model import (
    InvariantReport,
    InvariantResult,
    InvariantStatus,
    InvariantViolation,
    holds,
    unverifiable,
    violated,
)
from firewall.invariants.registry import (
    INVARIANTS,
    Invariant,
    assert_all,
    check_all,
    invariant,
    unverifiable_names,
)
from firewall.invariants.runtime import (
    check_capability_monotonicity,
    check_delegation_monotonicity,
    check_evidence_integrity,
    check_fail_closed,
    check_policy_non_widening,
    check_provenance_integrity,
    check_revocation_monotonicity,
    check_simulation_isolation,
    control_plane_snapshot,
)
from firewall.invariants.static import (
    check_authorization_uniqueness,
    check_control_plane_integrity,
    check_model_non_authority,
    duplicate_provenance_vocabularies,
)

__all__ = [
    "INVARIANTS",
    "Invariant",
    "InvariantReport",
    "InvariantResult",
    "InvariantStatus",
    "InvariantViolation",
    "assert_all",
    "check_all",
    "check_authorization_uniqueness",
    "check_capability_monotonicity",
    "check_control_plane_integrity",
    "check_delegation_monotonicity",
    "check_evidence_integrity",
    "check_fail_closed",
    "check_model_non_authority",
    "check_policy_non_widening",
    "check_provenance_integrity",
    "check_revocation_monotonicity",
    "check_simulation_isolation",
    "control_plane_snapshot",
    "duplicate_provenance_vocabularies",
    "holds",
    "invariant",
    "unverifiable",
    "unverifiable_names",
    "violated",
]
