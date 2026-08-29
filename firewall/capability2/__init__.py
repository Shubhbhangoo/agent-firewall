"""v2.1 Capability Firewall 2.0 (firewall.capability2).

Composable capability constraints over resource, scope, action, time,
context, agent identity, task identity, delegation lineage, provenance,
and environment, with safe attenuation: a delegated capability never
gains authority compared with its parent.
"""

from firewall.capability2.constraints import (
    CONSTRAINT_NAMESPACES,
    Capability2,
    Capability2Error,
    validate_constraints,
)

__all__ = [
    "CONSTRAINT_NAMESPACES",
    "Capability2",
    "Capability2Error",
    "validate_constraints",
]
