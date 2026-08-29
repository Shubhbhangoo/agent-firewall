"""v2.1 Real-Time Agent Defense Mesh (firewall.defense).

Continuously evaluated defense around agents: live identity verification,
dynamic trust evaluation, continuous capability evaluation, immediate
revocation, automatic quarantine, audited recovery and re-entry, and
fail-closed behavior.
"""

from firewall.defense.mesh import (
    DefenseError,
    DefenseMesh,
    MESH_STATES,
    MeshState,
    MeshTransition,
)

__all__ = [
    "DefenseError",
    "DefenseMesh",
    "MESH_STATES",
    "MeshState",
    "MeshTransition",
]
