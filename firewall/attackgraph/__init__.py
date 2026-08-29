"""v2.1 Autonomous Attack-Path Engine (firewall.attackgraph).

A continuously evaluated attack graph modeling agents, identities,
tasks, authorities, capabilities, tools, resources, delegations,
provenance, policies, trust relationships, and incidents - with
privilege-escalation paths, capability combinations, delegation abuse,
trust transitivity, blast radius, chokepoints, and paths from
compromised agents to sensitive resources. Every path distinguishes
observed evidence from inferred or simulated relationships.
"""

from firewall.attackgraph.engine import (
    ATTACK_EDGE_TYPES,
    ATTACK_NODE_TYPES,
    AttackEdge,
    AttackFinding,
    AttackGraph,
    AttackGraphError,
    AttackNode,
    AttackPath,
    is_sensitive,
)

__all__ = [
    "ATTACK_EDGE_TYPES",
    "ATTACK_NODE_TYPES",
    "AttackEdge",
    "AttackFinding",
    "AttackGraph",
    "AttackGraphError",
    "AttackNode",
    "AttackPath",
    "is_sensitive",
]
