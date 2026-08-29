"""v2.1 Agent-to-Agent Zero Trust (firewall.a2a).

Authenticated agent relationships: mutual cryptographic authentication,
scoped permissions, task-bound delegation, capability attenuation,
delegation-chain verification, expiring delegation, recursive
revocation, and cross-agent authorization decisions.
"""

from firewall.a2a.auth import (
    A2AError,
    A2ADecision,
    AgentRelationship,
    AgentToAgent,
)

__all__ = [
    "A2AError",
    "A2ADecision",
    "AgentRelationship",
    "AgentToAgent",
]
