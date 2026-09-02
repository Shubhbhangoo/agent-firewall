"""v2.1 Agent-to-Agent Zero Trust (firewall.a2a).

Authenticated agent relationships: mutual cryptographic authentication,
scoped permissions, task-bound delegation, capability attenuation,
delegation-chain verification, expiring delegation, recursive
revocation, and cross-agent authorization decisions.

A decision from :meth:`~firewall.a2a.auth.AgentToAgent.authorize` reports
what established it. ``basis == BASIS_CANONICAL`` (equivalently
``decision.is_canonical``) means ``FirewallSDK.authorize()`` ran and
allowed the action; ``BASIS_RELATIONSHIP_ONLY`` means only this module's
own relationship bookkeeping did, which is necessary for a cross-agent
call and not sufficient to authorize one.
"""

from firewall.a2a.auth import (
    BASIS_CANONICAL,
    BASIS_RELATIONSHIP_ONLY,
    BASIS_UNAVAILABLE,
    A2AError,
    A2ADecision,
    AgentRelationship,
    AgentToAgent,
)

__all__ = [
    "BASIS_CANONICAL",
    "BASIS_RELATIONSHIP_ONLY",
    "BASIS_UNAVAILABLE",
    "A2AError",
    "A2ADecision",
    "AgentRelationship",
    "AgentToAgent",
]
