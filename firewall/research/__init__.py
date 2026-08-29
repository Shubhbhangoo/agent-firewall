"""v2.1 Security Research Lab 3.0 (firewall.research).

An adversarial testing environment for the control plane itself:
automatically generates and tests malicious agents, forged identities,
delegation chains, capability escalation, revocation bypass, provenance
poisoning, replay attacks, trust manipulation, confused-deputy
scenarios, cross-agent escalation, and policy conflicts, plus
property-based testing. Every discovered violation is reported as a
regression-test seed.
"""

from firewall.research.lab import (
    SCENARIOS,
    ResearchFinding,
    ResearchReport,
    ResearchError,
    SecurityResearchLab,
)

__all__ = [
    "SCENARIOS",
    "ResearchFinding",
    "ResearchReport",
    "ResearchError",
    "SecurityResearchLab",
]
