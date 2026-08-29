"""v2.1 Security Intelligence Engine (firewall.intel).

Correlates evidence, agent behavior, trust relationships, provenance,
posture, attack paths, policy changes, and response history into
explainable security hypotheses with recommended containment actions.
Model output is advisory only and can never authorize actions.
"""

from firewall.intel.engine import (
    EvidenceFact,
    IntelError,
    IntelligenceEngine,
    IntelligenceReport,
    SecurityHypothesis,
)

__all__ = [
    "EvidenceFact",
    "IntelError",
    "IntelligenceEngine",
    "IntelligenceReport",
    "SecurityHypothesis",
]
