"""v2.1 Security Digital Twin (firewall.twin).

An isolated representation of the live agent security environment for
counterfactual analysis. The twin never mutates production state and
returns explainable attack paths, reachability changes, blast radius,
containment opportunities, policy changes, and risk deltas.
"""

from firewall.twin.twin import (
    COUNTERFACTUAL_KINDS,
    CounterfactualReport,
    ReachabilityDelta,
    SecurityTwin,
    TwinError,
)

__all__ = [
    "COUNTERFACTUAL_KINDS",
    "CounterfactualReport",
    "ReachabilityDelta",
    "SecurityTwin",
    "TwinError",
]
