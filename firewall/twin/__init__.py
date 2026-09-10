"""v2.1 Security Digital Twin (firewall.twin).

An isolated representation of the live agent security environment for
counterfactual analysis. The twin never mutates production state and
returns explainable attack paths, reachability changes, blast radius,
containment opportunities, policy changes, and risk deltas.

v2.2 adds :mod:`firewall.twin.adversarial`, which searches the same
recorded graph for weaknesses that already exist rather than for the
consequences of a hypothetical change. Both are analysis: neither grants
nor denies anything, and ``FirewallSDK.authorize`` consults neither.
"""

from firewall.twin.adversarial import (
    MAX_SEARCH_DEPTH,
    MAX_SEARCH_NODES,
    SEARCH_TIMEOUT_SECONDS,
    SEARCH_TYPES,
    WEAKNESS_SEVERITIES,
    AdversarialDigitalTwin,
    TwinSearchResult,
    WeaknessFinding,
)
from firewall.twin.twin import (
    COUNTERFACTUAL_KINDS,
    CounterfactualReport,
    ReachabilityDelta,
    SecurityTwin,
    TwinError,
)

__all__ = [
    "COUNTERFACTUAL_KINDS",
    "MAX_SEARCH_DEPTH",
    "MAX_SEARCH_NODES",
    "SEARCH_TIMEOUT_SECONDS",
    "SEARCH_TYPES",
    "WEAKNESS_SEVERITIES",
    "AdversarialDigitalTwin",
    "CounterfactualReport",
    "ReachabilityDelta",
    "SecurityTwin",
    "TwinError",
    "TwinSearchResult",
    "WeaknessFinding",
]
