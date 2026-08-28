"""Security Replay Laboratory (v1.8).

Replays a recorded artifact's authorization history through the real
authorization pipeline and answers counterfactual questions ("what
would have happened under this policy?"). Reuses the v1.7 simulation
engine; every replay runs in isolated throwaway workspaces.

Classifications are explicit and never conflated: ``observed``,
``replayed``, ``counterfactual``, ``simulated``, and ``unverifiable``.
"""

from firewall.replaylab.laboratory import (
    CounterfactualReport,
    CounterfactualRow,
    Laboratory,
    ReplayLabError,
    baseline_rules,
    extract_cases,
)

__all__ = [
    "CounterfactualReport",
    "CounterfactualRow",
    "Laboratory",
    "ReplayLabError",
    "baseline_rules",
    "extract_cases",
]
