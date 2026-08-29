"""v2.1 Agent Immune System (firewall.immune).

An autonomous defensive feedback loop:

    OBSERVE -> DETECT -> REASON -> SIMULATE -> CONTAIN -> RECOVER -> VERIFY

The reasoning system (including model output) is strictly advisory;
authorization and execution remain deterministic, policy-driven,
auditable, and fail-closed.
"""

from firewall.immune.engine import (
    CONTAINMENT_STAGES,
    ImmuneAction,
    ImmuneAdvice,
    ImmuneDetection,
    ImmuneError,
    ImmunePolicy,
    ImmuneRule,
    ImmuneSignal,
    ImmuneSystem,
)

__all__ = [
    "CONTAINMENT_STAGES",
    "ImmuneAction",
    "ImmuneAdvice",
    "ImmuneDetection",
    "ImmuneError",
    "ImmunePolicy",
    "ImmuneRule",
    "ImmuneSignal",
    "ImmuneSystem",
]
