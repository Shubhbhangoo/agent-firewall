"""Rule simulation and staged rollout (v1.7).

The v1.6 console gave developers a write surface: they can author rules
from the browser. This package answers the question that immediately
follows -- *what will this rule actually do?* -- before the rule is
allowed to take effect.

Nothing here authorizes anything. Every verdict in a simulation report is
produced by the real ``FirewallSDK.authorize()`` running the real gate
pipeline; this package only decides *which* requests to replay, *under
which rules*, and *how to compare* the outcomes. There is no second
authorization engine, no shadow policy language, and no rule type that
the existing gates do not already enforce.

The four pieces:

``case``
    A :class:`~firewall.simulation.case.RequestCase` is a replayable
    authorization request -- the material facts of a capability chain
    plus the request payload plus the decision that was observed.

``recorder``
    Turns real evaluations into cases, using the read-only projection
    layer so no cryptographic material is captured.

``ruleset``
    A :class:`~firewall.simulation.ruleset.RuleSet` is the set of
    globally scoped rules a person can author: the delegation-depth
    ceiling and the trusted-issuer set. Both are enforced by existing
    gates.

``replay``
    Replays a case set under two rule sets in isolated in-memory
    workspaces and reports every decision that changed.

``rollout``
    A governance state machine -- ``observe -> warn -> enforce``. A rule
    set cannot be enforced until it has been simulated, and a rule set
    that newly denies traffic cannot be enforced without an explicit
    acknowledgement. This is workflow, not authorization.
"""

from firewall.simulation.case import (
    CaseSet,
    DelegationHop,
    RequestCase,
    SimulationError,
)
from firewall.simulation.recorder import CaseRecorder
from firewall.simulation.replay import (
    MAX_CASES,
    simulate,
    simulate_change,
)
from firewall.simulation.report import (
    CaseOutcome,
    SimulationReport,
)
from firewall.simulation.rollout import (
    Rollout,
    RolloutError,
    RolloutStage,
)
from firewall.simulation.ruleset import RuleSet

__all__ = [
    "MAX_CASES",
    "CaseOutcome",
    "CaseRecorder",
    "CaseSet",
    "DelegationHop",
    "RequestCase",
    "Rollout",
    "RolloutError",
    "RolloutStage",
    "RuleSet",
    "SimulationError",
    "SimulationReport",
    "simulate",
    "simulate_change",
]
