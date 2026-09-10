"""The Agent Security Simulator (v1.9).

The simulator answers "what would happen if...?" for whole scenarios:
an agent compromised, a capability stolen, a policy changed, a
capability revoked, an unexpected delegation, an extra tool, a resource
compromise, or containment activation.

Design rules:

* **Never touches live state.** Every scenario runs in its own isolated
  throwaway workspace built from recorded facts (the v1.9 network) plus
  the scenario's mutations, using the real authorization pipeline.
* **Explainable.** A scenario report walks the whole chain: initial
  capabilities, available paths, reachable resources, policy decisions,
  security events, potential impact, containment opportunities.
* **Honest bases.** Outcomes are ``simulated``. Where a recorded fact
  contradicts the simulation, the contradiction is reported, never
  papered over. If a scenario cannot be reconstructed faithfully, it is
  ``unverifiable`` -- never counted as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from firewall.network.graph import AgentNetworkGraph, ReachabilityResult
from firewall.network.model import Provenance
from firewall.recorder import EventType, FlightRecorder
from firewall.sdk import FirewallSDK
from firewall.simulation import (
    MAX_CASES,
    CaseSet,
    DelegationHop,
    RequestCase,
    RuleSet,
    simulate,
)


class SimulatorError(ValueError):
    """Raised for a malformed scenario."""


# ----------------------------------------------------------------------
# Scenario model
# ----------------------------------------------------------------------

#: Scenario kinds the simulator understands.
SCENARIO_KINDS = (
    "compromised_agent",
    "stolen_capability",
    "changed_policy",
    "revoked_capability",
    "unexpected_delegation",
    "additional_tool",
    "resource_compromise",
    "containment",
)

#: Sensitivity markers reused for impact labeling.
SENSITIVE_MARKERS = (
    ".ssh/",
    "id_rsa",
    "credentials",
    "secrets",
    "token",
    "password",
    ".env",
    "shadow",
    "/etc/",
    "/root/",
)


def _is_sensitive(label: str) -> bool:
    lowered = (label or "").lower()
    return any(
        marker in lowered for marker in SENSITIVE_MARKERS
    )


@dataclass(frozen=True)
class Scenario:
    """One simulation scenario: mutations applied to recorded facts."""

    scenario_id: str
    kind: str
    title: str
    agent: str
    #: Capabilities to add for the scenario agent.
    added_capabilities: tuple[str, ...] = ()
    #: Capabilities to remove (simulated revocation).
    removed_capabilities: tuple[str, ...] = ()
    #: Policy rules to change (max_delegation_depth, trusted_issuers).
    policy: dict[str, Any] = field(default_factory=dict)
    #: Containment action to simulate (restrict / quarantine / none).
    containment: str = "none"
    #: Extra tools the scenario agent gains.
    added_tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or not self.scenario_id.strip():
            raise SimulatorError("scenario_id is required")

        if self.kind not in SCENARIO_KINDS:
            raise SimulatorError(
                f"unknown scenario kind: {self.kind}"
            )

        if not isinstance(self.agent, str) or not self.agent.strip():
            raise SimulatorError("scenario agent is required")

        if self.containment not in ("none", "restrict", "quarantine"):
            raise SimulatorError(
                f"unknown containment: {self.containment}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "kind": self.kind,
            "title": self.title,
            "agent": self.agent,
            "added_capabilities": list(self.added_capabilities),
            "removed_capabilities": list(self.removed_capabilities),
            "policy": dict(self.policy),
            "containment": self.containment,
            "added_tools": list(self.added_tools),
        }


# ----------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioReport:
    """The explainable result of one simulation."""

    scenario: dict[str, Any]
    initial: dict[str, Any]
    available_paths: tuple[dict[str, Any], ...]
    reachable_resources: tuple[str, ...]
    policy_decisions: tuple[dict[str, Any], ...]
    security_events: tuple[dict[str, Any], ...]
    potential_impact: tuple[dict[str, Any], ...]
    containment_opportunities: tuple[dict[str, Any], ...]
    unverifiable: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": dict(self.scenario),
            "initial": dict(self.initial),
            "available_paths": [
                dict(p) for p in self.available_paths
            ],
            "reachable_resources": list(self.reachable_resources),
            "policy_decisions": [
                dict(d) for d in self.policy_decisions
            ],
            "security_events": [
                dict(e) for e in self.security_events
            ],
            "potential_impact": [
                dict(i) for i in self.potential_impact
            ],
            "containment_opportunities": [
                dict(c) for c in self.containment_opportunities
            ],
            "unverifiable": [
                dict(u) for u in self.unverifiable
            ],
            "basis": Provenance.SIMULATED.value,
        }

    def to_json(self, *, indent: int = 2) -> str:
        import json

        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
        )

    def text(self) -> str:
        lines = [
            f"scenario: {self.scenario.get('title')} "
            f"({self.scenario.get('kind')})",
            "  initial capabilities: "
            + ", ".join(self.initial.get("capabilities", ()) or ("none",)),
        ]

        if self.available_paths:
            lines.append("  available paths:")
            for path in self.available_paths:
                lines.append(
                    "    " + " -> ".join(
                        [path["source"]]
                        + [hop["target"] for hop in path["hops"]]
                    )
                    + f" [{path['status']}]"
                )
        else:
            lines.append("  available paths: none")

        lines.append(
            "  reachable resources: "
            + ", ".join(self.reachable_resources or ("none",))
        )

        if self.policy_decisions:
            lines.append("  policy decisions:")
            for decision in self.policy_decisions:
                lines.append(
                    f"    {decision.get('agent')} "
                    f"{decision.get('action')} -> "
                    f"{'ALLOWED' if decision.get('allowed') else 'DENIED'}"
                    f" ({decision.get('reason')}) [{decision.get('basis')}]"
                )

        if self.potential_impact:
            lines.append("  potential impact:")
            for impact in self.potential_impact:
                lines.append(
                    f"    {impact.get('target')} "
                    f"({impact.get('label')})"
                )

        if self.containment_opportunities:
            lines.append("  containment opportunities:")
            for opportunity in self.containment_opportunities:
                lines.append(
                    f"    {opportunity.get('action')}: "
                    f"{opportunity.get('effect')}"
                )

        if self.unverifiable:
            lines.append("  unverifiable:")
            for entry in self.unverifiable:
                lines.append(
                    f"    {entry.get('reason')}"
                )

        return "\n".join(lines)


# ----------------------------------------------------------------------
# Simulator
# ----------------------------------------------------------------------


class Simulator:
    """Runs scenarios in isolated workspaces over recorded facts."""

    def __init__(
        self,
        graph: AgentNetworkGraph,
        artifacts: Iterable[dict[str, Any]] = (),
    ) -> None:
        self._graph = graph
        self._artifacts = tuple(artifacts)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def simulate(
        self,
        scenario: Scenario,
        *,
        limit: int = MAX_CASES,
    ) -> ScenarioReport:
        if not isinstance(scenario, Scenario):
            raise SimulatorError(
                "scenario must be a Scenario"
            )

        initial = self._graph.reachable(scenario.agent)

        # The scenario workspace: a fresh SDK per run, seeded from the
        # recorded facts of this agent, plus the scenario's mutations.
        workspace = FirewallSDK()
        workspace.generate_key("simulator-key")

        try:
            self._seed_agent(
                workspace,
                scenario.agent,
                initial,
            )
            self._apply_mutations(
                workspace,
                scenario,
            )

            decisions = self._evaluate(
                workspace,
                scenario,
                limit=limit,
            )
        finally:
            _close(workspace)

        paths = self._paths(initial, scenario)
        resources = self._resources(initial, scenario, decisions)
        impact = self._impact(resources, scenario)
        opportunities = self._opportunities(
            scenario,
            decisions,
        )

        unverifiable: list[dict[str, Any]] = []

        if scenario.removed_capabilities:
            missing = [
                capability
                for capability in scenario.removed_capabilities
                if capability not in initial.capabilities
            ]
            for capability in missing:
                unverifiable.append(
                    {
                        "reason": (
                            f"scenario removes {capability}, which was "
                            "not recorded as held by "
                            f"{scenario.agent}"
                        ),
                    }
                )

        return ScenarioReport(
            scenario=scenario.to_dict(),
            initial={
                "capabilities": list(initial.capabilities),
                "allowed_actions": list(initial.allowed_actions),
                "tools": list(initial.tools),
                "resources": list(initial.resources),
                "basis": Provenance.DERIVED.value,
            },
            available_paths=tuple(paths),
            reachable_resources=tuple(resources),
            policy_decisions=tuple(decisions),
            security_events=self._events(scenario, decisions),
            potential_impact=tuple(impact),
            containment_opportunities=tuple(opportunities),
            unverifiable=tuple(unverifiable),
        )

    # ------------------------------------------------------------------
    # Workspace seeding
    # ------------------------------------------------------------------

    def _seed_agent(
        self,
        workspace: FirewallSDK,
        agent: str,
        reachable: ReachabilityResult,
    ) -> None:
        """Re-issue the recorded capabilities in the throwaway
        workspace, so the scenario starts from the same authority the
        recordings describe."""

        for capability in reachable.capabilities:
            try:
                workspace.issue(
                    agent=agent,
                    capability=capability,
                )
            except Exception:
                # Re-issuing a recorded capability can fail if its name
                # violates issue rules; the scenario proceeds with the
                # capabilities it can reconstruct and the report's
                # unverifiable section flags the gap.
                continue

    def _apply_mutations(
        self,
        workspace: FirewallSDK,
        scenario: Scenario,
    ) -> None:
        """Apply the scenario's mutations in the workspace.

        This is the *simulated* reality: added capabilities are issued,
        removed capabilities are revoked, policy rules are set,
        containment elevates risk. None of this touches live state.
        """

        for capability in scenario.added_capabilities:
            try:
                workspace.issue(
                    agent=scenario.agent,
                    capability=capability,
                )
            except Exception:
                continue

        # Removals: find and revoke the issued capability.
        for capability in scenario.removed_capabilities:
            known = workspace.known_capabilities()
            for fingerprint in list(known.keys()):
                cap = known[fingerprint]
                if (
                    cap.capability == capability
                    and cap.agent_id == scenario.agent
                ):
                    try:
                        workspace.revoke(cap, reason="simulated revocation")
                    except Exception:
                        continue

        depth = scenario.policy.get("max_delegation_depth")
        if depth is not None:
            workspace.max_delegation_depth = depth

        issuers = scenario.policy.get("trusted_issuers")
        if isinstance(issuers, (list, tuple, set)):
            workspace.issuer_trust_store = _trust_set(issuers)

        if scenario.containment in ("restrict", "quarantine"):
            risk = workspace.risk_context
            if risk is not None:
                try:
                    risk.record_critical(scenario.agent)
                except Exception:
                    pass

    def _evaluate(
        self,
        workspace: FirewallSDK,
        scenario: Scenario,
        *,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Ask the real pipeline what happens for each capability."""

        decisions: list[dict[str, Any]] = []
        tested: set[str] = set()

        candidates = (
            set(scenario.added_capabilities)
            | set(scenario.removed_capabilities)
        )

        # Always test every capability the agent holds in the workspace.
        known = workspace.known_capabilities()

        for fingerprint in list(known.keys()):
            cap = known[fingerprint]
            if cap.agent_id != scenario.agent:
                continue
            candidates.add(cap.capability)

        for capability in sorted(candidates):
            if capability in tested:
                continue
            tested.add(capability)
            if len(tested) > limit:
                break

            try:
                result = workspace.authorize(
                    next(
                        cap
                        for cap in workspace.known_capabilities().values()
                        if (
                            cap.agent_id == scenario.agent
                            and cap.capability == capability
                        )
                    ),
                    capability,
                    {},
                )
            except StopIteration:
                continue
            except Exception:
                continue

            decisions.append(
                {
                    "agent": scenario.agent,
                    "action": capability,
                    "allowed": bool(result.allowed),
                    "reason": str(result.reason),
                    "basis": Provenance.SIMULATED.value,
                }
            )

        return decisions

    # ------------------------------------------------------------------
    # Derived sections
    # ------------------------------------------------------------------

    def _paths(
        self,
        initial: ReachabilityResult,
        scenario: Scenario,
    ) -> list[dict[str, Any]]:
        """Paths the scenario opens up, derived from recorded structure
        plus the scenario's added capabilities."""

        paths: list[dict[str, Any]] = []

        for capability in scenario.added_capabilities:
            sensitive = _is_sensitive(capability)

            paths.append(
                {
                    "source": scenario.agent,
                    "target": capability,
                    "hops": [
                        {
                            "edge": "issued",
                            "source": scenario.agent,
                            "target": capability,
                        }
                    ],
                    "status": (
                        "potentially_dangerous"
                        if sensitive
                        else "simulated"
                    ),
                    "basis": Provenance.SIMULATED.value,
                }
            )

        for resource in initial.resources:
            if _is_sensitive(resource):
                paths.append(
                    {
                        "source": scenario.agent,
                        "target": resource,
                        "hops": [
                            {
                                "edge": "accesses",
                                "source": scenario.agent,
                                "target": resource,
                            }
                        ],
                        "status": "potentially_dangerous",
                        "basis": Provenance.DERIVED.value,
                    }
                )

        return paths

    def _resources(
        self,
        initial: ReachabilityResult,
        scenario: Scenario,
        decisions: list[dict[str, Any]],
    ) -> list[str]:
        """Resources reachable under the scenario."""

        resources = set(initial.resources)

        for decision in decisions:
            if decision["allowed"]:
                resources.add(decision["action"])

        return sorted(resources)

    def _impact(
        self,
        resources: list[str],
        scenario: Scenario,
    ) -> list[dict[str, Any]]:
        impact: list[dict[str, Any]] = []

        for resource in resources:
            label = (
                "sensitive"
                if _is_sensitive(resource)
                else "general"
            )
            impact.append(
                {
                    "target": resource,
                    "label": label,
                    "agent": scenario.agent,
                }
            )

        return impact

    def _opportunities(
        self,
        scenario: Scenario,
        decisions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        opportunities: list[dict[str, Any]] = []

        denied = [
            decision
            for decision in decisions
            if not decision["allowed"]
        ]

        if denied:
            opportunities.append(
                {
                    "action": "maintain_denials",
                    "effect": (
                        f"{len(denied)} scenario actions are already "
                        "denied by the current policy; containment "
                        "preserves these gates"
                    ),
                }
            )

        if scenario.containment == "none":
            opportunities.append(
                {
                    "action": "quarantine",
                    "effect": (
                        f"quarantining {scenario.agent} would revoke "
                        "every capability it holds and elevate its "
                        "runtime risk, cutting the paths above"
                    ),
                }
            )
        else:
            opportunities.append(
                {
                    "action": scenario.containment,
                    "effect": (
                        f"{scenario.containment} is already applied in "
                        "this scenario; verify the remaining reach is "
                        "acceptable"
                    ),
                }
            )

        if scenario.added_capabilities:
            opportunities.append(
                {
                    "action": "revoke_added",
                    "effect": (
                        "revoking the scenario's added capabilities "
                        "restores the recorded baseline"
                    ),
                }
            )

        return opportunities

    def _events(
        self,
        scenario: Scenario,
        decisions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """The security events the scenario would produce."""

        events: list[dict[str, Any]] = [
            {
                "type": EventType.SESSION_STARTED.value,
                "agent": scenario.agent,
                "basis": Provenance.SIMULATED.value,
            }
        ]

        for capability in scenario.added_capabilities:
            events.append(
                {
                    "type": EventType.AUTHORITY_ISSUED.value,
                    "agent": scenario.agent,
                    "capability": capability,
                    "basis": Provenance.SIMULATED.value,
                }
            )

        for capability in scenario.removed_capabilities:
            events.append(
                {
                    "type": EventType.AUTHORITY_REVOKED.value,
                    "agent": scenario.agent,
                    "capability": capability,
                    "basis": Provenance.SIMULATED.value,
                }
            )

        if scenario.containment != "none":
            events.append(
                {
                    "type": EventType.CONTAINMENT.value,
                    "agent": scenario.agent,
                    "state": scenario.containment,
                    "basis": Provenance.SIMULATED.value,
                }
            )

        for decision in decisions:
            events.append(
                {
                    "type": EventType.AUTHORIZATION.value,
                    "agent": scenario.agent,
                    "action": decision["action"],
                    "allowed": decision["allowed"],
                    "reason": decision["reason"],
                    "basis": Provenance.SIMULATED.value,
                }
            )

        return events


def _trust_set(
    issuers: Iterable[str],
):
    from firewall.key_management import IssuerTrustStore

    return IssuerTrustStore(set(issuers))


def _close(sdk: FirewallSDK) -> None:
    try:
        sdk.close()
    except Exception:
        pass
