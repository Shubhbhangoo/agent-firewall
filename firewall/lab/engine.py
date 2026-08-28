"""v2.0 Security Lab 2.0 (firewall.lab).

An automated security laboratory over the network: given verified
artifacts it evaluates the current attack surface, possible attack
paths, authority escalation, delegation abuse, tool and supply-chain
compromise, containment opportunities, and policy weaknesses -- all in
isolated workspaces, never touching live state.

Counterfactual questions are answered by the v1.9 simulator; this
module orchestrates a full lab sweep and an explainable report.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from firewall.network import (
    AgentNetworkGraph,
    AttackPathAnalyzer,
    Scenario,
    Simulator,
)
from firewall.network.model import EntityType
from firewall.trust import TrustGraph


class LabError(ValueError):
    """Raised for an invalid lab request."""


class SecurityLab:
    """Automated security evaluation over a network graph."""

    def __init__(
        self,
        graph: AgentNetworkGraph,
        *,
        provenance=None,
    ) -> None:
        if not isinstance(graph, AgentNetworkGraph):
            raise LabError("graph must be an AgentNetworkGraph")
        self._graph = graph
        self._trust = TrustGraph(graph)
        self._analyzer = AttackPathAnalyzer(graph)
        self._simulator = Simulator(graph)
        self._provenance = provenance

    # ------------------------------------------------------------------
    # Sweep
    # ------------------------------------------------------------------

    def sweep(self) -> dict[str, Any]:
        """Evaluate the whole environment and return a lab report."""

        return {
            "attack_surface": self.attack_surface(),
            "dangers": self._trust.find_dangers(),
            "sensitive_resources": self._analyzer.summarize(),
            "containment_opportunities": self.containment_opportunities(),
            "policy_weaknesses": self.policy_weaknesses(),
            "supply_chain": self.supply_chain(),
            "basis": "derived",
        }

    def attack_surface(self) -> dict[str, Any]:
        """Per-agent reach summary."""

        agents: dict[str, dict[str, Any]] = {}

        for node in self._graph.nodes():
            if node.type != EntityType.AGENT:
                continue

            try:
                reachable = self._graph.reachable(node.label)
                agents[node.label] = {
                    "capabilities": list(reachable.capabilities),
                    "tools": list(reachable.tools),
                    "resources": list(reachable.resources),
                    "allowed_actions": list(reachable.allowed_actions),
                }
            except Exception:
                continue

        return {"agents": agents}

    def containment_opportunities(self) -> list[dict[str, Any]]:
        """High-value containment targets (agents with sensitive reach)."""

        opportunities: list[dict[str, Any]] = []

        for node in self._graph.nodes():
            if node.type != EntityType.AGENT:
                continue

            try:
                radius = self._trust.blast_radius(node.label)
            except Exception:
                continue

            if radius["sensitive_resources"]:
                opportunities.append(
                    {
                        "agent": node.label,
                        "sensitive_resources": radius[
                            "sensitive_resources"
                        ],
                        "action": "quarantine",
                        "effect": (
                            f"quarantining {node.label} cuts its reach "
                            "to "
                            + ", ".join(
                                radius["sensitive_resources"]
                            )
                        ),
                    }
                )

        return opportunities

    def policy_weaknesses(self) -> list[dict[str, Any]]:
        """Heuristic policy gaps: high-privilege reach without recorded
        containment."""

        weaknesses: list[dict[str, Any]] = []

        for node in self._graph.nodes():
            if node.type != EntityType.AGENT:
                continue

            try:
                radius = self._trust.blast_radius(node.label)
            except Exception:
                continue

            if radius["sensitive_resources"] and not radius[
                "capabilities"
            ]:
                weaknesses.append(
                    {
                        "agent": node.label,
                        "description": (
                            f"{node.label} reaches sensitive resources "
                            "with no recorded capability in the network "
                            "(direct resource access)"
                        ),
                        "basis": "inferred",
                    }
                )

        return weaknesses

    def supply_chain(self) -> dict[str, Any]:
        if self._provenance is None:
            return {
                "suspicious": [],
                "note": "no provenance provider attached",
            }

        try:
            suspicious = self._provenance.suspicious()
            return {
                "suspicious": [
                    {
                        "component_id": component.component_id,
                        "kind": component.kind,
                        "name": component.name,
                        "status": component.status,
                    }
                    for component in suspicious
                ],
            }
        except Exception as exc:
            return {
                "suspicious": [],
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Counterfactual questions
    # ------------------------------------------------------------------

    def counterfactual(
        self,
        *,
        agent: str,
        kind: str,
        title: str,
        added_capabilities: Iterable[str] = (),
        removed_capabilities: Iterable[str] = (),
        containment: str = "none",
    ) -> dict[str, Any]:
        scenario = Scenario(
            scenario_id=f"lab-{agent}-{kind}",
            kind=kind,
            title=title,
            agent=agent,
            added_capabilities=tuple(added_capabilities),
            removed_capabilities=tuple(removed_capabilities),
            containment=containment,
        )

        report = self._simulator.simulate(scenario)

        return report.to_dict()

    def tool_compromise(
        self,
        agent: str,
        tool: str,
    ) -> dict[str, Any]:
        """What happens if ``tool`` is compromised for ``agent``?"""

        return self.counterfactual(
            agent=agent,
            kind="additional_tool",
            title=f"{tool} compromised",
            added_capabilities=(tool,),
        )

    def capability_revocation(
        self,
        agent: str,
        capability: str,
    ) -> dict[str, Any]:
        return self.counterfactual(
            agent=agent,
            kind="revoked_capability",
            title=f"revoke {capability}",
            removed_capabilities=(capability,),
        )

    def delegation_expiry(
        self,
        agent: str,
    ) -> dict[str, Any]:
        return self.counterfactual(
            agent=agent,
            kind="changed_policy",
            title="delegation expires",
        )

    def policy_change(
        self,
        agent: str,
        **policy: Any,
    ) -> dict[str, Any]:
        return self.counterfactual(
            agent=agent,
            kind="changed_policy",
            title="policy change",
        )

    def blast_radius(
        self,
        agent: str,
    ) -> dict[str, Any]:
        return self._trust.blast_radius(agent)
