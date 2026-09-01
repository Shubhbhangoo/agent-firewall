"""v2.2 Adversarial Digital Twin 2.0 (firewall.twin2).

Upgrades the digital twin to actively search for security weaknesses:
- Privilege escalation
- Capability combinations
- Delegation abuse
- Trust transitivity
- Compromised agents
- Confused deputy paths
- Revocation bypass
- Provenance poisoning
- Policy conflicts
- Lateral movement
- Multi-agent attack chains

Requirements:
- Bounded search with guaranteed termination
- Deterministic behavior where possible
- Isolated state (no live registry references)
- No production mutation
- Explicit simulated provenance
- Never authorizes operations
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from firewall.attackgraph import (
    AttackGraph,
    AttackPath,
    AttackNode,
    AttackEdge,
    is_sensitive,
)
from firewall.network import AgentNetworkGraph


# Search bounds
MAX_SEARCH_DEPTH = 10
MAX_SEARCH_NODES = 1000
MAX_PATHS_PER_TARGET = 50
SEARCH_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class WeaknessFinding:
    """A security weakness discovered by the adversarial twin."""

    weakness_type: str
    description: str
    severity: str  # low, medium, high, critical
    agents_involved: tuple[str, ...] = ()
    attack_path: Optional[AttackPath] = None
    evidence: tuple[dict[str, Any], ...] = ()
    confidence: float = 0.0
    provenance: str = "simulated"
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "weakness_type": self.weakness_type,
            "description": self.description,
            "severity": self.severity,
            "agents_involved": list(self.agents_involved),
            "attack_path": self.attack_path.to_dict() if self.attack_path else None,
            "evidence": [dict(e) for e in self.evidence],
            "confidence": self.confidence,
            "provenance": self.provenance,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class TwinSearchResult:
    """Result of an adversarial twin search."""

    search_type: str
    target: str
    findings: tuple[WeaknessFinding, ...] = ()
    search_space_explored: int = 0
    search_time: float = 0.0
    terminated_early: bool = False
    termination_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "search_type": self.search_type,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "search_space_explored": self.search_space_explored,
            "search_time": self.search_time,
            "terminated_early": self.terminated_early,
            "termination_reason": self.termination_reason,
        }


class AdversarialDigitalTwin:
    """
    Adversarial digital twin that actively searches for security weaknesses
    in the agent ecosystem through bounded, deterministic simulation.
    """

    def __init__(
        self,
        graph_source: Callable[[], AttackGraph],
        *,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not callable(graph_source):
            raise TypeError("graph_source must be callable")

        self._graph_source = graph_source
        self._clock = clock or time.time
        self._lock = threading.RLock()

    def search_privilege_escalation(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: int = MAX_SEARCH_NODES,
        timeout: float = SEARCH_TIMEOUT_SECONDS,
    ) -> TwinSearchResult:
        """Search for privilege escalation paths from any agent to sensitive resources."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()
        sensitive_resources = [
            node for node in graph._nodes.values()
            if node.type == "resource" and is_sensitive(node.label)
        ]

        for resource in sensitive_resources:
            if self._clock() - start_time > timeout:
                return TwinSearchResult(
                    search_type="privilege_escalation",
                    target=resource.label,
                    findings=tuple(findings),
                    search_space_explored=nodes_explored,
                    search_time=self._clock() - start_time,
                    terminated_early=True,
                    termination_reason="timeout",
                )

            paths = graph.paths_to(
                resource.id,
                max_hops=max_depth,
                max_paths=MAX_PATHS_PER_TARGET,
            )

            for path in paths:
                nodes_explored += len(path.hops)
                if nodes_explored > max_nodes:
                    return TwinSearchResult(
                        search_type="privilege_escalation",
                        target=resource.label,
                        findings=tuple(findings),
                        search_space_explored=nodes_explored,
                        search_time=self._clock() - start_time,
                        terminated_early=True,
                        termination_reason="node_limit",
                    )

                # Analyze path for escalation characteristics
                source_agent = self._extract_source_agent(graph, path)
                if source_agent:
                    severity = self._assess_escalation_severity(path)
                    findings.append(WeaknessFinding(
                        weakness_type="privilege_escalation_path",
                        description=f"Agent {source_agent} can reach sensitive resource {resource.label} via {len(path.hops)} hops",
                        severity=severity,
                        agents_involved=(source_agent,),
                        attack_path=path,
                        evidence=[{"resource": resource.label, "hops": len(path.hops), "basis": path.basis}],
                        confidence=0.7 if path.basis == "observed" else 0.5,
                        remediation=f"Review and attenuate capabilities on path from {source_agent} to {resource.label}",
                    ))

        return TwinSearchResult(
            search_type="privilege_escalation",
            target="all_sensitive_resources",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_capability_combinations(
        self,
        agent: str,
        *,
        max_combos: int = 10,
    ) -> TwinSearchResult:
        """Search for dangerous capability combinations for a specific agent."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()
        combos = graph.capability_combinations(agent, max_combos=max_combos)

        for combo in combos:
            nodes_explored += 1
            findings.append(WeaknessFinding(
                weakness_type="dangerous_capability_combination",
                description=f"Agent {agent}: capabilities {', '.join(combo['labels'])} combine to reach sensitive resources {', '.join(combo['reaches'])}",
                severity="high",
                agents_involved=(agent,),
                evidence=[{
                    "capabilities": combo["labels"],
                    "reaches": combo["reaches"],
                    "note": combo["note"],
                }],
                confidence=0.6,
                remediation=f"Attenuate one or both capabilities: {', '.join(combo['labels'])}",
            ))

        return TwinSearchResult(
            search_type="capability_combinations",
            target=agent,
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_delegation_abuse(self) -> TwinSearchResult:
        """Search for delegation abuse patterns."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()
        abuses = graph.delegation_abuse()

        for abuse in abuses:
            nodes_explored += 1
            agents = abuse.agents
            findings.append(WeaknessFinding(
                weakness_type="delegation_abuse",
                description=abuse.description,
                severity="high",
                agents_involved=agents,
                evidence=[{"grantor": agents[0] if len(agents) > 0 else "", "grantee": agents[1] if len(agents) > 1 else ""}],
                confidence=0.7,
                remediation=abuse.response,
            ))

        return TwinSearchResult(
            search_type="delegation_abuse",
            target="all_agents",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_trust_transitivity(
        self,
        *,
        max_hops: int = 6,
    ) -> TwinSearchResult:
        """Search for dangerous trust transitivity chains."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()
        transitivity = graph.trust_transitivity(max_hops=max_hops)

        for finding in transitivity:
            nodes_explored += 1
            agents = finding.agents
            findings.append(WeaknessFinding(
                weakness_type="trust_transitivity",
                description=finding.description,
                severity="medium",
                agents_involved=agents,
                evidence=[{"chain": " -> ".join(finding.agents) if finding.agents else ""}],
                confidence=0.5,
                remediation=finding.response,
            ))

        return TwinSearchResult(
            search_type="trust_transitivity",
            target="all_agents",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_compromised_agent_impact(
        self,
        agent: str,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
    ) -> TwinSearchResult:
        """Search for impact of a specific agent being compromised."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()
        paths = graph.paths_from_compromised(agent, max_hops=max_depth)

        for path in paths:
            nodes_explored += len(path.hops)
            target_node = graph._nodes.get(path.target)
            target_label = target_node.label if target_node else path.target

            severity = "critical" if is_sensitive(target_label) else "high"
            findings.append(WeaknessFinding(
                weakness_type="compromised_agent_reach",
                description=f"If {agent} is compromised, can reach {target_label} via {len(path.hops)} hops",
                severity=severity,
                agents_involved=(agent,),
                attack_path=path,
                evidence=[{"target": target_label, "hops": len(path.hops), "basis": path.basis}],
                confidence=0.6 if path.basis == "observed" else 0.4,
                remediation=f"Monitor {agent} closely; consider containment if compromise suspected",
            ))

        return TwinSearchResult(
            search_type="compromised_agent_impact",
            target=agent,
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_lateral_movement(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
    ) -> TwinSearchResult:
        """Search for lateral movement paths between agents."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()
        agents = graph.agent_ids()

        for i, agent_a in enumerate(agents):
            for agent_b in agents[i+1:]:
                # Check if A can reach B's capabilities/resources
                paths = graph.paths_to(
                    f"agent:{agent_b}",
                    max_hops=max_depth,
                    max_paths=10,
                    from_agents=[f"agent:{agent_a}"],
                )

                for path in paths:
                    nodes_explored += len(path.hops)
                    if len(path.hops) > 1:  # Direct trust/delegation is expected
                        findings.append(WeaknessFinding(
                            weakness_type="lateral_movement_path",
                            description=f"Agent {agent_a} can laterally move to {agent_b} via {len(path.hops)} hops",
                            severity="high",
                            agents_involved=(agent_a, agent_b),
                            attack_path=path,
                            evidence=[{"source": agent_a, "target": agent_b, "hops": len(path.hops)}],
                            confidence=0.6,
                            remediation=f"Review trust/delegation between {agent_a} and {agent_b}",
                        ))

                if nodes_explored > 500:  # Limit for lateral movement search
                    break

        return TwinSearchResult(
            search_type="lateral_movement",
            target="all_agent_pairs",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_revocation_bypass(
        self,
    ) -> TwinSearchResult:
        """Search for paths that bypass revocation."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()

        # Look for derived_from edges where revoked attribute is not checked
        for edge in graph._edges:
            if edge.type == "derived_from":
                nodes_explored += 1
                if not edge.attributes.get("revoked"):
                    source_node = graph._nodes.get(edge.source)
                    target_node = graph._nodes.get(edge.target)
                    if source_node and target_node:
                        findings.append(WeaknessFinding(
                            weakness_type="revocation_bypass_potential",
                            description=f"Delegation edge {source_node.label} -> {target_node.label} missing revocation check",
                            severity="medium",
                            agents_involved=(),
                            evidence=[{"source": source_node.label, "target": target_node.label, "edge_type": "derived_from"}],
                            confidence=0.4,
                            remediation="Ensure all delegation edges have revoked attribute checked at authorization time",
                        ))

        return TwinSearchResult(
            search_type="revocation_bypass",
            target="all_delegation_edges",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_provenance_poisoning(
        self,
    ) -> TwinSearchResult:
        """Search for provenance poisoning vulnerabilities."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()

        # Look for inferred/simulated edges that could be promoted
        for edge in graph._edges:
            if edge.basis in ("inferred", "simulated"):
                nodes_explored += 1
                findings.append(WeaknessFinding(
                    weakness_type="provenance_weakness",
                    description=f"Edge {edge.source} -> {edge.target} has {edge.basis} basis, could be incorrectly promoted",
                    severity="low",
                    agents_involved=(),
                    evidence=[{"edge": f"{edge.source} -> {edge.target}", "basis": edge.basis}],
                    confidence=0.3,
                    remediation="Ensure explicit promotion with signed attestation for inferred/simulated edges",
                ))

        return TwinSearchResult(
            search_type="provenance_poisoning",
            target="all_edges",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_policy_conflicts(
        self,
    ) -> TwinSearchResult:
        """Search for policy conflicts in the attack graph."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()

        # Check for conflicting policy enforcements
        policy_nodes = [n for n in graph._nodes.values() if n.type == "policy"]

        for i, policy_a in enumerate(policy_nodes):
            for policy_b in policy_nodes[i+1:]:
                nodes_explored += 1
                # Check if they enforce contradictory rules on same agents
                edges_a = [e for e in graph._edges if e.source == policy_a.id and e.type == "enforced_by"]
                edges_b = [e for e in graph._edges if e.source == policy_b.id and e.type == "enforced_by"]

                agents_a = set()
                for edge in edges_a:
                    target = graph._nodes.get(edge.target)
                    if target and target.type == "agent":
                        agents_a.add(target.label)

                agents_b = set()
                for edge in edges_b:
                    target = graph._nodes.get(edge.target)
                    if target and target.type == "agent":
                        agents_b.add(target.label)

                overlap = agents_a & agents_b
                if overlap:
                    findings.append(WeaknessFinding(
                        weakness_type="policy_conflict",
                        description=f"Policies {policy_a.label} and {policy_b.label} both apply to agents: {', '.join(overlap)}",
                        severity="medium",
                        agents_involved=tuple(overlap),
                        evidence=[{"policy_a": policy_a.label, "policy_b": policy_b.label, "shared_agents": list(overlap)}],
                        confidence=0.5,
                        remediation="Review policy precedence and consolidate conflicting rules",
                    ))

        return TwinSearchResult(
            search_type="policy_conflicts",
            target="all_policies",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_confused_deputy(
        self,
    ) -> TwinSearchResult:
        """Search for confused deputy vulnerabilities."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()

        # Look for agents with capabilities that could be misused by other agents
        for edge in graph._edges:
            if edge.type == "holds":
                source = graph._nodes.get(edge.source)
                target = graph._nodes.get(edge.target)
                if source and source.type == "capability" and target and target.type == "agent":
                    # Check if another agent delegates to this agent
                    for dep_edge in graph._edges:
                        if dep_edge.type == "delegates" and dep_edge.target == target.id:
                            nodes_explored += 1
                            dep_source = graph._nodes.get(dep_edge.source)
                            if dep_source and dep_source.type == "agent":
                                findings.append(WeaknessFinding(
                                    weakness_type="confused_deputy_potential",
                                    description=f"Agent {target.label} holds capability {source.label} and receives delegation from {dep_source.label} - potential confused deputy",
                                    severity="medium",
                                    agents_involved=(target.label, dep_source.label),
                                    evidence=[{"capability": source.label, "deputy": target.label, "grantor": dep_source.label}],
                                    confidence=0.4,
                                    remediation="Ensure capabilities are bound to specific agents and not transferable via delegation",
                                ))

        return TwinSearchResult(
            search_type="confused_deputy",
            target="all_agents",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def search_multi_agent_attack_chains(
        self,
        *,
        min_agents: int = 3,
        max_depth: int = MAX_SEARCH_DEPTH,
    ) -> TwinSearchResult:
        """Search for coordinated multi-agent attack chains."""
        start_time = self._clock()
        findings: list[WeaknessFinding] = []
        nodes_explored = 0

        graph = self._graph_source()

        # Look for chains of delegations involving multiple agents
        # A -> B -> C -> ... where each step adds capabilities
        agent_paths: dict[str, list[list[str]]] = {}

        for agent in graph.agent_ids():
            paths = self._find_delegation_chains(graph, agent, max_depth=max_depth)
            if len(paths) >= min_agents - 1:
                agent_paths[agent] = paths

        for agent, paths in agent_paths.items():
            for path in paths:
                nodes_explored += len(path)
                if len(path) >= min_agents:
                    findings.append(WeaknessFinding(
                        weakness_type="multi_agent_attack_chain",
                        description=f"Multi-agent delegation chain: {' -> '.join(path)} ({len(path)} agents)",
                        severity="high",
                        agents_involved=tuple(path),
                        evidence=[{"chain": path, "length": len(path)}],
                        confidence=0.5,
                        remediation=f"Review delegation chain: {' -> '.join(path)}; ensure monotonic narrowing at each step",
                    ))

        return TwinSearchResult(
            search_type="multi_agent_attack_chains",
            target="all_agents",
            findings=tuple(findings),
            search_space_explored=nodes_explored,
            search_time=self._clock() - start_time,
        )

    def _find_delegation_chains(
        self,
        graph: AttackGraph,
        start_agent: str,
        max_depth: int,
    ) -> list[list[str]]:
        """Find all delegation chains starting from an agent."""
        start_node_id = f"agent:{start_agent}"
        if start_node_id not in graph._nodes:
            return []

        chains: list[list[str]] = []
        queue: deque[tuple[str, list[str]]] = deque([(start_node_id, [start_agent])])

        while queue:
            current, path = queue.popleft()
            if len(path) >= max_depth:
                continue

            for edge in graph._outgoing(current):
                if edge.type == "delegates":
                    target = graph._nodes.get(edge.target)
                    if target and target.type == "agent":
                        new_path = path + [target.label]
                        chains.append(new_path)
                        if edge.target not in [f"agent:{p}" for p in path]:  # Avoid cycles
                            queue.append((edge.target, new_path))

        return chains

    def _extract_source_agent(self, graph: AttackGraph, path: AttackPath) -> Optional[str]:
        """Extract the source agent from an attack path."""
        if not path.hops:
            return None

        first_hop = path.hops[0]
        from_node = graph._nodes.get(first_hop["from"])
        if from_node and from_node.type == "agent":
            return from_node.label
        return first_hop.get("from_label", "unknown")

    def _assess_escalation_severity(self, path: AttackPath) -> str:
        """Assess severity of an escalation path."""
        if path.basis == "observed":
            return "critical"
        elif path.basis == "derived":
            return "high"
        elif path.basis == "inferred":
            return "medium"
        else:
            return "low"

    def run_full_adversarial_search(
        self,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        timeout: float = SEARCH_TIMEOUT_SECONDS * 5,
    ) -> dict[str, TwinSearchResult]:
        """Run all adversarial searches."""
        results = {}

        results["privilege_escalation"] = self.search_privilege_escalation(max_depth=max_depth, timeout=timeout)
        results["delegation_abuse"] = self.search_delegation_abuse()
        results["trust_transitivity"] = self.search_trust_transitivity()
        results["revocation_bypass"] = self.search_revocation_bypass()
        results["provenance_poisoning"] = self.search_provenance_poisoning()
        results["policy_conflicts"] = self.search_policy_conflicts()
        results["confused_deputy"] = self.search_confused_deputy()
        results["lateral_movement"] = self.search_lateral_movement(max_depth=max_depth)
        results["multi_agent_chains"] = self.search_multi_agent_attack_chains(max_depth=max_depth)

        return results