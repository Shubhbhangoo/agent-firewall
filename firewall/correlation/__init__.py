"""v2.2 Multi-Agent Attack Correlation (firewall.correlation).

Extends the intelligence layer to reason about coordinated behavior across
multiple agents. Correlates:
- agents, resources, capabilities, tools
- delegations, identities, credentials
- provenance, timestamps, incidents
- attack paths, trust relationships

Detects suspicious coordinated patterns without promoting inference to observation.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from firewall.adversarial import (
    AdversarialAgentDefense,
    AgentSecurityProfile,
    DiscrepancyType,
    ProvenanceLevel,
    SecuritySignal,
)
from firewall.attackgraph import AttackGraph
from firewall.evidence_graph import EvidenceGraph
from firewall.sdk import FirewallSDK
from firewall.trust import TrustGraph


@dataclass(frozen=True)
class CorrelatedSignal:
    """A signal that has been correlated across multiple agents."""

    primary_signal: SecuritySignal
    related_signals: tuple[SecuritySignal, ...] = ()
    correlation_type: str = ""
    confidence: float = 0.0
    description: str = ""
    agents_involved: tuple[str, ...] = ()
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_signal": self.primary_signal.to_dict(),
            "related_signals": [s.to_dict() for s in self.related_signals],
            "correlation_type": self.correlation_type,
            "confidence": self.confidence,
            "description": self.description,
            "agents_involved": list(self.agents_involved),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CoordinationPattern:
    """A detected coordination pattern across agents."""

    pattern_type: str
    agents: tuple[str, ...]
    description: str
    confidence: float
    evidence: tuple[dict[str, Any], ...] = ()
    attack_graph_paths: tuple[dict[str, Any], ...] = ()
    timestamp: float = 0.0
    provenance: ProvenanceLevel = ProvenanceLevel.INFERRED

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "agents": list(self.agents),
            "description": self.description,
            "confidence": self.confidence,
            "evidence": [dict(e) for e in self.evidence],
            "attack_graph_paths": [dict(p) for p in self.attack_graph_paths],
            "timestamp": self.timestamp,
            "provenance": self.provenance.value,
        }


class MultiAgentCorrelationEngine:
    """
    Correlates security signals across multiple agents to detect
    coordinated attack patterns.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        adversarial_defense: Optional[AdversarialAgentDefense] = None,
        attack_graph: Optional[AttackGraph] = None,
        trust_graph: Optional[TrustGraph] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise TypeError("sdk must be a FirewallSDK")

        self._sdk = sdk
        self._adversarial_defense = adversarial_defense
        self._attack_graph = attack_graph
        self._trust_graph = trust_graph
        self._evidence_graph = evidence_graph
        self._clock = clock or time.time
        self._lock = threading.RLock()

    def correlate(
        self,
        agent_profiles: dict[str, AgentSecurityProfile],
        *,
        time_window: float = 3600.0,  # 1 hour default
        now: Optional[float] = None,
    ) -> tuple[CorrelatedSignal, ...]:
        """
        Correlate signals across agent profiles within a time window.

        Returns correlated signals with explicit provenance.
        """
        timestamp = float(now) if now is not None else float(self._clock())
        cutoff = timestamp - time_window

        # Collect all signals within time window
        all_signals: list[tuple[str, SecuritySignal]] = []
        for agent_id, profile in agent_profiles.items():
            for signal in profile.signals:
                if signal.timestamp >= cutoff:
                    all_signals.append((agent_id, signal))

        correlated: list[CorrelatedSignal] = []

        # 1. Correlate by shared resource access
        correlated.extend(self._correlate_shared_resources(all_signals, timestamp))

        # 2. Correlate by shared compromised tool
        correlated.extend(self._correlate_shared_tool(all_signals, timestamp))

        # 3. Correlate by delegation chain relationships
        correlated.extend(self._correlate_delegation_chains(all_signals, timestamp))

        # 4. Correlate by timing (near-simultaneous events)
        correlated.extend(self._correlate_timing(all_signals, timestamp))

        # 5. Correlate by trust relationships
        correlated.extend(self._correlate_trust_relationships(all_signals, timestamp))

        # 6. Correlate by shared credentials/identities
        correlated.extend(self._correlate_shared_credentials(all_signals, timestamp))

        return tuple(correlated)

    def _correlate_shared_resources(
        self,
        all_signals: list[tuple[str, SecuritySignal]],
        timestamp: float,
    ) -> list[CorrelatedSignal]:
        """Find agents accessing the same sensitive resources."""
        correlated = []

        # Group signals by resource mentioned in metadata
        resource_signals: dict[str, list[tuple[str, SecuritySignal]]] = defaultdict(list)

        for agent_id, signal in all_signals:
            # Check metadata for resource references
            for key, value in signal.metadata.items():
                if key in ("resource", "target", "path", "uri", "url"):
                    if isinstance(value, str):
                        resource_signals[value].append((agent_id, signal))

        for resource, signals in resource_signals.items():
            if len(signals) > 1:
                agents = tuple(s[0] for s in signals)
                primary = signals[0][1]
                related = tuple(s[1] for s in signals[1:])

                # Check if resource is sensitive
                from firewall.attackgraph.engine import is_sensitive
                sensitive = is_sensitive(resource)

                confidence = 0.7 if sensitive else 0.4

                correlated.append(CorrelatedSignal(
                    primary_signal=primary,
                    related_signals=related,
                    correlation_type="shared_resource_access",
                    confidence=confidence,
                    description=f"Multiple agents ({', '.join(agents)}) accessed shared resource: {resource}",
                    agents_involved=agents,
                    timestamp=timestamp,
                ))

        return correlated

    def _correlate_shared_tool(
        self,
        all_signals: list[tuple[str, SecuritySignal]],
        timestamp: float,
    ) -> list[CorrelatedSignal]:
        """Find agents using the same potentially compromised tool."""
        correlated = []

        tool_signals: dict[str, list[tuple[str, SecuritySignal]]] = defaultdict(list)

        for agent_id, signal in all_signals:
            for key, value in signal.metadata.items():
                if key in ("tool", "tool_name", "capability_tool"):
                    if isinstance(value, str):
                        tool_signals[value].append((agent_id, signal))

        for tool, signals in tool_signals.items():
            if len(signals) > 1:
                agents = tuple(s[0] for s in signals)
                primary = signals[0][1]
                related = tuple(s[1] for s in signals[1:])

                correlated.append(CorrelatedSignal(
                    primary_signal=primary,
                    related_signals=related,
                    correlation_type="shared_tool_usage",
                    confidence=0.5,
                    description=f"Multiple agents ({', '.join(agents)}) used shared tool: {tool}",
                    agents_involved=agents,
                    timestamp=timestamp,
                ))

        return correlated

    def _correlate_delegation_chains(
        self,
        all_signals: list[tuple[str, SecuritySignal]],
        timestamp: float,
    ) -> list[CorrelatedSignal]:
        """Find delegation chain relationships between agents with signals."""
        correlated = []

        if not self._attack_graph:
            return correlated

        # Build agent->signal map
        agent_signals: dict[str, list[SecuritySignal]] = defaultdict(list)
        for agent_id, signal in all_signals:
            agent_signals[agent_id].append(signal)

        # Check delegation relationships in attack graph
        for agent_id, signals in agent_signals.items():
            try:
                reachable = self._attack_graph.reachable(agent_id)
                delegated_agents = set()

                # Find agents that this agent delegated to
                for edge in self._attack_graph._outgoing(f"agent:{agent_id}"):
                    if edge.type == "delegates":
                        target_node = self._attack_graph._nodes.get(edge.target)
                        if target_node and target_node.type == "agent":
                            delegated_agents.add(target_node.label)

                # Check if any delegated agent also has signals
                for delegated in delegated_agents:
                    if delegated in agent_signals:
                        primary = signals[0]
                        related = tuple(agent_signals[delegated])

                        correlated.append(CorrelatedSignal(
                            primary_signal=primary,
                            related_signals=related,
                            correlation_type="delegation_chain_correlation",
                            confidence=0.6,
                            description=f"Agent {agent_id} delegated to {delegated}, both have security signals",
                            agents_involved=(agent_id, delegated),
                            timestamp=timestamp,
                        ))
            except Exception:
                pass

        return correlated

    def _correlate_timing(
        self,
        all_signals: list[tuple[str, SecuritySignal]],
        timestamp: float,
    ) -> list[CorrelatedSignal]:
        """Find near-simultaneous security events across agents."""
        correlated = []

        # Sort by timestamp
        sorted_signals = sorted(all_signals, key=lambda x: x[1].timestamp)

        # Group by time buckets (1 minute windows)
        time_buckets: dict[int, list[tuple[str, SecuritySignal]]] = defaultdict(list)
        for agent_id, signal in sorted_signals:
            bucket = int(signal.timestamp // 60)
            time_buckets[bucket].append((agent_id, signal))

        for bucket, signals in time_buckets.items():
            if len(signals) > 1:
                agents = tuple(s[0] for s in signals)
                primary = signals[0][1]
                related = tuple(s[1] for s in signals[1:])

                # Check if they're different agents
                unique_agents = set(agents)
                if len(unique_agents) > 1:
                    time_span = max(s[1].timestamp for s in signals) - min(s[1].timestamp for s in signals)

                    correlated.append(CorrelatedSignal(
                        primary_signal=primary,
                        related_signals=related,
                        correlation_type="temporal_correlation",
                        confidence=min(0.8, 0.3 + (60 - time_span) / 60 * 0.5),
                        description=f"Near-simultaneous security events across agents {', '.join(unique_agents)} within {time_span:.0f}s",
                        agents_involved=tuple(unique_agents),
                        timestamp=timestamp,
                    ))

        return correlated

    def _correlate_trust_relationships(
        self,
        all_signals: list[tuple[str, SecuritySignal]],
        timestamp: float,
    ) -> list[CorrelatedSignal]:
        """Correlate signals with trust graph relationships."""
        correlated = []

        if not self._trust_graph:
            return correlated

        agent_signals: dict[str, list[SecuritySignal]] = defaultdict(list)
        for agent_id, signal in all_signals:
            agent_signals[agent_id].append(signal)

        try:
            # Check trust relationships between agents with signals
            for agent_id in agent_signals:
                trust_info = self._trust_graph.blast_radius(agent_id)
                # This would need proper trust graph integration
                pass
        except Exception:
            pass

        return correlated

    def _correlate_shared_credentials(
        self,
        all_signals: list[tuple[str, SecuritySignal]],
        timestamp: float,
    ) -> list[CorrelatedSignal]:
        """Find agents sharing credentials or identity characteristics."""
        correlated = []

        # Group by key fingerprint
        fingerprint_signals: dict[str, list[tuple[str, SecuritySignal]]] = defaultdict(list)

        for agent_id, signal in all_signals:
            fp = signal.metadata.get("key_fingerprint") or signal.metadata.get("fingerprint")
            if fp:
                fingerprint_signals[fp].append((agent_id, signal))

        for fp, signals in fingerprint_signals.items():
            if len(signals) > 1:
                agents = tuple(s[0] for s in signals)
                if len(set(agents)) > 1:
                    primary = signals[0][1]
                    related = tuple(s[1] for s in signals[1:])

                    correlated.append(CorrelatedSignal(
                        primary_signal=primary,
                        related_signals=related,
                        correlation_type="shared_credential",
                        confidence=0.9,
                        description=f"Multiple agents ({', '.join(agents)}) share key fingerprint: {fp[:16]}...",
                        agents_involved=agents,
                        timestamp=timestamp,
                    ))

        return correlated

    def detect_coordination_patterns(
        self,
        correlated_signals: tuple[CorrelatedSignal, ...],
        *,
        now: Optional[float] = None,
    ) -> tuple[CoordinationPattern, ...]:
        """
        Detect higher-level coordination patterns from correlated signals.
        """
        timestamp = float(now) if now is not None else float(self._clock())
        patterns: list[CoordinationPattern] = []

        # Pattern 1: Capability obtain -> delegate -> access chain
        patterns.extend(self._detect_delegation_chain_pattern(correlated_signals, timestamp))

        # Pattern 2: Multiple agents -> shared resource -> shared tool
        patterns.extend(self._detect_shared_infrastructure_pattern(correlated_signals, timestamp))

        # Pattern 3: Temporal clustering + trust relationship
        patterns.extend(self._detect_temporal_trust_pattern(correlated_signals, timestamp))

        # Pattern 4: Credential sharing + coordinated access
        patterns.extend(self._detect_credential_sharing_pattern(correlated_signals, timestamp))

        return tuple(patterns)

    def _detect_delegation_chain_pattern(
        self,
        correlated_signals: tuple[CorrelatedSignal, ...],
        timestamp: float,
    ) -> list[CoordinationPattern]:
        """Detect A->B->C capability delegation chains with resource access."""
        patterns = []

        # Look for delegation_chain_correlation + shared_resource_access
        delegations = [c for c in correlated_signals if c.correlation_type == "delegation_chain_correlation"]
        resources = [c for c in correlated_signals if c.correlation_type == "shared_resource_access"]

        for dep in delegations:
            for res in resources:
                # Check if agents overlap
                dep_agents = set(dep.agents_involved)
                res_agents = set(res.agents_involved)
                overlap = dep_agents & res_agents

                if overlap:
                    all_agents = tuple(dep_agents | res_agents)
                    patterns.append(CoordinationPattern(
                        pattern_type="delegation_resource_chain",
                        agents=all_agents,
                        description=(
                            f"Delegation chain involving {', '.join(dep_agents)} "
                            f"correlates with shared resource access by {', '.join(res_agents)}"
                        ),
                        confidence=0.6,
                        evidence=[dep.to_dict(), res.to_dict()],
                        timestamp=timestamp,
                        provenance=ProvenanceLevel.INFERRED,
                    ))

        return patterns

    def _detect_shared_infrastructure_pattern(
        self,
        correlated_signals: tuple[CorrelatedSignal, ...],
        timestamp: float,
    ) -> list[CoordinationPattern]:
        """Detect multiple agents sharing both resources and tools."""
        patterns = []

        resources = [c for c in correlated_signals if c.correlation_type == "shared_resource_access"]
        tools = [c for c in correlated_signals if c.correlation_type == "shared_tool_usage"]

        for res in resources:
            for tool in tools:
                res_agents = set(res.agents_involved)
                tool_agents = set(tool.agents_involved)
                overlap = res_agents & tool_agents

                if len(overlap) >= 2:
                    all_agents = tuple(res_agents | tool_agents)
                    patterns.append(CoordinationPattern(
                        pattern_type="shared_infrastructure_coordination",
                        agents=all_agents,
                        description=(
                            f"Agents {', '.join(overlap)} share both resource "
                            f"access and tool usage - potential coordinated campaign"
                        ),
                        confidence=0.7,
                        evidence=[res.to_dict(), tool.to_dict()],
                        timestamp=timestamp,
                        provenance=ProvenanceLevel.INFERRED,
                    ))

        return patterns

    def _detect_temporal_trust_pattern(
        self,
        correlated_signals: tuple[CorrelatedSignal, ...],
        timestamp: float,
    ) -> list[CoordinationPattern]:
        """Detect temporal correlation with trust relationships."""
        patterns = []

        temporal = [c for c in correlated_signals if c.correlation_type == "temporal_correlation"]

        for temp in temporal:
            # If agents in temporal correlation also have trust relationships
            agents = temp.agents_involved
            if len(agents) >= 2 and self._trust_graph:
                try:
                    # Check if there's a trust path between them
                    for i, a1 in enumerate(agents):
                        for a2 in agents[i+1:]:
                            # Simplified check
                            patterns.append(CoordinationPattern(
                                pattern_type="temporal_trust_coordination",
                                agents=agents,
                                description=(
                                    f"Near-simultaneous events between agents {a1} and {a2} "
                                    f"with potential trust relationship"
                                ),
                                confidence=0.5,
                                evidence=[temp.to_dict()],
                                timestamp=timestamp,
                                provenance=ProvenanceLevel.INFERRED,
                            ))
                except Exception:
                    pass

        return patterns

    def _detect_credential_sharing_pattern(
        self,
        correlated_signals: tuple[CorrelatedSignal, ...],
        timestamp: float,
    ) -> list[CoordinationPattern]:
        """Detect credential sharing combined with other correlations."""
        patterns = []

        credentials = [c for c in correlated_signals if c.correlation_type == "shared_credential"]

        for cred in credentials:
            # Look for other correlations involving the same agents
            cred_agents = set(cred.agents_involved)
            other_correlations = [
                c for c in correlated_signals
                if c.correlation_type != "shared_credential"
                and set(c.agents_involved) & cred_agents
            ]

            if other_correlations:
                all_agents = cred_agents
                for c in other_correlations:
                    all_agents |= set(c.agents_involved)

                patterns.append(CoordinationPattern(
                    pattern_type="credential_sharing_with_coordination",
                    agents=tuple(all_agents),
                    description=(
                        f"Credential sharing among {', '.join(cred_agents)} "
                        f"correlates with {len(other_correlations)} other coordination signals"
                    ),
                    confidence=0.8,
                    evidence=[cred.to_dict()] + [c.to_dict() for c in other_correlations[:3]],
                    timestamp=timestamp,
                    provenance=ProvenanceLevel.INFERRED,
                ))

        return patterns