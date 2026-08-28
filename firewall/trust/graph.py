"""v2.0 Cross-Agent Trust Graph (firewall.trust).

Extends the v1.9 network graph with trust-centric queries and danger
detection:

* ``who_delegated(agent)`` -- who granted this agent authority,
* ``what_changed(agent)`` -- recorded authority changes over time,
* ``blast_radius(agent)`` -- what a compromised agent could reach,
  derived from recorded authority,
* privilege-escalation / dangerous-delegation / excessive-authority
  detection.

Everything derives from verified artifacts (via the v1.9 graph); this
module only adds queries and derived findings. Reachability is never
exploitability.
"""

from __future__ import annotations

from typing import Any, Optional

from firewall.network import AgentNetworkGraph
from firewall.network.attack_path import AttackPathAnalyzer
from firewall.network.model import (
    EntityType,
    Provenance,
    RelationType,
    entity_id,
)


class TrustError(ValueError):
    """Raised for an invalid trust query."""


#: Capability names treated as high-privilege by the excessive-authority
#: heuristic. This is a heuristic; it is labeled ``inferred``.
HIGH_PRIVILEGE_MARKERS = (
    "admin",
    "root",
    "bypass",
    "sudo",
    "superuser",
    "impersonate",
    "credential",
    "secret",
)


class TrustGraph:
    """Trust-centric queries over an :class:`AgentNetworkGraph`."""

    def __init__(
        self,
        graph: AgentNetworkGraph,
    ) -> None:
        if not isinstance(graph, AgentNetworkGraph):
            raise TrustError("graph must be an AgentNetworkGraph")
        self._graph = graph

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def what_can(
        self,
        agent: str,
    ) -> dict[str, Any]:
        return self._graph.reachable(agent).to_dict()

    def who_can(
        self,
        resource: str,
    ) -> list[dict[str, Any]]:
        return self._graph.who_can_reach(resource)

    def who_delegated(
        self,
        agent: str,
    ) -> list[dict[str, Any]]:
        """Who granted this agent authority (issued/delegated edges
        pointing into the agent's node)."""

        agent_node = entity_id(EntityType.AGENT, agent)

        if self._graph.node(agent_node) is None:
            return []

        results: list[dict[str, Any]] = []

        for edge in self._graph.edges():
            if edge.target != agent_node:
                continue

            if edge.type not in (
                RelationType.ISSUED.value,
                RelationType.DELEGATED.value,
            ):
                continue

            source = self._graph.node(edge.source)

            results.append(
                {
                    "grantor": (
                        source.label
                        if source is not None
                        else edge.source
                    ),
                    "relation": edge.type,
                    "evidence": [
                        ref.to_dict() for ref in edge.evidence
                    ],
                    "basis": edge.basis.value,
                }
            )

        return results

    def what_changed(
        self,
        agent: str,
    ) -> list[dict[str, Any]]:
        """Recorded authority changes involving this agent."""

        agent_node = entity_id(EntityType.AGENT, agent)

        changes: list[dict[str, Any]] = []

        for edge in self._graph.edges():
            if (
                edge.source != agent_node
                and edge.target != agent_node
            ):
                continue

            if edge.type not in (
                RelationType.ISSUED.value,
                RelationType.DELEGATED.value,
                RelationType.ATTENUATED.value,
                RelationType.REVOKED.value,
            ):
                continue

            target = self._graph.node(edge.target)
            source = self._graph.node(edge.source)

            changes.append(
                {
                    "relation": edge.type,
                    "other": (
                        target.label if target is not None else edge.target
                    ),
                    "by": (
                        source.label if source is not None else edge.source
                    ),
                    "evidence": [
                        ref.to_dict() for ref in edge.evidence
                    ],
                    "basis": edge.basis.value,
                }
            )

        return sorted(
            changes,
            key=lambda entry: (
                entry["evidence"][0]["event_seq"]
                if entry["evidence"] and entry["evidence"][0].get("event_seq")
                else 0
            ),
        )

    def blast_radius(
        self,
        agent: str,
    ) -> dict[str, Any]:
        """What a compromised agent could reach.

        Derived from recorded authority: capabilities, tools, resources,
        allowed actions. Never presented as what *will* be compromised.
        """

        try:
            reachable = self._graph.reachable(agent)
        except Exception as exc:
            raise TrustError(str(exc)) from exc

        analyzer = AttackPathAnalyzer(self._graph)
        sensitive_targets = []

        for resource in reachable.resources:
            if _is_sensitive(resource):
                sensitive_targets.append(resource)

        return {
            "agent": agent,
            "capabilities": list(reachable.capabilities),
            "tools": list(reachable.tools),
            "resources": list(reachable.resources),
            "allowed_actions": list(reachable.allowed_actions),
            "sensitive_resources": sensitive_targets,
            "derived_from": Provenance.DERIVED.value,
        }

    def path(
        self,
        agent: str,
        target: str,
    ) -> Optional[dict[str, Any]]:
        analyzer = AttackPathAnalyzer(self._graph)
        path = analyzer.shortest_path_to(agent, target)
        return path.to_dict() if path is not None else None

    # ------------------------------------------------------------------
    # Danger detection (heuristics, labeled inferred)
    # ------------------------------------------------------------------

    def find_dangers(
        self,
    ) -> list[dict[str, Any]]:
        """Heuristic findings: privilege escalation paths, dangerous
        delegation, excessive authority, compromised propagation.

        Every finding is labeled ``inferred`` and carries evidence.
        """

        findings: list[dict[str, Any]] = []

        findings.extend(self._excessive_authority())
        findings.extend(self._dangerous_delegation())
        findings.extend(self._privilege_escalation_paths())

        return findings

    def _excessive_authority(
        self,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for node in self._graph.nodes():
            if node.type != EntityType.AGENT:
                continue

            agent = node.label

            try:
                reachable = self._graph.reachable(agent)
            except Exception:
                continue

            dangerous = [
                capability
                for capability in reachable.capabilities
                if any(
                    marker in capability.lower()
                    for marker in HIGH_PRIVILEGE_MARKERS
                )
            ]

            if dangerous:
                findings.append(
                    {
                        "type": "excessive_authority",
                        "agent": agent,
                        "description": (
                            f"{agent} holds high-privilege capabilities: "
                            + ", ".join(dangerous)
                        ),
                        "capabilities": dangerous,
                        "basis": Provenance.INFERRED.value,
                        "evidence": [
                            entry
                            for entry in reachable.path_evidence
                            if entry["entity"] in dangerous
                        ],
                        "response": (
                            "attenuate or revoke the high-privilege "
                            "capabilities not required by the current task"
                        ),
                    }
                )

        return findings

    def _dangerous_delegation(
        self,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for edge in self._graph.edges():
            if edge.type != RelationType.DELEGATED.value:
                continue

            source = self._graph.node(edge.source)
            target = self._graph.node(edge.target)

            if source is None or target is None:
                continue

            if (
                source.type == EntityType.AGENT
                and target.type == EntityType.AGENT
            ):
                # A delegation to an agent with high-privilege reach.
                try:
                    reachable = self._graph.reachable(target.label)
                except Exception:
                    continue

                dangerous = [
                    capability
                    for capability in reachable.capabilities
                    if any(
                        marker in capability.lower()
                        for marker in HIGH_PRIVILEGE_MARKERS
                    )
                ]

                if dangerous:
                    findings.append(
                        {
                            "type": "dangerous_delegation",
                            "delegator": source.label,
                            "delegatee": target.label,
                            "description": (
                                f"{source.label} delegated to "
                                f"{target.label}, who reaches "
                                + ", ".join(dangerous)
                            ),
                            "capabilities": dangerous,
                            "basis": Provenance.INFERRED.value,
                            "evidence": [
                                ref.to_dict()
                                for ref in edge.evidence
                            ],
                            "response": (
                                "review the delegation; attenuate the "
                                "delegatee's reach"
                            ),
                        }
                    )

        return findings

    def _privilege_escalation_paths(
        self,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        analyzer = AttackPathAnalyzer(self._graph)

        for node in self._graph.nodes():
            if node.type != EntityType.AGENT:
                continue

            agent = node.label

            try:
                reachable = self._graph.reachable(agent)
            except Exception:
                continue

            for capability in reachable.capabilities:
                if not any(
                    marker in capability.lower()
                    for marker in HIGH_PRIVILEGE_MARKERS
                ):
                    continue

                path = analyzer.shortest_path_to(agent, capability)

                if path is None:
                    continue

                findings.append(
                    {
                        "type": "privilege_escalation_path",
                        "agent": agent,
                        "target": capability,
                        "description": (
                            f"{agent} has a recorded path to "
                            f"{capability}"
                        ),
                        "hops": len(path.hops),
                        "basis": Provenance.DERIVED.value,
                        "evidence": [
                            hop.to_dict() for hop in path.hops
                        ],
                        "response": (
                            "break the path by revoking or attenuating "
                            "the enabling capability"
                        ),
                    }
                )

        return findings


def _is_sensitive(label: str) -> bool:
    lowered = (label or "").lower()
    return any(
        marker in lowered
        for marker in (
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
    )
