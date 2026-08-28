"""The Agent Security Network graph (v1.9).

A :class:`AgentNetworkGraph` merges evidence from many artifacts into a
single, cross-agent relationship graph. It is the evolution of the v1.8
per-session :class:`~firewall.timeline.graph.SecurityGraph`: same
discipline -- every node and edge is evidence-backed and carries a
provenance ``basis`` -- but now spanning sessions, agents, and
environments.

Bases are never conflated:

* graph *extraction* from artifacts produces ``observed`` nodes/edges;
* *queries* (reachability, paths, who-can-reach) produce ``derived``
  answers computed deterministically from observed facts, each carrying
  the evidence chain that supports it;
* nothing here *infers* or *simulates* -- those bases come from the
  behavior engine and the simulator, which add their own clearly-labeled
  nodes/edges.

The graph is read-only with respect to authorization. It answers
questions about recorded and derived capability; it never decides
whether an action should be allowed. That remains the authorization
pipeline's job.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from firewall.artifact import ArtifactError, artifact_from_path
from firewall.network.model import (
    EntityType,
    EvidenceRef,
    NetworkEdge,
    NetworkNode,
    Provenance,
    RelationType,
    entity_id,
)
from firewall.recorder.events import EventType, SecurityEvent
from firewall.verify import verify_artifact


class NetworkError(ValueError):
    """Raised for a malformed network query or ingest."""


@dataclass(frozen=True)
class ReachabilityResult:
    """A derived answer to "what can this agent reach?"."""

    agent: str
    capabilities: tuple[str, ...]
    tools: tuple[str, ...]
    resources: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    path_evidence: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "capabilities": list(self.capabilities),
            "tools": list(self.tools),
            "resources": list(self.resources),
            "allowed_actions": list(self.allowed_actions),
            "path_evidence": [
                dict(entry) for entry in self.path_evidence
            ],
            "basis": Provenance.DERIVED.value,
        }


def extract_network_entities(
    artifact: dict[str, Any],
    *,
    artifact_id: Optional[str] = None,
) -> tuple[list[NetworkNode], list[NetworkEdge]]:
    """Turn one verified artifact into observed network nodes/edges.

    ``artifact_id`` defaults to the artifact's session id. Each node and
    edge carries ``observed`` provenance and an :class:`EvidenceRef` to
    the artifact + event sequence that supports it.
    """

    if artifact_id is None:
        artifact_id = str(
            artifact.get("session", {}).get("id", "artifact")
        )

    nodes: dict[str, NetworkNode] = {}
    edges: list[NetworkEdge] = []

    def add_node(
        entity_type: EntityType,
        key: str,
        label: Optional[str] = None,
        seq: Optional[int] = None,
        attributes: Optional[dict[str, Any]] = None,
    ) -> Optional[str]:
        if not isinstance(key, str) or not key.strip():
            return None
        node_id = entity_id(entity_type, key)
        existing = nodes.get(node_id)
        if existing is None:
            nodes[node_id] = NetworkNode(
                id=node_id,
                type=entity_type,
                label=label if label is not None else key,
                basis=Provenance.OBSERVED,
                evidence=(
                    (
                        EvidenceRef(
                            artifact_id=artifact_id,
                            event_seq=seq,
                        ),
                    )
                    if seq is not None
                    else ()
                ),
                attributes=dict(attributes or {}),
            )
        return node_id

    def add_edge(
        source: str,
        target: str,
        relation: RelationType,
        seq: Optional[int] = None,
        attributes: Optional[dict[str, Any]] = None,
    ) -> None:
        if not source or not target:
            return
        edges.append(
            NetworkEdge(
                source=source,
                target=target,
                type=relation,
                basis=Provenance.OBSERVED,
                evidence=(
                    (
                        EvidenceRef(
                            artifact_id=artifact_id,
                            event_seq=seq,
                        ),
                    )
                    if seq is not None
                    else ()
                ),
                attributes=dict(attributes or {}),
            )
        )

    raw_events = artifact.get("events", [])
    if not isinstance(raw_events, list):
        return [], []

    for entry in raw_events:
        if not isinstance(entry, dict):
            continue

        try:
            event = SecurityEvent.from_dict(entry)
        except Exception:
            # A malformed event is a verifier problem; extraction skips
            # it and the network never fabricates a fact from it.
            continue

        payload = event.payload or {}
        agent = event.agent or payload.get("agent") or "system"
        seq = event.seq

        agent_node = add_node(
            EntityType.AGENT,
            agent,
            seq=seq,
        )

        session_node = add_node(
            EntityType.SESSION,
            event.session,
            label=f"session {event.session}",
            seq=seq,
        )

        if agent_node and session_node:
            add_edge(
                agent_node,
                session_node,
                RelationType.BELONGS_TO,
                seq,
            )

        if event.type == EventType.AUTHORITY_ISSUED:
            capability = payload.get("capability")
            issuer = payload.get("issuer")
            tool = payload.get("tool")

            cap_node = add_node(
                EntityType.CAPABILITY,
                capability,
                seq=seq,
            )
            issuer_node = add_node(
                EntityType.TRUST_BOUNDARY,
                issuer,
                label=f"issuer {issuer}",
                seq=seq,
            )

            if cap_node and agent_node:
                add_edge(
                    issuer_node or agent_node,
                    cap_node,
                    RelationType.ISSUED,
                    seq,
                )
                add_edge(
                    cap_node,
                    agent_node,
                    RelationType.ISSUED,
                    seq,
                )

            if tool and cap_node:
                tool_node = add_node(
                    EntityType.TOOL,
                    tool,
                    seq=seq,
                )
                if tool_node:
                    add_edge(
                        cap_node,
                        tool_node,
                        RelationType.BOUND_TO,
                        seq,
                    )

        elif event.type == EventType.AUTHORITY_DELEGATED:
            capability = payload.get("capability")
            delegatee = payload.get("delegatee")

            cap_node = add_node(
                EntityType.CAPABILITY,
                capability,
                seq=seq,
            )
            delegatee_node = add_node(
                EntityType.AGENT,
                delegatee,
                seq=seq,
            )

            if agent_node and delegatee_node:
                add_edge(
                    agent_node,
                    delegatee_node,
                    RelationType.DELEGATED,
                    seq,
                )
            if cap_node and delegatee_node:
                add_edge(
                    cap_node,
                    delegatee_node,
                    RelationType.DELEGATED,
                    seq,
                )

        elif event.type == EventType.AUTHORITY_ATTENUATED:
            capability = payload.get("capability")
            cap_node = add_node(
                EntityType.CAPABILITY,
                capability,
                seq=seq,
            )
            if cap_node and agent_node:
                add_edge(
                    cap_node,
                    agent_node,
                    RelationType.ATTENUATED,
                    seq,
                )

        elif event.type == EventType.AUTHORITY_REVOKED:
            capability = payload.get("capability")
            fingerprint = payload.get("fingerprint")

            cap_key = capability or fingerprint or "?"
            cap_node = add_node(
                EntityType.CAPABILITY,
                cap_key,
                seq=seq,
            )
            if cap_node and agent_node:
                add_edge(
                    cap_node,
                    agent_node,
                    RelationType.REVOKED,
                    seq,
                )

        elif event.type == EventType.AUTHORIZATION:
            action = payload.get("action") or "?"
            tool = payload.get("tool")
            allowed = bool(payload.get("allowed"))

            action_node = add_node(
                EntityType.CAPABILITY,
                action,
                label=action,
                seq=seq,
            )

            if agent_node and action_node:
                add_edge(
                    agent_node,
                    action_node,
                    RelationType.ALLOWED
                    if allowed
                    else RelationType.DENIED,
                    seq,
                    attributes={
                        "reason": payload.get("reason"),
                    },
                )

            if tool and agent_node:
                tool_node = add_node(
                    EntityType.TOOL,
                    tool,
                    seq=seq,
                )
                if tool_node:
                    add_edge(
                        agent_node,
                        tool_node,
                        RelationType.USES,
                        seq,
                    )

            resource = _resource_of(payload)
            if resource and agent_node:
                resource_node = add_node(
                    EntityType.RESOURCE,
                    resource,
                    seq=seq,
                )
                if resource_node:
                    add_edge(
                        agent_node,
                        resource_node,
                        RelationType.ACCESSES,
                        seq,
                        attributes={
                            "allowed": allowed,
                        },
                    )

        elif event.type == EventType.POLICY_ACTIVE:
            policy = payload.get("policy") or payload.get(
                "name"
            ) or "?"
            policy_node = add_node(
                EntityType.POLICY,
                policy,
                seq=seq,
            )
            if policy_node and agent_node:
                add_edge(
                    policy_node,
                    agent_node,
                    RelationType.BELONGS_TO,
                    seq,
                )

        elif event.type == EventType.CONTAINMENT:
            state = payload.get("state") or "?"
            if agent_node:
                add_edge(
                    agent_node,
                    agent_node,
                    RelationType.ASSOCIATED_WITH,
                    seq,
                    attributes={"containment": state},
                )

    return list(nodes.values()), edges


def _resource_of(payload: dict[str, Any]) -> Optional[str]:
    """A best-effort resource projection from an authorization payload.

    Only deterministic, material keys are considered. Returns ``None``
    when nothing looks like a resource, so the network never fabricates
    one from free text.
    """

    request = payload.get("request")

    if isinstance(request, dict):
        for key in ("resource", "path", "resource_id", "url", "uri"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:120]
        for key in ("path_prefix", "namespace"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:120]

    return None


class AgentNetworkGraph:
    """Merged, evidence-backed network graph across artifacts."""

    def __init__(
        self,
        nodes: Iterable[NetworkNode] = (),
        edges: Iterable[NetworkEdge] = (),
    ) -> None:
        self._nodes: dict[str, NetworkNode] = {}
        self._edges: list[NetworkEdge] = []

        for node in nodes:
            self._nodes[node.id] = node

        self._edges.extend(edges)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_artifacts(
        cls,
        artifacts: Iterable[dict[str, Any]],
        *,
        verify: bool = True,
    ) -> "AgentNetworkGraph":
        """Merge verified artifacts into one network.

        ``verify=True`` (default) runs the independent verifier on each
        artifact and **refuses to ingest a failed artifact**: an
        artifact with broken integrity must never contribute facts to
        the network. Unverifiable or incomplete artifacts raise
        :class:`NetworkError` so the caller decides how to proceed.
        """

        graph = cls()

        for artifact in artifacts:
            if verify:
                report = verify_artifact(artifact)
                if report.status in ("failed", "unverifiable"):
                    raise NetworkError(
                        f"refusing to ingest artifact "
                        f"{artifact.get('session', {}).get('id')}: "
                        f"verification status is {report.status}"
                    )

            nodes, edges = extract_network_entities(artifact)

            for node in nodes:
                graph._nodes[node.id] = node

            graph._edges.extend(edges)

        return graph

    @classmethod
    def from_paths(
        cls,
        paths: Iterable[str],
    ) -> "AgentNetworkGraph":
        """Load and verify artifacts from disk, then merge them."""

        artifacts = []

        for path in paths:
            try:
                artifacts.append(artifact_from_path(path))
            except ArtifactError as exc:
                raise NetworkError(
                    f"cannot read artifact {path}: {exc}"
                ) from exc

        return cls.from_artifacts(artifacts)

    def add_inferred(
        self,
        node: NetworkNode,
    ) -> None:
        """Add a clearly-labeled inferred node (from the behavior
        engine or simulator). Never called with observed content."""

        if node.basis not in (
            Provenance.INFERRED,
            Provenance.SIMULATED,
        ):
            raise NetworkError(
                "only inferred or simulated nodes can be added "
                "post-ingest"
            )
        self._nodes[node.id] = node

    def add_inferred_edge(
        self,
        edge: NetworkEdge,
    ) -> None:
        if edge.basis not in (
            Provenance.INFERRED,
            Provenance.SIMULATED,
        ):
            raise NetworkError(
                "only inferred or simulated edges can be added "
                "post-ingest"
            )
        self._edges.append(edge)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def nodes(self) -> tuple[NetworkNode, ...]:
        return tuple(
            self._nodes[key]
            for key in sorted(self._nodes)
        )

    def edges(self) -> tuple[NetworkEdge, ...]:
        return tuple(self._edges)

    def node(self, node_id: str) -> Optional[NetworkNode]:
        return self._nodes.get(node_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                node.to_dict() for node in self.nodes()
            ],
            "edges": [
                edge.to_dict() for edge in self.edges()
            ],
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _outgoing(
        self,
        node_id: str,
    ) -> list[NetworkEdge]:
        return [
            edge
            for edge in self._edges
            if edge.source == node_id
        ]

    def _incoming(
        self,
        node_id: str,
    ) -> list[NetworkEdge]:
        return [
            edge
            for edge in self._edges
            if edge.target == node_id
        ]

    def _agents(self) -> list[str]:
        return sorted(
            {
                node.label
                for node in self._nodes.values()
                if node.type == EntityType.AGENT
            }
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def reachable(
        self,
        agent: str,
    ) -> ReachabilityResult:
        """Derived answer: what can this agent reach?

        BFS over issued/delegated/allowed/bound edges from the agent,
        honoring revoked capabilities. Capability edges (issued,
        delegated, attenuated) point *into* the agent, so the traversal
        follows them in reverse as well as ordinary outgoing edges.
        Every reachable item is ``derived`` from observed edges, and the
        returned evidence includes the recorded relationships.
        """

        start = entity_id(EntityType.AGENT, agent)

        if start not in self._nodes:
            raise NetworkError(
                f"unknown agent: {agent}"
            )

        capabilities: set[str] = set()
        tools: set[str] = set()
        resources: set[str] = set()
        allowed_actions: set[str] = set()
        revoked: set[str] = set()

        # First pass: collect revocations to exclude them.
        for edge in self._edges:
            if (
                edge.type == RelationType.REVOKED
                and edge.target == start
            ):
                revoked.add(edge.source)

        seen_edges: set[tuple[str, str, str]] = set()
        queue: deque[str] = deque([start])
        visited: set[str] = {start}

        def label(node_id: str) -> str:
            node = self._nodes.get(node_id)
            return node.label if node else node_id

        def process(current: str) -> None:
            node = self._nodes.get(current)

            # 1. Capabilities held by this node: issued/delegated/
            #    attenuated edges from capability nodes point INTO it.
            for edge in self._incoming(current):
                key = (edge.source, edge.target, edge.type.value)
                if key in seen_edges:
                    continue
                seen_edges.add(key)

                source_node = self._nodes.get(edge.source)

                if source_node is None:
                    continue

                if edge.type in (
                    RelationType.ISSUED,
                    RelationType.DELEGATED,
                    RelationType.ATTENUATED,
                ) and source_node.type == EntityType.CAPABILITY:
                    if edge.source not in revoked:
                        capabilities.add(source_node.label)
                        if edge.source not in visited:
                            visited.add(edge.source)
                            queue.append(edge.source)
                    continue

                if edge.type == RelationType.REVOKED:
                    continue

            # 2. Ordinary outgoing edges.
            for edge in self._outgoing(current):
                key = (edge.source, edge.target, edge.type.value)
                if key in seen_edges:
                    continue
                seen_edges.add(key)

                target_node = self._nodes.get(edge.target)

                if target_node is None:
                    continue

                if edge.type == RelationType.ALLOWED:
                    allowed_actions.add(target_node.label)

                elif edge.type == RelationType.USES:
                    tools.add(target_node.label)

                elif edge.type == RelationType.ACCESSES:
                    resources.add(target_node.label)

                elif edge.type == RelationType.BOUND_TO:
                    if edge.target not in visited:
                        visited.add(edge.target)
                        queue.append(edge.target)

                elif edge.type == RelationType.DELEGATED:
                    if edge.target not in visited:
                        visited.add(edge.target)
                        queue.append(edge.target)

        while queue:
            process(queue.popleft())

        path_evidence = []

        for node in self._nodes.values():
            if (
                node.type in (
                    EntityType.CAPABILITY,
                    EntityType.TOOL,
                    EntityType.RESOURCE,
                )
                and node.evidence
            ):
                path_evidence.append(
                    {
                        "entity": node.label,
                        "evidence": [
                            ref.to_dict() for ref in node.evidence
                        ],
                    }
                )

        return ReachabilityResult(
            agent=agent,
            capabilities=tuple(sorted(capabilities)),
            tools=tuple(sorted(tools)),
            resources=tuple(sorted(resources)),
            allowed_actions=tuple(sorted(allowed_actions)),
            path_evidence=tuple(path_evidence),
        )

    def why_can(
        self,
        agent: str,
        action: str,
    ) -> list[dict[str, Any]]:
        """Observed + derived reasons this agent could do ``action``.

        Returns the recorded allow edges for (agent, action) plus the
        authority path (issuance/delegation) recorded as backing them.
        """

        agent_node = entity_id(EntityType.AGENT, agent)
        action_node = entity_id(EntityType.CAPABILITY, action)

        results: list[dict[str, Any]] = []

        for edge in self._edges:
            if (
                edge.source == agent_node
                and edge.target == action_node
                and edge.type == RelationType.ALLOWED
            ):
                # Build the authority trail: how did this agent get the
                # capability that maps to this action?
                trail = self._authority_trail(
                    agent_node,
                    edge.evidence,
                )
                results.append(
                    {
                        "agent": agent,
                        "action": action,
                        "allowed": True,
                        "reason": edge.attributes.get(
                            "reason"
                        ),
                        "evidence": [
                            ref.to_dict() for ref in edge.evidence
                        ],
                        "authority_trail": trail,
                        "basis": Provenance.OBSERVED.value,
                    }
                )

        return results

    def who_can_reach(
        self,
        resource: str,
    ) -> list[dict[str, Any]]:
        """Which agents can reach a resource (reverse derived query)."""

        resource_node = entity_id(EntityType.RESOURCE, resource)

        if resource_node not in self._nodes:
            return []

        result: list[dict[str, Any]] = []

        for agent in self._agents():
            try:
                reachable = self.reachable(agent)
            except NetworkError:
                continue

            if resource in reachable.resources:
                result.append(
                    {
                        "agent": agent,
                        "resource": resource,
                        "evidence": self._path_evidence_for(
                            agent,
                            resource_node,
                        ),
                        "basis": Provenance.DERIVED.value,
                    }
                )

        return result

    def shortest_path(
        self,
        source: str,
        target: str,
    ) -> Optional[dict[str, Any]]:
        """Shortest directed path between two entity ids.

        Returns ``None`` when no path exists. The path is ``derived``
        and every hop carries its recorded evidence.
        """

        if source not in self._nodes or target not in self._nodes:
            return None

        queue: deque[tuple[str, list[dict[str, Any]]]] = deque(
            [(source, [])]
        )
        visited: set[str] = {source}

        while queue:
            current, path = queue.popleft()

            for edge in self._outgoing(current):
                if edge.target in visited:
                    continue

                hop = {
                    "edge": edge.type.value,
                    "from": edge.source,
                    "to": edge.target,
                    "basis": edge.basis.value,
                    "evidence": [
                        ref.to_dict() for ref in edge.evidence
                    ],
                }

                if edge.target == target:
                    return {
                        "path": path + [hop],
                        "hops": len(path) + 1,
                        "basis": Provenance.DERIVED.value,
                    }

                visited.add(edge.target)
                queue.append(
                    (edge.target, path + [hop])
                )

        return None

    def shared_paths(
        self,
        agents: Iterable[str],
        resource: str,
    ) -> list[dict[str, Any]]:
        """Agents among ``agents`` that can all reach ``resource``.

        Answers "which agents share a dangerous path to this resource?".
        """

        agent_list = list(agents)
        resource_node = entity_id(EntityType.RESOURCE, resource)

        if resource_node not in self._nodes:
            return []

        reachable_agents = {
            entry["agent"]
            for entry in self.who_can_reach(resource)
        }

        shared = [
            agent
            for agent in agent_list
            if agent in reachable_agents
        ]

        return [
            {
                "resource": resource,
                "agents": shared,
                "count": len(shared),
                "basis": Provenance.DERIVED.value,
            }
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _authority_trail(
        self,
        agent_node: str,
        evidence: tuple[EvidenceRef, ...],
    ) -> list[dict[str, Any]]:
        """Backwards walk from the agent through issued/delegated edges."""

        trail: list[dict[str, Any]] = []
        queue: deque[str] = deque([agent_node])
        visited: set[str] = set()

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            for edge in self._incoming(current):
                if edge.type not in (
                    RelationType.ISSUED,
                    RelationType.DELEGATED,
                    RelationType.ATTENUATED,
                ):
                    continue

                source_node = self._nodes.get(edge.source)
                if source_node is None:
                    continue

                trail.append(
                    {
                        "relation": edge.type.value,
                        "from": edge.source,
                        "from_label": source_node.label,
                        "to": current,
                        "evidence": [
                            ref.to_dict() for ref in edge.evidence
                        ],
                    }
                )
                queue.append(edge.source)

        return trail

    def _path_evidence_for(
        self,
        agent: str,
        resource_node: str,
    ) -> list[dict[str, Any]]:
        path = self.shortest_path(
            entity_id(EntityType.AGENT, agent),
            resource_node,
        )

        if path is None:
            return []

        return path["path"]
