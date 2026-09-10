"""The agent security graph (v1.8).

A relationship graph derived from recorded security history: agents,
capabilities, issuers, tools, resources, sessions, and policies as
nodes; issuance, delegation, attenuation, revocation, use, allow, and
deny as edges. Every node and edge is *derived* from the artifact's
events and carries the event sequence numbers that evidence it.

The graph is a read-only projection. It answers two questions and makes
no authorization decisions of its own:

``why_can(agent, action)``
    The recorded authority paths that let this agent perform this
    action, with the exact events that issued, delegated, and allowed
    it.

``reachable(agent)``
    What this agent could reach, given the authority recorded as issued
    to it, minus what was recorded as revoked.

It deliberately does not decide whether a reachable action *should* be
allowed -- that remains the job of the authorization pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional

from firewall.artifact import validate_manifest
from firewall.recorder.events import EventType, SecurityEvent


class NodeType(str, Enum):
    AGENT = "agent"
    CAPABILITY = "capability"
    ISSUER = "issuer"
    TOOL = "tool"
    RESOURCE = "resource"
    SESSION = "session"
    POLICY = "policy"


class EdgeType(str, Enum):
    ISSUES = "issues"
    DELEGATES = "delegates"
    ATTENUATES = "attenuates"
    REVOKES = "revokes"
    USES = "uses"
    ALLOWED = "allowed"
    DENIED = "denied"
    BOUND_TO = "bound_to"
    BELONGS_TO = "belongs_to"


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    label: str
    first_seq: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "first_seq": self.first_seq,
        }


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    type: str
    seqs: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "seqs": list(self.seqs),
        }


def _node_id(node_type: NodeType, key: str) -> str:
    return f"{node_type.value}:{key}"


class SecurityGraph:
    """Derived, evidence-backed relationship graph for one session."""

    def __init__(
        self,
        nodes: Iterable[GraphNode],
        edges: Iterable[GraphEdge],
        decisions: Optional[dict[int, dict[str, Any]]] = None,
    ) -> None:
        self._nodes: dict[str, GraphNode] = {
            node.id: node for node in nodes
        }
        self._edges: tuple[GraphEdge, ...] = tuple(
            edges
        )
        #: decision_seq -> recorded decision facts (for why_can).
        self._decisions: dict[int, dict[str, Any]] = (
            dict(decisions) if decisions else {}
        )
        #: capability label -> authority events that mention it.
        self._authority: dict[
            str, list[dict[str, Any]]
        ] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_events(
        cls,
        events: Iterable[SecurityEvent],
    ) -> "SecurityGraph":
        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        decisions: dict[int, dict[str, Any]] = {}
        authority: dict[str, list[dict[str, Any]]] = {}

        def add_node(
            node_type: NodeType,
            key: str,
            label: str,
            seq: int,
        ) -> str:
            if key is None or key == "":
                return ""
            node_id = _node_id(node_type, key)
            existing = nodes.get(node_id)
            if existing is None:
                nodes[node_id] = GraphNode(
                    id=node_id,
                    type=node_type.value,
                    label=label,
                    first_seq=seq,
                )
            return node_id

        def add_edge(
            source: str,
            target: str,
            edge_type: EdgeType,
            seq: int,
        ) -> None:
            if not source or not target:
                return
            edges.append(
                GraphEdge(
                    source=source,
                    target=target,
                    type=edge_type.value,
                    seqs=(seq,),
                )
            )

        def note_authority(
            capability: str,
            seq: int,
            kind: str,
            agent: str,
        ) -> None:
            if not capability:
                return
            authority.setdefault(
                capability, []
            ).append(
                {
                    "kind": kind,
                    "seq": seq,
                    "agent": agent,
                }
            )

        for event in events:
            payload = event.payload or {}
            agent = event.agent or payload.get("agent") or "system"

            add_node(
                NodeType.SESSION,
                event.session,
                f"session {event.session}",
                event.seq,
            )

            add_node(
                NodeType.AGENT,
                agent,
                agent,
                event.seq,
            )

            agent_node = _node_id(NodeType.AGENT, agent)
            session_node = _node_id(
                NodeType.SESSION, event.session
            )
            add_edge(
                agent_node,
                session_node,
                EdgeType.BELONGS_TO,
                event.seq,
            )

            event_type = event.type

            if event_type == EventType.AUTHORITY_ISSUED:
                capability = payload.get("capability") or "?"
                issuer = payload.get("issuer") or "?"
                tool = payload.get("tool")

                cap_node = add_node(
                    NodeType.CAPABILITY,
                    capability,
                    capability,
                    event.seq,
                )
                issuer_node = add_node(
                    NodeType.ISSUER,
                    issuer,
                    issuer,
                    event.seq,
                )
                add_edge(
                    issuer_node,
                    cap_node,
                    EdgeType.ISSUES,
                    event.seq,
                )
                add_edge(
                    cap_node,
                    agent_node,
                    EdgeType.ISSUES,
                    event.seq,
                )
                note_authority(
                    capability, event.seq, "issued", agent
                )

                if tool:
                    tool_node = add_node(
                        NodeType.TOOL,
                        tool,
                        tool,
                        event.seq,
                    )
                    add_edge(
                        cap_node,
                        tool_node,
                        EdgeType.BOUND_TO,
                        event.seq,
                    )

            elif event_type == EventType.AUTHORITY_DELEGATED:
                capability = payload.get("capability") or "?"
                delegatee = payload.get("delegatee") or "?"

                cap_node = add_node(
                    NodeType.CAPABILITY,
                    capability,
                    capability,
                    event.seq,
                )
                delegatee_node = add_node(
                    NodeType.AGENT,
                    delegatee,
                    delegatee,
                    event.seq,
                )
                add_edge(
                    agent_node,
                    delegatee_node,
                    EdgeType.DELEGATES,
                    event.seq,
                )
                add_edge(
                    cap_node,
                    delegatee_node,
                    EdgeType.DELEGATES,
                    event.seq,
                )
                note_authority(
                    capability, event.seq, "delegated", delegatee
                )

            elif event_type == EventType.AUTHORITY_ATTENUATED:
                capability = payload.get("capability") or "?"
                cap_node = add_node(
                    NodeType.CAPABILITY,
                    capability,
                    capability,
                    event.seq,
                )
                add_edge(
                    cap_node,
                    agent_node,
                    EdgeType.ATTENUATES,
                    event.seq,
                )
                note_authority(
                    capability, event.seq, "attenuated", agent
                )

            elif event_type == EventType.AUTHORITY_REVOKED:
                capability = payload.get("capability") or "?"
                fingerprint = payload.get("fingerprint") or ""

                cap_key = (
                    capability
                    if capability != "?"
                    else (fingerprint[:12] or "?")
                )
                cap_node = add_node(
                    NodeType.CAPABILITY,
                    cap_key,
                    cap_key,
                    event.seq,
                )
                add_edge(
                    cap_node,
                    agent_node,
                    EdgeType.REVOKES,
                    event.seq,
                )

            elif event_type == EventType.AUTHORIZATION:
                action = payload.get("action") or "?"
                tool = payload.get("tool")
                allowed = bool(payload.get("allowed"))

                add_node(
                    NodeType.CAPABILITY,
                    action,
                    action,
                    event.seq,
                )
                action_node = _node_id(
                    NodeType.CAPABILITY, action
                )

                add_edge(
                    agent_node,
                    action_node,
                    EdgeType.ALLOWED
                    if allowed
                    else EdgeType.DENIED,
                    event.seq,
                )

                if tool:
                    tool_node = add_node(
                        NodeType.TOOL,
                        tool,
                        tool,
                        event.seq,
                    )
                    add_edge(
                        agent_node,
                        tool_node,
                        EdgeType.USES,
                        event.seq,
                    )

                decisions[event.seq] = {
                    "agent": agent,
                    "action": action,
                    "allowed": allowed,
                    "reason": payload.get("reason"),
                    "capability": payload.get("capability"),
                    "issuer": payload.get("issuer"),
                    "tool": tool,
                    "chain": payload.get("chain"),
                    "request": payload.get("request"),
                }

            elif event_type == EventType.POLICY_ACTIVE:
                policy = payload.get("policy") or payload.get(
                    "name"
                ) or "?"
                policy_node = add_node(
                    NodeType.POLICY,
                    policy,
                    policy,
                    event.seq,
                )
                add_edge(
                    policy_node,
                    agent_node,
                    EdgeType.BELONGS_TO,
                    event.seq,
                )

        graph = cls(
            nodes.values(),
            edges,
            decisions=decisions,
        )
        graph._authority = authority
        return graph

    @classmethod
    def from_artifact(
        cls,
        artifact: dict[str, Any],
    ) -> "SecurityGraph":
        validate_manifest(artifact)

        events = [
            SecurityEvent.from_dict(entry)
            for entry in artifact.get("events", [])
            if isinstance(entry, dict)
        ]

        return cls.from_events(events)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def nodes(self) -> tuple[GraphNode, ...]:
        return tuple(
            self._nodes[key]
            for key in sorted(self._nodes)
        )

    def edges(self) -> tuple[GraphEdge, ...]:
        return self._edges

    def node(
        self,
        node_id: str,
    ) -> Optional[GraphNode]:
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
    # Queries
    # ------------------------------------------------------------------

    def why_can(
        self,
        agent: str,
        action: str,
    ) -> list[dict[str, Any]]:
        """Recorded reasons this agent could perform ``action``.

        Each result is one observed authorization decision plus the
        authority trail recorded for it: the issuer that granted the
        capability, the capability itself, and every agent in the chain
        that carried it.
        """

        results: list[dict[str, Any]] = []

        for seq in sorted(self._decisions):
            decision = self._decisions[seq]

            if (
                decision.get("agent") != agent
                or decision.get("action") != action
                or not decision.get("allowed")
            ):
                continue

            capability = decision.get("capability") or action
            issuer = decision.get("issuer") or "?"

            authority_events = self._authority.get(
                capability, []
            )

            chain = decision.get("chain") or []

            path: list[dict[str, Any]] = [
                {
                    "role": "issuer",
                    "label": issuer,
                    "node": _node_id(NodeType.ISSUER, issuer),
                    "evidence": [
                        entry["seq"]
                        for entry in authority_events
                        if entry["kind"] == "issued"
                    ],
                },
                {
                    "role": "capability",
                    "label": capability,
                    "node": _node_id(
                        NodeType.CAPABILITY, capability
                    ),
                    "evidence": [
                        entry["seq"]
                        for entry in authority_events
                    ],
                },
            ]

            for member in chain:
                member_agent = member.get("agent") if isinstance(
                    member, dict
                ) else None

                if not member_agent:
                    continue

                path.append(
                    {
                        "role": "chain_member",
                        "label": member_agent,
                        "node": _node_id(
                            NodeType.AGENT, member_agent
                        ),
                        "evidence": [
                            entry["seq"]
                            for entry in authority_events
                            if entry["agent"] == member_agent
                        ],
                    }
                )

            path.append(
                {
                    "role": "decision",
                    "label": action,
                    "node": _node_id(
                        NodeType.CAPABILITY, action
                    ),
                    "evidence": [seq],
                }
            )

            results.append(
                {
                    "agent": agent,
                    "action": action,
                    "decision_seq": seq,
                    "allowed": True,
                    "reason": decision.get("reason"),
                    "capability": capability,
                    "path": path,
                }
            )

        return results

    def reachable(
        self,
        agent: str,
    ) -> dict[str, Any]:
        """What this agent could reach, per recorded evidence.

        Combines every capability recorded as issued to or delegated to
        the agent with every action the agent was recorded as allowed to
        perform, minus capabilities recorded as revoked.
        """

        agent_node = _node_id(NodeType.AGENT, agent)

        issued: set[str] = set()
        revoked: set[str] = set()
        allowed_actions: set[str] = set()
        denied_actions: set[str] = set()

        for edge in self._edges:
            if edge.type == EdgeType.ISSUES.value:
                if edge.target == agent_node:
                    issued.add(edge.source)
                elif edge.source == agent_node:
                    issued.add(edge.target)
            elif edge.type == EdgeType.DELEGATES.value:
                if edge.target == agent_node:
                    issued.add(edge.source)
                elif edge.source == agent_node:
                    issued.add(edge.target)
            elif edge.type == EdgeType.REVOKES.value:
                if edge.target == agent_node:
                    revoked.add(edge.source)
            elif edge.type == EdgeType.ALLOWED.value:
                if edge.source == agent_node:
                    allowed_actions.add(edge.target)
            elif edge.type == EdgeType.DENIED.value:
                if edge.source == agent_node:
                    denied_actions.add(edge.target)

        def label_of(node_id: str) -> str:
            node = self._nodes.get(node_id)
            return node.label if node else node_id

        reachable_capabilities = sorted(
            issued - revoked
        )

        return {
            "agent": agent,
            "capabilities": [
                label_of(cap)
                for cap in reachable_capabilities
            ],
            "allowed_actions": sorted(
                label_of(action) for action in allowed_actions
            ),
            "denied_actions": sorted(
                label_of(action) for action in denied_actions
            ),
            "revoked_capabilities": sorted(
                label_of(cap) for cap in revoked
            ),
            "derived_from": "recorded_authority_and_decisions",
        }
