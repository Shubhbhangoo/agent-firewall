"""v2.1 Autonomous Attack-Path Engine (firewall.attackgraph).

A continuously evaluated attack graph that models the entities the
v2.0 control plane reasons about - agents, identities, tasks,
authorities, capabilities, tools, resources, delegations, provenance,
policies, trust relationships, and incidents - and automatically
identifies:

* privilege escalation paths,
* capability combinations that create dangerous reachability,
* delegation abuse,
* trust transitivity problems,
* potential blast radius,
* high-risk chokepoints,
* paths from compromised agents to sensitive resources.

Provenance discipline is inherited from the v1.9 network model: every
node and edge carries a ``basis`` and every discovered path reports the
per-hop basis. A path built from recorded facts is ``observed``; a path
that uses computed reachability is ``derived``; heuristic findings are
``inferred``; twin/simulator output is ``simulated``. No path ever
silently promotes a weaker basis to a stronger one - the path ``basis``
is the *weakest* (least trustworthy) hop basis.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

from firewall.network import AgentNetworkGraph
from firewall.network.model import (
    EntityType as NetEntityType,
    Provenance,
    RelationType,
    entity_id,
)
from firewall.trust import TrustGraph

#: Entities the attack graph can model.
ATTACK_NODE_TYPES = (
    "agent",
    "identity",
    "task",
    "authority",
    "capability",
    "tool",
    "resource",
    "delegation",
    "provenance",
    "policy",
    "trust",
    "incident",
)

#: Edge kinds in the attack graph.
ATTACK_EDGE_TYPES = (
    "holds",       # agent -> capability
    "has_identity",  # agent -> identity
    "performs",    # agent -> task
    "bound_to",    # capability -> tool
    "accesses",    # agent/capability -> resource
    "delegates",   # agent -> agent
    "derived_from",  # capability -> capability (attenuation/delegation)
    "trusts",      # agent -> agent (relationship)
    "requires",    # task -> capability
    "enforced_by",  # policy -> agent/capability
    "signed_by",   # authority/identity -> agent
    "affects",     # incident -> agent
    "uses",        # agent -> tool
)

#: Capability/action labels treated as sensitive targets.
SENSITIVE_MARKERS = (
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    "credentials",
    ".aws/",
    "secrets",
    "token",
    "password",
    ".env",
    "keyring",
    "shadow",
    "/etc/",
    "/root/",
    "admin",
    "sudo",
    "root",
)

#: Basis ordering, weakest to strongest. A path's basis is its weakest hop.
_BASIS_RANK = {
    "unknown": 0,
    "simulated": 1,
    "inferred": 2,
    "derived": 3,
    "observed": 4,
}


class AttackGraphError(ValueError):
    """Raised for an invalid attack-graph operation."""


def is_sensitive(label: str) -> bool:
    lowered = (label or "").lower()
    return any(
        marker in lowered for marker in SENSITIVE_MARKERS
    )


@dataclass(frozen=True)
class AttackNode:
    """One entity in the attack graph."""

    id: str
    type: str
    label: str
    basis: str = Provenance.OBSERVED.value
    evidence: tuple[dict[str, Any], ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in ATTACK_NODE_TYPES:
            raise AttackGraphError(f"unknown attack node type: {self.type}")
        if self.basis not in _BASIS_RANK:
            raise AttackGraphError(f"unknown basis: {self.basis}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "basis": self.basis,
            "evidence": [dict(entry) for entry in self.evidence],
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class AttackEdge:
    """One relationship in the attack graph."""

    source: str
    target: str
    type: str
    basis: str = Provenance.OBSERVED.value
    evidence: tuple[dict[str, Any], ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in ATTACK_EDGE_TYPES:
            raise AttackGraphError(f"unknown attack edge type: {self.type}")
        if self.basis not in _BASIS_RANK:
            raise AttackGraphError(f"unknown basis: {self.basis}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "basis": self.basis,
            "evidence": [dict(entry) for entry in self.evidence],
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class AttackPath:
    """One discovered path with per-hop provenance."""

    source: str
    target: str
    hops: tuple[dict[str, Any], ...]
    basis: str
    potentially_dangerous: bool = False
    finding_type: str = "path"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hops": [dict(hop) for hop in self.hops],
            "basis": self.basis,
            "potentially_dangerous": self.potentially_dangerous,
            "finding_type": self.finding_type,
        }


@dataclass(frozen=True)
class AttackFinding:
    """A heuristic or derived finding (escalation, abuse, transitivity)."""

    type: str
    basis: str
    description: str
    agents: tuple[str, ...] = ()
    paths: tuple[AttackPath, ...] = ()
    response: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "basis": self.basis,
            "description": self.description,
            "agents": list(self.agents),
            "paths": [path.to_dict() for path in self.paths],
            "response": self.response,
        }


@dataclass(frozen=True)
class _ReversedEdge:
    """A synthesized traversal edge (agent -> held capability)."""

    source: str
    target: str
    edge_type: str
    basis: str

    @property
    def type(self) -> str:
        return self.edge_type

    def __getattr__(self, name: str) -> Any:
        # _ReversedEdge only appears inside the BFS loop, which touches
        # ``type`` (property above) and nothing else; any other access
        # is a programming error and fails loudly.
        raise AttributeError(name)


def _weakest(bases: Iterable[str]) -> str:
    """The weakest basis in a collection - a path is only as strong as
    its least trustworthy hop."""

    return min(bases, key=lambda basis: _BASIS_RANK.get(basis, 0))


class AttackGraph:
    """Continuously evaluated attack graph.

    Built from recorded facts (observed), computed reachability
    (derived), heuristics (inferred), and twin simulations (simulated).
    """

    def __init__(self) -> None:
        self._nodes: dict[str, AttackNode] = {}
        self._edges: list[AttackEdge] = []

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_network(
        cls,
        network: AgentNetworkGraph,
    ) -> "AttackGraph":
        """Build an attack graph from a v1.9 network graph.

        Entity mapping:
          agent -> agent, capability -> capability, tool -> tool,
          resource -> resource, policy -> policy,
          trust_boundary -> trust (signed_by edges),
          incident -> incident.
        Every edge keeps the network's basis (observed or derived); the
        network's inferred/simulated nodes carry their basis through.
        """

        graph = cls()

        type_map = {
            NetEntityType.AGENT: "agent",
            NetEntityType.SESSION: "task",
            NetEntityType.TOOL: "tool",
            NetEntityType.RESOURCE: "resource",
            NetEntityType.CAPABILITY: "capability",
            NetEntityType.CREDENTIAL: "resource",
            NetEntityType.POLICY: "policy",
            NetEntityType.INCIDENT: "incident",
            NetEntityType.TRUST_BOUNDARY: "trust",
            NetEntityType.EVENT: "incident",
        }

        for node in network.nodes():
            kind = type_map.get(node.type, "incident")
            graph.add_node(
                node.id, kind, node.label,
                basis=node.basis.value,
                evidence=[ref.to_dict() for ref in node.evidence],
                attributes=dict(node.attributes),
            )
            if kind == "agent":
                graph.add_node(
                    f"identity:{node.label}",
                    "identity",
                    node.label,
                    basis=node.basis.value,
                    evidence=[ref.to_dict() for ref in node.evidence],
                    attributes={"network_node": node.id},
                )
                graph.add_edge(
                    node.id, f"identity:{node.label}",
                    "has_identity", basis=node.basis.value,
                )

        for edge in network.edges():
            basis = edge.basis.value
            mapping = {
                RelationType.ISSUED.value: ("authority", "holds"),
                RelationType.DELEGATED.value: ("delegation", "delegates"),
                RelationType.ATTENUATED.value: ("delegation", "derived_from"),
                RelationType.REVOKED.value: ("delegation", "derived_from"),
                RelationType.USES.value: ("tool", "uses"),
                RelationType.ALLOWED.value: ("capability", "holds"),
                RelationType.DENIED.value: ("capability", "holds"),
                RelationType.BOUND_TO.value: ("tool", "bound_to"),
                RelationType.ACCESSES.value: ("resource", "accesses"),
                RelationType.TRUSTS.value: ("trust", "trusts"),
                RelationType.BELONGS_TO.value: ("task", "performs"),
                RelationType.PARENT_OF.value: ("trust", "trusts"),
                RelationType.PART_OF.value: ("task", "requires"),
            }
            if edge.type not in mapping:
                continue
            node_type, edge_type = mapping[edge.type]
            # The edge may reference entity ids that were not
            # materialized above (e.g. a session node); synthesize a
            # minimal node of the mapped type so the path remains.
            for node_id in (edge.source, edge.target):
                if node_id not in graph._nodes:
                    graph.add_node(
                        node_id,
                        node_type,
                        node_id.split(":", 1)[-1],
                        basis=basis,
                    )
            graph.add_edge(
                edge.source,
                edge.target,
                edge_type,
                basis=basis,
                evidence=[ref.to_dict() for ref in edge.evidence],
                attributes=dict(edge.attributes),
            )

        return graph

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        *,
        basis: str = Provenance.OBSERVED.value,
        evidence: Iterable[dict[str, Any]] = (),
        attributes: Optional[dict[str, Any]] = None,
    ) -> AttackNode:
        node = AttackNode(
            id=node_id,
            type=node_type,
            label=label,
            basis=basis,
            evidence=tuple(evidence),
            attributes=dict(attributes or {}),
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        *,
        basis: str = Provenance.OBSERVED.value,
        evidence: Iterable[dict[str, Any]] = (),
        attributes: Optional[dict[str, Any]] = None,
    ) -> AttackEdge:
        if source not in self._nodes:
            raise AttackGraphError(f"unknown source node: {source}")
        if target not in self._nodes:
            raise AttackGraphError(f"unknown target node: {target}")
        edge = AttackEdge(
            source=source,
            target=target,
            type=edge_type,
            basis=basis,
            evidence=tuple(evidence),
            attributes=dict(attributes or {}),
        )
        self._edges.append(edge)
        return edge

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def nodes(self) -> tuple[AttackNode, ...]:
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    def edges(self) -> tuple[AttackEdge, ...]:
        return tuple(self._edges)

    def node(self, node_id: str) -> Optional[AttackNode]:
        return self._nodes.get(node_id)

    def agent_ids(self) -> list[str]:
        return sorted(
            node.id
            for node in self._nodes.values()
            if node.type == "agent"
        )

    def _outgoing(self, node_id: str) -> list[AttackEdge]:
        return [edge for edge in self._edges if edge.source == node_id]

    def _incoming(self, node_id: str) -> list[AttackEdge]:
        return [edge for edge in self._edges if edge.target == node_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes()],
            "edges": [edge.to_dict() for edge in self.edges()],
        }

    # ------------------------------------------------------------------
    # Analysis: reachability and blast radius
    # ------------------------------------------------------------------

    def reachable(
        self,
        agent: str,
    ) -> dict[str, Any]:
        """What this agent can reach, with per-edge provenance.

        Follows holds/uses/accesses/bound_to/delegates/trusts edges,
        honoring ``derived_from`` revocations (a capability edge whose
        target was later revoked is excluded when its basis is observed).
        """

        start = f"agent:{agent}" if not agent.startswith("agent:") else agent
        if start not in self._nodes:
            return {"agent": agent, "capabilities": [], "tools": [],
                    "resources": [], "actions": [], "evidence": []}

        capabilities: set[str] = set()
        tools: set[str] = set()
        resources: set[str] = set()
        actions: set[str] = set()
        path_evidence: list[dict[str, Any]] = []

        revoked: set[str] = set()
        for edge in self._edges:
            if edge.type == "derived_from" and edge.basis == Provenance.OBSERVED.value:
                if edge.attributes.get("revoked"):
                    revoked.add(edge.source)

        seen: set[tuple[str, str, str]] = set()
        queue: deque[str] = deque([start])
        visited: set[str] = {start}

        def label(node_id: str) -> str:
            node = self._nodes.get(node_id)
            return node.label if node else node_id

        while queue:
            current = queue.popleft()
            for edge in self._incoming(current):
                key = (edge.source, edge.target, edge.type)
                if key in seen:
                    continue
                seen.add(key)
                source = self._nodes.get(edge.source)
                if source is None or edge.source in revoked:
                    continue
                if edge.type == "holds" and source.type == "capability":
                    capabilities.add(source.label)
                    path_evidence.append(
                        {
                            "entity": source.label,
                            "basis": edge.basis,
                            "edge": edge.type,
                            "via": edge.source,
                        }
                    )
                    if edge.source not in visited:
                        visited.add(edge.source)
                        queue.append(edge.source)
                elif edge.type == "has_identity":
                    if edge.source not in visited:
                        visited.add(edge.source)
                        queue.append(edge.source)
            for edge in self._outgoing(current):
                key = (edge.source, edge.target, edge.type)
                if key in seen:
                    continue
                seen.add(key)
                target = self._nodes.get(edge.target)
                if target is None:
                    continue
                if edge.type == "uses" and target.type == "tool":
                    tools.add(target.label)
                elif edge.type == "accesses" and target.type == "resource":
                    resources.add(target.label)
                elif edge.type == "holds" and target.type == "capability":
                    actions.add(target.label)
                    capabilities.add(target.label)
                elif edge.type in ("delegates", "trusts", "bound_to", "performs"):
                    if edge.target not in visited:
                        visited.add(edge.target)
                        queue.append(edge.target)

        return {
            "agent": agent,
            "capabilities": sorted(capabilities),
            "tools": sorted(tools),
            "resources": sorted(resources),
            "actions": sorted(actions),
            "evidence": path_evidence,
            "basis": Provenance.DERIVED.value,
        }

    def blast_radius(self, agent: str) -> dict[str, Any]:
        """Derived blast radius: what a compromised agent could reach."""

        reachable = self.reachable(agent)
        sensitive = [
            item
            for item in (
                list(reachable["resources"])
                + list(reachable["capabilities"])
                + list(reachable["actions"])
            )
            if is_sensitive(item)
        ]
        return {
            "agent": agent,
            "capabilities": reachable["capabilities"],
            "tools": reachable["tools"],
            "resources": reachable["resources"],
            "sensitive_targets": sorted(set(sensitive)),
            "basis": Provenance.DERIVED.value,
        }

    # ------------------------------------------------------------------
    # Analysis: paths
    # ------------------------------------------------------------------

    def _resolve_target(self, target: str) -> Optional[str]:
        for prefix in ("resource:", "capability:", "tool:", "agent:"):
            candidate = f"{prefix}{target}" if ":" not in target else target
            if candidate in self._nodes:
                return candidate
        return None

    def paths_to(
        self,
        target: str,
        *,
        max_hops: int = 8,
        max_paths: int = 20,
        from_agents: Optional[Iterable[str]] = None,
    ) -> list[AttackPath]:
        """All paths from agents to ``target``, with per-hop basis."""

        if isinstance(max_hops, bool) or not isinstance(max_hops, int):
            raise AttackGraphError("max_hops must be an integer")
        if max_hops <= 0:
            raise AttackGraphError("max_hops must be positive")

        target_id = self._resolve_target(target)
        if target_id is None:
            return []

        agents = list(from_agents or self.agent_ids())
        paths: list[AttackPath] = []
        seen: set[tuple[str, ...]] = set()

        for agent in agents:
            start = f"agent:{agent}" if not agent.startswith("agent:") else agent
            if start not in self._nodes:
                continue
            for raw in self._bfs(start, target_id, max_hops=max_hops, max_paths=max_paths):
                key = tuple(hop["edge"] + ":" + hop["to"] for hop in raw)
                if key in seen:
                    continue
                seen.add(key)
                bases = [hop["basis"] for hop in raw]
                hops = tuple(
                    {
                        "edge": hop["edge"],
                        "from": hop["from"],
                        "to": hop["to"],
                        "basis": hop["basis"],
                        "from_label": hop["from_label"],
                        "to_label": hop["to_label"],
                    }
                    for hop in raw
                )
                paths.append(
                    AttackPath(
                        source=start,
                        target=target_id,
                        hops=hops,
                        basis=_weakest(bases),
                        potentially_dangerous=is_sensitive(target),
                    )
                )

        paths.sort(key=lambda p: (len(p.hops), p.source))
        return paths[:max_paths]

    def paths_from_compromised(
        self,
        agent: str,
        *,
        max_hops: int = 8,
        max_paths: int = 20,
    ) -> list[AttackPath]:
        """Paths from a compromised agent to sensitive resources.

        Labeled ``derived`` (from recorded authority) - this is what
        *could* be reached if the agent were compromised, never a claim
        that it happened.
        """

        start = f"agent:{agent}" if not agent.startswith("agent:") else agent
        if start not in self._nodes:
            return []

        paths: list[AttackPath] = []
        for node in self._nodes.values():
            if node.type != "resource":
                continue
            if not is_sensitive(node.label):
                continue
            paths.extend(
                self.paths_to(
                    node.id,
                    max_hops=max_hops,
                    max_paths=max_paths,
                    from_agents=[start],
                )
            )
        return paths

    def _bfs(
        self,
        source: str,
        target: str,
        *,
        max_hops: int,
        max_paths: int,
    ) -> list[list[dict[str, Any]]]:
        found: list[list[dict[str, Any]]] = []
        queue: list[tuple[str, list[dict[str, Any]]]] = [(source, [])]
        visited_paths: set[tuple[str, ...]] = set()
        # Nodes whose outgoing edges have already been expanded. The
        # graph contains cycles (e.g. capability -> agent ``holds``
        # paired with the agent -> capability traversal edge), so a
        # naive BFS never terminates. Expanding each node at most once
        # bounds the work: any path through an already-expanded node is
        # a cycle and adds no new reachability.
        expanded: set[str] = set()

        def label(node_id: str) -> str:
            node = self._nodes.get(node_id)
            return node.label if node else node_id

        while queue and len(found) < max_paths:
            current, path = queue.pop(0)
            if current in expanded:
                continue
            expanded.add(current)

            # Ordinary outgoing edges.
            outgoing = list(self._outgoing(current))
            # Incoming ``holds`` edges from capability nodes: an agent
            # reaches the capabilities it holds even though the recorded
            # edge points capability -> agent. The traversal runs *from*
            # the agent *to* the capability node.
            for edge in self._incoming(current):
                source_node = self._nodes.get(edge.source)
                if (
                    edge.type == "holds"
                    and source_node is not None
                    and source_node.type in ("capability", "identity")
                ):
                    outgoing.append(
                        _ReversedEdge(
                            source=current,
                            target=edge.source,
                            edge_type=edge.type,
                            basis=edge.basis,
                        )
                    )
            for edge in outgoing:
                if len(path) + 1 > max_hops:
                    continue
                hop = {
                    "edge": edge.type,
                    "from": edge.source,
                    "to": edge.target,
                    "basis": edge.basis,
                    "from_label": label(edge.source),
                    "to_label": label(edge.target),
                }
                next_path = path + [hop]
                if edge.target == target:
                    found.append(next_path)
                    continue
                # Skip cycles within this path: the target of the new
                # hop must not already appear in the path *so far* (the
                # new hop itself is never a cycle).
                seen_nodes = {h["to"] for h in path}
                if edge.target in seen_nodes:
                    continue
                key = tuple(h["edge"] + ":" + h["to"] for h in next_path)
                if key in visited_paths:
                    continue
                visited_paths.add(key)
                queue.append((edge.target, next_path))
        return found

    # ------------------------------------------------------------------
    # Analysis: findings
    # ------------------------------------------------------------------

    def escalation_paths(
        self,
        *,
        max_hops: int = 8,
        max_paths: int = 20,
    ) -> list[AttackFinding]:
        """Privilege-escalation paths: agents to sensitive targets."""

        findings: list[AttackFinding] = []
        sensitive_targets = [
            node.id
            for node in self._nodes.values()
            if node.type == "resource" and is_sensitive(node.label)
        ]
        for target_id in sensitive_targets:
            paths = self.paths_to(
                target_id,
                max_hops=max_hops,
                max_paths=max_paths,
            )
            if not paths:
                continue
            agents = sorted({p.source for p in paths})
            findings.append(
                AttackFinding(
                    type="privilege_escalation_path",
                    basis=_weakest(p.basis for p in paths),
                    description=(
                        f"{len(paths)} path(s) to sensitive target "
                        f"{self._nodes[target_id].label} from "
                        + ", ".join(agents)
                    ),
                    agents=agents,
                    paths=tuple(paths),
                    response=(
                        "revoke or attenuate the enabling capabilities; "
                        "break the recorded delegation/trust edges"
                    ),
                )
            )
        return findings

    def capability_combinations(
        self,
        agent: str,
        *,
        max_combos: int = 10,
    ) -> list[dict[str, Any]]:
        """Capability pairs whose *union* reaches a sensitive resource
        that neither capability reaches alone.

        Derived analysis: the combination finding is never promoted to
        observed.
        """

        start = f"agent:{agent}" if not agent.startswith("agent:") else agent
        if start not in self._nodes:
            return []

        per_capability: dict[str, set[str]] = {}
        sensitive_resources = {
            node.id
            for node in self._nodes.values()
            if node.type == "resource" and is_sensitive(node.label)
        }

        for edge in self._incoming(start):
            if edge.type != "holds":
                continue
            cap = self._nodes.get(edge.source)
            if cap is None or cap.type != "capability":
                continue
            per_capability[cap.id] = self._reach_via(start, cap.id)

        combos: list[dict[str, Any]] = []
        cap_ids = sorted(per_capability)
        for i in range(len(cap_ids)):
            for j in range(i + 1, len(cap_ids)):
                left, right = cap_ids[i], cap_ids[j]
                union = per_capability[left] | per_capability[right]
                combined_sensitive = union & sensitive_resources
                if not combined_sensitive:
                    continue
                alone = (
                    per_capability[left] & sensitive_resources
                ) or (per_capability[right] & sensitive_resources)
                if alone:
                    continue
                combos.append(
                    {
                        "agent": agent,
                        "capabilities": [left, right],
                        "labels": [
                            self._nodes[left].label,
                            self._nodes[right].label,
                        ],
                        "reaches": sorted(combined_sensitive),
                        "basis": Provenance.DERIVED.value,
                        "note": (
                            "neither capability alone reaches a sensitive "
                            "resource; the combination does - reachability, "
                            "not exploitability"
                        ),
                    }
                )
                if len(combos) >= max_combos:
                    return combos
        return combos

    def _reach_via(self, start: str, via: str) -> set[str]:
        """Resources reachable from ``start`` after traversing ``via``."""

        reached: set[str] = set()
        seen: set[tuple[str, str, str]] = set()
        queue: deque[str] = deque([start])
        visited: set[str] = {start}
        entered_via = False

        while queue:
            current = queue.popleft()
            for edge in self._outgoing(current):
                key = (edge.source, edge.target, edge.type)
                if key in seen:
                    continue
                seen.add(key)
                if edge.source == via:
                    entered_via = True
                if edge.type == "accesses" and self._nodes.get(edge.target) is not None:
                    reached.add(edge.target)
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append(edge.target)
        return reached

    def delegation_abuse(self) -> list[AttackFinding]:
        """Delegations that widen reach beyond what the grantor holds.

        A delegation edge from A to B where B's reach includes a
        capability A itself never held is a ``derived`` signal of
        delegation abuse (the v2.0 pipeline would deny the widening at
        authorization time; this finding surfaces the risk in recorded
        reach).
        """

        findings: list[AttackFinding] = []
        for edge in self._edges:
            if edge.type != "delegates":
                continue
            grantor = self._nodes.get(edge.source)
            grantee = self._nodes.get(edge.target)
            if grantor is None or grantee is None:
                continue
            if grantor.type != "agent" or grantee.type != "agent":
                continue
            grantor_reach = self.reachable(grantor.id)
            grantee_reach = self.reachable(grantee.id)
            extra = [
                cap
                for cap in grantee_reach["capabilities"]
                if cap not in grantor_reach["capabilities"]
            ]
            if extra:
                findings.append(
                    AttackFinding(
                        type="delegation_abuse",
                        basis=Provenance.DERIVED.value,
                        description=(
                            f"{grantor.label} delegated to {grantee.label}, "
                            f"whose reach includes capabilities the grantor "
                            f"never held: {', '.join(extra)}"
                        ),
                        agents=(grantor.label, grantee.label),
                        response=(
                            "verify the delegation against the v2.0 "
                            "delegation chain; revoke if the grantor's "
                            "authority was exceeded"
                        ),
                    )
                )
        return findings

    def trust_transitivity(self, *, max_hops: int = 6) -> list[AttackFinding]:
        """Trust chains that create reach beyond a direct relationship."""

        findings: list[AttackFinding] = []
        for node in self._nodes.values():
            if node.type != "agent":
                continue
            for edge in self._edges:
                if edge.type != "trusts" or edge.source != node.id:
                    continue
                # Walk the trust chain and look for transitive reach.
                chain: list[str] = [node.id]
                current = edge.target
                hops = 0
                while current in self._nodes and hops < max_hops:
                    if current in chain:
                        break
                    chain.append(current)
                    next_edges = [
                        e for e in self._edges
                        if e.type == "trusts" and e.source == current
                    ]
                    if not next_edges:
                        break
                    current = next_edges[0].target
                    hops += 1
                if len(chain) >= 3:
                    tail = self._nodes.get(chain[-1])
                    if tail is None:
                        continue
                    tail_reach = self.reachable(tail.id)
                    if tail_reach["sensitive_targets if False else 'resources'"] if False else tail_reach["resources"]:
                        findings.append(
                            AttackFinding(
                                type="trust_transitivity",
                                basis=Provenance.INFERRED.value,
                                description=(
                                    "trust chain "
                                    + " -> ".join(
                                        self._nodes[c].label for c in chain
                                    )
                                    + f" gives {self._nodes[chain[-1]].label} "
                                      "reach over sensitive resources "
                                      "through transitive trust"
                                ),
                                agents=tuple(
                                    self._nodes[c].label for c in chain
                                ),
                                response=(
                                    "review transitive trust; convert "
                                    "indirect trust into explicit scoped "
                                    "a2a relationships"
                                ),
                            )
                        )
        return findings

    def chokepoints(self, *, max_paths: int = 50) -> list[dict[str, Any]]:
        """Nodes that appear on the most attack paths to sensitive
        targets - high-value revocation targets."""

        counts: dict[str, int] = {}
        sensitive_targets = [
            node.id
            for node in self._nodes.values()
            if node.type == "resource" and is_sensitive(node.label)
        ]
        for target_id in sensitive_targets:
            for path in self.paths_to(target_id, max_paths=max_paths):
                for hop in path.hops:
                    if hop["edge"] in ("trusts", "delegates", "holds"):
                        counts[hop["to"]] = counts.get(hop["to"], 0) + 1

        ranked = sorted(
            counts.items(), key=lambda item: item[1], reverse=True
        )
        return [
            {
                "node": node_id,
                "label": (
                    self._nodes[node_id].label
                    if node_id in self._nodes
                    else node_id
                ),
                "paths": count,
                "basis": Provenance.DERIVED.value,
                "response": (
                    f"revoking or attenuating {node_id} breaks "
                    f"{count} recorded path(s)"
                ),
            }
            for node_id, count in ranked
        ]

    def summarize(self) -> dict[str, Any]:
        """An overview for consoles and CLI."""

        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "agents": self.agent_ids(),
            "sensitive_resources": sorted(
                node.label
                for node in self._nodes.values()
                if node.type == "resource" and is_sensitive(node.label)
            ),
            "basis": Provenance.DERIVED.value,
        }
