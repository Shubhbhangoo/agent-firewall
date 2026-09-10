"""Attack-path discovery (v1.9).

Given a network graph, find potentially dangerous reachable paths from
an agent to sensitive actions or resources, and answer:

* what is the shortest path to this resource?
* which capabilities make this path possible?
* which policy change would break the path?

Every path hop is labeled with a status taxonomy that is never
conflated:

``reachable``
    A graph edge exists (recorded relationship).

``policy-permitted``
    The relationship is an *allowed* authorization outcome (recorded).

``observed``
    The step was actually exercised (a recorded authorization).

``simulated``
    The step comes from a scenario simulator, not from recorded
    history.

``potentially_dangerous``
    The path targets a credential-shaped or sensitive resource.

Reachability is not exploitability. A path labeled ``reachable`` or
``potentially_dangerous`` is an *analytical* finding about recorded
authority, never a claim that it was or can be exploited.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from firewall.network.graph import AgentNetworkGraph
from firewall.network.model import (
    EntityType,
    Provenance,
    RelationType,
    entity_id,
)

#: Sensitive resource markers used to label potentially_dangerous hops.
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
)

#: Statuses, in increasing claim strength. A ``simulated`` path must
#: never be reported as ``observed``.
STATUS_ORDER = (
    "simulated",
    "reachable",
    "policy-permitted",
    "observed",
)


class AttackPathError(ValueError):
    """Raised for a malformed attack-path query."""


@dataclass(frozen=True)
class PathHop:
    """One step on an attack path."""

    edge: str
    source: str
    target: str
    status: str
    potentially_dangerous: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge": self.edge,
            "source": self.source,
            "target": self.target,
            "status": self.status,
            "potentially_dangerous": self.potentially_dangerous,
        }


@dataclass(frozen=True)
class AttackPath:
    """One discovered path, with the capabilities that enable it."""

    source: str
    target: str
    hops: tuple[PathHop, ...]
    enabling_capabilities: tuple[str, ...]
    status: str
    potentially_dangerous: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hops": [hop.to_dict() for hop in self.hops],
            "enabling_capabilities": list(
                self.enabling_capabilities
            ),
            "status": self.status,
            "potentially_dangerous": self.potentially_dangerous,
        }


def _is_sensitive(label: str) -> bool:
    lowered = (label or "").lower()
    return any(
        marker in lowered for marker in SENSITIVE_MARKERS
    )


def _hop_status(edge_type: str) -> str:
    if edge_type == RelationType.ALLOWED.value:
        return "observed"
    if edge_type in (
        RelationType.ISSUED.value,
        RelationType.DELEGATED.value,
        RelationType.ATTENUATED.value,
    ):
        return "policy-permitted"
    return "reachable"


class AttackPathAnalyzer:
    """Attack-path analysis over a network graph."""

    def __init__(
        self,
        graph: AgentNetworkGraph,
    ) -> None:
        if not isinstance(graph, AgentNetworkGraph):
            raise AttackPathError(
                "graph must be an AgentNetworkGraph"
            )
        self._graph = graph

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def paths_to(
        self,
        target: str,
        *,
        max_hops: int = 8,
        max_paths: int = 10,
    ) -> list[AttackPath]:
        """All recorded paths from any agent to ``target``.

        ``target`` may be a resource label or a capability/action
        label. Paths are produced by BFS over observed edges, so every
        hop is evidence-backed.
        """

        if isinstance(max_hops, bool) or not isinstance(
            max_hops, int
        ):
            raise AttackPathError(
                "max_hops must be an integer"
            )

        if max_hops <= 0:
            raise AttackPathError(
                "max_hops must be positive"
            )

        target_id = self._resolve_target(target)

        if target_id is None:
            return []

        paths: list[AttackPath] = []
        seen: set[tuple[str, ...]] = set()

        for agent_node_id in self._agent_ids():
            for path in self._bfs(
                agent_node_id,
                target_id,
                max_hops=max_hops,
                max_paths=max_paths,
            ):
                key = tuple(
                    hop["edge"] + hop["to"]
                    for hop in path
                )
                if key in seen:
                    continue
                seen.add(key)

                hops = tuple(
                    PathHop(
                        edge=hop["edge"],
                        source=hop["from"],
                        target=hop["to"],
                        status=_hop_status(hop["edge"]),
                        potentially_dangerous=_is_sensitive(
                            hop["to"]
                        ),
                    )
                    for hop in path
                )

                capabilities = self._capabilities_on(
                    path
                )

                potentially_dangerous = any(
                    hop.potentially_dangerous
                    for hop in hops
                ) or _is_sensitive(target)

                status = "observed" if any(
                    hop.status == "observed" for hop in hops
                ) else "policy-permitted"

                paths.append(
                    AttackPath(
                        source=agent_node_id,
                        target=target_id,
                        hops=hops,
                        enabling_capabilities=capabilities,
                        status=status,
                        potentially_dangerous=potentially_dangerous,
                    )
                )

        paths.sort(
            key=lambda p: (
                len(p.hops),
                p.source,
            )
        )

        return paths[:max_paths]

    def shortest_path_to(
        self,
        agent: str,
        target: str,
    ) -> Optional[AttackPath]:
        """Shortest path from one agent to ``target``."""

        agent_id = entity_id(EntityType.AGENT, agent)
        target_id = self._resolve_target(target)

        if self._graph.node(agent_id) is None or target_id is None:
            return None

        raw = self._graph.shortest_path(agent_id, target_id)

        if raw is None:
            return None

        hops = tuple(
            PathHop(
                edge=hop["edge"],
                source=hop["from"],
                target=hop["to"],
                status=_hop_status(hop["edge"]),
                potentially_dangerous=_is_sensitive(
                    hop["to"]
                ),
            )
            for hop in raw["path"]
        )

        return AttackPath(
            source=agent_id,
            target=target_id,
            hops=hops,
            enabling_capabilities=self._capabilities_on(
                raw["path"]
            ),
            status=(
                "observed"
                if any(
                    hop.status == "observed" for hop in hops
                )
                else "policy-permitted"
            ),
            potentially_dangerous=any(
                hop.potentially_dangerous for hop in hops
            )
            or _is_sensitive(target),
        )

    def break_path(
        self,
        path: AttackPath,
    ) -> list[dict[str, Any]]:
        """Policy changes that would break this path.

        For each enabling capability on the path, report what removing
        it (revoke) or not trusting its issuer would sever. These are
        *suggestions* derived from the graph; enforcement goes through
        the normal revocation/issuer-trust mechanisms.
        """

        suggestions: list[dict[str, Any]] = []

        for capability in path.enabling_capabilities:
            suggestions.append(
                {
                    "capability": capability,
                    "action": "revoke",
                    "effect": (
                        f"revoking {capability} breaks the "
                        "recorded issuance/delegation that enables "
                        "this path"
                    ),
                    "basis": Provenance.DERIVED.value,
                }
            )

            suggestions.append(
                {
                    "capability": capability,
                    "action": "attenuate",
                    "effect": (
                        f"narrowing {capability} to the minimal "
                        "required scope removes the excess reach "
                        "this path relies on"
                    ),
                    "basis": Provenance.DERIVED.value,
                }
            )

        return suggestions

    def summarize(self) -> dict[str, Any]:
        """Overview of dangerous reach in the network."""

        sensitive_targets: list[dict[str, Any]] = []

        for node in self._graph.nodes():
            if node.type == EntityType.RESOURCE and _is_sensitive(
                node.label
            ):
                sensitive_targets.append(
                    {
                        "resource": node.label,
                        "basis": node.basis.value,
                        "evidence": [
                            ref.to_dict() for ref in node.evidence
                        ],
                    }
                )

        return {
            "sensitive_resources": sensitive_targets,
            "basis": Provenance.DERIVED.value,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _agent_ids(self) -> list[str]:
        return sorted(
            {
                node.id
                for node in self._graph.nodes()
                if node.type == EntityType.AGENT
            }
        )

    def _resolve_target(
        self,
        target: str,
    ) -> Optional[str]:
        for entity_type in (
            EntityType.RESOURCE,
            EntityType.CAPABILITY,
            EntityType.TOOL,
        ):
            candidate = entity_id(entity_type, target)
            if self._graph.node(candidate) is not None:
                return candidate

        return None

    def _bfs(
        self,
        source: str,
        target: str,
        *,
        max_hops: int,
        max_paths: int,
    ) -> list[list[dict[str, Any]]]:
        found: list[list[dict[str, Any]]] = []
        queue: list[tuple[str, list[dict[str, Any]]]] = [
            (source, [])
        ]
        visited_paths: set[tuple[str, ...]] = set()

        while queue and len(found) < max_paths:
            current, path = queue.pop(0)

            for edge in self._graph._outgoing(current):
                if len(path) + 1 > max_hops:
                    continue

                hop = {
                    "edge": edge.type.value,
                    "from": edge.source,
                    "to": edge.target,
                }

                next_path = path + [hop]

                if edge.target == target:
                    found.append(next_path)
                    continue

                # Avoid trivial cycles.
                seen_nodes = {h["to"] for h in next_path}
                if edge.target in seen_nodes:
                    continue

                key = tuple(
                    h["edge"] + h["to"] for h in next_path
                )
                if key in visited_paths:
                    continue
                visited_paths.add(key)

                queue.append((edge.target, next_path))

        return found

    def _capabilities_on(
        self,
        path: list[dict[str, Any]],
    ) -> tuple[str, ...]:
        """Capability labels appearing on the path's hops."""

        capabilities: list[str] = []

        for hop in path:
            node = self._graph.node(hop["to"])
            if (
                node is not None
                and node.type == EntityType.CAPABILITY
            ):
                capabilities.append(node.label)

        # Deduplicate, preserve order.
        return tuple(
            dict.fromkeys(capabilities)
        )
