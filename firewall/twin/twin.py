"""v2.1 Security Digital Twin (firewall.twin).

An isolated representation of the live agent security environment used
for counterfactual analysis. The twin answers questions such as:

* what happens if agent X is compromised?
* what happens if capability Y is revoked?
* what happens if tool Z becomes untrusted?
* what happens if an agent delegates authority?
* what happens if a credential is exposed?
* what resources become reachable?

The twin **never mutates production authorization state**. It snapshots
the live attack graph (itself an immutable-with-respect-to-the-twin
analysis view), deep-copies it, applies the counterfactual to the copy,
and compares. Every report is explainable: it returns attack paths,
reachability changes, blast radius, containment opportunities, policy
changes, and risk deltas - all labeled ``simulated``.

The twin holds no reference to any live registry that a counterfactual
could mutate: it consumes a fresh :class:`AttackGraph` snapshot per
query. The live graph is read-only to the twin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from firewall.attackgraph import (
    AttackGraph,
    AttackPath,
    is_sensitive,
)
from firewall.network import AgentNetworkGraph
from firewall.network.model import Provenance

#: Counterfactual kinds the twin can answer.
COUNTERFACTUAL_KINDS = (
    "compromised_agent",
    "revoked_capability",
    "untrusted_tool",
    "delegated_authority",
    "exposed_credential",
)


class TwinError(ValueError):
    """Raised for an invalid twin operation."""


def _clone(graph: AttackGraph) -> AttackGraph:
    """Deep copy of an attack graph via serialization."""

    copy = AttackGraph()
    data = graph.to_dict()
    for node in data["nodes"]:
        copy.add_node(
            node["id"],
            node["type"],
            node["label"],
            basis=node["basis"],
            evidence=node.get("evidence", []),
            attributes=node.get("attributes", {}),
        )
    for edge in data["edges"]:
        copy.add_edge(
            edge["source"],
            edge["target"],
            edge["type"],
            basis=edge["basis"],
            evidence=edge.get("evidence", []),
            attributes=edge.get("attributes", {}),
        )
    return copy


@dataclass(frozen=True)
class ReachabilityDelta:
    """What a counterfactual added or removed from an agent's reach."""

    agent: str
    added_capabilities: tuple[str, ...] = ()
    removed_capabilities: tuple[str, ...] = ()
    added_resources: tuple[str, ...] = ()
    removed_resources: tuple[str, ...] = ()
    added_tools: tuple[str, ...] = ()
    removed_tools: tuple[str, ...] = ()

    def risk_delta(self) -> int:
        """New sensitive resources made reachable by the change."""

        return len(
            [r for r in self.added_resources if is_sensitive(r)]
        ) + len(
            [c for c in self.added_capabilities if is_sensitive(c)]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "added_capabilities": list(self.added_capabilities),
            "removed_capabilities": list(self.removed_capabilities),
            "added_resources": list(self.added_resources),
            "removed_resources": list(self.removed_resources),
            "added_tools": list(self.added_tools),
            "removed_tools": list(self.removed_tools),
            "risk_delta": self.risk_delta(),
        }


@dataclass(frozen=True)
class CounterfactualReport:
    """One explainable counterfactual result."""

    kind: str
    title: str
    description: str
    actions: tuple[dict[str, Any], ...] = ()
    before_paths: tuple[AttackPath, ...] = ()
    after_paths: tuple[AttackPath, ...] = ()
    reachability_deltas: tuple[ReachabilityDelta, ...] = ()
    blast_radius_after: dict[str, Any] = field(default_factory=dict)
    containment_opportunities: tuple[dict[str, Any], ...] = ()
    policy_changes: tuple[dict[str, Any], ...] = ()
    basis: str = Provenance.SIMULATED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "description": self.description,
            "actions": [dict(a) for a in self.actions],
            "before_paths": [p.to_dict() for p in self.before_paths],
            "after_paths": [p.to_dict() for p in self.after_paths],
            "reachability_deltas": [
                d.to_dict() for d in self.reachability_deltas
            ],
            "blast_radius_after": dict(self.blast_radius_after),
            "containment_opportunities": [
                dict(c) for c in self.containment_opportunities
            ],
            "policy_changes": [dict(p) for p in self.policy_changes],
            "basis": self.basis,
        }


class SecurityTwin:
    """Isolated counterfactual analysis over the live security graph.

    ``graph_source`` is a callable returning a fresh, read-only
    :class:`AttackGraph` of the live environment. Every query snapshots
    that graph and operates on a deep copy.
    """

    def __init__(
        self,
        graph_source: Callable[[], AttackGraph],
    ) -> None:
        if not callable(graph_source):
            raise TwinError("graph_source must be callable")
        self._graph_source = graph_source
        self._baseline: Optional[AttackGraph] = None

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_network(
        cls,
        network: AgentNetworkGraph,
    ) -> "SecurityTwin":
        """A twin over a v1.9 network graph (snapshotted per query)."""

        def source() -> AttackGraph:
            return AttackGraph.from_network(network)

        return cls(source)

    @classmethod
    def from_graph(
        cls,
        graph: AttackGraph,
    ) -> "SecurityTwin":
        """A twin over an existing attack graph (read-only source)."""

        def source() -> AttackGraph:
            return _clone(graph)

        return cls(source)

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self) -> AttackGraph:
        """A deep copy of the live graph - the counterfactual baseline."""

        self._baseline = _clone(self._graph_source())
        return self._baseline

    def baseline(self) -> Optional[AttackGraph]:
        if self._baseline is None:
            self.snapshot()
        return self._baseline

    # ------------------------------------------------------------------
    # Counterfactuals
    # ------------------------------------------------------------------

    def compromise(
        self,
        agent: str,
        *,
        title: str = "agent compromised",
    ) -> CounterfactualReport:
        """What happens if ``agent`` is compromised?"""

        base = self.baseline()
        after = _clone(base)
        start = f"agent:{agent}" if not agent.startswith("agent:") else agent
        if start not in after._nodes:
            raise TwinError(f"unknown agent: {agent}")

        incident_id = f"incident:simulated-{agent}"
        after.add_node(
            incident_id,
            "incident",
            f"simulated compromise of {agent}",
            basis=Provenance.SIMULATED.value,
            attributes={"counterfactual": True},
        )
        after.add_edge(
            incident_id,
            start,
            "affects",
            basis=Provenance.SIMULATED.value,
        )

        paths = after.paths_from_compromised(agent)
        before_paths = base.paths_from_compromised(agent)
        deltas = self._deltas(base, after)
        radius = after.blast_radius(agent)
        containment = self._containment_opportunities(after, agent)

        return CounterfactualReport(
            kind="compromised_agent",
            title=title,
            description=(
                f"simulation: {agent} is compromised. "
                "Reachability below is derived from recorded authority "
                "and simulated incident state; it is not evidence of "
                "actual exploitation."
            ),
            actions=[
                {
                    "type": "add_incident",
                    "agent": agent,
                    "basis": Provenance.SIMULATED.value,
                }
            ],
            before_paths=tuple(before_paths),
            after_paths=tuple(paths),
            reachability_deltas=deltas,
            blast_radius_after=radius,
            containment_opportunities=containment,
            policy_changes=self._policy_changes(radius),
        )

    def revoke_capability(
        self,
        agent: str,
        capability: str,
        *,
        title: str = "capability revoked",
    ) -> CounterfactualReport:
        """What happens if ``capability`` is revoked for ``agent``?"""

        base = self.baseline()
        after = _clone(base)
        start = f"agent:{agent}" if not agent.startswith("agent:") else agent

        removed: list[dict[str, Any]] = []
        cap_ids = [
            node.id
            for node in after._nodes.values()
            if node.type == "capability" and node.label == capability
        ]
        for cap_id in cap_ids:
            for edge in list(after._edges):
                if edge.type == "holds" and edge.source == cap_id:
                    if edge.target == start:
                        removed.append(
                            {"capability": capability, "agent": agent}
                        )
                        after._edges.remove(edge)
            # mark the capability revoked so reachability excludes it
            for edge in after._edges:
                if edge.source == cap_id and edge.type == "derived_from":
                    attrs = dict(edge.attributes)
                    attrs["revoked"] = True
                    from firewall.attackgraph import AttackEdge
                    after._edges[after._edges.index(edge)] = AttackEdge(
                        source=edge.source,
                        target=edge.target,
                        type=edge.type,
                        basis=edge.basis,
                        evidence=edge.evidence,
                        attributes=attrs,
                    )

        if not removed:
            raise TwinError(
                f"{agent} does not hold capability {capability}"
            )

        deltas = self._deltas(base, after)
        radius = after.blast_radius(agent)
        return CounterfactualReport(
            kind="revoked_capability",
            title=title,
            description=(
                f"simulation: revoking {capability} from {agent}. "
                "The delta below is what this would remove from reach."
            ),
            actions=removed,
            reachability_deltas=deltas,
            blast_radius_after=radius,
            policy_changes=self._policy_changes(radius),
        )

    def untrust_tool(
        self,
        tool: str,
        *,
        title: str = "tool untrusted",
    ) -> CounterfactualReport:
        """What happens if ``tool`` becomes untrusted?"""

        base = self.baseline()
        after = _clone(base)

        removed_agents: set[str] = set()
        tool_ids = [
            node.id
            for node in after._nodes.values()
            if node.type == "tool" and node.label == tool
        ]
        if not tool_ids:
            raise TwinError(f"unknown tool: {tool}")
        for tool_id in tool_ids:
            for edge in list(after._edges):
                if edge.type == "bound_to" and edge.target == tool_id:
                    source = after._nodes.get(edge.source)
                    if source is not None and source.type == "capability":
                        after._edges.remove(edge)

        deltas = self._deltas(base, after)
        return CounterfactualReport(
            kind="untrusted_tool",
            title=title,
            description=(
                f"simulation: {tool} is untrusted; every capability "
                "bound to it loses its tool binding."
            ),
            actions=[{"type": "untrust_tool", "tool": tool}],
            reachability_deltas=deltas,
        )

    def delegate(
        self,
        grantor: str,
        grantee: str,
        *,
        permissions: Optional[dict[str, Any]] = None,
        title: str = "authority delegated",
    ) -> CounterfactualReport:
        """What happens if ``grantor`` delegates authority to
        ``grantee``?"""

        base = self.baseline()
        after = _clone(base)
        start = f"agent:{grantor}" if not grantor.startswith("agent:") else grantor
        target = f"agent:{grantee}" if not grantee.startswith("agent:") else grantee
        if start not in after._nodes:
            raise TwinError(f"unknown grantor: {grantor}")
        if target not in after._nodes:
            after.add_node(
                target,
                "agent",
                grantee,
                basis=Provenance.SIMULATED.value,
                attributes={"counterfactual": True},
            )

        after.add_edge(
            start,
            target,
            "delegates",
            basis=Provenance.SIMULATED.value,
            attributes={
                "permissions": dict(permissions or {}),
                "counterfactual": True,
            },
        )
        for cap_id in [
            node.id
            for node in after._nodes.values()
            if node.type == "capability"
        ]:
            for edge in after._edges:
                if edge.type == "holds" and edge.target == start and edge.source == cap_id:
                    after.add_edge(
                        cap_id,
                        target,
                        "holds",
                        basis=Provenance.SIMULATED.value,
                    )
                    break

        deltas = self._deltas(base, after)
        radius = after.blast_radius(grantee)
        paths = after.paths_from_compromised(grantee)
        return CounterfactualReport(
            kind="delegated_authority",
            title=title,
            description=(
                f"simulation: {grantor} delegates to {grantee}. "
                "The delta shows what authority the grantee gains."
            ),
            actions=[
                {
                    "type": "delegate",
                    "grantor": grantor,
                    "grantee": grantee,
                    "permissions": dict(permissions or {}),
                }
            ],
            after_paths=tuple(paths),
            reachability_deltas=deltas,
            blast_radius_after=radius,
            policy_changes=self._policy_changes(radius),
        )

    def expose_credential(
        self,
        agent: str,
        *,
        credential: str = "credential",
        title: str = "credential exposed",
    ) -> CounterfactualReport:
        """What happens if ``agent``'s credential is exposed?"""

        base = self.baseline()
        after = _clone(base)
        start = f"agent:{agent}" if not agent.startswith("agent:") else agent
        if start not in after._nodes:
            raise TwinError(f"unknown agent: {agent}")

        cred_id = f"resource:{credential}"
        after.add_node(
            cred_id,
            "resource",
            credential,
            basis=Provenance.SIMULATED.value,
            attributes={"counterfactual": True, "exposed": True},
        )
        after.add_edge(
            start,
            cred_id,
            "accesses",
            basis=Provenance.SIMULATED.value,
        )

        deltas = self._deltas(base, after)
        radius = after.blast_radius(agent)
        return CounterfactualReport(
            kind="exposed_credential",
            title=title,
            description=(
                f"simulation: {agent} gains reach over {credential}. "
                "If this credential is real, treat it as compromised "
                "and rotate it."
            ),
            actions=[
                {"type": "expose_credential", "agent": agent, "credential": credential}
            ],
            reachability_deltas=deltas,
            blast_radius_after=radius,
            policy_changes=self._policy_changes(radius),
        )

    def run(
        self,
        kind: str,
        **kwargs: Any,
    ) -> CounterfactualReport:
        """Dispatch any supported counterfactual by name."""

        if kind == "compromised_agent":
            return self.compromise(kwargs["agent"], title=kwargs.get("title", "agent compromised"))
        if kind == "revoked_capability":
            return self.revoke_capability(
                kwargs["agent"], kwargs["capability"],
                title=kwargs.get("title", "capability revoked"),
            )
        if kind == "untrusted_tool":
            return self.untrust_tool(kwargs["tool"], title=kwargs.get("title", "tool untrusted"))
        if kind == "delegated_authority":
            return self.delegate(
                kwargs["grantor"], kwargs["grantee"],
                permissions=kwargs.get("permissions"),
                title=kwargs.get("title", "authority delegated"),
            )
        if kind == "exposed_credential":
            return self.expose_credential(
                kwargs["agent"], credential=kwargs.get("credential", "credential"),
                title=kwargs.get("title", "credential exposed"),
            )
        raise TwinError(f"unknown counterfactual kind: {kind}")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _deltas(
        self,
        before: AttackGraph,
        after: AttackGraph,
    ) -> tuple[ReachabilityDelta, ...]:
        deltas: list[ReachabilityDelta] = []

        def agent_labels(graph: AttackGraph) -> set[str]:
            return {
                node.label
                for node in graph._nodes.values()
                if node.type == "agent"
            }

        agents = sorted(agent_labels(before) | agent_labels(after))
        for agent in agents:
            try:
                before_reach = before.reachable(agent)
            except Exception:
                continue
            after_reach = after.reachable(agent)
            delta = ReachabilityDelta(
                agent=agent,
                added_capabilities=tuple(
                    sorted(set(after_reach["capabilities"]) - set(before_reach["capabilities"]))
                ),
                removed_capabilities=tuple(
                    sorted(set(before_reach["capabilities"]) - set(after_reach["capabilities"]))
                ),
                added_resources=tuple(
                    sorted(set(after_reach["resources"]) - set(before_reach["resources"]))
                ),
                removed_resources=tuple(
                    sorted(set(before_reach["resources"]) - set(after_reach["resources"]))
                ),
                added_tools=tuple(
                    sorted(set(after_reach["tools"]) - set(before_reach["tools"]))
                ),
                removed_tools=tuple(
                    sorted(set(before_reach["tools"]) - set(after_reach["tools"]))
                ),
            )
            if (
                delta.added_capabilities
                or delta.removed_capabilities
                or delta.added_resources
                or delta.removed_resources
                or delta.added_tools
                or delta.removed_tools
            ):
                deltas.append(delta)
        return tuple(deltas)

    def _containment_opportunities(
        self,
        graph: AttackGraph,
        compromised: str,
    ) -> tuple[dict[str, Any], ...]:
        """Which agents, if contained, would cut the compromised agent's
        sensitive reach."""

        opportunities: list[dict[str, Any]] = []
        radius = graph.blast_radius(compromised)
        sensitive = set(radius["sensitive_targets"])
        if not sensitive:
            return ()
        for agent in graph.agent_ids():
            if agent == f"agent:{compromised}":
                continue
            try:
                reach = graph.reachable(agent)
            except Exception:
                continue
            cut = sensitive & set(reach["resources"]) | (
                sensitive & set(reach["capabilities"])
            )
            if cut:
                opportunities.append(
                    {
                        "contain": agent,
                        "cuts": sorted(cut),
                        "effect": (
                            f"containing {agent} removes {len(cut)} "
                            "sensitive target(s) from the compromised "
                            "agent's path"
                        ),
                        "basis": Provenance.SIMULATED.value,
                    }
                )
        return tuple(opportunities[:10])

    @staticmethod
    def _policy_changes(radius: dict[str, Any]) -> tuple[dict[str, Any], ...]:
        changes: list[dict[str, Any]] = []
        if radius.get("sensitive_targets"):
            changes.append(
                {
                    "policy": "revoke_sensitive_reach",
                    "effect": (
                        "revoke or attenuate the capabilities reaching "
                        + ", ".join(radius["sensitive_targets"][:3])
                    ),
                    "basis": Provenance.SIMULATED.value,
                }
            )
        return tuple(changes)
