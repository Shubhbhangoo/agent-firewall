"""v2.1 defense projections for the browser console.

Builds a self-contained demo workspace (fresh identities, SDK, mesh,
containment, evidence graph, twin, immune system) so the v2.1 panel is
fully functional read-only in demo mode and reflects live state when an
SDK is attached. All analysis is labeled with its basis; nothing here
authorizes anything.
"""

from __future__ import annotations

from typing import Any, Optional

from firewall.defense import DefenseMesh
from firewall.evidence_graph import (
    EvidenceGraph,
    KeyEvidenceSigner,
)
from firewall.ident import IdentityRegistry
from firewall.immune import (
    ImmunePolicy,
    ImmuneRule,
    ImmuneSignal,
    ImmuneSystem,
)
from firewall.posture import PostureEngine
from firewall.sdk import FirewallSDK


class _Workspace:
    """One demo workspace backing the v2.1 panel."""

    def __init__(self) -> None:
        self.identities = IdentityRegistry()
        self.posture = PostureEngine()
        self.evidence = EvidenceGraph(signer=KeyEvidenceSigner())
        self.sdk = FirewallSDK()

        self.identities.create("agent-orchestrator")
        self.identities.create("agent-worker")
        self.sdk.generate_key("v21-demo-key")
        self.sdk.issue(
            agent="agent-orchestrator",
            capability="orchestrate.tasks",
            constraints={"max_workers": 3},
        )
        self.sdk.issue(
            agent="agent-worker",
            capability="worker.execute",
            constraints={"max_parallel": 2},
        )

        self.mesh = DefenseMesh(
            self.identities,
            posture=self.posture,
            attest=None,
        )
        self.mesh.attach_sdk(self.sdk)

        self.immune = ImmuneSystem(
            self.mesh,
            posture=self.posture,
            evidence_graph=self.evidence,
        )
        self.immune.set_policy(
            ImmunePolicy(
                rules=(
                    ImmuneRule(
                        "compromised_posture",
                        stage="quarantine",
                        min_severity="high",
                        auto_approve=False,
                    ),
                    ImmuneRule(
                        "repeated_denials",
                        stage="restrict",
                        min_severity="medium",
                        auto_approve=False,
                    ),
                )
            )
        )


class DefensePanelV21:
    """Read-only projections over the v2.1 subsystems."""

    def __init__(self) -> None:
        self._workspace: Optional[_Workspace] = None

    def _ws(self) -> _Workspace:
        if self._workspace is None:
            self._workspace = _Workspace()
        return self._workspace

    # ------------------------------------------------------------------
    # Defense mesh
    # ------------------------------------------------------------------

    def mesh_view(self) -> dict[str, Any]:
        ws = self._ws()
        states = []
        for agent in ws.identities.agent_ids():
            evaluation = ws.mesh.evaluate(agent)
            states.append(evaluation.to_dict())
        return {
            "states": states,
            "quarantine_threshold": 0.35,
            "basis": "observed",
        }

    # ------------------------------------------------------------------
    # A2A zero trust
    # ------------------------------------------------------------------

    def a2a_view(self) -> dict[str, Any]:
        from firewall.a2a import AgentToAgent

        ws = self._ws()
        a2a = AgentToAgent(ws.identities)
        graph = a2a.trust_graph()
        return {
            "relationships": graph["relationships"],
            "count": len(graph["relationships"]),
            "note": (
                "no relationships established in this demo; use the CLI "
                "`delegate establish` to create scoped trust"
            ),
            "basis": "observed",
        }

    # ------------------------------------------------------------------
    # Attack graph
    # ------------------------------------------------------------------

    def attack_graph_view(self) -> dict[str, Any]:
        from firewall.attackgraph import AttackGraph

        ws = self._ws()
        graph = AttackGraph()
        for identity in ws.identities.all():
            graph.add_node(
                f"agent:{identity.agent_id}",
                "agent",
                identity.agent_id,
                basis="observed",
                attributes={"status": identity.status},
            )
            graph.add_node(
                f"identity:{identity.agent_id}",
                "identity",
                identity.agent_id,
                basis="observed",
            )
            graph.add_edge(
                f"agent:{identity.agent_id}",
                f"identity:{identity.agent_id}",
                "has_identity",
                basis="observed",
            )
        for capability in ws.sdk.known_capabilities().values():
            if capability.agent_id not in ws.identities.agent_ids():
                continue
            cap_id = f"capability:{capability.capability}"
            if graph.node(cap_id) is None:
                graph.add_node(
                    cap_id,
                    "capability",
                    capability.capability,
                    basis="observed",
                )
            graph.add_edge(
                cap_id,
                f"agent:{capability.agent_id}",
                "holds",
                basis="observed",
                attributes={"constraints": dict(capability.constraints or {})},
            )
            if capability.tool:
                tool_id = f"tool:{capability.tool}"
                if graph.node(tool_id) is None:
                    graph.add_node(
                        tool_id,
                        "tool",
                        capability.tool,
                        basis="observed",
                    )
                graph.add_edge(
                    cap_id, tool_id, "bound_to", basis="observed"
                )

        return {
            "summary": graph.summarize(),
            "findings": [
                f.to_dict() for f in graph.escalation_paths()
            ],
            "chokepoints": graph.chokepoints(),
            "basis": "derived",
        }

    # ------------------------------------------------------------------
    # Digital twin
    # ------------------------------------------------------------------

    def twin_simulate(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        from firewall.attackgraph import AttackGraph
        from firewall.twin import SecurityTwin

        agent = payload.get("agent")
        if not isinstance(agent, str) or not agent.strip():
            return {"error": "agent is required", "basis": "unknown"}

        ws = self._ws()
        if agent not in ws.identities.agent_ids():
            return {
                "error": f"unknown agent: {agent}",
                "basis": "unknown",
            }

        def source() -> AttackGraph:
            return self._build_graph()

        twin = SecurityTwin(source)
        report = twin.compromise(agent)
        return report.to_dict()

    def _build_graph(self):
        from firewall.attackgraph import AttackGraph

        ws = self._ws()
        graph = AttackGraph()
        for identity in ws.identities.all():
            graph.add_node(
                f"agent:{identity.agent_id}",
                "agent",
                identity.agent_id,
                basis="observed",
            )
        for capability in ws.sdk.known_capabilities().values():
            cap_id = f"capability:{capability.capability}"
            if graph.node(cap_id) is None:
                graph.add_node(
                    cap_id,
                    "capability",
                    capability.capability,
                    basis="observed",
                )
            graph.add_edge(
                cap_id,
                f"agent:{capability.agent_id}",
                "holds",
                basis="observed",
            )
        return graph

    # ------------------------------------------------------------------
    # Evidence graph
    # ------------------------------------------------------------------

    def evidence_view(self) -> dict[str, Any]:
        ws = self._ws()
        events = ws.evidence.events()
        return {
            "events": [e.to_dict() for e in events[-20:]],
            "total": len(events),
            "verification": ws.evidence.verify(),
            "subjects": list(ws.evidence.subjects()),
        }

    # ------------------------------------------------------------------
    # Immune system
    # ------------------------------------------------------------------

    def immune_view(self) -> dict[str, Any]:
        ws = self._ws()
        return {
            "policy": ws.immune.policy(),
            "signals": [s.to_dict() for s in ws.immune.signals()],
            "detections": [d.to_dict() for d in ws.immune.detections()],
            "actions": [a.to_dict() for a in ws.immune.actions()],
            "loop": [
                "observe", "detect", "reason", "simulate",
                "contain", "recover", "verify",
            ],
            "authorization_model": (
                "reasoning is advisory; execution requires a "
                "deterministic policy rule"
            ),
        }

    def immune_cycle(self) -> dict[str, Any]:
        """Run one detection cycle over the demo workspace's current
        state and return the transcript."""

        ws = self._ws()
        ws.immune.observe(
            ImmuneSignal(
                "agent-worker",
                "authorization_denial",
                "denied attempt recorded by the mesh",
                "medium",
            )
        )
        result = ws.immune.run_cycle(agent="agent-worker")
        return {
            "cycle": result["cycle"],
            "state": self.immune_view(),
        }

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def system(self) -> dict[str, Any]:
        return {
            "v21_available": True,
            "basis": "derived",
        }
