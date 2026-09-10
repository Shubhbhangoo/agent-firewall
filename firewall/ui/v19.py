"""v1.9 Security Operations projections for the browser console.

The SOC panel answers, in the browser, the same questions the v1.9 CLI
answers: what agents exist in the network, what is each capable of,
what is suspicious (behavioral detections), what attack paths exist,
what would happen under a scenario (simulator), and what the response
policy would do.

Everything is derived from verified artifacts through
:mod:`firewall.network`; the browser never recomputes security state.
Scenario simulation runs in isolated workspaces. Responses go through
the audited control plane.
"""

from __future__ import annotations

from typing import Any, Optional

from firewall.network import (
    AgentNetworkGraph,
    AttackPathAnalyzer,
    CorrelationIndex,
    ResponseController,
    Scenario,
    Simulator,
    analyze_index,
)
from firewall.network.behavior import Detection
from firewall.network.response import ResponseRule


def build_demo_network() -> CorrelationIndex:
    """A demo network made of genuinely recorded sessions.

    Two correlated sessions: one with a delegation to an unknown agent,
    repeated denials, and a credential-shaped access; one ordinary
    session sharing a correlation id. Everything the SOC shows is real
    recorded material, not mock JSON.
    """

    from firewall.containment import (
        ContainmentAction,
        ContainmentController,
    )
    from firewall.recorder import FlightRecorder
    from firewall.risk_context import RiskContext
    from firewall.sdk import FirewallSDK

    index = CorrelationIndex()

    # Session 1: suspicious activity.
    recorder = FlightRecorder(
        session_id="soc-demo-1", agent="agent-alpha"
    )
    recorder.set_meta("correlation_id", "soc-campaign")
    sdk = FirewallSDK(recorder=recorder, risk_context=RiskContext())
    sdk.generate_key("soc-demo")
    capability = sdk.issue(
        agent="agent-alpha",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    sdk.authorize(
        capability, "payments.send", {"amount": 20, "path": "/tmp/data"}
    )
    for _ in range(6):
        sdk.authorize(capability, "payments.send", {"amount": 99999})
    sdk.authorize(
        capability, "payments.send", {"path": "/etc/shadow"}
    )
    child = sdk.delegate(
        capability,
        sdk.active_key().private_key,
        delegatee="ghost-agent",
    ).child
    controller = ContainmentController(
        sdk,
        recorder=recorder,
        authorizer=lambda: True,
    )
    controller.apply(
        ContainmentAction.QUARANTINE_AGENT,
        "agent-alpha",
        actor="console",
        reason="soc demo containment",
    )
    recorder.finalize(note="soc demo session 1")
    index.ingest(recorder.artifact(), artifact_id="soc-demo-1")

    # Session 2: ordinary, same campaign.
    recorder2 = FlightRecorder(
        session_id="soc-demo-2", agent="agent-beta"
    )
    recorder2.set_meta("correlation_id", "soc-campaign")
    sdk2 = FirewallSDK(recorder=recorder2)
    sdk2.generate_key("soc-demo")
    cap2 = sdk2.issue(agent="agent-beta", capability="files.read")
    sdk2.authorize(
        cap2, "files.read", {"path": "/tmp/data"}
    )
    recorder2.finalize(note="soc demo session 2")
    index.ingest(recorder2.artifact(), artifact_id="soc-demo-2")

    return index


class SocProjection:
    """Read/write projections over a CorrelationIndex for the browser."""

    def __init__(
        self,
        index: CorrelationIndex,
    ) -> None:
        if not isinstance(index, CorrelationIndex):
            raise TypeError("index must be a CorrelationIndex")
        self._index = index
        self._graph: Optional[AgentNetworkGraph] = None
        self._analyzer: Optional[AttackPathAnalyzer] = None

    # ------------------------------------------------------------------
    # Cached derived objects
    # ------------------------------------------------------------------

    def graph(self) -> AgentNetworkGraph:
        if self._graph is None:
            self._graph = self._index.graph()
        return self._graph

    def analyzer(self) -> AttackPathAnalyzer:
        if self._analyzer is None:
            self._analyzer = AttackPathAnalyzer(self.graph())
        return self._analyzer

    # ------------------------------------------------------------------
    # Read-only overview
    # ------------------------------------------------------------------

    def overview(self) -> dict[str, Any]:
        graph = self.graph()
        detections = analyze_index(self._index)

        agents: dict[str, dict[str, Any]] = {}

        for node in graph.nodes():
            if node.type.value != "agent":
                continue
            try:
                reachable = graph.reachable(node.label)
                reach = {
                    "capabilities": list(reachable.capabilities),
                    "tools": list(reachable.tools),
                    "resources": list(reachable.resources),
                    "allowed_actions": list(
                        reachable.allowed_actions
                    ),
                }
            except Exception:
                reach = {}

            detections_for = [
                detection.to_dict()
                for detection in detections
                if node.label in detection.agents
            ]

            agents[node.label] = {
                "agent": node.label,
                "reachable": reach,
                "detections": detections_for,
                "basis": node.basis.value,
            }

        bundles = [
            bundle.to_dict() for bundle in self._index.bundles()
        ]

        sensitive = self.analyzer().summarize()

        return {
            "agents": agents,
            "detections": [
                detection.to_dict() for detection in detections
            ],
            "bundles": bundles,
            "sensitive_resources": sensitive[
                "sensitive_resources"
            ],
            "graph": graph.to_dict(),
            "verified_artifacts": list(
                self._index.verified_ids()
            ),
        }

    def agents(self) -> list[dict[str, Any]]:
        return sorted(
            self.overview()["agents"].values(),
            key=lambda entry: entry["agent"],
        )

    # ------------------------------------------------------------------
    # Attack paths
    # ------------------------------------------------------------------

    def attack_paths(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")

        target = payload.get("target")
        agent = payload.get("agent")
        summary = bool(payload.get("summary", False))

        if summary:
            return {
                "summary": self.analyzer().summarize(),
            }

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target is required")

        if isinstance(agent, str) and agent.strip():
            path = self.analyzer().shortest_path_to(agent, target)
            return {
                "agent": agent,
                "target": target,
                "path": path.to_dict() if path is not None else None,
                "break_suggestions": (
                    self.analyzer().break_path(path)
                    if path is not None
                    else []
                ),
            }

        paths = self.analyzer().paths_to(target)
        return {
            "target": target,
            "paths": [path.to_dict() for path in paths],
        }

    # ------------------------------------------------------------------
    # Scenario simulation (read-only, isolated)
    # ------------------------------------------------------------------

    def simulate(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")

        scenario = Scenario(
            scenario_id=(
                payload.get("scenario_id") or "browser-scenario"
            ),
            kind=payload.get("kind", "compromised_agent"),
            title=(
                payload.get("title") or "browser scenario"
            ),
            agent=payload.get("agent") or "",
            added_capabilities=tuple(
                payload.get("added_capabilities") or ()
            ),
            removed_capabilities=tuple(
                payload.get("removed_capabilities") or ()
            ),
            policy=dict(payload.get("policy") or {}),
            containment=payload.get("containment", "none"),
            added_tools=tuple(payload.get("added_tools") or ()),
        )

        simulator = Simulator(self.graph())
        report = simulator.simulate(scenario)
        return report.to_dict()

    # ------------------------------------------------------------------
    # Response (control-plane write)
    # ------------------------------------------------------------------

    def respond(
        self,
        payload: dict[str, Any],
        *,
        containment=None,
    ) -> dict[str, Any]:
        """Evaluate detections against a policy and apply responses.

        Requires a real containment controller (supplied by the control
        plane, gated by the bearer token).
        """

        if containment is None:
            raise ValueError(
                "response requires the audited containment controller"
            )

        policy_data = payload.get("policy")

        if not isinstance(policy_data, dict):
            raise ValueError("policy must be an object with 'rules'")

        rules = [
            ResponseRule(
                rule_id=entry["rule_id"],
                min_severity=entry.get("min_severity", "medium"),
                stage=entry.get("stage", "observe"),
                auto_approve=bool(entry.get("auto_approve", False)),
            )
            for entry in policy_data.get("rules", [])
            if isinstance(entry, dict) and entry.get("rule_id")
        ]

        from firewall.recorder import FlightRecorder

        controller = ResponseController(
            containment,
            approver=(
                lambda stage: True
                if payload.get("approve_all")
                else None
            ),
        )

        for rule in rules:
            controller.add_rule(rule)

        detections = analyze_index(self._index)

        rule_filter = payload.get("rule")
        severity = payload.get("min_severity")

        if isinstance(rule_filter, str) and rule_filter:
            detections = [
                detection
                for detection in detections
                if detection.rule_id == rule_filter
            ]

        if isinstance(severity, str):
            rank = {
                "low": 0,
                "medium": 1,
                "high": 2,
                "critical": 3,
            }
            minimum = rank.get(severity, 0)
            detections = [
                detection
                for detection in detections
                if rank.get(detection.severity, 0) >= minimum
            ]

        records = []

        for detection in detections:
            try:
                records.append(
                    controller.respond(detection, actor="console")
                )
            except Exception as exc:
                records.append(
                    {
                        "rule_id": detection.rule_id,
                        "error": str(exc),
                    }
                )

        return {
            "records": [
                record.to_dict()
                if hasattr(record, "to_dict")
                else record
                for record in records
            ],
            "snapshot": controller.snapshot(),
        }
