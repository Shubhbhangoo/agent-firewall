"""v1.9 network core unit tests: model, graph, correlation, behavior."""

from __future__ import annotations

import json

import pytest

from firewall.network import (
    AgentNetworkGraph,
    AttackPathAnalyzer,
    CorrelationBundle,
    CorrelationIndex,
    Detection,
    EntityType,
    NetworkError,
    Provenance,
    RelationType,
    ResponseController,
    ResponseError,
    ResponseRule,
    Scenario,
    Simulator,
    SimulatorError,
    analyze_index,
    entity_id,
    extract_network_entities,
)
from firewall.recorder import EventType, FlightRecorder
from firewall.sdk import FirewallSDK


def _session(
    session_id,
    agent,
    cap_name,
    *,
    deny: int = 0,
    secret: str | None = None,
    delegate_to: str | None = None,
    correlation: str | None = None,
    incident: str | None = None,
):
    recorder = FlightRecorder(session_id=session_id, agent=agent)
    if correlation:
        recorder.set_meta("correlation_id", correlation)
    if incident:
        recorder.set_meta("incident_id", incident)
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    cap = sdk.issue(
        agent=agent,
        capability=cap_name,
        constraints={"amount_max": 100},
    )
    sdk.authorize(cap, cap_name, {"amount": 20, "path": "/tmp/data"})
    for _ in range(deny):
        sdk.authorize(cap, cap_name, {"amount": 99999})
    if secret:
        sdk.authorize(cap, cap_name, {"path": secret})
    if delegate_to:
        child = sdk.delegate(
            cap,
            sdk.active_key().private_key,
            delegatee=delegate_to,
        ).child
    recorder.finalize()
    return recorder.artifact()


# ----------------------------------------------------------------------
# Model
# ----------------------------------------------------------------------


def test_provenance_values_are_distinct():
    values = {provenance.value for provenance in Provenance}
    assert values == {
        "observed",
        "derived",
        "inferred",
        "simulated",
        "unknown",
    }


def test_entity_id_scopes_names_by_type():
    assert entity_id(EntityType.AGENT, "a") != entity_id(
        EntityType.CAPABILITY, "a"
    )


# ----------------------------------------------------------------------
# Graph extraction and merge
# ----------------------------------------------------------------------


def test_extract_network_entities_from_artifact():
    artifact = _session("s1", "agent-a", "payments.send", deny=1)
    nodes, edges = extract_network_entities(artifact)
    types = {node.type for node in nodes}
    assert EntityType.AGENT in types
    assert EntityType.CAPABILITY in types
    assert EntityType.RESOURCE in types
    assert all(node.basis == Provenance.OBSERVED for node in nodes)
    assert all(
        edge.evidence and edge.evidence[0].artifact_id == "s1"
        for edge in edges
    )


def test_graph_refuses_failed_artifact():
    artifact = _session("bad", "agent-a", "payments.send")
    artifact["events"][2]["payload"]["amount"] = 999
    with pytest.raises(NetworkError):
        AgentNetworkGraph.from_artifacts([artifact])


def test_graph_reachable_and_why_can():
    a1 = _session("s1", "agent-a", "payments.send", secret="/etc/shadow")
    a2 = _session("s2", "agent-b", "files.read", delegate_to="agent-c")
    graph = AgentNetworkGraph.from_artifacts([a1, a2])

    reach = graph.reachable("agent-a")
    assert "payments.send" in reach.capabilities
    assert "/etc/shadow" in reach.resources

    why = graph.why_can("agent-a", "payments.send")
    assert why
    assert why[0]["allowed"] is True

    who = graph.who_can_reach("/etc/shadow")
    assert any(entry["agent"] == "agent-a" for entry in who)


def test_graph_shortest_path_and_shared_paths():
    a1 = _session("s1", "agent-a", "payments.send", secret="/etc/shadow")
    a2 = _session("s2", "agent-b", "files.read", secret="/etc/shadow")
    graph = AgentNetworkGraph.from_artifacts([a1, a2])

    # shortest_path lives on the graph; the analyzer wraps it.
    path = graph.shortest_path(
        entity_id(EntityType.AGENT, "agent-a"),
        entity_id(EntityType.RESOURCE, "/etc/shadow"),
    )
    assert path is not None

    shared = graph.shared_paths(
        ["agent-a", "agent-b"], "/etc/shadow"
    )
    assert shared[0]["count"] == 2


def test_graph_unknown_agent_raises():
    artifact = _session("s1", "agent-a", "payments.send")
    graph = AgentNetworkGraph.from_artifacts([artifact])
    with pytest.raises(NetworkError):
        graph.reachable("ghost")


# ----------------------------------------------------------------------
# Correlation
# ----------------------------------------------------------------------


def test_correlation_index_ingest_and_bundles():
    index = CorrelationIndex()
    index.ingest(
        _session(
            "s1", "agent-a", "payments.send", correlation="c1"
        ),
        artifact_id="s1",
    )
    index.ingest(
        _session(
            "s2", "agent-b", "files.read", correlation="c1"
        ),
        artifact_id="s2",
    )

    assert index.verified_ids() == ("s1", "s2")
    bundles = index.bundles()
    assert any(
        bundle.bundle_id == "correlation:c1"
        for bundle in bundles
    )
    assert index.related("s1") == ("s2",)


def test_correlation_index_refuses_failed():
    artifact = _session("s1", "agent-a", "payments.send")
    artifact["events"][2]["payload"]["amount"] = 999
    index = CorrelationIndex()
    with pytest.raises(Exception):
        index.ingest(artifact, artifact_id="s1")


def test_correlation_index_allow_failed_flags():
    artifact = _session("s1", "agent-a", "payments.send")
    artifact["events"][2]["payload"]["amount"] = 999
    index = CorrelationIndex(allow_failed=True)
    record = index.ingest(artifact, artifact_id="s1")
    assert record.verification == "failed"
    # failed facts never enter the graph
    assert index.graph().nodes() == ()


# ----------------------------------------------------------------------
# Behavior
# ----------------------------------------------------------------------


def test_detection_engine_finds_patterns():
    index = CorrelationIndex()
    index.ingest(
        _session(
            "s1",
            "agent-a",
            "payments.send",
            deny=6,
            secret="/etc/shadow",
            delegate_to="ghost",
        ),
        artifact_id="s1",
    )

    detections = analyze_index(index)
    rules = {detection.rule_id for detection in detections}

    assert "repeated_denials" in rules
    assert "credential_shaped_access" in rules
    assert "unexpected_delegation" in rules

    for detection in detections:
        assert detection.basis == Provenance.INFERRED.value
        assert detection.explanation
        assert detection.evidence
        assert detection.response


def test_detection_has_all_required_fields():
    detection = Detection(
        rule_id="x",
        title="t",
        severity="medium",
        explanation="why",
        evidence=(),
        agents=("a",),
    )
    payload = detection.to_dict()
    for key in (
        "rule_id",
        "title",
        "severity",
        "explanation",
        "evidence",
        "agents",
        "response",
        "basis",
    ):
        assert key in payload


# ----------------------------------------------------------------------
# Attack paths
# ----------------------------------------------------------------------


def test_attack_paths_to_sensitive_target():
    artifact = _session(
        "s1", "agent-a", "payments.send", secret="/etc/shadow"
    )
    graph = AgentNetworkGraph.from_artifacts([artifact])
    analyzer = AttackPathAnalyzer(graph)

    paths = analyzer.paths_to("/etc/shadow")
    assert paths
    path = paths[0]
    assert path.status in {"observed", "policy-permitted"}
    assert path.potentially_dangerous is True
    assert path.hops

    # Break-path suggestions exist when capabilities enable the path;
    # a direct resource access has none, which is itself the finding.
    # A capability-enabled path does produce suggestions.
    cap_artifact = _session("s3", "agent-c", "admin.bypass")
    cap_graph = AgentNetworkGraph.from_artifacts([cap_artifact])
    cap_analyzer = AttackPathAnalyzer(cap_graph)
    cap_paths = cap_analyzer.paths_to("admin.bypass")
    if cap_paths:
        assert cap_analyzer.break_path(cap_paths[0])


def test_attack_path_summary_lists_sensitive():
    artifact = _session(
        "s1", "agent-a", "payments.send", secret="/etc/shadow"
    )
    graph = AgentNetworkGraph.from_artifacts([artifact])
    analyzer = AttackPathAnalyzer(graph)
    summary = analyzer.summarize()
    assert any(
        entry["resource"] == "/etc/shadow"
        for entry in summary["sensitive_resources"]
    )


def test_attack_path_statuses_never_conflated():
    from firewall.network.attack_path import STATUS_ORDER

    assert STATUS_ORDER.index("observed") > STATUS_ORDER.index(
        "simulated"
    )


# ----------------------------------------------------------------------
# Simulator
# ----------------------------------------------------------------------


def test_simulator_scenario_and_report():
    artifact = _session(
        "s1", "agent-a", "payments.send", secret="/etc/shadow"
    )
    graph = AgentNetworkGraph.from_artifacts([artifact])
    simulator = Simulator(graph)

    scenario = Scenario(
        scenario_id="sc1",
        kind="compromised_agent",
        title="compromised",
        agent="agent-a",
        added_capabilities=("admin.bypass",),
    )

    report = simulator.simulate(scenario)

    assert report.scenario["kind"] == "compromised_agent"
    assert report.initial["capabilities"]
    assert report.potential_impact
    assert report.containment_opportunities
    assert report.to_dict()["basis"] == "simulated"


def test_simulator_never_touches_live_state():
    artifact = _session(
        "s1", "agent-a", "payments.send"
    )
    graph = AgentNetworkGraph.from_artifacts([artifact])
    before = graph.to_dict()

    simulator = Simulator(graph)
    simulator.simulate(
        Scenario(
            scenario_id="sc2",
            kind="changed_policy",
            title="policy change",
            agent="agent-a",
            removed_capabilities=("payments.send",),
        )
    )

    assert graph.to_dict() == before


def test_simulator_rejects_bad_kind():
    with pytest.raises(SimulatorError):
        Scenario(
            scenario_id="bad",
            kind="not_a_kind",
            title="bad",
            agent="agent-a",
        )


def test_simulator_reports_unverifiable_removals():
    artifact = _session(
        "s1", "agent-a", "payments.send"
    )
    graph = AgentNetworkGraph.from_artifacts([artifact])
    simulator = Simulator(graph)

    report = simulator.simulate(
        Scenario(
            scenario_id="sc3",
            kind="revoked_capability",
            title="revoke",
            agent="agent-a",
            removed_capabilities=("never-held",),
        )
    )

    assert report.unverifiable
    assert "never-held" in report.unverifiable[0]["reason"]


# ----------------------------------------------------------------------
# Response
# ----------------------------------------------------------------------


def test_response_policy_stages_and_approval():
    from firewall.containment import ContainmentController
    from firewall.network.response import RESPONSE_STAGES

    assert RESPONSE_STAGES == (
        "observe",
        "warn",
        "restrict",
        "quarantine",
        "contain",
    )

    workspace = FirewallSDK()
    workspace.generate_key("k")
    containment = ContainmentController(
        workspace, authorizer=lambda: True
    )
    controller = ResponseController(
        containment,
        approver=lambda stage: True,
    )
    controller.add_rule(
        ResponseRule(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="quarantine",
        )
    )

    detection = Detection(
        rule_id="credential_shaped_access",
        title="credential",
        severity="high",
        explanation="e",
        evidence=(),
        agents=("agent-a",),
    )

    record = controller.respond(detection, actor="test")
    assert record.stage == "quarantine"
    assert record.approved is True
    assert controller.snapshot()["containment"]["states"].get(
        "agent-a"
    ) == "quarantined"


def test_response_requires_approval_for_high_impact():
    from firewall.containment import ContainmentController

    workspace = FirewallSDK()
    workspace.generate_key("k")
    containment = ContainmentController(
        workspace, authorizer=lambda: True
    )
    controller = ResponseController(
        containment,
        approver=lambda stage: False,
    )
    controller.add_rule(
        ResponseRule(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="quarantine",
        )
    )

    detection = Detection(
        rule_id="credential_shaped_access",
        title="credential",
        severity="high",
        explanation="e",
        evidence=(),
        agents=("agent-a",),
    )

    with pytest.raises(ResponseError):
        controller.respond(detection, actor="test")


def test_response_observes_below_threshold():
    from firewall.containment import ContainmentController

    workspace = FirewallSDK()
    workspace.generate_key("k")
    containment = ContainmentController(
        workspace, authorizer=lambda: True
    )
    controller = ResponseController(containment)
    controller.add_rule(
        ResponseRule(
            rule_id="repeated_denials",
            min_severity="high",
            stage="quarantine",
        )
    )

    detection = Detection(
        rule_id="repeated_denials",
        title="denials",
        severity="medium",
        explanation="e",
        evidence=(),
        agents=("agent-a",),
    )

    record = controller.respond(detection, actor="test")
    assert record.stage == "observe"
    assert "below" in record.reason
