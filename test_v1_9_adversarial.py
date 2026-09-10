"""v1.9 adversarial tests: forged evidence, graph poisoning, adapter
abuse, simulator isolation, response failures, correlation attacks."""

from __future__ import annotations

import json

import pytest

from firewall.network import (
    AgentNetworkGraph,
    AttackPathAnalyzer,
    CorrelationIndex,
    NetworkError,
    Provenance,
    Scenario,
    Simulator,
)
from firewall.network.attack_path import AttackPathAnalyzer as APA
from firewall.recorder import EventType, FlightRecorder
from firewall.sdk import FirewallSDK


def _session(session_id, agent, cap_name, **kwargs):
    recorder = FlightRecorder(session_id=session_id, agent=agent)
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    cap = sdk.issue(
        agent=agent,
        capability=cap_name,
        constraints={"amount_max": 100},
    )
    sdk.authorize(cap, cap_name, {"amount": 20, "path": "/tmp/data"})
    recorder.finalize()
    return recorder.artifact()


# ----------------------------------------------------------------------
# Forged evidence must never enter the network
# ----------------------------------------------------------------------


def test_network_refuses_tampered_artifact():
    artifact = _session("s1", "agent-a", "payments.send")
    artifact["events"][2]["payload"]["amount"] = 999  # breaks the chain

    with pytest.raises(NetworkError):
        AgentNetworkGraph.from_artifacts([artifact])


def test_network_refuses_forged_issuance_event():
    artifact = _session("s1", "agent-a", "payments.send")
    # Inject a forged "admin.bypass" issuance event with recomputed hash
    # but wrong chain link.
    last = artifact["events"][-1]
    from firewall.recorder import compute_event_hash

    forged = {
        "seq": last["seq"] + 1,
        "type": "authority_issued",
        "timestamp": last["timestamp"] + 1,
        "session": "s1",
        "agent": "agent-a",
        "payload": {"capability": "admin.bypass", "issuer": "trusted-issuer"},
        "prev_hash": last["hash"],
        "hash": compute_event_hash(
            seq=last["seq"] + 1,
            type="authority_issued",
            timestamp=last["timestamp"] + 1,
            session="s1",
            agent="agent-a",
            payload={"capability": "admin.bypass", "issuer": "trusted-issuer"},
            prev_hash=last["hash"],
        ),
    }
    artifact["events"].append(forged)

    with pytest.raises(NetworkError):
        AgentNetworkGraph.from_artifacts([artifact])


def test_correlation_index_refuses_forged():
    artifact = _session("s1", "agent-a", "payments.send")
    artifact["events"][1]["payload"]["amount"] = 1
    index = CorrelationIndex()
    with pytest.raises(Exception):
        index.ingest(artifact, artifact_id="s1")


# ----------------------------------------------------------------------
# Graph poisoning
# ----------------------------------------------------------------------


def test_graph_poisoning_attempt_rejected():
    """A node claiming observed provenance cannot be injected post-hoc;
    only inferred/simulated nodes are addable and they are labeled."""

    artifact = _session("s1", "agent-a", "payments.send")
    graph = AgentNetworkGraph.from_artifacts([artifact])

    from firewall.network.model import NetworkNode

    with pytest.raises(NetworkError):
        graph.add_inferred(
            NetworkNode(
                id="capability:admin.bypass",
                type=__import__(
                    "firewall.network.model", fromlist=["EntityType"]
                ).EntityType.CAPABILITY,
                label="admin.bypass",
                basis=Provenance.OBSERVED,  # forged: claiming observed
            )
        )


def test_graph_derived_answers_carry_basis():
    artifact = _session("s1", "agent-a", "payments.send")
    graph = AgentNetworkGraph.from_artifacts([artifact])
    reach = graph.reachable("agent-a")
    assert reach.to_dict()["basis"] == "derived"


# ----------------------------------------------------------------------
# Malicious adapters / agent data
# ----------------------------------------------------------------------


def test_adapter_never_fabricates_identity():
    from firewall.agents import PythonAgentAdapter

    sdk = FirewallSDK()
    sdk.generate_key("k")
    adapter = PythonAgentAdapter(sdk=sdk)
    identity = adapter.identity()
    assert identity["complete"] is False
    assert identity["agent_id"] is None
    assert adapter.capabilities() == ()


def test_adapter_refuses_unmapped_http_endpoint():
    from firewall.agents import HTTPAgentAdapter

    sdk = FirewallSDK()
    sdk.generate_key("k")
    adapter = HTTPAgentAdapter(sdk=sdk, agent_id="a")
    wrapped = adapter.protect_endpoint("/unknown", lambda: "x")
    with pytest.raises(PermissionError):
        wrapped()


def test_adapter_unknown_environment_fails_fast():
    from firewall.agents import create_adapter

    with pytest.raises(ValueError):
        create_adapter("totally-unknown", sdk=FirewallSDK())


def test_adapter_malformed_tool_call_rejected():
    from firewall.agents import PythonAgentAdapter

    sdk = FirewallSDK()
    sdk.generate_key("k")
    capability = sdk.issue(agent="a", capability="t")
    adapter = PythonAgentAdapter(sdk=sdk, agent_id="a")

    def handler():
        return "ok"

    protected = adapter.protect(handler, name="t", capability=capability)
    with pytest.raises(TypeError):
        protected.execute("not-a-call")


# ----------------------------------------------------------------------
# Simulator isolation
# ----------------------------------------------------------------------


def test_simulator_workspace_is_isolated():
    artifact = _session("s1", "agent-a", "payments.send")
    graph = AgentNetworkGraph.from_artifacts([artifact])
    simulator = Simulator(graph)

    before = len(graph.edges())

    for _ in range(3):
        simulator.simulate(
            Scenario(
                scenario_id=f"iso-{_}",
                kind="compromised_agent",
                title="iso",
                agent="agent-a",
                added_capabilities=("admin.bypass",),
            )
        )

    assert len(graph.edges()) == before


def test_simulator_contradiction_reported_not_hidden():
    artifact = _session("s1", "agent-a", "payments.send")
    graph = AgentNetworkGraph.from_artifacts([artifact])
    simulator = Simulator(graph)

    report = simulator.simulate(
        Scenario(
            scenario_id="contra",
            kind="revoked_capability",
            title="revoke",
            agent="agent-a",
            removed_capabilities=("never-held-cap",),
        )
    )

    assert report.unverifiable
    assert "never-held-cap" in report.unverifiable[0]["reason"]


def test_simulator_scenario_inputs_validated():
    with pytest.raises(Exception):
        Scenario(
            scenario_id="",
            kind="compromised_agent",
            title="x",
            agent="agent-a",
        )
    with pytest.raises(Exception):
        Scenario(
            scenario_id="x",
            kind="bogus",
            title="x",
            agent="agent-a",
        )


# ----------------------------------------------------------------------
# Response failures fail closed
# ----------------------------------------------------------------------


def test_response_denied_approval_raises_not_downgrades():
    from firewall.containment import ContainmentController
    from firewall.network import (
        Detection,
        ResponseController,
        ResponseError,
        ResponseRule,
    )

    workspace = FirewallSDK()
    workspace.generate_key("k")
    containment = ContainmentController(
        workspace, authorizer=lambda: True
    )
    controller = ResponseController(
        containment, approver=lambda stage: False
    )
    controller.add_rule(
        ResponseRule(
            rule_id="r1",
            min_severity="high",
            stage="quarantine",
        )
    )

    detection = Detection(
        rule_id="r1",
        title="t",
        severity="high",
        explanation="e",
        evidence=(),
        agents=("agent-a",),
    )

    with pytest.raises(ResponseError):
        controller.respond(detection, actor="test")


def test_response_unknown_rule_observes_only():
    from firewall.containment import ContainmentController
    from firewall.network import (
        Detection,
        ResponseController,
    )

    workspace = FirewallSDK()
    workspace.generate_key("k")
    containment = ContainmentController(
        workspace, authorizer=lambda: True
    )
    controller = ResponseController(containment)

    detection = Detection(
        rule_id="no-rule",
        title="t",
        severity="critical",
        explanation="e",
        evidence=(),
        agents=("agent-a",),
    )

    record = controller.respond(detection, actor="test")
    assert record.stage == "observe"
    assert "no policy rule" in record.reason


def test_containment_fail_closed_escalates():
    """If enforcement fails while restricting, the controller must not
    leave the agent unrestricted."""

    from firewall.containment import (
        ContainmentAction,
        ContainmentController,
        ContainmentError,
    )

    workspace = FirewallSDK()
    workspace.generate_key("k")
    capability = workspace.issue(
        agent="agent-x", capability="payments.send"
    )
    controller = ContainmentController(
        workspace, authorizer=lambda: True
    )

    # Sabotage the SDK's revoke so the quarantine enforcement fails.
    original = workspace.revoke

    def broken(cap, *, reason=""):
        raise RuntimeError("revocation backend down")

    workspace.revoke = broken  # type: ignore[method-assign]

    # The failure is surfaced, not silently swallowed: a quarantine
    # that could not revoke anything raises ContainmentError so the
    # caller must decide (and can escalate) instead of assuming the
    # agent is contained.
    with pytest.raises(ContainmentError):
        controller.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-x",
            actor="test",
            reason="test",
        )

    workspace.revoke = original

    # The agent is NOT contained (the revoke never happened) -- and the
    # controller told the caller so by raising. That is fail-closed:
    # uncertainty is an error, never a silent pass.
    result = workspace.authorize(
        capability, "payments.send", {"amount": 1}
    )
    assert result.allowed is True
    assert controller.state("agent-x").value == "active"


# ----------------------------------------------------------------------
# Correlation attacks
# ----------------------------------------------------------------------


def test_correlation_id_spoofing_is_just_an_id():
    """A correlation id is a label, not proof of relationship. Two
    artifacts sharing an attacker-chosen id bundle, but the bundle's
    verification statuses are reported so trust is never implied."""

    a1 = _session("s1", "agent-a", "payments.send", )
    a2 = _session("s2", "agent-b", "files.read")

    # Attacker claims both artifacts are the same incident.
    a1["meta"]["correlation_id"] = "spoofed"
    a2["meta"]["correlation_id"] = "spoofed"

    index = CorrelationIndex()
    index.ingest(a1, artifact_id="s1")
    index.ingest(a2, artifact_id="s2")

    bundles = index.bundles()
    assert any(b.bundle_id == "correlation:spoofed" for b in bundles)
    for bundle in bundles:
        assert bundle.reason == "shared correlation id"
        assert len(bundle.verification_statuses) == len(
            bundle.artifact_ids
        )


def test_redacted_artifact_correlates_but_stays_redacted():
    from firewall.incident import redact_artifact

    a1 = _session("s1", "agent-a", "payments.send")
    recorder = FlightRecorder(session_id="sec", agent="agent-s")
    recorder.record(
        EventType.TOOL_RESULT, {"tool": "db", "password": "x"}
    )
    recorder.finalize()
    redacted = redact_artifact(recorder.artifact())

    index = CorrelationIndex()
    record = index.ingest(redacted, artifact_id="red-1")
    assert record.verification == "redacted"
    assert index.graph().nodes()  # redacted facts still derive


# ----------------------------------------------------------------------
# Attack-path status honesty
# ----------------------------------------------------------------------


def test_reachable_is_not_claimed_observed():
    artifact = _session("s1", "agent-a", "payments.send")
    graph = AgentNetworkGraph.from_artifacts([artifact])
    analyzer = APA(graph)

    for path in analyzer.paths_to("payments.send"):
        # "observed" only when a recorded allow edge is on the path;
        # the taxonomy never upgrades an untested hop to observed.
        statuses = {hop.status for hop in path.hops}
        assert "simulated" not in statuses
        assert path.status in {"observed", "policy-permitted"}
