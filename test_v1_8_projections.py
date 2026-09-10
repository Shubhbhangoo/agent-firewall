"""v1.8 timeline, trajectory, graph, and containment unit tests."""

from __future__ import annotations

import pytest

from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
    ContainmentState,
)
from firewall.recorder import EventType, FlightRecorder
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.timeline import (
    SecurityGraph,
    build_timeline,
    trajectory_from_artifact,
)


# ----------------------------------------------------------------------
# Timeline
# ----------------------------------------------------------------------


def _recorded_session():
    recorder = FlightRecorder(
        session_id="tl",
        agent="agent-t",
        checkpoint_every=3,
        clock=lambda: 1700000000.0,
    )
    sdk = FirewallSDK(recorder=recorder, risk_context=RiskContext())
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-t",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    sdk.authorize(capability, "payments.send", {"amount": 20})
    sdk.authorize(capability, "payments.send", {"amount": 5000})
    recorder.finalize()
    return recorder


def test_timeline_builds_chronological_entries():
    artifact = _recorded_session().artifact()
    entries = build_timeline(artifact)
    assert len(entries) >= 4
    seqs = [entry.seq for entry in entries]
    assert seqs == sorted(seqs)
    kinds = {entry.kind for entry in entries}
    assert "authorization" in kinds
    assert "authority" in kinds
    assert "lifecycle" in kinds


def test_timeline_entries_carry_refs_to_evidence():
    artifact = _recorded_session().artifact()
    entries = build_timeline(artifact)
    authorization = [e for e in entries if e.kind == "authorization"]
    assert authorization
    assert authorization[0].refs["decision"] == authorization[0].seq


def test_timeline_text_renders():
    from firewall.timeline import timeline_to_text

    artifact = _recorded_session().artifact()
    text = timeline_to_text(build_timeline(artifact))
    assert "Session started" in text


# ----------------------------------------------------------------------
# Trajectory
# ----------------------------------------------------------------------


def test_trajectory_escalates_on_denials_with_evidence():
    recorder = _recorded_session()
    artifact = recorder.artifact()
    trajectory = trajectory_from_artifact(artifact)
    transitions = trajectory.for_agent("agent-t")
    assert transitions
    assert transitions[0].from_posture == "trusted"
    assert transitions[0].to_posture == "unusual"
    assert transitions[0].signals[0]["evidence_seq"] > 0
    assert trajectory.final["agent-t"]["posture"] in {
        "unusual",
        "suspicious",
    }


def test_trajectory_containment_transition():
    recorder = FlightRecorder(session_id="tc", agent="agent-c")
    sdk = FirewallSDK(recorder=recorder, risk_context=RiskContext())
    sdk.generate_key("k")
    controller = ContainmentController(
        sdk,
        recorder=recorder,
        authorizer=lambda: True,
    )
    controller.apply(
        ContainmentAction.QUARANTINE_AGENT,
        "agent-c",
        actor="test",
        reason="compromise",
    )
    artifact = recorder.finalize()
    trajectory = trajectory_from_artifact(artifact)
    contained = [
        t for t in trajectory.transitions
        if t.to_posture == "contained"
    ]
    assert contained
    assert contained[0].signals[0]["signal"] == "containment"


def test_trajectory_is_deterministic():
    left = trajectory_from_artifact(_recorded_session().artifact())
    right = trajectory_from_artifact(_recorded_session().artifact())
    assert left.to_dict() == right.to_dict()


# ----------------------------------------------------------------------
# Graph
# ----------------------------------------------------------------------


def test_graph_derives_nodes_and_edges():
    artifact = _recorded_session().artifact()
    graph = SecurityGraph.from_artifact(artifact)
    assert graph.nodes()
    assert graph.edges()
    types = {node.type for node in graph.nodes()}
    assert "agent" in types
    assert "capability" in types
    assert "session" in types


def test_graph_why_can_returns_recorded_paths():
    artifact = _recorded_session().artifact()
    graph = SecurityGraph.from_artifact(artifact)
    reasons = graph.why_can("agent-t", "payments.send")
    assert reasons
    reason = reasons[0]
    assert reason["allowed"] is True
    labels = [hop["label"] for hop in reason["path"]]
    assert "trusted-issuer" in labels
    assert "payments.send" in labels


def test_graph_why_can_empty_when_only_denied():
    recorder = FlightRecorder(session_id="gd", agent="agent-d")
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-d",
        capability="payments.send",
        constraints={"amount_max": 1},
    )
    sdk.authorize(capability, "payments.send", {"amount": 999})
    artifact = recorder.finalize()
    graph = SecurityGraph.from_artifact(artifact)
    assert graph.why_can("agent-d", "payments.send") == []
    reachable = graph.reachable("agent-d")
    assert "payments.send" not in reachable["allowed_actions"]
    assert "payments.send" in reachable["denied_actions"]


def test_graph_reachable_excludes_revoked():
    recorder = FlightRecorder(session_id="gr", agent="agent-r")
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-r",
        capability="files.read",
    )
    sdk.revoke(capability, reason="test")
    artifact = recorder.finalize()
    graph = SecurityGraph.from_artifact(artifact)
    reachable = graph.reachable("agent-r")
    assert reachable["capabilities"] == []
    assert "files.read" in reachable["revoked_capabilities"]


# ----------------------------------------------------------------------
# Containment
# ----------------------------------------------------------------------


def test_containment_lifecycle_and_enforcement():
    recorder = FlightRecorder(session_id="cl", agent="agent-x")
    sdk = FirewallSDK(recorder=recorder, risk_context=RiskContext())
    sdk.generate_key("k")
    capability = sdk.issue(agent="agent-x", capability="payments.send")

    controller = ContainmentController(
        sdk,
        recorder=recorder,
        authorizer=lambda: True,
    )

    assert controller.state("agent-x") == ContainmentState.ACTIVE

    event = controller.apply(
        ContainmentAction.QUARANTINE_AGENT,
        "agent-x",
        actor="admin",
        reason="compromise",
    )
    assert event.to_state == ContainmentState.QUARANTINED
    assert sdk.is_effectively_revoked(capability)

    # The real pipeline now denies the contained agent. Quarantine
    # both revokes the capability and elevates runtime risk; either
    # gate denies, and both are fail-closed.
    result = sdk.authorize(capability, "payments.send", {"amount": 1})
    assert not result.allowed
    assert result.reason in {
        "capability_revoked",
        "risk_state_revoked",
    }

    # Recovery re-issues equivalent authority.
    event = controller.apply(
        ContainmentAction.RECOVER,
        "agent-x",
        actor="admin",
        reason="cleared",
    )
    assert event.to_state == ContainmentState.RECOVERED

    artifact = recorder.finalize()
    assert any(
        event["type"] == EventType.CONTAINMENT.value
        for event in artifact["events"]
    )


def test_containment_requires_reason_and_authorization():
    sdk = FirewallSDK()
    sdk.generate_key("k")

    controller = ContainmentController(
        sdk,
        authorizer=lambda: False,
    )

    with pytest.raises(ContainmentError):
        controller.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-x",
            actor="admin",
            reason="",
        )

    with pytest.raises(ContainmentError):
        controller.apply(
            ContainmentAction.QUARANTINE_AGENT,
            "agent-x",
            actor="admin",
            reason="not authorized",
        )


def test_containment_illegal_transition_rejected():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    controller = ContainmentController(sdk, authorizer=lambda: True)
    controller.apply(
        ContainmentAction.QUARANTINE_AGENT,
        "agent-x",
        actor="admin",
        reason="compromise",
    )
    # Active-only transitions cannot be reached from quarantined.
    with pytest.raises(ContainmentError):
        controller.apply(
            ContainmentAction.RESTRICT_CAPABILITY,
            "agent-x",
            actor="admin",
            reason="nope",
        )


def test_containment_recovery_resets_risk():
    sdk = FirewallSDK(risk_context=RiskContext())
    sdk.generate_key("k")
    capability = sdk.issue(agent="agent-x", capability="payments.send")
    controller = ContainmentController(sdk, authorizer=lambda: True)
    controller.apply(
        ContainmentAction.RESTRICT_SESSION,
        "agent-x",
        actor="admin",
        reason="pattern",
    )
    # Risk gate now denies.
    result = sdk.authorize(capability, "payments.send", {"amount": 1})
    assert not result.allowed
    controller.apply(
        ContainmentAction.RECOVER,
        "agent-x",
        actor="admin",
        reason="cleared",
    )
    result = sdk.authorize(capability, "payments.send", {"amount": 1})
    assert result.allowed
