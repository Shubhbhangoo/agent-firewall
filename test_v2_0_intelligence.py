"""v2.0 intelligence tests: provenance, posture, trust graph, lab,
adaptive response."""

from __future__ import annotations

import pytest

from firewall.attest import Attestation, AttestationAuthority
from firewall.containment import ContainmentController
from firewall.ident import IdentityRegistry
from firewall.lab import SecurityLab
from firewall.network import AgentNetworkGraph
from firewall.network.behavior import Detection
from firewall.posture import PostureEngine, PostureSignal
from firewall.provenance import ProvenanceError, ProvenanceRegistry
from firewall.recorder import FlightRecorder
from firewall.response2 import (
    AdaptiveResponder,
    Response2Error,
    ResponseRule2,
)
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.trust import TrustGraph


def _session(session_id, agent, cap_name, *, secret=None, delegate_to=None):
    recorder = FlightRecorder(session_id=session_id, agent=agent)
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    cap = sdk.issue(
        agent=agent,
        capability=cap_name,
        constraints={"amount_max": 100},
    )
    sdk.authorize(cap, cap_name, {"amount": 20, "path": "/tmp/data"})
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


def _graph():
    a1 = _session("s1", "agent-a", "payments.send", secret="/etc/shadow", delegate_to="agent-b")
    a2 = _session("s2", "agent-b", "files.read", secret="/etc/shadow")
    return AgentNetworkGraph.from_artifacts([a1, a2])


# ----------------------------------------------------------------------
# Provenance
# ----------------------------------------------------------------------


def test_provenance_register_and_trust():
    reg = ProvenanceRegistry()
    component = reg.register(
        kind="mcp_server",
        name="github-mcp",
        version="1.0",
        integrity="abc123",
    )
    assert component.status == "unknown"  # never trusted implicitly

    trusted = reg.trust(component.component_id, reason="reviewed")
    assert trusted.status == "trusted"
    assert reg.trust_state(component.component_id)["status"] == "trusted"


def test_provenance_name_is_not_trust():
    reg = ProvenanceRegistry()
    reg.register(kind="tool", name="payments.send", version="1.0")
    # A name matching an expected value changes nothing.
    assert reg.trust_state("tool:payments.send:1.0")["status"] == "unknown"


def test_provenance_integrity_verification():
    reg = ProvenanceRegistry()
    component = reg.register(
        kind="package",
        name="lib",
        version="1.0",
        integrity="0" * 64,
    )
    result = reg.verify_integrity(component.component_id, b"\x00" * 32)
    assert result["status"] == "failed"

    from firewall.provenance import sha256_digest

    good = reg.register(
        kind="package",
        name="lib2",
        version="1.0",
        integrity=sha256_digest(b"content"),
    )
    assert reg.verify_integrity(good.component_id, b"content")["status"] == "verified"
    assert reg.verify_integrity(good.component_id, b"tampered")["status"] == "failed"


def test_provenance_missing_digest_unverifiable():
    reg = ProvenanceRegistry()
    component = reg.register(kind="tool", name="t", version="1")
    assert reg.verify_integrity(component.component_id, b"x")["status"] == "unverifiable"


def test_provenance_revocation_propagates():
    reg = ProvenanceRegistry()
    base = reg.register(kind="package", name="base", version="1", integrity="a")
    reg.trust(base.component_id)
    child = reg.register(
        kind="package",
        name="child",
        version="1",
        dependencies=(base.component_id,),
    )
    reg.trust(child.component_id)
    assert reg.trust_state(child.component_id)["status"] == "trusted"

    reg.revoke(base.component_id, reason="compromised")
    assert reg.trust_state(child.component_id)["status"] == "suspicious"
    assert any(
        component.status == "suspicious"
        for component in reg.suspicious()
    )


def test_provenance_unknown_dependency_rejected():
    reg = ProvenanceRegistry()
    with pytest.raises(ProvenanceError):
        reg.register(
            kind="package",
            name="p",
            version="1",
            dependencies=("ghost-component",),
        )


def test_provenance_suspicious_listing():
    reg = ProvenanceRegistry()
    component = reg.register(kind="tool", name="t", version="1")
    reg.suspect(component.component_id, reason="unexpected behavior")
    assert any(
        item.component_id == component.component_id
        for item in reg.suspicious()
    )


def test_provenance_persistence(tmp_path):
    reg = ProvenanceRegistry(state_path=str(tmp_path / "prov.json"))
    component = reg.register(kind="tool", name="t", version="1")
    reg.trust(component.component_id)
    reg.close()

    loaded = ProvenanceRegistry(state_path=str(tmp_path / "prov.json"))
    assert loaded.trust_state(component.component_id)["status"] == "trusted"


# ----------------------------------------------------------------------
# Posture
# ----------------------------------------------------------------------


def test_posture_unknown_without_evidence():
    engine = PostureEngine()
    assert engine.get("agent-a")["posture"] == "unknown"


def test_posture_escalates_with_evidence():
    engine = PostureEngine()
    engine.ingest(
        "agent-a",
        PostureSignal(
            name="authorization_denial",
            severity=2,
            description="repeated denials",
        ),
    )
    assert engine.get("agent-a")["posture"] == "degraded"

    engine.ingest(
        "agent-a",
        PostureSignal(
            name="credential_access",
            severity=5,
            description="credential-shaped access",
        ),
    )
    assert engine.get("agent-a")["posture"] == "compromised"


def test_posture_containment_and_recovery():
    engine = PostureEngine()
    engine.ingest("agent-a", PostureSignal(name="denial", severity=3, description="d"))
    engine.ingest("agent-a", PostureSignal(name="containment", severity=6, description="contained"))
    assert engine.get("agent-a")["posture"] == "contained"

    engine.ingest("agent-a", PostureSignal(name="recovery", severity=7, description="recovered"))
    assert engine.get("agent-a")["posture"] == "recovering"


def test_posture_explain_has_evidence():
    engine = PostureEngine()
    engine.ingest(
        "agent-a",
        PostureSignal(
            name="denial",
            severity=3,
            description="probing",
            evidence=({"artifact": "s1", "event_seq": 4},),
        ),
    )
    explanation = engine.explain("agent-a")
    assert explanation["posture"] == "suspicious"
    assert explanation["evidence"]
    assert "probing" in explanation["why"]


# ----------------------------------------------------------------------
# Trust graph
# ----------------------------------------------------------------------


def test_trust_what_can_and_who_can():
    graph = _graph()
    trust = TrustGraph(graph)

    what = trust.what_can("agent-a")
    assert "payments.send" in what["capabilities"]
    assert "/etc/shadow" in what["resources"]

    who = trust.who_can("/etc/shadow")
    assert any(entry["agent"] == "agent-a" for entry in who)


def test_trust_who_delegated():
    graph = _graph()
    trust = TrustGraph(graph)
    grantors = [entry["grantor"] for entry in trust.who_delegated("agent-b")]
    assert "agent-a" in grantors


def test_trust_blast_radius():
    graph = _graph()
    trust = TrustGraph(graph)
    radius = trust.blast_radius("agent-a")
    assert "/etc/shadow" in radius["sensitive_resources"]
    assert radius["derived_from"] == "derived"


def test_trust_dangers_inferred():
    graph = _graph()
    trust = TrustGraph(graph)
    dangers = trust.find_dangers()
    # Findings are labeled, and never claim observation.
    for danger in dangers:
        assert danger["basis"] in ("derived", "inferred")


# ----------------------------------------------------------------------
# Security Lab
# ----------------------------------------------------------------------


def test_lab_sweep():
    graph = _graph()
    lab = SecurityLab(graph)
    sweep = lab.sweep()
    assert "attack_surface" in sweep
    assert "dangers" in sweep
    assert "containment_opportunities" in sweep
    assert sweep["containment_opportunities"]


def test_lab_counterfactual_isolated():
    graph = _graph()
    lab = SecurityLab(graph)
    before = graph.to_dict()

    lab.counterfactual(
        agent="agent-a",
        kind="compromised_agent",
        title="what-if",
        added_capabilities=("admin.bypass",),
    )

    assert graph.to_dict() == before


def test_lab_tool_compromise_and_revocation():
    graph = _graph()
    lab = SecurityLab(graph)
    result = lab.tool_compromise("agent-a", "db.read")
    assert result["scenario"]["kind"] == "additional_tool"


# ----------------------------------------------------------------------
# Adaptive response
# ----------------------------------------------------------------------


def _responder(with_attestation=True, approver=None):
    recorder = FlightRecorder(session_id="r2", agent="agent-a")
    sdk = FirewallSDK(recorder=recorder, risk_context=RiskContext())
    sdk.generate_key("k")
    containment = ContainmentController(
        sdk, recorder=recorder, authorizer=lambda: True
    )
    identities = IdentityRegistry()
    identities.create("agent-a")
    authority = AttestationAuthority(identities) if with_attestation else None

    responder = AdaptiveResponder(
        containment,
        recorder=recorder,
        approver=approver,
        attestation_authority=authority,
    )
    return responder


def _detection(severity="high", agents=("agent-a",)):
    return Detection(
        rule_id="credential_shaped_access",
        title="credential access",
        severity=severity,
        explanation="credential-shaped access",
        evidence=({"artifact": "s1", "event_seq": 5},),
        agents=agents,
    )


def test_response_stages_and_attestation():
    responder = _responder()
    responder.add_rule(
        ResponseRule2(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="quarantine",
            auto_approve=True,
        )
    )

    record = responder.respond(_detection(), actor="cli")
    assert record.stage == "quarantine"
    assert record.attestation is not None
    assert record.evidence
    assert record.expires_at is None

    attestation = Attestation.from_dict(record.attestation)
    assert responder._attest.verify(attestation)["status"] == "verified"


def test_response_approval_required():
    responder = _responder(approver=lambda stage: False)
    responder.add_rule(
        ResponseRule2(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="quarantine",
        )
    )
    with pytest.raises(Response2Error):
        responder.respond(_detection(), actor="cli")


def test_response_observes_below_threshold():
    responder = _responder()
    responder.add_rule(
        ResponseRule2(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="quarantine",
        )
    )
    record = responder.respond(_detection(severity="low"), actor="cli")
    assert record.stage == "observe"
    assert "below" in record.reason


def test_response_ttl_expiration():
    responder = _responder()
    responder.add_rule(
        ResponseRule2(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="warn",
            ttl=60,
        )
    )
    record = responder.respond(_detection(), actor="cli")
    assert record.expires_at is not None
    assert record.expires_at > record.timestamp


def test_response_records_in_flight_recorder():
    recorder = FlightRecorder(session_id="r2b", agent="agent-a")
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    containment = ContainmentController(sdk, authorizer=lambda: True)
    responder = AdaptiveResponder(containment, recorder=recorder)
    responder.add_rule(
        ResponseRule2(
            rule_id="credential_shaped_access",
            min_severity="high",
            stage="quarantine",
            auto_approve=True,
        )
    )
    responder.respond(_detection(), actor="cli")
    artifact = recorder.finalize()
    from firewall.verify import verify_artifact

    assert verify_artifact(artifact).status == "verified"
    assert any(
        event["type"] == "security_state"
        for event in artifact["events"]
    )
