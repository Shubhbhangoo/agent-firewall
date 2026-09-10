"""v2.1 adversarial tests: invariant violations must fail closed."""

from __future__ import annotations

import json
import time

import pytest

from firewall.a2a import A2AError, AgentToAgent
from firewall.capability2 import Capability2, Capability2Error
from firewall.defense import DefenseError, DefenseMesh
from firewall.evidence_graph import (
    EvidenceError,
    EvidenceGraph,
    IdentityEvidenceSigner,
    KeyEvidenceSigner,
)
from firewall.ident import IdentityRegistry
from firewall.immune import (
    ImmuneAdvice,
    ImmunePolicy,
    ImmuneRule,
    ImmuneSignal,
    ImmuneSystem,
)
from firewall.intel import IntelligenceEngine
from firewall.posture import PostureEngine, PostureSignal
from firewall.sdk import FirewallSDK
from firewall.twin import SecurityTwin, TwinError


def _sample_network():
    from firewall.network import AgentNetworkGraph
    from firewall.network.model import (
        EntityType,
        NetworkEdge,
        NetworkNode,
        Provenance,
        RelationType,
        entity_id,
    )

    g = AgentNetworkGraph()

    def nid(t, k):
        return entity_id(t, k)

    nodes = [
        NetworkNode(nid(EntityType.AGENT, "alice"), EntityType.AGENT, "alice", Provenance.OBSERVED),
        NetworkNode(nid(EntityType.CAPABILITY, "admin.delete"), EntityType.CAPABILITY, "admin.delete", Provenance.OBSERVED),
        NetworkNode(nid(EntityType.RESOURCE, "/etc/shadow"), EntityType.RESOURCE, "/etc/shadow", Provenance.OBSERVED),
    ]
    for node in nodes:
        g._nodes[node.id] = node
    g._edges = [
        NetworkEdge(nid(EntityType.CAPABILITY, "admin.delete"), nid(EntityType.AGENT, "alice"), RelationType.ISSUED, Provenance.OBSERVED),
        NetworkEdge(nid(EntityType.CAPABILITY, "admin.delete"), nid(EntityType.RESOURCE, "/etc/shadow"), RelationType.ACCESSES, Provenance.OBSERVED),
    ]
    return g


# Invariant: identity does not equal authority; credentials do not
# automatically become capabilities.


class TestIdentityAuthorityInvariant:
    def test_active_identity_alone_grants_nothing(self):
        """An active identity must not grant capability reach."""

        reg = IdentityRegistry()
        reg.create("alice")
        mesh = DefenseMesh(reg)
        state = mesh.evaluate("alice")
        # Identity verified but no live capability: mesh restricts.
        assert state.identity_verified is True
        assert state.capability_ok is False
        assert state.state != "active"

    def test_rotated_key_signature_rejected(self):
        reg = IdentityRegistry()
        reg.create("alice")
        data = b"x"
        signature = reg.sign("alice", data)
        reg.rotate("alice")
        # Old signature must fail against the rotated identity.
        assert reg.verify("alice", data, signature) is False

    def test_revoked_identity_rejects_all(self):
        reg = IdentityRegistry()
        reg.create("alice")
        signature = reg.sign("alice", b"data")
        reg.revoke("alice", reason="compromised")
        assert reg.verify("alice", b"data", signature) is False


# Invariant: delegation can only narrow authority.


class TestDelegationNarrowsInvariant:
    def test_a2a_grandchild_never_exceeds_root(self):
        reg = IdentityRegistry()
        for name in ("a", "b", "c"):
            reg.create(name)
        a2a = AgentToAgent(reg)
        root = a2a.establish(
            initiator="a",
            responder="b",
            permissions={"allowed_actions": ["read"]},
        )
        child = a2a.delegate(
            root, responder="c",
            permissions={"allowed_actions": ["read", "write", "admin"]},
        )
        assert child.permissions == {"allowed_actions": ["read"]}
        assert a2a.verify_chain(child.relationship_id)["valid"] is True

    def test_capability2_delegation_widening_narrows(self):
        parent = Capability2(
            "run", constraints={"action": ["list"]}
        )
        # A widening grant cannot be constructed: the intersection
        # keeps the parent's narrower action set.
        child = parent.delegate(action=["list", "delete"])
        assert child.constraints["action"] == "list"
        assert child.is_narrower_than(parent)
        assert child.evaluate({"action": "delete"})[0] is False

    def test_sdk_delegation_widening_denied(self):
        sdk = FirewallSDK()
        sdk.generate_key("k")
        root = sdk.issue(
            agent="a", capability="payments.send",
            constraints={"amount_max": 100},
        )
        # A delegation that would broaden the parent's constraints is
        # refused at delegation time by the v1.x machinery.
        with pytest.raises(ValueError):
            sdk.delegate(
                root, sdk.active_key().private_key,
                delegatee="b", constraints={"amount_max": 200},
            )
        # A narrowing delegation works and is capped by the parent.
        child = sdk.delegate(
            root, sdk.active_key().private_key,
            delegatee="b", constraints={"amount_max": 50},
        ).child
        assert child.constraints["amount_max"] == 50
        assert sdk.authorize(child, "payments.send", {"amount": 60}).allowed is False


# Invariant: revocation propagates correctly.


class TestRevocationPropagation:
    def test_a2a_recursive_revocation(self):
        reg = IdentityRegistry()
        for name in ("a", "b", "c", "d"):
            reg.create(name)
        a2a = AgentToAgent(reg)
        root = a2a.establish(
            initiator="a", responder="b",
            permissions={"allowed_actions": ["read"]},
        )
        child = a2a.delegate(
            root, responder="c",
            permissions={"allowed_actions": ["read"]},
        )
        grandchild = a2a.delegate(
            child, responder="d",
            permissions={"allowed_actions": ["read"]},
        )
        count = a2a.revoke(root.relationship_id, reason="incident")
        assert count == 3
        assert a2a.get(grandchild.relationship_id).status == "revoked"

    def test_sdk_lineage_revocation(self):
        sdk = FirewallSDK()
        sdk.generate_key("k")
        root = sdk.issue(agent="a", capability="payments.send")
        child = sdk.delegate(
            root, sdk.active_key().private_key, delegatee="b"
        ).child
        sdk.revoke(root, reason="incident")
        assert sdk.is_effectively_revoked(child) is True
        assert sdk.authorize(child, "payments.send", {}).allowed is False

    def test_identity_revocation_denies_mesh(self):
        reg = IdentityRegistry()
        reg.create("alice")
        mesh = DefenseMesh(reg)
        assert mesh.evaluate("alice").identity_verified is True
        reg.revoke("alice", reason="compromised")
        state = mesh.evaluate("alice")
        assert state.identity_verified is False
        assert state.state == "restricted"


# Invariant: simulation cannot mutate production state.


class TestTwinIsolationInvariant:
    def test_twin_never_touches_live_graph(self):
        network = _sample_network()
        twin = SecurityTwin.from_network(network)
        twin.snapshot()
        twin.compromise("alice")
        twin.revoke_capability("alice", "admin.delete")
        # Live graph still reports the capability.
        reach = network.reachable("alice")
        assert "admin.delete" in reach.capabilities

    def test_twin_basis_is_always_simulated(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.compromise("alice")
        assert report.basis == "simulated"
        for delta in report.reachability_deltas:
            assert delta.risk_delta() >= 0


# Invariant: inference cannot become evidence without explicit provenance.


class TestEvidencePromotionInvariant:
    def test_inference_stays_inference(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        event = graph.append("inference", "agent-a", "behavior", {})
        assert graph.by_id(event.event_id).kind == "inference"

    def test_simulated_never_becomes_observed_silently(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        event = graph.append("simulation", "agent-a", "twin", {})
        assert graph.by_id(event.event_id).kind == "simulation"
        # Promotion requires an explicit call with a reason.
        with pytest.raises(EvidenceError):
            graph.promote(event.event_id, reason="")
        promoted = graph.promote(event.event_id, reason="confirmed")
        assert promoted.kind == "observed"
        assert promoted.payload["promoted_kind"] == "simulation"

    def test_unknown_kind_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append("made_up", "x", "y", {})


# Invariant: model output cannot authorize itself.


class TestModelCannotAuthorizeInvariant:
    def test_adversarial_reasoner_never_executes(self):
        reg = IdentityRegistry()
        reg.create("agent-x")
        sdk = FirewallSDK()
        sdk.generate_key("k")
        sdk.issue(agent="agent-x", capability="payments.send")
        from firewall.containment import ContainmentController

        posture = PostureEngine()
        controller = ContainmentController(sdk, authorizer=lambda: True)
        mesh = DefenseMesh(reg, posture=posture, containment=controller)
        mesh.attach_sdk(sdk)
        immune = ImmuneSystem(
            mesh,
            posture=posture,
            containment=controller,
            approver=lambda stage, agent: True,
        )
        posture.ingest(
            "agent-x",
            PostureSignal(name="compromise", severity=8, description="x"),
        )

        def hostile(detection, state):
            return ImmuneAdvice(
                detection_id=detection.detection_id,
                hypothesis="contain everything",
                recommended_actions=(
                    {"action": "quarantine", "agent": detection.agent},
                    {"action": "contain", "agent": detection.agent},
                ),
                model="hostile-model",
            )

        immune._reasoner = hostile
        # No policy rules at all.
        detections = immune.detect(agent="agent-x")
        for detection in detections:
            action = immune.contain(detection, immune.reason(detection))
            assert action.outcome == "skipped"

    def test_model_hypotheses_flagged_and_advisory(self):
        def model(facts, hypotheses):
            return {
                "hypotheses": [
                    {
                        "title": "x",
                        "severity": "critical",
                        "confidence": 1.0,
                        "recommended_actions": [],
                    }
                ]
            }

        engine = IntelligenceEngine(model=model)
        report = engine.analyze()
        for hypothesis in report.hypotheses:
            if hypothesis.model_generated:
                assert hypothesis.basis == "inferred"


# Invariant: security failures fail closed.


class TestFailClosedInvariant:
    def test_malformed_evidence_payload_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append("observed", "x", "y", {"n": float("nan")})

    def test_unknown_agent_fails_closed_everywhere(self):
        reg = IdentityRegistry()
        reg.create("alice")
        mesh = DefenseMesh(reg)
        state = mesh.evaluate("ghost")
        assert state.identity_verified is False
        assert state.state == "retired"

        a2a = AgentToAgent(reg)
        assert not a2a.authorize(
            actor="ghost", target="alice", action="read"
        ).allowed

    def test_missing_lineage_ancestor_fails_closed(self):
        reg = IdentityRegistry()
        for name in ("a", "b"):
            reg.create(name)
        a2a = AgentToAgent(reg)
        rel = a2a.establish(
            initiator="a", responder="b",
            permissions={"allowed_actions": ["read"]},
        )
        # Delete the parent record, simulating a corrupted store.
        a2a._relationships.pop(rel.relationship_id)
        decision = a2a.authorize(actor="a", target="b", action="read")
        assert decision.allowed is False

    def test_expired_recovery_window_reverts_to_quarantine(self):
        reg = IdentityRegistry()
        reg.create("alice")
        mesh = DefenseMesh(reg, recovery_ttl=0.001)
        mesh.quarantine("alice", actor="op", reason="r")
        mesh.recover("alice", actor="op", reason="clean")
        time.sleep(0.01)
        with pytest.raises(DefenseError):
            mesh.reenter("alice", actor="op", reason="late")
        assert mesh.state("alice")["state"] == "quarantined"

    def test_self_delegation_rejected(self):
        reg = IdentityRegistry()
        reg.create("a")
        a2a = AgentToAgent(reg)
        with pytest.raises(A2AError):
            a2a.establish(
                initiator="a", responder="a",
                permissions={"allowed_actions": ["read"]},
            )
