"""v2.1 unit tests: defense mesh, a2a zero trust, capability2."""

from __future__ import annotations

import json
import time

import pytest

from firewall.a2a import A2AError, AgentToAgent
from firewall.attest import AttestationAuthority
from firewall.capability2 import (
    Capability2,
    Capability2Error,
    validate_constraints,
)
from firewall.containment import ContainmentAction, ContainmentController
from firewall.defense import DefenseError, DefenseMesh
from firewall.ident import IdentityRegistry
from firewall.posture import PostureEngine, PostureSignal
from firewall.sdk import FirewallSDK


# ======================================================================
# Defense mesh
# ======================================================================


class FakeClock:
    """A mutable clock shared by the SDK and the mesh so re-issued
    capabilities get fresh fingerprints (a re-issue within the same
    clock tick would produce the identical signed payload and stay
    revoked)."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float = 1.0) -> None:
        self.t += seconds


class TestDefenseMesh:
    def _mesh(self, sdk=None):
        reg = IdentityRegistry()
        reg.create("agent-a")
        reg.create("agent-b")
        posture = PostureEngine()
        clock = FakeClock()
        if sdk is None:
            sdk = FirewallSDK(clock=clock)
            sdk.generate_key("mesh-key")
        controller = ContainmentController(
            sdk, authorizer=lambda: True, clock=clock
        )
        mesh = DefenseMesh(
            reg,
            posture=posture,
            containment=controller,
            clock=clock,
        )
        mesh.attach_sdk(sdk)
        # Live capabilities make the agents genuinely operational.
        for agent in ("agent-a", "agent-b"):
            sdk.issue(
                agent=agent,
                capability="payments.send",
                constraints={"amount_max": 100},
            )
        return reg, posture, mesh, clock

    def test_evaluate_active_identity(self):
        reg, posture, mesh, clock = self._mesh()
        state = mesh.evaluate("agent-a")
        assert state.identity_verified is True
        assert state.state == "active"
        assert 0.0 <= state.trust_score <= 1.0

    def test_unknown_identity_fails_closed(self):
        reg, posture, mesh, clock = self._mesh()
        state = mesh.evaluate("ghost")
        assert state.identity_verified is False
        assert state.state == "retired"

    def test_compromised_posture_auto_quarantines(self):
        reg, posture, mesh, clock = self._mesh()
        posture.ingest(
            "agent-a",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        mesh.evaluate("agent-a")
        # Restriction and quarantine happen in the same evaluation:
        # a compromised agent is immediately quarantined.
        assert mesh.state("agent-a")["state"] == "quarantined"

    def test_live_identity_proof_verified(self):
        reg, posture, mesh, clock = self._mesh()
        data = b"challenge-data"
        signature = reg.sign("agent-a", data)
        state = mesh.evaluate(
            "agent-a", identity_data=data, identity_signature=signature
        )
        assert state.identity_verified is True

    def test_forged_identity_proof_denied(self):
        reg, posture, mesh, clock = self._mesh()
        data = b"challenge-data"
        # Signature by agent-b over the same data presented as agent-a.
        signature = reg.sign("agent-b", data)
        state = mesh.evaluate(
            "agent-a", identity_data=data, identity_signature=signature
        )
        assert state.identity_verified is False
        assert state.state == "restricted"

    def test_recovery_path_required(self):
        reg, posture, mesh, clock = self._mesh()
        posture.ingest(
            "agent-a",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        mesh.evaluate("agent-a")
        assert mesh.state("agent-a")["state"] == "quarantined"

        # Cannot re-enter from quarantined.
        with pytest.raises(DefenseError):
            mesh.reenter("agent-a", actor="op", reason="nope")

        # Advance the clock so the re-issued capability gets a fresh
        # fingerprint (a same-tick re-issue would hash identically and
        # stay revoked).
        clock.advance(1.0)
        mesh.recover("agent-a", actor="op", reason="clean")
        assert mesh.state("agent-a")["state"] == "recovering"

        # The compromise is cleared before re-entry.
        posture.reset("agent-a")
        mesh.reenter("agent-a", actor="op", reason="verified")
        assert mesh.state("agent-a")["state"] == "active"

    def test_reentry_denied_with_compromised_posture(self):
        reg, posture, mesh, clock = self._mesh()
        posture.ingest(
            "agent-a",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        mesh.evaluate("agent-a")
        clock.advance(1.0)
        mesh.recover("agent-a", actor="op", reason="clean")
        # Posture still compromised: re-entry refused.
        with pytest.raises(DefenseError):
            mesh.reenter("agent-a", actor="op", reason="verified")

    def test_quarantine_attestation_audited(self):
        reg = IdentityRegistry()
        reg.create("agent-a")
        attest = AttestationAuthority(reg)
        mesh = DefenseMesh(reg, attest=attest)
        transition = mesh.quarantine("agent-a", actor="op", reason="incident")
        assert transition.to_state == "quarantined"
        assert transition.attestation is not None
        assert transition.attestation["statement_type"] == "defense_mesh_transition"

    def test_sdk_quarantine_revokes_capabilities(self):
        reg = IdentityRegistry()
        reg.create("agent-a")
        sdk = FirewallSDK()
        sdk.generate_key("k")
        sdk.issue(agent="agent-a", capability="payments.send")
        mesh = DefenseMesh(reg)
        mesh.attach_sdk(sdk)
        mesh.quarantine("agent-a", actor="op", reason="incident")
        assert mesh.state("agent-a")["state"] == "quarantined"

    def test_transitions_are_auditable(self):
        reg, posture, mesh, clock = self._mesh()
        mesh.quarantine("agent-a", actor="op", reason="r1")
        clock.advance(1.0)
        mesh.recover("agent-a", actor="op", reason="r2")
        mesh.reenter("agent-a", actor="op", reason="r3")
        history = mesh.state("agent-a")["transitions"]
        assert [t["to"] for t in history] == [
            "quarantined",
            "recovering",
            "active",
        ]
        assert all(t["actor"] == "op" for t in history)

    def test_recovery_ttl_enforced(self):
        reg = IdentityRegistry()
        reg.create("agent-a")
        mesh = DefenseMesh(reg, recovery_ttl=1.0)
        mesh.quarantine("agent-a", actor="op", reason="r")
        mesh.recover("agent-a", actor="op", reason="clean")
        time.sleep(1.1)
        with pytest.raises(DefenseError):
            mesh.reenter("agent-a", actor="op", reason="late")
        assert mesh.state("agent-a")["state"] == "quarantined"

    def test_persistence_round_trip(self, tmp_path):
        path = tmp_path / "mesh.json"
        reg = IdentityRegistry()
        reg.create("agent-a")
        mesh = DefenseMesh(reg, state_path=path)
        mesh.quarantine("agent-a", actor="op", reason="r")
        mesh.close()

        reg2 = IdentityRegistry()
        reg2.create("agent-a")
        reloaded = DefenseMesh(reg2, state_path=path)
        assert reloaded.state("agent-a")["state"] == "quarantined"
        assert reloaded.state("agent-a")["transitions"][-1]["reason"] == "r"


# ======================================================================
# A2A zero trust
# ======================================================================


class TestA2A:
    def _a2a(self, sdk_provider=None, task_provider=None):
        reg = IdentityRegistry()
        for name in ("alice", "bob", "carol", "mallory"):
            reg.create(name)
        a2a = AgentToAgent(
            reg,
            sdk_provider=sdk_provider,
            task_provider=task_provider,
        )
        return reg, a2a

    def test_mutual_authentication(self):
        reg, a2a = self._a2a()
        proof = a2a.mutual_authenticate("alice", "bob")
        assert proof["mutually_authenticated"] is True

    def test_forged_mutual_auth_rejected(self):
        reg, a2a = self._a2a()
        proof = a2a.mutual_authenticate("bob", "carol")
        proof["agent_a"] = "mallory"
        # The proof claims (mallory, carol); establish is asked for
        # (alice, carol) - the names must match exactly.
        with pytest.raises(A2AError):
            a2a.establish(
                initiator="alice",
                responder="carol",
                permissions={"allowed_actions": ["read"]},
                mutual_auth=proof,
            )

    def test_challenge_signature_bound_to_agent(self):
        reg, a2a = self._a2a()
        # A challenge consumed by a failed attempt cannot be reused.
        nonce = a2a.challenge("alice")
        wrong = reg.sign("bob", json.dumps({"agent": "alice", "nonce": nonce}, sort_keys=True, separators=(",", ":")).encode())
        assert a2a.authenticate("alice", nonce, wrong) is False
        # A fresh challenge verifies with the correct signature.
        nonce2 = a2a.challenge("alice")
        right = reg.sign("alice", json.dumps({"agent": "alice", "nonce": nonce2}, sort_keys=True, separators=(",", ":")).encode())
        assert a2a.authenticate("alice", nonce2, right) is True

    def test_self_relationship_rejected(self):
        reg, a2a = self._a2a()
        with pytest.raises(A2AError):
            a2a.establish(
                initiator="alice",
                responder="alice",
                permissions={"allowed_actions": ["read"]},
            )

    def test_authorize_within_scope(self):
        reg, a2a = self._a2a()
        rel = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read", "write"]},
        )
        assert a2a.authorize(actor="alice", target="bob", action="read").allowed
        assert a2a.authorize(actor="alice", target="bob", action="write").allowed
        assert not a2a.authorize(actor="alice", target="bob", action="admin").allowed
        assert not a2a.authorize(actor="bob", target="alice", action="read").allowed

    def test_no_relationship_denied(self):
        reg, a2a = self._a2a()
        decision = a2a.authorize(actor="alice", target="carol", action="read")
        assert not decision.allowed
        assert "no active relationship" in decision.reason

    def test_delegation_narrows_and_chain_verifies(self):
        reg, a2a = self._a2a()
        rel = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read", "write", "admin"]},
        )
        child = a2a.delegate(
            rel,
            responder="carol",
            permissions={"allowed_actions": ["read", "write"]},
        )
        assert child.permissions == {"allowed_actions": ["read", "write"]}
        report = a2a.verify_chain(child.relationship_id)
        assert report["valid"] is True
        assert report["hops"] == 2
        # Effective permissions are the intersection.
        assert a2a.effective_permissions(child.relationship_id) == {
            "allowed_actions": ["read", "write"]
        }

    def test_delegation_cannot_widen(self):
        reg, a2a = self._a2a()
        rel = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
        )
        child = a2a.delegate(
            rel,
            responder="carol",
            permissions={"allowed_actions": ["read", "admin"]},
        )
        assert child.permissions == {"allowed_actions": ["read"]}

    def test_chain_detects_cycle(self):
        reg, a2a = self._a2a()
        rel = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
        )
        # Forge a cycle in the internal map.
        rel2 = a2a.delegate(
            rel, responder="carol",
            permissions={"allowed_actions": ["read"]},
        )
        a2a._relationships[rel.relationship_id] = a2a._relationships[
            rel.relationship_id
        ].__class__(
            relationship_id=rel.relationship_id,
            initiator="alice",
            responder="bob",
            permissions=dict(rel.permissions),
            parent_relationship=rel2.relationship_id,
        )
        with pytest.raises(A2AError):
            a2a.lineage(rel.relationship_id)

    def test_recursive_revocation(self):
        reg, a2a = self._a2a()
        rel = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
        )
        child = a2a.delegate(
            rel, responder="carol",
            permissions={"allowed_actions": ["read"]},
        )
        count = a2a.revoke(rel.relationship_id, reason="incident")
        assert count == 2
        assert a2a.get(rel.relationship_id).status == "revoked"
        assert a2a.get(child.relationship_id).status == "revoked"
        assert not a2a.authorize(actor="alice", target="bob", action="read").allowed

    def test_expiring_delegation(self):
        reg, a2a = self._a2a()
        rel = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
            ttl=0.001,
        )
        time.sleep(0.01)
        assert not a2a.authorize(actor="alice", target="bob", action="read").allowed

    def test_teardown_revokes_both_directions(self):
        reg, a2a = self._a2a()
        rel1 = a2a.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
        )
        rel2 = a2a.establish(
            initiator="bob",
            responder="alice",
            permissions={"allowed_actions": ["write"]},
        )
        count = a2a.teardown("alice", "bob", reason="done")
        assert count == 2
        assert a2a.get(rel1.relationship_id).status == "revoked"
        assert a2a.get(rel2.relationship_id).status == "revoked"

    def test_task_bound_denial(self):
        reg, a2a = self._a2a()
        a2a_with_task = AgentToAgent(
            reg,
            task_provider=lambda task_id: False,
        )
        rel = a2a_with_task.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
            task_id="task-1",
        )
        assert not a2a_with_task.authorize(
            actor="alice", target="bob", action="read"
        ).allowed

    def test_sdk_provider_is_authoritative_gate(self):
        reg, a2a = self._a2a()
        denying = AgentToAgent(
            reg,
            sdk_provider=lambda actor, target, action, request: (
                False,
                "pipeline denies",
            ),
        )
        rel = denying.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
        )
        assert not denying.authorize(
            actor="alice", target="bob", action="read"
        ).allowed

    def test_persistence_round_trip(self, tmp_path):
        path = tmp_path / "a2a.json"
        reg, a2a = self._a2a()
        a2a_persistent = AgentToAgent(reg, state_path=path)
        rel = a2a_persistent.establish(
            initiator="alice",
            responder="bob",
            permissions={"allowed_actions": ["read"]},
        )
        a2a_persistent.close()

        reloaded = AgentToAgent(reg, state_path=path)
        stored = reloaded.get(rel.relationship_id)
        assert stored is not None
        assert stored.permissions == {"allowed_actions": ["read"]}


# ======================================================================
# Capability Firewall 2.0
# ======================================================================


class TestCapability2:
    def _policy(self):
        return Capability2(
            "payments.send",
            constraints={
                "resource": "payments",
                "scope": "/prod",
                "action": ["send", "refund"],
                "time": {"not_after": 10**12},
                "identity": {"agent_id": "alice"},
                "task": {"task_id": "task-1"},
                "lineage": {"max_depth": 2},
                "environment": {"env": "prod"},
                "context": {"session": "s-1"},
                "provenance": {"reviewed": True},
            },
        )

    def _request(self, **overrides):
        request = {
            "resource": "payments",
            "path": "/prod/invoice",
            "action": "send",
            "agent_id": "alice",
            "task_id": "task-1",
            "delegation_depth": 1,
            "env": "prod",
            "session": "s-1",
            "reviewed": True,
        }
        request.update(overrides)
        return request

    def test_all_constraints_satisfied(self):
        cap = self._policy()
        allowed, reason = cap.evaluate(self._request(), now=10**11)
        assert allowed is True
        assert "satisfied" in reason

    def test_resource_mismatch_denied(self):
        cap = self._policy()
        allowed, _ = cap.evaluate(
            self._request(resource="admin"), now=10**11
        )
        assert allowed is False

    def test_action_outside_list_denied(self):
        cap = self._policy()
        allowed, _ = cap.evaluate(
            self._request(action="void"), now=10**11
        )
        assert allowed is False

    def test_time_window_enforced(self):
        cap = self._policy()
        allowed, _ = cap.evaluate(self._request(), now=10**13)
        assert allowed is False

    def test_lineage_depth_enforced(self):
        cap = self._policy()
        allowed, _ = cap.evaluate(
            self._request(delegation_depth=3), now=10**11
        )
        assert allowed is False

    def test_missing_key_fails_closed(self):
        cap = self._policy()
        request = self._request()
        del request["env"]
        allowed, reason = cap.evaluate(request, now=10**11)
        assert allowed is False
        assert "missing" in reason

    def test_scope_prefix_matches(self):
        cap = self._policy()
        allowed, _ = cap.evaluate(
            self._request(path="/prod/deep/nested"), now=10**11
        )
        assert allowed is True

    def test_attenuation_narrows_actions(self):
        cap = self._policy()
        child = cap.attenuate(action=["send"])
        assert child.is_narrower_than(cap)
        assert child.evaluate(self._request(), now=10**11)[0] is True
        assert child.evaluate(self._request(action="refund"), now=10**11)[0] is False

    def test_attenuation_refuses_widening(self):
        cap = Capability2("fs.read", constraints={"scope": "/data"})
        with pytest.raises(Capability2Error):
            cap.attenuate(scope="/etc")

    def test_delegation_records_parent(self):
        parent = Capability2("x", constraints={"action": ["a", "b"]})
        child = parent.delegate(action=["a"])
        assert child.parent == "x"
        assert child.is_narrower_than(parent)

    def test_unknown_namespace_rejected(self):
        with pytest.raises(Capability2Error):
            validate_constraints({"bogus": 1})

    def test_invalid_time_key_rejected(self):
        with pytest.raises(Capability2Error):
            validate_constraints({"time": {"never": 1}})

    def test_operator_constraints(self):
        cap = Capability2(
            "x",
            constraints={"context": {"amount": {"lte": 100}}},
        )
        assert cap.evaluate({"amount": 50})[0] is True
        assert cap.evaluate({"amount": 150})[0] is False
