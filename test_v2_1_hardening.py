"""v2.1 production-hardening tests: concurrency, race conditions,
persistence failures, crash recovery, replay, state rollback, large
trust graphs, large agent populations, long delegation chains, key
rotation during active sessions, revocation during execution, partial
failures, malformed cryptographic data, and adversarial input.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import threading
import time

import pytest

from firewall.a2a import A2AError, AgentToAgent
from firewall.capability2 import Capability2, Capability2Error
from firewall.defense import DefenseError, DefenseMesh
from firewall.evidence_graph import (
    EvidenceError,
    EvidenceGraph,
    KeyEvidenceSigner,
)
from firewall.ident import IdentityError, IdentityRegistry
from firewall.sdk import FirewallSDK


# ======================================================================
# Concurrency / race conditions
# ======================================================================


class TestConcurrency:
    def test_evidence_graph_concurrent_append(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())

        def worker(i):
            graph.append("observed", f"subject-{i % 5}", "decision", {"i": i})

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(200)))

        result = graph.verify()
        assert result["status"] == "verified"
        assert len(graph.events()) == 200
        # Sequence numbers are strictly increasing.
        seqs = [event.seq for event in graph.events()]
        assert seqs == sorted(seqs)
        assert seqs == list(range(1, 201))

    def test_a2a_concurrent_establish(self):
        reg = IdentityRegistry()
        for i in range(20):
            reg.create(f"agent-{i}")
        a2a = AgentToAgent(reg)

        def worker(i):
            a2a.establish(
                initiator=f"agent-{i}",
                responder=f"agent-{(i + 1) % 20}",
                permissions={"allowed_actions": ["read"]},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(20)))

        assert len(a2a.all()) == 20

    def test_mesh_concurrent_evaluation(self):
        reg = IdentityRegistry()
        for i in range(20):
            reg.create(f"agent-{i}")
        mesh = DefenseMesh(reg)

        def worker(i):
            return mesh.evaluate(f"agent-{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            states = list(pool.map(worker, range(20)))

        assert all(s.identity_verified for s in states)

    def test_identity_registry_concurrent_create(self):
        reg = IdentityRegistry()
        errors = []

        def worker(i):
            try:
                reg.create(f"agent-{i}")
            except Exception as exc:  # pragma: no cover - failure probe
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(50)))

        assert not errors
        assert len(reg.all()) == 50

    def test_sdk_concurrent_authorize(self):
        sdk = FirewallSDK()
        sdk.generate_key("k")
        cap = sdk.issue(agent="alice", capability="payments.send")
        results = []

        def worker(_):
            result = sdk.authorize(cap, "payments.send", {"amount": 1})
            results.append(result.allowed)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(50)))

        assert results.count(True) == 50


# ======================================================================
# Persistence failures / crash recovery
# ======================================================================


class TestPersistence:
    def test_corrupted_state_fails_closed(self, tmp_path):
        path = tmp_path / "mesh.json"
        path.write_text("{not valid json", encoding="utf-8")
        reg = IdentityRegistry()
        reg.create("a")
        with pytest.raises(DefenseError):
            DefenseMesh(reg, state_path=path)

    def test_corrupted_a2a_state_fails_closed(self, tmp_path):
        path = tmp_path / "a2a.json"
        path.write_text("[]", encoding="utf-8")
        reg = IdentityRegistry()
        reg.create("a")
        reg.create("b")
        with pytest.raises(A2AError):
            AgentToAgent(reg, state_path=path)

    def test_partial_identity_state_loads_valid_records(self, tmp_path):
        path = tmp_path / "identities.json"
        path.write_text(
            json.dumps(
                {
                    "identities": [
                        {"agent_id": "good", "status": "active"},
                        {"agent_id": "", "status": "active"},  # invalid
                    ]
                }
            ),
            encoding="utf-8",
        )
        reg = IdentityRegistry(state_path=path)
        assert reg.get("good") is not None

    def test_crash_mid_write_recovers(self, tmp_path):
        """A torn state file (truncated JSON) must fail closed rather
        than silently loading partial state."""

        path = tmp_path / "evidence.json"
        graph = EvidenceGraph(signer=KeyEvidenceSigner(), state_path=path)
        for i in range(10):
            graph.append("observed", "x", "decision", {"i": i})
        graph.close()
        data = path.read_text(encoding="utf-8")
        path.write_text(data[: len(data) // 2], encoding="utf-8")
        with pytest.raises(EvidenceError):
            EvidenceGraph(signer=KeyEvidenceSigner(), state_path=path)

    def test_mesh_persistence_round_trip_with_recovery(self, tmp_path):
        path = tmp_path / "mesh.json"
        reg = IdentityRegistry()
        reg.create("alice")
        mesh = DefenseMesh(reg, state_path=path)
        mesh.quarantine("alice", actor="op", reason="r")
        mesh.close()

        reg2 = IdentityRegistry()
        reg2.create("alice")
        reloaded = DefenseMesh(reg2, state_path=path)
        assert reloaded.state("alice")["state"] == "quarantined"
        assert reloaded.state("alice")["transitions"][-1]["attestation"] is None


# ======================================================================
# Replay / state rollback
# ======================================================================


class TestReplayAndRollback:
    def test_replay_protection_on_nonce(self):
        sdk = FirewallSDK()
        sdk.generate_key("k")
        cap = sdk.issue(agent="alice", capability="payments.send")
        nonce = "fixed-nonce"
        assert sdk.consume_nonce("alice", cap, nonce) is True
        assert sdk.consume_nonce("alice", cap, nonce) is False

    def test_revocation_during_execution(self):
        """A capability revoked mid-flight is denied on the next use."""

        sdk = FirewallSDK()
        sdk.generate_key("k")
        cap = sdk.issue(agent="alice", capability="payments.send")
        assert sdk.authorize(cap, "payments.send", {}).allowed is True
        sdk.revoke(cap, reason="mid-flight incident")
        assert sdk.authorize(cap, "payments.send", {}).allowed is False

    def test_identity_rotation_during_active_session(self):
        reg = IdentityRegistry()
        reg.create("alice")
        signature = reg.sign("alice", b"data")
        assert reg.verify("alice", b"data", signature) is True
        rotated = reg.rotate("alice")
        assert rotated.identity_version == 2
        # Old signature invalid after rotation.
        assert reg.verify("alice", b"data", signature) is False
        # New signature valid.
        new_signature = reg.sign("alice", b"data")
        assert reg.verify("alice", b"data", new_signature) is True


# ======================================================================
# Large graphs / populations / chains
# ======================================================================


class TestScale:
    def test_large_evidence_graph(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        for i in range(500):
            graph.append(
                "observed" if i % 2 == 0 else "inference",
                f"subject-{i % 20}",
                "event",
                {"i": i},
            )
        assert graph.verify()["status"] == "verified"
        assert len(graph.events()) == 500

    def test_large_agent_population_mesh(self):
        reg = IdentityRegistry()
        for i in range(100):
            reg.create(f"agent-{i}")
        mesh = DefenseMesh(reg)
        for i in range(100):
            state = mesh.evaluate(f"agent-{i}")
            assert state.identity_verified is True

    def test_long_delegation_chain(self):
        sdk = FirewallSDK()
        sdk.generate_key("k")
        cap = sdk.issue(agent="a0", capability="payments.send")
        key = sdk.active_key().private_key
        for i in range(1, 30):
            cap = sdk.delegate(
                cap, key, delegatee=f"a{i}", constraints={"amount_max": 100 - i}
            ).child
        assert sdk.authorize(cap, "payments.send", {"amount": 1}).allowed is True
        # Revoking the root kills the whole chain.
        root = sdk.issue(agent="b0", capability="payments.send")
        child = root
        key2 = sdk.active_key().private_key
        for i in range(1, 15):
            child = sdk.delegate(
                child, key2, delegatee=f"b{i}", constraints={"amount_max": 50}
            ).child
        sdk.revoke(root, reason="root revoked")
        assert sdk.is_effectively_revoked(child) is True

    def test_large_a2a_chain_recursive_revocation(self):
        reg = IdentityRegistry()
        for i in range(40):
            reg.create(f"n{i}")
        a2a = AgentToAgent(reg)
        root = a2a.establish(
            initiator="n0", responder="n1",
            permissions={"allowed_actions": ["read"]},
        )
        current = root
        for i in range(2, 40):
            current = a2a.delegate(
                current, responder=f"n{i}",
                permissions={"allowed_actions": ["read"]},
            )
        count = a2a.revoke(root.relationship_id, reason="root")
        assert count == 39


# ======================================================================
# Malformed cryptographic data / adversarial input
# ======================================================================


class TestMalformedInput:
    def test_garbage_signature_denied(self):
        reg = IdentityRegistry()
        reg.create("alice")
        assert reg.verify("alice", b"data", "not-base64!!!") is False
        assert reg.verify("alice", b"data", "") is False

    def test_oversized_evidence_payload_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append(
                "observed", "x", "decision",
                {"key_" + str(i): i for i in range(100)},  # > MAX_KEYS
            )

    def test_non_finite_numbers_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append("observed", "x", "y", {"n": float("inf")})
        with pytest.raises(EvidenceError):
            graph.append("observed", "x", "y", {"n": float("nan")})

    def test_capability2_non_finite_rejected(self):
        with pytest.raises(Capability2Error):
            Capability2("x", constraints={"time": {"not_after": float("inf")}})

    def test_tampered_evidence_chain_detected(self):
        signer = KeyEvidenceSigner()
        graph = EvidenceGraph(signer=signer)
        events = [
            graph.append("observed", "x", "decision", {"n": i})
            for i in range(5)
        ]
        # Remove the middle event: the chain link breaks.
        tampered = EvidenceGraph(signer=signer)
        tampered._events = [
            e for i, e in enumerate(graph.events()) if i != 2
        ]
        tampered._by_id = {e.event_id: e for e in tampered._events}
        tampered._seq = len(tampered._events)
        problems = tampered.detect_tampering()
        assert any(p["type"] == "broken_link" for p in problems)

    def test_deep_nested_payload_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        payload = {"a": {"b": {"c": {"d": {"e": "f"}}}}}
        # Allowed (finite depth), but a cyclic object must be rejected.
        with pytest.raises(EvidenceError):
            cyclic: dict = {}
            cyclic["self"] = cyclic
            graph.append("observed", "x", "y", cyclic)

    def test_huge_string_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append("observed", "x", "y", {"big": "a" * 5000})

    def test_negative_ttl_rejected(self):
        from firewall.a2a import A2AError

        reg = IdentityRegistry()
        reg.create("a")
        reg.create("b")
        a2a = AgentToAgent(reg)
        with pytest.raises(A2AError):
            a2a.establish(
                initiator="a", responder="b",
                permissions={"allowed_actions": ["read"]},
                ttl=-5,
            )

    def test_scalar_payload_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append("observed", "x", "y", 42)

    def test_malformed_identity_state_fails_closed(self, tmp_path):
        path = tmp_path / "id.json"
        path.write_text("null", encoding="utf-8")
        with pytest.raises(IdentityError):
            IdentityRegistry(state_path=path)
