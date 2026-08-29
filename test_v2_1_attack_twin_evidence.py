"""v2.1 unit tests: attack graph, digital twin, evidence graph."""

from __future__ import annotations

import json
import time

import pytest

from firewall.attackgraph import (
    AttackGraph,
    AttackGraphError,
)
from firewall.evidence_graph import (
    EvidenceError,
    EvidenceGraph,
    EvidenceKind,
    IdentityEvidenceSigner,
    KeyEvidenceSigner,
)
from firewall.ident import IdentityRegistry
from firewall.network import AgentNetworkGraph
from firewall.network.model import (
    EntityType,
    NetworkEdge,
    NetworkNode,
    Provenance,
    RelationType,
    entity_id,
)
from firewall.twin import SecurityTwin, TwinError


def _sample_network() -> AgentNetworkGraph:
    g = AgentNetworkGraph()

    def nid(t, k):
        return entity_id(t, k)

    nodes = [
        NetworkNode(nid(EntityType.AGENT, "alice"), EntityType.AGENT, "alice", Provenance.OBSERVED),
        NetworkNode(nid(EntityType.AGENT, "bob"), EntityType.AGENT, "bob", Provenance.OBSERVED),
        NetworkNode(nid(EntityType.CAPABILITY, "payments.send"), EntityType.CAPABILITY, "payments.send", Provenance.OBSERVED),
        NetworkNode(nid(EntityType.TOOL, "payments"), EntityType.TOOL, "payments", Provenance.OBSERVED),
        NetworkNode(nid(EntityType.RESOURCE, "/etc/shadow"), EntityType.RESOURCE, "/etc/shadow", Provenance.OBSERVED),
    ]
    for node in nodes:
        g._nodes[node.id] = node
    g._edges = [
        NetworkEdge(nid(EntityType.CAPABILITY, "payments.send"), nid(EntityType.AGENT, "alice"), RelationType.ISSUED, Provenance.OBSERVED),
        NetworkEdge(nid(EntityType.CAPABILITY, "payments.send"), nid(EntityType.TOOL, "payments"), RelationType.BOUND_TO, Provenance.OBSERVED),
        NetworkEdge(nid(EntityType.TOOL, "payments"), nid(EntityType.RESOURCE, "/etc/shadow"), RelationType.ACCESSES, Provenance.OBSERVED),
        NetworkEdge(nid(EntityType.AGENT, "alice"), nid(EntityType.AGENT, "bob"), RelationType.DELEGATED, Provenance.OBSERVED),
    ]
    return g


# ======================================================================
# Attack graph
# ======================================================================


class TestAttackGraph:
    def test_from_network(self):
        graph = AttackGraph.from_network(_sample_network())
        assert graph.node("agent:alice") is not None
        assert graph.node("identity:alice") is not None
        paths = graph.paths_to("/etc/shadow")
        assert paths
        assert paths[0].basis == "observed"
        assert paths[0].potentially_dangerous is True

    def test_path_basis_is_weakest_hop(self):
        graph = AttackGraph.from_network(_sample_network())
        # Add a simulated hop: bob -> shadow simulated.
        graph.add_edge(
            "agent:bob",
            "resource:/etc/shadow",
            "accesses",
            basis="simulated",
        )
        paths = graph.paths_to("resource:/etc/shadow", from_agents=["agent:bob"])
        assert paths
        assert paths[0].basis == "simulated"

    def test_blast_radius_sensitive_targets(self):
        graph = AttackGraph.from_network(_sample_network())
        radius = graph.blast_radius("alice")
        assert "/etc/shadow" in radius["sensitive_targets"]

    def test_escalation_paths_finding(self):
        graph = AttackGraph.from_network(_sample_network())
        findings = graph.escalation_paths()
        assert findings
        assert findings[0].type == "privilege_escalation_path"
        assert findings[0].basis in (
            "observed",
            "derived",
        )

    def test_chokepoints(self):
        graph = AttackGraph.from_network(_sample_network())
        chokepoints = graph.chokepoints()
        assert isinstance(chokepoints, list)
        assert all("paths" in c for c in chokepoints)

    def test_capability_combinations(self):
        graph = AttackGraph.from_network(_sample_network())
        combos = graph.capability_combinations("alice")
        assert isinstance(combos, list)

    def test_unknown_agent_fails_closed(self):
        graph = AttackGraph.from_network(_sample_network())
        reach = graph.reachable("ghost")
        assert reach["capabilities"] == []

    def test_invalid_max_hops(self):
        graph = AttackGraph.from_network(_sample_network())
        with pytest.raises(AttackGraphError):
            graph.paths_to("/etc/shadow", max_hops=0)

    def test_serialization_round_trip(self):
        graph = AttackGraph.from_network(_sample_network())
        data = graph.to_dict()
        clone = AttackGraph()
        for node in data["nodes"]:
            clone.add_node(
                node["id"], node["type"], node["label"],
                basis=node["basis"],
                evidence=node.get("evidence", []),
                attributes=node.get("attributes", {}),
            )
        for edge in data["edges"]:
            clone.add_edge(
                edge["source"], edge["target"], edge["type"],
                basis=edge["basis"],
                evidence=edge.get("evidence", []),
                attributes=edge.get("attributes", {}),
            )
        assert clone.summarize()["nodes"] == graph.summarize()["nodes"]


# ======================================================================
# Digital twin
# ======================================================================


class TestTwin:
    def test_compromise_is_simulated_and_isolated(self):
        twin = SecurityTwin.from_network(_sample_network())
        base = twin.snapshot()
        report = twin.compromise("alice")
        assert report.kind == "compromised_agent"
        assert report.basis == "simulated"
        # Production graph untouched.
        reach = _sample_network().reachable("alice")
        assert "payments.send" in reach.capabilities

    def test_unknown_agent_compromise_raises(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        with pytest.raises(TwinError):
            twin.compromise("ghost")

    def test_revoke_capability_delta(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.revoke_capability("alice", "payments.send")
        assert any(
            delta.removed_capabilities
            for delta in report.reachability_deltas
        )

    def test_revoke_unknown_capability_raises(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        with pytest.raises(TwinError):
            twin.revoke_capability("alice", "does.not.exist")

    def test_untrust_tool(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.untrust_tool("payments")
        assert report.kind == "untrusted_tool"

    def test_delegate_to_new_agent(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.delegate("alice", "carol")
        assert any(
            delta.agent == "carol" and delta.added_capabilities
            for delta in report.reachability_deltas
        )

    def test_expose_credential(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.expose_credential("bob", credential="db-password")
        assert any(
            "db-password" in delta.added_resources
            for delta in report.reachability_deltas
        )

    def test_dispatch(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.run("compromised_agent", agent="alice")
        assert report.kind == "compromised_agent"
        with pytest.raises(TwinError):
            twin.run("bogus_kind")

    def test_reachability_delta_risk(self):
        twin = SecurityTwin.from_network(_sample_network())
        twin.snapshot()
        report = twin.expose_credential("bob", credential="root-password")
        assert any(
            delta.risk_delta() >= 1 for delta in report.reachability_deltas
        )


# ======================================================================
# Evidence graph
# ======================================================================


class TestEvidenceGraph:
    def test_append_and_verify(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        graph.append("observed", "agent-a", "decision", {"allowed": True})
        graph.append("inference", "agent-a", "behavior", {"score": 0.9})
        result = graph.verify()
        assert result["status"] == "verified"

    def test_kinds_never_conflated(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        graph.append("observed", "x", "decision", {})
        graph.append("inference", "x", "finding", {})
        graph.append("prediction", "x", "forecast", {})
        graph.append("simulation", "x", "twin", {})
        kinds = [e.kind for e in graph.events()]
        assert kinds == ["observed", "inference", "prediction", "simulation"]

    def test_hash_link_order(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        e1 = graph.append("observed", "x", "a", {})
        e2 = graph.append("observed", "x", "b", {})
        assert e2.prev_hash == e1.event_id
        assert e1.event_id != e2.event_id

    def test_tamper_detected(self):
        signer = KeyEvidenceSigner()
        graph = EvidenceGraph(signer=signer)
        e1 = graph.append("observed", "x", "decision", {"allowed": True})
        payload = e1.to_dict()
        payload["payload"] = {"allowed": False}

        tampered = EvidenceGraph(signer=signer)
        from firewall.evidence_graph import EvidenceEvent

        entry = EvidenceEvent.from_dict(payload)
        tampered._events.append(entry)
        tampered._by_id[entry.event_id] = entry
        tampered._seq = 1
        problems = tampered.detect_tampering()
        assert any(p["type"] == "hash_mismatch" for p in problems)
        assert tampered.verify()["status"] == "failed"

    def test_reordering_detected(self):
        signer = KeyEvidenceSigner()
        graph = EvidenceGraph(signer=signer)
        e1 = graph.append("observed", "x", "a", {})
        e2 = graph.append("observed", "x", "b", {})
        # Swap.
        tampered = EvidenceGraph(signer=signer)
        tampered._events = [e2, e1]
        tampered._by_id = {e1.event_id: e1, e2.event_id: e2}
        tampered._seq = 2
        problems = tampered.detect_tampering()
        assert any(p["type"] == "broken_link" for p in problems)

    def test_unsigned_event_unverifiable(self):
        graph = EvidenceGraph()
        graph.append("observed", "x", "decision", {})
        assert graph.verify()["status"] == "unverifiable"

    def test_promotion_is_explicit_and_non_destructive(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        inference = graph.append("inference", "agent-a", "behavior", {})
        promoted = graph.promote(
            inference.event_id, reason="confirmed by investigation"
        )
        assert promoted.kind == "observed"
        assert promoted.payload["promoted_from"] == inference.event_id
        assert promoted.payload["promoted_kind"] == "inference"
        # Original untouched.
        assert graph.by_id(inference.event_id).kind == "inference"
        # The promoted event causally references the original.
        assert inference.event_id in promoted.causal_parents

    def test_promote_observed_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        event = graph.append("observed", "x", "decision", {})
        with pytest.raises(EvidenceError):
            graph.promote(event.event_id, reason="already observed")

    def test_promote_requires_reason(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        event = graph.append("inference", "x", "behavior", {})
        with pytest.raises(EvidenceError):
            graph.promote(event.event_id, reason="  ")

    def test_missing_causal_parent_rejected(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append(
                "observed", "x", "a", {},
                causal_parents=("f" * 64,),
            )

    def test_timeline_causal_order(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        e1 = graph.append("observed", "agent-a", "auth", {"peer": "b"})
        e2 = graph.append("inference", "agent-a", "behavior", {}, causal_parents=(e1.event_id,))
        e3 = graph.append("prediction", "agent-a", "forecast", {}, causal_parents=(e2.event_id,))
        timeline = graph.timeline("agent-a")
        assert [t["event_id"] for t in timeline] == [
            e1.event_id,
            e2.event_id,
            e3.event_id,
        ]

    def test_provenance_chain_walks_to_root(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        e1 = graph.append("observed", "agent-a", "auth", {})
        e2 = graph.append("inference", "agent-a", "behavior", {}, causal_parents=(e1.event_id,))
        e3 = graph.append("inference", "agent-a", "more", {}, causal_parents=(e2.event_id,))
        chain = graph.provenance_chain(e3.event_id)
        assert [c["event_id"] for c in chain] == [
            e3.event_id,
            e2.event_id,
            e1.event_id,
        ]

    def test_identity_signer_revocation_invalidates(self):
        reg = IdentityRegistry()
        reg.create("agent-a")
        signer = IdentityEvidenceSigner(reg, "agent-a")
        graph = EvidenceGraph(signer=signer)
        graph.append("observed", "agent-a", "auth", {})
        assert graph.verify()["status"] == "verified"
        reg.revoke("agent-a")
        assert graph.verify()["status"] == "failed"

    def test_persistence_round_trip(self, tmp_path):
        path = tmp_path / "evidence.json"
        graph = EvidenceGraph(signer=KeyEvidenceSigner(), state_path=path)
        graph.append("observed", "x", "decision", {"ok": True})
        graph.close()

        reloaded = EvidenceGraph(
            signer=KeyEvidenceSigner(), state_path=path
        )
        assert len(reloaded.events()) == 1
        # Signatures do not survive a reload with a *different* signer,
        # so verification reports failed/unverifiable honestly.
        assert reloaded.verify()["status"] != "verified"

    def test_payload_rejects_non_jsonable(self):
        graph = EvidenceGraph(signer=KeyEvidenceSigner())
        with pytest.raises(EvidenceError):
            graph.append(
                "observed", "x", "decision",
                {"bad": object()},
            )
