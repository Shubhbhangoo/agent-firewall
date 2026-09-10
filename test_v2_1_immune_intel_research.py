"""v2.1 unit tests: immune system, intelligence engine, research lab."""

from __future__ import annotations

import time

import pytest

from firewall.containment import ContainmentAction, ContainmentController
from firewall.defense import DefenseMesh
from firewall.evidence_graph import EvidenceGraph, KeyEvidenceSigner
from firewall.ident import IdentityRegistry
from firewall.immune import (
    ImmuneAdvice,
    ImmuneError,
    ImmunePolicy,
    ImmuneRule,
    ImmuneSignal,
    ImmuneSystem,
)
from firewall.intel import IntelligenceEngine
from firewall.posture import PostureEngine, PostureSignal
from firewall.research import (
    SCENARIOS,
    ResearchError,
    SecurityResearchLab,
)
from firewall.sdk import FirewallSDK


# ======================================================================
# Immune system
# ======================================================================


class TestImmuneSystem:
    def _system(self, with_evidence=True):
        reg = IdentityRegistry()
        reg.create("agent-x")
        sdk = FirewallSDK()
        sdk.generate_key("k1")
        sdk.issue(agent="agent-x", capability="payments.send")
        posture = PostureEngine()
        controller = ContainmentController(
            sdk, authorizer=lambda: True
        )
        mesh = DefenseMesh(reg, posture=posture, containment=controller)
        mesh.attach_sdk(sdk)
        evidence = EvidenceGraph(signer=KeyEvidenceSigner()) if with_evidence else None
        immune = ImmuneSystem(
            mesh,
            posture=posture,
            containment=controller,
            evidence_graph=evidence,
            approver=lambda stage, agent: True,
        )
        return immune, posture

    def test_observe_feeds_posture(self):
        immune, posture = self._system()
        immune.observe(
            ImmuneSignal("agent-x", "authorization_denial", "denied", "medium")
        )
        assert posture.state("agent-x").posture != "unknown"

    def test_detect_repeated_denials(self):
        immune, posture = self._system()
        for i in range(3):
            immune.observe(
                ImmuneSignal(
                    "agent-x", "authorization_denial", f"denied {i}", "medium"
                )
            )
        detections = immune.detect(agent="agent-x")
        assert any(d.rule_id == "repeated_denials" for d in detections)

    def test_detect_compromised_posture(self):
        immune, posture = self._system()
        posture.ingest(
            "agent-x",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        detections = immune.detect(agent="agent-x")
        assert any(d.rule_id == "compromised_posture" for d in detections)

    def test_model_output_cannot_self_authorize(self):
        immune, posture = self._system()
        posture.ingest(
            "agent-x",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        # No policy at all: even a critical detection with a demanding
        # reasoner must be skipped, not executed.
        detections = immune.detect(agent="agent-x")

        def evil_reasoner(detection, state):
            return ImmuneAdvice(
                detection_id=detection.detection_id,
                hypothesis="escalate everything",
                recommended_actions=(
                    {"action": "quarantine", "agent": detection.agent},
                ),
                model="evil-model",
            )

        immune._reasoner = evil_reasoner
        for detection in detections:
            advice = immune.reason(detection)
            action = immune.contain(detection, advice)
            assert action.outcome == "skipped"
            assert "never self-authorizing" in action.detail

    def test_policy_rule_authorizes_quarantine(self):
        immune, posture = self._system()
        immune.set_policy(
            ImmunePolicy(
                rules=(
                    ImmuneRule(
                        "compromised_posture",
                        stage="quarantine",
                        min_severity="high",
                        auto_approve=False,
                    ),
                )
            )
        )
        posture.ingest(
            "agent-x",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        immune.observe(
            ImmuneSignal("agent-x", "compromise", "compromised", "critical")
        )
        detections = immune.detect(agent="agent-x")
        executed = False
        for detection in detections:
            if detection.rule_id != "compromised_posture":
                continue
            action = immune.contain(detection, immune.reason(detection))
            if action.action == "quarantine":
                executed = action.outcome == "executed"
        assert executed is True

    def test_high_impact_requires_approval(self):
        immune, posture = self._system()
        immune.set_policy(
            ImmunePolicy(
                rules=(
                    ImmuneRule(
                        "compromised_posture",
                        stage="quarantine",
                        min_severity="high",
                        auto_approve=False,
                    ),
                )
            )
        )
        # No approver attached: denied.
        immune._approver = None
        posture.ingest(
            "agent-x",
            PostureSignal(name="compromise", severity=8, description="x"),
        )
        detections = immune.detect(agent="agent-x")
        denied = [
            immune.contain(d, immune.reason(d))
            for d in detections
            if d.rule_id == "compromised_posture"
        ]
        assert denied and all(a.outcome == "denied" for a in denied)

    def test_recovery_requires_verification(self):
        immune, posture = self._system()
        action = immune.recover("agent-x", reason="clean bill")
        # Agent-x was never quarantined; the mesh-state gate denies.
        assert action.outcome == "denied"
        assert "nothing to recover" in action.detail

    def test_verify_report_shape(self):
        immune, posture = self._system()
        verification = immune.verify("agent-x")
        assert "recoverable" in verification
        assert "reason" in verification

    def test_evidence_recorded(self):
        immune, posture = self._system(with_evidence=True)
        for i in range(3):
            immune.observe(
                ImmuneSignal(
                    "agent-x", "authorization_denial", f"denied {i}", "medium"
                )
            )
        immune.detect(agent="agent-x")
        events = immune._evidence.events()
        assert events
        kinds = {e.kind for e in events}
        assert "observed" in kinds
        assert "inference" in kinds

    def test_invalid_rule_stage_rejected(self):
        with pytest.raises(ImmuneError):
            ImmuneRule("x", stage="nonsense")

    def test_run_cycle_transcript(self):
        immune, posture = self._system()
        immune.observe(
            ImmuneSignal("agent-x", "authorization_denial", "denied", "medium")
        )
        immune.observe(
            ImmuneSignal("agent-x", "authorization_denial", "denied", "medium")
        )
        immune.observe(
            ImmuneSignal("agent-x", "authorization_denial", "denied", "medium")
        )
        result = immune.run_cycle(agent="agent-x")
        assert result["cycle"]
        entry = result["cycle"][0]
        for key in ("detection", "advice", "simulation", "action", "verification"):
            assert key in entry


# ======================================================================
# Intelligence engine
# ======================================================================


class TestIntelligenceEngine:
    def _engine(self, model=None):
        posture = PostureEngine()
        posture.ingest(
            "agent-y",
            PostureSignal(name="unusual", severity=4, description="high risk"),
        )
        evidence = EvidenceGraph(signer=KeyEvidenceSigner())
        evidence.append(
            "observed", "agent-y", "containment", {"state": "quarantined"}
        )
        evidence.append(
            "inference", "agent-y", "immune_detection", {"rule": "x"}
        )
        return IntelligenceEngine(
            posture=posture,
            evidence_graph=evidence,
            model=model,
        )

    def test_facts_collected_with_basis(self):
        engine = self._engine()
        facts = engine.collect_facts()
        assert any(f.basis == "observed" for f in facts)
        assert any(f.basis == "inferred" for f in facts)

    def test_hypotheses_explainable(self):
        engine = self._engine()
        report = engine.analyze(agent="agent-y")
        assert report.hypotheses
        hypothesis = report.hypotheses[0]
        assert hypothesis.rationale
        assert hypothesis.supporting_facts
        assert hypothesis.basis == "inferred"
        assert 0.0 <= hypothesis.confidence <= 1.0

    def test_model_output_marked_and_advisory(self):
        def model(facts, hypotheses):
            return {
                "hypotheses": [
                    {
                        "title": "model says compromise",
                        "severity": "critical",
                        "confidence": 0.99,
                        "recommended_actions": [
                            {"action": "quarantine", "agent": "agent-y"}
                        ],
                    }
                ]
            }

        engine = self._engine(model=model)
        report = engine.analyze(agent="agent-y")
        model_hypotheses = [
            h for h in report.hypotheses if h.model_generated
        ]
        assert model_hypotheses
        assert model_hypotheses[0].basis == "inferred"
        # Built-ins remain.
        assert any(not h.model_generated for h in report.hypotheses)

    def test_invalid_model_output_ignored(self):
        engine = self._engine(model=lambda facts, hyps: "garbage")
        report = engine.analyze()
        assert all(not h.model_generated for h in report.hypotheses)

    def test_unknown_agent_no_facts(self):
        engine = self._engine()
        report = engine.analyze(agent="ghost")
        assert report.facts == ()


# ======================================================================
# Research lab
# ======================================================================


class TestResearchLab:
    def test_all_scenarios_defended(self):
        lab = SecurityResearchLab()
        report = lab.run_all()
        assert report.violated() == ()
        assert len(report.findings) == len(SCENARIOS)

    def test_unknown_scenario_rejected(self):
        lab = SecurityResearchLab()
        with pytest.raises(ResearchError):
            lab.run("does_not_exist")

    def test_property_tests_pass(self):
        lab = SecurityResearchLab()
        results = lab.property_tests()
        assert results
        assert all(result["passed"] for result in results.values())

    def test_regression_seed_format(self):
        lab = SecurityResearchLab()
        payload = lab.report()
        assert "violations" in payload
        assert "findings" in payload
        assert "regression_hint" in payload

    def test_scenario_isolation(self):
        """Each scenario runs in a fresh workspace; prior scenarios
        cannot leak state into later ones."""

        lab = SecurityResearchLab()
        first = lab.run("malicious_agent")
        second = lab.run("malicious_agent")
        assert first.to_dict() == second.to_dict()

    def test_each_violation_is_a_regression_seed(self):
        lab = SecurityResearchLab()
        report = lab.run_all()
        for finding in report.findings:
            assert finding.scenario in SCENARIOS
            assert isinstance(finding.reproduced, dict)
            assert "reproduced" in finding.to_dict()
