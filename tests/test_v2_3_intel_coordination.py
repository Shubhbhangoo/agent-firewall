"""v2.3: cross-agent coordination correlation and honest gap reporting.

Two properties are under test here.

**A blinded source is not a quiet one.** ``collect_facts`` previously
wrapped four of its five sources in ``except Exception: pass``, so a
trust graph that raised produced a report identical to one from a
healthy estate with nothing to report. Every configured source that
raises now names itself in ``gaps``, and an unwired source does not --
unwired is *unknown* and the caller chose it; wired-and-failing is a
probe failure.

**Coordination detection must name what is shared.** The deleted
``firewall.correlation`` package emitted a ``temporal_trust_coordination``
pattern for every pair of agents while its trust check was a comment
reading ``# Simplified check``, and its only trust-relationship source
was a bare ``pass`` inside a swallowed ``try``. A detector that fires on
every pair carries no information. Each pattern here requires two
distinct agents and a concrete shared value.
"""

from __future__ import annotations

import time

import pytest

from firewall.evidence_graph import EvidenceGraph, KeyEvidenceSigner
from firewall.intel import (
    EvidenceFact,
    FactCollection,
    IntelligenceEngine,
)
from firewall.posture import PostureEngine, PostureSignal


def _graph() -> EvidenceGraph:
    return EvidenceGraph(signer=KeyEvidenceSigner())


def _posture(agent: str = "agent-y") -> PostureEngine:
    engine = PostureEngine()
    engine.ingest(
        agent,
        PostureSignal(name="unusual", severity=4, description="high risk"),
    )
    return engine


class _Raises:
    """A configured source that fails every probe."""

    def __init__(self, message: str = "probe down") -> None:
        self._message = message

    def find_dangers(self):
        raise RuntimeError(self._message)

    def escalation_paths(self):
        raise RuntimeError(self._message)

    def chokepoints(self):
        raise RuntimeError(self._message)

    def all_states(self):
        raise RuntimeError(self._message)

    def events(self):
        raise RuntimeError(self._message)


def _titles(report) -> list[str]:
    return [h.title for h in report.hypotheses]


# ======================================================================
# Gaps: a source that could not be read is not a source with nothing
# ======================================================================


class TestGapReporting:
    def test_configured_source_that_raises_is_named(self):
        engine = IntelligenceEngine(posture=_posture())
        engine._trust = _Raises("trust graph offline")

        report = engine.analyze()

        assert report.complete is False
        assert any("trust" in gap for gap in report.gaps)
        assert any("trust graph offline" in gap for gap in report.gaps)

    def test_unwired_source_is_not_a_gap(self):
        # No trust graph, no attack graph, no evidence graph. Unwired is
        # unknown, and the caller chose it -- reporting it as a failure
        # would make every minimal engine look broken.
        engine = IntelligenceEngine(posture=_posture())

        report = engine.analyze()

        assert report.gaps == ()
        assert report.complete is True

    def test_every_source_can_report_its_own_failure(self):
        engine = IntelligenceEngine()
        engine._posture = _Raises()
        engine._trust = _Raises()
        engine._attack_graph = _Raises()
        engine._evidence = _Raises()

        report = engine.analyze()

        assert report.complete is False
        # posture, trust, escalation paths, chokepoints, evidence.
        assert len(report.gaps) == 5

    def test_blinded_engine_is_distinguishable_from_a_clean_one(self):
        clean = IntelligenceEngine(evidence_graph=_graph())
        blinded = IntelligenceEngine(evidence_graph=_Raises())

        clean_report = clean.analyze()
        blinded_report = blinded.analyze()

        # Both are empty. Only one of them checked anything.
        assert clean_report.hypotheses == ()
        assert blinded_report.hypotheses == ()
        assert clean_report.complete is True
        assert blinded_report.complete is False

    def test_model_failure_is_a_gap_not_a_silence(self):
        def model(facts, hypotheses):
            raise RuntimeError("provider timeout")

        engine = IntelligenceEngine(posture=_posture(), model=model)

        report = engine.analyze()

        assert report.complete is False
        assert any("model enrichment failed" in g for g in report.gaps)
        assert all(not h.model_generated for h in report.hypotheses)

    def test_invalid_model_output_is_not_a_gap(self):
        # Garbage output is refused by _model_hypotheses without raising.
        # That is a rejected claim, not an unreadable source.
        engine = IntelligenceEngine(
            posture=_posture(), model=lambda facts, hyps: "garbage"
        )

        report = engine.analyze()

        assert report.gaps == ()
        assert all(not h.model_generated for h in report.hypotheses)

    def test_gaps_survive_the_agent_filter(self):
        # The filter narrows facts by subject. A gap is about a source,
        # not about an agent, so filtering to one agent must not discard
        # the fact that a source could not be read.
        engine = IntelligenceEngine(posture=_posture())
        engine._trust = _Raises()

        report = engine.analyze(agent="nobody")

        assert report.facts == ()
        assert report.complete is False

    def test_report_dict_carries_gaps(self):
        engine = IntelligenceEngine(posture=_posture())
        engine._trust = _Raises()

        payload = engine.analyze().to_dict()

        assert payload["complete"] is False
        assert payload["gaps"]
        assert payload["basis"] == "inferred"


class TestFactCollection:
    def test_behaves_as_a_tuple_of_facts(self):
        fact = EvidenceFact(kind="posture", subject="a")
        collection = FactCollection([fact], ["source failed"])

        assert collection == (fact,)
        assert len(collection) == 1
        assert collection[0] is fact
        assert list(collection) == [fact]

    def test_empty_collection_equals_empty_tuple(self):
        assert FactCollection() == ()
        assert FactCollection().gaps == ()

    def test_collect_facts_returns_gaps_alongside_facts(self):
        engine = IntelligenceEngine(posture=_posture())
        engine._trust = _Raises()

        collected = engine.collect_facts()

        assert collected  # posture fact present
        assert collected.gaps


# ======================================================================
# Coordination: each pattern must name what is shared
# ======================================================================


class TestSharedResourceCoordination:
    def test_two_agents_on_one_resource_is_reported(self):
        graph = _graph()
        graph.append(
            "observed", "agent-a", "tool_call", {"resource": "db://prod"}
        )
        graph.append(
            "observed", "agent-b", "tool_call", {"resource": "db://prod"}
        )
        engine = IntelligenceEngine(evidence_graph=graph)

        report = engine.analyze()
        shared = [
            h for h in report.hypotheses if "shared resource" in h.title
        ]

        assert len(shared) == 1
        assert "agent-a" in shared[0].description
        assert "agent-b" in shared[0].description
        assert shared[0].basis == "inferred"
        assert shared[0].rationale
        assert shared[0].supporting_facts

    def test_one_agent_touching_a_resource_twice_is_not_coordination(self):
        graph = _graph()
        graph.append(
            "observed", "agent-a", "tool_call", {"resource": "db://prod"}
        )
        graph.append(
            "observed", "agent-a", "tool_call", {"resource": "db://prod"}
        )
        engine = IntelligenceEngine(evidence_graph=graph)

        assert not [
            h
            for h in engine.analyze().hypotheses
            if "shared resource" in h.title
        ]

    def test_distinct_resources_are_not_correlated(self):
        graph = _graph()
        graph.append(
            "observed", "agent-a", "tool_call", {"resource": "db://a"}
        )
        graph.append(
            "observed", "agent-b", "tool_call", {"resource": "db://b"}
        )
        engine = IntelligenceEngine(evidence_graph=graph)

        assert not [
            h
            for h in engine.analyze().hypotheses
            if "shared resource" in h.title
        ]

    def test_one_finding_per_shared_value_not_one_per_pair(self):
        graph = _graph()
        for agent in ("agent-a", "agent-b", "agent-c"):
            graph.append(
                "observed", agent, "tool_call", {"resource": "db://prod"}
            )
        engine = IntelligenceEngine(evidence_graph=graph)

        shared = [
            h
            for h in engine.analyze().hypotheses
            if "shared resource" in h.title
        ]

        # Three pairwise combinations, one finding.
        assert len(shared) == 1
        assert "3 agents" in shared[0].title
        assert len(shared[0].recommended_actions) == 3


class TestSharedCredentialCoordination:
    def test_shared_key_fingerprint_is_high_severity(self):
        graph = _graph()
        graph.append(
            "observed", "agent-a", "tool_call", {"key_fingerprint": "ab:cd"}
        )
        graph.append(
            "observed", "agent-b", "tool_call", {"key_fingerprint": "ab:cd"}
        )
        engine = IntelligenceEngine(evidence_graph=graph)

        shared = [
            h
            for h in engine.analyze().hypotheses
            if "credential material" in h.title
        ]

        assert len(shared) == 1
        assert shared[0].severity == "high"

    def test_evidence_signer_is_not_a_grouping_key(self):
        # Every event in one graph is signed by the same recorder key.
        # Grouping on it would tie the whole estate together on every
        # run -- a finding that always fires is not a finding.
        graph = _graph()
        graph.append("observed", "agent-a", "tool_call", {"x": 1})
        graph.append("observed", "agent-b", "tool_call", {"x": 2})
        engine = IntelligenceEngine(evidence_graph=graph)

        assert not [
            h
            for h in engine.analyze().hypotheses
            if "credential material" in h.title
        ]


class TestTemporalCoordination:
    def test_routine_activity_in_one_window_is_not_reported(self):
        # Two agents, same minute, nothing consequential recorded.
        graph = _graph()
        graph.append("observed", "agent-a", "tool_call", {"x": 1})
        graph.append("observed", "agent-b", "tool_call", {"x": 2})
        engine = IntelligenceEngine(evidence_graph=graph)

        assert not [
            h
            for h in engine.analyze().hypotheses
            if "temporal proximity" in h.title
        ]

    def test_proximity_to_a_consequential_event_is_reported(self):
        graph = _graph()
        graph.append("observed", "agent-a", "containment", {"state": "q"})
        graph.append("observed", "agent-b", "tool_call", {"x": 1})
        engine = IntelligenceEngine(evidence_graph=graph)

        proximity = [
            h
            for h in engine.analyze().hypotheses
            if "temporal proximity" in h.title
        ]

        assert len(proximity) == 1
        assert proximity[0].severity == "low"
        assert proximity[0].basis == "inferred"

    def test_proximity_asserts_no_trust_relationship(self):
        graph = _graph()
        graph.append("observed", "agent-a", "containment", {"state": "q"})
        graph.append("observed", "agent-b", "tool_call", {"x": 1})
        engine = IntelligenceEngine(evidence_graph=graph)

        proximity = [
            h
            for h in engine.analyze().hypotheses
            if "temporal proximity" in h.title
        ]

        # The rationale must state the limit rather than imply a link.
        assert "no trust relationship" in proximity[0].rationale

    def test_a_single_agent_is_never_proximate_to_itself(self):
        graph = _graph()
        graph.append("observed", "agent-a", "containment", {"state": "q"})
        graph.append("observed", "agent-a", "containment", {"state": "q2"})
        engine = IntelligenceEngine(evidence_graph=graph)

        assert not [
            h
            for h in engine.analyze().hypotheses
            if "temporal proximity" in h.title
        ]


class TestEscalationPathCoordination:
    class _Paths:
        def __init__(self, *findings):
            self._findings = findings

        def escalation_paths(self):
            return self._findings

        def chokepoints(self):
            return []

    class _Finding:
        def __init__(self, agents, description="a -> b"):
            self.agents = agents
            self.description = description
            self.basis = "inferred"

    def test_path_spanning_two_agents_is_reported(self):
        engine = IntelligenceEngine()
        engine._attack_graph = self._Paths(
            self._Finding(("agent-a", "agent-b"))
        )

        spans = [
            h
            for h in engine.analyze().hypotheses
            if "escalation path spans" in h.title
        ]

        assert len(spans) == 1
        assert spans[0].severity == "high"
        assert "agent-a" in spans[0].description
        assert "agent-b" in spans[0].description
        assert len(spans[0].recommended_actions) == 2

    def test_single_agent_path_is_not_coordination(self):
        engine = IntelligenceEngine()
        engine._attack_graph = self._Paths(self._Finding(("agent-a",)))

        assert not [
            h
            for h in engine.analyze().hypotheses
            if "escalation path spans" in h.title
        ]

    def test_reachability_is_not_claimed_as_exploitability(self):
        engine = IntelligenceEngine()
        engine._attack_graph = self._Paths(
            self._Finding(("agent-a", "agent-b"))
        )

        spans = [
            h
            for h in engine.analyze().hypotheses
            if "escalation path spans" in h.title
        ]

        assert "not" in spans[0].rationale
        assert "exploitability" in spans[0].rationale


# ======================================================================
# The correlation package is gone, not renamed
# ======================================================================


class TestCorrelationPackageRemoved:
    def test_firewall_correlation_no_longer_exists(self):
        # It had zero importers and zero tests, and two of its six
        # detection paths were structurally dead. Coordination detection
        # lives in firewall.intel, where hypotheses carry evidence, a
        # rationale and inferred provenance.
        with pytest.raises(ImportError):
            __import__("firewall.correlation")

    def test_coordination_output_is_never_authority(self):
        graph = _graph()
        graph.append(
            "observed", "agent-a", "tool_call", {"resource": "db://prod"}
        )
        graph.append(
            "observed", "agent-b", "tool_call", {"resource": "db://prod"}
        )
        engine = IntelligenceEngine(evidence_graph=graph)

        report = engine.analyze()

        assert report.to_dict()["basis"] == "inferred"
        assert all(h.basis == "inferred" for h in report.hypotheses)
        # The engine cannot decide anything.
        assert not hasattr(engine, "authorize")
        assert not hasattr(report, "allowed")
