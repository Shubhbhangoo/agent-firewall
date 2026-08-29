"""v2.1 Security Intelligence Engine (firewall.intel).

A security-analysis layer that correlates evidence, agent behavior,
trust relationships, provenance, posture, attack paths, policy changes,
and response history into **explainable security hypotheses** with
recommended containment actions.

Design rules:

* **Never authoritative.** The engine produces hypotheses and
  recommendations. Nothing it returns can authorize, bypass, or relax a
  decision. The immune system's deterministic policy rules and the
  v2.0 pipeline remain the only execution paths.
* **Explainable.** Every hypothesis carries the exact evidence that
  produced it, a confidence, a severity, and a rationale.
* **Honest provenance.** Correlation output is labeled ``inferred``.
  Only facts recorded in an evidence graph are ``observed``; the two are
  never merged silently.
* **Deterministic unless fed a model.** All built-in correlations are
  pure functions of their inputs. An optional ``model`` provider may
  enrich hypotheses, but its output is advisory and clearly marked.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from firewall.attackgraph import AttackGraph
from firewall.posture import PostureEngine
from firewall.trust import TrustGraph

#: Severity ranking.
_SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class IntelError(ValueError):
    """Raised for an invalid intelligence request."""


@dataclass(frozen=True)
class EvidenceFact:
    """One fact the engine can reason over."""

    kind: str
    subject: str
    detail: str = ""
    basis: str = "inferred"
    severity: str = "low"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "detail": self.detail,
            "basis": self.basis,
            "severity": self.severity,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class SecurityHypothesis:
    """One explainable security hypothesis."""

    hypothesis_id: str
    title: str
    description: str
    severity: str
    confidence: float
    supporting_facts: tuple[EvidenceFact, ...] = ()
    recommended_actions: tuple[dict[str, Any], ...] = ()
    rationale: str = ""
    basis: str = "inferred"
    model_generated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "supporting_facts": [f.to_dict() for f in self.supporting_facts],
            "recommended_actions": [dict(a) for a in self.recommended_actions],
            "rationale": self.rationale,
            "basis": self.basis,
            "model_generated": self.model_generated,
        }


@dataclass(frozen=True)
class IntelligenceReport:
    """The engine's output for one analysis run."""

    hypotheses: tuple[SecurityHypothesis, ...] = ()
    facts: tuple[EvidenceFact, ...] = ()
    generated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "facts": [f.to_dict() for f in self.facts],
            "generated_at": self.generated_at,
            "basis": "inferred",
        }


class IntelligenceEngine:
    """Correlates security facts into explainable hypotheses.

    Sources (all optional, read-only):

    * ``posture``   -- :class:`PostureEngine` for per-agent posture.
    * ``trust``     -- :class:`TrustGraph` for trust findings.
    * ``attack_graph`` -- :class:`AttackGraph` for paths/chokepoints.
    * ``evidence_graph`` -- v2.1 evidence graph for observed facts.
    * ``model``     -- optional callable
        ``(facts, hypotheses_so_far) -> dict`` returning advisory
        enrichment; its output is flagged ``model_generated`` and can
        never change a built-in hypothesis's authority.
    """

    def __init__(
        self,
        *,
        posture: Optional[PostureEngine] = None,
        trust: Optional[TrustGraph] = None,
        attack_graph: Optional[AttackGraph] = None,
        evidence_graph=None,
        model: Optional[Callable[..., dict[str, Any]]] = None,
        clock: Any = None,
    ) -> None:
        if trust is not None and not isinstance(trust, TrustGraph):
            raise IntelError("trust must be a TrustGraph")
        if attack_graph is not None and not isinstance(
            attack_graph, AttackGraph
        ):
            raise IntelError("attack_graph must be an AttackGraph")
        if posture is not None and not isinstance(posture, PostureEngine):
            raise IntelError("posture must be a PostureEngine")
        if model is not None and not callable(model):
            raise IntelError("model must be callable")

        self._posture = posture
        self._trust = trust
        self._attack_graph = attack_graph
        self._evidence = evidence_graph
        self._model = model
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()
        self._counter = 0

    # ------------------------------------------------------------------
    # Fact gathering
    # ------------------------------------------------------------------

    def collect_facts(self) -> tuple[EvidenceFact, ...]:
        """Gather every fact the attached sources can provide."""

        facts: list[EvidenceFact] = []

        if self._posture is not None:
            for state in self._posture.all_states():
                posture = state.posture
                if posture in (
                    "suspicious",
                    "high_risk",
                    "compromised",
                    "contained",
                ):
                    facts.append(
                        EvidenceFact(
                            kind="posture",
                            subject=state.agent,
                            detail=f"posture is {posture}",
                            basis="inferred",
                            severity=_posture_severity(posture),
                        )
                    )

        if self._trust is not None:
            try:
                for danger in self._trust.find_dangers():
                    facts.append(
                        EvidenceFact(
                            kind="trust_danger",
                            subject=danger.get("agent", "?"),
                            detail=danger.get("description", ""),
                            basis=danger.get("basis", "inferred"),
                            severity="high",
                            metadata={"type": danger.get("type", "")},
                        )
                    )
            except Exception:
                pass

        if self._attack_graph is not None:
            try:
                for finding in self._attack_graph.escalation_paths():
                    facts.append(
                        EvidenceFact(
                            kind="attack_path",
                            subject=", ".join(finding.agents),
                            detail=finding.description,
                            basis=finding.basis,
                            severity="high",
                        )
                    )
            except Exception:
                pass
            try:
                for chokepoint in self._attack_graph.chokepoints():
                    facts.append(
                        EvidenceFact(
                            kind="chokepoint",
                            subject=chokepoint["label"],
                            detail=chokepoint["response"],
                            basis="derived",
                            severity="medium",
                        )
                    )
            except Exception:
                pass

        if self._evidence is not None:
            try:
                for event in self._evidence.events():
                    if event.kind == "observed":
                        facts.append(
                            EvidenceFact(
                                kind=event.event_type,
                                subject=event.subject,
                                detail=str(event.payload),
                                basis="observed",
                                severity="medium",
                                metadata={"event_id": event.event_id},
                            )
                        )
            except Exception:
                pass

        return tuple(facts)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        *,
        agent: Optional[str] = None,
    ) -> IntelligenceReport:
        """Correlate all facts into explainable hypotheses."""

        generated_at = float(self._clock())
        facts = self.collect_facts()

        if agent is not None:
            facts = tuple(
                f
                for f in facts
                if f.subject == agent or agent in f.subject
            )

        hypotheses: list[SecurityHypothesis] = []
        hypotheses.extend(self._correlate_posture_and_trust(facts))
        hypotheses.extend(self._correlate_attack_paths(facts))
        hypotheses.extend(self._correlate_evidence(facts))

        if self._model is not None:
            try:
                enrichment = self._model(facts, hypotheses)
                hypotheses.extend(
                    self._model_hypotheses(enrichment)
                )
            except Exception:
                pass

        return IntelligenceReport(
            hypotheses=tuple(hypotheses),
            facts=facts,
            generated_at=generated_at,
        )

    # ------------------------------------------------------------------
    # Built-in correlations (deterministic)
    # ------------------------------------------------------------------

    def _correlate_posture_and_trust(
        self,
        facts: tuple[EvidenceFact, ...],
    ) -> list[SecurityHypothesis]:
        """Posture + trust findings for the same agent compound."""

        by_subject: dict[str, list[EvidenceFact]] = {}
        for fact in facts:
            if fact.kind in ("posture", "trust_danger"):
                by_subject.setdefault(fact.subject, []).append(fact)

        out: list[SecurityHypothesis] = []
        for subject, subject_facts in by_subject.items():
            if len(subject_facts) < 2:
                continue
            has_compromised = any(
                "compromised" in f.detail for f in subject_facts
            )
            severity = "critical" if has_compromised else "high"
            out.append(
                self._hypothesis(
                    title=f"compound risk for {subject}",
                    description=(
                        f"{subject} has multiple independent risk "
                        "indicators: "
                        + "; ".join(f.detail for f in subject_facts)
                    ),
                    severity=severity,
                    confidence=0.8 if has_compromised else 0.6,
                    facts=subject_facts,
                    actions=[
                        {
                            "action": "quarantine" if has_compromised else "restrict",
                            "agent": subject,
                            "via": "immune policy rule (requires approval)",
                        }
                    ],
                    rationale=(
                        "independent posture and trust signals agree; "
                        "compound findings are stronger than either alone"
                    ),
                )
            )
        return out

    def _correlate_attack_paths(
        self,
        facts: tuple[EvidenceFact, ...],
    ) -> list[SecurityHypothesis]:
        """Sensitive reach + chokepoints produce containment
        recommendations."""

        sensitive_reach: list[EvidenceFact] = [
            f
            for f in facts
            if f.kind == "attack_path" and f.severity == "high"
        ]
        out: list[SecurityHypothesis] = []
        for fact in sensitive_reach[:5]:
            out.append(
                self._hypothesis(
                    title=f"attack reach: {fact.subject}",
                    description=fact.detail,
                    severity="high",
                    confidence=0.55,
                    facts=(fact,),
                    actions=[
                        {
                            "action": "revoke",
                            "target": fact.subject,
                            "via": "v2.0 revocation registry",
                        }
                    ],
                    rationale=(
                        "an attack path to a sensitive target exists in "
                        "recorded reach; containment cuts the path"
                    ),
                )
            )
        return out

    def _correlate_evidence(
        self,
        facts: tuple[EvidenceFact, ...],
    ) -> list[SecurityHypothesis]:
        """Observed facts (from the evidence graph) that warrant a
        hypothesis even alone."""

        out: list[SecurityHypothesis] = []
        for fact in facts:
            if fact.kind not in (
                "immune_detection",
                "immune_action",
                "identity_revocation",
                "containment",
            ):
                continue
            if fact.basis != "observed":
                continue
            out.append(
                self._hypothesis(
                    title=f"recorded security event: {fact.kind}",
                    description=fact.detail or fact.kind,
                    severity="medium",
                    confidence=0.9,
                    facts=(fact,),
                    actions=[],
                    rationale=(
                        "the evidence graph recorded this event; it is "
                        "observed fact, not inference"
                    ),
                )
            )
        return out

    def _model_hypotheses(
        self,
        enrichment: Any,
    ) -> list[SecurityHypothesis]:
        """Turn advisory model output into clearly-labeled hypotheses.

        The model's output can never authorize anything; every
        hypothesis it produces is flagged ``model_generated`` and
        carries the same recommended-action shape as built-ins so the
        immune policy can still decide what (if anything) to do.
        """

        out: list[SecurityHypothesis] = []
        if not isinstance(enrichment, dict):
            return out
        entries = enrichment.get("hypotheses", [])
        if not isinstance(entries, list):
            return out
        for entry in entries[:10]:
            if not isinstance(entry, dict):
                continue
            self._counter += 1
            out.append(
                SecurityHypothesis(
                    hypothesis_id=f"model-{self._counter}",
                    title=str(entry.get("title", "model hypothesis")),
                    description=str(entry.get("description", "")),
                    severity=(
                        entry.get("severity")
                        if entry.get("severity") in _SEVERITY_RANK
                        else "medium"
                    ),
                    confidence=float(entry.get("confidence", 0.0) or 0.0),
                    recommended_actions=tuple(
                        dict(a) for a in entry.get("recommended_actions", [])
                    ),
                    rationale=str(entry.get("rationale", "")),
                    basis="inferred",
                    model_generated=True,
                )
            )
        return out

    def _hypothesis(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        confidence: float,
        facts: Iterable[EvidenceFact],
        actions: Iterable[dict[str, Any]],
        rationale: str,
    ) -> SecurityHypothesis:
        self._counter += 1
        return SecurityHypothesis(
            hypothesis_id=f"hyp-{self._counter}",
            title=title,
            description=description,
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            supporting_facts=tuple(facts),
            recommended_actions=tuple(actions),
            rationale=rationale,
            basis="inferred",
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        report = self.analyze()
        return report.to_dict()


def _posture_severity(posture: str) -> str:
    return {
        "suspicious": "medium",
        "high_risk": "high",
        "compromised": "critical",
        "contained": "critical",
    }.get(posture, "low")
