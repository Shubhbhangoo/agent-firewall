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

#: Window inside which activity from distinct agents is reported as
#: temporally proximate. Proximity is not a relationship; see
#: ``_temporal_coordination``.
_COORDINATION_WINDOW_SECONDS = 60.0

#: Recorded event types whose mere occurrence is consequential. A
#: containment, a revocation or an immune action is not routine traffic,
#: so an observed fact of one of these kinds enters correlation at
#: ``high`` rather than at the generic ``medium``.
_CONSEQUENTIAL_EVENT_TYPES = frozenset(
    {
        "containment",
        "identity_revocation",
        "immune_action",
        "capability_revocation",
    }
)

#: Payload keys lifted into fact metadata so the coordination
#: correlators can group on them structurally rather than by parsing a
#: stringified payload.
_CORRELATION_KEYS = (
    "resource",
    "target",
    "path",
    "key_fingerprint",
    "fingerprint",
)


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


class FactCollection(tuple):
    """The facts one collection run gathered, plus what it could not see.

    A ``tuple`` subclass so existing callers keep iterating it, comparing
    it to ``()`` and indexing it exactly as before. ``gaps`` is the part
    that must not be silently dropped: a *configured* source that raised
    produced no facts, which is indistinguishable from a source that had
    nothing to report unless the failure is named.
    """

    def __new__(
        cls,
        facts: Iterable[EvidenceFact] = (),
        gaps: Iterable[str] = (),
    ) -> "FactCollection":
        self = super().__new__(cls, tuple(facts))
        self.gaps = tuple(gaps)
        return self

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"FactCollection({tuple(self)!r}, gaps={self.gaps!r})"
        )


@dataclass(frozen=True)
class IntelligenceReport:
    """The engine's output for one analysis run."""

    hypotheses: tuple[SecurityHypothesis, ...] = ()
    facts: tuple[EvidenceFact, ...] = ()
    generated_at: float = 0.0
    gaps: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """True only when every configured source answered.

        An empty report from a blinded engine looks exactly like an
        empty report from a quiet estate. This is what distinguishes
        them; a caller treating ``not report.hypotheses`` as an
        all-clear must check this first.
        """

        return not self.gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "facts": [f.to_dict() for f in self.facts],
            "generated_at": self.generated_at,
            "gaps": list(self.gaps),
            "complete": self.complete,
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

    def collect_facts(self) -> FactCollection:
        """Gather every fact the attached sources can provide.

        Returns a :class:`FactCollection` -- a tuple of facts carrying a
        ``gaps`` tuple naming every configured source that raised. A
        source that is not wired at all produces no gap: unwired is
        *unknown*, and the caller chose it. A wired source that fails is
        a probe failure, and reporting nothing from it as if it were
        silence is the fail-open this records.
        """

        facts: list[EvidenceFact] = []
        gaps: list[str] = []

        if self._posture is not None:
            try:
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
            except Exception as exc:
                gaps.append(f"posture source failed: {exc}")

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
            except Exception as exc:
                gaps.append(f"trust danger search failed: {exc}")

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
                            metadata={"agents": list(finding.agents)},
                        )
                    )
            except Exception as exc:
                gaps.append(f"attack path search failed: {exc}")
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
            except Exception as exc:
                gaps.append(f"chokepoint search failed: {exc}")

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
                                severity=(
                                    "high"
                                    if event.event_type
                                    in _CONSEQUENTIAL_EVENT_TYPES
                                    else "medium"
                                ),
                                metadata=_event_metadata(event),
                            )
                        )
            except Exception as exc:
                gaps.append(f"evidence graph read failed: {exc}")

        return FactCollection(facts, gaps)

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
        collected = self.collect_facts()
        gaps = list(collected.gaps)
        facts: tuple[EvidenceFact, ...] = tuple(collected)

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
        hypotheses.extend(self._correlate_coordination(facts))

        if self._model is not None:
            try:
                enrichment = self._model(facts, hypotheses)
                hypotheses.extend(
                    self._model_hypotheses(enrichment)
                )
            except Exception as exc:
                gaps.append(f"model enrichment failed: {exc}")

        return IntelligenceReport(
            hypotheses=tuple(hypotheses),
            facts=facts,
            generated_at=generated_at,
            gaps=tuple(gaps),
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

    # ------------------------------------------------------------------
    # Cross-agent coordination (deterministic, inferred)
    # ------------------------------------------------------------------

    def _correlate_coordination(
        self,
        facts: tuple[EvidenceFact, ...],
    ) -> list[SecurityHypothesis]:
        """Cross-agent coordination patterns.

        Four patterns, each requiring at least two *distinct* agents and
        a concrete shared value or a shared escalation path. A pattern
        that cannot name what the agents share is not emitted: "these
        two agents both did something" is not coordination, and a
        detector that fires on every pair reports nothing.

        One hypothesis per shared value, not one per pair -- a resource
        touched by five agents is one finding naming five agents, not
        ten pair findings.
        """

        out: list[SecurityHypothesis] = []

        out.extend(
            self._shared_value_coordination(
                facts,
                keys=("key_fingerprint", "fingerprint"),
                label="credential material",
                severity="high",
                confidence=0.7,
                rationale=(
                    "two or more agents are associated with the same key "
                    "material; either a key is shared beyond its intended "
                    "holder or one agent is presenting another's "
                    "credential. This is a correlation over recorded "
                    "metadata, not proof of either"
                ),
            )
        )
        out.extend(
            self._shared_value_coordination(
                facts,
                keys=("resource", "target", "path"),
                label="resource",
                severity="medium",
                confidence=0.5,
                rationale=(
                    "two or more agents touched the same resource. Shared "
                    "access may be entirely legitimate; it is reported so "
                    "a reviewer can decide, and it is never a denial"
                ),
            )
        )
        out.extend(self._temporal_coordination(facts))
        out.extend(self._shared_path_coordination(facts))

        return out

    def _shared_value_coordination(
        self,
        facts: tuple[EvidenceFact, ...],
        *,
        keys: tuple[str, ...],
        label: str,
        severity: str,
        confidence: float,
        rationale: str,
    ) -> list[SecurityHypothesis]:
        """Group facts by a shared metadata value under any of ``keys``."""

        groups: dict[str, list[EvidenceFact]] = {}

        for fact in facts:
            for key in keys:
                raw = fact.metadata.get(key)
                if not isinstance(raw, str) or not raw.strip():
                    continue
                groups.setdefault(f"{key}={raw.strip()}", []).append(fact)

        out: list[SecurityHypothesis] = []
        for value, group in sorted(groups.items()):
            agents = _distinct_subjects(group)
            if len(agents) < 2:
                continue
            out.append(
                self._hypothesis(
                    title=f"shared {label} across {len(agents)} agents",
                    description=(
                        f"{', '.join(agents)} are all associated with "
                        f"{value}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    facts=tuple(group),
                    actions=[
                        {"action": "investigate", "agent": agent}
                        for agent in agents
                    ],
                    rationale=rationale,
                )
            )
        return out

    def _temporal_coordination(
        self,
        facts: tuple[EvidenceFact, ...],
    ) -> list[SecurityHypothesis]:
        """Distinct agents acting inside one time window.

        Proximity only. It is *not* evidence of a trust relationship
        between the agents, and this deliberately makes no trust claim:
        a proximity detector that asserted a trust path it never checked
        would be stating a fact it does not have.

        Reported only when the window also holds a ``high`` or
        ``critical`` fact. Two agents doing routine work in the same
        minute is not a finding -- proximity is corroborating context
        for something already concerning, and a detector that fires on
        every quiet minute reports nothing.

        The evidence signer is deliberately not a grouping key. Every
        event in one graph carries the same recorder signer, so grouping
        on it would tie every agent in the estate together on every run.
        """

        timed: list[tuple[float, EvidenceFact]] = []
        for fact in facts:
            stamp = fact.metadata.get("timestamp")
            if isinstance(stamp, bool) or not isinstance(
                stamp, (int, float)
            ):
                continue
            timed.append((float(stamp), fact))

        if len(timed) < 2:
            return []

        timed.sort(key=lambda pair: pair[0])

        out: list[SecurityHypothesis] = []
        window_start = 0
        emitted: set[tuple[str, ...]] = set()

        for index in range(len(timed)):
            while (
                timed[index][0] - timed[window_start][0]
                > _COORDINATION_WINDOW_SECONDS
            ):
                window_start += 1

            window = [pair[1] for pair in timed[window_start : index + 1]]
            agents = _distinct_subjects(window)
            if len(agents) < 2:
                continue
            if not any(
                _SEVERITY_RANK.get(f.severity, 0)
                >= _SEVERITY_RANK["high"]
                for f in window
            ):
                continue
            key = tuple(agents)
            if key in emitted:
                continue
            emitted.add(key)

            span = timed[index][0] - timed[window_start][0]
            out.append(
                self._hypothesis(
                    title=(
                        f"temporal proximity across {len(agents)} agents"
                    ),
                    description=(
                        f"{', '.join(agents)} each produced activity "
                        f"within {span:.1f}s"
                    ),
                    severity="low",
                    confidence=0.35,
                    facts=tuple(window),
                    actions=[],
                    rationale=(
                        "activity from these agents falls inside a "
                        f"{_COORDINATION_WINDOW_SECONDS:.0f}s window. "
                        "Proximity is the whole of the claim: no trust "
                        "relationship between them was checked, so none "
                        "is asserted"
                    ),
                )
            )
        return out

    def _shared_path_coordination(
        self,
        facts: tuple[EvidenceFact, ...],
    ) -> list[SecurityHypothesis]:
        """One escalation path naming more than one agent."""

        out: list[SecurityHypothesis] = []
        for fact in facts:
            if fact.kind != "attack_path":
                continue
            agents = fact.metadata.get("agents")
            if not isinstance(agents, (list, tuple)):
                continue
            named = sorted(
                {
                    str(a).strip()
                    for a in agents
                    if isinstance(a, str) and a.strip()
                }
            )
            if len(named) < 2:
                continue
            out.append(
                self._hypothesis(
                    title=(
                        f"escalation path spans {len(named)} agents"
                    ),
                    description=(
                        f"a single path traverses {', '.join(named)}: "
                        f"{fact.detail}"
                    ),
                    severity="high",
                    confidence=0.6,
                    facts=(fact,),
                    actions=[
                        {"action": "investigate", "agent": agent}
                        for agent in named
                    ],
                    rationale=(
                        "the path is graph reachability over recorded "
                        "authority, so compromising one agent on it "
                        "reaches the others. Reachability is not "
                        "exploitability and this path may never be taken"
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


def _event_metadata(event: Any) -> dict[str, Any]:
    """Lift the correlatable fields of an evidence event into metadata.

    ``detail`` keeps the stringified payload for a human reader; these
    are the fields the coordination correlators group on, so they must
    be structured rather than parsed back out of that string.
    """

    metadata: dict[str, Any] = {"event_id": event.event_id}

    timestamp = getattr(event, "timestamp", None)
    if isinstance(timestamp, (int, float)) and not isinstance(
        timestamp, bool
    ):
        metadata["timestamp"] = float(timestamp)

    signer = getattr(event, "signer", "")
    if isinstance(signer, str) and signer.strip():
        metadata["signer"] = signer.strip()

    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        for key in _CORRELATION_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                metadata[key] = value.strip()

    return metadata


def _distinct_subjects(facts: Iterable[EvidenceFact]) -> list[str]:
    """Distinct, sorted agent subjects across ``facts``.

    A multi-agent fact carries its agents in ``metadata["agents"]``; the
    subject string is a display join and is not split back apart here,
    because an agent id may legitimately contain a comma.
    """

    subjects: set[str] = set()
    for fact in facts:
        agents = fact.metadata.get("agents")
        if isinstance(agents, (list, tuple)) and agents:
            for agent in agents:
                if isinstance(agent, str) and agent.strip():
                    subjects.add(agent.strip())
            continue
        if isinstance(fact.subject, str) and fact.subject.strip():
            subjects.add(fact.subject.strip())
    return sorted(subjects)
