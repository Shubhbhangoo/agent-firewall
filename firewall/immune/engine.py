"""v2.1 Agent Immune System (firewall.immune).

An autonomous defensive feedback loop:

    OBSERVE -> DETECT -> REASON -> SIMULATE -> CONTAIN -> RECOVER -> VERIFY

The system continuously evaluates security state and recommends (or, when
policy explicitly authorizes it, executes) defensive actions.

The single most important property: **the reasoning system never becomes
the authorization authority.**

* The ``reasoner`` (which may be an LLM or any model) returns an
  *advisory* analysis: a hypothesis and recommended actions.
* Nothing the reasoner says can execute anything by itself.
* Execution requires a **deterministic policy rule** that matches the
  recommended action, the evidence, and the agent state. The policy is a
  plain declarative structure (`ImmunePolicy`); its matching is pure
  Python with no model involvement.
* Every executed action is audited in an optional evidence graph as an
  ``observed`` event, and every advisory analysis is recorded as an
  ``inference`` event - never promoted unless an operator explicitly
  confirms it via ``promote_finding``.
* Authorization for defensive actions still flows through the v2.0
  containment controller / SDK revocation and risk mechanisms. The
  immune system never opens a path around them.

The loop stages are explicit methods so the loop is testable and each
stage is explainable:
  ``observe()``   ingest signals (authorization denials, posture changes,
                  trust changes, ...).
  ``detect()``    deterministic detection rules over the observed signals.
  ``reason()``    advisory model analysis of the detections (optional).
  ``simulate()``  counterfactual check through the digital twin (optional).
  ``contain()``   execute policy-authorized containment actions.
  ``recover()``   execute policy-authorized recovery (after verification).
  ``verify()``    verify the outcome (the agent's state actually changed;
                  evidence was recorded).
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
    ContainmentState,
)
from firewall.defense import DefenseMesh
from firewall.posture import PostureEngine, PostureSignal
from firewall.twin import SecurityTwin

#: Containment stages, in escalating severity.
CONTAINMENT_STAGES = (
    "observe",
    "warn",
    "restrict",
    "quarantine",
    "contain",
)

#: Rank used to compare detection severity with policy minimums.
_SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

#: Immune stages -> v2.0 containment actions.
_STAGE_ACTION = {
    "restrict": ContainmentAction.RESTRICT_SESSION,
    "quarantine": ContainmentAction.QUARANTINE_AGENT,
    "contain": ContainmentAction.QUARANTINE_AGENT,
}

#: Immune stages -> resulting containment states.
_STAGE_STATE = {
    "restrict": ContainmentState.RESTRICTED,
    "quarantine": ContainmentState.QUARANTINED,
    "contain": ContainmentState.QUARANTINED,
}


class ImmuneError(ValueError):
    """Raised for an invalid immune-system operation."""


@dataclass(frozen=True)
class ImmuneSignal:
    """One observation fed into the loop."""

    agent: str
    kind: str
    description: str
    severity: str = "low"
    evidence: tuple[dict[str, Any], ...] = ()
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "kind": self.kind,
            "description": self.description,
            "severity": self.severity,
            "evidence": [dict(e) for e in self.evidence],
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class ImmuneDetection:
    """One deterministic detection produced from signals."""

    detection_id: str
    rule_id: str
    agent: str
    severity: str
    title: str
    detail: str
    signals: tuple[dict[str, Any], ...] = ()
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "agent": self.agent,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "signals": [dict(s) for s in self.signals],
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class ImmuneAdvice:
    """Advisory model output. Carries no authority."""

    detection_id: str
    hypothesis: str
    recommended_actions: tuple[dict[str, Any], ...] = ()
    confidence: float = 0.0
    model: str = ""
    basis: str = "inference"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "hypothesis": self.hypothesis,
            "recommended_actions": [
                dict(a) for a in self.recommended_actions
            ],
            "confidence": self.confidence,
            "model": self.model,
            "basis": self.basis,
        }


@dataclass(frozen=True)
class ImmuneAction:
    """One executed (or attempted) defensive action."""

    action_id: str
    stage: str
    agent: str
    action: str
    rule_id: str
    reason: str
    outcome: str  # executed / skipped / failed / denied
    timestamp: float = 0.0
    detail: str = ""
    basis: str = "observed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "stage": self.stage,
            "agent": self.agent,
            "action": self.action,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
            "detail": self.detail,
            "basis": self.basis,
        }


@dataclass(frozen=True)
class ImmuneRule:
    """A deterministic policy rule that authorizes a defensive action.

    ``match`` is a pure callable
    ``(detection, advice, state) -> (matched: bool, reason: str)``.
    When no ``match`` is supplied, the rule matches when the detection
    severity is at least ``min_severity`` and (if ``stage`` is a
    containment stage) the stage is at or above the policy stage.

    ``auto_approve`` gates high-impact stages (quarantine/contain):
    without it those actions are refused unless an ``approver``
    callable returns True. The rule is the *only* way a recommended
    action becomes an executed action - model output alone can never do
    it.
    """

    rule_id: str
    stage: str = "observe"
    min_severity: str = "medium"
    auto_approve: bool = False
    match: Optional[Callable[..., tuple[bool, str]]] = None
    description: str = ""

    def __post_init__(self) -> None:
        if self.stage not in CONTAINMENT_STAGES:
            raise ImmuneError(f"unknown stage: {self.stage}")
        if self.min_severity not in _SEVERITY_RANK:
            raise ImmuneError(f"unknown severity: {self.min_severity}")
        if self.match is not None and not callable(self.match):
            raise ImmuneError("match must be callable")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "stage": self.stage,
            "min_severity": self.min_severity,
            "auto_approve": self.auto_approve,
            "description": self.description,
        }


@dataclass(frozen=True)
class ImmunePolicy:
    """A set of deterministic rules. The immune system's only
    authorization surface."""

    rules: tuple[ImmuneRule, ...] = ()

    def rule(self, rule_id: str) -> Optional[ImmuneRule]:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": [rule.to_dict() for rule in self.rules]
        }


#: Detection rules built in by default (deterministic).
_DETECTION_RULES = {
    "repeated_denials": {
        "min_severity": "medium",
        "threshold": 3,
    },
    "compromised_posture": {
        "min_severity": "high",
        "postures": ("compromised", "contained"),
    },
    "untrusted_identity": {
        "min_severity": "critical",
        "postures": ("retired",),
    },
    "trust_collapse": {
        "min_severity": "high",
        "threshold": 0.3,
    },
    "no_live_capability": {
        "min_severity": "medium",
    },
}


class ImmuneSystem:
    """The OBSERVE -> DETECT -> REASON -> SIMULATE -> CONTAIN -> RECOVER
    -> VERIFY loop over a defense mesh, a posture engine, a twin, and a
    containment controller.

    ``reasoner`` is an optional callable
    ``(detection, state) -> ImmuneAdvice``; when absent, a deterministic
    default advice is produced so the loop still runs without any model.
    """

    def __init__(
        self,
        mesh: DefenseMesh,
        *,
        posture: Optional[PostureEngine] = None,
        containment: Optional[ContainmentController] = None,
        twin: Optional[SecurityTwin] = None,
        evidence_graph=None,
        reasoner: Optional[Callable[[Any, dict[str, Any]], ImmuneAdvice]] = None,
        approver: Optional[Callable[[str, str], bool]] = None,
        clock: Any = None,
    ) -> None:
        if not isinstance(mesh, DefenseMesh):
            raise ImmuneError("mesh must be a DefenseMesh")
        if posture is not None and not isinstance(posture, PostureEngine):
            raise ImmuneError("posture must be a PostureEngine")
        if containment is not None and not isinstance(
            containment, ContainmentController
        ):
            raise ImmuneError(
                "containment must be a ContainmentController"
            )
        if reasoner is not None and not callable(reasoner):
            raise ImmuneError("reasoner must be callable")

        self._mesh = mesh
        self._posture = posture
        self._containment = containment
        self._twin = twin
        self._evidence = evidence_graph
        self._reasoner = reasoner
        self._approver = approver
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()

        self._policy = ImmunePolicy()
        self._signals: list[ImmuneSignal] = []
        self._detections: list[ImmuneDetection] = []
        self._advice: list[ImmuneAdvice] = []
        self._actions: list[ImmuneAction] = []
        self._counter = 0

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def set_policy(
        self,
        policy: ImmunePolicy,
    ) -> None:
        if not isinstance(policy, ImmunePolicy):
            raise ImmuneError("policy must be an ImmunePolicy")
        with self._lock:
            self._policy = policy

    def policy(self) -> dict[str, Any]:
        return self._policy.to_dict()

    # ------------------------------------------------------------------
    # OBSERVE
    # ------------------------------------------------------------------

    def observe(
        self,
        signal: ImmuneSignal,
        *,
        now: Optional[float] = None,
    ) -> ImmuneSignal:
        """Record one observation and forward it to the posture engine."""

        if not isinstance(signal, ImmuneSignal):
            raise ImmuneError("signal must be an ImmuneSignal")

        timestamp = float(now) if now is not None else float(self._clock())
        signal = ImmuneSignal(
            agent=signal.agent,
            kind=signal.kind,
            description=signal.description,
            severity=signal.severity,
            evidence=signal.evidence,
            timestamp=timestamp,
        )

        with self._lock:
            self._signals.append(signal)

            if self._posture is not None:
                try:
                    self._posture.ingest(
                        signal.agent,
                        PostureSignal(
                            name=signal.kind,
                            severity=_severity_number(signal.severity),
                            description=signal.description,
                            evidence=[dict(e) for e in signal.evidence],
                            agent=signal.agent,
                        ),
                        now=timestamp,
                    )
                except Exception:
                    pass

            self._record_evidence(
                "observed",
                signal.agent,
                "immune_signal",
                {
                    "kind": signal.kind,
                    "severity": signal.severity,
                    "description": signal.description,
                },
            )

        return signal

    # ------------------------------------------------------------------
    # DETECT
    # ------------------------------------------------------------------

    def detect(
        self,
        *,
        agent: Optional[str] = None,
        now: Optional[float] = None,
    ) -> list[ImmuneDetection]:
        """Run the deterministic detection rules over observed signals."""

        timestamp = float(now) if now is not None else float(self._clock())
        found: list[ImmuneDetection] = []

        with self._lock:
            signals = [
                s for s in self._signals if agent is None or s.agent == agent
            ]
            by_agent: dict[str, list[ImmuneSignal]] = {}
            for signal in signals:
                by_agent.setdefault(signal.agent, []).append(signal)

            # The loop's primary observer is the mesh's continuous
            # evaluation: every known agent is evaluated even when it
            # emitted no signal this cycle.
            for known in self._mesh.known_agents():
                by_agent.setdefault(known, [])

            for agent_id, agent_signals in by_agent.items():
                self._counter += 1
                detection_id = f"det-{self._counter}"

                state = self._agent_state(agent_id)

                # Repeated denials.
                denials = [
                    s
                    for s in agent_signals
                    if s.kind == "authorization_denial"
                ]
                if len(denials) >= _DETECTION_RULES["repeated_denials"]["threshold"]:
                    found.append(
                        self._make_detection(
                            detection_id,
                            "repeated_denials",
                            agent_id,
                            "medium",
                            "repeated authorization denials",
                            f"{len(denials)} denials recorded for {agent_id}",
                            agent_signals,
                            timestamp,
                        )
                    )
                    self._counter += 1
                    detection_id = f"det-{self._counter}"

                # Compromised posture.
                posture = state.get("posture", "unknown")
                if posture in _DETECTION_RULES["compromised_posture"]["postures"]:
                    found.append(
                        self._make_detection(
                            detection_id,
                            "compromised_posture",
                            agent_id,
                            "high",
                            "compromised posture",
                            f"{agent_id} is in posture {posture}",
                            agent_signals,
                            timestamp,
                        )
                    )
                    self._counter += 1
                    detection_id = f"det-{self._counter}"

                # Trust collapse. ``state`` is a ``MeshState.to_dict()``,
                # where a missing score is not a low score -- the error
                # path in ``_agent_state`` writes an explicit 0.0 when the
                # mesh could not be reached. So an absent key means this
                # rule has nothing to evaluate, and the old
                # ``.get("trust_score", 1.0)`` answered it with the most
                # reassuring number available.
                trust = state.get("trust_score")
                if (
                    isinstance(trust, (int, float))
                    and not isinstance(trust, bool)
                    and trust
                    < _DETECTION_RULES["trust_collapse"]["threshold"]
                ):
                    found.append(
                        self._make_detection(
                            detection_id,
                            "trust_collapse",
                            agent_id,
                            "high",
                            "trust collapse",
                            f"{agent_id} trust score is {trust:.2f}",
                            agent_signals,
                            timestamp,
                        )
                    )
                    self._counter += 1
                    detection_id = f"det-{self._counter}"

                # No live capability.
                if not state.get("capability_ok", False):
                    found.append(
                        self._make_detection(
                            detection_id,
                            "no_live_capability",
                            agent_id,
                            "medium",
                            "no live capability",
                            f"{agent_id} has no live capability",
                            agent_signals,
                            timestamp,
                        )
                    )
                    self._counter += 1
                    detection_id = f"det-{self._counter}"

            for detection in found:
                self._detections.append(detection)
                self._record_evidence(
                    "inference",
                    detection.agent,
                    "immune_detection",
                    {
                        "rule": detection.rule_id,
                        "severity": detection.severity,
                        "detail": detection.detail,
                    },
                )

        return found

    def _make_detection(
        self,
        detection_id: str,
        rule_id: str,
        agent: str,
        severity: str,
        title: str,
        detail: str,
        signals: list[ImmuneSignal],
        timestamp: float,
    ) -> ImmuneDetection:
        return ImmuneDetection(
            detection_id=detection_id,
            rule_id=rule_id,
            agent=agent,
            severity=severity,
            title=title,
            detail=detail,
            signals=tuple(s.to_dict() for s in signals),
            timestamp=timestamp,
        )

    def _agent_state(self, agent: str) -> dict[str, Any]:
        try:
            evaluation = self._mesh.evaluate(agent)
            return evaluation.to_dict()
        except Exception as exc:
            return {
                "agent": agent,
                "state": "unknown",
                "trust_score": 0.0,
                "capability_ok": False,
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # REASON (advisory only - never authoritative)
    # ------------------------------------------------------------------

    def reason(
        self,
        detection: ImmuneDetection,
    ) -> ImmuneAdvice:
        """Produce an advisory analysis for one detection.

        When a model reasoner is attached, its output is *advice only*.
        Without one, a deterministic default advice is produced so the
        loop remains fully operational. Either way the advice cannot
        execute anything: the policy rules decide.
        """

        if self._reasoner is not None:
            try:
                advice = self._reasoner(detection, self._agent_state(detection.agent))
                if not isinstance(advice, ImmuneAdvice):
                    raise ImmuneError("reasoner must return ImmuneAdvice")
            except Exception as exc:
                advice = self._default_advice(detection, note=str(exc))
        else:
            advice = self._default_advice(detection)

        with self._lock:
            self._advice.append(advice)
            self._record_evidence(
                "inference",
                detection.agent,
                "immune_advice",
                {
                    "detection": detection.detection_id,
                    "hypothesis": advice.hypothesis,
                    "recommended": [
                        dict(a) for a in advice.recommended_actions
                    ],
                    "model": advice.model,
                },
            )

        return advice

    def _default_advice(
        self,
        detection: ImmuneDetection,
        *,
        note: str = "",
    ) -> ImmuneAdvice:
        recommended: list[dict[str, Any]] = []
        if detection.severity in ("high", "critical"):
            recommended.append(
                {"action": "restrict", "agent": detection.agent}
            )
        if detection.rule_id in ("compromised_posture", "trust_collapse"):
            recommended.append(
                {"action": "quarantine", "agent": detection.agent}
            )
        return ImmuneAdvice(
            detection_id=detection.detection_id,
            hypothesis=(
                f"{detection.agent} exhibits {detection.rule_id}; "
                f"recommend {' and '.join(a['action'] for a in recommended) or 'observation'}."
                + (f" (reasoner note: {note})" if note else "")
            ),
            recommended_actions=tuple(recommended),
            confidence=0.6,
            model="deterministic-default",
        )

    # ------------------------------------------------------------------
    # SIMULATE (counterfactual check through the twin)
    # ------------------------------------------------------------------

    def simulate(
        self,
        detection: ImmuneDetection,
        *,
        containment: str = "quarantine",
    ) -> dict[str, Any]:
        """Ask the digital twin what containing this agent would do.

        Purely analytical. The twin's answer is labeled ``simulated``
        and can never mutate production state.
        """

        if self._twin is None:
            return {
                "available": False,
                "reason": "no twin attached",
                "basis": "unknown",
            }
        try:
            report = self._twin.compromise(
                detection.agent,
                title=f"immune containment simulation for {detection.agent}",
            )
            delta = report.reachability_deltas
            return {
                "available": True,
                "containment_opportunities": [
                    dict(c) for c in report.containment_opportunities
                ],
                "blast_radius_after": dict(report.blast_radius_after),
                "path_count_after": len(report.after_paths),
                "basis": "simulated",
            }
        except Exception as exc:
            return {
                "available": False,
                "reason": str(exc),
                "basis": "unknown",
            }

    # ------------------------------------------------------------------
    # CONTAIN (execution - policy-authorized only)
    # ------------------------------------------------------------------

    def contain(
        self,
        detection: ImmuneDetection,
        advice: ImmuneAdvice,
        *,
        actor: str = "immune",
        now: Optional[float] = None,
    ) -> ImmuneAction:
        """Execute the policy-authorized action for this detection.

        The policy rule - not the advice - decides what (if anything)
        happens. An advice that names an action no rule authorizes is
        skipped with ``outcome=skipped`` and an explanation. High-impact
        stages require an approver unless ``auto_approve`` is set.
        """

        timestamp = float(now) if now is not None else float(self._clock())

        rule = self._policy.rule(detection.rule_id)
        if rule is None:
            return self._record_action(
                "observe",
                detection.agent,
                "observe",
                rule_id="(none)",
                reason=(
                    f"no policy rule for {detection.rule_id}; observing only"
                ),
                outcome="skipped",
                timestamp=timestamp,
                detail="a model recommendation is never self-authorizing",
            )

        matched, match_reason = self._match(rule, detection, advice)
        if not matched:
            return self._record_action(
                rule.stage,
                detection.agent,
                "observe",
                rule_id=rule.rule_id,
                reason=match_reason,
                outcome="skipped",
                timestamp=timestamp,
                detail="policy rule did not match",
            )

        if rule.stage in ("observe", "warn"):
            return self._record_action(
                rule.stage,
                detection.agent,
                rule.stage,
                rule_id=rule.rule_id,
                reason=match_reason,
                outcome="executed",
                timestamp=timestamp,
                detail="observation/warning stage; no enforcement",
            )

        approved = True
        if rule.stage in ("quarantine", "contain") and not rule.auto_approve:
            approved = False
            if self._approver is not None:
                try:
                    approved = bool(
                        self._approver(rule.stage, detection.agent)
                    )
                except Exception:
                    approved = False
            if not approved:
                return self._record_action(
                    rule.stage,
                    detection.agent,
                    rule.stage,
                    rule_id=rule.rule_id,
                    reason=match_reason,
                    outcome="denied",
                    timestamp=timestamp,
                    detail=(
                        f"{rule.stage} requires human approval "
                        "(policy rule does not auto-approve)"
                    ),
                )

        return self._execute(
            rule.stage,
            detection.agent,
            rule_id=rule.rule_id,
            reason=match_reason,
            actor=actor,
            timestamp=timestamp,
        )

    def _match(
        self,
        rule: ImmuneRule,
        detection: ImmuneDetection,
        advice: ImmuneAdvice,
    ) -> tuple[bool, str]:
        if rule.match is not None:
            try:
                return tuple(rule.match(detection, advice, self._agent_state(detection.agent)))
            except Exception as exc:
                return False, f"policy matcher error: {type(exc).__name__}"
        if _SEVERITY_RANK.get(
            detection.severity, 0
        ) < _SEVERITY_RANK.get(rule.min_severity, 0):
            return False, (
                f"detection severity {detection.severity} is below the "
                f"policy minimum {rule.min_severity}"
            )
        return True, f"policy rule {rule.rule_id} matched"

    def _execute(
        self,
        stage: str,
        agent: str,
        *,
        rule_id: str,
        reason: str,
        actor: str,
        timestamp: float,
    ) -> ImmuneAction:
        if self._containment is None:
            return self._record_action(
                stage,
                agent,
                stage,
                rule_id=rule_id,
                reason=reason,
                outcome="failed",
                timestamp=timestamp,
                detail="no containment controller attached; "
                       "the mesh state still reflects the evaluation",
            )

        # Immune stage names map onto the v2.0 containment actions:
        # restrict -> RESTRICT_SESSION, quarantine/contain ->
        # QUARANTINE_AGENT. ``observe``/``warn`` never reach here.
        try:
            action = _STAGE_ACTION.get(stage)
            if action is None:
                return self._record_action(
                    stage,
                    agent,
                    stage,
                    rule_id=rule_id,
                    reason=reason,
                    outcome="skipped",
                    timestamp=timestamp,
                    detail=f"stage {stage} has no containment action",
                )
            # Idempotent: if the agent is already in the target
            # containment state (e.g. the mesh auto-quarantined it in
            # the same cycle), report the action as already satisfied
            # rather than failing.
            try:
                current_state = self._containment.state(agent)
            except Exception:
                current_state = None
            target_state = _STAGE_STATE.get(stage)
            if (
                current_state is not None
                and target_state is not None
                and current_state == target_state
            ):
                return self._record_action(
                    stage,
                    agent,
                    stage,
                    rule_id=rule_id,
                    reason=reason,
                    outcome="executed",
                    timestamp=timestamp,
                    detail=(
                        f"agent already in {current_state.value}; "
                        "containment satisfied"
                    ),
                )
            event = self._containment.apply(
                action,
                agent,
                actor=actor,
                reason=f"immune system ({rule_id}): {reason}",
            )
            return self._record_action(
                stage,
                agent,
                stage,
                rule_id=rule_id,
                reason=reason,
                outcome="executed",
                timestamp=timestamp,
                detail=(
                    f"{event.from_state.value} -> {event.to_state.value}"
                ),
            )
        except ContainmentError as exc:
            return self._record_action(
                stage,
                agent,
                stage,
                rule_id=rule_id,
                reason=reason,
                outcome="failed",
                timestamp=timestamp,
                detail=str(exc),
            )

    # ------------------------------------------------------------------
    # RECOVER
    # ------------------------------------------------------------------

    def recover(
        self,
        agent: str,
        *,
        actor: str = "immune",
        reason: str = "",
        verify_first: bool = True,
        now: Optional[float] = None,
    ) -> ImmuneAction:
        """Recover an agent after verification.

        When ``verify_first`` is True (default), recovery is refused
        unless the verification stage reports the agent is safe to
        recover (identity active, posture not compromised, live
        capability present).
        """

        timestamp = float(now) if now is not None else float(self._clock())

        if verify_first:
            verification = self.verify(agent, now=timestamp)
            if not verification.get("recoverable", False):
                return self._record_action(
                    "recover",
                    agent,
                    "recover",
                    rule_id="recovery",
                    reason=reason or "recovery requested",
                    outcome="denied",
                    timestamp=timestamp,
                    detail=verification.get("reason", "verification failed"),
                )

        if self._containment is None:
            return self._record_action(
                "recover",
                agent,
                "recover",
                rule_id="recovery",
                reason=reason or "recovery requested",
                outcome="failed",
                timestamp=timestamp,
                detail="no containment controller attached",
            )

        try:
            event = self._containment.apply(
                ContainmentAction.RECOVER,
                agent,
                actor=actor,
                reason=reason or "immune recovery",
            )
            return self._record_action(
                "recover",
                agent,
                "recover",
                rule_id="recovery",
                reason=reason or "recovery requested",
                outcome="executed",
                timestamp=timestamp,
                detail=(
                    f"{event.from_state.value} -> {event.to_state.value}"
                ),
            )
        except ContainmentError as exc:
            return self._record_action(
                "recover",
                agent,
                "recover",
                rule_id="recovery",
                reason=reason or "recovery requested",
                outcome="failed",
                timestamp=timestamp,
                detail=str(exc),
            )

    # ------------------------------------------------------------------
    # VERIFY
    # ------------------------------------------------------------------

    def verify(
        self,
        agent: str,
        *,
        now: Optional[float] = None,
    ) -> dict[str, Any]:
        """Verify the outcome: re-evaluate the agent through the mesh,
        check posture, and confirm a live capability.

        Returns an explainable verdict. Recovery is only recommended when
        every check passes; anything unknown or failing denies.
        """

        timestamp = float(now) if now is not None else float(self._clock())

        try:
            evaluation = self._mesh.evaluate(agent)
        except Exception as exc:
            return {
                "agent": agent,
                "recoverable": False,
                "reason": f"mesh evaluation failed: {type(exc).__name__}",
            }

        posture = evaluation.posture
        posture_ok = posture not in (
            "compromised",
            "contained",
            "high_risk",
            "suspicious",
        )
        identity_ok = evaluation.identity_verified
        capability_ok = evaluation.capability_ok
        # Recovery only makes sense for an agent the mesh actually
        # restricted/quarantined. An active agent has nothing to recover.
        mesh_state_ok = evaluation.state in (
            "restricted",
            "quarantined",
            "recovering",
        )

        recoverable = (
            identity_ok
            and posture_ok
            and capability_ok
            and mesh_state_ok
        )

        reason_parts = []
        if not identity_ok:
            reason_parts.append("identity not verified")
        if not posture_ok:
            reason_parts.append(f"posture is {posture}")
        if not capability_ok:
            reason_parts.append("no live capability")
        if not mesh_state_ok:
            reason_parts.append(
                f"mesh state is {evaluation.state}; nothing to recover"
            )
        if recoverable:
            reason_parts.append("all checks passed")

        return {
            "agent": agent,
            "recoverable": recoverable,
            "reason": "; ".join(reason_parts),
            "mesh_state": evaluation.to_dict(),
            "checked_at": timestamp,
        }

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

    def run_cycle(
        self,
        *,
        agent: Optional[str] = None,
        actor: str = "immune",
    ) -> dict[str, Any]:
        """One full OBSERVE -> DETECT -> REASON -> SIMULATE -> CONTAIN
        -> VERIFY cycle over the current state.

        ``observe`` is expected to have been fed already (the mesh's
        continuous evaluation is the primary observer); this cycle runs
        detection and policy-authorized response. Returns a full,
        explainable transcript.
        """

        detections = self.detect(agent=agent)
        transcript: list[dict[str, Any]] = []

        for detection in detections:
            advice = self.reason(detection)
            simulation = self.simulate(detection)
            action = self.contain(
                detection,
                advice,
                actor=actor,
            )
            verification = self.verify(detection.agent)
            transcript.append(
                {
                    "detection": detection.to_dict(),
                    "advice": advice.to_dict(),
                    "simulation": simulation,
                    "action": action.to_dict(),
                    "verification": verification,
                }
            )

        return {"cycle": transcript}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record_action(
        self,
        stage: str,
        agent: str,
        action: str,
        *,
        rule_id: str,
        reason: str,
        outcome: str,
        timestamp: float,
        detail: str,
    ) -> ImmuneAction:
        self._counter += 1
        record = ImmuneAction(
            action_id=f"act-{self._counter}",
            stage=stage,
            agent=agent,
            action=action,
            rule_id=rule_id,
            reason=reason,
            outcome=outcome,
            timestamp=timestamp,
            detail=detail,
        )
        with self._lock:
            self._actions.append(record)
            self._record_evidence(
                "observed" if outcome == "executed" else "inference",
                agent,
                "immune_action",
                {
                    "action_id": record.action_id,
                    "stage": stage,
                    "action": action,
                    "rule_id": rule_id,
                    "outcome": outcome,
                    "detail": detail,
                },
            )
        return record

    def _record_evidence(
        self,
        kind: str,
        agent: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        if self._evidence is None:
            return
        try:
            self._evidence.append(
                kind,
                agent,
                event_type,
                payload,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def signals(self) -> tuple[ImmuneSignal, ...]:
        with self._lock:
            return tuple(self._signals)

    def detections(self) -> tuple[ImmuneDetection, ...]:
        with self._lock:
            return tuple(self._detections)

    def actions(self) -> tuple[ImmuneAction, ...]:
        with self._lock:
            return tuple(self._actions)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "policy": self._policy.to_dict(),
                "signals": [s.to_dict() for s in self._signals],
                "detections": [d.to_dict() for d in self._detections],
                "advice": [a.to_dict() for a in self._advice],
                "actions": [a.to_dict() for a in self._actions],
            }


def _severity_number(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0) + 1
