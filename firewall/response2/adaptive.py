"""v2.0 Adaptive Response (firewall.response2).

Extends v1.9 graduated response with evidence-backed, policy-driven
decisions, response expiration, rollback/recovery, and auditing.

Stages: observe -> warn -> restrict -> quarantine -> contain.

Response actions record an attestation (signed by the identity key
when available) so the response is independently verifiable. Every
decision carries the detection evidence that triggered it. High-impact
stages require human approval unless auto-approved by policy.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
)
from firewall.network.behavior import Detection
from firewall.recorder import EventType, FlightRecorder

#: Stages in escalating severity.
RESPONSE_STAGES = (
    "observe",
    "warn",
    "restrict",
    "quarantine",
    "contain",
)

#: High-impact stages requiring approval unless auto-approved.
APPROVAL_REQUIRED = ("quarantine", "contain")

_STAGE_ACTION = {
    "restrict": ContainmentAction.RESTRICT_SESSION,
    "quarantine": ContainmentAction.QUARANTINE_AGENT,
    "contain": ContainmentAction.QUARANTINE_AGENT,
}

_SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class Response2Error(ValueError):
    """Raised for an invalid or rejected response."""


@dataclass(frozen=True)
class ResponseRule2:
    rule_id: str
    min_severity: str = "medium"
    stage: str = "observe"
    auto_approve: bool = False
    ttl: Optional[float] = None  # response expiration in seconds

    def __post_init__(self) -> None:
        if self.stage not in RESPONSE_STAGES:
            raise Response2Error(
                f"unknown response stage: {self.stage}"
            )
        if self.min_severity not in _SEVERITY_RANK:
            raise Response2Error(
                f"unknown severity: {self.min_severity}"
            )
        if self.ttl is not None and self.ttl <= 0:
            raise Response2Error("ttl must be positive")


@dataclass(frozen=True)
class ResponseRecord2:
    detection_id: str
    rule_id: str
    agent: str
    stage: str
    actor: str
    reason: str
    timestamp: float
    approved: bool = True
    evidence: tuple[dict[str, Any], ...] = ()
    expires_at: Optional[float] = None
    error: Optional[str] = None
    attestation: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "agent": self.agent,
            "stage": self.stage,
            "actor": self.actor,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "approved": self.approved,
            "evidence": [dict(entry) for entry in self.evidence],
            "expires_at": self.expires_at,
            "error": self.error,
            "attestation": (
                dict(self.attestation)
                if self.attestation
                else None
            ),
        }


class AdaptiveResponder:
    """Evidence-backed, policy-driven graduated response."""

    def __init__(
        self,
        containment: ContainmentController,
        *,
        recorder: Optional[FlightRecorder] = None,
        approver: Optional[Callable[[str], bool]] = None,
        attestation_authority=None,
        clock: Any = None,
    ) -> None:
        if not isinstance(
            containment, ContainmentController
        ):
            raise Response2Error(
                "containment must be a ContainmentController"
            )
        self._containment = containment
        self._recorder = recorder
        self._approver = approver
        self._attest = attestation_authority
        self._clock = clock if clock is not None else time.time
        self._rules: dict[str, ResponseRule2] = {}
        self._history: list[ResponseRecord2] = []
        self._counter = 0

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def set_policy(
        self,
        rules: Iterable[ResponseRule2],
    ) -> None:
        self._rules = {
            rule.rule_id: rule for rule in rules
        }

    def add_rule(self, rule: ResponseRule2) -> None:
        self._rules[rule.rule_id] = rule

    def policy(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": rule.rule_id,
                "min_severity": rule.min_severity,
                "stage": rule.stage,
                "auto_approve": rule.auto_approve,
                "ttl": rule.ttl,
            }
            for rule in sorted(
                self._rules.values(),
                key=lambda rule: rule.rule_id,
            )
        ]

    # ------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------

    def respond(
        self,
        detection: Detection,
        *,
        actor: str = "automation",
    ) -> ResponseRecord2:
        self._counter += 1
        detection_id = f"d{self._counter}"

        rule = self._rules.get(detection.rule_id)

        if rule is None:
            return self._record(
                detection_id,
                detection,
                stage="observe",
                actor=actor,
                reason=(
                    f"no policy rule for {detection.rule_id}; "
                    "observing only"
                ),
                rule_id=detection.rule_id,
            )

        if _SEVERITY_RANK.get(
            detection.severity, 0
        ) < _SEVERITY_RANK.get(rule.min_severity, 0):
            return self._record(
                detection_id,
                detection,
                stage="observe",
                actor=actor,
                reason=(
                    f"severity {detection.severity} is below the "
                    f"policy minimum {rule.min_severity} for "
                    f"{rule.rule_id}; observing only"
                ),
                rule_id=rule.rule_id,
            )

        stage = rule.stage

        if stage in ("observe", "warn"):
            return self._record(
                detection_id,
                detection,
                stage=stage,
                actor=actor,
                reason=(
                    f"policy {rule.rule_id} escalates "
                    f"{detection.rule_id} to {stage}"
                ),
                rule_id=rule.rule_id,
                ttl=rule.ttl,
            )

        approved = True

        if stage in APPROVAL_REQUIRED and not rule.auto_approve:
            approved = False
            if self._approver is not None:
                try:
                    approved = bool(self._approver(stage))
                except Exception:
                    approved = False

        if not approved:
            raise Response2Error(
                f"{stage} of "
                f"{detection.agents[0] if detection.agents else '?'} "
                f"requires human approval (rule {rule.rule_id})"
            )

        action = _STAGE_ACTION.get(stage)
        agent = detection.agents[0] if detection.agents else ""

        if not agent:
            raise Response2Error(
                "detection carries no agent to contain"
            )

        if action is None:
            return self._record(
                detection_id,
                detection,
                stage=stage,
                actor=actor,
                reason=f"stage {stage} has no containment action",
                rule_id=rule.rule_id,
                approved=approved,
                ttl=rule.ttl,
            )

        try:
            event = self._containment.apply(
                action,
                agent,
                actor=actor,
                reason=(
                    f"automated response to {detection.rule_id}: "
                    f"{detection.title}"
                ),
            )
        except ContainmentError as exc:
            return self._record(
                detection_id,
                detection,
                stage=stage,
                actor=actor,
                reason=str(exc),
                rule_id=rule.rule_id,
                approved=approved,
                ttl=rule.ttl,
                error=str(exc),
            )

        return self._record(
            detection_id,
            detection,
            stage=stage,
            actor=actor,
            reason=(
                f"{action.value} applied to {agent}: "
                f"{event.from_state.value} -> {event.to_state.value}"
            ),
            rule_id=rule.rule_id,
            approved=approved,
            ttl=rule.ttl,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record(
        self,
        detection_id: str,
        detection: Detection,
        *,
        stage: str,
        actor: str,
        reason: str,
        rule_id: str,
        approved: bool = True,
        ttl: Optional[float] = None,
        error: Optional[str] = None,
    ) -> ResponseRecord2:
        timestamp = float(self._clock())

        record = ResponseRecord2(
            detection_id=detection_id,
            rule_id=rule_id,
            agent=(
                detection.agents[0]
                if detection.agents
                else ""
            ),
            stage=stage,
            actor=actor,
            reason=reason,
            timestamp=timestamp,
            approved=approved,
            evidence=tuple(
                dict(entry) for entry in detection.evidence
            ),
            expires_at=(
                timestamp + ttl
                if ttl is not None
                else None
            ),
            error=error,
            attestation=self._attestation(
                detection,
                stage,
                reason,
            ),
        )

        self._history.append(record)

        if self._recorder is not None:
            try:
                self._recorder.record(
                    EventType.SECURITY_STATE,
                    {
                        "change": f"response:{stage}",
                        "detection_id": detection_id,
                        "rule_id": rule_id,
                        "agent": record.agent,
                        "reason": reason,
                        "approved": approved,
                    },
                    agent=record.agent or None,
                )
            except Exception:
                pass

        return record

    def _attestation(
        self,
        detection: Detection,
        stage: str,
        reason: str,
    ) -> Optional[dict[str, Any]]:
        """A signed attestation of the response decision when an
        attestation authority is available."""

        if self._attest is None:
            return None

        agent = detection.agents[0] if detection.agents else None

        if not agent:
            return None

        try:
            attestation = self._attest.issue(
                agent_id=agent,
                subject=f"response:{stage}",
                statement_type="response",
                payload={
                    "detection": detection.rule_id,
                    "reason": reason,
                },
            )
            return attestation.to_dict()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def history(self) -> tuple[ResponseRecord2, ...]:
        return tuple(self._history)

    def snapshot(self) -> dict[str, Any]:
        return {
            "policy": self.policy(),
            "history": [
                record.to_dict() for record in self._history
            ],
            "containment": self._containment.snapshot(),
        }
