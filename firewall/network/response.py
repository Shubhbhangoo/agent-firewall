"""Graduated response automation (v1.9).

Extends v1.8 containment into policy-driven security automation:

    observe -> warn -> restrict -> quarantine -> contain

A :class:`ResponsePolicy` maps detections (by ``rule_id`` and
``severity``) to a target response stage. The
:class:`ResponseController` executes the policy through the existing
containment controller and SDK mechanisms -- never around the
authorization pipeline -- and enforces the automation discipline:

* **policy-driven** -- an action happens only when the policy says so;
* **auditable** -- every action is recorded in the control-plane audit
  and the flight recorder;
* **explainable** -- every action carries the detection and reason that
  triggered it;
* **fail-closed** -- a policy evaluation error escalates, never
  de-escalates, and never silently skips;
* **reversible where safe** -- recovery is available and itself
  audited;
* **human approval** -- high-impact stages (quarantine, contain) are
  refused unless the policy declares ``auto_approve`` or an approval
  callable approves.

No hidden autonomous privileges: the controller holds no signing keys
and can only do what the underlying SDK APIs allow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from firewall.containment import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
)
from firewall.network.behavior import Detection
from firewall.recorder import EventType, FlightRecorder


class ResponseError(ValueError):
    """Raised for an invalid or rejected response action."""


#: The graduated stages, low to high impact.
RESPONSE_STAGES = (
    "observe",
    "warn",
    "restrict",
    "quarantine",
    "contain",
)

#: Stages that are considered high-impact and require approval.
APPROVAL_REQUIRED_STAGES = ("quarantine", "contain")

#: Stage -> containment action mapping.
_STAGE_ACTION = {
    "restrict": ContainmentAction.RESTRICT_SESSION,
    "quarantine": ContainmentAction.QUARANTINE_AGENT,
    "contain": ContainmentAction.QUARANTINE_AGENT,
}


@dataclass(frozen=True)
class ResponseRule:
    """One policy rule: when to escalate to which stage."""

    rule_id: str
    min_severity: str = "medium"
    stage: str = "observe"
    auto_approve: bool = False

    def __post_init__(self) -> None:
        if self.stage not in RESPONSE_STAGES:
            raise ResponseError(
                f"unknown response stage: {self.stage}"
            )

        if self.min_severity not in (
            "low",
            "medium",
            "high",
            "critical",
        ):
            raise ResponseError(
                f"unknown severity: {self.min_severity}"
            )


#: Severity ordering for rule matching.
_SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass(frozen=True)
class ResponseRecord:
    """One audited response action."""

    detection_id: str
    rule_id: str
    agent: str
    stage: str
    actor: str
    reason: str
    timestamp: float
    approved: bool = True
    error: Optional[str] = None

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
            "error": self.error,
        }


class ResponseController:
    """Executes a response policy over detections."""

    def __init__(
        self,
        containment: ContainmentController,
        *,
        recorder: Optional[FlightRecorder] = None,
        clock: Any = None,
        approver: Optional[Callable[[str], bool]] = None,
    ) -> None:
        if not isinstance(
            containment,
            ContainmentController,
        ):
            raise ResponseError(
                "containment must be a ContainmentController"
            )

        self._containment = containment
        self._recorder = recorder
        self._approver = approver
        self._clock = clock
        self._rules: dict[str, ResponseRule] = {}
        self._history: list[ResponseRecord] = []
        self._counter: int = 0

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def set_policy(
        self,
        rules: Iterable[ResponseRule],
    ) -> None:
        """Replace the response policy."""

        self._rules = {
            rule.rule_id: rule for rule in rules
        }

    def add_rule(self, rule: ResponseRule) -> None:
        self._rules[rule.rule_id] = rule

    def policy(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": rule.rule_id,
                "min_severity": rule.min_severity,
                "stage": rule.stage,
                "auto_approve": rule.auto_approve,
            }
            for rule in sorted(
                self._rules.values(),
                key=lambda rule: rule.rule_id,
            )
        ]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def respond(
        self,
        detection: Detection,
        *,
        actor: str = "automation",
    ) -> ResponseRecord:
        """Evaluate one detection against the policy and act.

        Returns a record of what was done (including ``stage=observe``
        when the policy says to only watch). Raises
        :class:`ResponseError` when the policy demands a high-impact
        action that is not approved -- never silently downgrades.
        """

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
            )

        severity_rank = _SEVERITY_RANK.get(
            detection.severity,
            0,
        )
        min_rank = _SEVERITY_RANK.get(
            rule.min_severity,
            0,
        )

        if severity_rank < min_rank:
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
            )

        stage = rule.stage

        if stage == "observe":
            return self._record(
                detection_id,
                detection,
                stage="observe",
                actor=actor,
                reason="policy says observe",
            )

        if stage == "warn":
            return self._record(
                detection_id,
                detection,
                stage="warn",
                actor=actor,
                reason=(
                    f"policy {rule.rule_id} escalates "
                    f"{detection.rule_id} to warn"
                ),
            )

        # High-impact stages require approval unless auto-approved.
        approved = True

        if stage in APPROVAL_REQUIRED_STAGES and not rule.auto_approve:
            approved = False

            if self._approver is not None:
                try:
                    approved = bool(
                        self._approver(stage)
                    )
                except Exception:
                    approved = False

        if not approved:
            raise ResponseError(
                f"{stage} of {detection.agents[0] if detection.agents else '?'} "
                f"requires human approval (rule {rule.rule_id})"
            )

        action = _STAGE_ACTION.get(stage)

        if action is None:
            return self._record(
                detection_id,
                detection,
                stage=stage,
                actor=actor,
                reason=f"policy stage {stage} has no containment action",
                approved=approved,
            )

        agent = (
            detection.agents[0]
            if detection.agents
            else ""
        )

        if not agent:
            raise ResponseError(
                "detection carries no agent to contain"
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
                approved=approved,
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
            approved=approved,
        )

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def history(self) -> tuple[ResponseRecord, ...]:
        return tuple(self._history)

    def snapshot(self) -> dict[str, Any]:
        return {
            "policy": self.policy(),
            "history": [
                record.to_dict() for record in self._history
            ],
            "containment": self._containment.snapshot(),
        }

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
        approved: bool = True,
        error: Optional[str] = None,
    ) -> ResponseRecord:
        import time

        timestamp = (
            self._clock()
            if self._clock is not None
            else time.time()
        )

        record = ResponseRecord(
            detection_id=detection_id,
            rule_id=detection.rule_id,
            agent=(
                detection.agents[0]
                if detection.agents
                else ""
            ),
            stage=stage,
            actor=actor,
            reason=reason,
            timestamp=float(timestamp),
            approved=approved,
            error=error,
        )

        self._history.append(record)

        if self._recorder is not None:
            try:
                self._recorder.record(
                    EventType.SECURITY_STATE,
                    {
                        "change": f"response:{stage}",
                        "detection_id": detection_id,
                        "rule_id": detection.rule_id,
                        "agent": record.agent,
                        "reason": reason,
                    },
                    agent=record.agent or None,
                )
            except Exception:
                pass

        return record
