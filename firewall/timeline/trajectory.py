"""The agent security trajectory (v1.8).

Instead of treating every request as isolated, a trajectory is a
coherent, evidence-backed account of how an agent's security posture
changed over a session:

    TRUSTED -> UNUSUAL -> SUSPICIOUS -> HIGH_RISK -> CONTAINED -> RECOVERED

Every transition is produced by a named, deterministic signal rule that
points at the recorded event(s) that fired it. There is no magic risk
number: if the posture changed, the artifact contains the evidence and
this module can name it.

Posture only ever moves on evidence. A transition rule never invents
facts; it reads the artifact. Rules are deliberately conservative -- a
signal escalates, never de-escalates on its own -- and recovery requires
an explicit recovery action.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional

from firewall.artifact import validate_manifest
from firewall.recorder.events import EventType, SecurityEvent


class Posture(str, Enum):
    TRUSTED = "trusted"
    UNUSUAL = "unusual"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CONTAINED = "contained"
    RECOVERED = "recovered"


#: Posture rank used for monotonic escalation decisions.
_RANK = {
    Posture.TRUSTED: 0,
    Posture.UNUSUAL: 1,
    Posture.SUSPICIOUS: 2,
    Posture.HIGH_RISK: 3,
    Posture.CONTAINED: 4,
    Posture.RECOVERED: 5,
}


@dataclass(frozen=True)
class PostureTransition:
    """One evidence-backed posture change for one agent."""

    agent: str
    from_posture: str
    to_posture: str
    seq: int
    timestamp: float
    signals: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "from": self.from_posture,
            "to": self.to_posture,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "signals": [
                dict(signal) for signal in self.signals
            ],
        }


@dataclass(frozen=True)
class Trajectory:
    """The full posture history for every agent in a session."""

    transitions: tuple[PostureTransition, ...]

    #: agent -> (posture, seq, timestamp) at the end of the session.
    final: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "transitions": [
                transition.to_dict()
                for transition in self.transitions
            ],
            "final": {
                agent: dict(state)
                for agent, state in self.final.items()
            },
        }

    def for_agent(
        self,
        agent: str,
    ) -> tuple[PostureTransition, ...]:
        return tuple(
            transition
            for transition in self.transitions
            if transition.agent == agent
        )


def _signal(
    name: str,
    seq: int,
    description: str,
) -> dict[str, Any]:
    return {
        "signal": name,
        "evidence_seq": seq,
        "description": description,
    }


#: Denial reasons that are structurally significant rather than ordinary
#: constraint refusals.
_STRUCTURAL_DENIALS = {
    "capability_revoked",
    "untrusted_issuer",
    "delegation_chain_error",
    "delegation_depth_exceeded",
    "risk_state_revoked",
    "semantic_chain_denied",
    "missing_ancestor",
    "revoked_ancestor",
}

#: Default thresholds: denial counts that push an agent up the ladder.
_DEFAULT_THRESHOLDS = {
    "unusual_after_denials": 1,
    "suspicious_after_denials": 3,
    "high_risk_after_denials": 6,
}


def from_events(
    events: Iterable[SecurityEvent],
    *,
    thresholds: Optional[dict[str, int]] = None,
) -> Trajectory:
    """Derive the trajectory from recorded events.

    Deterministic: the same events always produce the same trajectory.
    Signals are evaluated per agent, in event order.
    """

    config = dict(_DEFAULT_THRESHOLDS)
    if thresholds:
        config.update(thresholds)

    posture: dict[str, Posture] = {}
    denial_counts: dict[str, int] = {}
    transitions: list[PostureTransition] = []
    final: dict[str, dict[str, Any]] = {}

    def current(agent: str) -> Posture:
        return posture.get(
            agent, Posture.TRUSTED
        )

    def escalate(
        agent: str,
        target: Posture,
        seq: int,
        timestamp: float,
        signals: list[dict[str, Any]],
    ) -> None:
        before = current(agent)

        if _RANK[target] <= _RANK[before]:
            return

        posture[agent] = target

        transitions.append(
            PostureTransition(
                agent=agent,
                from_posture=before.value,
                to_posture=target.value,
                seq=seq,
                timestamp=timestamp,
                signals=tuple(signals),
            )
        )

    for event in events:
        agent = event.agent or event.payload.get("agent") or "system"
        payload = event.payload or {}

        denial_counts.setdefault(agent, 0)

        if event.type == EventType.AUTHORIZATION:
            if not payload.get("allowed"):
                denial_counts[agent] += 1
                count = denial_counts[agent]
                signals: list[dict[str, Any]] = []
                target: Optional[Posture] = None

                reason = payload.get("reason") or ""

                if reason in _STRUCTURAL_DENIALS:
                    target = Posture.SUSPICIOUS
                    signals.append(
                        _signal(
                            "structural_denial",
                            event.seq,
                            f"denied with structural reason "
                            f"{reason!r}",
                        )
                    )
                elif count >= config["high_risk_after_denials"]:
                    target = Posture.HIGH_RISK
                    signals.append(
                        _signal(
                            "denial_accumulation",
                            event.seq,
                            f"{count} denials recorded",
                        )
                    )
                elif count >= config["suspicious_after_denials"]:
                    target = Posture.SUSPICIOUS
                    signals.append(
                        _signal(
                            "denial_accumulation",
                            event.seq,
                            f"{count} denials recorded",
                        )
                    )
                elif count >= config["unusual_after_denials"]:
                    target = Posture.UNUSUAL
                    signals.append(
                        _signal(
                            "first_denial",
                            event.seq,
                            "first authorization denial",
                        )
                    )

                if target is not None:
                    escalate(
                        agent,
                        target,
                        event.seq,
                        event.timestamp,
                        signals,
                    )

        elif event.type == EventType.AUTHORITY_REVOKED:
            escalate(
                agent,
                Posture.HIGH_RISK,
                event.seq,
                event.timestamp,
                [
                    _signal(
                        "authority_revoked",
                        event.seq,
                        "a capability was revoked for this agent",
                    )
                ],
            )

        elif event.type == EventType.SECURITY_STATE:
            change = payload.get("change") or ""

            if change == "replay_detected":
                escalate(
                    agent,
                    Posture.SUSPICIOUS,
                    event.seq,
                    event.timestamp,
                    [
                        _signal(
                            "replay_detected",
                            event.seq,
                            "a replayed capability was detected",
                        )
                    ],
                )
            elif change == "issuer_untrusted":
                escalate(
                    agent,
                    Posture.SUSPICIOUS,
                    event.seq,
                    event.timestamp,
                    [
                        _signal(
                            "issuer_untrusted",
                            event.seq,
                            "an issuer lost trust",
                        )
                    ],
                )

        elif event.type == EventType.CONTAINMENT:
            state = payload.get("state") or ""

            if state in (
                "quarantined",
                "suspended",
                "restricted",
            ):
                escalate(
                    agent,
                    Posture.CONTAINED,
                    event.seq,
                    event.timestamp,
                    [
                        _signal(
                            "containment",
                            event.seq,
                            f"containment state {state}",
                        )
                    ],
                )
            elif state == "recovered":
                escalate(
                    agent,
                    Posture.RECOVERED,
                    event.seq,
                    event.timestamp,
                    [
                        _signal(
                            "recovery",
                            event.seq,
                            "explicit recovery action recorded",
                        )
                    ],
                )

        elif event.type == EventType.RISK_CHANGED:
            level = payload.get("level") or ""

            if level == "revoked":
                escalate(
                    agent,
                    Posture.HIGH_RISK,
                    event.seq,
                    event.timestamp,
                    [
                        _signal(
                            "risk_revoked",
                            event.seq,
                            "runtime risk reached the revoked level",
                        )
                    ],
                )
            elif level in ("elevated", "restricted"):
                escalate(
                    agent,
                    Posture.SUSPICIOUS,
                    event.seq,
                    event.timestamp,
                    [
                        _signal(
                            "risk_elevated",
                            event.seq,
                            f"runtime risk level {level}",
                        )
                    ],
                )

        final[agent] = {
            "posture": current(agent).value,
            "seq": event.seq,
            "timestamp": event.timestamp,
        }

    return Trajectory(
        transitions=tuple(transitions),
        final=final,
    )


def from_artifact(
    artifact: dict[str, Any],
    *,
    thresholds: Optional[dict[str, int]] = None,
) -> Trajectory:
    """Derive the trajectory from a validated artifact."""

    validate_manifest(artifact)

    events = [
        SecurityEvent.from_dict(entry)
        for entry in artifact.get("events", [])
        if isinstance(entry, dict)
    ]

    return from_events(
        events,
        thresholds=thresholds,
    )


def trajectory_to_text(
    trajectory: Trajectory,
) -> str:
    """Render a trajectory as plain text."""

    lines = []

    for transition in trajectory.transitions:
        lines.append(
            f"{transition.timestamp:.3f}  "
            f"{transition.agent}: "
            f"{transition.from_posture} -> {transition.to_posture}"
        )

        for signal in transition.signals:
            lines.append(
                f"    evidence event {signal['evidence_seq']}: "
                f"{signal['description']}"
            )

    for agent, state in trajectory.final.items():
        lines.append(
            f"{agent} ends {state['posture']}"
        )

    return "\n".join(lines)
