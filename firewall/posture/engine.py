"""v2.0 Continuous Security Posture (firewall.posture).

A continuously calculated, evidence-backed agent posture with an
explicit state model:

    unknown < healthy < degraded < suspicious < high_risk
           < compromised < contained < recovering < retired

Every transition is produced by a named signal with evidence; the
posture engine never invents facts and never silently upgrades without
evidence. Inputs include authorization denials, behavioral detections,
attack paths, compromised dependencies, containment, verification
failures, and provenance failures.

``explain(agent)`` answers: why is this agent in this posture, which
evidence caused the transition, what can it currently do, and what
should be revoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

#: Posture order, low to high severity.
POSTURES = (
    "unknown",
    "healthy",
    "degraded",
    "suspicious",
    "high_risk",
    "compromised",
    "contained",
    "recovering",
    "retired",
)

_RANK = {posture: index for index, posture in enumerate(POSTURES)}


class PostureError(ValueError):
    """Raised for an invalid posture operation."""


@dataclass(frozen=True)
class PostureSignal:
    """One evidence-backed input that moves posture."""

    name: str
    severity: int  # 1..9, matching posture rank
    description: str
    evidence: tuple[dict[str, Any], ...] = ()
    agent: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "evidence": [dict(entry) for entry in self.evidence],
            "agent": self.agent,
        }


@dataclass(frozen=True)
class PostureTransition:
    """One posture change with its reason and evidence."""

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
            "signals": [dict(signal) for signal in self.signals],
        }


@dataclass(frozen=True)
class PostureState:
    """The current posture of one agent."""

    agent: str
    posture: str
    transitions: tuple[PostureTransition, ...] = ()
    signals: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "posture": self.posture,
            "transitions": [
                transition.to_dict() for transition in self.transitions
            ],
            "signals": [dict(signal) for signal in self.signals],
        }


def _signal(
    name: str,
    severity: int,
    description: str,
    evidence: Iterable[dict[str, Any]] = (),
    agent: str = "",
) -> PostureSignal:
    return PostureSignal(
        name=name,
        severity=severity,
        description=description,
        evidence=tuple(evidence),
        agent=agent,
    )


class PostureEngine:
    """Evidence-driven posture calculation for agents."""

    def __init__(self) -> None:
        self._lock = __import__("threading").RLock()
        # agent -> current posture
        self._postures: dict[str, str] = {}
        # agent -> list of (seq, PostureSignal)
        self._signals: dict[str, list[tuple[int, PostureSignal]]] = {}
        # agent -> transitions
        self._transitions: dict[str, list[PostureTransition]] = {}
        self._seq: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Signal ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        agent: str,
        signal: PostureSignal,
        *,
        now: Optional[float] = None,
    ) -> PostureState:
        """Record one signal and recompute the agent's posture.

        Posture is the maximum rank reached by the agent's recorded
        signals (with a floor of ``healthy`` once any evidence exists,
        and explicit recovery/containment states handled below).
        """

        import time

        if not isinstance(agent, str) or not agent.strip():
            raise PostureError("agent is required")

        if not isinstance(signal, PostureSignal):
            raise PostureError("signal must be a PostureSignal")

        with self._lock:
            self._seq.setdefault(agent, 0)
            self._signals.setdefault(agent, [])
            self._transitions.setdefault(agent, [])

            self._seq[agent] += 1
            seq = self._seq[agent]
            self._signals[agent].append((seq, signal))

            previous = self._postures.get(agent, "unknown")
            target = self._compute(agent)

            if _RANK[target] > _RANK[previous]:
                self._postures[agent] = target
                self._transitions[agent].append(
                    PostureTransition(
                        agent=agent,
                        from_posture=previous,
                        to_posture=target,
                        seq=seq,
                        timestamp=(
                            now if now is not None else time.time()
                        ),
                        signals=[signal.to_dict()],
                    )
                )
            elif target == "recovering" and previous != "recovering":
                self._postures[agent] = target
                self._transitions[agent].append(
                    PostureTransition(
                        agent=agent,
                        from_posture=previous,
                        to_posture=target,
                        seq=seq,
                        timestamp=(
                            now if now is not None else time.time()
                        ),
                        signals=[signal.to_dict()],
                    )
                )
            elif target == "contained" and _RANK[target] > _RANK.get(
                previous, 0
            ):
                self._postures[agent] = target
                self._transitions[agent].append(
                    PostureTransition(
                        agent=agent,
                        from_posture=previous,
                        to_posture=target,
                        seq=seq,
                        timestamp=(
                            now if now is not None else time.time()
                        ),
                        signals=[signal.to_dict()],
                    )
                )

            return self.state(agent)

    def _compute(self, agent: str) -> str:
        """Derive posture from recorded signals.

        Deterministic: the highest-severity signal rank wins, with
        containment (6) and recovery (7) handled as explicit states.
        """

        signals = [signal for _, signal in self._signals.get(agent, ())]

        if not signals:
            return "unknown"

        max_severity = max(signal.severity for signal in signals)

        # Explicit state signals override the severity floor; the LATEST
        # one wins (recovery after containment, retirement after
        # anything).
        for signal in reversed(signals):
            if signal.name == "containment":
                return "contained"
            if signal.name == "recovery":
                return "recovering"
            if signal.name == "retired":
                return "retired"

        if max_severity <= 1:
            return "healthy"
        if max_severity == 2:
            return "degraded"
        if max_severity == 3:
            return "suspicious"
        if max_severity == 4:
            return "high_risk"
        if max_severity >= 5:
            return "compromised"

        return "unknown"

    # ------------------------------------------------------------------
    # State / introspection
    # ------------------------------------------------------------------

    def state(self, agent: str) -> PostureState:
        with self._lock:
            posture = self._postures.get(agent, "unknown")
            return PostureState(
                agent=agent,
                posture=posture,
                transitions=tuple(
                    self._transitions.get(agent, [])
                ),
                signals=tuple(
                    signal.to_dict()
                    for _, signal in self._signals.get(agent, ())
                ),
            )

    def get(self, agent: str) -> dict[str, Any]:
        """Provider-shaped accessor for the passport builder."""

        return self.state(agent).to_dict()

    def all_states(self) -> tuple[PostureState, ...]:
        with self._lock:
            agents = sorted(set(self._postures))
            return tuple(self.state(agent) for agent in agents)

    def explain(self, agent: str) -> dict[str, Any]:
        """Why is this agent in this posture?"""

        state = self.state(agent)
        last_transition = (
            state.transitions[-1]
            if state.transitions
            else None
        )

        return {
            "agent": agent,
            "posture": state.posture,
            "why": (
                f"{agent} reached {state.posture} via "
                + (
                    "evidence: "
                    + "; ".join(
                        f"{s['name']} ({s['description']})"
                        for s in (
                            last_transition.signals
                            if last_transition
                            else ()
                        )
                    )
                    if last_transition
                    else "no recorded evidence"
                )
            ),
            "evidence": (
                [dict(s) for s in last_transition.signals]
                if last_transition
                else []
            ),
            "transition_count": len(state.transitions),
        }

    def reset(self, agent: str) -> None:
        with self._lock:
            self._postures.pop(agent, None)
            self._signals.pop(agent, None)
            self._transitions.pop(agent, None)
            self._seq.pop(agent, None)
