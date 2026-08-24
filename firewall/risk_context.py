from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from threading import RLock
from typing import Dict


class RiskLevel(IntEnum):
    NORMAL = 0
    ELEVATED = 1
    RESTRICTED = 2
    REVOKED = 3


@dataclass(frozen=True)
class RiskSnapshot:
    agent: str
    level: RiskLevel
    event_count: int
    denial_count: int
    escalation_count: int


class RiskContext:
    """
    Deterministic runtime risk state for an agent.

    Risk only moves upward. It never automatically decays.

    This primitive is intentionally independent from FirewallSDK.
    """

    def __init__(
        self,
        *,
        elevated_after_denials: int = 3,
        restricted_after_escalations: int = 3,
        revoke_after_critical: int = 1,
    ) -> None:
        if elevated_after_denials < 1:
            raise ValueError("elevated_after_denials must be >= 1")

        if restricted_after_escalations < 1:
            raise ValueError("restricted_after_escalations must be >= 1")

        if revoke_after_critical < 1:
            raise ValueError("revoke_after_critical must be >= 1")

        self.elevated_after_denials = elevated_after_denials
        self.restricted_after_escalations = restricted_after_escalations
        self.revoke_after_critical = revoke_after_critical

        self._lock = RLock()
        self._levels: Dict[str, RiskLevel] = {}
        self._events: Dict[str, int] = {}
        self._denials: Dict[str, int] = {}
        self._escalations: Dict[str, int] = {}
        self._critical: Dict[str, int] = {}

    def _ensure_agent(self, agent: str) -> None:
        if not agent:
            raise ValueError("agent must be non-empty")

        self._levels.setdefault(agent, RiskLevel.NORMAL)
        self._events.setdefault(agent, 0)
        self._denials.setdefault(agent, 0)
        self._escalations.setdefault(agent, 0)
        self._critical.setdefault(agent, 0)

    def level(self, agent: str) -> RiskLevel:
        with self._lock:
            self._ensure_agent(agent)
            return self._levels[agent]

    def snapshot(self, agent: str) -> RiskSnapshot:
        with self._lock:
            self._ensure_agent(agent)

            return RiskSnapshot(
                agent=agent,
                level=self._levels[agent],
                event_count=self._events[agent],
                denial_count=self._denials[agent],
                escalation_count=self._escalations[agent],
            )

    def record_denial(self, agent: str) -> RiskSnapshot:
        with self._lock:
            self._ensure_agent(agent)

            self._events[agent] += 1
            self._denials[agent] += 1

            if (
                self._denials[agent] >= self.elevated_after_denials
                and self._levels[agent] < RiskLevel.ELEVATED
            ):
                self._levels[agent] = RiskLevel.ELEVATED

            return self.snapshot(agent)

    def record_escalation(self, agent: str) -> RiskSnapshot:
        with self._lock:
            self._ensure_agent(agent)

            self._events[agent] += 1
            self._escalations[agent] += 1

            if self._levels[agent] < RiskLevel.ELEVATED:
                self._levels[agent] = RiskLevel.ELEVATED

            if (
                self._escalations[agent] >= self.restricted_after_escalations
                and self._levels[agent] < RiskLevel.RESTRICTED
            ):
                self._levels[agent] = RiskLevel.RESTRICTED

            return self.snapshot(agent)

    def record_critical(self, agent: str) -> RiskSnapshot:
        with self._lock:
            self._ensure_agent(agent)

            self._events[agent] += 1
            self._critical[agent] += 1

            if self._critical[agent] >= self.revoke_after_critical:
                self._levels[agent] = RiskLevel.REVOKED

            return self.snapshot(agent)

    def can_authorize(self, agent: str) -> bool:
        with self._lock:
            self._ensure_agent(agent)
            return self._levels[agent] < RiskLevel.REVOKED

    def reset(self, agent: str) -> None:
        """
        Explicit administrative reset.

        This is NOT automatic risk decay.
        """
        with self._lock:
            self._ensure_agent(agent)

            self._levels[agent] = RiskLevel.NORMAL
            self._events[agent] = 0
            self._denials[agent] = 0
            self._escalations[agent] = 0
            self._critical[agent] = 0