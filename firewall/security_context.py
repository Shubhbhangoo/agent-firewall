from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Optional


class SecurityContextError(Exception):
    """Base security-context error."""


class SecurityBudgetExceeded(SecurityContextError):
    """Raised when a security context budget would be exceeded."""


@dataclass(frozen=True)
class SecuritySnapshot:
    agent: str
    action_count: int
    total_amount: float
    denial_count: int
    used_capabilities: tuple[str, ...]


@dataclass
class SecurityContext:
    """
    Runtime security state for a single agent/session.

    v1.2 runtime controls currently include:

    - cumulative action budgets
    - cumulative amount budgets
    - denial tracking
    - capability usage tracking

    Budget validation and successful action recording are
    performed atomically under one lock.
    """

    agent: str

    max_actions: Optional[int] = None
    max_total_amount: Optional[float] = None

    action_count: int = 0
    total_amount: float = 0.0
    denial_count: int = 0

    _used_capabilities: set[str] = field(
        default_factory=set,
        repr=False,
    )

    _lock: RLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(
                self.agent,
                str,
            )
            or not self.agent
        ):
            raise ValueError(
                "agent must be a non-empty string"
            )

        if (
            self.max_actions is not None
            and (
                not isinstance(
                    self.max_actions,
                    int,
                )
                or isinstance(
                    self.max_actions,
                    bool,
                )
                or self.max_actions < 0
            )
        ):
            raise ValueError(
                "max_actions must be a non-negative integer"
            )

        if (
            self.max_total_amount is not None
            and (
                not isinstance(
                    self.max_total_amount,
                    (int, float),
                )
                or isinstance(
                    self.max_total_amount,
                    bool,
                )
                or self.max_total_amount < 0
            )
        ):
            raise ValueError(
                "max_total_amount must be non-negative"
            )

        if self.action_count < 0:
            raise ValueError(
                "action_count cannot be negative"
            )

        if self.total_amount < 0:
            raise ValueError(
                "total_amount cannot be negative"
            )

        if self.denial_count < 0:
            raise ValueError(
                "denial_count cannot be negative"
            )

    # =========================================================
    # Request helpers
    # =========================================================

    @staticmethod
    def _amount(
        request: dict[str, Any],
    ) -> float:
        value = request.get(
            "amount",
            0,
        )

        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "amount must be numeric"
            )

        if not isinstance(
            value,
            (int, float),
        ):
            raise ValueError(
                "amount must be numeric"
            )

        if value < 0:
            raise ValueError(
                "amount cannot be negative"
            )

        return float(value)

    @staticmethod
    def _validate_fingerprint(
        capability_fingerprint: Optional[str],
    ) -> None:
        if (
            capability_fingerprint is not None
            and not isinstance(
                capability_fingerprint,
                str,
            )
        ):
            raise ValueError(
                "capability_fingerprint must be a string"
            )

    # =========================================================
    # Budget checks
    # =========================================================

    def _check_action_budget(
        self,
    ) -> None:
        if (
            self.max_actions is not None
            and (
                self.action_count + 1
                > self.max_actions
            )
        ):
            raise SecurityBudgetExceeded(
                "action budget exceeded"
            )

    def _check_amount_budget(
        self,
        amount: float,
    ) -> None:
        if (
            self.max_total_amount is not None
            and (
                self.total_amount + amount
                > self.max_total_amount
            )
        ):
            raise SecurityBudgetExceeded(
                "total amount budget exceeded"
            )

    # =========================================================
    # Non-mutating preflight
    # =========================================================

    def check(
        self,
        request: dict[str, Any],
    ) -> None:
        """
        Check whether an action would fit inside the current
        budgets without mutating state.

        This is only a preflight operation.

        For an authorization decision that must consume budget,
        use authorize_and_record().
        """

        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be a dictionary"
            )

        amount = self._amount(
            request
        )

        with self._lock:
            self._check_action_budget()
            self._check_amount_budget(
                amount
            )

    # =========================================================
    # Atomic authorization + recording
    # =========================================================

    def authorize_and_record(
        self,
        *,
        request: dict[str, Any],
        capability_fingerprint: Optional[str] = None,
    ) -> None:
        """
        Atomically check budgets and record a successful action.

        The budget check and mutation happen under the same lock.

        This prevents concurrent requests from both observing
        the same remaining budget and both being accepted.
        """

        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be a dictionary"
            )

        self._validate_fingerprint(
            capability_fingerprint
        )

        amount = self._amount(
            request
        )

        with self._lock:
            self._check_action_budget()
            self._check_amount_budget(
                amount
            )

            self.action_count += 1
            self.total_amount += amount

            if capability_fingerprint is not None:
                self._used_capabilities.add(
                    capability_fingerprint
                )

    # =========================================================
    # Record
    # =========================================================

    def record(
        self,
        *,
        request: dict[str, Any],
        capability_fingerprint: Optional[str] = None,
    ) -> None:
        """
        Backwards-compatible recording API.

        Uses the same atomic implementation as
        authorize_and_record().
        """

        self.authorize_and_record(
            request=request,
            capability_fingerprint=(
                capability_fingerprint
            ),
        )

    # =========================================================
    # Denials
    # =========================================================

    def record_denial(
        self,
    ) -> None:
        with self._lock:
            self.denial_count += 1

    # =========================================================
    # Capability tracking
    # =========================================================

    def has_used_capability(
        self,
        fingerprint: str,
    ) -> bool:
        if not isinstance(
            fingerprint,
            str,
        ):
            raise ValueError(
                "fingerprint must be a string"
            )

        with self._lock:
            return (
                fingerprint
                in self._used_capabilities
            )

    # =========================================================
    # Snapshot
    # =========================================================

    def snapshot(
        self,
    ) -> SecuritySnapshot:
        with self._lock:
            return SecuritySnapshot(
                agent=self.agent,
                action_count=self.action_count,
                total_amount=self.total_amount,
                denial_count=self.denial_count,
                used_capabilities=tuple(
                    sorted(
                        self._used_capabilities
                    )
                ),
            )

    # =========================================================
    # Reset
    # =========================================================

    def reset(
        self,
    ) -> None:
        """
        Reset runtime state while preserving budget
        configuration.
        """

        with self._lock:
            self.action_count = 0
            self.total_amount = 0.0
            self.denial_count = 0
            self._used_capabilities.clear()