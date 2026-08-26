from __future__ import annotations

from dataclasses import dataclass
from threading import RLock


class DelegationBudgetExceeded(Exception):
    """Raised when a delegation lineage budget would be exceeded."""


@dataclass
class DelegationBudgetState:
    max_total_amount: float
    total_amount: float = 0.0

    def __post_init__(self) -> None:
        if (
            isinstance(
                self.max_total_amount,
                bool,
            )
            or not isinstance(
                self.max_total_amount,
                (int, float),
            )
            or self.max_total_amount < 0
        ):
            raise ValueError(
                "max_total_amount must be non-negative"
            )

        self.max_total_amount = float(
            self.max_total_amount
        )

    def reserve(
        self,
        amount: float,
    ) -> None:
        if (
            isinstance(
                amount,
                bool,
            )
            or not isinstance(
                amount,
                (int, float),
            )
        ):
            raise ValueError(
                "amount must be numeric"
            )

        amount = float(amount)

        if amount < 0:
            raise ValueError(
                "amount cannot be negative"
            )

        if (
            self.total_amount + amount
            > self.max_total_amount
        ):
            raise DelegationBudgetExceeded(
                "delegation budget exceeded"
            )

        self.total_amount += amount


class DelegationBudgetRegistry:
    """
    Thread-safe cumulative budgets keyed by the root
    capability fingerprint.

    Every descendant in a delegation lineage consumes
    the same root budget.
    """

    def __init__(self) -> None:
        self._budgets: dict[
            str,
            DelegationBudgetState,
        ] = {}

        self._lock = RLock()

    def configure(
        self,
        root_fingerprint: str,
        max_total_amount: float,
    ) -> DelegationBudgetState:
        if (
            not isinstance(
                root_fingerprint,
                str,
            )
            or not root_fingerprint
        ):
            raise ValueError(
                "root_fingerprint must be a non-empty string"
            )

        with self._lock:
            state = DelegationBudgetState(
                max_total_amount=max_total_amount,
            )

            self._budgets[
                root_fingerprint
            ] = state

            return state

    def get(
        self,
        root_fingerprint: str,
    ) -> DelegationBudgetState | None:
        with self._lock:
            return self._budgets.get(
                root_fingerprint
            )

    def reserve(
        self,
        root_fingerprint: str,
        amount: float,
    ) -> None:
        with self._lock:
            state = self._budgets.get(
                root_fingerprint
            )

            if state is None:
                raise KeyError(
                    "no delegation budget configured"
                )

            state.reserve(
                amount
            )

    def total_amount(
        self,
        root_fingerprint: str,
    ) -> float:
        with self._lock:
            state = self._budgets.get(
                root_fingerprint
            )

            if state is None:
                raise KeyError(
                    "no delegation budget configured"
                )

            return state.total_amount

    def max_total_amount(
        self,
        root_fingerprint: str,
    ) -> float:
        with self._lock:
            state = self._budgets.get(
                root_fingerprint
            )

            if state is None:
                raise KeyError(
                    "no delegation budget configured"
                )

            return state.max_total_amount
