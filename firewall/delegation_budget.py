from __future__ import annotations

import math
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
            or not math.isfinite(
                self.max_total_amount
            )
            or self.max_total_amount < 0
        ):
            raise ValueError(
                "max_total_amount must be non-negative"
            )

        if (
            isinstance(
                self.total_amount,
                bool,
            )
            or not isinstance(
                self.total_amount,
                (int, float),
            )
            or not math.isfinite(
                self.total_amount
            )
            or self.total_amount < 0
        ):
            raise ValueError(
                "total_amount must be non-negative"
            )

        self.max_total_amount = float(
            self.max_total_amount
        )

        self.total_amount = float(
            self.total_amount
        )

        # Deliberately *not* validated: ``total_amount > max_total_amount``.
        # Lowering a ceiling below what a lineage has already spent is a
        # narrowing operation and must take effect, not be rejected. The
        # resulting state simply admits nothing further, which is the
        # correct reading of "this lineage may spend at most N in total".

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

        # The ceiling is enforced by its negation -- the reservation is
        # admitted unless ``total + amount > max`` -- and NaN compares
        # False against every bound. A NaN reservation would therefore be
        # admitted *and* would make ``total_amount`` NaN, after which every
        # later comparison is False too and the budget admits everything
        # forever. Infinity is refused here rather than by the ceiling so
        # that the error names the input rather than the limit.
        if not math.isfinite(
            amount
        ):
            raise ValueError(
                "amount must be finite"
            )

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
        """
        Set the cumulative ceiling for a lineage, preserving what
        it has already consumed.

        Reconfiguring an existing lineage adjusts the ceiling only.
        The consumed total is a record of what was authorized, not a
        setting, and configuration does not rewrite it: a call that
        reset it to zero would restore an exhausted lineage's whole
        allowance without revoking, re-issuing or signing anything,
        which makes an administrative call an escalation path. The
        idempotent case is the dangerous one -- re-applying the same
        limit at startup would silently clear the ledger on every
        restart, so the budget would never bind.

        A new ceiling below the consumed total is accepted and
        admits nothing further.
        """

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
            existing = self._budgets.get(
                root_fingerprint
            )

            state = DelegationBudgetState(
                max_total_amount=max_total_amount,
                total_amount=(
                    0.0
                    if existing is None
                    else existing.total_amount
                ),
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
