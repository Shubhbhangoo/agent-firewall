from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class PolicyError(Exception):
    """Base policy evaluation error."""


class PolicyDefinitionError(PolicyError):
    """Raised when a policy definition is malformed."""


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason: str = "authorized"
    key: str | None = None
    operator: str | None = None


SUPPORTED_OPERATORS = frozenset(
    {
        "eq",
        "neq",
        "in",
        "not_in",
        "gte",
        "lte",
        "contains",
    }
)


def _safe_contains(
    actual: Any,
    expected: Any,
) -> bool:
    try:
        return expected in actual
    except (TypeError, AttributeError):
        return False


def _compare(
    operator: str,
    actual: Any,
    expected: Any,
) -> bool:
    if operator == "eq":
        return actual == expected

    if operator == "neq":
        return actual != expected

    if operator == "in":
        try:
            return actual in expected
        except TypeError:
            return False

    if operator == "not_in":
        try:
            return actual not in expected
        except TypeError:
            return False

    if operator == "gte":
        try:
            return actual >= expected
        except TypeError:
            return False

    if operator == "lte":
        try:
            return actual <= expected
        except TypeError:
            return False

    if operator == "contains":
        return _safe_contains(
            actual,
            expected,
        )

    raise PolicyDefinitionError(
        f"unsupported policy operator: {operator}"
    )


def _evaluate_operator_map(
    *,
    key: str,
    actual: Any,
    operators: Mapping[str, Any],
) -> PolicyResult:
    for operator, expected in operators.items():

        if operator not in SUPPORTED_OPERATORS:
            raise PolicyDefinitionError(
                f"unsupported policy operator: {operator}"
            )

        if not _compare(
            operator,
            actual,
            expected,
        ):
            return PolicyResult(
                allowed=False,
                reason="policy_denied",
                key=key,
                operator=operator,
            )

    return PolicyResult(
        allowed=True
    )


def evaluate_policy(
    policy: Mapping[str, Any],
    request: Mapping[str, Any],
) -> PolicyResult:
    """
    Evaluate a v1.1 policy against a request.

    Example:

        {
            "currency": {
                "eq": "USD"
            },
            "amount": {
                "gte": 10,
                "lte": 100
            }
        }

    Every policy entry must pass.

    Nested dictionaries without supported operators are
    treated as nested policy objects.
    """

    if not isinstance(
        policy,
        Mapping,
    ):
        raise PolicyDefinitionError(
            "policy must be a mapping"
        )

    if not isinstance(
        request,
        Mapping,
    ):
        return PolicyResult(
            allowed=False,
            reason="invalid_request",
        )

    for key, rule in policy.items():

        if not isinstance(
            key,
            str,
        ) or not key:
            raise PolicyDefinitionError(
                "policy keys must be non-empty strings"
            )

        if isinstance(
            rule,
            Mapping,
        ):
            operator_keys = set(
                rule.keys()
            ) & SUPPORTED_OPERATORS

            if operator_keys:
                if key not in request:
                    return PolicyResult(
                        allowed=False,
                        reason="policy_denied",
                        key=key,
                    )

                result = _evaluate_operator_map(
                    key=key,
                    actual=request[key],
                    operators=rule,
                )

                if not result.allowed:
                    return result

                continue

            if key not in request:
                return PolicyResult(
                    allowed=False,
                    reason="policy_denied",
                    key=key,
                )

            actual = request[key]

            if not isinstance(
                actual,
                Mapping,
            ):
                return PolicyResult(
                    allowed=False,
                    reason="policy_denied",
                    key=key,
                )

            result = evaluate_policy(
                rule,
                actual,
            )

            if not result.allowed:
                if result.key is None:
                    return PolicyResult(
                        allowed=False,
                        reason=result.reason,
                        key=key,
                        operator=result.operator,
                    )

                return result

            continue

        if key not in request:
            return PolicyResult(
                allowed=False,
                reason="policy_denied",
                key=key,
                operator="eq",
            )

        if request[key] != rule:
            return PolicyResult(
                allowed=False,
                reason="policy_denied",
                key=key,
                operator="eq",
            )

    return PolicyResult(
        allowed=True
    )