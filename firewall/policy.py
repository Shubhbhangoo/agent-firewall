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

COMPOSITION_OPERATORS = frozenset(
    {
        "and",
        "or",
        "not",
    }
)

# Reserved composition-like names. Anything outside
# COMPOSITION_OPERATORS is rejected when used as a
# top-level composition expression.
ALL_COMPOSITION_NAMES = frozenset(
    {
        "and",
        "or",
        "not",
        "xor",
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


def _evaluate_and(
    rules: Any,
    request: Mapping[str, Any],
) -> PolicyResult:
    if not isinstance(
        rules,
        (list, tuple),
    ):
        raise PolicyDefinitionError(
            "and requires a list"
        )

    for rule in rules:
        if not isinstance(
            rule,
            Mapping,
        ):
            raise PolicyDefinitionError(
                "and entries must be mappings"
            )

        result = evaluate_policy(
            rule,
            request,
        )

        if not result.allowed:
            return result

    return PolicyResult(
        allowed=True
    )


def _evaluate_or(
    rules: Any,
    request: Mapping[str, Any],
) -> PolicyResult:
    if not isinstance(
        rules,
        (list, tuple),
    ):
        raise PolicyDefinitionError(
            "or requires a list"
        )

    if not rules:
        return PolicyResult(
            allowed=False,
            reason="policy_denied",
        )

    first_failure: PolicyResult | None = None

    for rule in rules:
        if not isinstance(
            rule,
            Mapping,
        ):
            raise PolicyDefinitionError(
                "or entries must be mappings"
            )

        result = evaluate_policy(
            rule,
            request,
        )

        if result.allowed:
            return result

        if first_failure is None:
            first_failure = result

    return PolicyResult(
        allowed=False,
        reason="policy_denied",
        key=(
            first_failure.key
            if first_failure is not None
            else None
        ),
        operator=(
            first_failure.operator
            if first_failure is not None
            else "or"
        ),
    )


def _evaluate_not(
    rule: Any,
    request: Mapping[str, Any],
) -> PolicyResult:
    if not isinstance(
        rule,
        Mapping,
    ):
        raise PolicyDefinitionError(
            "not requires a mapping"
        )

    result = evaluate_policy(
        rule,
        request,
    )

    if result.allowed:
        return PolicyResult(
            allowed=False,
            reason="policy_denied",
            key=result.key,
            operator="not",
        )

    return PolicyResult(
        allowed=True
    )


def _looks_like_composition(
    policy: Mapping[str, Any],
) -> bool:
    return bool(
        set(policy.keys())
        & COMPOSITION_OPERATORS
    )


def _evaluate_composition(
    policy: Mapping[str, Any],
    request: Mapping[str, Any],
) -> PolicyResult:
    composition_keys = (
        set(policy.keys())
        & COMPOSITION_OPERATORS
    )

    if len(composition_keys) > 1:
        raise PolicyDefinitionError(
            "composition policy must contain exactly one "
            "of: and, or, not"
        )

    operator = next(
        iter(composition_keys)
    )

    if operator == "and":
        return _evaluate_and(
            policy[operator],
            request,
        )

    if operator == "or":
        return _evaluate_or(
            policy[operator],
            request,
        )

    if operator == "not":
        return _evaluate_not(
            policy[operator],
            request,
        )

    raise PolicyDefinitionError(
        f"unsupported composition operator: {operator}"
    )


def evaluate_policy(
    policy: Mapping[str, Any],
    request: Mapping[str, Any],
) -> PolicyResult:
    """
    Evaluate a v1.1 policy against a request.

    Existing operator form:

        {
            "currency": {
                "eq": "USD"
            },
            "amount": {
                "gte": 10,
                "lte": 100
            }
        }

    Composition form:

        {
            "and": [
                {"currency": {"eq": "USD"}},
                {"amount": {"lte": 100}}
            ]
        }

    Supported composition operators:

        and
        or
        not
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

    # --------------------------------------------------------
    # Reject reserved-but-unsupported composition operators
    # such as {"xor": [...]} explicitly.
    # --------------------------------------------------------

    if (
        len(policy) == 1
        and next(iter(policy))
        in ALL_COMPOSITION_NAMES
        and next(iter(policy))
        not in COMPOSITION_OPERATORS
    ):
        operator = next(
            iter(policy)
        )

        raise PolicyDefinitionError(
            f"unsupported composition operator: {operator}"
        )

    # --------------------------------------------------------
    # Top-level composition
    # --------------------------------------------------------

    if _looks_like_composition(
        policy
    ):
        return _evaluate_composition(
            policy,
            request,
        )

    # --------------------------------------------------------
    # Normal policy fields
    # --------------------------------------------------------

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
            # -----------------------------------------------
            # Nested composition
            # -----------------------------------------------

            if _looks_like_composition(
                rule
            ):
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

                result = _evaluate_composition(
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

            # -----------------------------------------------
            # Explicit value operators
            # -----------------------------------------------

            operator_keys = (
                set(rule.keys())
                & SUPPORTED_OPERATORS
            )

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

            # -----------------------------------------------
            # Existing nested policy behavior
            # -----------------------------------------------

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

        # ----------------------------------------------------
        # Literal equality
        # ----------------------------------------------------

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