from __future__ import annotations

from typing import Optional

from firewall.capability import Capability
from firewall.namespace import matches
from firewall.policy import (
    PolicyDefinitionError,
    evaluate_policy,
)


class AuthorizationResult:
    def __init__(
        self,
        allowed: bool,
        reason: str,
    ):
        self.allowed = allowed
        self.reason = reason

    def __bool__(self):
        return self.allowed

    def __repr__(self):
        return (
            f"AuthorizationResult("
            f"allowed={self.allowed!r}, "
            f"reason={self.reason!r})"
        )


def _request_key(
    constraint_key: str,
) -> str:
    if constraint_key.endswith("_max"):
        return constraint_key[:-4]

    if constraint_key.endswith("_min"):
        return constraint_key[:-4]

    return constraint_key


def _is_composition_rule(
    value: dict,
) -> bool:
    return bool(
        set(value.keys())
        & {
            "and",
            "or",
            "not",
        }
    )


def _check_constraints(
    constraints: dict,
    request: dict,
) -> bool:
    for key, expected in constraints.items():

        if key in {
            "and",
            "or",
            "not",
        }:
            try:
                result = evaluate_policy(
                    {
                        key: expected,
                    },
                    request,
                )
            except PolicyDefinitionError:
                return False

            if not result.allowed:
                return False

            continue

        request_key = _request_key(
            key
        )

        if isinstance(
            expected,
            dict,
        ):

            if _is_composition_rule(
                expected
            ):
                if request_key not in request:
                    return False

                actual = request[
                    request_key
                ]

                if not isinstance(
                    actual,
                    dict,
                ):
                    return False

                try:
                    result = evaluate_policy(
                        expected,
                        actual,
                    )
                except PolicyDefinitionError:
                    return False

                if not result.allowed:
                    return False

                continue

            if (
                set(expected.keys())
                & {
                    "eq",
                    "neq",
                    "in",
                    "not_in",
                    "gte",
                    "lte",
                    "contains",
                }
            ):
                if request_key not in request:
                    return False

                try:
                    result = evaluate_policy(
                        {
                            request_key: expected
                        },
                        request,
                    )
                except PolicyDefinitionError:
                    return False

                if not result.allowed:
                    return False

                continue

            if request_key not in request:
                return False

            actual = request[
                request_key
            ]

            if not isinstance(
                actual,
                dict,
            ):
                return False

            if not _check_constraints(
                expected,
                actual,
            ):
                return False

            continue

        if request_key not in request:
            return False

        actual = request[
            request_key
        ]

        if isinstance(
            expected,
            (int, float),
        ):
            if not isinstance(
                actual,
                (int, float),
            ):
                return False

            if key.endswith(
                "_max"
            ):
                if actual > expected:
                    return False

            elif key.endswith(
                "_min"
            ):
                if actual < expected:
                    return False

            elif actual != expected:
                return False

            continue

        if isinstance(
            expected,
            (
                list,
                tuple,
                set,
                frozenset,
            ),
        ):
            try:
                if actual not in expected:
                    return False
            except TypeError:
                return False

            continue

        if actual != expected:
            return False

    return True


def _check_tool_binding(
    capability: Capability,
    action: str,
) -> bool:
    """
    Enforce an optional cryptographically bound tool.

    Legacy capabilities with tool=None retain the existing
    namespace-based behavior.
    """
    if capability.tool is None:
        return True

    return capability.tool == action


def authorize(
    capability: Capability,
    action: str,
    request: Optional[dict] = None,
    verifier=None,
    clock=None,
) -> AuthorizationResult:

    if not isinstance(
        capability,
        Capability,
    ):
        return AuthorizationResult(
            False,
            "invalid_capability",
        )

    if (
        not isinstance(
            action,
            str,
        )
        or not action
    ):
        return AuthorizationResult(
            False,
            "invalid_action",
        )

    if request is None:
        request = {}

    if not isinstance(
        request,
        dict,
    ):
        return AuthorizationResult(
            False,
            "invalid_request",
        )

    if clock is not None:
        try:
            now = float(
                clock()
            )
        except Exception:
            return AuthorizationResult(
                False,
                "invalid_clock",
            )

        if now < capability.issued_at:
            return AuthorizationResult(
                False,
                "not_yet_valid",
            )

        if now >= capability.expires_at:
            return AuthorizationResult(
                False,
                "expired",
            )

    if verifier is not None:
        try:
            verified = verifier.verify(
                capability
            )
        except Exception:
            return AuthorizationResult(
                False,
                "verification_error",
            )

        if not verified:
            return AuthorizationResult(
                False,
                "invalid_signature",
            )

    # ========================================================
    # Tool binding
    # ========================================================

    if not _check_tool_binding(
        capability,
        action,
    ):
        return AuthorizationResult(
            False,
            "tool_binding_denied",
        )

    # ========================================================
    # Capability namespace
    # ========================================================

    if not matches(
        capability.capability,
        action,
    ):
        return AuthorizationResult(
            False,
            "namespace_denied",
        )

    # ========================================================
    # Constraints / policies
    # ========================================================

    if not _check_constraints(
        capability.constraints,
        request,
    ):
        return AuthorizationResult(
            False,
            "constraint_denied",
        )

    return AuthorizationResult(
        True,
        "authorized",
    )


def is_authorized(
    capability: Capability,
    action: str,
    request: Optional[dict] = None,
    verifier=None,
    clock=None,
) -> bool:
    return authorize(
        capability,
        action,
        request,
        verifier,
        clock,
    ).allowed