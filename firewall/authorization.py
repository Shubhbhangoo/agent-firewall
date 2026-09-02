from __future__ import annotations

import math
from typing import Optional

from firewall.capability import (
    Capability,
    capability_fingerprint,
)
from firewall.namespace import matches
from firewall.policy import (
    PolicyDefinitionError,
    evaluate_policy,
)
from firewall.security_decision import SecurityDecision


class AuthorizationResult:
    def __init__(
        self,
        allowed: bool,
        reason: str,
        trace: Optional[dict] = None,
    ):
        self.allowed = allowed
        self.reason = reason
        self.trace = trace

    def __bool__(self):
        return self.allowed

    @property
    def decision(self) -> SecurityDecision:
        trace = self.trace or {}

        return SecurityDecision(
            allowed=self.allowed,
            reason=self.reason,
            capability_id=trace.get("capability_id"),
            agent=trace.get("agent"),
            action=trace.get("action"),
            tool=trace.get("tool"),
        )

    def __repr__(self):
        return (
            f"AuthorizationResult("
            f"allowed={self.allowed!r}, "
            f"reason={self.reason!r})"
        )


def _authorization_trace(
    capability: Capability,
    action: str,
    reason: str,
) -> dict:
    """
    Build a deliberately minimal authorization trace.

    The trace identifies the authority involved in the decision
    without exposing cryptographic material, raw request data,
    constraints, or signed payload contents.
    """

    trace = {
        "capability_id": capability_fingerprint(
            capability
        ),
        "agent": capability.agent_id,
        "action": action,
        "reason": reason,
    }

    if capability.tool is not None:
        trace["tool"] = capability.tool

    return trace


def _result(
    capability: Capability,
    action: str,
    allowed: bool,
    reason: str,
) -> AuthorizationResult:
    return AuthorizationResult(
        allowed=allowed,
        reason=reason,
        trace=_authorization_trace(
            capability,
            action,
            reason,
        ),
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

            # A ceiling here is enforced by its negation: the request is
            # admitted unless ``actual > expected``. NaN compares False
            # against every bound, so ``nan > 100`` is False and a NaN
            # request value would satisfy every ``_max`` ceiling -- and
            # ``nan < 10`` is False too, so it would satisfy every
            # ``_min`` floor. A value that cannot be ordered cannot be
            # shown to be within the bound, and unknown is not trusted.
            #
            # ``json.loads`` accepts the bare tokens ``NaN``,
            # ``Infinity`` and ``-Infinity`` by default, so this reaches
            # the gate from any JSON request body or tool output without
            # the caller doing anything unusual.
            if not math.isfinite(actual):
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
            return _result(
                capability,
                action,
                False,
                "invalid_clock",
            )

        if now < capability.issued_at:
            return _result(
                capability,
                action,
                False,
                "not_yet_valid",
            )

        if now >= capability.expires_at:
            return _result(
                capability,
                action,
                False,
                "expired",
            )

    if verifier is not None:
        try:
            verified = verifier.verify(
                capability
            )
        except Exception:
            return _result(
                capability,
                action,
                False,
                "verification_error",
            )

        if not verified:
            return _result(
                capability,
                action,
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
        return _result(
            capability,
            action,
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
        return _result(
            capability,
            action,
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
        return _result(
            capability,
            action,
            False,
            "constraint_denied",
        )

    return _result(
        capability,
        action,
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