from __future__ import annotations

from functools import wraps
from typing import Callable, Any

from firewall.capability import Capability
from firewall.sdk import FirewallSDK


def protect(
    *,
    sdk: FirewallSDK,
    capability: Capability,
):
    """
    Protect a callable with an already-issued capability.

    Authorization is performed by the existing FirewallSDK.
    This wrapper does not create, sign, delegate, or modify
    capabilities.
    """

    if not isinstance(sdk, FirewallSDK):
        raise TypeError(
            "sdk must be a FirewallSDK"
        )

    if not isinstance(
        capability,
        Capability,
    ):
        raise TypeError(
            "capability must be a Capability"
        )

    def decorator(
        func: Callable[..., Any],
    ):
        if not callable(func):
            raise TypeError(
                "protected object must be callable"
            )

        @wraps(func)
        def wrapper(
            *args,
            **kwargs,
        ):
            request = {
                "args": args,
                "kwargs": kwargs,
            }

            result = sdk.authorize(
                capability,
                capability.capability,
                request,
            )

            if not result.allowed:
                raise PermissionError(
                    result.reason
                )

            return func(
                *args,
                **kwargs,
            )

        return wrapper

    return decorator