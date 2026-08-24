from __future__ import annotations

from functools import update_wrapper
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK


class ProtectedTool:
    """
    Callable wrapper that authorizes execution through FirewallSDK.

    Security flow:

        call
          ↓
        authorize
          ↓
        allowed?
        /     \
      yes     no
       ↓       ↓
    handler  PermissionError
    """

    def __init__(
        self,
        *,
        sdk: FirewallSDK,
        capability: Capability,
        handler: Callable[..., Any],
        action: Optional[str] = None,
        request_builder: Optional[
            Callable[..., dict]
        ] = None,
        chain_id: Optional[str] = None,
    ):
        if not isinstance(
            sdk,
            FirewallSDK,
        ):
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

        if not callable(handler):
            raise TypeError(
                "handler must be callable"
            )

        if action is None:
            action = capability.capability

        if not isinstance(
            action,
            str,
        ):
            raise TypeError(
                "action must be a string"
            )

        if not action.strip():
            raise ValueError(
                "action cannot be empty"
            )

        if (
            request_builder is not None
            and not callable(request_builder)
        ):
            raise TypeError(
                "request_builder must be callable"
            )

        self.sdk = sdk
        self.capability = capability
        self.handler = handler
        self.action = action
        self.request_builder = request_builder
        self.chain_id = chain_id

        update_wrapper(
            self,
            handler,
        )

    def _build_request(
        self,
        *args,
        **kwargs,
    ) -> dict:
        if self.request_builder is not None:
            request = self.request_builder(
                *args,
                **kwargs,
            )

            if not isinstance(
                request,
                dict,
            ):
                raise TypeError(
                    "request_builder must return a dictionary"
                )

            return request

        return {
            "args": args,
            "kwargs": kwargs,
        }

    def authorize(
        self,
        *args,
        chain_id: Optional[str] = None,
        **kwargs,
    ):
        request = self._build_request(
            *args,
            **kwargs,
        )

        return self.sdk.authorize(
            self.capability,
            self.action,
            request,
            chain_id=(
                chain_id
                if chain_id is not None
                else self.chain_id
            ),
        )

    def __call__(
        self,
        *args,
        **kwargs,
    ):
        result = self.authorize(
            *args,
            **kwargs,
        )

        if not result.allowed:
            raise PermissionError(
                result.reason
            )

        return self.handler(
            *args,
            **kwargs,
        )


def protect_tool(
    *,
    sdk: FirewallSDK,
    capability: Capability,
    handler: Callable[..., Any],
    action: Optional[str] = None,
    request_builder: Optional[
        Callable[..., dict]
    ] = None,
    chain_id: Optional[str] = None,
) -> ProtectedTool:
    """
    Create a ProtectedTool wrapper.
    """

    return ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=handler,
        action=action,
        request_builder=request_builder,
        chain_id=chain_id,
    )
