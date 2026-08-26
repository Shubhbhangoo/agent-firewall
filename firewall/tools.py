from __future__ import annotations

from functools import update_wrapper
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK


class UntrustedString(str):
    """
    String returned by a tool.

    This is explicitly marked as untrusted data. It carries no
    authorization semantics and cannot grant, widen, revoke, or
    modify a capability.

    It remains a normal str subclass for backwards compatibility.
    """

    def __new__(
        cls,
        value: str,
        *,
        tool: Optional[str] = None,
    ):
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "UntrustedString value must be a string"
            )

        instance = super().__new__(
            cls,
            value,
        )

        instance.tool = tool

        return instance


def mark_untrusted(
    value: Any,
    *,
    tool: Optional[str] = None,
) -> Any:
    """
    Mark tool output as untrusted data.

    Container types are preserved. String leaves become
    UntrustedString instances while remaining normal strings
    for compatibility.

    No parsing, instruction detection, or sanitization is performed.
    """

    if isinstance(
        value,
        UntrustedString,
    ):
        return value

    if isinstance(
        value,
        str,
    ):
        return UntrustedString(
            value,
            tool=tool,
        )

    if isinstance(
        value,
        dict,
    ):
        return {
            key: mark_untrusted(
                item,
                tool=tool,
            )
            for key, item in value.items()
        }

    if isinstance(
        value,
        list,
    ):
        return [
            mark_untrusted(
                item,
                tool=tool,
            )
            for item in value
        ]

    if isinstance(
        value,
        tuple,
    ):
        return tuple(
            mark_untrusted(
                item,
                tool=tool,
            )
            for item in value
        )

    if isinstance(
        value,
        set,
    ):
        return {
            mark_untrusted(
                item,
                tool=tool,
            )
            for item in value
        }

    return value


def unwrap_untrusted(
    value: Any,
) -> Any:
    """
    Explicitly remove the trust marker.

    This only converts the representation back to ordinary data.
    It does not grant or modify authority.
    """

    if isinstance(
        value,
        UntrustedString,
    ):
        return str(value)

    if isinstance(
        value,
        dict,
    ):
        return {
            key: unwrap_untrusted(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        list,
    ):
        return [
            unwrap_untrusted(item)
            for item in value
        ]

    if isinstance(
        value,
        tuple,
    ):
        return tuple(
            unwrap_untrusted(item)
            for item in value
        )

    if isinstance(
        value,
        set,
    ):
        return {
            unwrap_untrusted(item)
            for item in value
        }

    return value


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
       ↓
    untrusted output
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
            action = (
                capability.tool
                if capability.tool is not None
                else capability.capability
            )

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
            and not callable(
                request_builder
            )
        ):
            raise TypeError(
                "request_builder must be callable"
            )

        if (
            capability.tool is not None
            and capability.tool != action
        ):
            raise ValueError(
                "capability tool binding does not "
                "match protected action"
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

        output = self.handler(
            *args,
            **kwargs,
        )

        return mark_untrusted(
            output,
            tool=self.action,
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