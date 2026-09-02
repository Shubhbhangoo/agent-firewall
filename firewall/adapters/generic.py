from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool, mark_untrusted


@dataclass(frozen=True)
class GenericToolCall:
    """
    Vendor-neutral representation of a tool call.
    """

    name: str
    arguments: dict[str, Any]


class GenericToolAdapter:
    """
    Vendor-neutral tool adapter.

    Any agent framework can translate its tool-call format
    into GenericToolCall and use this adapter.

    Authorization remains inside FirewallSDK.
    """

    def __init__(
        self,
        *,
        sdk: FirewallSDK,
        capability: Capability,
        handler: Callable[..., Any],
        name: Optional[str] = None,
        action: Optional[str] = None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
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

        if name is None:
            name = getattr(
                handler,
                "__name__",
                None,
            )

        if not isinstance(
            name,
            str,
        ):
            raise TypeError(
                "name must be a string"
            )

        name = name.strip()

        if not name:
            raise ValueError(
                "name cannot be empty"
            )

        if (
            action is not None
            and not isinstance(
                action,
                str,
            )
        ):
            raise TypeError(
                "action must be a string"
            )

        if (
            action is not None
            and not action.strip()
        ):
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
        self.name = name
        self.action = action
        self.request_builder = (
            request_builder
        )
        self.chain_id = chain_id

        self.tool = ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler=handler,
            action=action,
            chain_id=chain_id,
        )

    def build_request(
        self,
        call: GenericToolCall,
    ) -> dict[str, Any]:
        if not isinstance(
            call,
            GenericToolCall,
        ):
            raise TypeError(
                "call must be a GenericToolCall"
            )

        if (
            call.name
            != self.name
        ):
            raise ValueError(
                "tool call name does not match adapter"
            )

        if self.request_builder is not None:
            request = self.request_builder(
                call.arguments
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
            "tool": call.name,
            "arguments": dict(
                call.arguments
            ),
        }

    def authorize(
        self,
        call: GenericToolCall,
        *,
        chain_id: Optional[str] = None,
    ):
        request = self.build_request(
            call
        )

        action = (
            self.action
            or self.capability.capability
        )

        return self.sdk.authorize(
            self.capability,
            action,
            request,
            chain_id=(
                chain_id
                if chain_id is not None
                else self.chain_id
            ),
        )

    def execute(
        self,
        call: GenericToolCall,
    ):
        result = self.authorize(
            call
        )

        if not result.allowed:
            raise PermissionError(
                result.reason
            )

        output = self.tool.handler(
            **call.arguments
        )

        # Marked for the same reason ``ProtectedTool.__call__`` marks:
        # what a tool returns is data the tool chose, so it must not be
        # able to pass for a decision or a capability further up. An
        # adapter that authorized correctly and then returned a bare
        # string would give the same handler a weaker guarantee than
        # ``protect_tool`` gives it.
        return mark_untrusted(
            output,
            tool=(
                self.action
                or self.capability.capability
            ),
        )

    def __call__(
        self,
        call: GenericToolCall,
    ):
        return self.execute(
            call
        )


def generic_tool(
    *,
    sdk: FirewallSDK,
    capability: Capability,
    handler: Callable[..., Any],
    name: Optional[str] = None,
    action: Optional[str] = None,
    request_builder: Optional[
        Callable[[dict[str, Any]], dict[str, Any]]
    ] = None,
    chain_id: Optional[str] = None,
) -> GenericToolAdapter:
    """
    Create a vendor-neutral protected tool adapter.
    """

    return GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=handler,
        name=name,
        action=action,
        request_builder=request_builder,
        chain_id=chain_id,
    )
