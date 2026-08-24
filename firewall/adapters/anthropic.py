from __future__ import annotations

from typing import Any, Callable, Optional

from firewall.adapters.generic import (
    GenericToolCall,
)
from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool


class AnthropicTool:
    """
    Thin Anthropic-style tool adapter.

    Expected tool-call shape:

    {
        "id": "toolu_123",
        "name": "send_payment",
        "input": {
            "amount": 50
        }
    }

    Authorization is delegated to FirewallSDK.
    """

    def __init__(
        self,
        *,
        sdk: FirewallSDK,
        capability: Capability,
        handler: Callable[..., Any],
        name: Optional[str] = None,
        description: Optional[str] = None,
        input_schema: Optional[dict] = None,
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

        if description is None:
            description = (
                getattr(
                    handler,
                    "__doc__",
                    None,
                )
                or ""
            )

        if not isinstance(
            description,
            str,
        ):
            raise TypeError(
                "description must be a string"
            )

        if input_schema is None:
            input_schema = {
                "type": "object",
                "properties": {},
            }

        if not isinstance(
            input_schema,
            dict,
        ):
            raise TypeError(
                "input_schema must be a dictionary"
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
        self.description = description
        self.input_schema = dict(
            input_schema
        )
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

    # ========================================================
    # Anthropic tool definition
    # ========================================================

    def definition(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(
                self.input_schema
            ),
        }

    # ========================================================
    # Normalize
    # ========================================================

    def normalize(
        self,
        call: dict,
    ) -> GenericToolCall:
        if not isinstance(
            call,
            dict,
        ):
            raise TypeError(
                "call must be a dictionary"
            )

        name = call.get(
            "name"
        )

        if name != self.name:
            raise ValueError(
                "tool call name does not match adapter"
            )

        arguments = call.get(
            "input",
            {},
        )

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "tool call input must be a dictionary"
            )

        return GenericToolCall(
            name=name,
            arguments=dict(
                arguments
            ),
        )

    # ========================================================
    # Authorization
    # ========================================================

    def authorize(
        self,
        call: dict,
        *,
        chain_id: Optional[str] = None,
    ):
        normalized = self.normalize(
            call
        )

        arguments = normalized.arguments

        if self.request_builder is not None:
            request = self.request_builder(
                arguments
            )

            if not isinstance(
                request,
                dict,
            ):
                raise TypeError(
                    "request_builder must return a dictionary"
                )
        else:
            request = {
                "tool": normalized.name,
                "input": dict(
                    arguments
                ),
            }

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

    # ========================================================
    # Execute
    # ========================================================

    def execute(
        self,
        call: dict,
    ):
        normalized = self.normalize(
            call
        )

        result = self.authorize(
            call
        )

        if not result.allowed:
            raise PermissionError(
                result.reason
            )

        return self.tool.handler(
            **normalized.arguments
        )

    def __call__(
        self,
        call: dict,
    ):
        return self.execute(
            call
        )


def anthropic_tool(
    *,
    sdk: FirewallSDK,
    capability: Capability,
    handler: Callable[..., Any],
    name: Optional[str] = None,
    description: Optional[str] = None,
    input_schema: Optional[dict] = None,
    action: Optional[str] = None,
    request_builder: Optional[
        Callable[[dict[str, Any]], dict[str, Any]]
    ] = None,
    chain_id: Optional[str] = None,
) -> AnthropicTool:
    return AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=handler,
        name=name,
        description=description,
        input_schema=input_schema,
        action=action,
        request_builder=request_builder,
        chain_id=chain_id,
    )
