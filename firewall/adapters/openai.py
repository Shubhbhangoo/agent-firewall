from __future__ import annotations

from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool


class OpenAITool:
    """
    Thin OpenAI-style tool adapter.

    Converts a Python callable protected by Agent Firewall
    into an OpenAI-style tool definition plus an execution
    wrapper.

    Authorization remains entirely inside FirewallSDK.
    """

    def __init__(
        self,
        *,
        sdk: FirewallSDK,
        capability: Capability,
        handler: Callable[..., Any],
        name: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[dict] = None,
        action: Optional[str] = None,
        request_builder: Optional[
            Callable[..., dict]
        ] = None,
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

        if parameters is None:
            parameters = {
                "type": "object",
                "properties": {},
            }

        if not isinstance(
            parameters,
            dict,
        ):
            raise TypeError(
                "parameters must be a dictionary"
            )

        self.sdk = sdk
        self.capability = capability
        self.name = name
        self.description = description
        self.parameters = dict(
            parameters
        )

        self.tool = ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler=handler,
            action=action,
            request_builder=request_builder,
        )

    # ========================================================
    # OpenAI tool definition
    # ========================================================

    def definition(self) -> dict:
        """
        Return an OpenAI-style function tool schema.
        """

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": dict(
                    self.parameters
                ),
            },
        }

    # ========================================================
    # Authorization
    # ========================================================

    def authorize(
        self,
        arguments: Optional[dict] = None,
    ):
        if arguments is None:
            arguments = {}

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "arguments must be a dictionary"
            )

        return self.sdk.authorize(
            self.capability,
            (
                self.tool.action
                if self.tool.action
                else self.capability.capability
            ),
            arguments,
        )

    # ========================================================
    # Execute
    # ========================================================

    def execute(
        self,
        arguments: Optional[dict] = None,
    ):
        if arguments is None:
            arguments = {}

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "arguments must be a dictionary"
            )

        return self.tool(
            **arguments
        )

    # ========================================================
    # Combined call
    # ========================================================

    def __call__(
        self,
        arguments: Optional[dict] = None,
    ):
        return self.execute(
            arguments
        )


def openai_tool(
    *,
    sdk: FirewallSDK,
    capability: Capability,
    handler: Callable[..., Any],
    name: Optional[str] = None,
    description: Optional[str] = None,
    parameters: Optional[dict] = None,
    action: Optional[str] = None,
    request_builder: Optional[
        Callable[..., dict]
    ] = None,
) -> OpenAITool:
    """
    Create an OpenAI-style protected tool.
    """

    return OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=handler,
        name=name,
        description=description,
        parameters=parameters,
        action=action,
        request_builder=request_builder,
    )