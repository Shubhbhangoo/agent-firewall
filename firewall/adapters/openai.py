from __future__ import annotations

from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool


class OpenAITool:
    """
    Thin OpenAI-style tool adapter.

    Accepted execution forms:

        tool.execute({
            "amount": 20,
        })

    or:

        tool.execute({
            "name": "payment",
            "arguments": {
                "amount": 20,
            },
        })

    Authorization remains inside FirewallSDK.
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
        self.parameters = dict(
            parameters
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
    # Tool definition
    # ========================================================

    def definition(self) -> dict:
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
    # Normalize OpenAI input
    # ========================================================

    def normalize(
        self,
        arguments: Optional[dict] = None,
    ) -> dict:

        if arguments is None:
            return {}

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "arguments must be a dictionary"
            )

        # Full OpenAI-style tool-call object.
        if (
            "name" in arguments
            or "arguments" in arguments
        ):
            call_name = arguments.get(
                "name"
            )

            if call_name is not None:

                if not isinstance(
                    call_name,
                    str,
                ):
                    raise TypeError(
                        "tool call name must be a string"
                    )

                if call_name != self.name:
                    raise ValueError(
                        "tool call name does not match adapter"
                    )

            payload = arguments.get(
                "arguments",
                {},
            )

            if not isinstance(
                payload,
                dict,
            ):
                raise TypeError(
                    "tool call arguments must be a dictionary"
                )

            return dict(payload)

        # Raw function arguments.
        return dict(arguments)

    # ========================================================
    # Build authorization request
    # ========================================================

    def _build_request(
        self,
        arguments: dict,
    ) -> dict:

        if self.request_builder is not None:
            request = self.request_builder(
                **arguments
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
            "args": (),
            "kwargs": dict(
                arguments
            ),
        }

    # ========================================================
    # Authorize
    # ========================================================

    def authorize(
        self,
        arguments: Optional[dict] = None,
        *,
        chain_id: Optional[str] = None,
    ):
        normalized = self.normalize(
            arguments
        )

        request = self._build_request(
            normalized
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

    # ========================================================
    # Execute
    # ========================================================

    def execute(
        self,
        arguments: Optional[dict] = None,
    ):
        normalized = self.normalize(
            arguments
        )

        result = self.authorize(
            normalized
        )

        if not result.allowed:
            raise PermissionError(
                result.reason
            )

        return self.tool.handler(
            **normalized
        )

    # ========================================================
    # Call
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
    chain_id: Optional[str] = None,
) -> OpenAITool:
    return OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=handler,
        name=name,
        description=description,
        parameters=parameters,
        action=action,
        request_builder=request_builder,
        chain_id=chain_id,
    )
