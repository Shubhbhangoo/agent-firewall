from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK


class MCPError(Exception):
    """Base exception for MCP firewall errors."""


class MCPAuthorizationError(MCPError):
    """Raised when an MCP tool call is not authorized."""


@dataclass(frozen=True)
class MCPRequest:
    agent: str
    tool: str
    arguments: dict[str, Any]
    capability_token: str
    nonce: str


@dataclass(frozen=True)
class MCPDecision:
    allowed: bool
    tool: str
    agent: str
    reason: str = ""


class MCPFirewall:
    """
    Lightweight MCP security adapter.

    The adapter deliberately does not implement an MCP transport.
    It sits at the authorization boundary immediately before an MCP
    tool is executed.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        require_nonce: bool = True,
    ):
        if not isinstance(
            sdk,
            FirewallSDK,
        ):
            raise TypeError(
                "sdk must be a FirewallSDK"
            )

        self.sdk = sdk
        self.require_nonce = require_nonce

    # ========================================================
    # Decode
    # ========================================================

    def decode_capability(
        self,
        token: str,
    ) -> Capability:
        return self.sdk.decode_verified(
            token
        )

    # ========================================================
    # Authorize
    # ========================================================

    def authorize(
        self,
        request: MCPRequest,
    ) -> MCPDecision:
        if not isinstance(
            request,
            MCPRequest,
        ):
            raise TypeError(
                "request must be an MCPRequest"
            )

        try:
            capability = (
                self.decode_capability(
                    request.capability_token
                )
            )
        except Exception as exc:
            return MCPDecision(
                allowed=False,
                tool=request.tool,
                agent=request.agent,
                reason=(
                    "invalid capability: "
                    f"{exc}"
                ),
            )

        if capability.agent_id != request.agent:
            return MCPDecision(
                allowed=False,
                tool=request.tool,
                agent=request.agent,
                reason=(
                    "capability agent does not "
                    "match request agent"
                ),
            )

        if self.require_nonce:
            if not request.nonce:
                return MCPDecision(
                    allowed=False,
                    tool=request.tool,
                    agent=request.agent,
                    reason="nonce is required",
                )

            consumed = self.sdk.consume_nonce(
                request.agent,
                capability,
                request.nonce,
            )

            if not consumed:
                return MCPDecision(
                    allowed=False,
                    tool=request.tool,
                    agent=request.agent,
                    reason="replay detected",
                )

        result = self.sdk.authorize(
            capability,
            request.tool,
            request.arguments,
        )

        if not result.allowed:
            return MCPDecision(
                allowed=False,
                tool=request.tool,
                agent=request.agent,
                reason=getattr(
                    result,
                    "reason",
                    "authorization denied",
                ),
            )

        return MCPDecision(
            allowed=True,
            tool=request.tool,
            agent=request.agent,
            reason=getattr(
                result,
                "reason",
                "authorized",
            ),
        )

    # ========================================================
    # Enforce
    # ========================================================

    def enforce(
        self,
        request: MCPRequest,
    ) -> MCPDecision:
        decision = self.authorize(
            request
        )

        if not decision.allowed:
            raise MCPAuthorizationError(
                decision.reason
            )

        return decision

    # ========================================================
    # Execute
    # ========================================================

    def execute(
        self,
        request: MCPRequest,
        handler: Callable[
            [dict[str, Any]],
            Any,
        ],
    ) -> Any:
        if not callable(handler):
            raise TypeError(
                "handler must be callable"
            )

        self.enforce(
            request
        )

        return handler(
            request.arguments
        )

    # ========================================================
    # Convenience request builder
    # ========================================================

    @staticmethod
    def request(
        *,
        agent: str,
        tool: str,
        arguments: Optional[
            dict[str, Any]
        ] = None,
        capability_token: str,
        nonce: str,
    ) -> MCPRequest:
        if arguments is None:
            arguments = {}

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "arguments must be a dictionary"
            )

        return MCPRequest(
            agent=agent,
            tool=tool,
            arguments=dict(arguments),
            capability_token=capability_token,
            nonce=nonce,
        )