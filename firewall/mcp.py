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
    chain_id: Optional[str] = None


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

    Security properties:

    - malformed requests fail closed
    - invalid capabilities fail closed
    - agent identity must match the capability
    - replay protection is enforced when enabled
    - SDK authorization is the final authority
    - denied requests never reach the handler
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

        if not isinstance(
            require_nonce,
            bool,
        ):
            raise TypeError(
                "require_nonce must be a bool"
            )

        self.sdk = sdk
        self.require_nonce = require_nonce

    # ========================================================
    # Request validation
    # ========================================================

    @staticmethod
    def _validate_request(
        request: MCPRequest,
    ) -> None:
        if not isinstance(
            request,
            MCPRequest,
        ):
            raise TypeError(
                "request must be an MCPRequest"
            )

        if not isinstance(
            request.agent,
            str,
        ) or not request.agent.strip():
            raise ValueError(
                "request agent must be a non-empty string"
            )

        if not isinstance(
            request.tool,
            str,
        ) or not request.tool.strip():
            raise ValueError(
                "request tool must be a non-empty string"
            )

        if not isinstance(
            request.arguments,
            dict,
        ):
            raise TypeError(
                "request arguments must be a dictionary"
            )

        if not isinstance(
            request.capability_token,
            str,
        ) or not request.capability_token.strip():
            raise ValueError(
                "capability token must be a non-empty string"
            )

        if not isinstance(
            request.nonce,
            str,
        ):
            raise TypeError(
                "request nonce must be a string"
            )

    # ========================================================
    # Decode
    # ========================================================

    def decode_capability(
        self,
        token: str,
    ) -> Capability:
        if not isinstance(
            token,
            str,
        ):
            raise TypeError(
                "capability token must be a string"
            )

        if not token.strip():
            raise ValueError(
                "capability token cannot be empty"
            )

        capability = self.sdk.decode_verified(
            token
        )

        if not isinstance(
            capability,
            Capability,
        ):
            raise MCPError(
                "decoded capability is invalid"
            )

        return capability

    # ========================================================
    # Authorize
    # ========================================================

    def authorize(
        self,
        request: MCPRequest,
    ) -> MCPDecision:
        try:
            self._validate_request(
                request
            )
        except (
            TypeError,
            ValueError,
        ):
            if not isinstance(
                request,
                MCPRequest,
            ):
                raise

            return MCPDecision(
                allowed=False,
                tool=request.tool,
                agent=request.agent,
                reason="invalid request",
            )

        # ----------------------------------------------------
        # Decode + verify capability
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Agent binding
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Replay protection
        # ----------------------------------------------------

        if self.require_nonce:
            if not request.nonce:
                return MCPDecision(
                    allowed=False,
                    tool=request.tool,
                    agent=request.agent,
                    reason="nonce is required",
                )

            try:
                consumed = self.sdk.consume_nonce(
                    request.agent,
                    capability,
                    request.nonce,
                )
            except Exception:
                return MCPDecision(
                    allowed=False,
                    tool=request.tool,
                    agent=request.agent,
                    reason="replay protection error",
                )

            if not consumed:
                return MCPDecision(
                    allowed=False,
                    tool=request.tool,
                    agent=request.agent,
                    reason="replay detected",
                )

        # ----------------------------------------------------
        # Final authorization
        # ----------------------------------------------------

        try:
            result = self.sdk.authorize(
                capability,
                request.tool,
                request.arguments,
                chain_id=request.chain_id,
            )
        except Exception:
            return MCPDecision(
                allowed=False,
                tool=request.tool,
                agent=request.agent,
                reason="authorization error",
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
        if not callable(
            handler
        ):
            raise TypeError(
                "handler must be callable"
            )

        self.enforce(
            request
        )

        arguments = dict(
            request.arguments
        )

        return handler(
            arguments
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
        chain_id: Optional[str] = None,
    ) -> MCPRequest:
        if not isinstance(
            agent,
            str,
        ) or not agent.strip():
            raise ValueError(
                "agent must be a non-empty string"
            )

        if not isinstance(
            tool,
            str,
        ) or not tool.strip():
            raise ValueError(
                "tool must be a non-empty string"
            )

        if arguments is None:
            arguments = {}

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "arguments must be a dictionary"
            )

        if not isinstance(
            capability_token,
            str,
        ) or not capability_token.strip():
            raise ValueError(
                "capability_token must be a non-empty string"
            )

        if not isinstance(
            nonce,
            str,
        ):
            raise TypeError(
                "nonce must be a string"
            )

        return MCPRequest(
            agent=agent,
            tool=tool,
            arguments=dict(
                arguments
            ),
            capability_token=capability_token,
            nonce=nonce,
            chain_id=chain_id,
        )
