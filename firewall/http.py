from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from firewall.sdk import FirewallSDK


class HTTPFirewallError(Exception):
    """Base HTTP firewall error."""


class HTTPAuthorizationError(HTTPFirewallError):
    """Raised when an HTTP request is denied."""


@dataclass(frozen=True)
class HTTPRequest:
    agent: str
    method: str
    path: str
    arguments: dict[str, Any]
    capability_token: str
    nonce: str
    chain_id: Optional[str] = None


@dataclass(frozen=True)
class HTTPDecision:
    allowed: bool
    agent: str
    method: str
    path: str
    status_code: int
    reason: str = ""


class HTTPFirewall:
    """
    HTTP authorization boundary for Agent Firewall.

    Converts HTTP requests into the existing firewall
    namespace model, verifies the capability, checks
    agent binding, enforces constraints, and protects
    against replay.
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
    # Request construction
    # ========================================================

    @staticmethod
    def request(
        *,
        agent: str,
        method: str,
        path: str,
        arguments: Optional[
            dict[str, Any]
        ] = None,
        capability_token: str,
        nonce: str,
        chain_id: Optional[str] = None,
    ) -> HTTPRequest:

        if arguments is None:
            arguments = {}

        if not isinstance(
            arguments,
            dict,
        ):
            raise TypeError(
                "arguments must be a dictionary"
            )

        return HTTPRequest(
            agent=agent,
            method=method,
            path=path,
            arguments=dict(arguments),
            capability_token=capability_token,
            nonce=nonce,
            chain_id=chain_id,
        )

    # ========================================================
    # HTTP -> firewall namespace
    # ========================================================

    @staticmethod
    def action_for(
        method: str,
        path: str,
    ) -> str:

        if not isinstance(
            method,
            str,
        ):
            raise TypeError(
                "method must be a string"
            )

        if not isinstance(
            path,
            str,
        ):
            raise TypeError(
                "path must be a string"
            )

        method = method.strip().upper()
        path = path.strip()

        if not method:
            raise ValueError(
                "method cannot be empty"
            )

        if not path:
            raise ValueError(
                "path cannot be empty"
            )

        if not path.startswith("/"):
            raise ValueError(
                "path must start with '/'"
            )

        # Root endpoint.
        if path == "/":
            return f"http.{method}.root"

        parts = path.split("/")[1:]

        if not parts:
            raise ValueError(
                "path cannot be empty"
            )

        for part in parts:
            if not part:
                raise ValueError(
                    "path contains empty segment"
                )

            if not re.fullmatch(
                r"[a-zA-Z0-9_-]+",
                part,
            ):
                raise ValueError(
                    "path contains invalid "
                    "namespace segment"
                )

        return ".".join(
            [
                "http",
                method,
                *parts,
            ]
        )

    # ========================================================
    # Capability decoding
    # ========================================================

    def decode_capability(
        self,
        token: str,
    ):
        return self.sdk.decode_verified(
            token
        )

    # ========================================================
    # Authorization
    # ========================================================

    def authorize(
        self,
        request: HTTPRequest,
    ) -> HTTPDecision:

        if not isinstance(
            request,
            HTTPRequest,
        ):
            raise TypeError(
                "request must be an HTTPRequest"
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
            return HTTPDecision(
                allowed=False,
                agent=request.agent,
                method=request.method,
                path=request.path,
                status_code=401,
                reason=(
                    "invalid capability: "
                    f"{exc}"
                ),
            )

        # ----------------------------------------------------
        # Agent binding
        # ----------------------------------------------------

        if (
            capability.agent_id
            != request.agent
        ):
            return HTTPDecision(
                allowed=False,
                agent=request.agent,
                method=request.method,
                path=request.path,
                status_code=403,
                reason=(
                    "capability agent does not "
                    "match request agent"
                ),
            )

        # ----------------------------------------------------
        # Build action before consuming nonce
        # ----------------------------------------------------

        try:
            action = self.action_for(
                request.method,
                request.path,
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            return HTTPDecision(
                allowed=False,
                agent=request.agent,
                method=request.method,
                path=request.path,
                status_code=400,
                reason=str(exc),
            )

        # ----------------------------------------------------
        # Authorization
        # ----------------------------------------------------

        result = self.sdk.authorize(
            capability,
            action,
            request.arguments,
            refusal_scope="request",
            chain_id=request.chain_id,
        )

        if not result.allowed:
            reason = getattr(
                result,
                "reason",
                "authorization denied",
            )

            status_code = 403

            if reason in {
                "expired",
                "not_yet_valid",
                "invalid_signature",
                "verification_error",
            }:
                status_code = 401

            return HTTPDecision(
                allowed=False,
                agent=request.agent,
                method=request.method,
                path=request.path,
                status_code=status_code,
                reason=reason,
            )

        # ----------------------------------------------------
        # Replay protection
        #
        # Consume nonce only AFTER authorization succeeds.
        # This prevents denied requests from burning a nonce.
        # ----------------------------------------------------

        if self.require_nonce:

            if not request.nonce:
                return HTTPDecision(
                    allowed=False,
                    agent=request.agent,
                    method=request.method,
                    path=request.path,
                    status_code=400,
                    reason="nonce is required",
                )

            consumed = self.sdk.consume_nonce(
                request.agent,
                capability,
                request.nonce,
            )

            if not consumed:
                return HTTPDecision(
                    allowed=False,
                    agent=request.agent,
                    method=request.method,
                    path=request.path,
                    status_code=409,
                    reason="replay detected",
                )

        return HTTPDecision(
            allowed=True,
            agent=request.agent,
            method=request.method,
            path=request.path,
            status_code=200,
            reason=getattr(
                result,
                "reason",
                "authorized",
            ),
        )

    # ========================================================
    # Enforcement
    # ========================================================

    def enforce(
        self,
        request: HTTPRequest,
    ) -> HTTPDecision:

        decision = self.authorize(
            request
        )

        if not decision.allowed:
            raise HTTPAuthorizationError(
                decision.reason
            )

        return decision

    # ========================================================
    # Execution
    # ========================================================

    def execute(
        self,
        request: HTTPRequest,
        handler: Callable[
            [HTTPRequest],
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
            request
        )

    # ========================================================
    # Ordinary HTTP request conversion
    # ========================================================

    def from_http(
        self,
        *,
        agent: str,
        method: str,
        path: str,
        arguments: Optional[
            dict[str, Any]
        ],
        headers: Mapping[str, str],
        nonce_header: str = (
            "X-Agent-Nonce"
        ),
        chain_header: str = (
            "X-Agent-Chain"
        ),
        capability_header: str = (
            "Authorization"
        ),
    ) -> HTTPRequest:

        if not isinstance(
            headers,
            Mapping,
        ):
            raise TypeError(
                "headers must be a mapping"
            )

        capability_token = headers.get(
            capability_header
        )

        if capability_token is None:
            raise HTTPFirewallError(
                "missing capability header"
            )

        if not isinstance(
            capability_token,
            str,
        ):
            raise HTTPFirewallError(
                "capability header must be a string"
            )

        if capability_token.startswith(
            "Bearer "
        ):
            capability_token = (
                capability_token[7:]
            )

        nonce = headers.get(
            nonce_header,
            "",
        )

        if not isinstance(
            nonce,
            str,
        ):
            raise HTTPFirewallError(
                "nonce header must be a string"
            )

        chain_id = headers.get(
            chain_header
        )

        if (
            chain_id is not None
            and not isinstance(
                chain_id,
                str,
            )
        ):
            raise HTTPFirewallError(
                "chain header must be a string"
            )

        return self.request(
            agent=agent,
            method=method,
            path=path,
            arguments=arguments,
            capability_token=capability_token,
            nonce=nonce,
            chain_id=chain_id,
        )
