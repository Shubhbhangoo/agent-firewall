from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


class DecisionReason:
    AUTHORIZED = "authorized"

    INVALID_CAPABILITY = "invalid_capability"
    INVALID_ACTION = "invalid_action"
    INVALID_REQUEST = "invalid_request"

    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"

    VERIFICATION_ERROR = "verification_error"
    INVALID_SIGNATURE = "invalid_signature"

    TOOL_BINDING_DENIED = "tool_binding_denied"
    NAMESPACE_DENIED = "namespace_denied"
    CONSTRAINT_DENIED = "constraint_denied"

    REVOKED = "revoked"
    REVOKED_ANCESTOR = "revoked_ancestor"
    MISSING_ANCESTOR = "missing_ancestor"

    REPLAY = "replay"
    BUDGET_EXCEEDED = "budget_exceeded"

    RISK_DENIED = "risk_denied"
    REFUSED = "refused"

    PERSISTENCE_ERROR = "persistence_error"
    SECURITY_STATE_ERROR = "security_state_error"

    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class SecurityDecision:
    """
    Canonical internal representation of a security decision.

    This object deliberately contains security metadata only.
    It must not contain raw prompts, credentials, signatures,
    private keys, or unrestricted request payloads.
    """

    allowed: bool
    reason: str

    capability_id: Optional[str] = None
    agent: Optional[str] = None
    action: Optional[str] = None
    tool: Optional[str] = None

    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def allow(
        cls,
        *,
        reason: str = DecisionReason.AUTHORIZED,
        capability_id: Optional[str] = None,
        agent: Optional[str] = None,
        action: Optional[str] = None,
        tool: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "SecurityDecision":
        return cls(
            allowed=True,
            reason=reason,
            capability_id=capability_id,
            agent=agent,
            action=action,
            tool=tool,
            metadata=metadata,
        )

    @classmethod
    def deny(
        cls,
        reason: str,
        *,
        capability_id: Optional[str] = None,
        agent: Optional[str] = None,
        action: Optional[str] = None,
        tool: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "SecurityDecision":
        return cls(
            allowed=False,
            reason=reason,
            capability_id=capability_id,
            agent=agent,
            action=action,
            tool=tool,
            metadata=metadata,
        )

    def __bool__(self) -> bool:
        return self.allowed