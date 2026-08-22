from __future__ import annotations

from typing import Optional

from firewall.authorization import (
    AuthorizationResult,
    authorize,
)

from firewall.attenuation import (
    attenuate_capability,
)

from firewall.capability import (
    Capability,
    CapabilityVerifier,
    sign_capability,
)

from firewall.delegation import (
    Delegation,
    delegate_capability,
    verify_delegation,
)

from firewall.evidence import (
    Evidence,
)

from firewall.replay import (
    ReplayProtector,
    make_replay_key,
)

from firewall.transport import (
    DEFAULT_MAX_TOKEN_SIZE,
    decode_capability,
    encode_capability,
)


class FirewallSDK:
    """
    Developer-facing v0.7 API.

    Provides a single interface for:

    - issuing capabilities
    - verifying capabilities
    - attenuating capabilities
    - delegating capabilities
    - serializing/deserializing capabilities
    - encoding/decoding transport tokens
    - authorizing tool actions
    - replay protection
    """

    def __init__(
        self,
        trusted_issuers: Optional[set[str]] = None,
        clock=None,
        replay_protector: Optional[
            ReplayProtector
        ] = None,
    ):
        if trusted_issuers is None:
            trusted_issuers = {
                "trusted-issuer"
            }

        if not isinstance(
            trusted_issuers,
            (set, frozenset),
        ):
            raise TypeError(
                "trusted_issuers must be a set"
            )

        self.verifier = CapabilityVerifier(
            trusted_issuers,
            clock=clock,
        )

        self.replay = (
            replay_protector
            or ReplayProtector(
                clock=clock
            )
        )

    # ========================================================
    # Issue
    # ========================================================

    def issue(
        self,
        *,
        private_key,
        agent: str,
        capability: str,
        constraints: Optional[dict] = None,
        issuer: str = "trusted-issuer",
        expires_at: Optional[float] = None,
        issued_at: Optional[float] = None,
    ) -> Capability:
        return sign_capability(
            private_key=private_key,
            agent_id=agent,
            capability=capability,
            constraints=(
                {}
                if constraints is None
                else dict(constraints)
            ),
            issuer=issuer,
            expires_at=expires_at,
            issued_at=issued_at,
        )

    # ========================================================
    # Verify
    # ========================================================

    def verify(
        self,
        capability: Capability,
    ) -> bool:
        if not isinstance(
            capability,
            Capability,
        ):
            return False

        return self.verifier.verify(
            capability
        )

    # ========================================================
    # Attenuate
    # ========================================================

    def attenuate(
        self,
        capability: Capability,
        private_key,
        *,
        constraints: Optional[dict] = None,
        expires_at: Optional[float] = None,
    ) -> Capability:
        return attenuate_capability(
            capability,
            private_key,
            constraints=constraints,
            expires_at=expires_at,
        )

    # ========================================================
    # Delegate
    # ========================================================

    def delegate(
        self,
        capability: Capability,
        private_key,
        *,
        delegatee: str,
        constraints: Optional[dict] = None,
        expires_at: Optional[float] = None,
    ) -> Delegation:
        return delegate_capability(
            capability,
            private_key,
            delegatee,
            constraints=constraints,
            expires_at=expires_at,
        )

    # ========================================================
    # Verify delegation
    # ========================================================

    def verify_delegation(
        self,
        delegation: Delegation,
    ) -> bool:
        return verify_delegation(
            delegation,
            self.verifier,
        )

    # ========================================================
    # Authorization
    # ========================================================

    def authorize(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
    ) -> AuthorizationResult:
        return authorize(
            capability,
            action,
            request,
            verifier=self.verifier,
        )

    # ========================================================
    # Boolean authorization
    # ========================================================

    def is_authorized(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
    ) -> bool:
        return self.authorize(
            capability,
            action,
            request,
        ).allowed

    # ========================================================
    # Replay protection
    # ========================================================

    def consume_nonce(
        self,
        agent: str,
        capability: Capability,
        nonce: str,
    ) -> bool:
        key = make_replay_key(
            agent,
            capability,
            nonce,
        )

        return self.replay.check_and_consume(
            key,
            capability.expires_at,
        )

    # ========================================================
    # Dictionary serialization
    # ========================================================

    def serialize(
        self,
        capability: Capability,
    ) -> dict:
        if not isinstance(
            capability,
            Capability,
        ):
            raise TypeError(
                "capability must be a Capability"
            )

        return capability.to_dict()

    def deserialize(
        self,
        data: dict,
    ) -> Capability:
        if not isinstance(
            data,
            dict,
        ):
            raise TypeError(
                "capability data must be a dictionary"
            )

        return Capability(
            **data
        )

    # ========================================================
    # Transport encoding
    # ========================================================

    def encode(
        self,
        capability: Capability,
        *,
        max_size: int = DEFAULT_MAX_TOKEN_SIZE,
    ) -> str:
        return encode_capability(
            capability,
            max_size=max_size,
        )

    # ========================================================
    # Transport decoding
    # ========================================================

    def decode(
        self,
        token: str,
        *,
        max_size: int = DEFAULT_MAX_TOKEN_SIZE,
    ) -> Capability:
        return decode_capability(
            token,
            max_size=max_size,
        )

    # ========================================================
    # Encode + verify convenience method
    # ========================================================

    def decode_verified(
        self,
        token: str,
        *,
        max_size: int = DEFAULT_MAX_TOKEN_SIZE,
    ) -> Capability:
        capability = self.decode(
            token,
            max_size=max_size,
        )

        if not self.verify(
            capability
        ):
            raise ValueError(
                "decoded capability failed verification"
            )

        return capability

    # ========================================================
    # Evidence helper
    # ========================================================

    def evidence(
        self,
        result: AuthorizationResult,
    ) -> Optional[Evidence]:
        return getattr(
            result,
            "evidence",
            None,
        )