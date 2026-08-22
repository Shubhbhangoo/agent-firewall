from __future__ import annotations

from pathlib import Path
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
    capability_fingerprint,
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

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.replay import (
    ReplayProtector,
    make_replay_key,
)

from firewall.revocation import (
    RevocationRegistry,
    RevokedCapabilityError,
)

from firewall.revocation_store import (
    SQLiteRevocationStore,
)

from firewall.transport import (
    DEFAULT_MAX_TOKEN_SIZE,
    decode_capability,
    encode_capability,
)


class FirewallSDK:
    """
    Developer-facing v0.8 API.

    Provides:

    - capability issuance
    - capability verification
    - attenuation
    - delegation
    - serialization
    - transport encoding/decoding
    - authorization
    - replay protection
    - capability revocation
    - optional persistent revocation storage
    - lifecycle event recording
    """

    def __init__(
        self,
        trusted_issuers: Optional[set[str]] = None,
        clock=None,
        replay_protector: Optional[
            ReplayProtector
        ] = None,
        revocation_registry: Optional[
            RevocationRegistry
        ] = None,
        revocation_store_path: Optional[
            str | Path
        ] = None,
        lifecycle_recorder: Optional[
            LifecycleRecorder
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

        if (
            revocation_registry is not None
            and revocation_store_path is not None
        ):
            raise ValueError(
                "provide either revocation_registry "
                "or revocation_store_path, not both"
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

        self.lifecycle = (
            lifecycle_recorder
            or LifecycleRecorder(
                clock=clock
            )
        )

        self._revocation_store = None

        if revocation_registry is not None:
            self.revocation = (
                revocation_registry
            )

        elif revocation_store_path is not None:
            self._revocation_store = (
                SQLiteRevocationStore(
                    revocation_store_path,
                    clock=clock,
                )
            )

            self.revocation = (
                RevocationRegistry(
                    clock=clock,
                    backend=self._revocation_store,
                    lifecycle_recorder=self.lifecycle,
                )
            )

        else:
            self.revocation = (
                RevocationRegistry(
                    clock=clock,
                    lifecycle_recorder=self.lifecycle,
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

        result = sign_capability(
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

        self.lifecycle.record(
            LifecycleEventType.ISSUED,
            capability_fingerprint(
                result
            ),
            agent_id=result.agent_id,
            capability=result.capability,
            issuer=result.issuer,
            details={
                "issued_at": result.issued_at,
                "expires_at": result.expires_at,
            },
        )

        return result

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

        if self.is_revoked(
            capability
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

        result = attenuate_capability(
            capability,
            private_key,
            constraints=constraints,
            expires_at=expires_at,
        )

        self.lifecycle.record(
            LifecycleEventType.ATTENUATED,
            capability_fingerprint(
                result
            ),
            agent_id=result.agent_id,
            capability=result.capability,
            issuer=result.issuer,
            details={
                "parent_fingerprint": (
                    capability_fingerprint(
                        capability
                    )
                ),
                "constraints": dict(
                    result.constraints
                ),
                "expires_at": result.expires_at,
            },
        )

        return result

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

        delegation = delegate_capability(
            capability,
            private_key,
            delegatee,
            constraints=constraints,
            expires_at=expires_at,
        )

        self.lifecycle.record(
            LifecycleEventType.DELEGATED,
            capability_fingerprint(
                capability
            ),
            agent_id=capability.agent_id,
            capability=capability.capability,
            issuer=capability.issuer,
            details={
                "delegatee": delegatee,
                "delegation": True,
                "child_fingerprint": (
                    capability_fingerprint(
                        delegation.child
                    )
                ),
            },
        )

        return delegation

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
    # Revocation
    # ========================================================

    def fingerprint(
        self,
        capability: Capability,
    ) -> str:
        if not isinstance(
            capability,
            Capability,
        ):
            raise TypeError(
                "capability must be a Capability"
            )

        return capability_fingerprint(
            capability
        )

    def revoke(
        self,
        capability: Capability,
        *,
        reason: str = "",
    ):
        fingerprint = self.fingerprint(
            capability
        )

        return self.revocation.revoke(
            fingerprint,
            reason=reason,
        )

    def is_revoked(
        self,
        capability: Capability,
    ) -> bool:
        fingerprint = self.fingerprint(
            capability
        )

        return self.revocation.is_revoked(
            fingerprint
        )

    def require_active(
        self,
        capability: Capability,
    ) -> None:
        fingerprint = self.fingerprint(
            capability
        )

        self.revocation.require_active(
            fingerprint
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

        if not isinstance(
            capability,
            Capability,
        ):
            return AuthorizationResult(
                False,
                "invalid_capability",
            )

        request_data = (
            {}
            if request is None
            else dict(request)
        )

        # ----------------------------------------------------
        # Revocation
        # ----------------------------------------------------

        if self.is_revoked(
            capability
        ):
            result = AuthorizationResult(
                False,
                "capability_revoked",
            )

            self.lifecycle.record(
                LifecycleEventType.DENIED,
                capability_fingerprint(
                    capability
                ),
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                reason=result.reason,
                details={
                    "action": action,
                    "request": request_data,
                },
            )

            return result

        # ----------------------------------------------------
        # Time validity
        #
        # Check before cryptographic verification so an
        # expired capability gets EXPIRED rather than an
        # indistinguishable verification failure.
        # ----------------------------------------------------

        clock = getattr(
            self.verifier,
            "clock",
            None,
        )

        if clock is not None:

            try:
                now = float(
                    clock()
                )
            except Exception:
                now = None

            if now is not None:

                if now >= capability.expires_at:

                    result = AuthorizationResult(
                        False,
                        "expired",
                    )

                    self.lifecycle.record(
                        LifecycleEventType.EXPIRED,
                        capability_fingerprint(
                            capability
                        ),
                        agent_id=capability.agent_id,
                        capability=capability.capability,
                        issuer=capability.issuer,
                        reason=result.reason,
                        details={
                            "action": action,
                            "request": request_data,
                            "expires_at": (
                                capability.expires_at
                            ),
                        },
                    )

                    return result

                if now < capability.issued_at:

                    result = AuthorizationResult(
                        False,
                        "not_yet_valid",
                    )

                    self.lifecycle.record(
                        LifecycleEventType.DENIED,
                        capability_fingerprint(
                            capability
                        ),
                        agent_id=capability.agent_id,
                        capability=capability.capability,
                        issuer=capability.issuer,
                        reason=result.reason,
                        details={
                            "action": action,
                            "request": request_data,
                        },
                    )

                    return result

        # ----------------------------------------------------
        # Authorization
        # ----------------------------------------------------

        result = authorize(
            capability,
            action,
            request,
            verifier=self.verifier,
        )

        if result.allowed:

            self.lifecycle.record(
                LifecycleEventType.USED,
                capability_fingerprint(
                    capability
                ),
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                details={
                    "action": action,
                    "request": request_data,
                },
            )

        else:

            self.lifecycle.record(
                LifecycleEventType.DENIED,
                capability_fingerprint(
                    capability
                ),
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                reason=result.reason,
                details={
                    "action": action,
                    "request": request_data,
                },
            )

        return result

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

        if self.is_revoked(
            capability
        ):
            return False

        key = make_replay_key(
            agent,
            capability,
            nonce,
        )

        consumed = (
            self.replay.check_and_consume(
                key,
                capability.expires_at,
            )
        )

        if consumed is False:
            self.lifecycle.record(
                LifecycleEventType.REPLAYED,
                capability_fingerprint(
                    capability
                ),
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                reason="replay_detected",
                details={
                    "agent": agent,
                    "nonce": nonce,
                },
            )

        return consumed

    # ========================================================
    # Serialization
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
    # Transport
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

        if self.is_revoked(
            capability
        ):
            raise RevokedCapabilityError(
                "capability is revoked"
            )

        if not self.verifier.verify(
            capability
        ):
            raise ValueError(
                "decoded capability failed verification"
            )

        return capability

    # ========================================================
    # Evidence
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

    # ========================================================
    # Lifecycle
    # ========================================================

    def lifecycle_events(self):
        return self.lifecycle.events()

    # ========================================================
    # Close
    # ========================================================

    def close(self) -> None:
        if self._revocation_store is not None:
            self._revocation_store.close()
            self._revocation_store = None

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()