from __future__ import annotations

from copy import deepcopy
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

from firewall.key_management import (
    CapabilityKeyManager,
    IssuerTrustStore,
    KeyRecord,
)

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.lifecycle_store import (
    SQLiteLifecycleStore,
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
    Developer-facing v1.0 API.

    Provides:

    - capability issuance
    - capability verification
    - managed signing-key rotation
    - issuer trust management
    - attenuation
    - delegation
    - serialization
    - transport encoding/decoding
    - authorization
    - replay protection
    - capability revocation
    - optional persistent revocation storage
    - lifecycle event recording
    - optional persistent lifecycle storage

    Backwards compatibility:

        sdk.issue(
            private_key=private_key,
            agent="agent-a",
            capability="payments.send",
        )

    remains supported.

    Managed-key issuance:

        sdk.keys.generate("key-1")

        sdk.issue(
            agent="agent-a",
            capability="payments.send",
        )
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
        lifecycle_store_path: Optional[
            str | Path
        ] = None,
        key_manager: Optional[
            CapabilityKeyManager
        ] = None,
        issuer_trust_store: Optional[
            IssuerTrustStore
        ] = None,
    ):
        if (
            trusted_issuers is not None
            and not isinstance(
                trusted_issuers,
                (set, frozenset),
            )
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

        if (
            lifecycle_recorder is not None
            and lifecycle_store_path is not None
        ):
            raise ValueError(
                "provide either lifecycle_recorder "
                "or lifecycle_store_path, not both"
            )

        # ----------------------------------------------------
        # Issuer trust
        # ----------------------------------------------------

        self.issuer_trust_store = (
            issuer_trust_store
            or IssuerTrustStore(
                trusted_issuers
                or {"trusted-issuer"}
            )
        )

        # The current capability format uses issuer names
        # plus an embedded public key. Preserve that model.
        self.verifier = CapabilityVerifier(
            self.issuer_trust_store.trusted_issuers(),
            clock=clock,
        )

        # ----------------------------------------------------
        # Managed signing keys
        # ----------------------------------------------------

        self.keys = (
            key_manager
            or CapabilityKeyManager()
        )

        # ----------------------------------------------------
        # Replay protection
        # ----------------------------------------------------

        self.replay = (
            replay_protector
            or ReplayProtector(
                clock=clock
            )
        )

        # ----------------------------------------------------
        # Lifecycle
        # ----------------------------------------------------

        self._lifecycle_store = None

        if lifecycle_recorder is not None:
            self.lifecycle = (
                lifecycle_recorder
            )

        elif lifecycle_store_path is not None:
            self._lifecycle_store = (
                SQLiteLifecycleStore(
                    lifecycle_store_path
                )
            )

            self.lifecycle = (
                LifecycleRecorder(
                    clock=clock,
                    store=self._lifecycle_store,
                )
            )

        else:
            self.lifecycle = (
                LifecycleRecorder(
                    clock=clock
                )
            )

        # ----------------------------------------------------
        # Revocation
        # ----------------------------------------------------

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
    # Key management
    # ========================================================

    @property
    def key_manager(
        self,
    ) -> CapabilityKeyManager:
        return self.keys

    def generate_key(
        self,
        key_id: str,
    ) -> KeyRecord:
        return self.keys.generate(
            key_id
        )

    def rotate_key(
        self,
        key_id: str,
    ) -> KeyRecord:
        return self.keys.rotate(
            key_id
        )

    def retire_key(
        self,
        key_id: str,
    ) -> None:
        self.keys.retire(
            key_id
        )

    def active_key(
        self,
    ) -> KeyRecord:
        return self.keys.active()

    def trust_issuer(
        self,
        issuer: str,
    ) -> None:
        self.issuer_trust_store.trust(
            issuer
        )

        self._refresh_verifier_trust()

    def revoke_issuer(
        self,
        issuer: str,
    ) -> None:
        self.issuer_trust_store.revoke(
            issuer
        )

        self._refresh_verifier_trust()

    def is_issuer_trusted(
        self,
        issuer: str,
    ) -> bool:
        return self.issuer_trust_store.is_trusted(
            issuer
        )

    def _refresh_verifier_trust(
        self,
    ) -> None:
        self.verifier.trusted_issuers = set(
            self.issuer_trust_store.trusted_issuers()
        )

    # ========================================================
    # Issue
    # ========================================================

    def issue(
        self,
        *,
        agent: str,
        capability: str,
        private_key=None,
        key_id: Optional[str] = None,
        constraints: Optional[dict] = None,
        issuer: str = "trusted-issuer",
        expires_at: Optional[float] = None,
        issued_at: Optional[float] = None,
    ) -> Capability:
        """
        Issue a capability.

        Legacy mode:

            private_key=...

        Managed-key mode:

            no private_key
            → active key is used

            key_id="key-2"
            → selected active managed key is used
        """

        if (
            private_key is not None
            and key_id is not None
        ):
            raise ValueError(
                "provide either private_key or key_id, "
                "not both"
            )

        selected_key_id = None

        # ----------------------------------------------------
        # Managed key path
        # ----------------------------------------------------

        if private_key is None:
            if key_id is None:
                key_record = self.keys.active()

            else:
                key_record = self.keys.get(
                    key_id
                )

                if not key_record.active:
                    raise ValueError(
                        f"key is retired: {key_id}"
                    )

            private_key = (
                key_record.private_key
            )

            selected_key_id = (
                key_record.key_id
            )

        # ----------------------------------------------------
        # Issuer validation
        # ----------------------------------------------------

        if not self.is_issuer_trusted(
            issuer
        ):
            raise ValueError(
                f"issuer is not trusted: {issuer}"
            )

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

        details = {
            "issued_at": result.issued_at,
            "expires_at": result.expires_at,
        }

        if selected_key_id is not None:
            details["key_id"] = (
                selected_key_id
            )

        self.lifecycle.record(
            LifecycleEventType.ISSUED,
            capability_fingerprint(
                result
            ),
            agent_id=result.agent_id,
            capability=result.capability,
            issuer=result.issuer,
            details=details,
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

        if not self.is_issuer_trusted(
            capability.issuer
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
                "constraints": deepcopy(
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
            else deepcopy(request)
        )

        # ----------------------------------------------------
        # Issuer trust
        # ----------------------------------------------------

        if not self.is_issuer_trusted(
            capability.issuer
        ):
            result = AuthorizationResult(
                False,
                "untrusted_issuer",
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
                    "request": deepcopy(
                        request_data
                    ),
                },
            )

            return result

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
                    "request": deepcopy(
                        request_data
                    ),
                },
            )

            return result

        # ----------------------------------------------------
        # Time validity
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
                            "request": deepcopy(
                                request_data
                            ),
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
                            "request": deepcopy(
                                request_data
                            ),
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
                    "request": deepcopy(
                        request_data
                    ),
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
                    "request": deepcopy(
                        request_data
                    ),
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

        if not self.is_issuer_trusted(
            capability.issuer
        ):
            raise ValueError(
                "capability issuer is not trusted"
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
    # Lifecycle persistence
    # ========================================================

    @property
    def lifecycle_store(self):
        return self._lifecycle_store

    # ========================================================
    # Close
    # ========================================================

    def close(self) -> None:
        lifecycle_error = None
        revocation_error = None

        if self._lifecycle_store is not None:
            try:
                self._lifecycle_store.close()
            except Exception as exc:
                lifecycle_error = exc
            finally:
                self._lifecycle_store = None

        if self._revocation_store is not None:
            try:
                self._revocation_store.close()
            except Exception as exc:
                revocation_error = exc
            finally:
                self._revocation_store = None

        if lifecycle_error is not None:
            raise lifecycle_error

        if revocation_error is not None:
            raise revocation_error

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()