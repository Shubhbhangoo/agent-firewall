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

from firewall.delegation_lineage import (
    DelegationLineage,
)
from firewall.delegation_store import (
    SQLiteDelegationStore,
)

from firewall.evidence import (
    Evidence,
)

from firewall.key_management import (
    CapabilityKeyManager,
    IssuerTrustStore,
    KeyRecord,
)

from firewall.key_store import (
    SQLiteKeyStore,
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

from firewall.replay_store import (
    SQLiteReplayStore,
)

from firewall.revocation import (
    RevocationRegistry,
    RevokedCapabilityError,
)

from firewall.revocation_store import (
    SQLiteRevocationStore,
)

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)

from firewall.risk_context import (
    RiskContext,
)

from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticChainDenied,
)

from firewall.refusal_state import (
    RefusalState,
)

from firewall.transport import (
    DEFAULT_MAX_TOKEN_SIZE,
    decode_capability,
    encode_capability,
)


class FirewallSDK:
    """
    Developer-facing Agent Firewall SDK.

    v1.2 adds an optional runtime SecurityContext while
    preserving the existing v1.1 authorization model.

    Existing users can continue using:

        sdk = FirewallSDK()

    Runtime security context:

        context = SecurityContext(
            agent="agent-a",
            max_actions=10,
            max_total_amount=500,
        )

        sdk = FirewallSDK(
            security_context=context,
        )
    """

    def __init__(
        self,
        trusted_issuers: Optional[set[str]] = None,
        clock=None,
        replay_protector: Optional[
            ReplayProtector
        ] = None,
        replay_store_path: Optional[
            str | Path
        ] = None,
        replay_store: Optional[
            SQLiteReplayStore
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
        key_store_path: Optional[
            str | Path
        ] = None,
        master_key: Optional[bytes] = None,
        key_store: Optional[
            SQLiteKeyStore
        ] = None,
        security_context: Optional[
            SecurityContext
        ] = None,
        semantic_context: Optional[
            SemanticChainContext
        ] = None,
        risk_context: Optional[
            RiskContext
        ] = None,
        delegation_lineage: Optional[
            DelegationLineage
        ] = None,
        delegation_store_path: Optional[
            str | Path
        ] = None,
        refusal_state: Optional[
            RefusalState
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
            replay_store is not None
            and replay_store_path is not None
        ):
            raise ValueError(
                "provide either replay_store "
                "or replay_store_path, not both"
            )

        if (
            replay_protector is not None
            and (
                replay_store is not None
                or replay_store_path is not None
            )
        ):
            raise ValueError(
                "provide either replay_protector "
                "or persistent replay storage, not both"
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

        if (
            key_store is not None
            and key_store_path is not None
        ):
            raise ValueError(
                "provide either key_store "
                "or key_store_path, not both"
            )

        if (
            key_store is not None
            and master_key is not None
        ):
            raise ValueError(
                "master_key must not be provided "
                "when key_store is supplied"
            )

        if (
            key_manager is not None
            and (
                key_store is not None
                or key_store_path is not None
            )
        ):
            raise ValueError(
                "provide either key_manager "
                "or persistent key storage, not both"
            )

        if security_context is not None:
            if not isinstance(
                security_context,
                SecurityContext,
            ):
                raise TypeError(
                    "security_context must be a SecurityContext"
                )

        if semantic_context is not None:
            if not isinstance(
                semantic_context,
                SemanticChainContext,
            ):
                raise TypeError(
                    "semantic_context must be a SemanticChainContext"
                )

        if risk_context is not None:
            if not isinstance(
                risk_context,
                RiskContext,
            ):
                raise TypeError(
                    "risk_context must be a RiskContext"
                )

        # ----------------------------------------------------
        # Runtime security context
        # ----------------------------------------------------

        self.security_context = (
            security_context
        )

        # ----------------------------------------------------
        # Runtime semantic chain context
        # ----------------------------------------------------

        self.semantic_context = (
            semantic_context
        )

        # ----------------------------------------------------
        # Runtime risk context
        # ----------------------------------------------------

        self.risk_context = risk_context

        # ----------------------------------------------------
        # Delegation lineage
        # ----------------------------------------------------

        if delegation_lineage is not None:
            if not isinstance(
                delegation_lineage,
                DelegationLineage,
            ):
                raise TypeError(
                    "delegation_lineage must be a DelegationLineage"
                )

            self.delegation_lineage = (
                delegation_lineage
            )
        else:
            self.delegation_lineage = (
                DelegationLineage()
            )

        # v1.3 effective delegation authority registry.
        # Maps capability fingerprints to the concrete capabilities
        # needed to evaluate the complete delegation chain.
        self._capability_registry: dict[str, Capability] = {}

        # Optional persistent delegation metadata. This stores only
        # signed capability records and child -> parent lineage.
        # Private signing keys remain in the key store.
        self._delegation_store = None

        if delegation_store_path is not None:
            self._delegation_store = SQLiteDelegationStore(
                delegation_store_path
            )

            persisted = self._delegation_store.load()

            for capability_data in persisted["capabilities"]:
                capability = Capability(
                    **capability_data
                )
                self._capability_registry[
                    capability_fingerprint(
                        capability
                    )
                ] = capability

            for lineage_record in persisted["lineage"]:
                self.delegation_lineage.register(
                    child_fingerprint=lineage_record[
                        "child_fingerprint"
                    ],
                    parent_fingerprint=lineage_record[
                        "parent_fingerprint"
                    ],
                )

        # ----------------------------------------------------
        # Refusal state
        # ----------------------------------------------------

        if refusal_state is not None:
            if not isinstance(
                refusal_state,
                RefusalState,
            ):
                raise TypeError(
                    "refusal_state must be a RefusalState"
                )

            self.refusal_state = refusal_state
        else:
            self.refusal_state = RefusalState()

        # ----------------------------------------------------
        # Persistent key store
        # ----------------------------------------------------

        self._key_store = None

        if key_store is not None:
            self._key_store = key_store

        elif key_store_path is not None:
            if master_key is None:
                raise ValueError(
                    "master_key is required when "
                    "key_store_path is provided"
                )

            self._key_store = SQLiteKeyStore(
                key_store_path,
                master_key=master_key,
            )

        # ----------------------------------------------------
        # Issuer trust
        # ----------------------------------------------------

        if issuer_trust_store is not None:
            self.issuer_trust_store = (
                issuer_trust_store
            )

        elif self._key_store is not None:
            persisted_issuers = set(
                self._key_store.trusted_issuers()
            )

            effective_issuers = (
                persisted_issuers
                | set(
                    trusted_issuers
                    if trusted_issuers is not None
                    else {"trusted-issuer"}
                )
            )

            self.issuer_trust_store = (
                IssuerTrustStore(
                    effective_issuers,
                    store=self._key_store,
                )
            )

            for issuer in effective_issuers:
                self._key_store.trust_issuer(
                    issuer
                )

        else:
            self.issuer_trust_store = (
                IssuerTrustStore(
                    trusted_issuers
                    if trusted_issuers is not None
                    else {"trusted-issuer"}
                )
            )

        self.verifier = CapabilityVerifier(
            self.issuer_trust_store.trusted_issuers(),
            clock=clock,
        )

        # ----------------------------------------------------
        # Managed signing keys
        # ----------------------------------------------------

        if key_manager is not None:
            self.keys = key_manager

        else:
            self.keys = (
                CapabilityKeyManager(
                    store=self._key_store
                )
            )

        self._register_managed_keys_for_trusted_issuers()

        # ----------------------------------------------------
        # Replay protection
        # ----------------------------------------------------

        self._replay_store = None

        if replay_store is not None:
            self._replay_store = replay_store

        elif replay_store_path is not None:
            self._replay_store = SQLiteReplayStore(
                replay_store_path,
                clock=clock,
            )

        if replay_protector is not None:
            self.replay = replay_protector

        else:
            self.replay = ReplayProtector(
                clock=clock,
                store=self._replay_store,
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
        record = self.keys.generate(
            key_id
        )

        for issuer in (
            self.issuer_trust_store.trusted_issuers()
        ):
            self.verifier.register_key(
                issuer,
                record.key_id,
                record.public_key,
            )

        return record

    def rotate_key(
        self,
        key_id: str,
    ) -> KeyRecord:
        record = self.keys.rotate(
            key_id
        )

        for issuer in (
            self.issuer_trust_store.trusted_issuers()
        ):
            self.verifier.register_key(
                issuer,
                record.key_id,
                record.public_key,
            )

        return record

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

        self._register_managed_keys_for_issuer(
            issuer
        )

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

    def _register_managed_keys_for_issuer(
        self,
        issuer: str,
    ) -> None:
        for key_id in self.keys.key_ids():
            record = self.keys.get(
                key_id
            )

            self.verifier.register_key(
                issuer,
                record.key_id,
                record.public_key,
            )

    def _register_managed_keys_for_trusted_issuers(
        self,
    ) -> None:
        for issuer in (
            self.issuer_trust_store.trusted_issuers()
        ):
            self._register_managed_keys_for_issuer(
                issuer
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
        tool: Optional[str] = None,
    ) -> Capability:

        if (
            private_key is not None
            and key_id is not None
        ):
            raise ValueError(
                "provide either private_key or key_id, "
                "not both"
            )

        selected_key_id = None

        if private_key is None:
            try:
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

            except RuntimeError as exc:
                if str(exc) == "no active key":
                    raise ValueError(
                        "no active key"
                    ) from exc

                raise

            private_key = (
                key_record.private_key
            )

            selected_key_id = (
                key_record.key_id
            )

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
            key_id=selected_key_id,
            tool=tool,
        )

        details = {
            "issued_at": result.issued_at,
            "expires_at": result.expires_at,
        }

        if selected_key_id is not None:
            details["key_id"] = (
                selected_key_id
            )

        result_fingerprint = capability_fingerprint(
            result
        )

        self._capability_registry[
            result_fingerprint
        ] = result

        if self._delegation_store is not None:
            self._delegation_store.save_capability(
                result_fingerprint,
                result.to_dict(),
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

        if self.is_effectively_revoked(
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

        parent_fingerprint = (
            capability_fingerprint(
                capability
            )
        )

        child_fingerprint = (
            capability_fingerprint(
                result
            )
        )

        # A no-op attenuation can produce the exact same signed
        # capability as its parent. In that case there is no
        # distinct child capability to register in the lineage.
        if child_fingerprint != parent_fingerprint:
            self.delegation_lineage.register(
                child_fingerprint=child_fingerprint,
                parent_fingerprint=parent_fingerprint,
            )

        self._capability_registry[
            parent_fingerprint
        ] = capability

        self._capability_registry[
            child_fingerprint
        ] = result

        if self._delegation_store is not None:
            self._delegation_store.save_capability(
                parent_fingerprint,
                capability.to_dict(),
            )
            self._delegation_store.save_capability(
                child_fingerprint,
                result.to_dict(),
            )

            if child_fingerprint != parent_fingerprint:
                self._delegation_store.save_lineage(
                    child_fingerprint,
                    parent_fingerprint,
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
                "tool": result.tool,
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

        parent_fingerprint = (
            capability_fingerprint(
                capability
            )
        )

        child_fingerprint = (
            capability_fingerprint(
                delegation.child
            )
        )

        self.delegation_lineage.register(
            child_fingerprint=child_fingerprint,
            parent_fingerprint=parent_fingerprint,
        )

        self._capability_registry[
            parent_fingerprint
        ] = capability

        self._capability_registry[
            child_fingerprint
        ] = delegation.child

        if self._delegation_store is not None:
            self._delegation_store.save_capability(
                parent_fingerprint,
                capability.to_dict(),
            )
            self._delegation_store.save_capability(
                child_fingerprint,
                delegation.child.to_dict(),
            )
            self._delegation_store.save_lineage(
                child_fingerprint,
                parent_fingerprint,
            )

        self.lifecycle.record(
            LifecycleEventType.DELEGATED,
            parent_fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
            issuer=capability.issuer,
            details={
                "delegatee": delegatee,
                "delegation": True,
                "child_fingerprint": (
                    child_fingerprint
                ),
                "tool": delegation.child.tool,
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

    def is_effectively_revoked(
        self,
        capability: Capability,
    ) -> bool:
        """
        Return True when the capability itself or any
        ancestor in its delegation lineage is revoked.
        """

        fingerprint = self.fingerprint(
            capability
        )

        if self.revocation.is_revoked(
            fingerprint
        ):
            return True

        for ancestor in self.delegation_lineage.chain(
            fingerprint
        ):
            if self.revocation.is_revoked(
                ancestor
            ):
                return True

        return False

    # ========================================================
    # Security context
    # ========================================================

    def set_security_context(
        self,
        context: Optional[
            SecurityContext
        ],
    ) -> None:
        if context is not None:
            if not isinstance(
                context,
                SecurityContext,
            ):
                raise TypeError(
                    "context must be a SecurityContext"
                )

        self.security_context = context

    def get_security_context(
        self,
    ) -> Optional[SecurityContext]:
        return self.security_context

    # ========================================================
    # Semantic chain context
    # ========================================================

    def set_semantic_context(
        self,
        context: Optional[
            SemanticChainContext
        ],
    ) -> None:
        if context is not None:
            if not isinstance(
                context,
                SemanticChainContext,
            ):
                raise TypeError(
                    "context must be a SemanticChainContext"
                )

        self.semantic_context = context

    def get_semantic_context(
        self,
    ) -> Optional[SemanticChainContext]:
        return self.semantic_context

    # ========================================================
    # Risk context
    # ========================================================

    def set_risk_context(
        self,
        context: Optional[RiskContext],
    ) -> None:
        if context is not None and not isinstance(context, RiskContext):
            raise TypeError("context must be a RiskContext")
        self.risk_context = context

    def get_risk_context(self) -> Optional[RiskContext]:
        return self.risk_context


    def mint_session_capability(
        self,
        *,
        agent: str,
        tool: str,
        capability: str,
        constraints: Optional[dict] = None,
        ttl: float = 300,
    ) -> Capability:
        """
        Mint a short-lived, tool-bound capability for an
        agent session.

        Session capabilities always receive an explicit tool
        binding and a fresh expiration derived from ttl.
        """

        if (
            not isinstance(
                agent,
                str,
            )
            or not agent.strip()
        ):
            raise ValueError(
                "agent must be a non-empty string"
            )

        if (
            not isinstance(
                tool,
                str,
            )
            or not tool.strip()
        ):
            raise ValueError(
                "tool must be a non-empty string"
            )

        if (
            not isinstance(
                capability,
                str,
            )
            or not capability.strip()
        ):
            raise ValueError(
                "capability must be a non-empty string"
            )

        if (
            isinstance(
                ttl,
                bool,
            )
            or not isinstance(
                ttl,
                (int, float),
            )
            or ttl <= 0
        ):
            raise ValueError(
                "ttl must be a positive number"
            )

        issued_at = float(
            self.verifier.clock()
        )

        expires_at = (
            issued_at + float(ttl)
        )

        key_record = self.keys.active()

        result = sign_capability(
            private_key=key_record.private_key,
            agent_id=agent,
            capability=capability,
            constraints=(
                {}
                if constraints is None
                else dict(constraints)
            ),
            issuer="trusted-issuer",
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=key_record.key_id,
            tool=tool,
        )

        self._capability_registry[
            capability_fingerprint(result)
        ] = result

        self.lifecycle.record(
            LifecycleEventType.ISSUED,
            capability_fingerprint(result),
            agent_id=result.agent_id,
            capability=result.capability,
            issuer=result.issuer,
            details={
                "session_capability": True,
                "tool": result.tool,
                "ttl": float(ttl),
                "expires_at": result.expires_at,
            },
        )

        return result
    # ========================================================
    # Refusal state
    # ========================================================

    def get_refusal_state(
        self,
    ) -> RefusalState:
        return self.refusal_state

    # ========================================================
    # Effective delegation authority
    # ========================================================

    def _authorization_chain(
        self,
        capability: Capability,
    ) -> tuple[Capability, ...]:
        """Return the capability and every delegation ancestor.

        The requested capability is first, followed by its direct
        parent and then all ancestors. Authorization succeeds only
        when the request is valid against every capability in the
        delegation chain. This makes effective authority the
        intersection of all delegated authority.
        """
        fingerprint = capability_fingerprint(
            capability
        )

        chain = [capability]

        for ancestor_fingerprint in self.delegation_lineage.chain(
            fingerprint
        ):
            ancestor = self._capability_registry.get(
                ancestor_fingerprint
            )

            if ancestor is None:
                raise ValueError(
                    "delegation ancestor capability is unavailable"
                )

            chain.append(ancestor)

        return tuple(chain)

    # ========================================================
    # Authorization
    # ========================================================

    def authorize(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
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

        fingerprint = (
            capability_fingerprint(
                capability
            )
        )

        if refusal_scope == "action":
            refusal = self.refusal_state.check_action(
                agent=capability.agent_id,
                capability_fingerprint=fingerprint,
                action=action,
            )
        elif refusal_scope == "request":
            refusal = self.refusal_state.check(
                agent=capability.agent_id,
                capability_fingerprint=fingerprint,
                action=action,
                request=request_data,
            )
        else:
            return AuthorizationResult(
                False,
                "invalid_refusal_scope",
            )

        if refusal is not None:
            result = AuthorizationResult(
                False,
                "refusal_state",
            )

            if self.security_context is not None:
                self.security_context.record_denial()

            if self.risk_context is not None:
                self.risk_context.record_denial(capability.agent_id)

            self.lifecycle.record(
                LifecycleEventType.DENIED,
                fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                reason=result.reason,
                details={
                    "action": action,
                    "request": deepcopy(
                        request_data
                    ),
                    "refusal_reason": refusal.reason,
                },
            )

            return result

        def record_denial(
            result: AuthorizationResult,
        ) -> AuthorizationResult:

            if self.security_context is not None:
                self.security_context.record_denial()

            if self.risk_context is not None:
                self.risk_context.record_denial(capability.agent_id)

            if result.reason in {
                "constraint_denied",
                "policy_denied",
            }:
                self.refusal_state.record(
                    agent=capability.agent_id,
                    capability_fingerprint=fingerprint,
                    action=action,
                    request=request_data,
                    reason=result.reason,
                )

            self.lifecycle.record(
                LifecycleEventType.DENIED,
                fingerprint,
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
        # Runtime risk state
        # ----------------------------------------------------

        if (
            self.risk_context is not None
            and not self.risk_context.can_authorize(capability.agent_id)
        ):
            return record_denial(
                AuthorizationResult(False, "risk_state_revoked")
            )

        # ----------------------------------------------------
        # Issuer trust
        # ----------------------------------------------------

        if not self.is_issuer_trusted(
            capability.issuer
        ):
            return record_denial(
                AuthorizationResult(
                    False,
                    "untrusted_issuer",
                )
            )

        # ----------------------------------------------------
        # Revocation
        # ----------------------------------------------------

        if self.is_effectively_revoked(
            capability
        ):
            return record_denial(
                AuthorizationResult(
                    False,
                    "capability_revoked",
                )
            )

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

                    if self.security_context is not None:
                        self.security_context.record_denial()

                    if self.risk_context is not None:
                        self.risk_context.record_denial(capability.agent_id)

                    self.lifecycle.record(
                        LifecycleEventType.EXPIRED,
                        fingerprint,
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
                    return record_denial(
                        AuthorizationResult(
                            False,
                            "not_yet_valid",
                        )
                    )

        # ----------------------------------------------------
        # Cryptographic + effective delegation authorization
        # ----------------------------------------------------

        try:
            authorization_chain = self._authorization_chain(
                capability
            )
        except (
            ValueError,
            TypeError,
        ) as exc:
            return record_denial(
                AuthorizationResult(
                    False,
                    f"delegation_chain_error: {exc}",
                )
            )

        result = AuthorizationResult(
            True,
            "authorized",
        )

        for chain_capability in authorization_chain:
            chain_result = authorize(
                chain_capability,
                action,
                request_data,
                verifier=self.verifier,
            )

            if not chain_result.allowed:
                result = chain_result
                break

        if not result.allowed:
            return record_denial(
                result
            )

        semantic_transaction = None

        # ----------------------------------------------------
        # Runtime semantic chain context
        # ----------------------------------------------------

        if self.semantic_context is not None:

            try:
                semantic_transaction = (
                    self.semantic_context.begin_authorization(
                        agent=capability.agent_id,
                        action=action,
                        request=request_data,
                        capability_fingerprint=fingerprint,
                        capability=capability.capability,
                        chain_id=chain_id,
                    )
                )

            except SemanticChainDenied:
                return record_denial(
                    AuthorizationResult(
                        False,
                        "semantic_chain_denied",
                    )
                )

            except (
                ValueError,
                TypeError,
            ) as exc:
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"semantic_context_error: {exc}",
                    )
                )

        def abort_semantic_transaction() -> None:
            if semantic_transaction is not None:
                semantic_transaction.abort()

        def commit_semantic_transaction() -> None:
            if semantic_transaction is not None:
                semantic_transaction.commit()

        # ----------------------------------------------------
        # Runtime security context
        # ----------------------------------------------------

        if self.security_context is not None:

            if (
                self.security_context.agent
                != capability.agent_id
            ):
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        "security_context_agent_mismatch",
                    )
                )

            try:
                self.security_context.authorize_and_record(
                    request=request_data,
                    capability_fingerprint=fingerprint,
                )

            except SecurityBudgetExceeded as exc:
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        str(exc),
                    )
                )

            except (
                ValueError,
                TypeError,
            ) as exc:
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"security_context_error: {exc}",
                    )
                )

        try:
            commit_semantic_transaction()
        except (
            ValueError,
            TypeError,
        ) as exc:
            return record_denial(
                AuthorizationResult(
                    False,
                    f"semantic_context_error: {exc}",
                )
            )

        # ----------------------------------------------------
        # Successful authorization
        # ----------------------------------------------------

        self.lifecycle.record(
            LifecycleEventType.USED,
            fingerprint,
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

        return result

    # ========================================================
    # Boolean authorization
    # ========================================================

    def is_authorized(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        chain_id: Optional[str] = None,
    ) -> bool:

        return self.authorize(
            capability,
            action,
            request,
            chain_id=chain_id,
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

        if self.is_effectively_revoked(
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

        if self.is_effectively_revoked(
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

    @property
    def key_store(self):
        return self._key_store

    @property
    def replay_store(self):
        return self._replay_store

    @property
    def delegation_store(self):
        return self._delegation_store

    # ========================================================
    # Close
    # ========================================================

    def close(self) -> None:
        lifecycle_error = None
        revocation_error = None
        key_store_error = None
        replay_store_error = None
        delegation_store_error = None

        if self._delegation_store is not None:
            try:
                self._delegation_store.close()
            except Exception as exc:
                delegation_store_error = exc
            finally:
                self._delegation_store = None

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

        if self._key_store is not None:
            try:
                self._key_store.close()
            except Exception as exc:
                key_store_error = exc
            finally:
                self._key_store = None

        if self._replay_store is not None:
            try:
                self._replay_store.close()
            except Exception as exc:
                replay_store_error = exc
            finally:
                self._replay_store = None

        if lifecycle_error is not None:
            raise lifecycle_error

        if revocation_error is not None:
            raise revocation_error

        if key_store_error is not None:
            raise key_store_error

        if replay_store_error is not None:
            raise replay_store_error

        if delegation_store_error is not None:
            raise delegation_store_error

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()
