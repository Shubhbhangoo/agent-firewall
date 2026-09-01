
from copy import deepcopy
from dataclasses import dataclass, replace
import math
from pathlib import Path
from typing import Optional
import uuid

from firewall.authorization import (
    AuthorizationResult,
    authorize,
)

from firewall.security_decision import SecurityDecision

from firewall.north_star import (
    DelegationAuthority,
    NorthStarPipeline,
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

from firewall.delegation_budget import (
    DelegationBudgetExceeded,
    DelegationBudgetRegistry,
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

from firewall.replay_store import (
    SQLiteReplayStore,
)
from firewall.replay import (
    ReplayProtector,
    make_replay_key,
)

from firewall.continuous_auth.engine import (
    ContinuousAuthorizationEngine,
    RevalidationResult,
    RevalidationTrigger,
)
from firewall.continuous_auth.monitor import (
    ContinuousAuthorizationMonitor,
    MonitoringConfig,
)
from firewall.continuous_auth.predicates import (
    is_narrower_than,
    MonotonicityResult,
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

from firewall.recorder import (
    EventType,
    FlightRecorder,
)


@dataclass
class _AuthorizationContext:
    """
    Mutable per-request state shared across the ordered authorization
    gates of ``FirewallSDK.authorize``.

    The context is a plain data carrier: it holds the inputs every gate
    needs (the requested capability, the action, the deep-copied request
    payload, and the capability fingerprint), the per-request runtime
    security mechanisms the gates and the transactional tail operate on
    (the risk, security, and semantic-chain contexts and the refusal
    state), and the two values that a gate populates for later gates --
    the resolved North Star ``delegation_authority`` and the successful
    cryptographic ``result``.

    The mechanism references are bound once from the SDK when the context
    is constructed and are never reassigned during a request, so a gate
    reading ``ctx.risk_context`` sees exactly the object it would have
    read as ``self.risk_context``. Carrying them here -- rather than
    having each gate reach into ``self`` -- makes the per-request context
    explicit and self-contained, which is the direction of the North Star
    migration; it changes no behaviour.

    It exists so the canonical gate ordering can live in one place
    (``_authorization_gate_phases``) while each gate remains a thin
    adapter around an existing security mechanism. It carries no
    behaviour of its own.
    """

    capability: Capability
    action: str
    request_data: dict
    fingerprint: str
    refusal_scope: str
    chain_id: Optional[str]
    risk_context: Optional[RiskContext] = None
    security_context: Optional[SecurityContext] = None
    semantic_context: Optional[SemanticChainContext] = None
    refusal_state: Optional[RefusalState] = None
    delegation_authority: Optional[DelegationAuthority] = None
    result: Optional[AuthorizationResult] = None


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
        max_delegation_depth: Optional[int] = None,
        recorder: Optional[
            FlightRecorder
        ] = None,
        continuous_auth_config: Optional[
            MonitoringConfig
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

        # v1.5 cumulative budget registry.
        # One budget belongs to the root capability of a
        # delegation lineage. Every descendant consumes that
        # same budget.
        self._delegation_budgets = (
            DelegationBudgetRegistry()
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
        # Delegation-depth policy
        # ----------------------------------------------------
        #
        # Optional, opt-in ceiling on the effective delegation depth
        # (the length of the resolved delegation authority). ``None``
        # leaves the policy disabled, so the v1.5 baseline is unchanged.
        # When set, it is enforced identically by both authorize() and
        # authorize_north_star() through the shared gate tuple, so the
        # two paths cannot diverge. Validation mirrors the generic
        # North Star delegation phase: reject bool and non-int as a type
        # error, and reject non-positive limits as a value error.

        if max_delegation_depth is not None:
            if isinstance(
                max_delegation_depth,
                bool,
            ) or not isinstance(
                max_delegation_depth,
                int,
            ):
                raise TypeError(
                    "max_delegation_depth must be an integer"
                )

            if max_delegation_depth <= 0:
                raise ValueError(
                    "max_delegation_depth must be positive"
                )

        self.max_delegation_depth = max_delegation_depth

        # ----------------------------------------------------
        # v1.8 flight recorder
        # ----------------------------------------------------
        #
        # Optional, opt-in, and observational. The recorder is
        # consulted only *after* a decision exists, so enabling it
        # can never change an authorization outcome. Recording
        # failures are swallowed: the recorder is observability,
        # not authority, and must never break the pipeline it
        # observes.

        if recorder is not None:
            if not isinstance(
                recorder,
                FlightRecorder,
            ):
                raise TypeError(
                    "recorder must be a FlightRecorder"
                )

        self._recorder = recorder

        # ----------------------------------------------------
        # Continuous Authorization
        # ----------------------------------------------------

        self.continuous_auth_engine = None
        self.continuous_auth_monitor = None

        if continuous_auth_config is not None:
            self.continuous_auth_engine = ContinuousAuthorizationEngine(
                sdk=self,
                risk_context=self.risk_context,
            )
            self.continuous_auth_monitor = ContinuousAuthorizationMonitor(
                engine=self.continuous_auth_engine,
                sdk=self,
                config=continuous_auth_config,
            )

        # ----------------------------------------------------
        # North Star compatibility boundary
        # ----------------------------------------------------
        #
        # North Star is deliberately downstream of the established
        # authorization implementation at this stage. The legacy
        # authorize() path remains the source of truth, while the
        # canonical SecurityDecision is exposed through a dedicated
        # pipeline boundary. This prevents a new orchestration layer
        # from changing v1.5 authorization semantics.
        self.north_star = self._build_north_star_pipeline()

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
    # v1.8 flight recorder
    # ========================================================

    @property
    def flight_recorder(
        self,
    ) -> Optional[FlightRecorder]:
        """The optional v1.8 flight recorder, if attached."""

        return self._recorder

    def _record_flight_event(
        self,
        event_type: EventType,
        payload: dict,
        *,
        agent: Optional[str] = None,
    ) -> None:
        """Best-effort recording. Never raises, never influences."""

        recorder = self._recorder

        if recorder is None:
            return

        try:
            recorder.record(
                event_type,
                payload,
                agent=agent,
            )
        except Exception:
            # A recorder must never break the security pipeline it
            # observes. Failures are dropped; the lifecycle log and
            # the artifact remain the durable record.
            return

    def _record_flight_authorization(
        self,
        ctx: "_AuthorizationContext",
        result: AuthorizationResult,
    ) -> None:
        """Record one already-final authorization decision.

        Captures the material facts the gates reasoned about: the
        requested action, the verdict, the capability chain shape
        (agents and constraints, root first), and the request
        projection. Signatures, keys, and credential-shaped request
        values are excluded (the recorder redacts the latter by
        default).
        """

        recorder = self._recorder

        if recorder is None:
            return

        capability = ctx.capability
        authority = ctx.delegation_authority

        chain = None
        depth = None

        if (
            authority is not None
            and authority.capabilities
        ):
            depth = authority.depth
            chain = [
                {
                    "agent": member.agent_id,
                    "constraints": dict(
                        member.constraints or {}
                    ),
                }
                for member in reversed(
                    authority.capabilities
                )
            ]
        elif isinstance(
            capability,
            Capability,
        ):
            chain = [
                {
                    "agent": capability.agent_id,
                    "constraints": dict(
                        capability.constraints or {}
                    ),
                }
            ]

        payload = {
            "action": ctx.action,
            "allowed": bool(result.allowed),
            "reason": str(result.reason),
            "capability": (
                capability.capability
                if isinstance(
                    capability,
                    Capability,
                )
                else None
            ),
            "tool": (
                capability.tool
                if isinstance(
                    capability,
                    Capability,
                )
                else None
            ),
            "issuer": (
                capability.issuer
                if isinstance(
                    capability,
                    Capability,
                )
                else None
            ),
            "depth": depth,
            "chain": chain,
            "request": dict(ctx.request_data or {}),
        }

        self._record_flight_event(
            EventType.AUTHORIZATION,
            payload,
            agent=(
                capability.agent_id
                if isinstance(
                    capability,
                    Capability,
                )
                else None
            ),
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

        self._record_flight_event(
            EventType.SECURITY_STATE,
            {
                "change": "issuer_trusted",
                "issuer": issuer,
            },
        )

    def revoke_issuer(
        self,
        issuer: str,
    ) -> None:
        self.issuer_trust_store.revoke(
            issuer
        )

        self._refresh_verifier_trust()

        self._record_flight_event(
            EventType.SECURITY_STATE,
            {
                "change": "issuer_untrusted",
                "issuer": issuer,
            },
        )

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

        # Generate a unique nonce to ensure distinct fingerprints even
        # for rapid re-issuance of identical payloads.
        nonce = uuid.uuid4().hex

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
            nonce=nonce,
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

        self._record_flight_event(
            EventType.AUTHORITY_ISSUED,
            {
                "capability": result.capability,
                "issuer": result.issuer,
                "fingerprint": (
                    capability_fingerprint(
                        result
                    )
                ),
                "tool": result.tool,
                "constraints": dict(
                    result.constraints or {}
                ),
                "expires_at": result.expires_at,
            },
            agent=result.agent_id,
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

        self._record_flight_event(
            EventType.AUTHORITY_ATTENUATED,
            {
                "capability": result.capability,
                "issuer": result.issuer,
                "fingerprint": (
                    capability_fingerprint(
                        result
                    )
                ),
                "parent_fingerprint": (
                    capability_fingerprint(
                        capability
                    )
                ),
                "constraints": dict(
                    result.constraints or {}
                ),
                "expires_at": result.expires_at,
                "tool": result.tool,
            },
            agent=result.agent_id,
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

        self._record_flight_event(
            EventType.AUTHORITY_DELEGATED,
            {
                "capability": delegation.child.capability,
                "issuer": delegation.child.issuer,
                "delegatee": delegatee,
                "child_fingerprint": (
                    child_fingerprint
                ),
                "parent_fingerprint": (
                    parent_fingerprint
                ),
                "tool": delegation.child.tool,
            },
            agent=capability.agent_id,
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

        record = self.revocation.revoke(
            fingerprint,
            reason=reason,
        )

        self._record_flight_event(
            EventType.AUTHORITY_REVOKED,
            {
                "capability": capability.capability,
                "fingerprint": fingerprint,
                "reason": str(reason),
                "revoked_at": record.revoked_at,
            },
            agent=capability.agent_id,
        )

        return record

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
        ):
            raise TypeError(
                "ttl must be numeric"
            )

        ttl = float(ttl)

        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError(
                "ttl must be a finite positive number"
            )

        issued_at = float(
            self.verifier.clock()
        )

        if not math.isfinite(issued_at):
            raise ValueError(
                "clock must return a finite number"
            )

        expires_at = (
            issued_at + ttl
        )

        if not math.isfinite(expires_at):
            raise ValueError(
                "computed expiration must be finite"
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

        self._record_flight_event(
            EventType.AUTHORITY_ISSUED,
            {
                "capability": result.capability,
                "issuer": result.issuer,
                "fingerprint": (
                    capability_fingerprint(
                        result
                    )
                ),
                "tool": result.tool,
                "session_capability": True,
                "ttl": float(ttl),
                "expires_at": result.expires_at,
            },
            agent=result.agent_id,
        )

        return result
    # ========================================================
    # Refusal state
    # ========================================================

    def get_refusal_state(
        self,
    ) -> RefusalState:
        return self.refusal_state

    def _build_north_star_pipeline(
        self,
    ) -> NorthStarPipeline:
        """Build the v1.6 North Star authorization pipeline.

        North Star owns the canonical ordering and control flow of the
        authorization decision. The established SDK mechanisms remain the
        authority for their own semantics: ``authorize()`` is the single
        authority for the security decision, including cryptographic
        verification and delegation-chain enforcement.

        The delegation phase here is intentionally *observational*. It
        resolves the established SDK lineage via
        ``_resolve_delegation_authority()`` -- the same resolver the
        authoritative delegation-chain gate uses -- and publishes an
        immutable :class:`DelegationAuthority` into the
        pipeline state for downstream phases, but it never denies. Any
        lineage-resolution failure is deferred to ``authorize()`` below,
        which fails closed with the canonical reason, precedence, and side
        effects. Swallowing a resolution error in this phase cannot cause
        an unsafe allow, because ``authorize()`` independently re-resolves
        and enforces the same chain.

        Keeping ``authorize()`` as the sole decision authority makes the
        North Star path semantically equivalent to the direct authorize()
        path without duplicating any security check or changing any
        denial-reason precedence.

        The ``canonical_authorization`` phase then *consumes* that
        published authority to enrich the returned decision with the
        observed delegation depth as ``metadata``. This is observability
        only: it never changes the allow/deny outcome, the reason, or any
        identity field, so North Star stays equivalent to ``authorize()``
        while carrying strictly more information than the raw result.
        """

        def observe_delegation(
            state: dict,
        ) -> Optional[SecurityDecision]:
            capability = state.get(
                "capability"
            )

            # The invalid_capability decision is owned by authorize().
            if not isinstance(
                capability,
                Capability,
            ):
                return None

            try:
                state["delegation_authority"] = (
                    self._resolve_delegation_authority(
                        capability
                    )
                )
            except Exception as exc:
                # Observational only. authorize() remains the authority
                # for the delegation-chain decision and will fail closed
                # with the canonical reason. Record the resolution failure
                # type for observability without leaking any detail that
                # could expose cryptographic material.
                state["delegation_authority_error"] = (
                    type(exc).__name__
                )

            return None

        def canonical_authorization(
            state: dict,
        ) -> Optional[SecurityDecision]:
            result = self.authorize(
                state["capability"],
                state["action"],
                state["request"],
                refusal_scope=state.get(
                    "refusal_scope",
                    "action",
                ),
                chain_id=state.get("chain_id"),
            )
            decision = self.security_decision(result)
            return self._annotate_delegation_posture(
                decision,
                state,
            )

        return (
            NorthStarPipeline()
            .add_phase(
                "delegation",
                observe_delegation,
            )
            .add_phase(
                "canonical_authorization",
                canonical_authorization,
            )
        )

    def _annotate_delegation_posture(
        self,
        decision: SecurityDecision,
        state: dict,
    ) -> SecurityDecision:
        """Enrich a North Star decision with the observed delegation posture.

        Observational only. This consumes the immutable
        :class:`DelegationAuthority` that the delegation phase already
        published into pipeline state and surfaces its effective depth as
        decision ``metadata``. It never touches ``allowed``, ``reason``,
        or any identity field, so the North Star decision stays
        semantically equivalent to ``authorize()`` (locked by the
        equivalence suite) while carrying strictly more observability than
        the raw result.

        Fails closed to the *unenriched* decision. If no authority was
        published -- an invalid capability, or a lineage-resolution error
        that the delegation phase recorded instead of publishing -- the
        original decision is returned unchanged. The enrichment itself is
        wrapped defensively because metadata must never be able to flip a
        finalized decision or turn it into an internal error: any
        unexpected failure falls back to the decision exactly as
        ``authorize()`` produced it.
        """
        authority = state.get(
            "delegation_authority"
        )
        if not isinstance(
            authority,
            DelegationAuthority,
        ):
            return decision

        try:
            metadata = (
                dict(decision.metadata)
                if decision.metadata
                else {}
            )
            metadata["delegation_depth"] = authority.depth
            return replace(
                decision,
                metadata=metadata,
            )
        except Exception:
            return decision

    def authorize_north_star(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> SecurityDecision:
        """Evaluate authorization through the North Star boundary.

        This is an additive v1.6 API. The established authorize()
        implementation remains unchanged and continues to own all
        security side effects and compatibility behavior.
        """

        return self.north_star.evaluate(
            capability=capability,
            action=action,
            request=request,
            context={
                "refusal_scope": refusal_scope,
                "chain_id": chain_id,
            },
        )

    def security_decision(
        self,
        result: AuthorizationResult,
    ) -> SecurityDecision:
        """Return the canonical v1.6 security decision for an authorization result.

        Existing SDK authorization APIs remain unchanged. This accessor provides
        a stable SecurityDecision representation for new v1.6 integrations.
        """
        if not isinstance(
            result,
            AuthorizationResult,
        ):
            raise TypeError(
                "result must be an AuthorizationResult"
            )

        return result.decision

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

    def _trace_result(
        self,
        capability: Capability,
        action: str,
        result: AuthorizationResult,
    ) -> AuthorizationResult:
        """Attach a minimal capability-aware trace to a result.

        Existing trace data is preserved when it already identifies the
        requested capability. For delegation-chain failures, the trace is
        rewritten to identify the concrete capability that the caller
        attempted to use.
        """

        trace = {
            "capability_id": capability_fingerprint(
                capability
            ),
            "agent": capability.agent_id,
            "action": action,
            "reason": result.reason,
        }

        if capability.tool is not None:
            trace["tool"] = capability.tool

        return AuthorizationResult(
            allowed=result.allowed,
            reason=result.reason,
            trace=trace,
        )

    def _delegation_root(
        self,
        capability: Capability,
    ) -> Capability:
        """
        Resolve the root capability for a delegation lineage.

        The requested capability is followed through its registered
        ancestors. The final ancestor is the root authority that owns
        the cumulative lineage budget.
        """

        if not isinstance(
            capability,
            Capability,
        ):
            raise TypeError(
                "capability must be a Capability"
            )

        fingerprint = capability_fingerprint(
            capability
        )

        current = capability

        for ancestor_fingerprint in (
            self.delegation_lineage.chain(
                fingerprint
            )
        ):
            ancestor = (
                self._capability_registry.get(
                    ancestor_fingerprint
                )
            )

            if ancestor is None:
                raise ValueError(
                    "delegation ancestor capability is unavailable"
                )

            current = ancestor

        return current

    def configure_delegation_budget(
        self,
        capability: Capability,
        *,
        max_total_amount: float,
    ) -> None:
        """
        Configure one cumulative amount budget for the complete
        delegation lineage rooted at ``capability``.

        Descendants do not receive independent budgets. They all
        consume the root lineage budget.
        """

        root = self._delegation_root(
            capability
        )

        self._delegation_budgets.configure(
            capability_fingerprint(
                root
            ),
            max_total_amount,
        )

    def delegation_budget_total(
        self,
        capability: Capability,
    ) -> float:
        """
        Return cumulative amount consumed by the lineage root.
        """

        root = self._delegation_root(
            capability
        )

        return self._delegation_budgets.total_amount(
            capability_fingerprint(
                root
            )
        )

    def delegation_budget_limit(
        self,
        capability: Capability,
    ) -> float:
        """
        Return the configured cumulative amount limit for the
        lineage root.
        """

        root = self._delegation_root(
            capability
        )

        return self._delegation_budgets.max_total_amount(
            capability_fingerprint(
                root
            )
        )

    def authorize_with_delegation_budget(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> AuthorizationResult:
        """
        Authorize a request and consume the cumulative budget
        belonging to the root capability of its delegation lineage.

        Authorization is evaluated first. Budget state is mutated only
        after the request has passed normal capability authorization.

        If no budget has been configured for the lineage, the request
        is denied explicitly rather than silently creating authority.
        """

        result = self.authorize(
            capability,
            action,
            request,
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        if not result.allowed:
            return result

        request_data = (
            {}
            if request is None
            else deepcopy(
                request
            )
        )

        if not isinstance(
            request_data,
            dict,
        ):
            return self._trace_result(
                capability,
                action,
                AuthorizationResult(
                    False,
                    "invalid_request",
                ),
            )

        amount = request_data.get(
            "amount",
            0,
        )

        if (
            isinstance(
                amount,
                bool,
            )
            or not isinstance(
                amount,
                (int, float),
            )
        ):
            return self._trace_result(
                capability,
                action,
                AuthorizationResult(
                    False,
                    "invalid_budget_amount",
                ),
            )

        amount = float(amount)

        if (
            not math.isfinite(amount)
            or amount < 0
        ):
            return self._trace_result(
                capability,
                action,
                AuthorizationResult(
                    False,
                    "invalid_budget_amount",
                ),
            )

        root = self._delegation_root(
            capability
        )

        root_fingerprint = (
            capability_fingerprint(
                root
            )
        )

        try:
            self._delegation_budgets.reserve(
                root_fingerprint,
                float(amount),
            )

        except KeyError:
            return self._trace_result(
                capability,
                action,
                AuthorizationResult(
                    False,
                    "delegation_budget_not_configured",
                ),
            )

        except DelegationBudgetExceeded:
            return self._trace_result(
                capability,
                action,
                AuthorizationResult(
                    False,
                    "delegation_budget_exceeded",
                ),
            )

        return result

    # ========================================================
    # Authorization
    # ========================================================

    def _apply_denial(
        self,
        ctx: "_AuthorizationContext",
        result: AuthorizationResult,
    ) -> AuthorizationResult:
        """
        Single sink for ordinary denials raised by the gates.

        Mirrors the historical ``record_denial`` closure exactly: trace
        the result, record the runtime security/risk denial, memoize
        constraint/policy denials in the refusal state, and emit the
        DENIED lifecycle event.

        Gates whose denial must emit a *different* lifecycle event -- the
        refusal-state hit (which carries ``refusal_reason``) and the
        expired capability (which emits EXPIRED with ``expires_at``) --
        deliberately do not route through this sink; they record inline.
        """

        result = self._trace_result(
            ctx.capability,
            ctx.action,
            result,
        )

        if ctx.security_context is not None:
            ctx.security_context.record_denial()

        if ctx.risk_context is not None:
            ctx.risk_context.record_denial(
                ctx.capability.agent_id
            )

        if result.reason in {
            "constraint_denied",
            "policy_denied",
        }:
            ctx.refusal_state.record(
                agent=ctx.capability.agent_id,
                capability_fingerprint=ctx.fingerprint,
                action=ctx.action,
                request=ctx.request_data,
                reason=result.reason,
            )

        self.lifecycle.record(
            LifecycleEventType.DENIED,
            ctx.fingerprint,
            agent_id=ctx.capability.agent_id,
            capability=ctx.capability.capability,
            issuer=ctx.capability.issuer,
            reason=result.reason,
            details={
                "action": ctx.action,
                "request": deepcopy(
                    ctx.request_data
                ),
            },
        )

        return result

    def _gate_refusal(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        capability = ctx.capability

        if ctx.refusal_scope == "action":
            refusal = ctx.refusal_state.check_action(
                agent=capability.agent_id,
                capability_fingerprint=ctx.fingerprint,
                action=ctx.action,
            )
        elif ctx.refusal_scope == "request":
            refusal = ctx.refusal_state.check(
                agent=capability.agent_id,
                capability_fingerprint=ctx.fingerprint,
                action=ctx.action,
                request=ctx.request_data,
            )
        else:
            return self._trace_result(
                capability,
                ctx.action,
                AuthorizationResult(
                    False,
                    "invalid_refusal_scope",
                ),
            )

        if refusal is not None:
            result = self._trace_result(
                capability,
                ctx.action,
                AuthorizationResult(
                    False,
                    "refusal_state",
                ),
            )

            if ctx.security_context is not None:
                ctx.security_context.record_denial()

            if ctx.risk_context is not None:
                ctx.risk_context.record_denial(
                    capability.agent_id
                )

            self.lifecycle.record(
                LifecycleEventType.DENIED,
                ctx.fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                reason=result.reason,
                details={
                    "action": ctx.action,
                    "request": deepcopy(
                        ctx.request_data
                    ),
                    "refusal_reason": refusal.reason,
                },
            )

            return result

        return None

    def _gate_risk(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        if (
            ctx.risk_context is not None
            and not ctx.risk_context.can_authorize(
                ctx.capability.agent_id
            )
        ):
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "risk_state_revoked",
                ),
            )

        return None

    def _gate_issuer(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        if not self.is_issuer_trusted(
            ctx.capability.issuer
        ):
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "untrusted_issuer",
                ),
            )

        return None

    def _gate_revocation(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        if self.is_effectively_revoked(
            ctx.capability
        ):
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "capability_revoked",
                ),
            )

        return None

    def _gate_time(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        capability = ctx.capability

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
                    result = self._trace_result(
                        capability,
                        ctx.action,
                        AuthorizationResult(
                            False,
                            "expired",
                        ),
                    )

                    if ctx.security_context is not None:
                        ctx.security_context.record_denial()

                    if ctx.risk_context is not None:
                        ctx.risk_context.record_denial(
                            capability.agent_id
                        )

                    self.lifecycle.record(
                        LifecycleEventType.EXPIRED,
                        ctx.fingerprint,
                        agent_id=capability.agent_id,
                        capability=capability.capability,
                        issuer=capability.issuer,
                        reason=result.reason,
                        details={
                            "action": ctx.action,
                            "request": deepcopy(
                                ctx.request_data
                            ),
                            "expires_at": (
                                capability.expires_at
                            ),
                        },
                    )

                    return result

                if now < capability.issued_at:
                    return self._apply_denial(
                        ctx,
                        AuthorizationResult(
                            False,
                            "not_yet_valid",
                        ),
                    )

        return None

    def _resolve_delegation_authority(
        self,
        capability: Capability,
    ) -> DelegationAuthority:
        """Resolve the canonical North Star delegation authority.

        Wraps the established SDK lineage resolution
        (``_authorization_chain``) in North Star's immutable
        :class:`DelegationAuthority`. This is the single resolver shared
        by the authoritative delegation-chain gate and the observational
        North Star delegation phase, so both paths agree on exactly the
        same effective lineage.

        ``from_chain`` is total on a successfully resolved chain: the
        chain is always non-empty (it starts with the requested
        capability), every element is a ``Capability`` from the registry,
        and the lineage resolver guarantees distinct fingerprints. Its
        empty/type/cycle validation is therefore unreachable here, so
        wrapping introduces no new failure mode. A lineage-resolution
        failure still raises out of ``_authorization_chain`` first, with
        the established exception type and message.
        """

        return DelegationAuthority.from_chain(
            self._authorization_chain(
                capability
            )
        )

    def _gate_delegation_chain(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        try:
            ctx.delegation_authority = (
                self._resolve_delegation_authority(
                    ctx.capability
                )
            )
        except (
            ValueError,
            TypeError,
        ) as exc:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    f"delegation_chain_error: {exc}",
                ),
            )

        return None

    def _gate_delegation_monotonicity(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        """Enforce authority monotonicity across the delegation chain.

        Verifies that each child capability in the delegation chain is
        structurally narrower than or equal to its parent. This prevents
        delegates from widening the scope of their authority.
        """
        authority = ctx.delegation_authority
        if authority is None:
            return None

        capabilities = authority.capabilities
        if len(capabilities) <= 1:
            return None

        for i in range(len(capabilities) - 1):
            parent = capabilities[i]
            child = capabilities[i+1]

            res = is_narrower_than(parent, child)
            if not res.monotonic:
                return self._apply_denial(
                    ctx,
                    AuthorizationResult(
                        False,
                        f"delegation_widening: {res.reason}",
                    ),
                )

        return None

    def _gate_delegation_depth(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        """Enforce the optional delegation-depth ceiling.

        Consumes the canonical ``DelegationAuthority`` published by
        ``_gate_delegation_chain``, which always runs first in the gate
        ordering and populates ``ctx.delegation_authority`` before it
        returns ``None``; whenever this gate runs the authority is
        therefore present and valid. The policy is opt-in: when
        ``max_delegation_depth`` is ``None`` the gate is a no-op, so the
        v1.5 baseline is unaffected. This is an authorization-time policy
        distinct from the fixed structural cap enforced at lineage
        registration. Attenuation and cryptographic authority remain the
        job of the downstream crypto gate and are not duplicated here.
        """

        max_depth = self.max_delegation_depth

        if max_depth is None:
            return None

        if ctx.delegation_authority.depth > max_depth:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "delegation_depth_exceeded",
                ),
            )

        return None

    def _gate_cryptographic_authority(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        capability = ctx.capability

        # Authorize the requested capability first so the success
        # result starts with a trace for the capability the caller
        # actually presented.
        result = authorize(
            capability,
            ctx.action,
            ctx.request_data,
            verifier=self.verifier,
        )

        if not result.allowed:
            return self._apply_denial(
                ctx,
                result,
            )

        # Every ancestor in the delegation chain must also authorize
        # the same action. An ancestor denial is attributed to the
        # requested child capability in the outward-facing trace. The
        # ancestors are the canonical delegation authority beyond the
        # requested capability at index 0.
        for chain_capability in ctx.delegation_authority.capabilities[1:]:
            chain_result = authorize(
                chain_capability,
                ctx.action,
                ctx.request_data,
                verifier=self.verifier,
            )

            if not chain_result.allowed:
                return self._apply_denial(
                    ctx,
                    chain_result,
                )

        ctx.result = result

        return None

    def _gate_transaction(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        """Terminal gate: the semantic-chain + security-budget transaction.

        This is the one gate that always returns a decision (never
        ``None``). It is reached only after every upstream gate has
        passed, and it either denies -- aborting any in-flight semantic
        transaction -- or records the successful use and returns the
        authorized result.

        It is deliberately a single atomic method rather than a set of
        sub-phases: a semantic transaction opened by
        ``begin_authorization`` must be aborted on every subsequent denial
        and committed exactly once on success, so the transaction handle
        and its abort/commit helpers must share one scope. Splitting them
        across phases would risk a missed abort or a double commit.
        Denials funnel through the same single-sourced sink
        (``_apply_denial``) as every other gate.
        """

        def record_denial(
            result: AuthorizationResult,
        ) -> AuthorizationResult:
            return self._apply_denial(
                ctx,
                result,
            )

        capability = ctx.capability
        action = ctx.action
        request_data = ctx.request_data
        fingerprint = ctx.fingerprint
        chain_id = ctx.chain_id
        result = ctx.result

        # Re-check revocation atomically before consuming any budgets.
        # This closes the TOCTOU window between the revocation gate and
        # the final decision.
        if self.is_effectively_revoked(ctx.capability):
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "capability_revoked",
                ),
            )

        semantic_transaction = None

        # ----------------------------------------------------
        # Runtime semantic chain context
        # ----------------------------------------------------

        if ctx.semantic_context is not None:

            try:
                semantic_transaction = (
                    ctx.semantic_context.begin_authorization(
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

        if ctx.security_context is not None:

            if (
                ctx.security_context.agent
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
                ctx.security_context.authorize_and_record(
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
            abort_semantic_transaction()
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

        return self._trace_result(
            capability,
            action,
            result,
        )

    def _authorization_gate_phases(self):
        """
        The canonical, ordered authorization gates.

        Each gate is a thin adapter around an existing security
        mechanism. A gate returns an ``AuthorizationResult`` to
        terminate authorization, or ``None`` to continue to the next
        gate. The ordering *is* the policy:

            refusal memo -> runtime risk -> issuer trust -> revocation
            -> time validity -> delegation-chain resolution
            -> delegation-depth policy
            -> cryptographic + effective-delegation verification
            -> semantic-chain + security-budget transaction

        The final gate is the transactional tail (semantic-chain
        begin/commit and the runtime security budget). Unlike the
        upstream gates it always returns a decision, so it terminates the
        pipeline: it either denies -- aborting any in-flight semantic
        transaction -- or records the successful use and returns the
        authorized result.
        """

        return (
            self._gate_refusal,
            self._gate_risk,
            self._gate_issuer,
            self._gate_revocation,
            self._gate_time,
            self._gate_delegation_chain,
            self._gate_delegation_monotonicity,
            self._gate_delegation_depth,
            self._gate_cryptographic_authority,
            self._gate_transaction,
        )

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
            outcome = AuthorizationResult(
                False,
                "invalid_capability",
            )

            self._record_flight_event(
                EventType.AUTHORIZATION,
                {
                    "action": str(action),
                    "allowed": False,
                    "reason": "invalid_capability",
                    "capability": None,
                    "tool": None,
                    "issuer": None,
                    "depth": None,
                    "chain": None,
                    "request": dict(
                        {}
                        if request is None
                        else deepcopy(request)
                    ),
                },
            )

            return outcome

        ctx = _AuthorizationContext(
            capability=capability,
            action=action,
            request_data=(
                {}
                if request is None
                else deepcopy(request)
            ),
            fingerprint=capability_fingerprint(
                capability
            ),
            refusal_scope=refusal_scope,
            chain_id=chain_id,
            risk_context=self.risk_context,
            security_context=self.security_context,
            semantic_context=self.semantic_context,
            refusal_state=self.refusal_state,
        )

        # North Star owns the ordering: run each canonical gate in
        # sequence and terminate on the first that returns a decision.
        # The terminal transaction gate always returns a decision, so the
        # loop always terminates within it; the trailing return is a
        # fail-closed guard against a misconfigured (e.g. empty) gate
        # tuple and is unreachable in the canonical pipeline.
        for gate in (
            self._authorization_gate_phases()
        ):
            outcome = gate(ctx)
            if outcome is not None:
                self._record_flight_authorization(
                    ctx,
                    outcome,
                )
                return outcome

        outcome = AuthorizationResult(
            False,
            "internal_error",
        )
        self._record_flight_authorization(
            ctx,
            outcome,
        )
        return outcome

    def authorize_continuous(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> AuthorizationResult:
        """
        Authorize and register the decision for continuous revalidation.
        Returns the authorization result.
        """
        if self.continuous_auth_engine is None or self.continuous_auth_monitor is None:
            # Fallback to standard authorization if continuous auth is not configured
            return self.authorize(
                capability,
                action,
                request,
                refusal_scope=refusal_scope,
                chain_id=chain_id,
            )

        # 1. Authorize and capture context snapshot
        result = self.continuous_auth_engine.authorize_with_context(
            capability,
            action,
            request or {},
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        # 2. Register with the monitor
        from firewall.capability import capability_fingerprint
        fp = capability_fingerprint(capability)

        # Request hash for the monitor
        import hashlib, json
        req_str = json.dumps(request or {}, sort_keys=True, separators=(",", ":"))
        req_hash = hashlib.sha256(req_str.encode()).hexdigest()[:32]

        # Cache key is generated by the engine
        cache_key = self.continuous_auth_engine._cache_key(capability, action, request or {})

        self.continuous_auth_monitor.monitor_decision(
            capability_fingerprint=fp,
            action=action,
            request=request or {},
            request_hash=req_hash,
            cache_key=cache_key,
        )

        return result

    def revalidate(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        trigger: Optional[RevalidationTrigger] = None,
    ) -> Optional[RevalidationResult]:
        """
        Manually trigger revalidation of a previous authorization decision.
        """
        if self.continuous_auth_engine is None:
            return None

        return self.continuous_auth_engine.revalidate(
            capability,
            action,
            request or {},
            trigger=trigger or RevalidationTrigger.EXPLICIT_REQUEST,
        )

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

            self._record_flight_event(
                EventType.SECURITY_STATE,
                {
                    "change": "replay_detected",
                    "agent": agent,
                    "nonce": nonce,
                },
                agent=capability.agent_id,
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
        if self.continuous_auth_monitor is not None:
            self.continuous_auth_monitor.stop_periodic_monitoring()

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
