
from copy import deepcopy
from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional
import uuid

from firewall.authorization import (
    AuthorizationResult,
    authorize,
)

from firewall.aegis import (
    AegisController,
    AuthorityEnvelope,
    bottom_envelope,
    chain_envelope,
    local_envelope,
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
    UNKNOWN,
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
        continuous_auth_identity_registry=None,
        continuous_auth_posture_engine=None,
        continuous_auth_trust_graph=None,
        continuous_auth_provenance_registry=None,
        continuous_auth_task_registry=None,
        continuous_auth_incident_provider: Optional[
            Callable[[str], bool]
        ] = None,
        continuous_auth_environment_provider: Optional[
            Callable[[], dict]
        ] = None,
        continuous_auth_policy_version_provider: Optional[
            Callable[[], str]
        ] = None,
        aegis: Optional[AegisController] = None,
        aegis_enabled: bool = False,
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
        #
        # The engine does not authorize. It re-runs this SDK's
        # authorize() and compares the new decision against the
        # cached original, so the canonical boundary stays the only
        # authority. What it needs from us is the *state* to watch:
        # if a subsystem is not wired in, the corresponding change
        # class is simply undetectable, which is why every one of
        # these is injectable rather than silently defaulted.
        #
        # ``policy_version_provider`` defaults to a fingerprint of
        # this SDK's own authorization policy surface (see
        # ``_authorization_policy_version``) so POLICY_CHANGED is
        # detectable without an external policy engine. Callers with
        # a real policy engine should inject its version instead.

        self.continuous_auth_engine = None
        self.continuous_auth_monitor = None

        if continuous_auth_config is not None:
            self.continuous_auth_engine = ContinuousAuthorizationEngine(
                sdk=self,
                identity_registry=continuous_auth_identity_registry,
                task_registry=continuous_auth_task_registry,
                posture_engine=continuous_auth_posture_engine,
                trust_graph=continuous_auth_trust_graph,
                risk_context=self.risk_context,
                provenance_registry=continuous_auth_provenance_registry,
                policy_version_provider=(
                    continuous_auth_policy_version_provider
                    or self._authorization_policy_version
                ),
                environment_provider=continuous_auth_environment_provider,
                incident_provider=continuous_auth_incident_provider,
            )
            self.continuous_auth_monitor = ContinuousAuthorizationMonitor(
                engine=self.continuous_auth_engine,
                sdk=self,
                config=continuous_auth_config,
            )

        # ----------------------------------------------------
        # v2.4 Project Aegis
        # ----------------------------------------------------
        #
        # Opt-in, and off by default. When ``self.aegis`` is ``None`` the
        # Aegis gate abstains on every request, so a deployment that does
        # not ask for Aegis runs the v2.3 decision sequence unchanged --
        # not "equivalently", but the same gates in the same order.
        #
        # Even switched on, the only state Aegis contributes to a decision
        # is a ``Restriction``, whose sole effect is to produce a deny
        # reason. The controller cannot construct an
        # ``AuthorizationResult`` (AUTHORIZATION_UNIQUENESS restricts that
        # to this file and ``firewall/authorization.py``), so there is no
        # shape Aegis state can take that causes an allow.
        #
        # The revoke hook is wired to this SDK's own ``revoke`` so an
        # executed REVOKE reaches the revocation registry -- the actual
        # authority on revocation -- rather than being recorded only in
        # Aegis. It is deliberately the one hook wired automatically: it
        # reduces authority, and reduction needs no caller consent.

        self.aegis = aegis

        if self.aegis is None and aegis_enabled:
            self.aegis = AegisController()

        if self.aegis is not None:
            if not isinstance(
                self.aegis,
                AegisController,
            ):
                raise TypeError(
                    "aegis must be an AegisController"
                )

            self.aegis.attach_hooks(
                revoke=self._aegis_revoke,
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

        # ----------------------------------------------------
        # Continuous authorization: start the sweep last
        # ----------------------------------------------------
        #
        # Deliberately the final statement of __init__. The monitor
        # thread calls back into authorize(), which reads subsystems
        # constructed above this point (self.revocation among them).
        # Starting it next to the engine construction would let the
        # sweep observe a half-built SDK and raise inside the probe
        # path, which the engine would -- correctly -- read as an
        # unavailable security dependency and deny on. The visible
        # symptom would be spurious revocations at startup; the cause
        # would be this ordering. Keep it here.
        #
        # No-ops when enable_periodic_revalidation is False.

        if self.continuous_auth_monitor is not None:
            self.continuous_auth_monitor.start_periodic_monitoring()

    # ========================================================
    # v1.8 flight recorder
    # ========================================================

    @property
    def flight_recorder(
        self,
    ) -> Optional[FlightRecorder]:
        """The optional v1.8 flight recorder, if attached."""

        return self._recorder

    @staticmethod
    def _flight_request(
        request: Any,
    ) -> dict:
        """The request projection a pre-gate flight record carries.

        The two argument-validation branches of ``authorize()`` and the
        two context-construction guards all run before a
        ``_AuthorizationContext`` exists, so they cannot use
        ``_evidence_request``. They face the same hazard: the request is a
        caller object, and copying one that refuses to be copied used to
        raise out of a *denial* path. The record degrades; the denial
        stands.
        """

        if request is None:
            return {}

        try:
            return dict(
                deepcopy(request)
            )

        except Exception as error:  # noqa: BLE001 - a request is not a verdict
            return {
                "uncopyable_request": type(
                    error
                ).__name__
            }

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
        """
        Remove a key from issuance.

        A retired key can no longer sign: it stops being the active
        key and :meth:`issue` refuses once no active key remains.

        Capabilities it already signed keep verifying. That is what
        makes :meth:`rotate_key` usable -- rotation retires the
        outgoing key, and invalidating its signatures would kill every
        capability in flight at that moment.

        Retirement is therefore **not** containment for a stolen key.
        Anyone holding the private key can still sign new capabilities
        that this SDK will accept, because verification asks whether
        the signature is genuine and the issuer trusted, not whether
        the key is still in the issuance rotation. To stop a
        compromised signer, revoke its issuer with
        :meth:`revoke_issuer`, which refuses every capability under
        that issuer with ``untrusted_issuer``; revoke the affected
        capabilities to withdraw the ones already handed out.
        """

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

    def _issuance_timestamp(self) -> float:
        """The boundary's own clock, for stamping a new capability.

        Reads the same attribute ``_gate_time`` reads, so that the start of
        a validity window and the comparison against it come from one
        source. Refuses rather than substituting wall time, for the reason
        given in :meth:`issue`.
        """

        clock = getattr(
            self.verifier,
            "clock",
            None,
        )

        if not callable(clock):
            raise ValueError(
                "cannot issue: the verifier exposes no clock, so "
                "issued_at cannot be stamped in the time base the "
                "boundary compares against"
            )

        try:
            issued_at = float(clock())
        except Exception as error:  # noqa: BLE001 - reported, never swallowed
            raise ValueError(
                "cannot issue: the clock could not be read "
                f"({type(error).__name__}: {error})"
            ) from error

        if not math.isfinite(issued_at):
            raise ValueError(
                "cannot issue: the clock returned a non-finite reading"
            )

        return issued_at

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
        """Sign a new root capability.

        ``issued_at`` defaults to *this SDK's* clock -- the same reading
        ``_gate_time`` compares against -- and not to wall time. One
        validity window must be measured in one time base. Before v2.5
        this path let ``sign_capability`` default ``issued_at`` to
        ``time.time()`` while the boundary read the injected clock, so a
        deployment or test that supplied a clock got a window whose start
        and whose comparison came from different sources. With a clock
        behind wall time a freshly issued capability was
        ``not_yet_valid``; with either skew the window the boundary
        honoured was displaced from the window the capability's own
        timestamps declare. ``mint_session_capability`` already stamped
        from this clock, so this makes the two issuance paths agree.

        A clock that cannot be read is a refusal to issue, not a fallback
        to wall time: a capability stamped in a base the boundary cannot
        compare against is worse than no capability. Issuance is not the
        authorization boundary, so raising here is the fail-closed
        outcome.
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

        if issued_at is None:
            issued_at = self._issuance_timestamp()

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

    def known_capabilities(
        self,
    ) -> Mapping[str, Capability]:
        """Read-only view of every capability this SDK has minted.

        The registry is part of the authorization data plane: the
        ancestor walk in ``_authorization_chain`` resolves lineage
        fingerprints through it, so an entry that is replaced or removed
        changes which parent constraints a delegated capability is held
        to. Subsystems that need to enumerate capabilities -- monitors,
        containment, the read-only UI projection, the simulator --
        therefore get a ``MappingProxyType`` rather than the live dict.
        The proxy refuses ``__setitem__``/``__delitem__``, so a caller
        cannot inject a forged parent or delete an inconvenient
        ancestor, and it stays a live view so a caller cannot pin a
        stale snapshot past a revocation.

        ``Capability`` is a frozen dataclass, so the values are
        immutable too; the only mutable thing reachable from here was
        the mapping itself.

        CONTROL_PLANE_INTEGRITY (see :mod:`firewall.invariants`)
        enforces that nothing outside this module reaches for
        ``_capability_registry`` directly.
        """

        return MappingProxyType(
            self._capability_registry
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

        The resolved chain is then reconciled against each capability's
        *signed* ``parent_fingerprint``. Two representations of the same
        fact exist here -- the signature covers the parent a capability
        was delegated from, and the lineage registry records the parent
        it is currently bound to -- and only one of them is
        cryptographic. Where they disagree, the signature wins and
        authorization fails closed; see
        ``_verify_signed_lineage_agreement``.
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

        self._verify_signed_lineage_agreement(
            chain
        )

        return tuple(chain)

    @staticmethod
    def _verify_signed_lineage_agreement(
        chain: list[Capability],
    ) -> None:
        """Require the registered lineage to match the signed lineage.

        ``delegate_capability`` binds the parent's fingerprint into the
        child's signed payload. The lineage registry holds the same edge
        as mutable state: it is populated by ``delegate``/``attenuate``,
        rehydrated from the delegation store at construction, and
        writable by anything holding the SDK. The signature is the only
        one of the two an attacker cannot rewrite, so it is the one that
        decides.

        Two disagreements are refused:

        * **A signed parent with no resolved parent.** Without this, a
          delegated capability whose lineage edge is absent -- never
          registered, dropped by a store, or cleared -- is silently
          promoted to a root. That is not a narrowing. It detaches the
          capability from transitive revocation of its ancestors and
          from the cumulative lineage budget the root owns, both of
          which are enforced by walking the registry. A capability that
          says under signature "I am a delegate" must never authorize as
          a root.

        * **A signed parent that is not the resolved parent.** The
          monotonicity gate and the effective-authority intersection
          both read the resolved chain. Binding a legitimately signed
          child to some *other*, wider parent leaves the signature
          intact while widening what the child is checked against.

        The reverse asymmetry is deliberate: a resolved parent with no
        signed ``parent_fingerprint`` is allowed. Attenuated children
        (``attenuate_capability`` does not set the field) are the normal
        case, and an extra ancestor can only add constraints to the
        intersection and widen the reach of revocation -- it restricts,
        so it cannot be an escalation path.

        Raises ``ValueError``, which ``_gate_delegation_chain`` converts
        into a ``delegation_chain_error`` denial. Deliberately not a new
        gate: the chain resolver is the single place both the
        authoritative gate and North Star's observational phase read
        lineage from, so enforcing here keeps one resolver and one
        verdict.
        """

        for index, child in enumerate(chain):
            claimed_parent = getattr(
                child,
                "parent_fingerprint",
                None,
            )

            if claimed_parent is None:
                continue

            if index + 1 >= len(chain):
                raise ValueError(
                    "capability is signed as a delegation of "
                    "another capability but no delegation parent "
                    "is registered"
                )

            resolved_parent = capability_fingerprint(
                chain[index + 1]
            )

            if claimed_parent != resolved_parent:
                raise ValueError(
                    "capability parent_fingerprint does not match "
                    "its registered delegation parent"
                )

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

        Calling this again for the same lineage adjusts the ceiling
        and leaves the consumed total alone. Reconfiguration is not a
        reset: restoring an exhausted lineage's allowance through an
        administrative call would let the control plane grant spend
        that no capability, signature or delegation ever authorized.
        A ceiling set below the amount already consumed takes effect
        and admits nothing further.
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

        try:
            amount = float(amount)
        except OverflowError:
            # An int too large to convert. It cannot be reserved against a
            # float budget, and refusing it is the same answer the ceiling
            # would give -- reached without an exception escaping the
            # boundary.
            return self._trace_result(
                capability,
                action,
                AuthorizationResult(
                    False,
                    "invalid_budget_amount",
                ),
            )

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

    @staticmethod
    def _read_security_state(
        read: Callable[[], Any],
    ) -> tuple[Any, Optional[str]]:
        """Read one piece of security state; report unreadability.

        Returns ``(value, None)`` on success and ``(None, type_name)`` when
        the read raised. Every dependency the gates consult is injectable
        and several of the bundled ones are backed by persistence that can
        fail on its own -- a closed or unwritable ``SQLiteRevocationStore``
        raises out of ``is_revoked``, for one. Before this helper existed
        such a failure propagated out of ``authorize()``, which left the
        caller holding an exception instead of a verdict; a caller that
        wraps the boundary in ``except Exception`` and continues has then
        been handed an unauthorized request with no verdict attached.

        The caller turns the reported failure into a denial. Unreadable is
        never treated as permissive: an unanswerable security question is
        a denial, exactly as ``_gate_aegis`` already treats an unreadable
        Aegis store. This helper deliberately does not decide anything
        itself -- it only converts a raise into a value the gate can act
        on, so the gate remains the only thing producing a result.
        """

        try:
            return read(), None

        except Exception as error:  # noqa: BLE001 - unreadable is a denial
            return None, type(error).__name__

    @staticmethod
    def _write_evidence(
        write: Callable[[], None],
    ) -> Optional[str]:
        """Emit one evidence record; report a failure rather than raising.

        Returns ``None`` on success and the exception's type name when the
        write failed. Evidence is the record of a decision, not the
        decision, so a failed write must not be able to replace a verdict
        with an exception -- an unwritable audit log used to defeat every
        denial the gates could produce, including the hostile-input
        denials ``FAIL_CLOSED`` exists to guarantee.

        The failure is *contained*, not discarded. Every caller either
        surfaces it in the returned result (denials carry it as
        ``trace["evidence_error"]``) or converts it into a denial (a
        successful authorization that cannot be recorded is refused). What
        this cannot do is make the lost record reappear; see the stated
        non-guarantee in ``docs/v2.5-boundary.md``.
        """

        try:
            write()

        except Exception as error:  # noqa: BLE001 - evidence loss is not a verdict
            return type(error).__name__

        return None

    @staticmethod
    def _note_evidence_failures(
        result: AuthorizationResult,
        failures: "list[Optional[str]]",
    ) -> AuthorizationResult:
        """Record on a denial that some of its evidence could not be written.

        The verdict is untouched: a denial whose audit record failed is
        still that denial, and re-deciding it on the strength of a
        telemetry fault would be a security change driven by an
        observability fault. The failure is attached to the trace so it is
        visible to the caller rather than silently dropped.
        """

        seen = [name for name in failures if name]

        if seen and isinstance(
            result.trace,
            dict,
        ):
            result.trace["evidence_error"] = ",".join(seen)

        return result

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

        Every side effect here is an evidence write, and every one of them
        is contained: this sink produces the denial that the gates already
        decided on, and no failure of the recording machinery may turn that
        denial into an exception. That was reachable with bundled
        components only -- a closed ``SQLiteLifecycleStore`` made every
        FAIL_CLOSED probe raise instead of deny.
        """

        result = self._trace_result(
            ctx.capability,
            ctx.action,
            result,
        )

        failures: list[Optional[str]] = []

        if ctx.security_context is not None:
            failures.append(
                self._write_evidence(
                    ctx.security_context.record_denial
                )
            )

        if ctx.risk_context is not None:
            failures.append(
                self._write_evidence(
                    lambda: ctx.risk_context.record_denial(
                        ctx.capability.agent_id
                    )
                )
            )

        if result.reason in {
            "constraint_denied",
            "policy_denied",
        }:
            failures.append(
                self._write_evidence(
                    lambda: ctx.refusal_state.record(
                        agent=ctx.capability.agent_id,
                        capability_fingerprint=ctx.fingerprint,
                        action=ctx.action,
                        request=ctx.request_data,
                        reason=result.reason,
                    )
                )
            )

        failures.append(
            self._write_evidence(
                lambda: self.lifecycle.record(
                    LifecycleEventType.DENIED,
                    ctx.fingerprint,
                    agent_id=ctx.capability.agent_id,
                    capability=ctx.capability.capability,
                    issuer=ctx.capability.issuer,
                    reason=result.reason,
                    details={
                        "action": ctx.action,
                        "request": self._evidence_request(
                            ctx
                        ),
                    },
                )
            )
        )

        return self._note_evidence_failures(
            result,
            failures,
        )

    @staticmethod
    def _evidence_request(
        ctx: "_AuthorizationContext",
    ) -> Any:
        """The request projection an evidence record carries.

        ``deepcopy`` is what keeps a recorded request from aliasing live
        caller state, but it is also a call into arbitrary user objects:
        anything in the request may define ``__deepcopy__`` or
        ``__reduce__``, and a value that refuses to be copied used to
        propagate out of the evidence write and past ``authorize()``. A
        request that cannot be copied is still worth recording, so the
        projection degrades to a description of the failure rather than
        taking the record -- or the verdict -- down with it.
        """

        try:
            return deepcopy(
                ctx.request_data
            )

        except Exception as error:  # noqa: BLE001 - a request is not a verdict
            return {
                "uncopyable_request": type(
                    error
                ).__name__
            }

    def _gate_refusal(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        capability = ctx.capability

        if ctx.refusal_scope == "action":
            refusal, unreadable = self._read_security_state(
                lambda: ctx.refusal_state.check_action(
                    agent=capability.agent_id,
                    capability_fingerprint=ctx.fingerprint,
                    action=ctx.action,
                )
            )
        elif ctx.refusal_scope == "request":
            refusal, unreadable = self._read_security_state(
                lambda: ctx.refusal_state.check(
                    agent=capability.agent_id,
                    capability_fingerprint=ctx.fingerprint,
                    action=ctx.action,
                    request=ctx.request_data,
                )
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

        # A refusal state that cannot be consulted is a refusal state that
        # may be holding a refusal. Denying is the only reading of an
        # unanswerable question that cannot widen authority.
        if unreadable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "refusal_state_unavailable:"
                    f"{unreadable}",
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

            failures: list[Optional[str]] = []

            if ctx.security_context is not None:
                failures.append(
                    self._write_evidence(
                        ctx.security_context.record_denial
                    )
                )

            if ctx.risk_context is not None:
                failures.append(
                    self._write_evidence(
                        lambda: ctx.risk_context.record_denial(
                            capability.agent_id
                        )
                    )
                )

            failures.append(
                self._write_evidence(
                    lambda: self.lifecycle.record(
                        LifecycleEventType.DENIED,
                        ctx.fingerprint,
                        agent_id=capability.agent_id,
                        capability=capability.capability,
                        issuer=capability.issuer,
                        reason=result.reason,
                        details={
                            "action": ctx.action,
                            "request": self._evidence_request(
                                ctx
                            ),
                            "refusal_reason": refusal.reason,
                        },
                    )
                )
            )

            return self._note_evidence_failures(
                result,
                failures,
            )

        return None

    def _gate_risk(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        if ctx.risk_context is None:
            return None

        permitted, unreadable = self._read_security_state(
            lambda: ctx.risk_context.can_authorize(
                ctx.capability.agent_id
            )
        )

        if unreadable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "risk_state_unavailable:"
                    f"{unreadable}",
                ),
            )

        if not permitted:
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
        trusted, unreadable = self._read_security_state(
            lambda: self.is_issuer_trusted(
                ctx.capability.issuer
            )
        )

        # An issuer trust store that cannot answer has not said "trusted".
        if unreadable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "issuer_trust_unavailable:"
                    f"{unreadable}",
                ),
            )

        if not trusted:
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
        revoked, unreadable = self._read_security_state(
            lambda: self.is_effectively_revoked(
                ctx.capability
            )
        )

        # An unreadable revocation store is indistinguishable from one
        # holding a revocation for this capability, so it is treated as
        # one. The bundled SQLite backend raises on a closed connection.
        if unreadable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "revocation_state_unavailable:"
                    f"{unreadable}",
                ),
            )

        if revoked:
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
        """Deny anything whose validity window cannot be established.

        The expiry check used to be skipped -- silently, with the gate
        abstaining -- whenever ``now`` could not be read: no clock on the
        verifier, a clock that raised, or a clock returning ``nan``. With
        the bundled ``CapabilityVerifier`` that skip is invisible, because
        ``verify`` consults the same clock and refuses on its own. But the
        verifier is replaceable, and a *correct* custom one -- real Ed25519
        checks, forgeries and tampering both rejected -- that left time
        authority to this gate turned an expired capability into
        ``allowed=True reason=authorized``. Containment came from another
        component's private choice, not from this boundary.

        So an unestablishable "now" is a denial. Expiry is the check this
        gate exists to make, and a gate that cannot make it must not
        abstain into the allow path. Strictly narrowing: no bundled
        configuration reaches it, because ``CapabilityVerifier`` always
        carries a clock.
        """

        capability = ctx.capability

        clock = getattr(
            self.verifier,
            "clock",
            None,
        )

        if not callable(clock):
            now, unreadable = None, "no_clock"

        else:
            now, unreadable = self._read_security_state(
                lambda: float(clock())
            )

            if (
                unreadable is None
                and not math.isfinite(now)
            ):
                unreadable = "non_finite"

        if unreadable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "clock_unavailable:"
                    f"{unreadable}",
                ),
            )

        # ``expires_at`` and ``issued_at`` are ordinary attributes
        # of a caller-supplied object. A capability whose copy in
        # memory carries a non-numeric bound -- the shape
        # ``dataclasses.replace`` produces, and the shape
        # FAIL_CLOSED's own tampered probe relies on -- made these
        # comparisons raise ``TypeError`` out of ``authorize()``.
        # The cryptographic gate would have refused such a
        # capability a few gates later, so denying here changes
        # only the reason, never the outcome.
        bounds, unusable = self._read_security_state(
            lambda: (
                now
                >= capability.expires_at,
                now
                < capability.issued_at,
            )
        )

        if unusable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "capability_time_invalid:"
                    f"{unusable}",
                ),
            )

        expired, not_yet_valid = bounds

        if expired:
            result = self._trace_result(
                capability,
                ctx.action,
                AuthorizationResult(
                    False,
                    "expired",
                ),
            )

            failures: list[Optional[str]] = []

            if ctx.security_context is not None:
                failures.append(
                    self._write_evidence(
                        ctx.security_context.record_denial
                    )
                )

            if ctx.risk_context is not None:
                failures.append(
                    self._write_evidence(
                        lambda: ctx.risk_context.record_denial(
                            capability.agent_id
                        )
                    )
                )

            failures.append(
                self._write_evidence(
                    lambda: self.lifecycle.record(
                        LifecycleEventType.EXPIRED,
                        ctx.fingerprint,
                        agent_id=capability.agent_id,
                        capability=capability.capability,
                        issuer=capability.issuer,
                        reason=result.reason,
                        details={
                            "action": ctx.action,
                            "request": self._evidence_request(
                                ctx
                            ),
                            "expires_at": (
                                capability.expires_at
                            ),
                        },
                    )
                )
            )

            return self._note_evidence_failures(
                result,
                failures,
            )

        if not_yet_valid:
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
        """Resolve and publish the effective delegation authority.

        Resolution reaches the lineage registry, which is injectable and
        may be backed by persistence. ``ValueError`` and ``TypeError`` are
        the resolver's own vocabulary for a chain that does not hold
        together, and they keep the established reason string that callers
        and tests match on. Anything else is the *store* failing rather
        than the chain being wrong, and it used to propagate out of
        ``authorize()``; it is now the denial that an unresolvable lineage
        has always been. The North Star delegation phase already made
        exactly this distinction (``firewall/north_star.py``), so the
        canonical gate was the weaker of the two surfaces.
        """

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
        except Exception as error:  # noqa: BLE001 - unresolvable is a denial
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "delegation_chain_unavailable:"
                    f"{type(error).__name__}",
                ),
            )

        return None

    def _gate_delegation_monotonicity(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        """Enforce authority monotonicity across the delegation chain.

        Verifies that each child capability in the delegation chain is
        structurally narrower than or equal to its parent, so that a
        delegate cannot widen the authority it was granted.

        Chain ordering matters here. ``_authorization_chain`` returns the
        chain leaf-first: the requested capability is at index 0, its
        direct parent at index 1, and so on up to the root. So for each
        adjacent pair the *later* element is the parent and the *earlier*
        element is the child, which is the opposite of the index order.
        Passing them the other way round would assert that each parent is
        narrower than its own child, which is not the invariant and would
        both deny legitimate attenuation and admit real widening.
        """
        authority = ctx.delegation_authority
        if authority is None:
            return None

        capabilities = authority.capabilities
        if len(capabilities) <= 1:
            return None

        for index in range(len(capabilities) - 1):
            child = capabilities[index]
            parent = capabilities[index + 1]

            result = is_narrower_than(
                parent,
                child,
            )

            if not result.monotonic:
                return self._apply_denial(
                    ctx,
                    AuthorizationResult(
                        False,
                        f"delegation_widening: {result.reason}",
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

    def _aegis_chain_fingerprints(
        self,
        ctx: "_AuthorizationContext",
    ) -> tuple[str, ...]:
        """Every fingerprint an Aegis restriction could apply to.

        The requested capability first, then each delegation ancestor. A
        restriction on an ancestor must refuse a descendant's request --
        otherwise suspending a parent would leave its children usable,
        which is the authority-resurrection shape §3 rules out.

        Reads ``ctx.delegation_authority``, published by
        ``_gate_delegation_chain``, so the chain is the same one the
        cryptographic gate authorizes against rather than a second
        resolution that could disagree with it. Falls back to the
        requested fingerprint alone if the authority is absent, which
        cannot happen in the canonical ordering but must not raise here.
        """

        names = [ctx.fingerprint]

        authority = ctx.delegation_authority

        if authority is None:
            return tuple(names)

        try:
            members = authority.capabilities[1:]
        except (AttributeError, TypeError):
            return tuple(names)

        for ancestor in members:
            try:
                names.append(
                    capability_fingerprint(
                        ancestor
                    )
                )
            except Exception:  # noqa: BLE001 - a chain we cannot name
                # An unnameable ancestor cannot be checked against the
                # restriction store. Record nothing and let the gate deny:
                # see ``_gate_aegis``, which treats a short chain as
                # unreadable state rather than as an absence of
                # restrictions.
                return tuple(names) + ("",)

        return tuple(names)

    def _gate_aegis(
        self,
        ctx: "_AuthorizationContext",
    ) -> Optional[AuthorizationResult]:
        """Enforce active Aegis restrictions. Deny-only, by construction.

        Placement is load-bearing. The gate runs after the delegation
        chain is resolved -- it needs the ancestor fingerprints -- and
        before ``_gate_cryptographic_authority``, so a suspended grant is
        refused without spending signature verifications on it. It is the
        last gate that can deny on *adaptive* state; everything after it
        is cryptography and the transaction.

        Three properties make this incapable of granting authority:

        1. The only ``AuthorizationResult`` it constructs has a literal
           ``False`` as its first argument. MODEL_NON_AUTHORITY
           machine-checks that every result constructed outside the
           terminal allow function is a literal denial, so a later edit
           that made this conditional would fail the invariant run.
        2. Returning ``None`` is an abstention, not an allow. Six more
           gates run afterwards, including the cryptographic one.
        3. The restriction store is read *here*, inside the gate, rather
           than cached earlier in the request. A restriction written while
           this request was in flight is therefore seen by this request
           (§9's TOCTOU requirement), and ``_gate_transaction`` re-reads
           suspension a second time immediately before committing.

        Total. A controller that raises is treated as unreadable state and
        denies; it does not propagate out of ``authorize()``. That holds for
        a *supplied* controller too, not only the bundled one:
        ``FirewallSDK(aegis=...)`` accepts any object with the controller's
        shape, so every call this gate makes into it is guarded here rather
        than trusting the callee to be total.
        """

        controller = self.aegis

        if controller is None:
            return None

        try:
            if not controller.tracked():
                return None
        except Exception:  # noqa: BLE001 - unreadable state is a denial
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "aegis_state_unavailable",
                ),
            )

        fingerprints = self._aegis_chain_fingerprints(
            ctx
        )

        if any(not name for name in fingerprints):
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "aegis_state_unavailable",
                ),
            )

        try:
            reason = controller.restriction_reason(
                fingerprints,
                ctx.action,
                ctx.request_data,
            )
        except Exception as error:  # noqa: BLE001 - unreadable state is a denial
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    f"aegis_state_unavailable:{type(error).__name__}",
                ),
            )

        if reason is None:
            return None

        return self._apply_denial(
            ctx,
            AuthorizationResult(
                False,
                reason,
            ),
        )

    def _observe_aegis(
        self,
        ctx: "_AuthorizationContext",
        outcome: AuthorizationResult,
    ) -> None:
        """Let Aegis read the decision this SDK just made.

        Called from ``authorize`` after a decision exists, in the same
        position as the flight recorder and for the same reason: it cannot
        change an outcome that has already been returned. This is the only
        direction in which authority information crosses into Aegis, and
        the ``REVALIDATING -> ACTIVE`` edge accepts nothing else.

        Swallows every exception. Aegis is adaptive bookkeeping; a
        bookkeeping failure must not turn a completed authorization into
        an exception at the call site.
        """

        controller = self.aegis

        if controller is None:
            return

        try:
            controller.observe_authorization(
                ctx.fingerprint,
                outcome,
            )
        except Exception:  # noqa: BLE001 - observational, never fatal
            pass

    def _aegis_revoke(
        self,
        fingerprint: str,
    ) -> None:
        """Revoke by fingerprint, for Aegis's revoke hook.

        Aegis knows fingerprints, not capabilities, so this resolves one
        through the registry and calls the canonical ``revoke``. A
        fingerprint the registry does not know raises, which Aegis records
        as an unexecuted revocation and answers by suspending instead --
        it never latches ``REVOKED`` for a revocation that did not happen.
        """

        capability = self._capability_registry.get(
            fingerprint
        )

        if capability is None:
            raise KeyError(
                "aegis cannot revoke a capability this SDK has not seen"
            )

        self.revoke(
            capability,
            reason="aegis: adaptive revocation",
        )

    def authority_envelope(
        self,
        capability: Capability,
    ) -> AuthorityEnvelope:
        """The bounded authority this capability actually carries.

        Resolves the delegation chain here -- chain resolution is the
        SDK's job and depends on the capability registry and the lineage
        store -- and hands the resolved chain to
        ``firewall.aegis.envelope.chain_envelope``, which is pure. The
        aegis package therefore never reaches into SDK internals.

        The result is *sound and incomplete*: everything the envelope
        excludes, ``authorize()`` denies. The converse does not hold, and
        deliberately: the envelope decomposes constraints per dimension,
        which drops the cross-dimension ``and``/``or``/``not`` structure
        the boundary evaluates exactly. So an action the envelope admits
        may still be denied, and reading ``may_admit`` as permission is a
        category error -- ``AuthorityEnvelope.__bool__`` raises to make
        that hard to do by accident.

        Active restrictions are *not* folded in. The envelope describes
        the capability; restrictions are separate, later, and lifted
        separately. Use ``aegis.explain`` for the composed picture.

        A projection that cannot be computed yields the bottom envelope --
        which excludes everything -- rather than an exception or a
        permissive default. That covers an unresolvable chain and every
        dependency this method reads: revocation, issuer trust, and the
        fingerprinting of each member. All of them could raise before
        v2.5, in contradiction of the sentence above.

        The bottom is *sound* in each of those cases, which is worth
        stating because it is not self-evident. Soundness requires that
        whatever the envelope excludes, ``authorize()`` denies -- so
        answering "excludes everything" is only honest if the boundary
        would in fact refuse. It would: an unreadable read is a denial at
        the corresponding gate (``revocation_state_unavailable``,
        ``issuer_trust_unavailable``, ``invalid_capability``). Before the
        v2.5 gate fixes the boundary *raised* on those inputs instead of
        denying, and this bottom would have been a claim about a decision
        that was never made.

        The one raise kept is a non-``Capability`` argument, which is a
        caller error rather than unreadable state: there is no grant to
        project, so there is no envelope to return.
        """

        if not isinstance(
            capability,
            Capability,
        ):
            raise TypeError(
                "authority_envelope requires a Capability"
            )

        try:
            return self._authority_envelope(
                capability
            )
        except Exception as error:  # noqa: BLE001 - unreadable state is bottom
            return bottom_envelope(
                f"envelope_unavailable:{type(error).__name__}"
            )

    def _authority_envelope(
        self,
        capability: Capability,
    ) -> AuthorityEnvelope:
        """Project the envelope, assuming every read answers.

        Separated from :meth:`authority_envelope` so the guard there wraps
        the whole projection rather than one call in it. An earlier
        version caught ``ValueError`` around chain resolution alone, which
        left the revocation read, the trust read and the per-member
        fingerprinting able to raise.
        """

        try:
            chain = self._authorization_chain(
                capability
            )
        except ValueError as exc:
            return bottom_envelope(
                f"delegation_chain_unresolvable: {exc}"
            )

        # Head-only dimensions (``issuer_trusted``, the depth ceiling) are
        # passed for index 0 alone, matching the gates: ``_gate_issuer``
        # reads ``ctx.capability.issuer`` and ``_gate_delegation_depth``
        # reads the resolved depth, neither walking ancestors. Revocation
        # is per member, because ``is_effectively_revoked`` is.
        locals_ = []

        for position, member in enumerate(chain):
            fingerprint = capability_fingerprint(
                member
            )

            locals_.append(
                local_envelope(
                    member,
                    revoked=self.is_revoked(
                        member
                    ),
                    issuer_trusted=(
                        self.is_issuer_trusted(
                            member.issuer
                        )
                        if position == 0
                        else None
                    ),
                    depth_ceiling=(
                        self.max_delegation_depth
                        if position == 0
                        else None
                    ),
                    fingerprint=fingerprint,
                )
            )

        return chain_envelope(
            locals_
        )

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
        #
        # Guarded for the same reason the Aegis re-check below is guarded:
        # the store is injectable, the bundled SQLite backend raises on a
        # closed connection, and a re-check that raised here would leave
        # ``authorize()`` with no decision to return.
        revoked, unreadable = self._read_security_state(
            lambda: self.is_effectively_revoked(
                ctx.capability
            )
        )

        if unreadable is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "revocation_state_unavailable_at_commit:"
                    f"{unreadable}",
                ),
            )

        if revoked:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "capability_revoked",
                ),
            )

        # And re-check Aegis suspension, for the same reason and in the
        # same place. ``_gate_aegis`` ran before the cryptographic gate,
        # which performs signature verification over the whole chain and
        # is the slowest step in the pipeline -- a comfortable window for a
        # concurrent suspension to land in. Only suspension is re-checked,
        # not the full constraint evaluation: suspension is the total
        # refusal, it is the cheapest question the store answers, and this
        # runs inside the transaction where a slow check would widen the
        # very window it is closing.
        #
        # Guarded for the same reason ``_gate_aegis`` guards its own reads:
        # the controller is injectable, and a re-check that raised here
        # would leave ``authorize()`` with no decision to return, no flight
        # record, and no observation -- an outcome whose safety depends
        # entirely on what the caller does with an exception.
        if self.aegis is not None:
            try:
                suspended = self.aegis.suspended_in(
                    self._aegis_chain_fingerprints(
                        ctx
                    )
                )
            except Exception as error:  # noqa: BLE001 - unreadable is a denial
                return self._apply_denial(
                    ctx,
                    AuthorizationResult(
                        False,
                        "aegis_state_unavailable_at_commit:"
                        f"{type(error).__name__}",
                    ),
                )

            if suspended is not None:
                return self._apply_denial(
                    ctx,
                    AuthorizationResult(
                        False,
                        f"aegis_suspended_at_commit:{suspended}",
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
        #
        # The last thing an allow does is record that it happened. That
        # write used to be unguarded, and it is the one evidence write
        # whose failure cannot simply be noted: the semantic transaction
        # has committed and the security budget has been consumed, so a
        # raise here left the caller with no verdict *and* a permanently
        # smaller budget -- authority spent on a request that was never
        # answered, with nothing in the audit log to say so.
        #
        # An authorization that cannot be recorded is refused. That is the
        # narrow direction, and it is the only one available: returning the
        # allow would authorize an action that leaves no evidence behind,
        # which the evidence chain exists to prevent. The commit is not
        # rolled back -- the budget stays spent -- so this denial is
        # conservative rather than neutral, and it is documented as such.
        recording = self._write_evidence(
            lambda: self.lifecycle.record(
                LifecycleEventType.USED,
                fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
                issuer=capability.issuer,
                details={
                    "action": action,
                    "request": self._evidence_request(
                        ctx
                    ),
                },
            )
        )

        if recording is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    "evidence_unavailable:"
                    f"{recording}",
                ),
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
            -> delegation authority monotonicity
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
            self._gate_aegis,
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
                    "request": self._flight_request(
                        request
                    ),
                },
            )

            return outcome

        # An unusable action is a denial, not an exception.
        #
        # ``RefusalState.check_action`` validates its arguments and
        # raises ``ValueError`` on an empty action, so before this guard
        # ``authorize(cap, action="")`` raised from inside the first gate
        # instead of returning a verdict. That breaks the gate chain's
        # contract -- every gate returns a decision or abstains -- and it
        # hands a caller that wraps ``authorize`` in ``except Exception``
        # an unauthorized request with no verdict attached. Action names
        # can originate in untrusted tool output, so this is reachable
        # from outside.
        #
        # The correction is purely narrowing: the request was never
        # authorized before and is not authorized now, and the downstream
        # namespace check would have denied it anyway had the chain got
        # that far. It mirrors the ``invalid_capability`` branch above.
        # FAIL_CLOSED in :mod:`firewall.invariants` probes it.
        if (
            not isinstance(action, str)
            or not action.strip()
        ):
            outcome = AuthorizationResult(
                False,
                "invalid_action",
            )

            self._record_flight_event(
                EventType.AUTHORIZATION,
                {
                    "action": str(action),
                    "allowed": False,
                    "reason": "invalid_action",
                    "capability": capability.capability,
                    "tool": capability.tool,
                    "issuer": capability.issuer,
                    "depth": None,
                    "chain": None,
                    "request": self._flight_request(
                        request
                    ),
                },
            )

            return outcome

        # Building the context is the first thing that touches the
        # caller's objects, and both operations it performs can fail on a
        # hostile one: ``deepcopy`` calls into ``__deepcopy__`` and
        # ``__reduce__``, and fingerprinting canonicalises the capability's
        # fields as JSON, which a non-serialisable constraint value or a
        # self-referential one refuses. Both used to propagate out of
        # ``authorize()`` before a single gate had run.
        #
        # Neither is recoverable: a request that cannot be copied cannot be
        # evaluated against a constraint, and a capability that cannot be
        # fingerprinted cannot be looked up in any registry. So both are
        # denials of exactly the kind the two guards above already produce,
        # and they reuse those reasons rather than inventing new authority
        # semantics for a malformed argument.
        try:
            request_data = (
                {}
                if request is None
                else deepcopy(request)
            )
        except Exception as error:  # noqa: BLE001 - uncopyable is a denial
            outcome = AuthorizationResult(
                False,
                "invalid_request:"
                f"{type(error).__name__}",
            )

            self._record_flight_event(
                EventType.AUTHORIZATION,
                {
                    "action": str(action),
                    "allowed": False,
                    "reason": outcome.reason,
                    "capability": capability.capability,
                    "tool": capability.tool,
                    "issuer": capability.issuer,
                    "depth": None,
                    "chain": None,
                    "request": self._flight_request(
                        request
                    ),
                },
            )

            return outcome

        try:
            fingerprint = capability_fingerprint(
                capability
            )
        except Exception as error:  # noqa: BLE001 - unnameable is a denial
            outcome = AuthorizationResult(
                False,
                "invalid_capability:"
                f"{type(error).__name__}",
            )

            self._record_flight_event(
                EventType.AUTHORIZATION,
                {
                    "action": str(action),
                    "allowed": False,
                    "reason": outcome.reason,
                    "capability": None,
                    "tool": None,
                    "issuer": None,
                    "depth": None,
                    "chain": None,
                    "request": self._flight_request(
                        request
                    ),
                },
            )

            return outcome

        ctx = _AuthorizationContext(
            capability=capability,
            action=action,
            request_data=request_data,
            fingerprint=fingerprint,
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
                self._observe_aegis(
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

    def _authorization_policy_version(self) -> str:
        """Fingerprint of this SDK's own authorization policy surface.

        Continuous authorization needs to notice that policy changed. Most
        deployments have no external policy engine to ask, so the default
        is a hash of the policy inputs this SDK actually enforces:

        * the set of trusted issuers, and
        * the delegation depth ceiling.

        Scope is deliberately narrow and worth being explicit about. This
        covers exactly the two knobs above. It does *not* cover the
        contents of an external policy engine, per-tool rules, or
        constraint semantics -- a change to any of those will not move this
        fingerprint. A deployment with real policy must inject
        ``continuous_auth_policy_version_provider``; treating this default
        as complete coverage would be a false guarantee.

        Returns UNKNOWN when the inputs cannot be read. An unreadable
        policy surface must not hash to a stable value, because a stable
        value reads as "policy did not change".
        """
        try:
            issuers = sorted(self.issuer_trust_store.trusted_issuers())
            payload = json.dumps(
                {
                    "trusted_issuers": issuers,
                    "max_delegation_depth": self.max_delegation_depth,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        except Exception:
            return UNKNOWN

        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"sdk-policy:{digest[:32]}"

    def authorize_continuous(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> AuthorizationResult:
        """Authorize, then register the decision for continuous revalidation.

        The decision itself is produced by :meth:`authorize` -- reached
        through the engine only so that the state the decision was made
        under is snapshotted for later comparison. This method adds
        monitoring; it does not add an authorization path.

        One subtraction is applied on top: if a *configured* security
        dependency could not be read while the decision was taken, an allow
        is withheld. The engine already refused to confirm such a decision on
        revalidation, which left the first decision as the single permissive
        answer in the sequence -- allowed once, then denied by every
        revalidation of the same request. An attacker who can stop a probe
        answering would aim at exactly that window. Withholding here makes
        "will not report a live authority it cannot verify" true from the
        first decision onward.

        This can only ever narrow: the verdict starts as ``authorize()``'s
        and the only edit available is allow to deny.
        """
        if (
            self.continuous_auth_engine is None
            or self.continuous_auth_monitor is None
        ):
            # Continuous authorization is opt-in. Without it the caller
            # still gets a real decision from the canonical boundary --
            # they just get no revalidation.
            return self.authorize(
                capability,
                action,
                request,
                refusal_scope=refusal_scope,
                chain_id=chain_id,
            )

        request = request or {}

        result = self.continuous_auth_engine.authorize_with_context(
            capability,
            action,
            request,
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        result = self._withhold_on_degraded_dependencies(
            capability,
            action,
            request,
            result,
        )

        # Only allowed decisions carry live authority, and only live
        # authority can go stale. Registering denials would fill the
        # bounded monitor table with entries whose revalidation cannot
        # withdraw anything, evicting the decisions that matter.
        if result.allowed:
            self.continuous_auth_monitor.monitor_decision(
                capability_fingerprint=capability_fingerprint(capability),
                action=action,
                request=request,
                # Reuse the engine's hashing rather than recomputing it
                # here: two canonicalisations of the same request that
                # drift apart would silently split one decision into two
                # monitor entries, and the stale one would never be
                # revalidated against the live one.
                request_hash=self.continuous_auth_engine.request_hash(request),
                cache_key=self.continuous_auth_engine.cache_key(
                    capability, action, request
                ),
            )

        return result

    def _withhold_on_degraded_dependencies(
        self,
        capability: Capability,
        action: str,
        request: dict,
        result: AuthorizationResult,
    ) -> AuthorizationResult:
        """Withhold an allow taken while a configured dependency was blind.

        Reads the snapshot the engine recorded for this very decision rather
        than probing again: a second round of probes could report a different
        state from the one the decision was actually taken under, and the
        point is to describe *that* decision.

        A denial is returned untouched. Its own reason -- ``constraint_denied``,
        ``namespace_denied`` -- names what actually decided it, and replacing
        that with the degradation notice would lose the more specific fact
        without changing the outcome.
        """
        if not result.allowed:
            return result

        engine = self.continuous_auth_engine

        snapshot = engine.snapshot_for(
            capability,
            action,
            request,
        )

        if snapshot is None:
            # The engine caches every decision it takes, so this is only
            # reachable if the entry was evicted between the two calls. An
            # unreadable record of the state is itself not a state we can
            # confirm authority against.
            return AuthorizationResult(
                allowed=False,
                reason="security_context_unavailable",
                trace=self._degraded_trace(
                    result,
                    "security_context_unavailable",
                ),
            )

        allowed, degraded_reason = engine.effective_verdict(
            result,
            snapshot,
        )

        if degraded_reason is None:
            return result

        return AuthorizationResult(
            allowed=allowed,
            reason=degraded_reason,
            trace=self._degraded_trace(
                result,
                degraded_reason,
            ),
        )

    @staticmethod
    def _degraded_trace(
        result: AuthorizationResult,
        reason: str,
    ) -> dict:
        """The original decision's trace, re-labelled with the new reason.

        Keeping the capability, agent, action and tool identifiers means the
        audit record still names what was refused; overwriting ``reason``
        keeps the trace from disagreeing with the verdict it belongs to.
        """
        trace = dict(result.trace) if result.trace else {}
        trace["reason"] = reason
        return trace

    def revalidate(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        trigger: Optional[RevalidationTrigger] = None,
    ) -> RevalidationResult:
        """Re-evaluate a previous authorization decision against current state.

        Raises RuntimeError when continuous authorization is not configured.
        Returning ``None`` there would be indistinguishable from "checked,
        nothing changed", so a caller relying on this to keep authority
        fresh would read a missing subsystem as an all-clear.
        """
        if self.continuous_auth_engine is None:
            raise RuntimeError(
                "continuous authorization is not configured on this SDK; "
                "construct FirewallSDK with continuous_auth_config= to use "
                "revalidate()"
            )

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
        # Stop the sweep before anything else is torn down. The monitor
        # thread calls authorize(), which reads the stores closed below;
        # letting it outlive them would have it querying closed SQLite
        # handles. A stop that cannot be confirmed is reported rather
        # than ignored -- the alternative is closing the stores out from
        # under a thread we know is still running.
        monitor_error = None
        if self.continuous_auth_monitor is not None:
            try:
                stopped = self.continuous_auth_monitor.stop_periodic_monitoring()
            except Exception as exc:
                monitor_error = exc
            else:
                if not stopped:
                    monitor_error = RuntimeError(
                        "continuous authorization monitor did not stop within "
                        "its join timeout; it may still be running against "
                        "closed stores"
                    )

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

        if monitor_error is not None:
            raise monitor_error

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()
