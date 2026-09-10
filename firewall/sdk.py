
from copy import deepcopy
from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Sequence
import uuid

from firewall.authorization import (
    AuthorizationResult,
    authorize,
)

from firewall.authority_epoch import (
    AuthorityEpoch,
    EpochSample,
    bind_epoch,
)
from firewall.state_commit import (
    StateCommitJournal,
    bind_state_commit,
    record_state_commit,
    issuer_trust_reader,
    lineage_reader,
    revocation_reader,
)
from firewall.state_commit_store import SQLiteStateCommitStore

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
    SemanticBudgetExceeded,
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

from firewall.execution_lease import (
    DEFAULT_LEASE_TTL_SECONDS,
    ExecutionIdentityBoundError,
    ExecutionLease,
    ExecutionLeaseError,
    ExecutionLeaseOutcome,
    ExecutionLeaseStore,
    ExecutionState,
    IllegalTransitionError,
    canonical_request_digest,
    is_terminal,
    transition_allowed,
)
from firewall.execution_store import (
    SQLiteExecutionLeaseStore,
)

from firewall.effect import (
    DEFAULT_EFFECT_TTL_SECONDS,
    EffectAlreadyBoundError,
    EffectJournal,
    EffectJournalError,
    EffectOutcome,
    EffectResult,
    EffectState,
    IllegalEffectTransitionError,
    ReceiptKind,
    canonical_effect_digest,
)
from firewall.effect_store import (
    SQLiteEffectJournal,
)
from firewall.effect_verification import (
    STRUCTURAL_METHOD,
    VerificationJournal,
    VerificationJournalError,
    VerificationOutcome,
    VerificationRecord,
    VerificationResult,
    VerifierVerdict,
    canonical_evidence_digest,
    canonical_evidence_snapshot,
    evidence_package,
    structural_verifier,
    verification_outcome_of,
)
from firewall.verification_store import (
    SQLiteVerificationJournal,
)
from firewall.external_attestation import (
    ATTESTATION_VERSION,
    AttestationError,
    CONCLUSIVE_OUTCOMES,
    DEFAULT_MAX_AGE_SECONDS,
    STATEMENT_TYPE,
    SUPPORTED_ALGORITHMS,
    AttestationEnvelope,
    AttestationJournal,
    AttestationJournalError,
    AttestationOutcome,
    AttestationRecord,
    AttestationResult,
    ExternalIssuerError,
    ExternalIssuerKey,
    ExternalIssuerTrustStore,
    contradiction_between,
    freshness_failure,
    scope_mismatch,
    verify_envelope_signature,
)
from firewall.external_attestation_store import (
    SQLiteExternalAttestationStore,
)
from firewall.temporal import (
    DEFAULT_REGRESSION_TOLERANCE_SECONDS,
    TEMPORAL_ANOMALY_PREFIX,
    TemporalContext,
    TemporalError,
    TemporalGuard,
    bind_temporal,
)
from firewall.temporal_store import (
    SQLiteTemporalStore,
)
from firewall.lineage import (
    BINDING_FIELDS,
    PRIOR_STAGES,
    STAGE_ORDINAL,
    ExecutionLineage,
    LineageBindingError,
    LineageBrokenError,
    LineageConflictError,
    LineageError,
    LineageForkError,
    LineageJournal,
    LineageJournalError,
    LineageOutcome,
    LineageSealedError,
    LineageStage,
    LineageStageOrderError,
    LineageSubjectMismatchError,
    LineageUnknownError,
    canonical_binding,
    # Aliased on purpose: ``firewall.effect_verification`` exports a
    # ``canonical_evidence_digest`` of its own for the v2.9 claim snapshot,
    # and the two are different digests over different things. Importing this
    # one unaliased silently replaced that one in this module's namespace,
    # which made every verification of an effect row fail.
    canonical_evidence_digest as lineage_evidence_digest,
    completeness_problems,
)
from firewall.lineage_store import (
    SQLiteLineageStore,
)


#: Execution-continuity refusal reasons that mean the lease or the
#: authority it continues is permanently unusable, so the lease should be
#: moved to a terminal state rather than left for retry. Refusals *not*
#: in this set -- caller misuse, mismatched arguments, unreadable state --
#: leave the record where it is: a temporary inability to establish the
#: basis is a refusal of that progression, and a lease that was never
#: burned can be retried against state that has recovered. The asymmetry
#: is the safe one: nothing here can make a refusal into a pass.
EXECUTION_INVALIDATING_PREFIXES = (
    "capability_revoked",
    "issuer_untrusted",
    "capability_verification_failed",
    "lease_expired",
    "capability_expired",
    "not_yet_valid",
    "aegis_restricted",
    "aegis_suspended",
    "risk_state_revoked",
    "delegation_chain_changed",
    "delegation_chain_unavailable",
    "policy_version_changed",
    "policy_version_unavailable",
    "execution_epoch_diverged",
    "execution_widening_in_flight",
)


def _sdk_evidence(value: Any) -> Any:
    """The digestable projection of a journal row, for lineage evidence.

    A link commits to a *digest* of the row that justified its stage rather
    than to a copy of it, so the lineage holds no second account of what the
    effect journal, the verification journal or the attestation journal say.
    A row that cannot be projected is described by its type instead of
    raising: the lineage then commits to the fact that the evidence could not
    be named, which is a refusal the caller sees, rather than an exception
    thrown out of a progression that already happened.
    """

    projector = getattr(value, "to_dict", None)

    if callable(projector):
        try:
            return projector()
        except Exception:  # noqa: BLE001 - a row is not a verdict
            return {"unnameable_evidence": type(value).__name__}

    if isinstance(value, dict):
        return dict(value)

    return {"evidence": type(value).__name__}


def _execution_invalidating(reason: str) -> bool:
    return reason.startswith(EXECUTION_INVALIDATING_PREFIXES)


def _execution_terminal_for(reason: str) -> ExecutionState:
    """The terminal phase a burned lease should stop in.

    ``EXPIRED`` when the deadline passed; ``REVOKED`` when the authority
    basis no longer holds (revoked, suspended, untrusted, lineage or
    policy changed, epoch diverged); ``DENIED`` for everything else the
    caller may not proceed under.
    """
    if reason.startswith(
        ("lease_expired", "capability_expired")
    ):
        return ExecutionState.EXPIRED
    if reason.startswith(("not_yet_valid",)):
        return ExecutionState.DENIED
    if _execution_invalidating(reason):
        return ExecutionState.REVOKED
    return ExecutionState.DENIED


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

    ``entry_epoch`` is the exception to "bound once from the SDK": it is
    not a mechanism reference but an observation, taken by ``authorize``
    before the first gate runs and compared by the terminal gate before it
    allows. It is carried here because the two halves of that comparison
    live in different methods, and the value has to survive the trip
    without being re-read -- re-reading it would compare the epoch to
    itself and always agree. See :mod:`firewall.authority_epoch`.

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
    entry_epoch: Optional[EpochSample] = None
    #: The validated temporal context the request's time checks were taken
    #: in. Carried so the terminal gate can ask whether the verdict is
    #: still inside that context -- the same reason ``entry_epoch`` is
    #: carried, one dimension over.
    entry_temporal: Optional[TemporalContext] = None


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
        execution_lease_store: Optional[
            ExecutionLeaseStore
        ] = None,
        execution_store_path: Optional[
            str | Path
        ] = None,
        effect_journal: Optional[
            EffectJournal
        ] = None,
        effect_store_path: Optional[
            str | Path
        ] = None,
        verification_journal: Optional[
            VerificationJournal
        ] = None,
        verification_store_path: Optional[
            str | Path
        ] = None,
        attestation_journal: Optional[
            AttestationJournal
        ] = None,
        attestation_store_path: Optional[
            str | Path
        ] = None,
        external_issuer_trust_store: Optional[
            ExternalIssuerTrustStore
        ] = None,
        external_issuer_keys: Optional[
            Sequence[tuple[str, str, Any]]
        ] = None,
        require_external_attestation: bool = False,
        attestation_max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
        attestation_clock_skew_seconds: float = 0.0,
        temporal_guard: Optional[
            TemporalGuard
        ] = None,
        temporal_store_path: Optional[
            str | Path
        ] = None,
        temporal_tolerance_seconds: float = (
            DEFAULT_REGRESSION_TOLERANCE_SECONDS
        ),
        monotonic_clock=None,
        temporal_decision_budget_seconds: Optional[
            float
        ] = None,
        lineage_journal: Optional[
            LineageJournal
        ] = None,
        lineage_store_path: Optional[
            str | Path
        ] = None,
        require_lineage: bool = True,
        state_commit_store_path: Optional[
            str | Path
        ] = None,
        state_commit_store: Optional[Any] = None,
    ):
        # The authority epoch is created before anything else, including
        # argument validation, so that no code path can reach a store's
        # widening bracket while the attribute is missing. Stores are bound
        # to it at the end of __init__, once they all exist; widening that
        # happens *during* construction is uncounted by design -- nothing
        # is authorizing yet, so there is no in-flight verdict to protect.
        self.authority_epoch = AuthorityEpoch()

        # The temporal guard is created before anything else, for the same
        # reason the epoch is: no store may be used before the boundary
        # that audits its clock exists, and a store bound later would have
        # issued records with no anchors in the meantime. It needs only the
        # clock arguments and, when persistence is asked for, a path -- all
        # of which are available here.
        if (
            temporal_guard is not None
            and temporal_store_path is not None
        ):
            raise ValueError(
                "provide either temporal_guard "
                "or temporal_store_path, not both"
            )

        if temporal_guard is not None and not isinstance(
            temporal_guard,
            TemporalGuard,
        ):
            raise TypeError(
                "temporal_guard must be a TemporalGuard"
            )

        if temporal_decision_budget_seconds is not None:
            if isinstance(
                temporal_decision_budget_seconds, bool
            ) or not isinstance(
                temporal_decision_budget_seconds, (int, float)
            ):
                raise TypeError(
                    "temporal_decision_budget_seconds must be numeric or "
                    "None"
                )

            if (
                not math.isfinite(
                    float(temporal_decision_budget_seconds)
                )
                or float(temporal_decision_budget_seconds) <= 0
            ):
                raise ValueError(
                    "temporal_decision_budget_seconds must be a finite "
                    "positive number or None"
                )

        self._temporal_store = None

        if temporal_guard is not None:
            self.temporal = temporal_guard
        else:
            # Persistence is opt-in and the path is the deployment's to
            # name. With no path the guard still detects a wall-clock
            # regression inside this process -- the in-memory high-water
            # mark -- and simply cannot prove anything about the previous
            # process generation, which is what the durable floor is for.
            temporal_store_file = temporal_store_path

            if temporal_store_file is None:
                temporal_store_file = state_commit_store_path

            if temporal_store_file is None:
                temporal_store_file = attestation_store_path

            if temporal_store_file is None:
                temporal_store_file = verification_store_path

            if temporal_store_file is None:
                temporal_store_file = effect_store_path

            if temporal_store_file is None:
                temporal_store_file = execution_store_path

            if temporal_store_file is not None:
                self._temporal_store = SQLiteTemporalStore(
                    temporal_store_file,
                    clock=clock,
                )

            self.temporal = TemporalGuard(
                monotonic=monotonic_clock,
                tolerance=temporal_tolerance_seconds,
                store=self._temporal_store,
            )

        # Read-only after construction. Lowering it narrows and raising it
        # widens, and a mutable threshold a caller could raise mid-flight
        # would let a long-running decision escape the budget it was taken
        # under; construct the SDK you want instead.
        self._temporal_decision_budget = (
            None
            if temporal_decision_budget_seconds is None
            else float(temporal_decision_budget_seconds)
        )

        if (
            state_commit_store is not None
            and state_commit_store_path is not None
        ):
            raise ValueError(
                "provide either state_commit_store "
                "or state_commit_store_path, not both"
            )

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
            execution_lease_store is not None
            and execution_store_path is not None
        ):
            raise ValueError(
                "provide either execution_lease_store "
                "or execution_store_path, not both"
            )

        if (
            effect_journal is not None
            and effect_store_path is not None
        ):
            raise ValueError(
                "provide either effect_journal "
                "or effect_store_path, not both"
            )

        if effect_journal is not None:
            if not isinstance(
                effect_journal,
                EffectJournal,
            ):
                raise TypeError(
                    "effect_journal must be an EffectJournal"
                )

        if (
            verification_journal is not None
            and verification_store_path is not None
        ):
            raise ValueError(
                "provide either verification_journal "
                "or verification_store_path, not both"
            )

        if verification_journal is not None:
            if not isinstance(
                verification_journal,
                VerificationJournal,
            ):
                raise TypeError(
                    "verification_journal must be a "
                    "VerificationJournal"
                )

        if (
            attestation_journal is not None
            and attestation_store_path is not None
        ):
            raise ValueError(
                "provide either attestation_journal "
                "or attestation_store_path, not both"
            )

        if attestation_journal is not None:
            if not isinstance(
                attestation_journal,
                AttestationJournal,
            ):
                raise TypeError(
                    "attestation_journal must be an AttestationJournal"
                )

        if external_issuer_trust_store is not None:
            if not isinstance(
                external_issuer_trust_store,
                ExternalIssuerTrustStore,
            ):
                raise TypeError(
                    "external_issuer_trust_store must be an "
                    "ExternalIssuerTrustStore"
                )

        if not isinstance(require_external_attestation, bool):
            raise TypeError(
                "require_external_attestation must be a boolean"
            )

        if (
            lineage_journal is not None
            and lineage_store_path is not None
        ):
            raise ValueError(
                "provide either lineage_journal "
                "or lineage_store_path, not both"
            )

        if lineage_journal is not None and not isinstance(
            lineage_journal,
            LineageJournal,
        ):
            raise TypeError(
                "lineage_journal must be a LineageJournal"
            )

        if not isinstance(require_lineage, bool):
            raise TypeError("require_lineage must be a boolean")

        for label, value, minimum in (
            (
                "attestation_max_age_seconds",
                attestation_max_age_seconds,
                1e-9,
            ),
            (
                "attestation_clock_skew_seconds",
                attestation_clock_skew_seconds,
                0.0,
            ),
        ):
            if isinstance(value, bool) or not isinstance(
                value, (int, float)
            ):
                raise TypeError(f"{label} must be numeric")
            if not math.isfinite(float(value)) or float(value) < minimum:
                raise ValueError(
                    f"{label} must be a finite number no smaller than "
                    f"{minimum}"
                )

        if execution_lease_store is not None:
            if not isinstance(
                execution_lease_store,
                ExecutionLeaseStore,
            ):
                raise TypeError(
                    "execution_lease_store must be an "
                    "ExecutionLeaseStore"
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

        self._max_delegation_depth = max_delegation_depth

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
        # Execution lease store (v2.7)
        # ----------------------------------------------------
        #
        # The continuation of an authorized decision is recorded here.
        # The store is created before the epoch binding below so that
        # nothing can reach a lease operation on an unbound SDK; like
        # the lifecycle and replay recorders it is always present, and
        # persistence is opt-in through ``execution_store_path`` or a
        # caller-supplied store that already wraps a backend. An
        # internally created SQLite backend is closed by ``close()``; a
        # caller-supplied store stays the caller's to close, matching
        # the replay/lifecycle precedent.
        self._execution_store = None

        if execution_lease_store is not None:
            self.execution_leases = execution_lease_store

        elif execution_store_path is not None:
            self._execution_store = SQLiteExecutionLeaseStore(
                execution_store_path,
                clock=clock,
            )

            self.execution_leases = ExecutionLeaseStore(
                clock=clock,
                backend=self._execution_store,
            )

        else:
            self.execution_leases = ExecutionLeaseStore(
                clock=clock
            )

        # ----------------------------------------------------
        # Authority epoch: bind the stores that can widen

        # ----------------------------------------------------
        # Side-effect journal (v2.8)
        # ----------------------------------------------------
        #
        # Durable, idempotent, recoverable record of the one external
        # side effect an execution may cause. The journal is state, not
        # evidence and not authority: no value stored here can ever make
        # an ``authorize`` allow, and every journal progression re-
        # establishes the *execution's* authority basis first (see the
        # prepare_effect/attempt_effect/... methods). It is always
        # present (empty in memory by default); persistence is opt-in
        # through ``effect_store_path``, and when the execution lease
        # store is already persistent the journal shares its file so a
        # restart recovers both journals from one database. A caller-
        # supplied journal stays the caller's to close.
        self._effect_store = None

        if effect_journal is not None:
            self.effects = effect_journal

        elif effect_store_path is not None:
            self._effect_store = SQLiteEffectJournal(
                effect_store_path,
                clock=clock,
            )

            self.effects = EffectJournal(
                clock=clock,
                backend=self._effect_store,
            )

        elif execution_store_path is not None:
            self._effect_store = SQLiteEffectJournal(
                execution_store_path,
                clock=clock,
            )

            self.effects = EffectJournal(
                clock=clock,
                backend=self._effect_store,
            )

        else:
            self.effects = EffectJournal(
                clock=clock
            )

        # ----------------------------------------------------
        # Effect verification journal (v2.9)
        # ----------------------------------------------------
        #
        # Whether the *recorded* side-effect claim can be trusted. A
        # third journal beside the lease journal and the side-effect
        # journal: each row binds exactly one effect, attempt and
        # evidence snapshot, and rows are written only by the SDK
        # protocol methods below (verify_effect and the commit/run
        # path). The journal is state, not evidence and not authority:
        # nothing here can make an ``authorize`` allow, its only effect
        # elsewhere is a refusal, and it never writes to either of the
        # other journals. Always present (empty in memory by default);
        # persistence is opt-in through ``verification_store_path``,
        # sharing the configured effect/execution store file otherwise
        # so one restart recovers all three journals from one database.
        # A caller-supplied journal stays the caller's to close.
        self._verification_store = None

        if verification_journal is not None:
            self.verifications = verification_journal

        elif verification_store_path is not None:
            self._verification_store = SQLiteVerificationJournal(
                verification_store_path,
                clock=clock,
            )

            self.verifications = VerificationJournal(
                clock=clock,
                backend=self._verification_store,
            )

        elif effect_store_path is not None:
            self._verification_store = SQLiteVerificationJournal(
                effect_store_path,
                clock=clock,
            )

            self.verifications = VerificationJournal(
                clock=clock,
                backend=self._verification_store,
            )

        elif execution_store_path is not None:
            self._verification_store = SQLiteVerificationJournal(
                execution_store_path,
                clock=clock,
            )

            self.verifications = VerificationJournal(
                clock=clock,
                backend=self._verification_store,
            )

        else:
            self.verifications = VerificationJournal(
                clock=clock
            )

        # ----------------------------------------------------
        # External state attestation (v3.1)
        # ----------------------------------------------------
        #
        # Whether an *external system* authenticated the state a side
        # effect claims. A fourth journal beside the lease, side-effect and
        # verification journals: each row binds exactly one effect, attempt
        # and signed envelope, and rows are written only by the SDK
        # protocol methods below. Nothing here is on the ALLOW path --
        # ``authorize()`` never reads this journal, which
        # EXTERNAL_STATE_ATTESTATION_SOUNDNESS checks -- so its only
        # possible effect elsewhere is a refusal, and it never writes to
        # any of the other three journals. Always present (empty in memory
        # by default); persistence is opt-in through
        # ``attestation_store_path``, sharing the configured
        # effect/verification/execution store file otherwise so one restart
        # recovers all four journals from one database -- which matters
        # most for the nonce ledger, since replay protection that dies with
        # the process is not replay protection. A caller-supplied journal
        # stays the caller's to close, and carries its own freshness
        # parameters; the two arguments below are used only when this
        # constructor builds the journal.
        self._attestation_store = None

        if attestation_journal is not None:
            self.attestations = attestation_journal

        elif attestation_store_path is not None:
            self._attestation_store = SQLiteExternalAttestationStore(
                attestation_store_path,
                clock=clock,
            )

            self.attestations = AttestationJournal(
                clock=clock,
                backend=self._attestation_store,
                max_age=attestation_max_age_seconds,
                skew=attestation_clock_skew_seconds,
            )

        elif verification_store_path is not None:
            self._attestation_store = SQLiteExternalAttestationStore(
                verification_store_path,
                clock=clock,
            )

            self.attestations = AttestationJournal(
                clock=clock,
                backend=self._attestation_store,
                max_age=attestation_max_age_seconds,
                skew=attestation_clock_skew_seconds,
            )

        elif effect_store_path is not None:
            self._attestation_store = SQLiteExternalAttestationStore(
                effect_store_path,
                clock=clock,
            )

            self.attestations = AttestationJournal(
                clock=clock,
                backend=self._attestation_store,
                max_age=attestation_max_age_seconds,
                skew=attestation_clock_skew_seconds,
            )

        elif execution_store_path is not None:
            self._attestation_store = SQLiteExternalAttestationStore(
                execution_store_path,
                clock=clock,
            )

            self.attestations = AttestationJournal(
                clock=clock,
                backend=self._attestation_store,
                max_age=attestation_max_age_seconds,
                skew=attestation_clock_skew_seconds,
            )

        else:
            self.attestations = AttestationJournal(
                clock=clock,
                max_age=attestation_max_age_seconds,
                skew=attestation_clock_skew_seconds,
            )

        # ----------------------------------------------------
        # Execution lineage journal (v3.3)
        # ----------------------------------------------------
        #
        # One append-only, hash-chained commitment per stage of one
        # execution: AUTHORIZED -> EXECUTED -> OBSERVED -> VERIFIED ->
        # ATTESTED -> COMPLETED. The four journals above each answer a
        # question about one stage; this one answers the question about the
        # *sequence* -- that these stages belong to one execution, that they
        # happened in that order, and that nothing was forked, grafted or
        # re-ordered along the way.
        #
        # It is not a fifth authority and not a second path: it commits to
        # the other journals rather than replacing them, its only effect on
        # the boundary is a refusal, and nothing here can make an
        # ``authorize`` allow. Persistence is opt-in through
        # ``lineage_store_path``, sharing the configured store file
        # otherwise so one restart recovers every journal from one database
        # -- which matters most here, because a lineage that does not
        # survive a restart leaves the firewall holding an execution it can
        # no longer say anything provable about. A caller-supplied journal
        # stays the caller's to close.
        self._lineage_store = None

        if lineage_journal is not None:
            self.lineages = lineage_journal

        else:
            lineage_store_file = lineage_store_path

            if lineage_store_file is None:
                lineage_store_file = temporal_store_path

            if lineage_store_file is None:
                lineage_store_file = state_commit_store_path

            if lineage_store_file is None:
                lineage_store_file = attestation_store_path

            if lineage_store_file is None:
                lineage_store_file = verification_store_path

            if lineage_store_file is None:
                lineage_store_file = effect_store_path

            if lineage_store_file is None:
                lineage_store_file = execution_store_path

            if lineage_store_file is not None:
                self._lineage_store = SQLiteLineageStore(
                    lineage_store_file,
                    clock=clock,
                )

            self.lineages = LineageJournal(
                clock=clock,
                backend=self._lineage_store,
            )

        # Whether a progression must have a verifiable lineage behind it.
        # Read-only after construction, for the reason the attestation
        # requirement is: switching it off would widen what may execute, and
        # a mutable widening switch on the progression path is the shape
        # this package refuses everywhere else.
        self._require_lineage = bool(require_lineage)

        # ----------------------------------------------------
        # External issuer trust (v3.1)
        # ----------------------------------------------------
        #
        # The registration of a public key for a named external issuer is
        # the whole of this firewall's authority over an attestation: it
        # cannot tell whether the key really belongs to the system the
        # issuer id names, and it does not pretend to. What it can do is
        # refuse anything signed by a key nobody registered, keep
        # registration monotone, and make "who may register one" a checked
        # property of the source -- a subsystem that could register its own
        # key could mint its own evidence.
        if external_issuer_trust_store is not None:
            self.external_issuers = external_issuer_trust_store
        else:
            self.external_issuers = ExternalIssuerTrustStore(clock=clock)

        if external_issuer_keys is not None:
            if isinstance(external_issuer_keys, (str, bytes)) or not isinstance(
                external_issuer_keys, Sequence
            ):
                raise TypeError(
                    "external_issuer_keys must be a sequence of "
                    "(issuer_id, key_id, public_key) triples"
                )

            for entry in external_issuer_keys:
                if not isinstance(entry, Sequence) or isinstance(
                    entry, (str, bytes)
                ) or len(entry) != 3:
                    raise TypeError(
                        "external_issuer_keys entries must be "
                        "(issuer_id, key_id, public_key) triples"
                    )

                issuer_id, key_id, public_key = entry

                # Routed through the declared trust-anchor method rather
                # than the store directly, so there is exactly one code
                # path in the package that registers an external issuer
                # key -- which is what EXTERNAL_STATE_ATTESTATION_SOUNDNESS
                # checks in both directions. Construction-time
                # registration is the deployment's configuration being
                # applied, not a second kind of trust anchor.
                self.trust_external_issuer(
                    issuer_id,
                    key_id,
                    public_key,
                )

        # Whether a completion must rest on a current external
        # attestation. Read-only after construction: switching it *on* is a
        # narrowing, but switching it off would widen -- a deployment that
        # stopped requiring external evidence -- and a mutable widening
        # switch on the completion path is exactly the shape this package
        # refuses. Construct the SDK you want instead.
        self._require_external_attestation = bool(
            require_external_attestation
        )

        # ----------------------------------------------------
        #
        # Every store constructed above now exists, so this is the first
        # point at which the binding can be complete. It must run before
        # the monitor thread starts, because that thread calls back into
        # authorize() and an unbound store would leave its widening writes
        # uncounted for the life of the SDK.
        #
        # A failed binding is a hard error rather than a warning. The
        # failure mode of a missed binding is silent -- widening writes stop
        # being counted and authorize() goes back to v2.5 behaviour with no
        # symptom -- and an SDK that cannot make the guarantee should not
        # start up claiming to.
        unbound = self._bind_authority_epoch()
        if unbound:
            raise RuntimeError(
                "authority epoch could not be bound to: "
                + ", ".join(unbound)
            )

        # ----------------------------------------------------
        # Security state-commit journal (v3.0)
        # ----------------------------------------------------
        #
        # The epoch counts the *writes* that can widen authority;
        # the state-commitment journal records the *state* those
        # writes produce (see :mod:`firewall.state_commit`). The
        # journal is created here, after every in-domain store
        # exists and after the epoch binding, so the boot state
        # can be committed as the genesis of the chain before any
        # write can happen. An SDK whose in-domain store cannot be
        # bound to the journal refuses to start for the same reason
        # an unbound epoch store does: a store whose writes are not
        # committed is a silent return to the pre-v3.0 guarantee.
        self._state_commit_store = None

        if state_commit_store is not None:
            self._state_commit_store = state_commit_store

        elif state_commit_store_path is not None:
            self._state_commit_store = SQLiteStateCommitStore(
                state_commit_store_path
            )

        self.state_commit = StateCommitJournal(
            store=self._state_commit_store
        )

        unbound = self._bind_state_commit()
        if unbound:
            raise RuntimeError(
                "state-commit journal could not be bound to: "
                + ", ".join(unbound)
            )

        # ----------------------------------------------------
        # Temporal integrity (v3.2)
        # ----------------------------------------------------
        #
        # Every store whose deadlines are measured in a clock is bound to
        # the guard here, so its own readings are audited where they are
        # taken -- one watermark per named source, per store that reads a
        # clock. A store that could not be bound is reported rather than
        # ignored, for the same reason an unbound epoch store is: the
        # failure mode is silent (windows measured against an unaudited
        # clock look exactly like windows measured against an audited one)
        # and an SDK that cannot make the guarantee should not start up
        # claiming to.
        unbound = self._bind_temporal()
        if unbound:
            raise RuntimeError(
                "temporal guard could not be bound to: "
                + ", ".join(unbound)
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
    # Delegation depth policy
    # ========================================================

    @property
    def max_delegation_depth(
        self,
    ) -> Optional[int]:
        """The authorization-time delegation depth ceiling.

        A property rather than a plain attribute because raising it widens
        authority and ``_gate_delegation_depth`` reads it mid-request. As a
        bare attribute, ``sdk.max_delegation_depth = 99`` was an uncounted
        widening with no call site to bracket -- the assignment *is* the
        write. The setter validates exactly as ``__init__`` does, so the
        two entry points cannot disagree about what a legal ceiling is.
        """

        return self._max_delegation_depth

    @max_delegation_depth.setter
    def max_delegation_depth(
        self,
        value: Optional[int],
    ) -> None:
        if value is not None:
            if isinstance(
                value,
                bool,
            ) or not isinstance(
                value,
                int,
            ):
                raise TypeError(
                    "max_delegation_depth must be an integer"
                )

            if value <= 0:
                raise ValueError(
                    "max_delegation_depth must be positive"
                )

        # Lowering the ceiling narrows and raising it widens, but the
        # bracket is unconditional: distinguishing them here would mean
        # comparing against the old value and deciding, outside the gate,
        # that this particular write cannot matter. ``None`` disables the
        # gate outright and is the widest write of all.
        #
        # v3.0: the ceiling is part of the canonical security state the
        # ALLOW boundary reads, so changing it is a state transition the
        # commitment journal must record. The mutation bracket nests inside
        # the epoch bracket: the epoch is about widening writes in flight,
        # the commitment is about the state that results.
        # record_state_commit on the SDK itself: the ceiling is
        # in-domain state, and the journal was bound to this SDK in
        # ``_bind_state_commit`` so the write is committed when it
        # lands. An SDK that predates the binding (nothing can call
        # the setter before __init__ completes) is an unbound
        # pass-through, exactly like the stores.
        with record_state_commit(
            self,
            "delegation_depth_ceiling_changed",
        ):
            with self.authority_epoch.widening(
                "delegation_depth_ceiling_changed"
            ):
                self._max_delegation_depth = value

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
        """Replace the runtime security context.

        Epoch-bracketed. Swapping the context is a widening even though
        nothing inside either object changed: the new one carries its own
        spent budget and its own used-capability set, so a request the old
        context would have denied on budget can succeed against the new
        one. Setting it to ``None`` removes the budget gate outright, which
        is the widest form of the same move.

        The replacement is also bound to this SDK's epoch, so its own
        ``reset`` is counted from here on. A binding failure raises for the
        same reason it does in ``__init__``: an uncounted store is a silent
        return to v2.5 behaviour.
        """

        if context is not None:
            if not isinstance(
                context,
                SecurityContext,
            ):
                raise TypeError(
                    "context must be a SecurityContext"
                )

        with self.authority_epoch.widening(
            "security_context_replaced"
        ):
            self.security_context = context
            self._bind_replacement_context(
                "security_context",
                context,
            )

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
        """Replace the semantic-chain context.

        Epoch-bracketed, for the reason given on
        :meth:`set_security_context`: the replacement carries no chain
        history, so a sequence the old context refused is permitted against
        the new one, and ``None`` removes the semantic gate entirely.
        """

        if context is not None:
            if not isinstance(
                context,
                SemanticChainContext,
            ):
                raise TypeError(
                    "context must be a SemanticChainContext"
                )

        with self.authority_epoch.widening(
            "semantic_context_replaced"
        ):
            self.semantic_context = context
            self._bind_replacement_context(
                "semantic_context",
                context,
            )

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
        """Replace the runtime risk context.

        Epoch-bracketed, for the reason given on
        :meth:`set_security_context`: an agent the old context had escalated
        to ``REVOKED`` starts at ``NORMAL`` in the replacement, and ``None``
        removes the risk gate.
        """

        if context is not None and not isinstance(context, RiskContext):
            raise TypeError("context must be a RiskContext")

        with self.authority_epoch.widening(
            "risk_context_replaced"
        ):
            self.risk_context = context
            self._bind_replacement_context(
                "risk_context",
                context,
            )

    def _bind_replacement_context(
        self,
        name: str,
        context: Any,
    ) -> None:
        """Bind a context installed after ``__init__`` to the epoch."""

        if context is None:
            return

        if not bind_epoch(
            context,
            self.authority_epoch,
        ):
            raise RuntimeError(
                "authority epoch could not be bound to: "
                f"{name}"
            )

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

        # The reading is audited against this source's own history before
        # it is used for anything. A wall clock that moved backwards makes
        # every window measured against it longer than the deployment
        # asked for, so the answer is a refusal -- and it is a refusal the
        # gate has to make, because the alternative is comparing a
        # deadline against a clock that is known not to be trustworthy.
        anomaly = self._temporal_audit(now)

        if anomaly is not None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    f"{TEMPORAL_ANOMALY_PREFIX}:{anomaly}",
                ),
            )

        context = self._temporal_context(now)

        if context is None:
            return self._apply_denial(
                ctx,
                AuthorizationResult(
                    False,
                    f"{TEMPORAL_ANOMALY_PREFIX}:"
                    "temporal_context_unprovable",
                ),
            )

        ctx.entry_temporal = context

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
        ``__init__`` requires an ``AegisController`` instance, but a subclass
        may override any method this gate calls, so every one of those calls
        is guarded here rather than trusting the callee to be total.
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

        #: Names of exceptions raised while rolling a semantic transaction
        #: back. Populated by ``abort_semantic_transaction`` and drained by
        #: ``record_denial``; empty in every ordinary run.
        rollback_failures: "list[Optional[str]]" = []

        def record_denial(
            result: AuthorizationResult,
        ) -> AuthorizationResult:
            applied = self._apply_denial(
                ctx,
                result,
            )

            # A rollback that failed is attached here rather than at the
            # call site, because every abort is followed by exactly one
            # denial and putting it in one place is what stops the next
            # denial path from forgetting to.
            if rollback_failures and isinstance(applied.trace, dict):
                applied.trace["rollback_error"] = ",".join(
                    name for name in rollback_failures if name
                )

            return applied

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

            # v2.6. This clause used to be absent, and its absence was not
            # a missing feature -- it was an escape hatch out of the
            # boundary. ``begin_authorization`` raises this when the
            # cumulative amount ceiling would be crossed, and with nothing
            # catching it the exception left ``authorize()`` in place of a
            # verdict. Fail-closed held in the narrow sense -- no allow was
            # produced -- but every write ``_apply_denial`` performs was
            # skipped: the audit trace, the security context's denial
            # counter, the risk context's ``record_denial``, and the DENIED
            # lifecycle event.
            #
            # That is the part that matters. Risk escalation is driven by
            # accumulated denials, so a caller able to hold the semantic
            # budget at its ceiling could be refused without limit and
            # never accumulate any of the state those refusals are supposed
            # to produce. No single request was wrongly allowed; the
            # narrowing that repeated refusals owe the next request simply
            # never happened.
            #
            # ``SecurityBudgetExceeded`` two blocks down was always caught
            # and converted here, which is what made the omission look like
            # an oversight rather than a decision -- the same failure on the
            # same gate, one recorded and one not.
            except SemanticBudgetExceeded as exc:
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"semantic_budget_exceeded: {exc}",
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

            # v2.6. The three clauses above name the failures somebody
            # anticipated. This one exists because the gate has no way to
            # know that list is complete: the semantic context is
            # injectable, ``begin_authorization`` runs caller-supplied
            # rules and deep-copies caller-supplied request data, and the
            # bundled implementation's own error family has a base class
            # that could grow a third member tomorrow.
            #
            # ``_read_security_state`` already applies this reasoning to
            # every gate that *reads* injectable state. The two calls in
            # this gate were the exception, and they are the two that
            # mutate -- so the failure mode was not merely a missing
            # verdict but a missing verdict on the request that had already
            # passed all eleven gates.
            #
            # Safe to deny without unwinding: ``begin_authorization``
            # releases its lock and rolls back any reservation on every
            # exit path, so a raise leaves ``semantic_transaction`` unset
            # and the context unchanged.
            except Exception as exc:  # noqa: BLE001 - unreadable is a denial
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"semantic_state_unavailable:{type(exc).__name__}",
                    )
                )

        def abort_semantic_transaction() -> None:
            """Roll back, and do not become the reason a denial disappears.

            v2.6. Every caller of this is a denial that has already been
            decided -- and most of them are the ``except`` handlers above,
            whose entire purpose is to stop an exception replacing a
            verdict. An ``abort`` that raised defeated them exactly where
            they were supposed to work: the gate caught the injected
            failure, converted it into a denial, and then lost the denial
            on the way out.

            ``SemanticChainTransaction.abort`` releases a lock in a
            ``finally`` and cannot reach this, but the transaction object
            comes from an injectable context, so what is guarded is the
            contract rather than the bundled implementation.

            The verdict is not reconsidered. It is already a refusal, and
            there is no narrower answer available. What must not happen is
            the failure being discarded: a reservation that would not roll
            back is state the next request will be decided against, so the
            exception's name is collected and attached to the denial's
            trace under its own key -- ``rollback_error`` rather than
            ``evidence_error``, because a lost audit record and a failed
            rollback call for different responses.
            """

            if semantic_transaction is None:
                return

            failure = self._write_evidence(semantic_transaction.abort)

            if failure is not None:
                rollback_failures.append(failure)

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

            # v2.6, and this is the one that was reachable with the
            # shipped class and no subclassing at all.
            #
            # ``authorize_and_record`` reloads the persisted budget from
            # disk *inside* this gate, before its check, so that a
            # cross-process sibling's spend is not lost. Every way that
            # load can fail raises ``SecurityContextError``: a truncated
            # file, a failed integrity hash, an agent mismatch, an
            # ``OSError`` on the atomic replace. ``SecurityBudgetExceeded``
            # is a *subclass* of it, so the clause above caught the one
            # member of the family somebody had in mind and let the rest
            # through.
            #
            # An attacker who can write ``state_path`` -- not the key, not
            # the capability, just the file the budget is persisted to --
            # therefore made every authorization raise. That failed closed
            # in the only sense that matters least: no allow was produced.
            # No denial was produced either, so nothing was traced, no
            # denial counted, and no DENIED event written -- the boundary
            # was silent about a request it had refused.
            #
            # Denying is safe without unwinding the store: every raising
            # path in ``authorize_and_record`` either precedes its mutation
            # or rolls it back before re-raising.
            except Exception as exc:  # noqa: BLE001 - unreadable is a denial
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"security_state_unavailable:{type(exc).__name__}",
                    )
                )

        # ----------------------------------------------------
        # Serializability: did authority widen underneath us?
        # ----------------------------------------------------
        #
        # Every read this authorization performs has now happened -- the ten
        # upstream gates, the commit-time revocation and suspension
        # re-checks above, and the security budget's own check-and-consume.
        # Comparing the epoch here therefore covers the whole interval the
        # verdict was assembled from, which is the point: an earlier
        # comparison would leave later reads outside it, and there are no
        # later reads to leave outside this one.
        #
        # A moved epoch does not mean the request is unauthorized. It means
        # this execution's verdict is not a statement about any single point
        # in time, so the evidence for allowing is not evidence at all. The
        # only safe answer is to refuse, and the reason is deliberately not
        # a policy reason: nothing here re-derives what the new state
        # permits, because deciding that is the gates' job and the caller
        # can simply ask again.
        #
        # The cost when this fires is the same one the ``evidence_
        # unavailable`` denial below already pays and documents: the
        # security budget has been consumed and is not refunded, so the
        # denial is conservative rather than neutral. The semantic
        # transaction *is* aborted, because it has not been committed yet --
        # which is why the check sits here rather than after the commit.
        entry_epoch = ctx.entry_epoch
        if entry_epoch is not None:
            commit_epoch = self.authority_epoch.sample()
            if not entry_epoch.covers(commit_epoch):
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        entry_epoch.divergence(
                            commit_epoch
                        ),
                    )
                )

        # ----------------------------------------------------
        # Security state coherence (v3.0)
        # ----------------------------------------------------
        #
        # The epoch comparison above proves that no widening write
        # finished inside this request; it does not prove that the state
        # the gates read is the state the firewall itself last recorded.
        # A store changed without its declared write path -- a record
        # removed by hand, a lineage edge rewritten, a store file rolled
        # back, a crash between a write and its commitment -- leaves the
        # live state disagreeing with the head of the state-commitment
        # journal (see :mod:`firewall.state_commit`). An allow assembled
        # from that state would rely on a security state the firewall
        # cannot prove is coherent, so it is refused exactly as an epoch
        # divergence is refused: the semantic transaction is aborted, no
        # allow is emitted, and nothing is re-derived from the unaccounted
        # state -- the caller can simply ask again after the operator
        # reconciles the store.
        state_denial = self._state_coherence_denial()
        if state_denial is not None:
            abort_semantic_transaction()
            return record_denial(
                AuthorizationResult(
                    False,
                    state_denial,
                )
            )

        # ----------------------------------------------------
        # Temporal integrity (v3.2)
        # ----------------------------------------------------
        #
        # The gate above proved this verdict was taken inside a trustworthy
        # temporal context. This one asks whether it is *still* inside it:
        # an authorization is a statement about an instant, and a decision
        # that takes long enough to cross its own validity window has
        # become a statement about a window that no longer exists.
        #
        # Two questions, both answered from the guard's own record rather
        # than from a second reading of the clock:
        #
        # * is the context still provable? A wall clock that regressed
        #   between entry and commit means the instant this verdict
        #   describes never existed, so the allow cannot be emitted;
        # * has the capability window closed? The gate checked it at entry
        #   against an earlier instant; a request that started before
        #   ``expires_at`` and finished after it is exactly the stale
        #   authorization this boundary exists to refuse.
        #
        # The elapsed-time question is asked in the monotonic base, so a
        # wall clock moved backwards cannot make a long decision look
        # short. A deployment may also set an explicit decision budget; it
        # is off by default because a default budget would be a policy the
        # firewall invented rather than one it was told.
        entry_temporal = ctx.entry_temporal

        if entry_temporal is not None:
            now, unreadable = self._read_security_state(
                lambda: float(
                    getattr(self.verifier, "clock", None)()
                )
            )

            if unreadable is not None or not math.isfinite(now):
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        "clock_unavailable:"
                        + (unreadable or "non_finite"),
                    )
                )

            anomaly = self._temporal_audit(now)

            if anomaly is not None:
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"{TEMPORAL_ANOMALY_PREFIX}:{anomaly}",
                    )
                )

            commit_context = self._temporal_context(now)

            if commit_context is None:
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        f"{TEMPORAL_ANOMALY_PREFIX}:"
                        "temporal_context_unprovable",
                    )
                )

            try:
                elapsed = (
                    commit_context.monotonic
                    - entry_temporal.monotonic
                )
            except (AttributeError, TypeError):
                elapsed = None

            budget = self._temporal_decision_budget

            if (
                elapsed is not None
                and budget is not None
                and elapsed > budget
            ):
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        "stale_authorization:decision_budget",
                    )
                )

            closed, unusable = self._read_security_state(
                lambda: (
                    now >= capability.expires_at,
                    now < capability.issued_at,
                )
            )

            if unusable is not None:
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        "capability_time_invalid:"
                        f"{unusable}",
                    )
                )

            expired_at_commit, not_yet_valid_at_commit = closed

            if expired_at_commit or not_yet_valid_at_commit:
                abort_semantic_transaction()
                return record_denial(
                    AuthorizationResult(
                        False,
                        "stale_authorization:capability_window",
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

        # v2.6, and the same argument as the two clauses above with one
        # thing added: this raise would happen on the *allow* path, after
        # every gate has passed and the budget has been spent. An escape
        # here is the most expensive kind -- the caller is handed an
        # exception for a request that was in fact authorized, having
        # already paid for it.
        #
        # The bundled ``commit`` cannot reach this: it appends to a list
        # and releases the context lock in a ``finally``. The transaction
        # object comes from an injectable context, though, so what is
        # guarded is the contract, not the bundled implementation.
        except Exception as exc:  # noqa: BLE001 - unreadable is a denial
            abort_semantic_transaction()
            return record_denial(
                AuthorizationResult(
                    False,
                    f"semantic_state_unavailable:{type(exc).__name__}",
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

    def _authority_epoch_stores(self) -> "dict[str, Any]":
        """The mutable stores whose widening writes must be counted.

        The companion to :meth:`_authorization_gate_phases`: that method
        enumerates what the boundary *reads*, this one enumerates what can
        change underneath those reads in the widening direction. A store
        listed here and reachable by a widening path that is not bracketed
        is a hole, and a widening path on a store that is not listed here
        is the same hole reached from the other side, so the two lists are
        checked against each other by the ``AUTHORITY_EPOCH_COVERAGE``
        invariant rather than by review.

        Absent deliberately:

        ``revocation``
            :class:`~firewall.revocation.RevocationRegistry` has no
            un-revoke. Revocation is permanent, so every write to it
            narrows and none can invalidate an in-flight verdict.

        ``lifecycle``, ``replay``, ``key_manager``
            The evidence chain and the replay ledger only ever accumulate,
            and retiring a key leaves already-issued signatures verifiable
            (see the v2.5 finding pinned in
            ``tests/test_v2_5_stale_revalidation.py``), so a key write
            cannot turn a denial into an allow for a capability that
            already exists.

        ``_delegation_budgets``
            Raising a lineage ceiling widens, but no canonical gate reads
            it: ``authorize_with_delegation_budget`` runs the full gate
            chain first and then reserves against the ledger in one atomic
            check-and-consume, which is linearizable at its own instant.
            Counting it would deny requests over a value the epoch's window
            never covered.

        ``max_delegation_depth``
            Widens when raised and *is* read by a gate, so it is counted --
            but by the property setter on this class rather than by a
            store, because the write is an attribute assignment with no
            store method to bracket.

        A value of ``None`` means the mechanism is not wired on this SDK;
        it is skipped rather than reported, because an absent optional
        context is not an unbound one.
        """

        return {
            "issuer_trust_store": self.issuer_trust_store,
            "aegis_restrictions": getattr(
                self.aegis,
                "store",
                None,
            ),
            "refusal_state": self.refusal_state,
            "risk_context": self.risk_context,
            "security_context": self.security_context,
            "semantic_context": self.semantic_context,
        }

    def _bind_authority_epoch(self) -> tuple[str, ...]:
        """Bind every wired store to this SDK's epoch.

        Returns the names that could not be bound, so the caller can refuse
        to continue. Idempotent, and re-callable: the context setters use it
        to bind a replacement context.
        """

        unbound: list[str] = []

        for name, component in (
            self._authority_epoch_stores().items()
        ):
            if component is None:
                continue

            if not bind_epoch(
                component,
                self.authority_epoch,
            ):
                unbound.append(name)

        return tuple(unbound)

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

        # Sample the authority epoch before any gate reads security state.
        #
        # The eleven gates each read their own input at their own instant,
        # under no shared lock. That is sound only while every
        # control-plane write narrows authority: a gate passing at ``t_k``
        # then implies its input was permissive at ``t_0`` too, so ``t_0``
        # serves as a linearization point for the whole conjunction. A
        # write that *widens* breaks the implication, and a verdict
        # assembled from reads on both sides of one can describe a state
        # that no instant ever had -- see :mod:`firewall.authority_epoch`
        # for the concrete interleaving that produced an allow no
        # serialization admits.
        #
        # So the epoch is sampled here, at ``t_0``, and compared again in
        # the terminal gate. It is not consulted anywhere else and cannot
        # cause anything to be permitted; the comparison's only possible
        # effect is to turn an allow into a denial.
        entry_epoch = self.authority_epoch.sample()

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
            entry_epoch=entry_epoch,
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

    def _bind_state_commit(self) -> tuple[str, ...]:
        """Bind every in-domain store to this SDK's state-commit
        journal and commit the boot state as the genesis record.

        The companion to :meth:`_bind_authority_epoch`: that method
        binds the stores whose *writes can widen* to the epoch; this
        one binds the stores whose *state an ALLOW reads* to the
        commitment journal. The four attached readers are the
        canonical security state of this SDK -- revocation records,
        trusted issuers, delegation-lineage edges and the
        delegation-depth ceiling -- and the genesis record commits
        whatever that state is at boot, so a boot whose stores were
        tampered before startup is either caught against a persisted
        chain or blessed as the new baseline when no chain exists.

        Returns the names that could not be bound. Idempotent, and
        re-callable after a store is replaced.
        """

        journal = self.state_commit
        journal.attach(
            "revocation",
            lambda: revocation_reader(self.revocation),
        )
        journal.attach(
            "issuer_trust",
            lambda: issuer_trust_reader(
                self.issuer_trust_store
            ),
        )
        journal.attach(
            "delegation_lineage",
            lambda: lineage_reader(
                self.delegation_lineage
            ),
        )
        journal.attach(
            "delegation_depth",
            lambda: self.max_delegation_depth,
        )
        journal.set_epoch_source(
            lambda: (
                self.authority_epoch.sample().finished,
                self.authority_epoch.sample().in_flight,
            )
        )

        unbound: list[str] = []

        for name, component in (
            (
                "revocation",
                self.revocation,
            ),
            (
                "issuer_trust_store",
                self.issuer_trust_store,
            ),
            (
                "delegation_lineage",
                self.delegation_lineage,
            ),
        ):
            if component is None:
                continue

            if not bind_state_commit(
                component,
                journal,
            ):
                unbound.append(name)

        # The SDK itself is an in-domain writer too: changing the
        # delegation-depth ceiling mutates the canonical state, and
        # binding ``self`` lets the property setter commit it
        # through the same ``record_state_commit`` helper the
        # stores use (and lets the census see one helper name).
        if not bind_state_commit(self, journal):
            unbound.append("self")

        journal.bootstrap(source="sdk-boot")
        return tuple(unbound)

    def _bind_temporal(self) -> tuple[str, ...]:
        """Bind every clock-reading store to this SDK's temporal guard.

        The companion to :meth:`_bind_authority_epoch` and
        :meth:`_bind_state_commit`, and the same shape: a store
        constructed standalone has no SDK and must keep working, so
        binding is how the SDK brings an existing store inside its temporal
        boundary without the store depending on an SDK.

        One source per store rather than one shared "sdk" source. Each
        store stamps its deadlines with its own clock, and a watermark is a
        statement about *one* time source: pooling them would make a store
        whose clock is honest look regressed because another store's clock
        is set differently, which is how a security check becomes noise
        people turn off.

        ``state_commit`` is deliberately absent. It holds ``__slots__``
        with no room for a binding attribute -- the constraint v2.6 and
        v3.0 documented for stores that cannot be bound -- and its
        ``committed_at`` is an *evidence ordering* timestamp rather than a
        validity window, so it is not a source this boundary has to audit.
        Its ordering is checked from the records themselves by the
        release's invariant, which needs no binding to do it.

        Returns the names that could not be bound.
        """

        unbound: list[str] = []

        for name, component in (
            ("execution_leases", getattr(self, "execution_leases", None)),
            ("effects", getattr(self, "effects", None)),
            ("attestations", getattr(self, "attestations", None)),
            ("lineages", getattr(self, "lineages", None)),
            ("replay", getattr(self, "replay", None)),
            ("lifecycle", getattr(self, "lifecycle", None)),
        ):
            if component is None:
                continue

            if not bind_temporal(component, self.temporal):
                unbound.append(name)

        return tuple(unbound)

    def _temporal_audit(
        self,
        wall: float,
        *,
        name: str = "sdk",
    ) -> Optional[str]:
        """Audit one already-taken wall reading; return an anomaly reason.

        The gates read their clock through ``_read_security_state`` so that
        an unreadable clock produces a *denial reason* rather than an
        exception -- that behaviour is v2.5's and is preserved exactly.
        What this adds is the audit: the reading is compared against this
        source's own history, and a regression is returned as an anomaly
        for the caller to deny on.

        A monotonic clock that cannot be read marks the reading
        anomalous rather than raising, because the wall reading is already
        in hand and the caller needs a reason to record. An anomaly is
        never returned for a reading that is merely unusual: time moving
        forward is not an attack, and calling it one would deny legitimate
        requests.
        """

        try:
            context = self.temporal.observe_reading(wall, name=name)
        except TemporalError:
            return "temporal_context_unprovable"

        return context.anomaly

    def _temporal_context(
        self,
        wall: float,
        *,
        name: str = "sdk",
    ) -> Optional[TemporalContext]:
        """The validated context for one reading, or ``None``.

        ``None`` when the guard could not audit the reading at all, which
        the caller treats exactly as an anomaly: no context, no window.
        """

        try:
            return self.temporal.observe_reading(wall, name=name)
        except TemporalError:
            return None

    @property
    def temporal_decision_budget_seconds(self) -> Optional[float]:
        """The longest an authorization may take, when a deployment set one.

        Read-only: raising it would let a decision outlive the budget it
        was taken under, which is the widening direction.
        """

        return self._temporal_decision_budget

    @property
    def temporal_store(self):
        """The internally created SQLite watermark store, or ``None``."""

        return self._temporal_store

    def temporal_state(self) -> dict:
        """Read-only snapshot of the guard's audit state.

        For operators and the invariant suite: which sources have been
        sampled, their high-water marks, and whether any of them recorded
        an anomaly. Reading it decides nothing.
        """

        try:
            return self.temporal.snapshot()
        except Exception:  # noqa: BLE001 - unreadable is reported as such
            return {"suspect": "unavailable"}

    def _state_coherence_denial(self) -> Optional[str]:
        """Why the live security state is not provably coherent, if it
        is not.

        ``None`` means the live canonical digest of the in-domain
        stores equals the head of the state-commitment journal: the
        state an allow would rely on is exactly the state the firewall
        last recorded. Anything else -- a drifted store, a broken
        chain, an unreadable component -- is returned as a denial
        reason under the ``state_incoherent`` prefix. Unreadable is a
        denial, never a pass, for the same reason every other
        unreadable security dependency in the boundary is one.
        """

        journal = getattr(self, "state_commit", None)

        if journal is None:
            return None

        try:
            coherent, reason = journal.coherent()
        except Exception as exc:  # noqa: BLE001 - unreadable is a denial
            return (
                "state_incoherent:security_state_unavailable:"
                f"{type(exc).__name__}"
            )

        if coherent:
            return None

        return f"state_incoherent:{reason}"

    def state_commit_records(self) -> tuple[dict, ...]:
        """Every recorded state commitment, oldest first.

        Read-only accessor for operators and the invariant suite: the
        journal is append-only and nothing here can make an authorize
        allow. Plain dicts are returned so callers cannot mutate the
        live records through the returned objects.
        """

        journal = getattr(self, "state_commit", None)

        if journal is None:
            return ()

        return tuple(
            record.to_dict()
            for record in journal.records()
        )

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
    # Execution leases (v2.7)
    # ========================================================
    #
    # The ALLOW -> execute boundary. ``authorize`` returns a verdict
    # about the instant its last read happened; nothing in v2.6 connected
    # that instant to the moment a side effect runs. These methods record
    # the continuation (a lease), and each progression of the recorded
    # state machine re-establishes the authority basis against live state
    # before it advances. An execution that cannot establish the basis is
    # refused with a verdict-shaped outcome -- never an exception, never a
    # guess, never a clean COMPLETED.
    #
    # This is not a second authorization system. No verdict is
    # constructed here; every check below is deny-only, the same shape as
    # a gate (``MODEL_NON_AUTHORITY``: a gate may deny or abstain, never
    # allow), and the only allow an execution rests on is the one
    # ``authorize`` already produced and recorded. What these methods add
    # is that the allow can no longer be *used* once the state that
    # produced it stops holding.

    # ------------------------------------------------------------------
    # Issue
    # ------------------------------------------------------------------

    def authorize_execution(
        self,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
        ttl: float = DEFAULT_LEASE_TTL_SECONDS,
    ) -> ExecutionLeaseOutcome:
        """Authorize through the canonical boundary, then record a lease.

        The decision is made by :meth:`authorize` -- reached exactly as
        every other caller reaches it -- and the lease is issued only for
        an allow. Between the allow and the issue the authority epoch is
        sampled again and must still cover the whole interval; a
        widening that moved the context between the decision and its
        continuation is refused exactly as one that moved during the
        decision would have been.

        The returned lease binds the material facts of the decision:
        capability fingerprint, agent, action, request digest, the
        delegation chain, the policy version and the epoch sample.
        Nothing in the lease is a permission; every later operation
        re-reads the authoritative record and re-establishes the basis
        against live state.

        Refusals return an :class:`ExecutionLeaseOutcome` with
        ``allowed=False``. A denial from the boundary keeps its reason;
        a refusal to attach an execution to an allow that could not be
        recorded is ``evidence_unavailable``-shaped and conservative
        (the allow's budget has been spent and is not refunded), exactly
        as ``authorize`` itself treats an unrecordable allow.
        """

        if not isinstance(capability, Capability):
            return ExecutionLeaseOutcome.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return ExecutionLeaseOutcome.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return ExecutionLeaseOutcome.refused("invalid_request")

        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
            return ExecutionLeaseOutcome.refused(
                "invalid_lease_ttl"
            )

        ttl = float(ttl)

        if not math.isfinite(ttl) or ttl <= 0:
            return ExecutionLeaseOutcome.refused(
                "invalid_lease_ttl"
            )

        # Outer epoch window around the whole authorize-then-issue
        # sequence. ``authorize`` runs its own window inside this one; a
        # window that covers here covers the inner window too.
        entry = self.authority_epoch.sample()

        result = self.authorize(
            capability,
            action,
            request,
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        if not result.allowed:
            return ExecutionLeaseOutcome.refused(result.reason)

        commit = self.authority_epoch.sample()

        if not entry.covers(commit):
            reason = entry.divergence(commit)
            self._record_flight_event(
                EventType.SECURITY_STATE,
                {
                    "change": "execution_lease_withheld",
                    "reason": reason,
                    "capability": capability.capability,
                    "agent": capability.agent_id,
                    "action": action,
                },
                agent=capability.agent_id,
            )
            return ExecutionLeaseOutcome.refused(reason)

        policy_version = self._authorization_policy_version()

        if policy_version == UNKNOWN or not isinstance(
            policy_version, str
        ):
            return ExecutionLeaseOutcome.refused(
                "policy_version_unavailable"
            )

        try:
            request_digest = canonical_request_digest(request)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return ExecutionLeaseOutcome.refused(
                f"invalid_request:{type(error).__name__}"
            )

        try:
            authority = self._resolve_delegation_authority(
                capability
            )
        except Exception as error:  # noqa: BLE001 - unresolvable is a refusal
            return ExecutionLeaseOutcome.refused(
                "delegation_chain_unavailable:"
                f"{type(error).__name__}"
            )

        try:
            chain_fingerprints = tuple(
                capability_fingerprint(member)
                for member in authority.capabilities
            )
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return ExecutionLeaseOutcome.refused(
                f"invalid_capability:{type(error).__name__}"
            )

        try:
            record = self.execution_leases.issue(
                capability_fingerprint=capability_fingerprint(
                    capability
                ),
                agent_id=capability.agent_id,
                capability=capability.capability,
                action=action,
                request_digest=request_digest,
                chain_id=chain_id,
                policy_version=policy_version,
                ttl=ttl,
                issuer=capability.issuer,
                tool=capability.tool,
                chain_fingerprints=chain_fingerprints,
                epoch_finished=entry.finished,
                epoch_in_flight=entry.in_flight,
            )
        except ExecutionLeaseError as exc:
            # The allow exists but its continuation could not be
            # recorded. Refusing the lease is the conservative answer;
            # the allow was spent and is not refunded, and the lease
            # record is the evidence the execution would have needed.
            self._record_flight_event(
                EventType.SECURITY_STATE,
                {
                    "change": "execution_lease_store_error",
                    "error": type(exc).__name__,
                    "capability": capability.capability,
                    "agent": capability.agent_id,
                    "action": action,
                },
                agent=capability.agent_id,
            )
            return ExecutionLeaseOutcome.refused(
                "execution_lease_store_error:"
                f"{type(exc).__name__}"
            )
        except (ValueError, TypeError) as exc:
            return ExecutionLeaseOutcome.refused(
                f"execution_lease_error:{type(exc).__name__}"
            )

        # v3.3: the genesis of this execution's lineage. The lease exists
        # because an allow produced it, so the chain begins at AUTHORIZED and
        # every later stage is gated on this chain's head. A chain that cannot
        # be opened withholds the lease: an execution the firewall cannot
        # account for afterwards is one it should not start.
        if self._open_lineage(record) is None and self._require_lineage:
            self._record_flight_event(
                EventType.SECURITY_STATE,
                {
                    "change": "execution_lineage_unavailable",
                    "lease_id": record.lease_id,
                    "capability": record.capability,
                    "agent": record.agent_id,
                    "action": record.action,
                },
                agent=record.agent_id,
            )
            return ExecutionLeaseOutcome.refused(
                "lineage_unavailable"
            )

        self._record_execution_event(
            "execution_lease_issued",
            record,
        )

        return ExecutionLeaseOutcome(
            allowed=True,
            reason="lease_issued",
            state=record.state,
            lease=record,
        )

    # ------------------------------------------------------------------
    # Execution lineage (v3.3): helpers
    # ------------------------------------------------------------------
    #
    # One chain per execution, one commitment per stage, and every
    # progression conditional on the chain's current head. The journal below
    # is a *fourth* mechanism beside the lease store, the effect journal, the
    # verification journal and the attestation journal: it commits to them
    # and refuses when it cannot, and it has no authority of its own.

    @property
    def require_lineage(self) -> bool:
        """Whether a progression must have a verifiable lineage behind it.

        Read-only after construction, for the reason
        ``require_external_attestation`` is: switching it off would widen
        what may execute, and a mutable widening switch on the progression
        path is the shape this package refuses everywhere else.
        """

        return self._require_lineage

    @property
    def lineage_store(self):
        """The internally created SQLite lineage backend, or ``None``."""

        return self._lineage_store

    def lineage_records(self) -> tuple[ExecutionLineage, ...]:
        """Every open lineage, in open order.

        The lineage journal is state, not evidence and not authority; these
        values say which stage each execution reached and with which
        evidence. Reading them never changes anything.
        """

        try:
            return self.lineages.lineages()
        except LineageJournalError:
            return ()

    def lineage_links(self):
        """Every link in every chain, in chain order."""

        try:
            return self.lineages.links()
        except LineageJournalError:
            return ()

    def lineage_findings(self):
        """Every refused lineage operation, oldest first.

        A finding is the mechanism working: an attempted fork, a stale
        binding, a stage presented out of order. It is kept so the attempt is
        visible rather than being only a refusal in a return value.
        """

        try:
            return self.lineages.findings()
        except LineageJournalError:
            return ()

    def lineage_for_lease(
        self,
        lease_id: str,
    ) -> Optional[ExecutionLineage]:
        """The lineage bound to one lease, or ``None``."""

        try:
            return self.lineages.for_lease(lease_id)
        except LineageJournalError:
            return None

    # ------------------------------------------------------------------
    # Binding and evidence
    # ------------------------------------------------------------------

    @staticmethod
    def _lease_digest(record: ExecutionLease) -> str:
        """A stable digest of the lease record a stage progressed.

        Committed into the chain so a lease edited after the fact is visible
        as a disagreement between the row and the lineage that claims to
        describe it -- without the lineage holding a copy of the row.
        """

        try:
            return lineage_evidence_digest(record.to_dict())
        except Exception:  # noqa: BLE001 - an unnameable lease is refused
            return ""

    def _lineage_binding(
        self,
        record: ExecutionLease,
        *,
        effect_row: Any = None,
        claim: Any = None,
    ) -> dict[str, Any]:
        """The subject binding for one stage of one execution.

        Built from the *journal rows*, never from caller arguments: the lease
        record is authoritative for who, what, which capability and which
        request, and the effect row supplies the fields that only exist once
        an effect was prepared. Accumulating rather than replacing is what
        makes the chain's binding rule enforceable -- a stage may add a field
        it has newly learned, and may never change or drop one.

        Returns a dict already normalized by :func:`canonical_binding`, or an
        empty dict when the row cannot be read -- which the caller turns into
        a refusal, because a stage that cannot name its own execution is a
        stage that cannot be committed to a chain.
        """

        fields: dict[str, Any] = {
            "lease_id": record.lease_id,
            "capability_fingerprint": record.capability_fingerprint,
            "agent_id": record.agent_id,
            "capability": record.capability,
            "action": record.action,
            "request_digest": record.request_digest,
            "policy_version": record.policy_version,
            "execution_id": record.execution_id,
            "chain_id": record.chain_id,
            "issuer": record.issuer,
            "tool": record.tool,
        }

        if effect_row is not None:
            fields["effect_id"] = getattr(effect_row, "effect_id", None)
            fields["attempt_id"] = getattr(effect_row, "attempt_id", None)
            fields["idempotency_key"] = getattr(
                effect_row, "idempotency_key", None
            )
            fields["provider"] = getattr(effect_row, "provider", None)

        if claim is not None:
            fields["provider"] = getattr(claim, "provider", None) or fields.get(
                "provider"
            )

        try:
            return canonical_binding(fields)
        except LineageBindingError:
            return {}

    # ------------------------------------------------------------------
    # Open and advance
    # ------------------------------------------------------------------

    def _open_lineage(
        self,
        record: ExecutionLease,
        *,
        adopted: bool = False,
    ) -> Optional[ExecutionLineage]:
        """Open this lease's lineage, or return the one already open.

        Idempotent, because the issue path calls it once per lease and a
        retry after a crash between the backend write and the publish must
        resume rather than create a second chain. A *differently bound*
        genesis for the same lease is refused by the journal as a
        substitution, and a second lineage for an execution identity already
        bound elsewhere as a fork -- both recorded as findings.
        """

        binding = self._lineage_binding(record)

        if not binding:
            return None

        try:
            return self.lineages.open(
                lease_id=record.lease_id,
                execution_id=record.execution_id,
                binding=binding,
                lease_digest=self._lease_digest(record),
                adopted=adopted,
            )
        except LineageError:
            return None

    def _lineage_for(
        self,
        record: ExecutionLease,
    ) -> Optional[ExecutionLineage]:
        """The lineage for a lease, adopting one when none exists.

        Adoption is for the execution the firewall *inherited*: a
        caller-supplied lease store is a supported configuration, and a lease
        issued by a previous process generation legitimately has no lineage
        in this one. The adopted chain is marked as such in its genesis, so
        an operator can tell the firewall's own executions from the ones it
        took over, and the lease record remains the authority for the binding
        either way.

        What adoption is *not* is a way to escape the gate. Once a chain
        exists -- adopted or not -- every stage after it is gated on that
        chain's head, so a caller cannot obtain a second chain for one lease
        by deleting the first from memory.
        """

        existing = self.lineages.for_lease(record.lease_id)

        if existing is not None:
            return existing

        adopted = self._open_lineage(record, adopted=True)

        if adopted is None:
            return None

        self._adopt_lineage_stages(record)

        return self.lineages.for_lease(record.lease_id)

    def _lease_reached_executed(self, record: ExecutionLease) -> bool:
        """Whether the lease's own history shows the boundary was crossed.

        Read from the record's transition history rather than from its
        current phase, so a lease that was *aborted* after starting still
        shows EXECUTED -- it did execute, and the chain must say so -- while
        a lease that never left RESERVED does not.
        """

        if record.executed:
            return True

        if record.state is ExecutionState.STARTED:
            return True

        for entry in record.history:
            if entry[1] is ExecutionState.STARTED:
                return True

        return False

    def _adopt_lineage_stages(self, record: ExecutionLease) -> None:
        """Bring an adopted chain up to the position the records justify.

        An execution the firewall inherited -- a lease issued by a previous
        process generation, or by a caller-supplied store -- has no lineage
        in this one. The chain is opened at AUTHORIZED and then advanced
        through exactly the stages the *journals* show, so the adopted chain
        describes the execution as the records describe it rather than
        restarting the story at the moment the firewall noticed.

        Nothing here can widen anything: every derived stage is read from a
        row, a stage the journals do not justify is left for the completion
        gate to record as ``NOT_ADOPTED``, and a lease that is already
        terminal gets its chain sealed so no further commitment can land on
        an execution that has ended.
        """

        if not self._require_lineage:
            return

        row = self._effect_row(record.lease_id)

        if self._lease_reached_executed(record):
            lineage = self.lineages.for_lease(record.lease_id)

            if lineage is not None and (
                lineage.link_for(LineageStage.EXECUTED) is None
            ):
                reason = self._advance_lineage(
                    record,
                    stage=LineageStage.EXECUTED,
                    outcome=LineageOutcome.ADOPTED,
                    evidence={
                        "stage": LineageStage.EXECUTED.value,
                        "lease": _sdk_evidence(record),
                        "adopted": True,
                    },
                    effect_row=row,
                    details={"adopted": True},
                )

                if reason is not None:
                    # A refusal here is a finding, never silence: an adopted
                    # chain that stops one stage short of the execution it
                    # describes would make the completion gate refuse with a
                    # reason about a missing stage rather than about the
                    # adoption that failed to record it.
                    self._record_lineage_refusal(record, reason, "adopt")
                    return

        if not is_terminal(record.state):
            # A live adopted execution is gated from here on like one the
            # firewall issued itself: the evidence stages it has not reached
            # are committed at its close, from the journals.
            return

        # A terminal execution the firewall inherited is closed out here, so
        # its chain describes how it ended rather than stopping at the point
        # the firewall noticed it. The evidence stages are read from the rows
        # the journals hold -- never asserted -- and COMPLETED is committed
        # only for a lease that actually completed.
        self._complete_lineage_stages(record)

        lineage = self.lineages.for_lease(record.lease_id)

        if lineage is None or lineage.sealed:
            return

        if (
            record.state is ExecutionState.COMPLETED
            and lineage.link_for(LineageStage.COMPLETED) is None
        ):
            reason = self._advance_lineage(
                record,
                stage=LineageStage.COMPLETED,
                outcome=LineageOutcome.ADOPTED,
                evidence={
                    "stage": LineageStage.COMPLETED.value,
                    "lease": _sdk_evidence(record),
                    "adopted": True,
                },
                effect_row=row,
                details={"adopted": True},
            )

            if reason is not None:
                self._record_lineage_refusal(record, reason, "adopt")
                return

        self._seal_lineage(
            record,
            reason=f"adopted:{record.state.value}",
        )

    def _lineage_gate(
        self,
        record: ExecutionLease,
        *,
        expect: LineageStage,
    ) -> Optional[str]:
        """Why this progression lacks a provable lineage, or ``None``.

        Four questions, in the order that makes the refusal most useful: is
        there a chain; does it verify; is it still open; and is the head the
        stage this progression must follow. Every one of them is *deny-only*
        -- a ``None`` answer is the only pass, and an unreadable journal
        answers with a reason rather than an exception.
        """

        if not self._require_lineage:
            return None

        lineage = self._lineage_for(record)

        if lineage is None:
            return "lineage_unavailable"

        problem = lineage.first_problem()

        if problem is not None:
            return f"lineage_broken:{problem}"

        if lineage.sealed:
            return (
                "lineage_sealed:"
                + (lineage.seal_reason or "sealed")
            )

        head = lineage.head

        if head is None:
            return "lineage_empty"

        if head.is_seal:
            return "lineage_sealed:" + (head.seal_reason or "sealed")

        expected = head.ordinal

        if expected != STAGE_ORDINAL[expect]:
            commit = (
                head.stage.value if head.stage is not None else "seal"
            )
            return (
                f"lineage_stage_mismatch:expected_{expect.value}"
                f"_found_{commit}"
            )

        return None

    def _lineage_gate_satisfied(
        self,
        record: ExecutionLease,
        *,
        stage: LineageStage,
    ) -> Optional[str]:
        """Why the chain does not hold ``stage`` or a later one, or ``None``.

        For the operations that may legitimately arrive at more than one
        point in the pipeline. A reconciliation is the recovery path for an
        attempt that was never observed, so it must be admissible both before
        and after the observation it may produce; the strict
        :meth:`_lineage_gate` cannot express that, and expressing it as "any
        head at or after this stage" keeps the requirement deny-only.

        Like :meth:`_lineage_gate`, this answers ``None`` when the
        requirement is off. ``require_lineage=False`` is the v3.2 behaviour
        and *every* progression path has to honour it, not only the lease
        path -- the two gates diverging is what refused a caller with the
        requirement off on the side-effect path with
        ``lineage_stage_missing``.
        """

        if not self._require_lineage:
            return None

        lineage = self._lineage_for(record)

        if lineage is None:
            return "lineage_unavailable"

        problem = lineage.first_problem()

        if problem is not None:
            return f"lineage_broken:{problem}"

        if lineage.sealed:
            return "lineage_sealed:" + (lineage.seal_reason or "sealed")

        if lineage.ordinal < STAGE_ORDINAL[stage]:
            return f"lineage_stage_missing:{stage.value}"

        return None

    def _record_lineage_refusal(
        self,
        record: ExecutionLease,
        reason: str,
        where: str,
    ) -> None:
        """Record one lineage refusal in the journal's own audit trail.

        Best effort on purpose: the *decision* is the refusal the caller
        receives, and a failure to write the finding must not turn that
        refusal into an exception. The kind is derived from the reason so an
        operator can group attempts -- forks together, substitutions
        together -- without parsing prose.
        """

        kind = "unverifiable"

        for candidate in (
            "fork",
            "subject_mismatch",
            "stage_out_of_order",
            "sealed",
        ):
            if candidate in reason:
                kind = candidate
                break

        try:
            lineage = self.lineages.for_lease(record.lease_id)
            lineage_id = lineage.lineage_id if lineage is not None else ""
            self.lineages.record_finding(
                kind,
                lineage_id,
                0,
                f"{where}: {reason}",
            )
        except LineageError:
            return

    def _lineage_head_stage(
        self,
        record: ExecutionLease,
    ) -> Optional[LineageStage]:
        """The stage the chain's head commits, or ``None``.

        Used by the hooks that must fire only when the pipeline has reached
        exactly the stage before theirs -- an attestation recorded before the
        claim was verified is *deferred* rather than re-ordered, and the
        completion gate commits it from the journal when the order permits.
        """

        lineage = self._lineage_for(record)

        if lineage is None or lineage.sealed:
            return None

        head = lineage.head

        if head is None or not head.is_commitment:
            return None

        return head.stage

    def _advance_lineage(
        self,
        record: ExecutionLease,
        *,
        stage: LineageStage,
        outcome: LineageOutcome,
        evidence: Any,
        effect_row: Any = None,
        claim: Any = None,
        details: Optional[dict] = None,
    ) -> Optional[str]:
        """Commit one stage; return a refusal reason or ``None``.

        The evidence is the journal row that justified the progression -- or,
        for a stage the protocol did not perform, a small dict saying so --
        digested into the link rather than copied into it. The binding comes
        from the rows, so a stage cannot be committed describing an execution
        other than the one this chain is about.
        """

        if not self._require_lineage:
            return None

        lineage = self._lineage_for(record)

        if lineage is None:
            return "lineage_unavailable"

        # Cross-execution substitution is only visible where the rows are.
        # The journal's rule catches a field the chain has already *fixed*
        # changing; this catches the other direction -- evidence that belongs
        # to a different execution's lease being offered as this one's, which
        # the chain would otherwise accept as a newly learned field.
        if effect_row is not None:
            row_lease = getattr(effect_row, "lease_id", None)

            if row_lease is not None and row_lease != record.lease_id:
                self._record_lineage_refusal(
                    record,
                    f"lineage_subject_mismatch:the evidence names lease "
                    f"{str(row_lease)[:8]}...",
                    stage.value,
                )
                return (
                    "lineage_subject_mismatch:the evidence belongs to "
                    "another execution"
                )

        if lineage.link_for(stage) is not None:
            # The stage is already committed. A second call is a retry of
            # something that already happened -- re-presenting an identical
            # attestation, re-running a verification -- and re-committing it
            # would be the one thing the chain exists to refuse: a second
            # claim about one stage. The journal would refuse it as a fork,
            # so the hook declines to ask.
            return None

        binding = self._lineage_binding(
            record, effect_row=effect_row, claim=claim
        )

        if not binding:
            return "lineage_binding_invalid"

        try:
            self.lineages.advance(
                lineage_id=lineage.lineage_id,
                stage=stage,
                outcome=outcome,
                evidence=evidence,
                binding=binding,
                lease_digest=self._lease_digest(record),
                details=details,
            )
        except LineageStageOrderError as exc:
            return f"lineage_stage_out_of_order:{exc}"
        except LineageSubjectMismatchError as exc:
            return f"lineage_subject_mismatch:{exc}"
        except LineageForkError as exc:
            return f"lineage_fork:{exc}"
        except LineageSealedError as exc:
            return f"lineage_sealed:{exc}"
        except LineageBrokenError as exc:
            return f"lineage_broken:{exc}"
        except LineageUnknownError:
            return "lineage_unavailable"
        except LineageError:
            return "lineage_store_error"

        return None

    def _complete_lineage_stages(
        self,
        record: ExecutionLease,
    ) -> Optional[str]:
        """Bring the chain up to the stage before COMPLETED, or refuse.

        Two jobs, and they are deliberately one method because they must agree
        about what the journals say:

        * **Deferred stages are committed here.** An attestation recorded
          before its claim was verified could not be committed when it
          happened -- the pipeline order is OBSERVED, VERIFIED, ATTESTED, and
          the chain refuses to re-order itself -- so it is committed now,
          from the claim the journal already holds. The commitment names that
          claim, so the chain still binds the evidence that existed at the
          time rather than one produced for the occasion.
        * **Stages the protocol never performed are recorded as
          ``NOT_ADOPTED``.** An execution that adopted no side effect has no
          OBSERVED and no VERIFIED stage; recording that as a fact in the
          chain is what makes "this execution never adopted the protocol" an
          observation instead of an inference from a missing row.

        The adoption of each stage is *derived from the journals*, never
        asserted by the caller: an effect row with a recorded observation is
        an adopted OBSERVED stage, a current VERIFIED claim is an adopted
        VERIFIED stage, a current ATTESTED claim is an adopted ATTESTED stage,
        and a contradicted claim is a REFUSED one. That is the same rule the
        invariant re-checks, so the gate and the audit cannot drift apart.
        """

        if not self._require_lineage:
            return None

        lineage = self._lineage_for(record)

        if lineage is None:
            return "lineage_unavailable"

        row = self._effect_row(record.lease_id)

        for stage in PRIOR_STAGES:
            if lineage.link_for(stage) is not None:
                continue

            outcome, evidence = self._lineage_stage_evidence(
                record, stage=stage, row=row
            )

            reason = self._advance_lineage(
                record,
                stage=stage,
                outcome=outcome,
                evidence=evidence,
                effect_row=row,
                details={"derived": True},
            )

            if reason is not None:
                return reason

            lineage = self.lineages.for_lease(record.lease_id)

            if lineage is None:
                return "lineage_unavailable"

        return None

    def _lineage_stage_evidence(
        self,
        record: ExecutionLease,
        *,
        stage: LineageStage,
        row: Any,
    ):
        """``(outcome, evidence)`` for one stage, read from the journals.

        The evidence is the *row* the stage is about, so the digest committed
        into the chain names what actually existed. An absent row is
        ``NOT_ADOPTED`` with a small marker dict; a contradicted claim is
        ``REFUSED``, which is what stops a completion from being taken over an
        attestation or a verification the firewall recorded as
        contradictory.
        """

        if stage is LineageStage.OBSERVED:
            if row is not None and row.observed_outcome is not None:
                return (
                    LineageOutcome.ADOPTED,
                    _sdk_evidence(row),
                )

            return (
                LineageOutcome.NOT_ADOPTED,
                {"stage": stage.value, "evidence": "not_adopted"},
            )

        if stage is LineageStage.VERIFIED:
            claims = (
                self._effect_current_claims(row)
                if row is not None
                else ()
            )

            if not claims:
                return (
                    LineageOutcome.NOT_ADOPTED,
                    {"stage": stage.value, "evidence": "not_adopted"},
                )

            latest = claims[-1]

            if latest.outcome is VerificationOutcome.VERIFIED:
                return (LineageOutcome.ADOPTED, _sdk_evidence(latest))

            if latest.outcome is VerificationOutcome.CONTRADICTED:
                return (LineageOutcome.REFUSED, _sdk_evidence(latest))

            return (LineageOutcome.REFUSED, _sdk_evidence(latest))

        if stage is LineageStage.ATTESTED:
            claims = (
                self._attestation_current_claims(row)
                if row is not None
                else ()
            )

            if not claims:
                return (
                    LineageOutcome.NOT_ADOPTED,
                    {"stage": stage.value, "evidence": "not_adopted"},
                )

            latest = claims[-1]

            if latest.outcome is AttestationOutcome.ATTESTED:
                return (LineageOutcome.ADOPTED, _sdk_evidence(latest))

            return (LineageOutcome.REFUSED, _sdk_evidence(latest))

        # AUTHORIZED, EXECUTED and COMPLETED have no row-based evidence: the
        # lease record is their evidence, and the caller passes it.
        return (
            LineageOutcome.ADOPTED,
            {
                "stage": stage.value,
                "lease": _sdk_evidence(record),
            },
        )

    def _seal_lineage(
        self,
        record: ExecutionLease,
        *,
        reason: str,
    ) -> None:
        """End a lineage, recording why. Never raises, never blocks a verdict.

        Sealing is best effort on the way *out* of an execution: it records
        that this execution stopped and why, and it prevents any further
        commitment from being accepted. A seal that cannot be written is
        reported as a finding rather than propagated, because a failure to
        record why an execution ended must not turn a refusal (or a
        completion) into an exception at the call site.
        """

        try:
            lineage = self.lineages.for_lease(record.lease_id)

            if lineage is None or lineage.sealed:
                return

            self.lineages.seal(
                lineage_id=lineage.lineage_id,
                reason=reason or "terminated",
                lease_digest=self._lease_digest(record),
            )
        except LineageError:
            return

    # ------------------------------------------------------------------
    # Continuity validation (deny-only)
    # ------------------------------------------------------------------

    def _continuity_failure(
        self,
        lease: ExecutionLease,
        record: ExecutionLease,
        capability: Any,
        action: Any,
        request: Any,
    ) -> tuple[bool, str]:
        """Re-establish the authority basis; returns ``(ok, reason)``.

        Every check here is deny-only and total: a check that raises is a
        refusal naming the unavailable state, never a pass. ``unknown !=
        trusted`` applies to every read. The checks mirror the reads the
        boundary took at allow time -- revocation, issuer trust,
        signature, time, delegation lineage, policy version, Aegis, risk
        -- plus the authority epoch, so a lease cannot progress under a
        context that no longer covers its issue instant.

        Deliberately absent: security/semantic budgets. Those were
        consumed exactly once by the allow (``_gate_transaction``); an
        execution must not pay twice for the authorization it continues.
        """

        if not isinstance(lease, ExecutionLease):
            return False, "invalid_lease"

        if not isinstance(capability, Capability):
            return False, "invalid_capability"

        if not isinstance(action, str) or not action.strip():
            return False, "invalid_action"

        if request is not None and not isinstance(request, dict):
            return False, "invalid_request"

        # The object is a reference; the record is the authority. A
        # forged, copied, stale or edited object disagrees with the
        # record it names and is refused before any state is read.
        if getattr(lease, "lease_id", None) != record.lease_id:
            return False, "lease_mismatch"

        if getattr(lease, "nonce", None) != record.nonce:
            return False, "lease_mismatch"

        # A modified serialized lease is refused by name. The record is
        # authoritative, so an edited copy could not have changed what
        # the store enforces -- but refusing loudly is what makes a
        # tampered object visible in the audit trail instead of silently
        # equivalent to the untampered one. ``state`` is deliberately
        # excluded: the object's state is decoration and the record's is
        # authority, so forging it must not even cause a refusal (it must
        # simply change nothing).
        for field in (
            "capability_fingerprint",
            "agent_id",
            "capability",
            "action",
            "request_digest",
            "policy_version",
            "chain_id",
            "issued_at",
            "expires_at",
            "issuer",
            "tool",
            "chain_fingerprints",
        ):
            if getattr(lease, field, None) != getattr(record, field, None):
                return False, "lease_mismatch"

        try:
            fingerprint = capability_fingerprint(capability)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return False, f"invalid_capability:{type(error).__name__}"

        if fingerprint != record.capability_fingerprint:
            return False, "lease_capability_mismatch"

        if action != record.action:
            return False, "lease_action_mismatch"

        try:
            digest = canonical_request_digest(request)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return False, f"invalid_request:{type(error).__name__}"

        if digest != record.request_digest:
            return False, "lease_request_mismatch"

        if (
            capability.agent_id != record.agent_id
            or capability.capability != record.capability
            or capability.tool != record.tool
            or capability.issuer != record.issuer
        ):
            return False, "lease_identity_mismatch"

        # Time first: an unreadable clock, an expired lease or an expired
        # capability is answered before any other authority read, so a
        # store whose clock died reports ``clock_unavailable`` rather than
        # some downstream symptom of the same fault. The store clock is
        # the one that stamped the lease, so it is the one that compares
        # against the lease deadline.
        try:
            now = self.execution_leases.now()
        except ExecutionLeaseError as exc:
            return False, f"clock_unavailable:{type(exc).__name__}"

        if not math.isfinite(now):
            return False, "clock_unavailable:non_finite"

        # One definition of lease expiry, in the lease store, so the
        # enforcement path and the lapse sweep cannot disagree. It answers
        # with the earlier of two bounds -- the absolute wall deadline and
        # the monotonic budget the lease was granted -- and with an
        # anomaly reason when the clock the comparison would use is not
        # trustworthy. An anomaly deliberately does *not* burn the record:
        # a clock that moved backwards is not a statement about the
        # execution's authority, and burning it would let a clock fault
        # destroy a live execution's record.
        try:
            lapsed = self.execution_leases.validity(record)
        except TemporalError:
            return False, "clock_unavailable:TemporalError"
        except ExecutionLeaseError as exc:
            return False, f"clock_unavailable:{type(exc).__name__}"

        if lapsed is not None:
            return False, lapsed

        try:
            expires_at = capability.expires_at
            issued_at = capability.issued_at
        except Exception as error:  # noqa: BLE001 - unreadable is a refusal
            return False, (
                f"capability_time_invalid:{type(error).__name__}"
            )

        # ``unknown != trusted`` applies to the bounds themselves: a NaN
        # ceiling is not a ceiling, so a capability whose window cannot be
        # ordered is treated as expired rather than as valid.
        if isinstance(expires_at, float) and not math.isfinite(expires_at):
            return False, "capability_expired"

        if isinstance(issued_at, float) and not math.isfinite(issued_at):
            return False, "not_yet_valid"

        try:
            expired = now >= expires_at
            not_yet_valid = now < issued_at
        except Exception as error:  # noqa: BLE001 - unorderable is a refusal
            return False, (
                f"capability_time_invalid:{type(error).__name__}"
            )

        if not_yet_valid:
            return False, "not_yet_valid"
        if expired:
            return False, "capability_expired"

        # Issuer trust.
        trusted, unreadable = self._read_security_state(
            lambda: self.is_issuer_trusted(capability.issuer)
        )
        if unreadable is not None:
            return False, f"issuer_trust_unavailable:{unreadable}"
        if not trusted:
            return False, "issuer_untrusted"

        # Cryptographic verification against current trust state.
        verified, unreadable = self._read_security_state(
            lambda: self.verifier.verify(capability)
        )
        if unreadable is not None:
            return False, (
                f"capability_verification_unavailable:{unreadable}"
            )
        if not verified:
            return False, "capability_verification_failed"

        # Revocation, including ancestors of the *current* lineage.
        revoked, unreadable = self._read_security_state(
            lambda: self.is_effectively_revoked(capability)
        )
        if unreadable is not None:
            return False, f"revocation_state_unavailable:{unreadable}"
        if revoked:
            return False, "capability_revoked"

        # Delegation lineage: the chain the decision was taken under must
        # still be the chain this capability resolves to.
        try:
            authority = self._resolve_delegation_authority(
                capability
            )
            current_chain = tuple(
                capability_fingerprint(member)
                for member in authority.capabilities
            )
        except Exception as error:  # noqa: BLE001 - unresolvable is a refusal
            return False, (
                f"delegation_chain_unavailable:{type(error).__name__}"
            )

        if current_chain != tuple(record.chain_fingerprints):
            return False, "delegation_chain_changed"

        # Policy version: trusted issuers and the delegation-depth
        # ceiling, as ``authorize`` enforces them.
        policy_version = self._authorization_policy_version()
        if policy_version == UNKNOWN or not isinstance(
            policy_version, str
        ):
            return False, "policy_version_unavailable"
        if policy_version != record.policy_version:
            return False, "policy_version_changed"

        # Authority epoch: the context the decision was taken under must
        # still cover this instant.
        current_epoch = self.authority_epoch.sample()
        if current_epoch.finished != record.epoch_finished:
            return False, "execution_epoch_diverged"
        if record.epoch_in_flight or current_epoch.in_flight:
            return False, "execution_widening_in_flight"

        # Aegis restrictions, exactly as the boundary applies them.
        if self.aegis is not None:
            try:
                if self.aegis.tracked():
                    try:
                        reason = self.aegis.restriction_reason(
                            current_chain,
                            action,
                            request if request is not None else {},
                        )
                    except Exception as error:  # noqa: BLE001
                        return False, (
                            "aegis_state_unavailable:"
                            f"{type(error).__name__}"
                        )
                    if reason is not None:
                        return False, f"aegis_restricted:{reason}"
            except Exception as error:  # noqa: BLE001 - unreadable is a denial
                return False, (
                    f"aegis_state_unavailable:{type(error).__name__}"
                )

        # Risk state, when the SDK carries one.
        if self.risk_context is not None:
            permitted, unreadable = self._read_security_state(
                lambda: self.risk_context.can_authorize(
                    capability.agent_id
                )
            )
            if unreadable is not None:
                return False, f"risk_state_unavailable:{unreadable}"
            if not permitted:
                return False, "risk_state_revoked"

        return True, ""

    # ------------------------------------------------------------------
    # Progression helpers
    # ------------------------------------------------------------------

    def _lease_record(
        self,
        lease: Any,
    ) -> Optional[ExecutionLease]:
        """The authoritative record for a presented lease.

        ``None`` is the fail-closed answer for an unknown, absent or
        malformed lease: it cannot authorise anything.
        """

        if not isinstance(lease, ExecutionLease):
            return None

        try:
            return self.execution_leases.get(lease.lease_id)
        except ExecutionLeaseError:
            return None

    def _record_execution_event(
        self,
        change: str,
        record: ExecutionLease,
        *,
        extra: Optional[dict] = None,
    ) -> None:
        """Best-effort flight event for one execution phase change."""

        payload = {
            "change": change,
            "lease_id": record.lease_id,
            "capability": record.capability,
            "fingerprint": record.capability_fingerprint,
            "agent": record.agent_id,
            "action": record.action,
            "state": record.state.value,
        }
        if extra:
            payload.update(extra)
        self._record_flight_event(
            EventType.SECURITY_STATE,
            payload,
            agent=record.agent_id,
        )

    def _refuse_current(
        self,
        record: ExecutionLease,
        reason: str,
    ) -> ExecutionLeaseOutcome:
        return ExecutionLeaseOutcome(
            allowed=False,
            reason=reason,
            state=record.state,
            lease=record,
        )

    def _burn(
        self,
        record: ExecutionLease,
        reason: str,
    ) -> Optional[ExecutionLease]:
        """Move a lease to the terminal state its refusal names.

        Only called when the refusal means the lease itself (deadline)
        or the authority it continues (revoked, suspended, changed) is
        no longer usable, so the record must stop in an explicit
        terminal phase rather than linger for retry. An execution that
        was already ``STARTED`` records ``executed=True``: the action may
        have run, and the record must say so instead of silently
        pretending a refusal happened before anything did.
        """

        terminal = _execution_terminal_for(reason)

        if record.state is ExecutionState.STARTED:
            executed = True
        else:
            executed = False

        try:
            advanced = self.execution_leases.transition(
                record.lease_id,
                terminal,
                executed=executed,
                reason=reason,
                terminal_reason=reason,
            )
        except ExecutionLeaseError:
            return None

        if advanced is not None:
            # A burned lease is an execution that stopped where it stood, and
            # the chain says so: sealing prevents any further commitment from
            # being accepted, so a burned execution cannot later acquire a
            # stage that describes it as having progressed.
            self._seal_lineage(
                advanced,
                reason=f"{terminal.value}:{reason}",
            )

        return advanced

    # ------------------------------------------------------------------
    # Reserve / start / complete / abort
    # ------------------------------------------------------------------

    def reserve_execution(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        execution_id: Optional[str] = None,
    ) -> ExecutionLeaseOutcome:
        """Bind a lease to one execution identity and reserve it.

        Validation runs first: the presented capability/action/request
        must be the ones authorized, and the authority basis must still
        hold. A reservation is not execution -- nothing external has
        happened -- it is the recorded intent, held exactly once by the
        store's compare-and-set. A second reservation of the same lease,
        or a reservation of a second lease against the same live
        ``execution_id``, is refused.

        A refusal that invalidates the lease (revocation, suspension,
        expiry, a changed policy or epoch) moves it to a terminal state
        before returning; a refusal caused by caller misuse or unreadable
        state leaves the record in place.
        """

        record = self._lease_record(lease)

        if record is None:
            return ExecutionLeaseOutcome.refused("lease_unknown")

        if execution_id is not None and (
            not isinstance(execution_id, str)
            or not execution_id.strip()
        ):
            return self._refuse_current(
                record,
                "invalid_execution_id",
            )

        # v3.3: a reservation is the next step of an execution that already
        # has an AUTHORIZED stage. Without a provable chain this is not a
        # continuation, it is the start of an execution nobody can account
        # for -- so it is refused, and the refusal names which property of
        # the chain failed rather than merely that something did.
        lineage_reason = self._lineage_gate(
            record, expect=LineageStage.AUTHORIZED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "reserve")
            return self._refuse_current(record, lineage_reason)

        if record.state is not ExecutionState.LEASE_ISSUED:
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "reserve"),
            )

        ok, reason = self._continuity_failure(
            lease,
            record,
            capability,
            action,
            request,
        )

        if not ok:
            self._record_execution_event(
                "execution_reserve_refused",
                record,
                extra={"reason": reason},
            )
            if _execution_invalidating(reason):
                burned = self._burn(record, reason)
                if burned is not None:
                    return self._refuse_current(burned, reason)
            return self._refuse_current(record, reason)

        try:
            advanced = self.execution_leases.transition(
                record.lease_id,
                ExecutionState.RESERVED,
                execution_id=execution_id,
                reserve_authority_valid=True,
                reason="reserved",
            )
        except ExecutionIdentityBoundError:
            return self._refuse_current(record, "execution_identity_bound")
        except IllegalTransitionError:
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "reserve"),
            )
        except ExecutionLeaseError:
            return self._refuse_current(record, "lease_store_error")

        if advanced is None:
            return self._refuse_current(record, "lease_contended")

        self._record_execution_event(
            "execution_reserved",
            advanced,
        )

        return ExecutionLeaseOutcome(
            allowed=True,
            reason="reserved",
            state=advanced.state,
            lease=advanced,
        )

    def start_execution(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
    ) -> ExecutionLeaseOutcome:
        """Advance a reserved lease to ``STARTED``.

        This is the gate the caller crosses immediately before the
        external action runs. It re-establishes the whole authority
        basis *and* re-checks that the lease is still reserved by this
        caller; only then does the store's compare-and-set move the
        record. A refusal invalidating the lease terminates it here --
        before the action, so ``executed`` stays false.
        """

        record = self._lease_record(lease)

        if record is None:
            return ExecutionLeaseOutcome.refused("lease_unknown")

        if record.state is not ExecutionState.RESERVED:
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "start"),
            )

        # v3.3: this is the boundary crossing. The chain must still stand at
        # AUTHORIZED -- nothing between the allow and the action may have
        # added a stage to it -- and crossing commits EXECUTED, so the record
        # of *that* the action was entered is on the chain before the action
        # can run.
        lineage_reason = self._lineage_gate(
            record, expect=LineageStage.AUTHORIZED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "start")
            return self._refuse_current(record, lineage_reason)

        ok, reason = self._continuity_failure(
            lease,
            record,
            capability,
            action,
            request,
        )

        if not ok:
            self._record_execution_event(
                "execution_start_refused",
                record,
                extra={"reason": reason},
            )
            if _execution_invalidating(reason):
                burned = self._burn(record, reason)
                if burned is not None:
                    return self._refuse_current(burned, reason)
            return self._refuse_current(record, reason)

        try:
            advanced = self.execution_leases.transition(
                record.lease_id,
                ExecutionState.STARTED,
                start_authority_valid=True,
                reason="started",
            )
        except IllegalTransitionError:
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "start"),
            )
        except ExecutionLeaseError:
            return self._refuse_current(record, "lease_store_error")

        if advanced is None:
            return self._refuse_current(record, "lease_contended")

        committed = self._advance_lineage(
            advanced,
            stage=LineageStage.EXECUTED,
            outcome=LineageOutcome.ADOPTED,
            evidence={
                "stage": LineageStage.EXECUTED.value,
                "lease": _sdk_evidence(advanced),
            },
        )

        if committed is not None:
            # The action has not run yet, so this refusal costs nothing
            # external -- and an execution whose crossing is not on its chain
            # is exactly the one that must not proceed.
            self._record_lineage_refusal(advanced, committed, "start")
            burned = self._burn(advanced, committed)
            if burned is not None:
                return self._refuse_current(burned, committed)
            return self._refuse_current(advanced, committed)

        self._record_execution_event(
            "execution_started",
            advanced,
        )

        return ExecutionLeaseOutcome(
            allowed=True,
            reason="started",
            state=advanced.state,
            lease=advanced,
        )

    def complete_execution(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        details: Optional[dict] = None,
    ) -> ExecutionLeaseOutcome:
        """Close a started execution as ``COMPLETED``.

        Called *after* the external action has run. The authority basis
        is re-established one final time; if it no longer holds, the
        record stops in the terminal state the refusal names with
        ``executed=True`` -- an explicit, auditable failure saying the
        action ran and the authority did not hold to the end. A clean
        ``COMPLETED`` is only ever written when the basis held at the
        moment of completion.
        """

        record = self._lease_record(lease)

        if record is None:
            return ExecutionLeaseOutcome.refused("lease_unknown")

        if record.state is not ExecutionState.STARTED:
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "complete"),
            )

        ok, reason = self._continuity_failure(
            lease,
            record,
            capability,
            action,
            request,
        )

        if not ok:
            self._record_execution_event(
                "execution_complete_refused",
                record,
                extra={"reason": reason},
            )
            burned = self._burn(record, reason)
            if burned is not None:
                return self._refuse_current(burned, reason)
            return self._refuse_current(record, reason)

        # v2.8: an execution that adopted the side-effect protocol (its
        # lease carries a side-effect row) may only be recorded as a clean
        # COMPLETED when the journal shows the effect SUCCEEDED under
        # currently valid authority. A caller that prepared an effect and
        # then bypasses the protocol (recording neither a receipt nor a
        # reconciliation) gets a refusal that leaves the lease in place
        # for recovery -- never a clean completion over an unresolved
        # effect, and never a guess that the effect did or did not happen.
        #
        # v2.9 adds the last separator: AUTHORIZED =/= EXECUTED =/= OBSERVED
        # =/= VERIFIED =/= COMPLETED. A succeeded receipt is an
        # observation; a clean COMPLETED additionally requires a
        # verification claim on file that speaks about the row's *current*
        # evidence (same attempt, same evidence snapshot) and is VERIFIED,
        # with no CONTRADICTED claim recorded against that evidence. The
        # verification journal is a third journal; this gate only refuses.
        effect_row = self._effect_row(record.lease_id)

        if effect_row is not None:
            if not (
                effect_row.state is EffectState.SUCCEEDED
                and effect_row.observed_outcome is EffectOutcome.SUCCEEDED
                and effect_row.receipt_authority_valid is True
            ):
                self._record_effect_event(
                    "effect_completion_refused",
                    effect_row,
                    extra={
                        "reason": f"effect_unresolved:{effect_row.state.value}"
                    },
                )
                return self._refuse_current(
                    record,
                    f"effect_unresolved:{effect_row.state.value}",
                )

            current = self._effect_current_claims(effect_row)

            if not current:
                reason = "effect_unverified:no_verification_claim"
            elif any(
                claim.outcome is VerificationOutcome.CONTRADICTED
                for claim in current
            ):
                reason = "effect_unverified:evidence_contradicted"
            elif current[-1].outcome is not VerificationOutcome.VERIFIED:
                reason = (
                    "effect_unverified:"
                    + current[-1].outcome.value
                )
            else:
                reason = ""

            if reason:
                self._record_effect_event(
                    "effect_completion_refused",
                    effect_row,
                    extra={"reason": reason},
                )
                return self._refuse_current(record, reason)

        # v3.3: the chain must reach ATTESTED before a completion can be
        # committed, which is what makes "a completion was only ever written
        # over a complete sequence" a property of the record rather than a
        # promise about the code. Deferred stages are committed here from the
        # journals, stages the protocol never performed are recorded as
        # NOT_ADOPTED, and the completeness rule is then asked once.
        lineage_reason = self._complete_lineage_stages(record)

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "complete")
            return self._refuse_current(record, lineage_reason)

        lineage_reason = self._lineage_gate(
            record, expect=LineageStage.ATTESTED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "complete")
            return self._refuse_current(record, lineage_reason)

        lineage = (
            self.lineages.for_lease(record.lease_id)
            if self._require_lineage
            else None
        )

        if lineage is not None:
            problems = completeness_problems(
                lineage,
                side_effect_adopted=effect_row is not None,
                attestation_required=self._require_external_attestation,
                # The chain is one commitment short of finished: COMPLETED
                # is the stage this gate is about to write.
                expect_completed=False,
            )

            if problems:
                reason = "lineage_incomplete:" + "; ".join(problems)
                self._record_lineage_refusal(record, reason, "complete")
                return self._refuse_current(record, reason)

        try:
            advanced = self.execution_leases.transition(
                record.lease_id,
                ExecutionState.COMPLETED,
                complete_authority_valid=True,
                executed=True,
                reason="completed",
                details=details,
            )
        except IllegalTransitionError:
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "complete"),
            )
        except ExecutionLeaseError:
            return self._refuse_current(record, "lease_store_error")

        if advanced is None:
            return self._refuse_current(record, "lease_contended")

        committed = self._advance_lineage(
            advanced,
            stage=LineageStage.COMPLETED,
            outcome=LineageOutcome.ADOPTED,
            evidence={
                "stage": LineageStage.COMPLETED.value,
                "lease": _sdk_evidence(advanced),
            },
            effect_row=effect_row,
        )

        if committed is not None:
            # The store has already moved, so the lease is completed and the
            # chain is not -- the one state the layer refuses to paper over.
            # The refusal is returned with the completed record attached, so
            # the caller sees exactly what happened and an operator can
            # reconcile rather than guess.
            self._record_lineage_refusal(advanced, committed, "complete")
            return self._refuse_current(advanced, committed)

        self._seal_lineage(advanced, reason="completed")

        self._record_execution_event(
            "execution_completed",
            advanced,
        )

        return ExecutionLeaseOutcome(
            allowed=True,
            reason="completed",
            state=advanced.state,
            lease=advanced,
        )

    def abort_execution(
        self,
        lease: Any,
        *,
        reason: str = "aborted",
    ) -> ExecutionLeaseOutcome:
        """Terminate a lease without executing.

        Accepts an :class:`ExecutionLease` or a raw ``lease_id``, so an
        operator recovering a stuck record after a restart can abort by
        id. A lease that never started stops in ``ABORTED`` (``DENIED``
        from the unreserved phase, which has no abort edge); a started
        lease stops in ``ABORTED`` with ``executed=True``, because the
        action may already have run.
        """

        record = self._lease_record(lease)

        if record is None and isinstance(lease, str):
            try:
                record = self.execution_leases.get(lease)
            except ExecutionLeaseError:
                record = None

        if record is None:
            return ExecutionLeaseOutcome.refused("lease_unknown")

        if is_terminal(record.state):
            return self._refuse_current(
                record,
                f"lease_terminal:{record.state.value}",
            )

        if record.state is ExecutionState.LEASE_ISSUED:
            terminal = ExecutionState.DENIED
        else:
            terminal = ExecutionState.ABORTED

        executed = record.state is ExecutionState.STARTED

        try:
            advanced = self.execution_leases.transition(
                record.lease_id,
                terminal,
                executed=executed,
                reason=reason or "aborted",
                terminal_reason=reason or "aborted",
            )
        except (IllegalTransitionError, ExecutionLeaseError):
            return self._refuse_current(
                record,
                self._phase_mismatch_reason(record, "abort"),
            )

        if advanced is None:
            return self._refuse_current(record, "lease_contended")

        self._seal_lineage(
            advanced,
            reason=f"aborted:{reason or 'aborted'}",
        )

        self._record_execution_event(
            "execution_aborted",
            advanced,
        )

        return ExecutionLeaseOutcome(
            allowed=True,
            reason=reason or "aborted",
            state=advanced.state,
            lease=advanced,
        )

    def run_execution(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        handler: Optional[Callable[[], Any]] = None,
        execution_id: Optional[str] = None,
        abort_reason: str = "handler_failed",
    ) -> ExecutionLeaseOutcome:
        """Reserve, start, run the handler, and complete -- or fail loudly.

        The complete lifecycle for callers that want one call. Every
        progression still runs the deny-only continuity validation and
        the store's compare-and-set; this method only sequences them.
        The ``handler`` is the external action and runs strictly between
        ``STARTED`` and ``COMPLETED``. If it raises, the lease is aborted
        with ``executed=True`` (the action may have partially run) and
        the exception is re-raised -- a handler failure is the caller's
        failure, not a firewall verdict.

        Returns the ``COMPLETED`` outcome on success and the first
        refused outcome otherwise.
        """

        if handler is None or not callable(handler):
            raise TypeError("handler must be callable")

        reserved = self.reserve_execution(
            lease,
            capability,
            action,
            request,
            execution_id=execution_id,
        )

        if not reserved.allowed:
            return reserved

        started = self.start_execution(
            reserved.lease,
            capability,
            action,
            request,
        )

        if not started.allowed:
            # The lease was already burned to a terminal state by the
            # refusal, or left reserved; either way nothing ran.
            return started

        try:
            handler()
        except BaseException:
            self.abort_execution(
                started.lease,
                reason=abort_reason,
            )
            raise

        return self.complete_execution(
            started.lease,
            capability,
            action,
            request,
        )

    # ------------------------------------------------------------------
    # Inspection and housekeeping
    # ------------------------------------------------------------------

    @staticmethod
    def _phase_mismatch_reason(
        record: ExecutionLease,
        attempted: str,
    ) -> str:
        """Name why a progression does not apply to the current phase."""

        state = record.state.value

        if attempted == "reserve":
            if state == "reserved":
                return "lease_already_reserved"
            if state == "started":
                return "lease_already_started"
        if attempted == "start":
            if state == "started":
                return "lease_already_started"
            if state == "lease_issued":
                return "lease_not_reserved"
        if attempted == "complete":
            if state == "completed":
                return "lease_already_completed"
            if state == "reserved":
                return "lease_not_started"
            if state == "lease_issued":
                return "lease_not_reserved"

        return f"lease_phase:{attempted}:{state}"

    def execution_lease_records(
        self,
    ) -> tuple[ExecutionLease, ...]:
        """Every execution lease record, in insertion order.

        The lease store is state, not evidence; these records are for an
        operator reconciling what an execution did, not for deciding
        anything. Reading them never changes a phase.
        """

        try:
            return self.execution_leases.records()
        except ExecutionLeaseError:
            return ()

    def expire_lapsed_executions(self) -> int:
        """Terminate leases whose deadline passed without progression.

        Returns how many were lapsed. ``STARTED`` leases are left alone:
        the action may genuinely be running, and deciding it did not is
        the guess the store refuses to make.

        v3.3: the lineages of the leases this sweep terminates are sealed.
        The sweep moves records in the store, which the journal knows
        nothing about, so without this a lapsed execution would be terminal
        with an open chain -- an execution whose record of *how* it ended is
        missing, which is the one thing the lineage exists to prevent.
        """

        try:
            before = {
                lease.lease_id
                for lease in self.execution_leases.records()
                if not is_terminal(lease.state)
            }
        except ExecutionLeaseError:
            return 0

        try:
            lapsed = self.execution_leases.expire_lapsed()
        except ExecutionLeaseError:
            return 0

        if lapsed:
            for lease_id in self._lapsed_lease_ids(before):
                record = None

                try:
                    record = self.execution_leases.get(lease_id)
                except ExecutionLeaseError:
                    record = None

                if record is None or not is_terminal(record.state):
                    continue

                self._seal_lineage(
                    record,
                    reason=f"expired:{record.terminal_reason or 'lapsed'}",
                )

        return lapsed

    def _lapsed_lease_ids(self, before: set) -> tuple[str, ...]:
        """The leases this sweep moved to a terminal state, by id."""

        moved: list[str] = []

        for lease_id in sorted(before):
            try:
                record = self.execution_leases.get(lease_id)
            except ExecutionLeaseError:
                continue

            if record is not None and is_terminal(record.state):
                moved.append(lease_id)

        return tuple(moved)


    # ------------------------------------------------------------------
    # Side-effect protocol (v2.8): helpers
    # ------------------------------------------------------------------

    def _effect_row(
        self,
        lease_id: str,
    ):
        """The side-effect row bound to one lease, or ``None``.

        ``None`` is the fail-closed answer for an unknown row *and* for an
        unreadable journal: either way there is no recorded side effect to
        advance.
        """

        if not isinstance(lease_id, str) or not lease_id:
            return None

        try:
            return self.effects.by_lease(lease_id)
        except EffectJournalError:
            return None

    def _record_effect_event(
        self,
        change: str,
        row,
        *,
        extra: Optional[dict] = None,
    ) -> None:
        """Best-effort flight event for one side-effect phase change."""

        payload = {
            "change": change,
            "effect_id": row.effect_id,
            "lease_id": row.lease_id,
            "execution_id": row.execution_id,
            "effect_type": row.effect_type,
            "state": row.state.value,
            "capability": row.capability,
            "agent": row.agent_id,
            "action": row.action,
        }

        if extra:
            payload.update(extra)

        self._record_flight_event(
            EventType.SECURITY_STATE,
            payload,
            agent=row.agent_id,
        )

    def _refuse_effect_current(
        self,
        row,
        reason: str,
    ):
        """An :class:`EffectResult` refusal carrying the current row."""

        return EffectResult(
            allowed=False,
            reason=reason,
            state=row.state,
            effect=row,
        )

    def _effect_refusal_outcome(
        self,
        record: ExecutionLease,
        reason: str,
    ):
        """An :class:`EffectResult` for a lease-level refusal.

        A reason that invalidates the lease (revocation, suspension,
        expiry, a changed policy or epoch) burns it to its terminal state
        before returning, exactly as the v2.7 progression refusals do;
        a refusal caused by caller misuse or unreadable state leaves the
        record in place for retry.
        """

        if _execution_invalidating(reason):
            burned = self._burn(record, reason)
            if burned is not None:
                record = burned

        return EffectResult(
            allowed=False,
            reason=reason,
            state=None,
            effect=self._effect_row(record.lease_id),
        )

    def _effect_phase_refusal(
        self,
        record: ExecutionLease,
        step: str,
    ):
        """A refusal for a side-effect step attempted from the wrong phase."""

        name = record.state.value

        if step == "prepare":
            if name == "lease_issued":
                reason = "lease_not_reserved"
            else:
                reason = f"lease_phase:prepare:{name}"
        else:  # attempt
            if name == "reserved":
                reason = "lease_not_started"
            elif name == "lease_issued":
                reason = "lease_not_reserved"
            else:
                reason = f"lease_phase:attempt:{name}"

        return EffectResult(
            allowed=False,
            reason=reason,
            state=None,
            effect=self._effect_row(record.lease_id),
        )

    def _effect_authority_snapshot(
        self,
        lease: ExecutionLease,
        record: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict],
    ):
        """``(authority_valid, reason, lease_record)`` -- journal-free.

        A terminal lease cannot complete under currently valid authority,
        so it answers ``(False, lease_terminal:...)``. For a live lease
        the deny-only continuity validation decides; when it fails the
        lease is burned exactly as v2.7 completion burns it, so an
        observation that arrives after authority was lost leaves an
        auditable terminal execution -- history is never rewritten, and
        the observation is never claimed to have happened under authority
        the execution cannot establish.
        """

        if is_terminal(record.state):
            return False, f"lease_terminal:{record.state.value}", record

        ok, reason = self._continuity_failure(
            lease,
            record,
            capability,
            action,
            request,
        )

        if ok:
            return True, "", record

        self._record_execution_event(
            "effect_authority_lost",
            record,
            extra={"reason": reason},
        )
        burned = self._burn(record, reason)
        if burned is not None:
            return False, reason, burned
        return False, reason, record

    def _effect_binding_mismatch(
        self,
        row,
        effect_type: str,
        effect_digest: str,
        idempotency_key: str,
    ) -> Optional[str]:
        """Why a presented effect disagrees with the bound row, if it does.

        The row's binding fields are immutable; the effect that executes
        must be the effect that was prepared. A mismatch returns
        ``effect_mismatch`` -- a modified effect never silently executes
        under a recorded intent.
        """

        if row.effect_type != effect_type:
            return "effect_mismatch"
        if row.effect_digest != effect_digest:
            return "effect_mismatch"
        if row.idempotency_key != idempotency_key:
            return "effect_mismatch"
        return None

    @staticmethod
    def _coerce_outcome(value):
        """``EffectOutcome`` from a member or its value; ``None`` otherwise."""

        try:
            return EffectOutcome(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_receipt_kind(value):
        """``ReceiptKind`` from a member or its value; ``None`` otherwise."""

        try:
            return ReceiptKind(value)
        except (TypeError, ValueError):
            return None

    def _effect_default_key(
        self,
        idempotency_key: Optional[str],
        effect_digest: str,
    ) -> Optional[str]:
        """The effective idempotency key.

        Omitted keys default to the effect digest, so an unprepared retry
        of the same logical effect naturally maps to the same key.
        """

        if idempotency_key is not None and idempotency_key != "":
            if not isinstance(idempotency_key, str):
                return None
            return idempotency_key
        return effect_digest

    # ------------------------------------------------------------------
    # Effect verification (v2.9): helpers
    # ------------------------------------------------------------------

    def _effect_current_claims(
        self,
        row,
    ) -> tuple:
        """Every verification claim about the row's *current* evidence.

        A claim speaks about exactly one evidence snapshot. Only claims
        whose snapshot matches the row's current snapshot and whose
        attempt is the row's current attempt speak about what the row now
        says; anything else is stale, belongs to another attempt, or was
        superseded by a later reconciliation. Returned oldest first, so
        the last element is the latest verdict on the current evidence.
        """

        try:
            claims = self.verifications.by_effect(row.effect_id)
        except VerificationJournalError:
            return ()

        if not claims:
            return ()

        try:
            current_digest = canonical_evidence_digest(row)
        except Exception:  # noqa: BLE001 - unnameable evidence is a refusal
            return ()

        return tuple(
            claim
            for claim in claims
            if (
                claim.attempt_id == row.attempt_id
                and claim.snapshot_digest == current_digest
            )
        )

    @staticmethod
    def _resolve_verifier(verifier, method):
        """``(verifier, method)``, or ``None`` when the pair is not legal.

        No verifier means the built-in structural verifier, the only one
        that may run unnamed: it establishes internal soundness only and
        says so with ``STRUCTURAL_METHOD``. A deployment verifier must be
        named by the caller and must not claim the structural id -- the
        journal must never guess whose check a VERIFIED claim came from,
        and nothing else may impersonate the built-in method.
        """

        if verifier is None:
            return structural_verifier, STRUCTURAL_METHOD

        if not callable(verifier):
            return None

        if method is None or not isinstance(method, str) or not method.strip():
            return None

        if method.strip() == STRUCTURAL_METHOD:
            return None

        return verifier, method.strip()

    def _journal_verification(
        self,
        row,
        *,
        outcome: VerificationOutcome,
        method: str,
        snapshot: dict,
        snapshot_digest: str,
        note: Optional[str] = None,
    ) -> Optional[VerificationRecord]:
        """Persist one verification claim, idempotently.

        Returns ``None`` when the claim could not be written -- a claim
        must not be reported recorded when it was not. An identical
        retry returns the existing claim.
        """

        try:
            return self.verifications.record(
                effect_id=row.effect_id,
                lease_id=row.lease_id,
                execution_id=row.execution_id,
                attempt_id=row.attempt_id,
                outcome=outcome,
                method=method,
                snapshot=snapshot,
                snapshot_digest=snapshot_digest,
                observed_outcome=row.observed_outcome,
                evidence_kind=row.evidence_kind,
                receipt_authority_valid=(
                    row.receipt_authority_valid is True
                ),
                note=note,
            )
        except (VerificationJournalError, TypeError, ValueError):
            return None

    def _verify_row_claim(
        self,
        lease,
        record,
        capability,
        action,
        request,
        row,
        *,
        verifier,
        method,
        note,
    ) -> VerificationResult:
        """Run one verification of the row's recorded claim.

        ``allowed`` is true only when a ``VERIFIED`` claim is now on
        record for the row's current evidence. The row's recorded
        observation -- not the caller -- is what is verified: the
        evidence snapshot is re-derived from the journal row, and the
        verifier inspects that package. A ``VERIFIED`` verdict may only
        be recorded while the execution's authority basis still holds; if
        it was withdrawn the verdict is preserved truthfully as
        ``NOT_VERIFIED`` (never as a pass), the lease is burned exactly
        as a v2.8 receipt after authority loss burns it, and the result
        refuses. Contradictory and negative verdicts are recorded
        whenever the verifier produced them: they can only refuse.
        """

        if getattr(row, "attempt_id", None) is None:
            return VerificationResult.refused("effect_not_attempted")

        if (
            getattr(row, "evidence_kind", None) is None
            or getattr(row, "observed_outcome", None) is None
        ):
            return VerificationResult.refused(
                "effect_has_no_recorded_observation"
            )

        try:
            snapshot = canonical_evidence_snapshot(row)
            snapshot_digest = canonical_evidence_digest(row)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return VerificationResult.refused(
                f"invalid_effect_evidence:{type(error).__name__}"
            )

        resolved = self._resolve_verifier(verifier, method)

        if resolved is None:
            return VerificationResult.refused(
                "invalid_verification_method"
            )

        verifier_fn, method_name = resolved

        authority_valid, failure_reason, _latest = (
            self._effect_authority_snapshot(
                lease,
                record,
                capability,
                action,
                request,
            )
        )

        package = evidence_package(
            row,
            snapshot=snapshot,
            snapshot_digest=snapshot_digest,
        )

        try:
            verdict = verifier_fn(package)
        except BaseException as error:  # noqa: BLE001 - crashed verifier
            claim = self._journal_verification(
                row,
                outcome=VerificationOutcome.NOT_VERIFIED,
                method=method_name,
                snapshot=snapshot,
                snapshot_digest=snapshot_digest,
                note=(
                    f"the verifier {method_name!r} raised "
                    f"{type(error).__name__}"
                ),
            )
            return VerificationResult(
                allowed=False,
                reason="effect_verification_failed:verifier_raised",
                outcome=VerificationOutcome.NOT_VERIFIED,
                record=claim,
            )

        if not isinstance(verdict, VerifierVerdict):
            return VerificationResult.refused(
                "invalid_verifier_verdict"
            )

        outcome = verdict.outcome

        if outcome is VerificationOutcome.VERIFIED:
            if not authority_valid:
                # A VERIFIED verdict cannot be recorded under lost
                # authority, and the withdrawal must not be hidden: the
                # verdict is preserved as NOT_VERIFIED naming the loss.
                claim = self._journal_verification(
                    row,
                    outcome=VerificationOutcome.NOT_VERIFIED,
                    method=method_name,
                    snapshot=snapshot,
                    snapshot_digest=snapshot_digest,
                    note=(
                        "the verifier returned VERIFIED but the "
                        "execution's authority basis no longer holds "
                        f"({failure_reason or 'authority_lost'}); the "
                        "claim was not recorded as verified"
                    ),
                )
                reason = failure_reason or "effect_authority_lost"
                self._record_effect_event(
                    "effect_verification_refused",
                    row,
                    extra={"reason": reason},
                )
                return VerificationResult(
                    allowed=False,
                    reason=reason,
                    outcome=VerificationOutcome.NOT_VERIFIED,
                    record=claim,
                )

            claim = self._journal_verification(
                row,
                outcome=VerificationOutcome.VERIFIED,
                method=method_name,
                snapshot=snapshot,
                snapshot_digest=snapshot_digest,
                note=verdict.note,
            )

            if claim is None:
                return VerificationResult.refused(
                    "verification_store_error"
                )

            self._record_effect_event(
                "effect_verified",
                row,
                extra={
                    "method": method_name,
                    "verification_id": claim.verification_id[:8],
                },
            )

            return VerificationResult(
                allowed=True,
                reason="effect_verified",
                outcome=VerificationOutcome.VERIFIED,
                record=claim,
            )

        if outcome not in (
            VerificationOutcome.NOT_VERIFIED,
            VerificationOutcome.CONTRADICTED,
        ):
            return VerificationResult.refused(
                "invalid_verifier_verdict"
            )

        # Negative and contradictory verdicts are recorded truthfully
        # whenever the verifier produced them; neither can grant anything.
        claim = self._journal_verification(
            row,
            outcome=outcome,
            method=method_name,
            snapshot=snapshot,
            snapshot_digest=snapshot_digest,
            note=verdict.note,
        )

        if claim is None:
            return VerificationResult.refused(
                "verification_store_error"
            )

        if outcome is VerificationOutcome.CONTRADICTED:
            reason = "effect_contradicted"
        else:
            reason = "effect_not_verified"

        return VerificationResult(
            allowed=False,
            reason=reason,
            outcome=outcome,
            record=claim,
        )

    # ------------------------------------------------------------------
    # Side-effect protocol (v2.8): the protocol itself
    # ------------------------------------------------------------------

    def prepare_effect(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        ttl: float = DEFAULT_EFFECT_TTL_SECONDS,
    ):
        """Record the durable intent of one external effect (the outbox).

        This is the step that makes the v2.7 boundary explicit: before
        any external request may be authorized, the intended effect is
        recorded durably as ``INTENT_RECORDED`` and bound to the
        execution's lease, capability fingerprint, agent, action, request
        digest, effect digest, policy version, epoch sample and
        idempotency key. The lease must be reserved or started, and the
        execution's authority basis must hold -- an allow whose state died
        after ``authorize`` cannot even record an intent.

        The effect payload itself is not stored: the row carries only its
        canonical digest, so sensitive effect data is not duplicated into
        the journal. A caller that later presents a different effect (or a
        different idempotency key) for the same lease is refused with
        ``effect_mismatch`` -- the effect cannot change after it was
        recorded.

        Idempotency: repeating this call with the same lease, same effect
        and same key returns the existing row (``effect_already_prepared``)
        and creates no second row and no second attempt.

        Returns an :class:`EffectResult`; ``allowed`` is true when a
        durable intent row for exactly this effect exists.
        """

        if not isinstance(lease, ExecutionLease):
            return EffectResult.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return EffectResult.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return EffectResult.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return EffectResult.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return EffectResult.refused("invalid_effect_type")

        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
            return EffectResult.refused("invalid_effect_ttl")

        ttl = float(ttl)

        if not math.isfinite(ttl) or ttl <= 0:
            return EffectResult.refused("invalid_effect_ttl")

        record = self._lease_record(lease)

        if record is None:
            return EffectResult.refused("lease_unknown")

        if record.state not in (
            ExecutionState.RESERVED,
            ExecutionState.STARTED,
        ):
            return self._effect_phase_refusal(record, "prepare")

        ok, reason = self._continuity_failure(
            lease,
            record,
            capability,
            action,
            request,
        )

        if not ok:
            self._record_execution_event(
                "effect_prepare_refused",
                record,
                extra={"reason": reason},
            )
            return self._effect_refusal_outcome(record, reason)

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return EffectResult.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return EffectResult.refused("invalid_idempotency_key")

        effect_type = effect_type.strip()

        existing = self._effect_row(record.lease_id)

        if existing is not None:
            mismatch = self._effect_binding_mismatch(
                existing,
                effect_type,
                effect_digest,
                idem,
            )
            if mismatch is not None:
                return self._refuse_effect_current(existing, mismatch)
            return EffectResult(
                allowed=True,
                reason="effect_already_prepared",
                state=existing.state,
                effect=existing,
            )

        try:
            row = self.effects.create(
                lease_id=record.lease_id,
                execution_id=record.execution_id,
                capability_fingerprint=record.capability_fingerprint,
                agent_id=record.agent_id,
                capability=record.capability,
                action=record.action,
                request_digest=record.request_digest,
                effect_type=effect_type,
                effect_digest=effect_digest,
                idempotency_key=idem,
                chain_id=record.chain_id,
                policy_version=record.policy_version,
                issuer=record.issuer,
                tool=record.tool,
                chain_fingerprints=record.chain_fingerprints,
                epoch_finished=record.epoch_finished,
                epoch_in_flight=record.epoch_in_flight,
                ttl=ttl,
                intent_authority_valid=True,
            )
        except EffectAlreadyBoundError:
            # Another process prepared first. Serve the existing row on an
            # identical binding; refuse a different one.
            existing = self._effect_row(record.lease_id)
            if existing is None:
                return EffectResult.refused("effect_contended")
            mismatch = self._effect_binding_mismatch(
                existing,
                effect_type,
                effect_digest,
                idem,
            )
            if mismatch is not None:
                return self._refuse_effect_current(existing, mismatch)
            return EffectResult(
                allowed=True,
                reason="effect_already_prepared",
                state=existing.state,
                effect=existing,
            )
        except EffectJournalError as exc:
            return EffectResult.refused(
                f"effect_store_error:{type(exc).__name__}"
            )
        except (ValueError, TypeError) as exc:
            return EffectResult.refused(
                f"effect_store_error:{type(exc).__name__}"
            )

        self._record_effect_event(
            "effect_prepared",
            row,
        )

        return EffectResult(
            allowed=True,
            reason="effect_prepared",
            state=row.state,
            effect=row,
        )

    def attempt_effect(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ):
        """Authorize and record the attempt: the boundary crossing.

        The lease must be ``STARTED`` and the execution's authority basis
        must still hold -- this is the last gate before the external
        request, so the full deny-only continuity validation runs here
        exactly as it runs on ``start_execution``. Only then does the one
        atomic compare-and-set move the row ``INTENT_RECORDED ->
        ATTEMPT_STARTED`` and stamp an attempt identifier.

        Exactly one attempt is possible per row. A retry of the same
        lease/effect/key after a timeout finds the row already in
        ``ATTEMPT_STARTED`` and is refused with ``effect_already_attempted``
        (carrying the row): the firewall will not authorise an unbounded
        number of real-world attempts because a caller retried.
        """

        if not isinstance(lease, ExecutionLease):
            return EffectResult.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return EffectResult.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return EffectResult.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return EffectResult.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return EffectResult.refused("invalid_effect_type")

        record = self._lease_record(lease)

        if record is None:
            return EffectResult.refused("lease_unknown")

        if record.state is not ExecutionState.STARTED:
            return self._effect_phase_refusal(record, "attempt")

        ok, reason = self._continuity_failure(
            lease,
            record,
            capability,
            action,
            request,
        )

        if not ok:
            self._record_execution_event(
                "effect_attempt_refused",
                record,
                extra={"reason": reason},
            )
            return self._effect_refusal_outcome(record, reason)

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return EffectResult.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return EffectResult.refused("invalid_idempotency_key")

        row = self._effect_row(record.lease_id)

        if row is None:
            return EffectResult.refused("effect_unknown")

        mismatch = self._effect_binding_mismatch(
            row,
            effect_type.strip(),
            effect_digest,
            idem,
        )

        if mismatch is not None:
            return self._refuse_effect_current(row, mismatch)

        if row.state is EffectState.ATTEMPT_STARTED:
            return self._refuse_effect_current(
                row,
                "effect_already_attempted",
            )

        if row.state in (
            EffectState.SUCCEEDED,
            EffectState.FAILED,
        ):
            return self._refuse_effect_current(
                row,
                "effect_already_resolved",
            )

        if row.state is EffectState.UNKNOWN:
            # The effect may already have happened. Retrying the
            # transmission could duplicate a real-world action, so the
            # only path out of UNKNOWN is an explicit reconciliation.
            return self._refuse_effect_current(
                row,
                "effect_unresolved:unknown",
            )

        try:
            attempted_at = self.effects.now()
        except EffectJournalError:
            return EffectResult.refused("effect_clock_unavailable")

        attempt_id = uuid.uuid4().hex

        try:
            advanced = self.effects.transition(
                row.effect_id,
                EffectState.ATTEMPT_STARTED,
                attempt_id=attempt_id,
                attempted_at=attempted_at,
                attempt_authority_valid=True,
                reason="attempt_started",
            )
        except IllegalEffectTransitionError:
            return self._refuse_effect_current(row, "effect_contended")
        except EffectJournalError as exc:
            return EffectResult.refused(
                f"effect_store_error:{type(exc).__name__}"
            )

        if advanced is None:
            current = self._effect_row(record.lease_id)
            if current is None:
                return EffectResult.refused("effect_unknown")
            return self._refuse_effect_current(current, "effect_contended")

        self._record_effect_event(
            "effect_attempt_started",
            advanced,
        )

        return EffectResult(
            allowed=True,
            reason="effect_attempt_started",
            state=advanced.state,
            effect=advanced,
        )

    def record_effect_receipt(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        observed_outcome=None,
        evidence_kind=None,
        external_request_id: Optional[str] = None,
        provider: Optional[str] = None,
        note: Optional[str] = None,
    ):
        """Record what the external handler claims happened to an attempt.

        A receipt is an **observation**, never a permission and never a
        proof: it states which three-way outcome the handler reported
        (``succeeded`` / ``failed`` / ``unknown``), who supplied it
        (``caller_assertion`` / ``handler_observation`` /
        ``provider_evidence``), and any external request/transaction id,
        provider identity and note as correlation evidence.

        The three-way outcome is load-bearing: a timeout after the request
        was transmitted is ``unknown`` -- the external system may have
        processed it -- and is recorded as ``UNKNOWN``, never as a clean
        success and never as a confirmed failure. ``UNKNOWN`` is not
        auto-retried; only an explicit reconciliation may resolve it.

        Authority semantics: the observation is always recorded truthfully
        (history is never rewritten because authority later changed), but
        the row's ``receipt_authority_valid`` flag records whether the
        execution's authority basis held at the moment the receipt was
        recorded. A receipt that arrives after revocation or suspension
        therefore says the effect *happened* without claiming it completed
        under currently valid authority -- the lease is burned to its
        terminal failure state (``executed=True``) and ``allowed`` is
        ``False``, so nothing clean can be completed from it.

        A replayed receipt (the row is already ``SUCCEEDED``/``FAILED``)
        is refused with ``effect_already_resolved``: it cannot produce a
        second completion.
        """

        if not isinstance(lease, ExecutionLease):
            return EffectResult.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return EffectResult.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return EffectResult.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return EffectResult.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return EffectResult.refused("invalid_effect_type")

        outcome = self._coerce_outcome(observed_outcome)

        if outcome is None:
            return EffectResult.refused("invalid_outcome")

        kind = self._coerce_receipt_kind(evidence_kind)

        if kind is None:
            return EffectResult.refused("invalid_evidence_kind")

        for label, value in (
            ("external_request_id", external_request_id),
            ("provider", provider),
            ("note", note),
        ):
            if value is not None and not isinstance(value, str):
                return EffectResult.refused(f"invalid_evidence:{label}")

        record = self._lease_record(lease)

        if record is None:
            return EffectResult.refused("lease_unknown")

        row = self._effect_row(record.lease_id)

        if row is None:
            return EffectResult.refused("effect_unknown")

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return EffectResult.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return EffectResult.refused("invalid_idempotency_key")

        mismatch = self._effect_binding_mismatch(
            row,
            effect_type.strip(),
            effect_digest,
            idem,
        )

        if mismatch is not None:
            return self._refuse_effect_current(row, mismatch)

        if row.state in (
            EffectState.SUCCEEDED,
            EffectState.FAILED,
        ):
            return self._refuse_effect_current(row, "effect_already_resolved")

        if (
            row.state is EffectState.INTENT_RECORDED
            and outcome is not EffectOutcome.FAILED
        ):
            # Nothing was transmitted, so only a *confirmed* failure (the
            # handler proves the request never went out) may be recorded.
            return self._refuse_effect_current(row, "effect_not_attempted")

        # v3.3: an observation belongs to a chain that must already hold
        # EXECUTED -- the stage that says the boundary was crossed. The chain
        # must be intact and open, and the OBSERVED commitment is written at
        # the execution's close, from this row. An observation that cannot be
        # placed on its execution's lineage is an observation about an
        # execution the firewall cannot account for.
        lineage_reason = self._lineage_gate_satisfied(
            record, stage=LineageStage.EXECUTED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "receipt")
            return self._refuse_effect_current(row, lineage_reason)

        target = {
            EffectOutcome.SUCCEEDED: EffectState.SUCCEEDED,
            EffectOutcome.FAILED: EffectState.FAILED,
            EffectOutcome.UNKNOWN: EffectState.UNKNOWN,
        }[outcome]

        authority_valid, failure_reason, _latest = (
            self._effect_authority_snapshot(
                lease,
                record,
                capability,
                action,
                request,
            )
        )

        try:
            observed_at = self.effects.now()
        except EffectJournalError:
            return EffectResult.refused("effect_clock_unavailable")

        try:
            advanced = self.effects.transition(
                row.effect_id,
                target,
                observed_outcome=outcome,
                observed_at=observed_at,
                evidence_kind=kind,
                external_request_id=external_request_id,
                provider=provider,
                note=note,
                receipt_authority_valid=authority_valid,
                reason=f"receipt:{outcome.value}",
            )
        except IllegalEffectTransitionError:
            return self._refuse_effect_current(row, "effect_already_resolved")
        except EffectJournalError as exc:
            return EffectResult.refused(
                f"effect_store_error:{type(exc).__name__}"
            )

        if advanced is None:
            current = self._effect_row(record.lease_id)
            if current is None:
                return EffectResult.refused("effect_unknown")
            if current.state in (
                EffectState.SUCCEEDED,
                EffectState.FAILED,
            ):
                return self._refuse_effect_current(
                    current,
                    "effect_already_resolved",
                )
            return self._refuse_effect_current(current, "effect_contended")

        self._record_effect_event(
            "effect_receipt_recorded",
            advanced,
            extra={
                "outcome": outcome.value,
                "authority_valid": authority_valid,
            },
        )

        if not authority_valid:
            return EffectResult(
                allowed=False,
                reason=failure_reason or f"authority_lost:{row.state.value}",
                state=advanced.state,
                effect=advanced,
            )

        return EffectResult(
            allowed=True,
            reason=f"receipt_recorded:{outcome.value}",
            state=advanced.state,
            effect=advanced,
        )

    def reconcile_effect(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        resolution=None,
        evidence_kind=None,
        external_request_id: Optional[str] = None,
        provider: Optional[str] = None,
        note: Optional[str] = None,
    ):
        """Reconcile an unresolved side effect after a crash or timeout.

        The recovery path. An effect stuck in ``ATTEMPT_STARTED`` (the
        process crashed after the external request, or the handler timed
        out) or ``UNKNOWN`` may be reconciled against the external
        system's status:

        * ``resolution=succeeded`` with provider evidence moves the row to
          ``SUCCEEDED``;
        * ``resolution=failed`` moves it to ``FAILED``;
        * ``resolution=unknown`` records that the status is *still*
          unknown (the row is re-stamped ``UNKNOWN`` with the attempt
          recorded in its history).

        The firewall never *auto*-retries an unknown side effect: the only
        way out of ``UNKNOWN`` is this explicit, evidence-carrying call,
        because an automatic retry could duplicate a real-world action.
        Exactly like a receipt, a reconciliation is an observation with an
        authority flag -- it never grants anything.
        """

        if not isinstance(lease, ExecutionLease):
            return EffectResult.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return EffectResult.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return EffectResult.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return EffectResult.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return EffectResult.refused("invalid_effect_type")

        outcome = self._coerce_outcome(resolution)

        if outcome is None:
            return EffectResult.refused("invalid_resolution")

        kind = self._coerce_receipt_kind(evidence_kind)

        if kind is None:
            return EffectResult.refused("invalid_evidence_kind")

        for label, value in (
            ("external_request_id", external_request_id),
            ("provider", provider),
            ("note", note),
        ):
            if value is not None and not isinstance(value, str):
                return EffectResult.refused(f"invalid_evidence:{label}")

        record = self._lease_record(lease)

        if record is None:
            return EffectResult.refused("lease_unknown")

        row = self._effect_row(record.lease_id)

        if row is None:
            return EffectResult.refused("effect_unknown")

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return EffectResult.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return EffectResult.refused("invalid_idempotency_key")

        mismatch = self._effect_binding_mismatch(
            row,
            effect_type.strip(),
            effect_digest,
            idem,
        )

        if mismatch is not None:
            return self._refuse_effect_current(row, mismatch)

        if row.state in (
            EffectState.SUCCEEDED,
            EffectState.FAILED,
        ):
            return self._refuse_effect_current(row, "effect_already_resolved")

        if row.state is EffectState.INTENT_RECORDED:
            # Nothing was ever transmitted: there is nothing to reconcile
            # against the world. Abort or lapse the execution instead.
            return self._refuse_effect_current(row, "effect_not_attempted")

        # v3.3: a reconciliation is the recovery path for an attempt that
        # was never observed, so what it requires of the chain is that the
        # execution was *entered* -- EXECUTED -- and that the chain is intact
        # and open. The OBSERVED commitment it justifies is written at the
        # close, from whatever row the journals hold by then, so a
        # reconciliation can legitimately follow a receipt and an earlier
        # reconciliation without a second claim about one stage.
        lineage_reason = self._lineage_gate_satisfied(
            record, stage=LineageStage.EXECUTED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "reconcile")
            return self._refuse_effect_current(row, lineage_reason)

        target = {
            EffectOutcome.SUCCEEDED: EffectState.SUCCEEDED,
            EffectOutcome.FAILED: EffectState.FAILED,
            EffectOutcome.UNKNOWN: EffectState.UNKNOWN,
        }[outcome]

        authority_valid, failure_reason, _latest = (
            self._effect_authority_snapshot(
                lease,
                record,
                capability,
                action,
                request,
            )
        )

        try:
            observed_at = self.effects.now()
        except EffectJournalError:
            return EffectResult.refused("effect_clock_unavailable")

        try:
            advanced = self.effects.transition(
                row.effect_id,
                target,
                observed_outcome=outcome,
                observed_at=observed_at,
                evidence_kind=kind,
                external_request_id=external_request_id,
                provider=provider,
                note=note,
                receipt_authority_valid=authority_valid,
                reason=f"reconcile:{outcome.value}",
            )
        except IllegalEffectTransitionError:
            return self._refuse_effect_current(row, "effect_already_resolved")
        except EffectJournalError as exc:
            return EffectResult.refused(
                f"effect_store_error:{type(exc).__name__}"
            )

        if advanced is None:
            current = self._effect_row(record.lease_id)
            if current is None:
                return EffectResult.refused("effect_unknown")
            if current.state in (
                EffectState.SUCCEEDED,
                EffectState.FAILED,
            ):
                return self._refuse_effect_current(
                    current,
                    "effect_already_resolved",
                )
            return self._refuse_effect_current(current, "effect_contended")

        self._record_effect_event(
            "effect_reconciled",
            advanced,
            extra={
                "resolution": outcome.value,
                "authority_valid": authority_valid,
                "reconcile_count": advanced.reconcile_count,
            },
        )

        if not authority_valid:
            return EffectResult(
                allowed=False,
                reason=failure_reason or f"authority_lost:{row.state.value}",
                state=advanced.state,
                effect=advanced,
            )

        return EffectResult(
            allowed=True,
            reason=f"reconcile_recorded:{outcome.value}",
            state=advanced.state,
            effect=advanced,
        )

    def verify_effect(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        verifier=None,
        method: Optional[str] = None,
        note: Optional[str] = None,
    ) -> VerificationResult:
        """Verify one recorded side-effect claim, on its own.

        The independent-check step of the v2.9 protocol. The row's
        recorded observation -- never the caller's retelling -- is bound
        to the effect, attempt and evidence snapshot, packaged, and given
        to the verifier. ``allowed`` is true only when a ``VERIFIED``
        claim is on record for the row's current evidence.

        ``verifier`` defaults to the built-in structural verifier, which
        confirms internal soundness for caller/handler observations and
        refuses provider-labelled evidence. A deployment that
        authenticates a provider must pass a callable returning a
        :class:`~firewall.effect_verification.VerifierVerdict` and name
        it with ``method``; the journal never guesses whose check a
        VERIFIED claim came from, and no other code may claim the
        structural method id. A VERIFIED verdict is only recorded while
        the execution's authority basis still holds; after revocation,
        expiry or a policy/lineage change the verdict is preserved
        truthfully as ``NOT_VERIFIED`` and the result refuses.
        """

        if not isinstance(lease, ExecutionLease):
            return VerificationResult.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return VerificationResult.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return VerificationResult.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return VerificationResult.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return VerificationResult.refused("invalid_effect_type")

        record = self._lease_record(lease)

        if record is None:
            return VerificationResult.refused("lease_unknown")

        row = self._effect_row(record.lease_id)

        if row is None:
            return VerificationResult.refused("effect_unknown")

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return VerificationResult.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return VerificationResult.refused("invalid_idempotency_key")

        mismatch = self._effect_binding_mismatch(
            row,
            effect_type.strip(),
            effect_digest,
            idem,
        )

        if mismatch is not None:
            return VerificationResult.refused(mismatch)

        # v3.3: verification is the fourth stage, so the chain must be intact,
        # open, and past the boundary crossing. The VERIFIED commitment itself
        # is written at the close, from the claim the journal trusts then --
        # which is what lets a provisional structural NOT_VERIFIED be replaced
        # by a named authenticator's VERIFIED verdict on the same evidence
        # without a second claim about one stage.
        lineage_reason = self._lineage_gate_satisfied(
            record, stage=LineageStage.EXECUTED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "verify")
            return VerificationResult.refused(lineage_reason)

        return self._verify_row_claim(
            lease,
            record,
            capability,
            action,
            request,
            row,
            verifier=verifier,
            method=method,
            note=note,
        )

    # ------------------------------------------------------------------
    # External state attestation (v3.1)
    # ------------------------------------------------------------------
    #
    # A fourth stage after the v2.9 verification stage, and the only one
    # whose evidence originates outside this process:
    #
    #   AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED
    #              =/= ATTESTED =/= COMPLETED
    #
    # The layer can only ever refuse. It writes to its own journal, never
    # to the capability registry, the revocation registry, the lineage, the
    # epoch, the state-commitment chain, the lease journal, the side-effect
    # journal or the verification journal, and no gate on the ALLOW path
    # reads it. EXTERNAL_STATE_ATTESTATION_SOUNDNESS checks the census of
    # who may drive both halves, both ways.

    @property
    def require_external_attestation(self) -> bool:
        """Whether a completion must rest on a current attestation.

        Set at construction and never afterwards: turning it off would
        widen what may complete, and a mutable widening switch on the
        completion path is the shape this package refuses everywhere else.
        """

        return self._require_external_attestation

    # ========================================================
    # External issuer trust
    # ========================================================

    def trust_external_issuer(
        self,
        issuer_id: str,
        key_id: str,
        public_key,
        *,
        note: Optional[str] = None,
    ) -> ExternalIssuerKey:
        """Register one external issuer's signing key.

        The operator's trust decision, and the only way to make an
        attestation verifiable. The key is whatever the external system
        publishes: an ``Ed25519PublicKey``, 32 raw bytes, or its base64. The
        firewall checks that it *is* such a key, and checks nothing about
        whose it is -- a deployment that registers a key it also controls
        has attested its own claim, and the honest name for that is in the
        module docstring rather than hidden here.

        Registration is monotone for a ``(issuer_id, key_id)`` pair: a
        revoked key cannot be re-registered, and a live one cannot be
        silently replaced. Rotating a compromised issuer means a new
        ``key_id``.
        """

        try:
            return self.external_issuers.register(
                issuer_id,
                key_id,
                public_key,
                note=note,
            )
        except ExternalIssuerError:
            raise
        finally:
            self._record_flight_event(
                EventType.SECURITY_STATE,
                {
                    "change": "external_issuer_trusted",
                    "issuer_id": issuer_id,
                    "key_id": key_id,
                },
            )

    def revoke_external_issuer_key(
        self,
        issuer_id: str,
        key_id: str,
        *,
        reason: str = "",
    ) -> ExternalIssuerKey:
        """Withdraw one external signing key. Its signatures stop verifying."""

        record = self.external_issuers.revoke_key(
            issuer_id,
            key_id,
            reason=reason,
        )

        self._record_flight_event(
            EventType.SECURITY_STATE,
            {
                "change": "external_issuer_key_revoked",
                "issuer_id": issuer_id,
                "key_id": key_id,
                "reason": str(reason),
            },
        )

        return record

    def revoke_external_issuer(
        self,
        issuer_id: str,
        *,
        reason: str = "",
    ) -> tuple[ExternalIssuerKey, ...]:
        """Withdraw every key of one external issuer.

        The containment action for a compromised external system: every
        envelope it ever signed stops verifying, including ones still
        inside their own validity window, and every future completion that
        requires attestation from it is refused until an operator
        re-registers it under a new key id.
        """

        records = self.external_issuers.revoke_issuer(
            issuer_id,
            reason=reason,
        )

        self._record_flight_event(
            EventType.SECURITY_STATE,
            {
                "change": "external_issuer_revoked",
                "issuer_id": issuer_id,
                "keys": [record.key_id for record in records],
                "reason": str(reason),
            },
        )

        return records

    def external_issuer_records(self) -> tuple[ExternalIssuerKey, ...]:
        """Every registered external issuer key, revoked ones included.

        Configuration, not state: reading it decides nothing. Revoked
        records are kept rather than deleted so that an operator can see
        that a key was once trusted and why it stopped being trusted.
        """

        try:
            return self.external_issuers.records()
        except Exception:  # noqa: BLE001 - unreadable config is a refusal
            return ()

    # ========================================================
    # Attestation (v3.1): helpers
    # ========================================================

    def _attestation_now(self) -> Optional[float]:
        """The journal's clock reading, or ``None`` when unreadable.

        ``None`` rather than an exception: an unreadable clock means no
        freshness question can be answered, and every freshness question it
        could not answer is a refusal.
        """

        try:
            return self.attestations.now()
        except AttestationJournalError:
            return None

    def _attestation_current_claims(self, row):
        """Every attestation claim about the row's *current* attempt.

        Selected on the attempt, not on an evidence snapshot: an
        attestation speaks about the external system's view of the attempt,
        which does not change when the firewall re-stamps its own record of
        what the handler claimed. A claim recorded against an earlier
        attempt is therefore never current -- an attestation cannot speak
        for an attempt it did not name -- and freshness is re-checked
        separately at the moment a completion relies on the claim.
        """

        try:
            claims = self.attestations.by_effect(row.effect_id)
        except AttestationJournalError:
            return ()

        if not claims:
            return ()

        return tuple(
            claim
            for claim in claims
            if claim.attempt_id == row.attempt_id
        )

    def _journal_attestation(
        self,
        row,
        *,
        outcome: AttestationOutcome,
        reason: str,
        envelope=None,
        asserted_outcome=None,
        state_digest: str = "",
        external_request_id: Optional[str] = None,
        provider: Optional[str] = None,
        correlated: bool = False,
        correlation_source: str = "none",
        signature_verified: bool = False,
        note: Optional[str] = None,
    ) -> Optional[AttestationRecord]:
        """Record one attestation claim, idempotently.

        The single entry point that drives the attestation journal, which
        is what the release's census constrains: a second path that records
        an attestation "on the side" fails the invariant even if it looks
        safe.

        An ``ATTESTED`` verdict additionally *claims the envelope's nonce*
        before it is recorded, and a nonce already claimed for a different
        envelope or a different effect downgrades the verdict to
        ``NOT_ATTESTED`` here rather than being accepted. The claim is
        idempotent for a byte-identical re-presentation, so a crash between
        the claim and the record is recoverable by presenting the same
        envelope again; the refusal is recorded truthfully instead of being
        dropped, and the ledger and the journal therefore cannot disagree
        about what was accepted.

        Returns ``None`` when the claim could not be written -- a claim must
        not be reported recorded when it was not. The caller turns that into
        ``attestation_store_error``, which is a refusal.
        """

        envelope_fields: dict

        if envelope is not None:
            envelope_fields = dict(
                envelope_id=envelope.envelope_id,
                issuer_id=envelope.issuer_id,
                key_id=envelope.key_id,
                algorithm=envelope.algorithm,
                nonce=envelope.nonce,
                issued_at=float(envelope.issued_at),
                not_before=float(envelope.not_before),
                expires_at=float(envelope.expires_at),
            )
        else:
            envelope_fields = dict(
                issued_at=0.0,
                not_before=0.0,
                expires_at=0.0,
            )

        if outcome is AttestationOutcome.ATTESTED:
            try:
                claimed, existing = self.attestations.claim_nonce(
                    issuer_id=envelope.issuer_id,
                    nonce=envelope.nonce,
                    envelope_id=envelope.envelope_id,
                    effect_id=row.effect_id,
                    attempt_id=row.attempt_id,
                )
            except (
                AttestationJournalError,
                AttributeError,
                TypeError,
                ValueError,
            ):
                return None

            if not claimed:
                outcome = AttestationOutcome.NOT_ATTESTED
                reason = "attestation_replayed"
                note = (
                    "the envelope's nonce was already accepted"
                    + (
                        f" for envelope {existing.envelope_id[:8]}... of "
                        f"effect {existing.effect_id[:8]}..."
                        if existing is not None
                        else ""
                    )
                    + "; a signed statement is evidence once"
                )

        try:
            return self.attestations.record(
                effect_id=row.effect_id,
                lease_id=row.lease_id,
                execution_id=row.execution_id,
                attempt_id=row.attempt_id,
                effect_digest=row.effect_digest,
                capability_fingerprint=row.capability_fingerprint,
                agent_id=row.agent_id,
                action=row.action,
                idempotency_key=row.idempotency_key,
                outcome=outcome,
                reason=reason,
                asserted_outcome=asserted_outcome,
                state_digest=state_digest,
                external_request_id=external_request_id,
                provider=provider,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=signature_verified,
                note=note,
                **envelope_fields,
            )
        except (AttestationJournalError, TypeError, ValueError):
            return None

    def _attest_row_claim(
        self,
        lease: ExecutionLease,
        record: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict],
        row,
        *,
        envelope=None,
        note: Optional[str] = None,
    ) -> AttestationResult:
        """Verify one presented envelope against the row's bound effect.

        The envelope -- never the caller's retelling -- is checked against
        the *journal row*: its scope fields must name exactly this effect,
        attempt, execution, capability, agent, action, idempotency key and
        effect digest, and its correlation handle must agree with what the
        effect row recorded. Every refusal writes a truthful record naming
        the reason, so an operator can see which attestation was refused and
        why rather than only that a completion did not happen.

        An ``ATTESTED`` verdict may only be *recorded* while the
        execution's authority basis still holds. A signature that arrives
        after revocation, expiry, suspension or a policy/epoch change is
        preserved truthfully as ``NOT_ATTESTED`` and the lease is burned
        exactly as a v2.8 receipt after authority loss burns it -- an
        external statement is evidence about what happened, never a
        resurrection of the authority that allowed it.
        """

        if getattr(row, "attempt_id", None) is None:
            return AttestationResult.refused("effect_not_attempted")

        parsed = None

        def refusal(
            reason: str,
            *,
            parsed=None,
            asserted=None,
            state_digest: str = "",
            external_request_id=None,
            provider=None,
            correlated: bool = False,
            correlation_source: str = "none",
            signature_verified: bool = False,
            verdict: AttestationOutcome = AttestationOutcome.NOT_ATTESTED,
            note_text: Optional[str] = None,
        ) -> AttestationResult:
            claim = self._journal_attestation(
                row,
                outcome=verdict,
                reason=reason,
                envelope=parsed,
                asserted_outcome=asserted,
                state_digest=state_digest,
                external_request_id=external_request_id,
                provider=provider,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=signature_verified,
                note=note_text,
            )

            if claim is None:
                # Distinguish the two reasons a refusal row could not be
                # written, because an operator fixes them differently: an
                # unreadable clock cannot stamp a row at all, while a
                # store that will not write is a journal problem.
                if self._attestation_now() is None:
                    return AttestationResult.refused(
                        "attestation_clock_unavailable"
                    )

                return AttestationResult.refused(
                    "attestation_store_error"
                )

            self._record_effect_event(
                "effect_attestation_refused",
                row,
                extra={"reason": reason},
            )

            return AttestationResult(
                allowed=False,
                reason=reason,
                outcome=verdict,
                record=claim,
            )

        if envelope is None:
            return refusal(
                "attestation_missing",
                note_text=(
                    note
                    or "no external attestation was supplied where one "
                    "was required; the firewall recorded an effect and no "
                    "external system attested its state"
                ),
            )

        if not isinstance(envelope, AttestationEnvelope):
            try:
                parsed = AttestationEnvelope.from_dict(envelope)
            except AttestationError as error:
                return refusal(
                    "attestation_malformed",
                    note_text=(
                        "the presented envelope could not be parsed as a "
                        f"signed statement: {error}"
                    ),
                )
        else:
            parsed = envelope

        asserted = parsed.asserted_outcome
        digest = (
            parsed.state_digest
            if isinstance(parsed.state_digest, str)
            else ""
        )

        common = dict(
            parsed=parsed,
            asserted=asserted,
            state_digest=digest,
            external_request_id=parsed.external_request_id or None,
            provider=parsed.provider,
        )

        if parsed.algorithm not in SUPPORTED_ALGORITHMS:
            return refusal(
                "attestation_unsupported_algorithm",
                **common,
                note_text=(
                    f"the envelope names algorithm {parsed.algorithm!r}, "
                    "which this firewall cannot verify; an unverifiable "
                    "signature is not a verified one"
                ),
            )

        if parsed.attestation_version != ATTESTATION_VERSION:
            return refusal(
                "attestation_unsupported_version",
                **common,
                note_text=(
                    f"the envelope declares format version "
                    f"{parsed.attestation_version}, and this firewall "
                    f"verifies version {ATTESTATION_VERSION}"
                ),
            )

        if parsed.statement_type != STATEMENT_TYPE:
            return refusal(
                "attestation_statement_unsupported",
                **common,
                note_text=(
                    f"the envelope says it is a "
                    f"{parsed.statement_type!r} statement; only "
                    f"{STATEMENT_TYPE!r} is evidence about an effect"
                ),
            )

        try:
            issuer_key = self.external_issuers.get(
                parsed.issuer_id,
                parsed.key_id,
            )
        except Exception as error:  # noqa: BLE001 - unreadable is a refusal
            return refusal(
                "attestation_trust_unavailable",
                **common,
                note_text=(
                    "the external issuer trust store could not be read "
                    f"({type(error).__name__}), so no key could be shown "
                    "to be trusted"
                ),
            )

        if issuer_key is None:
            return refusal(
                "attestation_issuer_unknown",
                **common,
                note_text=(
                    f"no key {parsed.key_id!r} is registered for external "
                    f"issuer {parsed.issuer_id!r}; an unregistered signer "
                    "is not an issuer"
                ),
            )

        if issuer_key.revoked_at is not None:
            return refusal(
                "attestation_issuer_revoked",
                **common,
                note_text=(
                    f"key {parsed.key_id!r} of external issuer "
                    f"{parsed.issuer_id!r} was revoked and its statements "
                    "are no longer accepted, whatever window they claim"
                ),
            )

        public_key = issuer_key.public_key()

        if public_key is None:
            return refusal(
                "attestation_key_unusable",
                **common,
                note_text=(
                    f"the registered key {parsed.key_id!r} of external "
                    f"issuer {parsed.issuer_id!r} could not be loaded, so "
                    "no signature can be checked against it"
                ),
            )

        try:
            verified = bool(
                verify_envelope_signature(parsed, public_key)
            )
        except Exception:  # noqa: BLE001 - a crashing check is not a pass
            verified = False

        if not verified:
            return refusal(
                "attestation_signature_invalid",
                **common,
                note_text=(
                    "the envelope's signature does not verify under the "
                    "key registered for the issuer it names"
                ),
            )

        mismatch = scope_mismatch(row, parsed)

        if mismatch is not None:
            return refusal(
                "attestation_scope_mismatch",
                **common,
                signature_verified=True,
                note_text=(
                    f"the envelope is signed, but it names a different "
                    f"{mismatch} than the recorded effect; an attestation "
                    "speaks about one effect and no other"
                ),
            )

        if row.external_request_id:
            if parsed.external_request_id != row.external_request_id:
                return refusal(
                    "attestation_correlation_mismatch",
                    **common,
                    signature_verified=True,
                    note_text=(
                        "the effect row records external request "
                        f"{row.external_request_id!r} and the envelope "
                        f"names {parsed.external_request_id!r}; a "
                        "statement about a different external request "
                        "does not attest this effect"
                    ),
                )
            correlated, correlation_source = True, "receipt"
        elif parsed.external_request_id:
            # The receipt recorded no correlation handle -- the handler
            # did not know one -- so the signed envelope is the only
            # correlation there is, and the record says where it came
            # from rather than presenting it as the handler's.
            correlated, correlation_source = True, "attestation"
        else:
            return refusal(
                "attestation_correlation_absent",
                **common,
                signature_verified=True,
                note_text=(
                    "neither the effect row nor the envelope names an "
                    "external request, so nothing ties this signed "
                    "statement to this effect beyond the scope fields"
                ),
            )

        if row.provider is not None and parsed.provider != row.provider:
            return refusal(
                "attestation_provider_mismatch",
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                note_text=(
                    f"the effect row records provider {row.provider!r} "
                    f"and the envelope names {parsed.provider!r}; the "
                    "state was not attested by the claimed external "
                    "system"
                ),
            )

        if not digest.strip():
            return refusal(
                "attestation_state_digest_missing",
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                note_text=(
                    "the envelope asserts an outcome without naming the "
                    "external state it observed, so there is nothing to "
                    "correlate with the world"
                ),
            )

        # Freshness comes from the journal, which owns the definition and
        # takes the reading inside the temporal guard when one is bound
        # (v3.2). An anomalous clock is refused by name here rather than
        # being turned into a comparison against a reading that just moved
        # backwards, which is the one answer that could resurrect an
        # expired envelope.
        stale = self.attestations.check_window(envelope=parsed)

        if stale is not None:
            return refusal(
                stale,
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                note_text=(
                    "the envelope's signature verifies, but its validity "
                    f"window is not current: {stale}. A statement about "
                    "past external state is evidence about the past, not a "
                    "warrant now"
                ),
            )

        if asserted is None:
            return refusal(
                "attestation_outcome_unknown",
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                note_text=(
                    f"the envelope asserts outcome "
                    f"{parsed.observed_outcome!r}, which is not one of the "
                    "three outcomes this firewall records"
                ),
            )

        if asserted not in CONCLUSIVE_OUTCOMES:
            return refusal(
                "attestation_inconclusive",
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                note_text=(
                    "the external system attested that it does not know "
                    "what happened; that is an honest answer and not "
                    "evidence of completion"
                ),
            )

        if contradiction_between(asserted, row.observed_outcome):
            return refusal(
                "attestation_contradicted",
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                verdict=AttestationOutcome.CONTRADICTED,
                note_text=(
                    f"the external system attests {asserted.value!r} while "
                    f"the effect row records "
                    f"{row.observed_outcome.value!r}; the two conclusive "
                    "statements disagree and neither is resolved away"
                ),
            )

        for earlier in self._attestation_current_claims(row):
            previous = earlier.asserted_outcome

            if (
                previous in CONCLUSIVE_OUTCOMES
                and previous is not asserted
            ):
                return refusal(
                    "attestation_contradicted",
                    **common,
                    correlated=correlated,
                    correlation_source=correlation_source,
                    signature_verified=True,
                    verdict=AttestationOutcome.CONTRADICTED,
                    note_text=(
                        f"the envelope attests {asserted.value!r} while "
                        f"attestation "
                        f"{earlier.attestation_id[:8]}... from issuer "
                        f"{earlier.issuer_id!r} attests "
                        f"{previous.value!r} for the same effect; both "
                        "statements are preserved and the contradiction "
                        "stands"
                    ),
                )

        authority_valid, failure_reason, _latest = (
            self._effect_authority_snapshot(
                lease,
                record,
                capability,
                action,
                request,
            )
        )

        if not authority_valid:
            reason = failure_reason or "effect_authority_lost"

            return refusal(
                reason,
                **common,
                correlated=correlated,
                correlation_source=correlation_source,
                signature_verified=True,
                note_text=(
                    "the envelope verifies, but the execution's authority "
                    "basis no longer holds; an external attestation is "
                    "evidence about what happened, never a restoration of "
                    "the authority that allowed it"
                ),
            )

        claim = self._journal_attestation(
            row,
            outcome=AttestationOutcome.ATTESTED,
            reason="attestation_verified",
            envelope=parsed,
            asserted_outcome=asserted,
            state_digest=digest,
            external_request_id=parsed.external_request_id or None,
            provider=parsed.provider,
            correlated=True,
            correlation_source=correlation_source,
            signature_verified=True,
        )

        if claim is None:
            return AttestationResult.refused("attestation_store_error")

        if claim.outcome is not AttestationOutcome.ATTESTED:
            # ``_journal_attestation`` refused the nonce: the same signed
            # statement has already been accepted, for another effect or
            # under another envelope. The replay refusal is on the record.
            return AttestationResult(
                allowed=False,
                reason=claim.reason,
                outcome=claim.outcome,
                record=claim,
            )

        self._record_effect_event(
            "effect_attested",
            row,
            extra={
                "issuer_id": parsed.issuer_id,
                "key_id": parsed.key_id,
                "attestation_id": claim.attestation_id[:8],
            },
        )

        return AttestationResult(
            allowed=True,
            reason="attestation_verified",
            outcome=AttestationOutcome.ATTESTED,
            record=claim,
        )

    # ========================================================
    # Attestation (v3.1): the protocol step
    # ========================================================

    def record_attestation(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        attestation=None,
        note: Optional[str] = None,
    ) -> AttestationResult:
        """Record an external system's signed statement about one effect.

        The step that answers the question v2.9 could not: not "does my
        record hold up" but "did the named external system authenticate
        this state, about this effect, now". The envelope is treated as
        untrusted input -- its signature is verified against a key the
        operator registered for the issuer it names, its scope fields are
        compared against the journal row, its correlation handle against
        what the receipt recorded, its window against the firewall's clock,
        and its nonce against the replay ledger. ``allowed`` is true only
        when an ``ATTESTED`` claim is on record as a result.

        Nothing here grants authority. The journal is not read by
        ``authorize()`` or by any gate on the ALLOW path, so no attestation
        can make an authorization allow, bypass a policy, or restore a
        revoked capability; and a verification that arrives after authority
        was lost is recorded as a refusal rather than accepted.

        Anything unusable is a refusal with a reason: a missing envelope
        (``attestation_missing``), a malformed one, an unsupported algorithm
        or version, an unregistered or revoked issuer key, a signature that
        does not verify, a scope or correlation mismatch, an absent state
        digest, a window that is not current, an outcome that contradicts
        the recorded observation, and a replayed nonce.
        """

        if not isinstance(lease, ExecutionLease):
            return AttestationResult.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return AttestationResult.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return AttestationResult.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return AttestationResult.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return AttestationResult.refused("invalid_effect_type")

        if note is not None and not isinstance(note, str):
            return AttestationResult.refused("invalid_note")

        record = self._lease_record(lease)

        if record is None:
            return AttestationResult.refused("lease_unknown")

        row = self._effect_row(record.lease_id)

        if row is None:
            return AttestationResult.refused("effect_unknown")

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return AttestationResult.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return AttestationResult.refused("invalid_idempotency_key")

        mismatch = self._effect_binding_mismatch(
            row,
            effect_type.strip(),
            effect_digest,
            idem,
        )

        if mismatch is not None:
            return AttestationResult.refused(mismatch)

        # v3.3: attestation is the fifth stage, so the chain must be intact,
        # open, and past the boundary crossing. The ATTESTED commitment is
        # written at the close from the claim the journal trusts then, so an
        # attestation recorded before its claim was verified is deferred
        # rather than re-ordered onto the chain.
        lineage_reason = self._lineage_gate_satisfied(
            record, stage=LineageStage.EXECUTED
        )

        if lineage_reason is not None:
            self._record_lineage_refusal(record, lineage_reason, "attest")
            return AttestationResult.refused(lineage_reason)

        return self._attest_row_claim(
            lease,
            record,
            capability,
            action,
            request,
            row,
            envelope=attestation,
            note=note,
        )

    def commit_effect(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        verifier=None,
        method: Optional[str] = None,
        verifier_note: Optional[str] = None,
        attestation=None,
        attestation_required: Optional[bool] = None,
        attestation_note: Optional[str] = None,
    ) -> ExecutionLeaseOutcome:
        """Close the execution as ``COMPLETED`` over a succeeded effect.

        The COMMIT step of the protocol. It requires the effect row bound
        to this lease to be ``SUCCEEDED`` with an observed success, a
        valid receipt authority flag, and -- since v2.9 -- a ``VERIFIED``
        verification claim about the row's current evidence, i.e. the
        firewall can establish what execution authority existed, what
        attempt occurred, what completion evidence was observed, and that
        the recorded claim was independently checked and held up. It then
        runs the ordinary v2.7 completion path (continuity re-validation
        plus the atomic lease transition).

        Verification runs only when the row does not already carry a
        current ``VERIFIED`` claim. ``verifier`` defaults to the built-in
        structural verifier, which confirms internal soundness for caller
        and handler observations and refuses provider-labelled evidence
        (a label is not proof). A deployment that authenticates a
        provider must pass a named ``verifier`` returning a
        :class:`~firewall.effect_verification.VerifierVerdict` plus its
        ``method`` -- the journal must never guess whose check a VERIFIED
        claim came from. A clean ``COMPLETED`` is only ever written for a
        side effect whose completion the protocol actually established.
        """

        if not isinstance(lease, ExecutionLease):
            return ExecutionLeaseOutcome.refused("invalid_lease")

        if not isinstance(capability, Capability):
            return ExecutionLeaseOutcome.refused("invalid_capability")

        if not isinstance(action, str) or not action.strip():
            return ExecutionLeaseOutcome.refused("invalid_action")

        if request is not None and not isinstance(request, dict):
            return ExecutionLeaseOutcome.refused("invalid_request")

        if (
            not isinstance(effect_type, str)
            or not effect_type.strip()
        ):
            return ExecutionLeaseOutcome.refused("invalid_effect_type")

        record = self._lease_record(lease)

        if record is None:
            return ExecutionLeaseOutcome.refused("lease_unknown")

        row = self._effect_row(record.lease_id)

        if row is None:
            return ExecutionLeaseOutcome.refused("effect_unknown")

        try:
            effect_digest = canonical_effect_digest(effect)
        except Exception as error:  # noqa: BLE001 - unnameable is a refusal
            return ExecutionLeaseOutcome.refused(
                f"invalid_effect:{type(error).__name__}"
            )

        idem = self._effect_default_key(idempotency_key, effect_digest)

        if not isinstance(idem, str) or not idem:
            return ExecutionLeaseOutcome.refused("invalid_idempotency_key")

        mismatch = self._effect_binding_mismatch(
            row,
            effect_type.strip(),
            effect_digest,
            idem,
        )

        if mismatch is not None:
            return self._refuse_current(
                record,
                mismatch,
            )

        if (
            row.state is not EffectState.SUCCEEDED
            or row.observed_outcome is not EffectOutcome.SUCCEEDED
            or row.receipt_authority_valid is not True
        ):
            return self._refuse_current(
                record,
                f"effect_unresolved:{row.state.value}",
            )

        # v2.9: the verified chain. An already-current VERIFIED claim
        # (with no CONTRADICTED claim against the same evidence) lets the
        # commit proceed without re-running the verifier; otherwise the
        # verifier runs now, and its outcome decides.
        current = self._effect_current_claims(row)

        if any(
            claim.outcome is VerificationOutcome.CONTRADICTED
            for claim in current
        ):
            return self._refuse_current(
                record,
                "effect_unverified:evidence_contradicted",
            )

        if not current or current[-1].outcome is not (
            VerificationOutcome.VERIFIED
        ):
            verification = self._verify_row_claim(
                lease,
                record,
                capability,
                action,
                request,
                row,
                verifier=verifier,
                method=method,
                note=verifier_note,
            )

            if not verification.allowed:
                self._record_effect_event(
                    "effect_verification_refused",
                    row,
                    extra={"reason": verification.reason},
                )
                return self._refuse_current(
                    record,
                    f"effect_unverified:{verification.reason}",
                )

        # v3.1: the externally attested chain. VERIFIED says the recorded
        # claim survived the deployment's check; ATTESTED says a named
        # external system signed a statement about this effect's state. A
        # presented envelope is verified whether or not attestation is
        # required -- supplying one and having it refused is never silently
        # ignored -- and a deployment that requires attestation refuses
        # without a current ATTESTED claim or with a contradiction standing.
        if attestation is not None:
            attested = self._attest_row_claim(
                lease,
                record,
                capability,
                action,
                request,
                row,
                envelope=attestation,
                note=attestation_note,
            )

            if not attested.allowed:
                self._record_effect_event(
                    "effect_attestation_refused",
                    row,
                    extra={"reason": attested.reason},
                )
                return self._refuse_current(
                    record,
                    f"effect_unattested:{attested.reason}",
                )

        if (
            attestation_required is None
            and self._require_external_attestation
        ):
            attestation_required = True

        if attestation_required:
            current = self._attestation_current_claims(row)
            refusal_reason = None

            if any(
                claim.outcome is AttestationOutcome.CONTRADICTED
                for claim in current
            ):
                refusal_reason = "attestation_contradicted"
            elif not current:
                refusal_reason = "attestation_required"
            elif current[-1].outcome is not AttestationOutcome.ATTESTED:
                refusal_reason = (
                    current[-1].reason or "attestation_not_attested"
                )
            else:
                # Freshness is re-checked *here*, not trusted from the
                # moment the claim was recorded: a claim that was current
                # when it was accepted and has since expired is stale, not
                # satisfied. v3.2 supplies the monotonic half of the age as
                # well -- elapsed time since the claim was recorded, in the
                # base a wall clock cannot move -- so a clock set backwards
                # between the claim and the completion cannot make an old
                # statement look young enough to complete.
                try:
                    context = self.attestations.temporal_context()
                except TemporalError:
                    context = None

                if context is None:
                    refusal_reason = "attestation_clock_unavailable"
                elif not context.unguarded and not context.provable:
                    refusal_reason = (
                        f"{TEMPORAL_ANOMALY_PREFIX}:{context.anomaly}"
                    )
                else:
                    stale = current[-1].fresh_at(
                        context.wall,
                        max_age=self.attestations.max_age,
                        skew=self.attestations.skew,
                        monotonic=context.monotonic,
                        generation=context.generation,
                    )

                    if stale is not None:
                        refusal_reason = f"{stale}_at_completion"

            if refusal_reason is not None:
                # The refusal is journaled, not merely returned: a
                # completion that required external evidence and did not
                # get it leaves a row saying so, with the reason, instead
                # of an absence an operator would have to infer.
                self._journal_attestation(
                    row,
                    outcome=AttestationOutcome.NOT_ATTESTED,
                    reason=refusal_reason,
                    note=attestation_note,
                )
                self._record_effect_event(
                    "effect_attestation_refused",
                    row,
                    extra={"reason": refusal_reason},
                )
                return self._refuse_current(
                    record,
                    f"effect_unattested:{refusal_reason}",
                )

        details = {
            "effect_id": row.effect_id,
            "effect_digest": row.effect_digest,
            "attempt_id": row.attempt_id,
            "external_request_id": row.external_request_id,
            "evidence_kind": (
                row.evidence_kind.value
                if row.evidence_kind is not None
                else None
            ),
            "idempotency_key": row.idempotency_key,
            "attested": any(
                claim.outcome is AttestationOutcome.ATTESTED
                for claim in self._attestation_current_claims(row)
            ),
        }

        return self.complete_execution(
            lease,
            capability,
            action,
            request,
            details=details,
        )

    def run_effect(
        self,
        lease: ExecutionLease,
        capability: Capability,
        action: str,
        request: Optional[dict] = None,
        *,
        effect: Any = None,
        effect_type: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        execution_id: Optional[str] = None,
        handler=None,
        receipt_kind=None,
        abort_reason: str = "handler_failed",
        verifier=None,
        method: Optional[str] = None,
        verifier_note: Optional[str] = None,
        attestor=None,
        attestation_required: Optional[bool] = None,
    ) -> ExecutionLeaseOutcome:
        """One-call form of the full side-effect protocol.

        Sequences reserve -> start -> prepare -> attempt -> handler ->
        receipt -> verify -> commit, each step still running the deny-only
        continuity validation and the atomic compare-and-set. The
        ``handler`` is the external action and runs strictly between the
        recorded attempt and the receipt; the verification runs between
        the receipt and the commit.

        A normal handler return is recorded as an observed ``succeeded``
        receipt (evidence kind ``handler_observation`` unless
        ``receipt_kind`` says otherwise). The handler may return a dict
        with optional ``external_request_id`` / ``provider`` / ``note``
        keys that are preserved as correlation evidence. If the handler
        raises, the outcome is recorded ``unknown`` (the request may have
        gone out and the firewall will not guess), the lease is aborted
        with ``executed=True``, and the exception is re-raised -- a
        handler failure is the caller's failure, not a firewall verdict.

        Since v2.9 a clean ``COMPLETED`` requires a verified claim:
        ``verifier`` / ``method`` / ``verifier_note`` are passed through
        to :meth:`commit_effect` and default to the structural verifier,
        which confirms handler/caller observations and refuses
        provider-labelled evidence. Pass a named authenticating verifier
        when the receipt kind is ``provider_evidence``.
        """

        if handler is None or not callable(handler):
            raise TypeError("handler must be callable")

        if receipt_kind is None:
            receipt_kind = ReceiptKind.HANDLER_OBSERVATION

        kind = self._coerce_receipt_kind(receipt_kind)

        if kind is None:
            return ExecutionLeaseOutcome.refused("invalid_evidence_kind")

        reserved = self.reserve_execution(
            lease,
            capability,
            action,
            request,
            execution_id=execution_id,
        )

        if not reserved.allowed:
            return reserved

        started = self.start_execution(
            reserved.lease,
            capability,
            action,
            request,
        )

        if not started.allowed:
            return started

        prepared = self.prepare_effect(
            started.lease,
            capability,
            action,
            request,
            effect=effect,
            effect_type=effect_type,
            idempotency_key=idempotency_key,
        )

        if not prepared.allowed:
            current = self._lease_record(started.lease)
            if current is None:
                return ExecutionLeaseOutcome.refused(prepared.reason)
            return self._refuse_current(current, prepared.reason)

        attempted = self.attempt_effect(
            started.lease,
            capability,
            action,
            request,
            effect=effect,
            effect_type=effect_type,
            idempotency_key=idempotency_key,
        )

        if not attempted.allowed:
            current = self._lease_record(started.lease)
            if current is None:
                return ExecutionLeaseOutcome.refused(attempted.reason)
            return self._refuse_current(current, attempted.reason)

        observation = {}

        try:
            result = handler()
        except BaseException as exc:
            # The transmission may or may not have happened. Record the
            # three-way UNKNOWN (never a guess of success or failure),
            # abort the execution truthfully, and hand the failure back.
            try:
                self.record_effect_receipt(
                    started.lease,
                    capability,
                    action,
                    request,
                    effect=effect,
                    effect_type=effect_type,
                    idempotency_key=idempotency_key,
                    observed_outcome=EffectOutcome.UNKNOWN,
                    evidence_kind=kind,
                    note=(
                        "handler raised while recording the receipt: "
                        f"{type(exc).__name__}"
                    ),
                )
            except BaseException:  # noqa: BLE001 - receipt is best effort
                pass
            self.abort_execution(
                started.lease,
                reason=abort_reason,
            )
            raise

        if isinstance(result, dict):
            observation = dict(result)

        receipt = self.record_effect_receipt(
            started.lease,
            capability,
            action,
            request,
            effect=effect,
            effect_type=effect_type,
            idempotency_key=idempotency_key,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=kind,
            external_request_id=observation.get("external_request_id"),
            provider=observation.get("provider"),
            note=observation.get("note"),
        )

        if not receipt.allowed:
            current = self._lease_record(started.lease)
            if current is None:
                return ExecutionLeaseOutcome.refused(receipt.reason)
            return self._refuse_current(current, receipt.reason)

        required = attestation_required
        attestation = None

        if attestor is not None:
            if not callable(attestor):
                return ExecutionLeaseOutcome.refused("invalid_attestor")

            # An attestor is asked *after* the receipt, because the
            # external system can only be asked about an effect that has
            # already been attempted. Supplying one is a statement that
            # this completion requires external evidence, so the
            # requirement is on regardless of the flag.
            required = True

            try:
                attestation = attestor(dict(observation))
            except BaseException as exc:  # noqa: BLE001
                # The handler already ran: the effect is recorded and it is
                # the *completion* that must fail closed. A crash while
                # obtaining evidence is evidence that could not be
                # obtained, so it is recorded as such and refused -- never
                # re-raised into a caller that might read the absence of a
                # verdict as permission.
                attestation = None
                missing_note = (
                    "no attestation could be obtained: the attestor "
                    f"raised {type(exc).__name__}"
                )
            else:
                missing_note = (
                    "the attestor returned no attestation for the "
                    "recorded effect"
                )

            if attestation is None:
                missing_row = self._effect_row(started.lease.lease_id)

                if missing_row is not None:
                    self._attest_row_claim(
                        started.lease,
                        self._lease_record(started.lease) or started.lease,
                        capability,
                        action,
                        request,
                        missing_row,
                        envelope=None,
                        note=missing_note,
                    )

        return self.commit_effect(
            started.lease,
            capability,
            action,
            request,
            effect=effect,
            effect_type=effect_type,
            idempotency_key=idempotency_key,
            verifier=verifier,
            method=method,
            verifier_note=verifier_note,
            attestation=attestation,
            attestation_required=required,
        )

    def expire_lapsed_effects(self) -> int:
        """Close side-effect intents whose deadline passed before any attempt.

        Returns how many were closed. Only ``INTENT_RECORDED`` rows lapse
        (to ``FAILED``, because the row itself proves nothing was ever
        transmitted); attempted rows are left alone -- the action may
        genuinely be running, and deciding it did not is the guess the
        journal refuses to make.
        """

        try:
            return self.effects.expire_lapsed()
        except EffectJournalError:
            return 0

    def side_effect_records(self):
        """Every side-effect journal row, in insertion order.

        The journal is state, not evidence; these rows are for an operator
        reconciling what an execution intended and what was observed, not
        for deciding anything. Reading them never changes a phase.
        """

        try:
            return self.effects.records()
        except EffectJournalError:
            return ()

    def verification_records(self):
        """Every verification claim, in insertion order.

        The verification journal is state, not evidence and not
        authority; these rows say which recorded side-effect claims were
        independently checked and what each check concluded. Reading
        them never changes anything.
        """

        try:
            return self.verifications.records()
        except VerificationJournalError:
            return ()

    def attestation_records(self):
        """Every external attestation claim, in insertion order.

        The attestation journal is state, not evidence and not authority;
        these rows say which signed statements from which external issuers
        were accepted, refused or found contradictory. Reading them never
        changes anything and never makes a completion possible -- the gate
        re-reads them and re-checks freshness when the completion happens.
        """

        try:
            return self.attestations.records()
        except AttestationJournalError:
            return ()

    def nonce_claims(self):
        """Every accepted ``(issuer, nonce)`` pair, in key order.

        The replay ledger. Exposed because "this signed statement was
        accepted once, for this effect" is a claim an operator should be
        able to audit directly, and because the release's invariant checks
        it against the accepted claims.
        """

        try:
            return self.attestations.nonce_claims()
        except AttestationJournalError:
            return ()

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

    @property
    def effect_store(self):
        """The internally created SQLite side-effect backend, or ``None``.

        Mirrors ``execution_store``: only a backend this SDK created (via
        ``effect_store_path`` or a persistent ``execution_store_path``) is
        returned and later closed. A caller that passed ``effect_journal``
        owns its own backend.
        """
        return self._effect_store

    @property
    def execution_store(self):
        """The internally created SQLite backend, or ``None``.

        Mirrors ``replay_store``: only a backend this SDK created (via
        ``execution_store_path``) is returned and later closed. A caller
        that passed ``execution_lease_store`` owns its own backend.
        """
        return self._execution_store

    @property
    def verification_store(self):
        """The internally created SQLite verification backend, or ``None``.

        Only a backend this SDK created (via ``verification_store_path``
        or a persistent effect/execution store file) is returned and
        later closed. A caller that passed ``verification_journal`` owns
        its own backend.
        """
        return self._verification_store

    @property
    def attestation_store(self):
        """The internally created SQLite attestation backend, or ``None``.

        Only a backend this SDK created (via ``attestation_store_path`` or
        a persistent verification/effect/execution store file) is returned
        and later closed. A caller that passed ``attestation_journal`` owns
        its own backend.
        """
        return self._attestation_store

    @property
    def external_issuer_store(self):
        """The external issuer trust store this SDK verifies against.

        Configuration, not authority: it decides which signatures are
        accepted, and nothing here can make an ``authorize`` allow.
        """
        return self.external_issuers

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
        execution_store_error = None
        effect_store_error = None
        verification_store_error = None
        attestation_store_error = None
        temporal_store_error = None
        lineage_store_error = None
        state_commit_store_error = None

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

        if self._execution_store is not None:
            try:
                self._execution_store.close()
            except Exception as exc:
                execution_store_error = exc
            finally:
                self._execution_store = None

        if self._effect_store is not None:
            try:
                self._effect_store.close()
            except Exception as exc:
                effect_store_error = exc
            finally:
                self._effect_store = None

        if self._verification_store is not None:
            try:
                self._verification_store.close()
            except Exception as exc:
                verification_store_error = exc
            finally:
                self._verification_store = None

        if self._attestation_store is not None:
            try:
                self._attestation_store.close()
            except Exception as exc:
                attestation_store_error = exc
            finally:
                self._attestation_store = None

        if self._temporal_store is not None:
            try:
                self._temporal_store.close()
            except Exception as exc:
                temporal_store_error = exc
            finally:
                self._temporal_store = None

        if self._lineage_store is not None:
            try:
                self._lineage_store.close()
            except Exception as exc:
                lineage_store_error = exc
            finally:
                self._lineage_store = None

        if self._state_commit_store is not None:
            try:
                self._state_commit_store.close()
            except Exception as exc:
                state_commit_store_error = exc
            finally:
                self._state_commit_store = None

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

        if execution_store_error is not None:
            raise execution_store_error

        if effect_store_error is not None:
            raise effect_store_error

        if verification_store_error is not None:
            raise verification_store_error

        if attestation_store_error is not None:
            raise attestation_store_error

        if temporal_store_error is not None:
            raise temporal_store_error

        if lineage_store_error is not None:
            raise lineage_store_error

        if state_commit_store_error is not None:
            raise state_commit_store_error

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
