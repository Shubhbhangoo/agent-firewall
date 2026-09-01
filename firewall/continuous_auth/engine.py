"""v2.2 Continuous Authorization Engine.

Deterministic re-evaluation of authorization decisions when security-relevant
state changes.

This module is **not** an authorization authority. Every allow/deny answer it
reports comes from ``FirewallSDK.authorize()``; the engine's only jobs are

1. to snapshot the security state a decision was made under, and
2. to notice when that state has materially changed and re-ask the canonical
   authorization path.

A revalidation can therefore only ever agree with ``authorize()``. It cannot
grant, extend, or restore authority on its own.

Fail-closed posture
-------------------
Every state probe here defaults to the *untrusted* value, not the convenient
one. If the identity registry is absent, identity status is ``"unknown"`` and
not ``"active"``; if a probe raises, the field records the failure rather than
a healthy placeholder. Unknown is not trusted, and a monitoring subsystem that
cannot read state must not report that state as safe.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from firewall.sdk import FirewallSDK

from firewall.authorization import AuthorizationResult
from firewall.capability import Capability, capability_fingerprint
from firewall.risk_context import RiskContext

# Sentinel recorded when a state probe could not produce an answer. It is
# deliberately distinct from any real value so that "we could not tell" is
# never confused with "we checked and it was fine".
UNKNOWN = "unknown"

# Recorded when a *configured* dependency raised while being probed. Distinct
# from UNKNOWN on purpose: UNKNOWN means "no such subsystem is wired, so it was
# never part of this decision", whereas PROBE_FAILED means "the deployment
# depends on this and we are blind to it". Only the latter withholds an allow.
PROBE_FAILED = "probe_failed"

# Fields excluded from the change-detection hash.
#
# `timestamp` must be excluded: it advances on every capture, so including it
# would make state_changed unconditionally True and the "no material change"
# path unreachable. The remaining three are identity of the decision itself
# (they are already part of the cache key), not state that can drift under it.
_HASH_EXCLUDED_FIELDS = frozenset(
    {
        "timestamp",
        "capability_fingerprint",
        "action",
        "request_hash",
    }
)

# Default bound on the decision cache. Unbounded growth in a long-lived
# control-plane process is a denial-of-service surface, and the cache holds
# only an optimisation -- evicting an entry costs a fresh authorize(), never
# an unchecked allow.
DEFAULT_MAX_CACHED_DECISIONS = 4096


class RevalidationTrigger(str, Enum):
    """What triggered a revalidation."""

    TIME = "time"                          # Periodic revalidation
    IDENTITY_CHANGED = "identity_changed"  # Identity revoked/rotated/retired
    CAPABILITY_REVOKED = "capability_revoked"
    DELEGATION_REVOKED = "delegation_revoked"
    DELEGATION_CHAIN_BROKEN = "delegation_chain_broken"
    TASK_REVOKED = "task_revoked"
    TASK_EXPIRED = "task_expired"
    POSTURE_CHANGED = "posture_changed"
    RISK_THRESHOLD_EXCEEDED = "risk_threshold_exceeded"
    TRUST_COLLAPSE = "trust_collapse"
    POLICY_CHANGED = "policy_changed"
    PROVENANCE_REVOKED = "provenance_revoked"
    INCIDENT_OPENED = "incident_opened"
    ENVIRONMENT_CHANGED = "environment_changed"
    EXPLICIT_REQUEST = "explicit_request"


# Triggers that must never be rate-limited away. An explicit request is a
# caller asking a direct question, and a periodic sweep is the only thing that
# notices time-based expiry; silently dropping either turns the monitor into a
# no-op.
UNTHROTTLED_TRIGGERS = frozenset(
    {
        RevalidationTrigger.EXPLICIT_REQUEST,
        RevalidationTrigger.TIME,
    }
)


@dataclass(frozen=True)
class SecurityContextSnapshot:
    """Snapshot of security-relevant state at a point in time.

    ``environment`` is normalised to a canonical JSON string rather than kept
    as a dict, so the snapshot is genuinely immutable and hashable. A frozen
    dataclass holding a live dict is not immutable -- the caller's provider
    could mutate it after capture and silently rewrite history.
    """

    timestamp: float
    capability_fingerprint: str
    agent_id: str
    action: str
    request_hash: str
    identity_status: str
    identity_version: int
    capability_revoked: bool
    capability_expired: bool
    delegation_chain_valid: bool
    delegation_depth: int
    max_delegation_depth: Optional[int]
    posture: str
    trust_findings: int
    risk_level: str
    policy_version: str
    environment: str
    provenance_state: str
    incident_active: bool

    # Names of security dependencies that were configured but could not be
    # read when this snapshot was taken. Sorted for a stable hash.
    #
    # The distinction that matters: a subsystem left unwired is recorded as
    # UNKNOWN and does not appear here, because the deployment never claimed
    # to observe it and authorize() never consulted it. A subsystem that IS
    # wired and then fails to answer is a different thing entirely -- the
    # deployment depends on it and we are now blind. That belongs here, and
    # revalidate() refuses to report an allow while it is non-empty.
    degraded_dependencies: tuple[str, ...] = ()

    @property
    def degraded(self) -> bool:
        """True when some configured security dependency could not be read."""
        return bool(self.degraded_dependencies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "capability_fingerprint": self.capability_fingerprint,
            "agent_id": self.agent_id,
            "action": self.action,
            "request_hash": self.request_hash,
            "identity_status": self.identity_status,
            "identity_version": self.identity_version,
            "capability_revoked": self.capability_revoked,
            "capability_expired": self.capability_expired,
            "delegation_chain_valid": self.delegation_chain_valid,
            "delegation_depth": self.delegation_depth,
            "max_delegation_depth": self.max_delegation_depth,
            "posture": self.posture,
            "trust_findings": self.trust_findings,
            "risk_level": self.risk_level,
            "policy_version": self.policy_version,
            "environment": self.environment,
            "provenance_state": self.provenance_state,
            "incident_active": self.incident_active,
            "degraded_dependencies": list(self.degraded_dependencies),
        }

    def state_hash(self) -> str:
        """Hash of the security state that can drift under a decision.

        Excludes ``_HASH_EXCLUDED_FIELDS`` -- see the comment on that set for
        why ``timestamp`` in particular must not be hashed.
        """
        material = {
            key: value
            for key, value in self.to_dict().items()
            if key not in _HASH_EXCLUDED_FIELDS
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class RevalidationResult:
    """Result of a continuous authorization revalidation.

    ``authority_revoked`` is the case that matters operationally: a decision
    that was allowed and is no longer allowed. It is surfaced as its own
    property so that callers do not have to re-derive the comparison (and
    cannot get the direction wrong).
    """

    original_allowed: bool
    revalidated_allowed: bool
    trigger: RevalidationTrigger
    snapshot_before: SecurityContextSnapshot
    snapshot_after: SecurityContextSnapshot
    state_changed: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def authority_revoked(self) -> bool:
        """True when revalidation withdrew a previously granted authority."""
        return self.original_allowed and not self.revalidated_allowed

    @property
    def authority_widened(self) -> bool:
        """True when revalidation turned a denial into an allow.

        This is not inherently a violation -- a lifted quarantine or a
        corrected policy legitimately produces it -- but it is the shape an
        illegitimate restoration would take, so it is reported explicitly
        rather than left for a caller to notice.
        """
        return not self.original_allowed and self.revalidated_allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_allowed": self.original_allowed,
            "revalidated_allowed": self.revalidated_allowed,
            "authority_revoked": self.authority_revoked,
            "authority_widened": self.authority_widened,
            "trigger": self.trigger.value,
            "snapshot_before": self.snapshot_before.to_dict(),
            "snapshot_after": self.snapshot_after.to_dict(),
            "state_changed": self.state_changed,
            "reason": self.reason,
            "details": dict(self.details),
        }


class ContinuousAuthorizationEngine:
    """
    Re-evaluates authorization decisions when security-relevant state changes.

    This does NOT replace ``FirewallSDK.authorize()`` and is not a second
    authorization engine. It records the security state a decision was taken
    under, detects material drift in that state, and re-asks the canonical
    path. Every ``allowed`` value it reports was produced by ``authorize()``.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        clock: Optional[Callable[[], float]] = None,
        identity_registry=None,
        task_registry=None,
        posture_engine=None,
        trust_graph=None,
        risk_context: Optional[RiskContext] = None,
        provenance_registry=None,
        policy_version_provider: Optional[Callable[[], str]] = None,
        environment_provider: Optional[Callable[[], dict[str, Any]]] = None,
        incident_provider: Optional[Callable[[str], bool]] = None,
        max_cached_decisions: int = DEFAULT_MAX_CACHED_DECISIONS,
    ) -> None:
        if not hasattr(sdk, "authorize"):
            raise TypeError(
                "sdk must expose authorize(); the continuous authorization "
                "engine has no authorization path of its own"
            )

        if (
            not isinstance(max_cached_decisions, int)
            or isinstance(max_cached_decisions, bool)
            or max_cached_decisions <= 0
        ):
            raise ValueError("max_cached_decisions must be a positive integer")

        self._sdk = sdk
        self._clock = clock or time.time
        self._identity_registry = identity_registry
        self._task_registry = task_registry
        self._posture_engine = posture_engine
        self._trust_graph = trust_graph
        self._risk_context = risk_context
        self._provenance_registry = provenance_registry
        self._policy_version_provider = policy_version_provider
        self._environment_provider = environment_provider or (lambda: {})
        self._incident_provider = incident_provider
        self._max_cached_decisions = max_cached_decisions
        self._lock = threading.RLock()

        # Bounded LRU of original decisions, for drift comparison only.
        self._decision_cache: "OrderedDict[str, tuple[AuthorizationResult, SecurityContextSnapshot]]" = (
            OrderedDict()
        )

    # ------------------------------------------------------------------
    # Canonical authorization, plus a snapshot for later comparison
    # ------------------------------------------------------------------

    def authorize_with_context(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
        *,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> AuthorizationResult:
        """Authorize through the SDK and record the state it was decided under.

        The snapshot is taken *after* the decision deliberately: it must
        describe the state the decision actually reflects, including any state
        the authorization itself moved (a denial that raises risk level, for
        instance). Snapshotting first would record a state that the cached
        decision does not correspond to, and the very next revalidation would
        report spurious drift.
        """
        result = self._sdk.authorize(
            capability,
            action,
            request,
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        snapshot = self._capture_snapshot(capability, action, request)
        cache_key = self._cache_key(capability, action, request)

        with self._lock:
            self._decision_cache[cache_key] = (result, snapshot)
            self._decision_cache.move_to_end(cache_key)
            while len(self._decision_cache) > self._max_cached_decisions:
                self._decision_cache.popitem(last=False)

        return result

    # ------------------------------------------------------------------
    # Revalidation
    # ------------------------------------------------------------------

    def revalidate(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
        *,
        trigger: RevalidationTrigger = RevalidationTrigger.EXPLICIT_REQUEST,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> RevalidationResult:
        """Re-evaluate a previous decision against current security state.

        On a cache miss the decision is treated as ``original_allowed=False``.
        We have no record that the authority was ever granted, so presenting
        the fresh result as if it were also the original would let a cache
        eviction launder a denial into "unchanged". Reporting it as a widening
        from unknown is the fail-closed reading.
        """
        cache_key = self._cache_key(capability, action, request)

        with self._lock:
            cached = self._decision_cache.get(cache_key)
            if cached is not None:
                self._decision_cache.move_to_end(cache_key)

        if cached is None:
            snapshot = self._capture_snapshot(capability, action, request)
            result = self._sdk.authorize(
                capability,
                action,
                request,
                refusal_scope=refusal_scope,
                chain_id=chain_id,
            )
            allowed, degraded_reason = self._effective_verdict(result, snapshot)
            return RevalidationResult(
                original_allowed=False,
                revalidated_allowed=allowed,
                trigger=trigger,
                snapshot_before=snapshot,
                snapshot_after=snapshot,
                state_changed=True,
                reason=degraded_reason or "no_previous_decision",
                details={
                    "cache_key": cache_key,
                    "revalidated_reason": result.reason,
                    "degraded_dependencies": list(snapshot.degraded_dependencies),
                },
            )

        original_result, original_snapshot = cached
        current_snapshot = self._capture_snapshot(capability, action, request)

        state_changed = (
            original_snapshot.state_hash() != current_snapshot.state_hash()
        )

        if not state_changed:
            # State is unchanged, but "unchanged" includes unchanged-and-still-
            # degraded: a dependency that was already unreadable when the
            # decision was cached does not become readable by standing still.
            allowed, degraded_reason = self._effective_verdict(
                original_result, current_snapshot
            )
            return RevalidationResult(
                original_allowed=original_result.allowed,
                revalidated_allowed=allowed,
                trigger=trigger,
                snapshot_before=original_snapshot,
                snapshot_after=current_snapshot,
                state_changed=False,
                reason=degraded_reason or "no_material_state_change",
                details=(
                    {"degraded_dependencies": list(current_snapshot.degraded_dependencies)}
                    if current_snapshot.degraded
                    else {}
                ),
            )

        revalidated_result = self._sdk.authorize(
            capability,
            action,
            request,
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        change_reasons = self._diff_snapshots(original_snapshot, current_snapshot)
        allowed, degraded_reason = self._effective_verdict(
            revalidated_result, current_snapshot
        )

        with self._lock:
            if cache_key in self._decision_cache:
                self._decision_cache[cache_key] = (
                    revalidated_result,
                    current_snapshot,
                )
                self._decision_cache.move_to_end(cache_key)

        if degraded_reason:
            reason = degraded_reason
        elif change_reasons:
            reason = "; ".join(change_reasons)
        else:
            reason = "state_changed"

        return RevalidationResult(
            original_allowed=original_result.allowed,
            revalidated_allowed=allowed,
            trigger=trigger,
            snapshot_before=original_snapshot,
            snapshot_after=current_snapshot,
            state_changed=True,
            reason=reason,
            details={
                "change_reasons": change_reasons,
                "original_reason": original_result.reason,
                "revalidated_reason": revalidated_result.reason,
                "degraded_dependencies": list(current_snapshot.degraded_dependencies),
            },
        )

    @staticmethod
    def _effective_verdict(
        result: AuthorizationResult,
        snapshot: SecurityContextSnapshot,
    ) -> tuple[bool, Optional[str]]:
        """Gate an authorize() verdict on the readability of security state.

        This only ever moves an allow to a deny. It cannot turn a denial into
        an allow, so ``authorize()`` remains the sole grantor of authority --
        the engine is permitted to be more restrictive than the canonical
        decision, never less.

        The case being closed: a configured security dependency that raises
        does not make ``authorize()`` deny, because ``authorize()`` never
        consulted it. Reporting "still authorized" while blind to identity,
        posture, or provenance state would be fail-open in exactly the way
        continuous authorization exists to prevent.
        """
        if not snapshot.degraded:
            return result.allowed, None

        names = ", ".join(snapshot.degraded_dependencies)
        return False, f"security_dependency_unavailable: {names}"

    # ------------------------------------------------------------------
    # State capture
    # ------------------------------------------------------------------

    def cache_key(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
    ) -> str:
        """Identity of a decision: which capability, doing what, to what.

        Public because the monitor keys its table by this value and must
        derive it identically. Two independent canonicalisations that drift
        apart would split one decision into two entries, leaving a stale
        one that is never compared against the live one.
        """
        fingerprint = capability_fingerprint(capability)
        return f"{fingerprint}:{action}:{self.request_hash(request)[:16]}"

    def request_hash(self, request: dict[str, Any]) -> str:
        """Canonical hash of a request payload. Single definition, shared."""
        return _canonical_hash(request)

    # Retained for internal call sites and any existing callers.
    _cache_key = cache_key

    def _capture_snapshot(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
    ) -> SecurityContextSnapshot:
        """Capture current security-relevant state.

        Every probe is individually guarded and every failure resolves to the
        untrusted value. A probe that cannot answer must not be able to report
        a healthy state.
        """
        fingerprint = capability_fingerprint(capability)
        agent_id = capability.agent_id

        now = float(self._clock())

        identity_status, identity_version = self._probe_identity(agent_id)
        capability_revoked = self._probe_revoked(capability)
        capability_expired = self._probe_expired(capability, now)
        delegation_chain_valid, delegation_depth = self._probe_delegation(fingerprint)
        max_delegation_depth = getattr(self._sdk, "max_delegation_depth", None)
        posture = self._probe_posture(agent_id)
        trust_findings = self._probe_trust(agent_id)
        risk_level = self._probe_risk(agent_id)
        policy_version = self._probe_policy_version()
        environment = self._probe_environment()
        provenance_state = self._probe_provenance(agent_id)
        incident_active = self._probe_incident(agent_id)

        # Which configured dependencies failed to answer. Only probes whose
        # subsystem is actually wired can land here -- an unwired subsystem
        # returns UNKNOWN, which is recorded but is not a degradation.
        degraded: list[str] = []
        if self._identity_registry is not None and identity_status == PROBE_FAILED:
            degraded.append("identity")
        if self._posture_engine is not None and posture == PROBE_FAILED:
            degraded.append("posture")
        if self._trust_graph is not None and trust_findings < 0:
            degraded.append("trust")
        if self._risk_context is not None and risk_level == PROBE_FAILED:
            degraded.append("risk")
        if self._policy_version_provider is not None and policy_version == PROBE_FAILED:
            degraded.append("policy")
        if environment in (PROBE_FAILED, "unserialisable"):
            degraded.append("environment")
        if self._provenance_registry is not None and provenance_state == PROBE_FAILED:
            degraded.append("provenance")
        # A negative depth means the lineage could not be walked at all, which
        # is distinct from "walked, no ancestors" (depth 0).
        if delegation_depth < 0:
            degraded.append("delegation_lineage")

        return SecurityContextSnapshot(
            timestamp=now,
            capability_fingerprint=fingerprint,
            agent_id=agent_id,
            action=action,
            request_hash=self.request_hash(request)[:32],
            identity_status=identity_status,
            identity_version=identity_version,
            capability_revoked=capability_revoked,
            capability_expired=capability_expired,
            delegation_chain_valid=delegation_chain_valid,
            delegation_depth=delegation_depth,
            max_delegation_depth=max_delegation_depth,
            posture=posture,
            trust_findings=trust_findings,
            risk_level=risk_level,
            policy_version=policy_version,
            environment=environment,
            provenance_state=provenance_state,
            incident_active=incident_active,
            degraded_dependencies=tuple(sorted(degraded)),
        )

    # -- individual probes, each fail-closed -----------------------------

    def _probe_identity(self, agent_id: str) -> tuple[str, int]:
        if self._identity_registry is None:
            return UNKNOWN, -1
        try:
            identity = self._identity_registry.get(agent_id)
        except Exception:
            return PROBE_FAILED, -1
        if identity is None:
            return "unregistered", -1
        return str(identity.status), int(identity.identity_version)

    def _probe_revoked(self, capability: Capability) -> bool:
        try:
            return bool(self._sdk.is_effectively_revoked(capability))
        except Exception:
            # Cannot determine revocation state. Treat as revoked.
            return True

    def _probe_expired(self, capability: Capability, now: float) -> bool:
        if not math.isfinite(now):
            return True
        try:
            expires_at = float(capability.expires_at)
        except (TypeError, ValueError):
            return True
        if not math.isfinite(expires_at):
            return True
        return now >= expires_at

    def _probe_delegation(self, fingerprint: str) -> tuple[bool, int]:
        try:
            chain = self._sdk.delegation_lineage.chain(fingerprint)
        except Exception:
            return False, -1

        for ancestor in chain:
            try:
                if self._sdk.revocation.is_revoked(ancestor):
                    return False, len(chain)
            except Exception:
                return False, len(chain)

        return True, len(chain)

    def _probe_posture(self, agent_id: str) -> str:
        if self._posture_engine is None:
            return UNKNOWN
        try:
            return str(self._posture_engine.state(agent_id).posture)
        except Exception:
            return PROBE_FAILED

    def _probe_trust(self, agent_id: str) -> int:
        """Count trust-graph danger findings implicating this agent.

        A count of concrete findings, not a synthesised score. The trust graph
        exposes no per-agent scalar and inventing one would be exactly the
        "inference presented as fact" the design forbids. ``-1`` means the
        graph could not be consulted, which is distinguishable from ``0``
        ("consulted, nothing found").
        """
        if self._trust_graph is None:
            return -1
        try:
            findings = self._trust_graph.find_dangers()
        except Exception:
            return -1

        count = 0
        for finding in findings:
            rendered = json.dumps(
                finding if isinstance(finding, (dict, list)) else str(finding),
                sort_keys=True,
                default=repr,
            )
            if agent_id in rendered:
                count += 1
        return count

    def _probe_risk(self, agent_id: str) -> str:
        if self._risk_context is None:
            return UNKNOWN
        try:
            level = self._risk_context.level(agent_id)
        except Exception:
            return PROBE_FAILED
        # RiskLevel is an IntEnum; record the name so the snapshot stays
        # readable and JSON-stable rather than an opaque integer.
        return getattr(level, "name", str(level))

    def _probe_policy_version(self) -> str:
        if self._policy_version_provider is None:
            return UNKNOWN
        try:
            return str(self._policy_version_provider())
        except Exception:
            return PROBE_FAILED

    def _probe_environment(self) -> str:
        try:
            environment = self._environment_provider()
        except Exception:
            return PROBE_FAILED
        try:
            return json.dumps(environment, sort_keys=True, separators=(",", ":"), default=repr)
        except Exception:
            return "unserialisable"

    def _probe_provenance(self, agent_id: str) -> str:
        """Worst provenance trust state across components bound to the agent."""
        if self._provenance_registry is None:
            return UNKNOWN
        try:
            components = self._provenance_registry.for_agent(agent_id)
        except Exception:
            return PROBE_FAILED

        if not components:
            return "no_components"

        # Worst state present governs. Anything the registry reports that we
        # do not recognise is treated as UNKNOWN rather than assumed benign.
        ranking = ("revoked", "suspect", UNKNOWN, "trusted")
        worst_index = len(ranking) - 1
        for component in components:
            state = str(getattr(component, "trust", UNKNOWN))
            index = ranking.index(state) if state in ranking else ranking.index(UNKNOWN)
            worst_index = min(worst_index, index)
        return ranking[worst_index]

    def _probe_incident(self, agent_id: str) -> bool:
        if self._incident_provider is None:
            return False
        try:
            return bool(self._incident_provider(agent_id))
        except Exception:
            # An incident probe that fails is treated as an active incident.
            return True

    # ------------------------------------------------------------------
    # Drift explanation
    # ------------------------------------------------------------------

    def _diff_snapshots(
        self,
        before: SecurityContextSnapshot,
        after: SecurityContextSnapshot,
    ) -> list[str]:
        """Human-readable account of every material field that moved.

        Driven off ``_HASH_EXCLUDED_FIELDS`` so that the explanation and the
        change detection cannot disagree: anything hashed is reported, and
        anything reported is hashed.
        """
        before_fields = before.to_dict()
        after_fields = after.to_dict()

        reasons: list[str] = []
        for key in sorted(before_fields):
            if key in _HASH_EXCLUDED_FIELDS:
                continue
            old = before_fields[key]
            new = after_fields.get(key)
            if old != new:
                reasons.append(f"{key}: {old!r} -> {new!r}")

        return reasons

    # ------------------------------------------------------------------
    # Cache introspection
    # ------------------------------------------------------------------

    def snapshot_for(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
    ) -> Optional[SecurityContextSnapshot]:
        """Return the recorded snapshot for a decision, if one is cached."""
        cache_key = self._cache_key(capability, action, request)
        with self._lock:
            cached = self._decision_cache.get(cache_key)
        return None if cached is None else cached[1]

    def clear_cache(self) -> None:
        """Clear the decision cache.

        Safe by construction: the cache only ever holds a baseline for drift
        comparison, so clearing it can at worst cause a redundant
        ``authorize()`` call. It cannot grant anything.
        """
        with self._lock:
            self._decision_cache.clear()

    def cache_size(self) -> int:
        """Return the number of cached decisions."""
        with self._lock:
            return len(self._decision_cache)


def _canonical_hash(payload: Any) -> str:
    """Stable SHA-256 over a request payload.

    ``default=repr`` keeps this total: an unserialisable request must still
    produce a key, because refusing to hash would mean refusing to monitor the
    decision at all.
    """
    try:
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=repr
        )
    except Exception:
        canonical = repr(payload)
    return hashlib.sha256(canonical.encode()).hexdigest()
