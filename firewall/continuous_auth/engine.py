"""v2.2 Continuous Authorization Engine.

Deterministic re-evaluation of authorization decisions when security-relevant
state changes. Feeds the canonical SDK authorization path.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from firewall.sdk import FirewallSDK

from firewall.authorization import AuthorizationResult, authorize
from firewall.capability import Capability, capability_fingerprint
from firewall.delegation_lineage import DelegationLineage
from firewall.revocation import RevocationRegistry
from firewall.risk_context import RiskContext

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

@dataclass(frozen=True)
class SecurityContextSnapshot:
    """Immutable snapshot of security-relevant state at a point in time."""

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
    trust_score: float
    risk_level: str
    policy_version: str
    environment: dict[str, Any]
    provenance_trusted: bool
    incident_active: bool

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
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "policy_version": self.policy_version,
            "environment": dict(self.environment),
            "provenance_trusted": self.provenance_trusted,
            "incident_active": self.incident_active,
        }

    def state_hash(self) -> str:
        """Hash of all security-relevant state for change detection."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

@dataclass(frozen=True)
class RevalidationResult:
    """Result of a continuous authorization revalidation."""

    original_allowed: bool
    revalidated_allowed: bool
    trigger: RevalidationTrigger
    snapshot_before: SecurityContextSnapshot
    snapshot_after: SecurityContextSnapshot
    state_changed: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_allowed": self.original_allowed,
            "revalidated_allowed": self.revalidated_allowed,
            "trigger": self.trigger.value,
            "snapshot_before": self.snapshot_before.to_dict(),
            "snapshot_after": self.snapshot_after.to_dict(),
            "state_changed": self.state_changed,
            "reason": self.reason,
            "details": dict(self.details),
        }

class ContinuousAuthorizationEngine:
    """
    Continuous authorization engine that re-evaluates authorization decisions
    when security-relevant state materially changes.

    This does NOT replace FirewallSDK.authorize(). It provides a mechanism to
    detect when a previous authorization decision should be re-evaluated by
    the canonical authorization path.
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
    ) -> None:
        # To avoid circular imports, we avoid using isinstance(sdk, FirewallSDK)
        # here if FirewallSDK is not imported. We trust the type hint.

        self._sdk = sdk
        self._clock = clock or time.time
        self._identity_registry = identity_registry
        self._task_registry = task_registry
        self._posture_engine = posture_engine
        self._trust_graph = trust_graph
        self._risk_context = risk_context
        self._provenance_registry = provenance_registry
        self._policy_version_provider = policy_version_provider or (lambda: "1.0")
        self._environment_provider = environment_provider or (lambda: {})
        self._incident_provider = incident_provider or (lambda agent_id: False)
        self._lock = threading.RLock()

        # Cache of original authorization decisions for revalidation
        self._decision_cache: dict[str, tuple[AuthorizationResult, SecurityContextSnapshot]] = {}

    def authorize_with_context(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
        *,
        refusal_scope: str = "action",
        chain_id: Optional[str] = None,
    ) -> AuthorizationResult:
        """
        Authorize and capture the security context snapshot for future
        continuous revalidation.
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

        return result

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
        """
        Revalidate a previous authorization decision against current state.

        Returns a RevalidationResult indicating whether the decision would
        change given current security state.
        """
        cache_key = self._cache_key(capability, action, request)

        with self._lock:
            cached = self._decision_cache.get(cache_key)

        if cached is None:
            # No previous decision - perform fresh authorization
            current_snapshot = self._capture_snapshot(capability, action, request)
            result = self._sdk.authorize(
                capability,
                action,
                request,
                refusal_scope=refusal_scope,
                chain_id=chain_id,
            )
            return RevalidationResult(
                original_allowed=result.allowed,
                revalidated_allowed=result.allowed,
                trigger=trigger,
                snapshot_before=current_snapshot,
                snapshot_after=current_snapshot,
                state_changed=False,
                reason="no_previous_decision",
                details={"cache_key": cache_key},
            )

        original_result, original_snapshot = cached
        current_snapshot = self._capture_snapshot(capability, action, request)

        # Check if security-relevant state has changed
        state_changed = original_snapshot.state_hash() != current_snapshot.state_hash()

        if not state_changed:
            return RevalidationResult(
                original_allowed=original_result.allowed,
                revalidated_allowed=original_result.allowed,
                trigger=trigger,
                snapshot_before=original_snapshot,
                snapshot_after=current_snapshot,
                state_changed=False,
                reason="no_material_state_change",
            )

        # Re-evaluate through the canonical authorization path
        revalidated_result = self._sdk.authorize(
            capability,
            action,
            request,
            refusal_scope=refusal_scope,
            chain_id=chain_id,
        )

        # Determine why the state changed
        change_reasons = self._diff_snapshots(original_snapshot, current_snapshot)

        return RevalidationResult(
            original_allowed=original_result.allowed,
            revalidated_allowed=revalidated_result.allowed,
            trigger=trigger,
            snapshot_before=original_snapshot,
            snapshot_after=current_snapshot,
            state_changed=True,
            reason="; ".join(change_reasons) if change_reasons else "state_changed",
            details={
                "change_reasons": change_reasons,
                "original_reason": original_result.reason,
                "revalidated_reason": revalidated_result.reason,
            },
        )

    def _cache_key(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
    ) -> str:
        """Generate a cache key for an authorization decision."""
        fingerprint = capability_fingerprint(capability)
        request_str = json.dumps(request, sort_keys=True, separators=(",", ":"))
        return f"{fingerprint}:{action}:{hashlib.sha256(request_str.encode()).hexdigest()[:16]}"

    def _capture_snapshot(
        self,
        capability: Capability,
        action: str,
        request: dict[str, Any],
    ) -> SecurityContextSnapshot:
        """Capture current security-relevant state."""
        fingerprint = capability_fingerprint(capability)
        agent_id = capability.agent_id

        # Identity state
        identity_status = "unknown"
        identity_version = 0
        if self._identity_registry is not None:
            identity = self._identity_registry.get(agent_id)
            if identity is not None:
                identity_status = identity.status
                identity_version = identity.identity_version

        # Capability state
        capability_revoked = self._sdk.is_effectively_revoked(capability)
        capability_expired = False
        now = float(self._clock())
        if not math.isfinite(now):
            capability_expired = True
        elif now >= capability.expires_at:
            capability_expired = True

        # Delegation chain
        delegation_chain_valid = True
        delegation_depth = 0
        try:
            chain = self._sdk.delegation_lineage.chain(fingerprint)
            delegation_depth = len(chain)
            # Check if any ancestor is revoked
            for ancestor in chain:
                if self._sdk.revocation.is_revoked(ancestor):
                    delegation_chain_valid = False
                    break
        except Exception:
            delegation_chain_valid = False

        max_delegation_depth = self._sdk.max_delegation_depth

        # Posture
        posture = "unknown"
        if self._posture_engine is not None:
            try:
                posture = self._posture_engine.state(agent_id).posture
            except Exception:
                posture = "unknown"

        # Trust score
        trust_score = 1.0
        if self._trust_graph is not None:
            try:
                # Simplified trust score extraction
                trust_score = 1.0  # Would need proper trust graph integration
            except Exception:
                trust_score = 0.0

        # Risk level
        risk_level = "low"
        if self._risk_context is not None:
            try:
                risk_level = self._risk_context.level(agent_id)
            except Exception:
                risk_level = "unknown"

        # Policy version
        policy_version = self._policy_version_provider()

        # Environment
        environment = self._environment_provider()

        # Provenance
        provenance_trusted = True
        if self._provenance_registry is not None:
            try:
                # Simplified - would check component trust status
                provenance_trusted = True
            except Exception:
                provenance_trusted = False

        # Incident
        incident_active = self._incident_provider(agent_id)

        request_str = json.dumps(request, sort_keys=True, separators=(",", ":"))
        request_hash = hashlib.sha256(request_str.encode()).hexdigest()[:32]

        return SecurityContextSnapshot(
            timestamp=now,
            capability_fingerprint=fingerprint,
            agent_id=agent_id,
            action=action,
            request_hash=request_hash,
            identity_status=identity_status,
            identity_version=identity_version,
            capability_revoked=capability_revoked,
            capability_expired=capability_expired,
            delegation_chain_valid=delegation_chain_valid,
            delegation_depth=delegation_depth,
            max_delegation_depth=max_delegation_depth,
            posture=posture,
            trust_score=trust_score,
            risk_level=risk_level,
            policy_version=policy_version,
            environment=environment,
            provenance_trusted=provenance_trusted,
            incident_active=incident_active,
        )

    def _diff_snapshots(
        self,
        before: SecurityContextSnapshot,
        after: SecurityContextSnapshot,
    ) -> list[str]:
        """Identify what changed between two snapshots."""
        reasons = []

        if before.identity_status != after.identity_status:
            reasons.append(f"identity: {before.identity_status} -> {after.identity_status}")
        if before.identity_version != after.identity_version:
            reasons.append(f"identity_version: {before.identity_version} -> {after.identity_version}")
        if before.capability_revoked != after.capability_revoked:
            reasons.append(f"capability_revoked: {before.capability_revoked} -> {after.capability_revoked}")
        if before.capability_expired != after.capability_expired:
            reasons.append(f"capability_expired: {before.capability_expired} -> {after.capability_expired}")
        if before.delegation_chain_valid != after.delegation_chain_valid:
            reasons.append(f"delegation_chain_valid: {before.delegation_chain_valid} -> {after.delegation_chain_valid}")
        if before.delegation_depth != after.delegation_depth:
            reasons.append(f"delegation_depth: {before.delegation_depth} -> {after.delegation_depth}")
        if before.max_delegation_depth != after.max_delegation_depth:
            reasons.append(f"max_delegation_depth: {before.max_delegation_depth} -> {after.max_delegation_depth}")
        if before.posture != after.posture:
            reasons.append(f"posture: {before.posture} -> {after.posture}")
        if abs(before.trust_score - after.trust_score) > 0.01:
            reasons.append(f"trust_score: {before.trust_score:.2f} -> {after.trust_score:.2f}")
        if before.risk_level != after.risk_level:
            reasons.append(f"risk_level: {before.risk_level} -> {after.risk_level}")
        if before.policy_version != after.policy_version:
            reasons.append(f"policy_version: {before.policy_version} -> {after.policy_version}")
        if before.provenance_trusted != after.provenance_trusted:
            reasons.append(f"provenance_trusted: {before.provenance_trusted} -> {after.provenance_trusted}")
        if before.incident_active != after.incident_active:
            reasons.append(f"incident_active: {before.incident_active} -> {after.incident_active}")

        return reasons

    def clear_cache(self) -> None:
        """Clear the decision cache."""
        with self._lock:
            self._decision_cache.clear()

    def cache_size(self) -> int:
        """Return the number of cached decisions."""
        with self._lock:
            return len(self._decision_cache)
