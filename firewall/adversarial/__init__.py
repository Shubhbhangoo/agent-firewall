"""v2.2 Adversarial Agent Defense (firewall.adversarial).

Deterministic security signals around discrepancies between:
- claimed identity vs actual identity
- declared task vs authorized task
- capabilities vs observed actions
- delegations vs provenance
- posture vs historical behavior

Detects contradictions explicitly. Does not resolve contradictions by guessing.
If the system cannot establish a required security fact: unknown remains unknown.

Uses explicit provenance: observed, derived, inferred, simulated, unknown.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.delegation_lineage import DelegationLineage
from firewall.evidence_graph import EvidenceGraph, EvidenceKind
from firewall.ident import IdentityRegistry
from firewall.posture import PostureEngine
from firewall.revocation import RevocationRegistry
from firewall.sdk import FirewallSDK
from firewall.task import TaskRegistry


class DiscrepancyType(str, Enum):
    """Types of security discrepancies detected."""

    IDENTITY_MISMATCH = "identity_mismatch"
    IDENTITY_UNVERIFIED = "identity_unverified"
    TASK_MISMATCH = "task_mismatch"
    TASK_UNAUTHORIZED = "task_unauthorized"
    CAPABILITY_MISMATCH = "capability_mismatch"
    CAPABILITY_REVOKED = "capability_revoked"
    CAPABILITY_EXPIRED = "capability_expired"
    DELEGATION_MISMATCH = "delegation_mismatch"
    DELEGATION_CHAIN_BROKEN = "delegation_chain_broken"
    DELEGATION_WIDENING = "delegation_widening"
    PROVENANCE_MISMATCH = "provenance_mismatch"
    PROVENANCE_UNTRUSTED = "provenance_untrusted"
    POSTURE_CONTRADICTION = "posture_contradiction"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    EVIDENCE_CONTRADICTION = "evidence_contradiction"
    REPLAY_DETECTED = "replay_detected"
    TIME_TRAVEL = "time_travel"
    UNKNOWN = "unknown"


class ProvenanceLevel(str, Enum):
    """Explicit provenance levels for security facts."""

    OBSERVED = "observed"       # Directly recorded security evidence
    DERIVED = "derived"         # Deterministically computed from recorded evidence
    INFERRED = "inferred"       # Analytical or heuristic finding
    SIMULATED = "simulated"     # Produced by an isolated counterfactual
    UNKNOWN = "unknown"         # Required evidence is missing or unverifiable


@dataclass(frozen=True)
class SecuritySignal:
    """One deterministic security signal with explicit provenance."""

    discrepancy_type: DiscrepancyType
    provenance: ProvenanceLevel
    agent_id: str
    description: str
    evidence: tuple[dict[str, Any], ...] = ()
    confidence: float = 0.0  # 0.0-1.0, only meaningful for inferred
    timestamp: float = 0.0
    related_signals: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "discrepancy_type": self.discrepancy_type.value,
            "provenance": self.provenance.value,
            "agent_id": self.agent_id,
            "description": self.description,
            "evidence": [dict(e) for e in self.evidence],
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "related_signals": list(self.related_signals),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AgentSecurityProfile:
    """Aggregated security profile for an agent."""

    agent_id: str
    signals: tuple[SecuritySignal, ...] = ()
    identity_verified: bool = False
    identity_status: str = "unknown"
    active_tasks: tuple[str, ...] = ()
    live_capabilities: tuple[str, ...] = ()
    delegation_depth: int = 0
    posture: str = "unknown"
    trust_score: float = 1.0
    risk_level: str = "low"
    last_evaluated: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "signals": [s.to_dict() for s in self.signals],
            "identity_verified": self.identity_verified,
            "identity_status": self.identity_status,
            "active_tasks": list(self.active_tasks),
            "live_capabilities": list(self.live_capabilities),
            "delegation_depth": self.delegation_depth,
            "posture": self.posture,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "last_evaluated": self.last_evaluated,
        }


class AdversarialAgentDefense:
    """
    Adversarial agent defense that evaluates security discrepancies
    with explicit provenance tracking.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        identity_registry: Optional[IdentityRegistry] = None,
        task_registry: Optional[TaskRegistry] = None,
        posture_engine: Optional[PostureEngine] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise TypeError("sdk must be a FirewallSDK")

        self._sdk = sdk
        self._identity_registry = identity_registry
        self._task_registry = task_registry
        self._posture_engine = posture_engine
        self._evidence_graph = evidence_graph
        self._clock = clock or time.time
        self._lock = threading.RLock()

        # Agent profiles cache
        self._profiles: dict[str, AgentSecurityProfile] = {}

    def evaluate_agent(
        self,
        agent_id: str,
        *,
        claimed_identity: Optional[dict[str, Any]] = None,
        declared_task: Optional[str] = None,
        presented_capability: Optional[Capability] = None,
        observed_action: Optional[dict[str, Any]] = None,
        now: Optional[float] = None,
    ) -> AgentSecurityProfile:
        """
        Evaluate an agent for security discrepancies.

        All inputs are optional - the evaluator uses what's available
        and marks missing evidence as UNKNOWN provenance.
        """
        timestamp = float(now) if now is not None else float(self._clock())
        signals: list[SecuritySignal] = []

        # 1. Identity verification
        identity_signals = self._verify_identity(agent_id, claimed_identity, timestamp)
        signals.extend(identity_signals)

        # 2. Task authorization
        task_signals = self._verify_task(agent_id, declared_task, timestamp)
        signals.extend(task_signals)

        # 3. Capability validation
        capability_signals = self._verify_capability(agent_id, presented_capability, timestamp)
        signals.extend(capability_signals)

        # 4. Delegation chain validation
        delegation_signals = self._verify_delegation_chain(agent_id, presented_capability, timestamp)
        signals.extend(delegation_signals)

        # 5. Provenance validation
        provenance_signals = self._verify_provenance(agent_id, presented_capability, timestamp)
        signals.extend(provenance_signals)

        # 6. Posture and behavioral analysis
        posture_signals = self._analyze_posture_and_behavior(agent_id, observed_action, timestamp)
        signals.extend(posture_signals)

        # 7. Evidence contradiction detection
        evidence_signals = self._detect_evidence_contradictions(agent_id, timestamp)
        signals.extend(evidence_signals)

        # Build profile
        identity_verified = any(
            s.discrepancy_type == DiscrepancyType.IDENTITY_UNVERIFIED
            for s in signals
        ) is False

        identity_status = "unknown"
        if self._identity_registry:
            ident = self._identity_registry.get(agent_id)
            if ident:
                identity_status = ident.status

        active_tasks = ()
        if self._task_registry:
            try:
                active_tasks = tuple(
                    t.task_id for t in self._task_registry.tasks_for_agent(agent_id)
                    if t.status == "active"
                )
            except Exception:
                pass

        live_capabilities = ()
        try:
            registry = getattr(self._sdk, "_capability_registry", {}) or {}
            live_capabilities = tuple(
                cap.capability for cap in registry.values()
                if cap.agent_id == agent_id and not self._sdk.is_effectively_revoked(cap)
            )
        except Exception:
            pass

        delegation_depth = 0
        if presented_capability:
            try:
                chain = self._sdk.delegation_lineage.chain(
                    self._sdk.fingerprint(presented_capability)
                )
                delegation_depth = len(chain)
            except Exception:
                pass

        posture = "unknown"
        if self._posture_engine:
            try:
                posture = self._posture_engine.state(agent_id).posture
            except Exception:
                pass

        trust_score = 1.0
        for signal in signals:
            if signal.discrepancy_type in (
                DiscrepancyType.IDENTITY_MISMATCH,
                DiscrepancyType.CAPABILITY_REVOKED,
                DiscrepancyType.DELEGATION_WIDENING,
            ):
                trust_score *= 0.5
            elif signal.discrepancy_type in (
                DiscrepancyType.POSTURE_CONTRADICTION,
                DiscrepancyType.BEHAVIOR_ANOMALY,
            ):
                trust_score *= 0.8

        risk_level = "low"
        if trust_score < 0.3:
            risk_level = "critical"
        elif trust_score < 0.5:
            risk_level = "high"
        elif trust_score < 0.7:
            risk_level = "medium"

        profile = AgentSecurityProfile(
            agent_id=agent_id,
            signals=tuple(signals),
            identity_verified=identity_verified,
            identity_status=identity_status,
            active_tasks=active_tasks,
            live_capabilities=live_capabilities,
            delegation_depth=delegation_depth,
            posture=posture,
            trust_score=trust_score,
            risk_level=risk_level,
            last_evaluated=timestamp,
        )

        with self._lock:
            self._profiles[agent_id] = profile

        return profile

    def _verify_identity(
        self,
        agent_id: str,
        claimed_identity: Optional[dict[str, Any]],
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if self._identity_registry is None:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.IDENTITY_UNVERIFIED,
                provenance=ProvenanceLevel.UNKNOWN,
                agent_id=agent_id,
                description="No identity registry available for verification",
                timestamp=timestamp,
                metadata={"reason": "no_registry"},
            ))
            return signals

        identity = self._identity_registry.get(agent_id)

        if identity is None:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.IDENTITY_UNVERIFIED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Identity not found in registry: {agent_id}",
                timestamp=timestamp,
                metadata={"reason": "not_found"},
            ))
            return signals

        # Check identity status
        if identity.status != "active":
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.IDENTITY_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Identity status is {identity.status}, not active",
                timestamp=timestamp,
                metadata={"status": identity.status},
            ))

        # Verify claimed identity if provided
        if claimed_identity is not None:
            claimed_fp = claimed_identity.get("key_fingerprint")
            if claimed_fp and claimed_fp != identity.key_fingerprint:
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.IDENTITY_MISMATCH,
                    provenance=ProvenanceLevel.OBSERVED,
                    agent_id=agent_id,
                    description="Claimed key fingerprint does not match registered identity",
                    timestamp=timestamp,
                    metadata={
                        "claimed_fingerprint": claimed_fp,
                        "registered_fingerprint": identity.key_fingerprint,
                    },
                ))

        return signals

    def _verify_task(
        self,
        agent_id: str,
        declared_task: Optional[str],
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if declared_task is None:
            return signals

        if self._task_registry is None:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TASK_UNAUTHORIZED,
                provenance=ProvenanceLevel.UNKNOWN,
                agent_id=agent_id,
                description="No task registry available for verification",
                timestamp=timestamp,
                metadata={"declared_task": declared_task, "reason": "no_registry"},
            ))
            return signals

        try:
            task = self._task_registry.get(declared_task)
            if task is None:
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.TASK_UNAUTHORIZED,
                    provenance=ProvenanceLevel.OBSERVED,
                    agent_id=agent_id,
                    description=f"Declared task not found: {declared_task}",
                    timestamp=timestamp,
                    metadata={"declared_task": declared_task, "reason": "not_found"},
                ))
            elif task.agent_id != agent_id:
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.TASK_MISMATCH,
                    provenance=ProvenanceLevel.OBSERVED,
                    agent_id=agent_id,
                    description=f"Task {declared_task} belongs to agent {task.agent_id}, not {agent_id}",
                    timestamp=timestamp,
                    metadata={"declared_task": declared_task, "task_owner": task.agent_id},
                ))
            elif task.status != "active":
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.TASK_UNAUTHORIZED,
                    provenance=ProvenanceLevel.OBSERVED,
                    agent_id=agent_id,
                    description=f"Task {declared_task} status is {task.status}",
                    timestamp=timestamp,
                    metadata={"declared_task": declared_task, "task_status": task.status},
                ))
        except Exception as e:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TASK_UNAUTHORIZED,
                provenance=ProvenanceLevel.UNKNOWN,
                agent_id=agent_id,
                description=f"Task verification error: {e}",
                timestamp=timestamp,
                metadata={"declared_task": declared_task, "reason": "error"},
            ))

        return signals

    def _verify_capability(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if capability is None:
            return signals

        # Check capability agent matches
        if capability.agent_id != agent_id:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Capability agent_id {capability.agent_id} does not match {agent_id}",
                timestamp=timestamp,
                metadata={"capability_agent": capability.agent_id, "expected_agent": agent_id},
            ))

        # Check revocation
        if self._sdk.is_effectively_revoked(capability):
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_REVOKED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description="Capability is effectively revoked (self or ancestor)",
                timestamp=timestamp,
                metadata={"fingerprint": self._sdk.fingerprint(capability)},
            ))

        # Check expiration
        now = float(self._clock())
        if now >= capability.expires_at:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_EXPIRED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Capability expired at {capability.expires_at}",
                timestamp=timestamp,
                metadata={"expires_at": capability.expires_at, "now": now},
            ))

        # Check issuer trust
        if not self._sdk.is_issuer_trusted(capability.issuer):
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Capability issuer not trusted: {capability.issuer}",
                timestamp=timestamp,
                metadata={"issuer": capability.issuer},
            ))

        return signals

    def _verify_delegation_chain(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if capability is None:
            return signals

        fingerprint = self._sdk.fingerprint(capability)

        try:
            chain = self._sdk.delegation_lineage.chain(fingerprint)
        except Exception as e:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.DELEGATION_CHAIN_BROKEN,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Delegation chain error: {e}",
                timestamp=timestamp,
                metadata={"fingerprint": fingerprint, "error": str(e)},
            ))
            return signals

        # Check each ancestor for revocation
        for ancestor_fp in chain:
            if self._sdk.revocation.is_revoked(ancestor_fp):
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.DELEGATION_CHAIN_BROKEN,
                    provenance=ProvenanceLevel.DERIVED,
                    agent_id=agent_id,
                    description=f"Delegation ancestor revoked: {ancestor_fp}",
                    timestamp=timestamp,
                    metadata={"revoked_ancestor": ancestor_fp, "chain": list(chain)},
                ))

        # Check for cycles (lineage already prevents cycles on register, but verify)
        if len(set(chain)) != len(chain):
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.DELEGATION_CHAIN_BROKEN,
                provenance=ProvenanceLevel.DERIVED,
                agent_id=agent_id,
                description="Delegation chain contains a cycle",
                timestamp=timestamp,
                metadata={"chain": list(chain)},
            ))

        return signals

    def _verify_provenance(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if capability is None:
            return signals

        # This would integrate with firewall.provenance registry
        # For now, check basic capability provenance fields
        if capability.key_id is None:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.PROVENANCE_MISMATCH,
                provenance=ProvenanceLevel.INFERRED,
                agent_id=agent_id,
                description="Capability missing key_id provenance field",
                confidence=0.5,
                timestamp=timestamp,
                metadata={"fingerprint": self._sdk.fingerprint(capability)},
            ))

        return signals

    def _analyze_posture_and_behavior(
        self,
        agent_id: str,
        observed_action: Optional[dict[str, Any]],
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if self._posture_engine is None:
            return signals

        try:
            posture_state = self._posture_engine.state(agent_id)
            posture = posture_state.posture

            # Check for compromised/contained posture
            if posture in ("compromised", "contained", "high_risk"):
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.POSTURE_CONTRADICTION,
                    provenance=ProvenanceLevel.DERIVED,
                    agent_id=agent_id,
                    description=f"Agent posture is {posture}",
                    confidence=0.9,
                    timestamp=timestamp,
                    metadata={"posture": posture, "signals": posture_state.signals},
                ))

            # If we have observed action, check against posture
            if observed_action and posture in ("healthy", "degraded"):
                action_type = observed_action.get("type", "unknown")
                if action_type in ("privilege_escalation", "credential_access", "lateral_movement"):
                    signals.append(SecuritySignal(
                        discrepancy_type=DiscrepancyType.BEHAVIOR_ANOMALY,
                        provenance=ProvenanceLevel.INFERRED,
                        agent_id=agent_id,
                        description=f"Observed {action_type} action inconsistent with {posture} posture",
                        confidence=0.6,
                        timestamp=timestamp,
                        metadata={"action": observed_action, "posture": posture},
                    ))
        except Exception:
            pass

        return signals

    def _detect_evidence_contradictions(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecuritySignal]:
        signals = []

        if self._evidence_graph is None:
            return signals

        try:
            # Check for contradictory evidence in the graph
            events = self._evidence_graph.events()
            agent_events = [e for e in events if e.subject == agent_id]

            # Look for conflicting observed events
            seen: dict[str, dict] = {}
            for event in agent_events:
                key = f"{event.event_type}:{json.dumps(event.payload, sort_keys=True)}"
                if key in seen:
                    prev = seen[key]
                    if prev["kind"] == "observed" and event.kind == "observed":
                        # Check for contradictory payloads
                        if prev["payload"] != event.payload:
                            signals.append(SecuritySignal(
                                discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
                                provenance=ProvenanceLevel.DERIVED,
                                agent_id=agent_id,
                                description=f"Contradictory observed events for {event.event_type}",
                                confidence=0.8,
                                timestamp=timestamp,
                                metadata={
                                    "event_type": event.event_type,
                                    "event_id_1": prev["event_id"],
                                    "event_id_2": event.event_id,
                                    "payload_1": prev["payload"],
                                    "payload_2": event.payload,
                                },
                            ))
                else:
                    seen[key] = {"event_id": event.event_id, "kind": event.kind, "payload": event.payload}

            # Check for inference promoted to observed without promotion event
            for event in agent_events:
                if event.kind == "inference":
                    # Look for a later observed event with same content
                    for later_event in agent_events:
                        if (later_event.kind == "observed" and
                            later_event.timestamp > event.timestamp and
                            later_event.event_type == event.event_type):
                            # Check if this was an explicit promotion
                            promoted_from = later_event.payload.get("promoted_from")
                            if promoted_from != event.event_id:
                                signals.append(SecuritySignal(
                                    discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
                                    provenance=ProvenanceLevel.INFERRED,
                                    agent_id=agent_id,
                                    description=f"Inference may have been implicitly promoted to observed",
                                    confidence=0.5,
                                    timestamp=timestamp,
                                    metadata={
                                        "inference_event_id": event.event_id,
                                        "observed_event_id": later_event.event_id,
                                        "explicit_promotion": False,
                                    },
                                ))
        except Exception:
            pass

        return signals

    def get_profile(self, agent_id: str) -> Optional[AgentSecurityProfile]:
        """Get the cached security profile for an agent."""
        with self._lock:
            return self._profiles.get(agent_id)

    def get_all_profiles(self) -> dict[str, AgentSecurityProfile]:
        """Get all cached security profiles."""
        with self._lock:
            return dict(self._profiles)

    def clear_profile(self, agent_id: str) -> None:
        """Clear the cached profile for an agent."""
        with self._lock:
            self._profiles.pop(agent_id, None)

    def clear_all_profiles(self) -> None:
        """Clear all cached profiles."""
        with self._lock:
            self._profiles.clear()


def detect_contradiction(
    signal_a: SecuritySignal,
    signal_b: SecuritySignal,
) -> Optional[SecuritySignal]:
    """
    Detect if two security signals contradict each other.

    Returns a new signal describing the contradiction if found.
    """
    # Same agent, different discrepancy types that conflict
    if signal_a.agent_id != signal_b.agent_id:
        return None

    # Identity verified vs identity mismatch
    if (signal_a.discrepancy_type == DiscrepancyType.IDENTITY_UNVERIFIED and
        signal_b.discrepancy_type == DiscrepancyType.IDENTITY_MISMATCH):
        return SecuritySignal(
            discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
            provenance=ProvenanceLevel.DERIVED,
            agent_id=signal_a.agent_id,
            description="Identity both unverified and mismatched",
            confidence=0.9,
            timestamp=max(signal_a.timestamp, signal_b.timestamp),
            related_signals=(signal_a.discrepancy_type.value, signal_b.discrepancy_type.value),
        )

    # Capability revoked but action allowed
    if (signal_a.discrepancy_type == DiscrepancyType.CAPABILITY_REVOKED and
        signal_b.discrepancy_type == DiscrepancyType.BEHAVIOR_ANOMALY):
        return SecuritySignal(
            discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
            provenance=ProvenanceLevel.DERIVED,
            agent_id=signal_a.agent_id,
            description="Capability revoked but anomalous behavior observed",
            confidence=0.8,
            timestamp=max(signal_a.timestamp, signal_b.timestamp),
            related_signals=(signal_a.discrepancy_type.value, signal_b.discrepancy_type.value),
        )

    # Posture compromised but trust high
    if (signal_a.discrepancy_type == DiscrepancyType.POSTURE_CONTRADICTION and
        "compromised" in signal_a.metadata.get("posture", "")):
        # This would need trust score from profile
        pass

    return None