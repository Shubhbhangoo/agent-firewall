"""v2.2 Deception and Integrity Engine (firewall.deception).

Creates an integrity model that compares independent claims:
- identity = A
- task = T  
- capability = C
- provenance = P
- observed behavior = B
- posture = H

Detects meaningful contradictions explicitly. Does not resolve contradictions by guessing.
If the system cannot establish a required security fact: unknown remains unknown.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from firewall.adversarial import (
    AdversarialAgentDefense,
    AgentSecurityProfile,
    DiscrepancyType,
    ProvenanceLevel,
    SecuritySignal,
)
from firewall.evidence_graph import EvidenceGraph
from firewall.ident import IdentityRegistry
from firewall.posture import PostureEngine
from firewall.sdk import FirewallSDK
from firewall.task import TaskRegistry


class ClaimType(str, Enum):
    """Types of claims that can be made about an agent."""

    IDENTITY = "identity"
    TASK = "task"
    CAPABILITY = "capability"
    PROVENANCE = "provenance"
    BEHAVIOR = "behavior"
    POSTURE = "posture"
    DELEGATION = "delegation"
    AUTHORIZATION = "authorization"


class ClaimStatus(str, Enum):
    """Status of a claim after verification."""

    VERIFIED = "verified"           # Directly observed/confirmed
    CONTRADICTED = "contradicted"   # Another claim contradicts this
    UNVERIFIED = "unverified"       # Cannot be verified (missing evidence)
    UNKNOWN = "unknown"             # Required evidence unavailable


@dataclass(frozen=True)
class SecurityClaim:
    """A claim about an agent's security state."""

    claim_id: str
    claim_type: ClaimType
    agent_id: str
    content: dict[str, Any]
    provenance: ProvenanceLevel
    source: str  # What made this claim (e.g., "identity_registry", "agent_self_report", "evidence_graph")
    timestamp: float
    status: ClaimStatus = ClaimStatus.UNVERIFIED
    contradicts: tuple[str, ...] = ()  # claim_ids this contradicts
    contradicted_by: tuple[str, ...] = ()  # claim_ids that contradict this
    evidence_refs: tuple[str, ...] = ()  # Evidence event IDs supporting this claim

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type.value,
            "agent_id": self.agent_id,
            "content": dict(self.content),
            "provenance": self.provenance.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "status": self.status.value,
            "contradicts": list(self.contradicts),
            "contradicted_by": list(self.contradicted_by),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class Contradiction:
    """A detected contradiction between claims."""

    contradiction_id: str
    claim_a: SecurityClaim
    claim_b: SecurityClaim
    description: str
    severity: str  # low, medium, high, critical
    resolved: bool = False
    resolution: str = ""
    provenance: ProvenanceLevel = ProvenanceLevel.DERIVED
    detected_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "claim_a": self.claim_a.to_dict(),
            "claim_b": self.claim_b.to_dict(),
            "description": self.description,
            "severity": self.severity,
            "resolved": self.resolved,
            "resolution": self.resolution,
            "provenance": self.provenance.value,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True)
class IntegrityReport:
    """Complete integrity assessment for an agent."""

    agent_id: str
    claims: tuple[SecurityClaim, ...] = ()
    contradictions: tuple[Contradiction, ...] = ()
    verified_claims: int = 0
    contradicted_claims: int = 0
    unverified_claims: int = 0
    unknown_claims: int = 0
    overall_integrity: str = "unknown"  # high, medium, low, unknown
    assessed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "claims": [c.to_dict() for c in self.claims],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "verified_claims": self.verified_claims,
            "contradicted_claims": self.contradicted_claims,
            "unverified_claims": self.unverified_claims,
            "unknown_claims": self.unknown_claims,
            "overall_integrity": self.overall_integrity,
            "assessed_at": self.assessed_at,
        }


class DeceptionIntegrityEngine:
    """
    Compares independent security claims to detect contradictions.
    Never resolves contradictions by guessing - unknown remains unknown.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        identity_registry: Optional[IdentityRegistry] = None,
        task_registry: Optional[TaskRegistry] = None,
        posture_engine: Optional[PostureEngine] = None,
        adversarial_defense: Optional[AdversarialAgentDefense] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise TypeError("sdk must be a FirewallSDK")

        # Injected, not read off the SDK. ``FirewallSDK`` does not own
        # these registries -- it passes them to
        # ``ContinuousAuthorizationEngine`` without storing them -- so the
        # earlier ``hasattr(self._sdk, '_identity_registry')`` form was
        # always false and these three collectors could never produce a
        # claim. Injection also keeps this engine out of the SDK's
        # control-plane state, which CONTROL_PLANE_INTEGRITY requires.
        self._sdk = sdk
        self._identity_registry = identity_registry
        self._task_registry = task_registry
        self._posture_engine = posture_engine
        self._adversarial_defense = adversarial_defense
        self._evidence_graph = evidence_graph
        self._clock = clock or time.time
        self._lock = threading.RLock()

    def assess_integrity(
        self,
        agent_id: str,
        *,
        include_self_reported: bool = True,
        now: Optional[float] = None,
    ) -> IntegrityReport:
        """
        Assess the integrity of an agent by collecting and comparing
        all available claims about their security state.
        """
        timestamp = float(now) if now is not None else float(self._clock())
        claims: list[SecurityClaim] = []

        # 1. Collect identity claims
        claims.extend(self._collect_identity_claims(agent_id, timestamp))

        # 2. Collect task claims
        claims.extend(self._collect_task_claims(agent_id, timestamp))

        # 3. Collect capability claims
        claims.extend(self._collect_capability_claims(agent_id, timestamp))

        # 4. Collect provenance claims
        claims.extend(self._collect_provenance_claims(agent_id, timestamp))

        # 5. Collect behavior claims (from adversarial defense)
        claims.extend(self._collect_behavior_claims(agent_id, timestamp))

        # 6. Collect posture claims
        claims.extend(self._collect_posture_claims(agent_id, timestamp))

        # 7. Collect delegation claims
        claims.extend(self._collect_delegation_claims(agent_id, timestamp))

        # 8. Collect authorization claims
        claims.extend(self._collect_authorization_claims(agent_id, timestamp))

        # Detect contradictions
        contradictions = self._detect_contradictions(claims, timestamp)

        # Update claim statuses based on contradictions
        claims = self._update_claim_statuses(claims, contradictions)

        # Count statuses
        verified = sum(1 for c in claims if c.status == ClaimStatus.VERIFIED)
        contradicted = sum(1 for c in claims if c.status == ClaimStatus.CONTRADICTED)
        unverified = sum(1 for c in claims if c.status == ClaimStatus.UNVERIFIED)
        unknown = sum(1 for c in claims if c.status == ClaimStatus.UNKNOWN)

        # Determine overall integrity.
        #
        # The ladder is ordered worst-first and every rung is reachable
        # only by evidence. Two properties matter:
        #
        # * The no-claims case comes first and is ``unknown``, not
        #   ``high``. Every counter is zero when no subsystem could say
        #   anything about this agent, and the later rungs would
        #   otherwise fall through to ``high`` -- reporting an agent
        #   nothing is known about as the most trustworthy state
        #   available.
        # * ``high`` requires *every* collected claim to be VERIFIED. A
        #   single unknown or unverified claim caps the report at
        #   ``medium``. Unknown is not trusted, so a fact the platform
        #   could not establish must not be silently counted as one it
        #   did.
        if not claims:
            overall = "unknown"
        elif contradicted > 0:
            overall = "low"
        elif unknown > verified:
            overall = "unknown"
        elif unverified > 0 or unknown > 0:
            overall = "medium"
        else:
            overall = "high"

        return IntegrityReport(
            agent_id=agent_id,
            claims=tuple(claims),
            contradictions=tuple(contradictions),
            verified_claims=verified,
            contradicted_claims=contradicted,
            unverified_claims=unverified,
            unknown_claims=unknown,
            overall_integrity=overall,
            assessed_at=timestamp,
        )

    def _collect_identity_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        # Claim from identity registry (observed)
        if self._identity_registry is not None:
            registry = self._identity_registry
            identity = registry.get(agent_id)
            if identity:
                claims.append(SecurityClaim(
                    claim_id=f"identity_registry_{agent_id}",
                    claim_type=ClaimType.IDENTITY,
                    agent_id=agent_id,
                    content={
                        "status": identity.status,
                        "key_fingerprint": identity.key_fingerprint,
                        "identity_version": identity.identity_version,
                        "issuer": identity.issuer,
                    },
                    provenance=ProvenanceLevel.OBSERVED,
                    source="identity_registry",
                    timestamp=timestamp,
                    status=ClaimStatus.VERIFIED,
                ))

        # Self-reported identity (if available)
        # This would come from the agent's own attestation

        return claims

    def _collect_task_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        if self._task_registry is not None:
            registry = self._task_registry
            # No ``try``/``except Exception: pass`` here. The earlier
            # form swallowed an ``AttributeError`` from
            # ``task.parent_task_id`` -- ``Task`` has ``parent_task`` --
            # so this collector silently produced zero claims and the
            # report looked like "this agent has no tasks" rather than
            # "the collector is broken". A collector that cannot read
            # its source must fail loudly, not fabricate an empty
            # answer.
            for task in registry.tasks_for_agent(agent_id):
                claims.append(SecurityClaim(
                    claim_id=f"task_{task.task_id}",
                    claim_type=ClaimType.TASK,
                    agent_id=agent_id,
                    content={
                        "task_id": task.task_id,
                        "status": task.status,
                        "permissions": task.permissions,
                        "parent_task": task.parent_task,
                    },
                    provenance=ProvenanceLevel.OBSERVED,
                    source="task_registry",
                    timestamp=timestamp,
                    status=ClaimStatus.VERIFIED if task.status == "active" else ClaimStatus.UNVERIFIED,
                ))

        return claims

    def _collect_capability_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        registry = self._sdk.known_capabilities()
        for fp, cap in registry.items():
            if cap.agent_id == agent_id:
                is_revoked = self._sdk.is_effectively_revoked(cap)
                claims.append(SecurityClaim(
                    claim_id=f"capability_{fp[:16]}",
                    claim_type=ClaimType.CAPABILITY,
                    agent_id=agent_id,
                    content={
                        "capability": cap.capability,
                        "constraints": dict(cap.constraints or {}),
                        "issuer": cap.issuer,
                        "tool": cap.tool,
                        "expires_at": cap.expires_at,
                        "revoked": is_revoked,
                        "fingerprint": fp,
                    },
                    provenance=ProvenanceLevel.OBSERVED,
                    source="capability_registry",
                    timestamp=timestamp,
                    status=ClaimStatus.UNVERIFIED if is_revoked else ClaimStatus.VERIFIED,
                ))

        return claims

    def _collect_provenance_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        # Check capability provenance
        registry = self._sdk.known_capabilities()
        for fp, cap in registry.items():
            if cap.agent_id == agent_id and cap.key_id:
                claims.append(SecurityClaim(
                    claim_id=f"provenance_{fp[:16]}",
                    claim_type=ClaimType.PROVENANCE,
                    agent_id=agent_id,
                    content={
                        "capability_fingerprint": fp,
                        "key_id": cap.key_id,
                        "issuer": cap.issuer,
                        "nonce": cap.nonce,
                    },
                    provenance=ProvenanceLevel.OBSERVED,
                    source="capability_metadata",
                    timestamp=timestamp,
                    status=ClaimStatus.VERIFIED,
                ))

        return claims

    def _collect_behavior_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        if self._adversarial_defense:
            profile = self._adversarial_defense.get_profile(agent_id)
            if profile:
                # Convert signals to claims
                for signal in profile.signals:
                    claims.append(SecurityClaim(
                        claim_id=f"behavior_{signal.discrepancy_type.value}_{agent_id}",
                        claim_type=ClaimType.BEHAVIOR,
                        agent_id=agent_id,
                        content={
                            "discrepancy_type": signal.discrepancy_type.value,
                            "description": signal.description,
                            "severity": signal.severity if hasattr(signal, 'severity') else "medium",
                        },
                        provenance=signal.provenance,
                        source="adversarial_defense",
                        timestamp=signal.timestamp,
                        status=ClaimStatus.VERIFIED if signal.provenance == ProvenanceLevel.OBSERVED else ClaimStatus.UNVERIFIED,
                    ))

        return claims

    def _collect_posture_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        if self._posture_engine is not None:
            posture_state = self._posture_engine.state(agent_id)
            claims.append(SecurityClaim(
                claim_id=f"posture_{agent_id}",
                claim_type=ClaimType.POSTURE,
                agent_id=agent_id,
                content={
                    "posture": posture_state.posture,
                    # ``PostureState.signals`` is a tuple of dicts, not
                    # of ``PostureSignal`` objects, so the name is a key
                    # rather than an attribute.
                    "signals": [
                        signal.get("name", "")
                        for signal in posture_state.signals
                    ],
                },
                # Posture is computed from signals rather than read from
                # the world, so it is derived and never observed.
                provenance=ProvenanceLevel.DERIVED,
                source="posture_engine",
                timestamp=timestamp,
                # ``PostureEngine.state`` answers for every agent,
                # including one it has never seen, by returning the
                # ``"unknown"`` posture. That is the absence of a
                # posture, not a verified one, so it is recorded as an
                # UNKNOWN claim -- otherwise an agent nothing is known
                # about arrives here carrying one VERIFIED claim and
                # ``assess_integrity`` reads it as evidence of health.
                status=(
                    ClaimStatus.UNKNOWN
                    if posture_state.posture == "unknown"
                    else ClaimStatus.VERIFIED
                ),
            ))

        return claims

    def _collect_delegation_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        # Check delegation lineage for this agent's capabilities
        registry = self._sdk.known_capabilities()
        for fp, cap in registry.items():
            if cap.agent_id == agent_id:
                # ``chain`` raises only on a malformed fingerprint, and
                # these keys come from the registry, so there is nothing
                # here worth swallowing. The removed
                # ``except Exception: pass`` would have turned a broken
                # lineage walk into "this capability has no ancestors" --
                # the same shape as an un-delegated root, and the input
                # to the revoked-ancestor contradiction rule below.
                chain = self._sdk.delegation_lineage.chain(fp)
                if chain:
                    claims.append(SecurityClaim(
                        claim_id=f"delegation_{fp[:16]}",
                        claim_type=ClaimType.DELEGATION,
                        agent_id=agent_id,
                        content={
                            "capability_fingerprint": fp,
                            "delegation_depth": len(chain),
                            "ancestors": list(chain),
                        },
                        provenance=ProvenanceLevel.DERIVED,
                        source="delegation_lineage",
                        timestamp=timestamp,
                        status=ClaimStatus.VERIFIED,
                    ))

        return claims

    def _collect_authorization_claims(
        self,
        agent_id: str,
        timestamp: float,
    ) -> list[SecurityClaim]:
        claims = []

        # Check recent authorization decisions from evidence graph
        if self._evidence_graph is not None:
            events = self._evidence_graph.events()
            auth_events = [
                e for e in events
                if e.subject == agent_id and e.event_type == "authorization"
            ]
            for event in auth_events[-10:]:  # Last 10
                claims.append(SecurityClaim(
                    claim_id=f"auth_{event.event_id[:16]}",
                    claim_type=ClaimType.AUTHORIZATION,
                    agent_id=agent_id,
                    content={
                        "action": event.payload.get("action"),
                        "allowed": event.payload.get("allowed"),
                        "reason": event.payload.get("reason"),
                    },
                    provenance=ProvenanceLevel.OBSERVED,
                    source="evidence_graph",
                    timestamp=event.timestamp,
                    status=ClaimStatus.VERIFIED,
                    evidence_refs=(event.event_id,),
                ))

        return claims

    def _detect_contradictions(
        self,
        claims: list[SecurityClaim],
        timestamp: float,
    ) -> list[Contradiction]:
        """Cross-check independent claims and report disagreements.

        Four rules, each comparing two claims that came from
        *different* sources. A rule never resolves a disagreement: it
        records both sides and a severity, and leaves the claims'
        provenance untouched. Nothing here authorizes or de-authorizes
        anything -- a contradiction is evidence for
        ``FirewallSDK.authorize`` to be run under, not a verdict.

        The detected contradictions are:

        1. identity is not usable (any status other than ``"active"``)
           while the agent still holds a non-revoked capability
        2. a revoked capability alongside a recorded allow for it
        3. anomalous behaviour alongside a healthy or merely degraded
           posture
        4. a delegation chain with a revoked ancestor alongside a
           capability claimed valid

        Three further comparisons that the claim types invite -- task
        permissions against capability constraints, a capability's
        ``key_id`` against the evidence graph's signer, and a completed
        task against a still-live capability -- are deliberately absent
        rather than stubbed. None has a defined comparison in the
        current data model: task permissions and capability constraints
        use different vocabularies, provenance claims carry no signer to
        compare against, and a capability outliving a task is normal
        because capability lifetime is bounded by expiry and revocation
        rather than by task status. A rule that cannot decide is worse
        than no rule -- it yields either silence that reads as agreement
        or noise that buries the four real findings.
        """

        contradictions = []

        identity_claims = [c for c in claims if c.claim_type == ClaimType.IDENTITY]
        capability_claims = [c for c in claims if c.claim_type == ClaimType.CAPABILITY]

        live_capability_claims = [
            claim
            for claim in capability_claims
            if not claim.content.get("revoked")
        ]

        # Identity vs Capability. The registry is the only authority on
        # whether an agent's identity is usable; a capability that is
        # still live under a revoked or retired identity is authority
        # outliving the principal it was issued to.
        #
        # This deliberately does not compare ``content["agent_id"]``
        # against the identity's agent: capability claims are collected
        # per agent, so that comparison is vacuously satisfied and
        # reported a critical contradiction for every capability held.
        for id_claim in identity_claims:
            if id_claim.content.get("status") == "active":
                continue

            for cap_claim in live_capability_claims:
                contradictions.append(Contradiction(
                    contradiction_id=f"contra_{id_claim.claim_id}_{cap_claim.claim_id}",
                    claim_a=id_claim,
                    claim_b=cap_claim,
                    description=(
                        f"identity is {id_claim.content.get('status')!r} "
                        f"but capability "
                        f"{cap_claim.content.get('capability')!r} is not "
                        "revoked"
                    ),
                    severity="critical",
                    provenance=ProvenanceLevel.DERIVED,
                    detected_at=timestamp,
                ))

        # Capability vs Revocation: capability claimed valid but revoked
        for cap_claim in capability_claims:
            if cap_claim.content.get("revoked"):
                # Find any claim saying capability is valid
                for other in claims:
                    if other.claim_type == ClaimType.AUTHORIZATION:
                        if other.content.get("allowed") and other.content.get("action") == cap_claim.content.get("capability"):
                            contradictions.append(Contradiction(
                                contradiction_id=f"contra_{cap_claim.claim_id}_{other.claim_id}",
                                claim_a=cap_claim,
                                claim_b=other,
                                description=f"Capability {cap_claim.content.get('capability')} is revoked but authorization was allowed",
                                severity="high",
                                provenance=ProvenanceLevel.DERIVED,
                                detected_at=timestamp,
                            ))

        # Task vs Capability is not compared here -- see the docstring.

        # Behavior vs Posture: anomalous behavior but healthy posture
        behavior_claims = [c for c in claims if c.claim_type == ClaimType.BEHAVIOR]
        posture_claims = [c for c in claims if c.claim_type == ClaimType.POSTURE]

        for beh_claim in behavior_claims:
            for post_claim in posture_claims:
                if (beh_claim.content.get("discrepancy_type") in ("compromised_posture", "trust_collapse") and
                    post_claim.content.get("posture") in ("healthy", "degraded")):
                    contradictions.append(Contradiction(
                        contradiction_id=f"contra_{beh_claim.claim_id}_{post_claim.claim_id}",
                        claim_a=beh_claim,
                        claim_b=post_claim,
                        description=f"Behavior indicates {beh_claim.content.get('discrepancy_type')} but posture is {post_claim.content.get('posture')}",
                        severity="high",
                        provenance=ProvenanceLevel.DERIVED,
                        detected_at=timestamp,
                    ))

        # Delegation vs Capability: delegation chain broken but capability claimed valid
        delegation_claims = [c for c in claims if c.claim_type == ClaimType.DELEGATION]
        for del_claim in delegation_claims:
            ancestors = del_claim.content.get("ancestors", [])
            for ancestor_fp in ancestors:
                if self._sdk.revocation.is_revoked(ancestor_fp):
                    for cap_claim in capability_claims:
                        if cap_claim.content.get("fingerprint") == del_claim.content.get("capability_fingerprint"):
                            contradictions.append(Contradiction(
                                contradiction_id=f"contra_{del_claim.claim_id}_{cap_claim.claim_id}",
                                claim_a=del_claim,
                                claim_b=cap_claim,
                                description=f"Delegation chain has revoked ancestor {ancestor_fp} but capability claimed valid",
                                severity="high",
                                provenance=ProvenanceLevel.DERIVED,
                                detected_at=timestamp,
                            ))

        # Provenance vs Evidence is not compared here -- see the
        # docstring.

        return contradictions

    def _update_claim_statuses(
        self,
        claims: list[SecurityClaim],
        contradictions: list[Contradiction],
    ) -> list[SecurityClaim]:
        """Update claim statuses based on detected contradictions."""
        claim_map = {c.claim_id: c for c in claims}
        updated_claims = []

        for claim in claims:
            # Check if this claim is contradicted
            contradicted_by = tuple(
                c.claim_a.claim_id for c in contradictions
                if c.claim_b.claim_id == claim.claim_id
            )
            contradicts = tuple(
                c.claim_b.claim_id for c in contradictions
                if c.claim_a.claim_id == claim.claim_id
            )

            new_status = claim.status
            if contradicted_by:
                new_status = ClaimStatus.CONTRADICTED
            elif claim.status == ClaimStatus.UNVERIFIED and not contradicts:
                new_status = ClaimStatus.UNKNOWN

            updated_claims.append(SecurityClaim(
                claim_id=claim.claim_id,
                claim_type=claim.claim_type,
                agent_id=claim.agent_id,
                content=claim.content,
                provenance=claim.provenance,
                source=claim.source,
                timestamp=claim.timestamp,
                status=new_status,
                contradicts=contradicts,
                contradicted_by=contradicted_by,
                evidence_refs=claim.evidence_refs,
            ))

        return updated_claims

    def get_contradictions(self, agent_id: str) -> list[Contradiction]:
        """Get all contradictions for an agent."""
        report = self.assess_integrity(agent_id)
        return list(report.contradictions)

    def is_claim_verified(self, agent_id: str, claim_type: ClaimType) -> bool:
        """Check if a specific type of claim is verified for an agent."""
        report = self.assess_integrity(agent_id)
        for claim in report.claims:
            if claim.claim_type == claim_type and claim.status == ClaimStatus.VERIFIED:
                return True
        return False

    def get_unknown_facts(self, agent_id: str) -> list[str]:
        """Get list of security facts that are unknown for an agent."""
        report = self.assess_integrity(agent_id)
        unknown = []
        for claim in report.claims:
            if claim.status == ClaimStatus.UNKNOWN:
                unknown.append(f"{claim.claim_type.value}: {claim.content}")
        return unknown