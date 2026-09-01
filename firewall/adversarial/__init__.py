"""v2.2 Adversarial Agent Defense (firewall.adversarial).

Deterministic security signals about discrepancies between what an agent
claims and what the control plane actually records:

- claimed identity vs registered identity
- declared task vs authorized task
- presented capability vs its issuance, revocation and expiry state
- delegation lineage vs the capability's declared parent
- dependency provenance vs recorded component trust
- posture vs observed action
- evidence vs evidence

Contradictions are reported explicitly. They are never resolved by
guessing. When a required security fact cannot be established, this
module says so -- in :attr:`AgentSecurityProfile.gaps` and by leaving
:attr:`AgentSecurityProfile.identity_verified` as ``None`` -- rather than
reporting the reassuring answer.

Three-valued honesty
--------------------
``identity_verified`` is ``Optional[bool]``. ``True`` means a claim was
checked and matched; ``False`` means a check ran and failed; ``None``
means no check was possible. The previous version was a plain ``bool``
computed as "no ``IDENTITY_UNVERIFIED`` signal was raised", which made it
``True`` in two situations where nothing had been verified at all: when
the caller presented no claim to check, and -- worse -- when the registry
reported a *proven* impersonation, because that raises
``IDENTITY_MISMATCH``, not ``IDENTITY_UNVERIFIED``. A confirmed
fingerprint mismatch reported ``identity_verified=True``.

``SecuritySignal.confidence`` is ``Optional[float]``. It is present
exactly for the provenances where a numeric confidence means something
(``inferred``, ``simulated``) and ``None`` for ``observed``, ``derived``
and ``unknown``. A recorded fact does not carry a probability, and "no
registry was configured" is not a 0%-confidence claim about the agent --
it is not a claim about the agent at all. The old default of ``0.0`` on
factual signals was indistinguishable from "certainly false".

Failures are visible
--------------------
Every check that raises produces a ``DiscrepancyType.UNKNOWN`` signal at
``unknown`` provenance plus a gap naming the check. The previous version
wrapped six of these in ``except Exception: pass``, so a registry that
threw produced a profile that looked exactly like a clean one: no
signals, an empty capability list, ``trust_score`` 1.0 and
``risk_level`` ``"low"``.

Risk is triage, not authority
-----------------------------
:attr:`AgentSecurityProfile.trust_score` and
:attr:`AgentSecurityProfile.risk_level` order findings for a human or a
containment operator. They are **not** an authorization input.
``FirewallSDK.authorize`` does not read them, and nothing in this module
grants, widens or removes authority. A ``critical`` profile does not deny
a request that policy allows, and -- the direction that matters -- a
``low`` profile does not allow one that policy denies.

``risk_level`` defaults to ``"unknown"`` and can never be ``"low"`` while
any required fact is unestablished. The previous default was ``"low"``,
so an agent nothing was known about was reported as the least risky kind.

Provenance uses the single canonical vocabulary in
:mod:`firewall.platform`; see :data:`ProvenanceLevel`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.continuous_auth import is_narrower_than
from firewall.evidence_graph import EvidenceGraph, EvidenceKind
from firewall.ident import IdentityRegistry
from firewall.lifecycle import LifecycleEventType
from firewall.platform import Provenance, is_factual
from firewall.posture import PostureEngine
from firewall.provenance import ProvenanceRegistry
from firewall.sdk import FirewallSDK
from firewall.task import TaskRegistry


class DiscrepancyType(str, Enum):
    """Types of security discrepancy this module detects.

    Every member has an emitter. ``test_every_discrepancy_type_is_emitted``
    fails the suite if one stops having a scenario that produces it,
    because an enum member nothing raises is a documented detection that
    does not happen.

    ==========================  ================================================
    member                      raised when
    ==========================  ================================================
    ``IDENTITY_MISMATCH``       registered identity is not active, a claimed
                                key fingerprint disagrees with the registered
                                one, or a presented attestation fails to verify
    ``IDENTITY_UNVERIFIED``     no identity registry, or the agent has no
                                registry record
    ``TASK_MISMATCH``           the declared task belongs to another agent
    ``TASK_UNAUTHORIZED``       the declared task is missing, not active, or
                                unverifiable for want of a task registry
    ``CAPABILITY_MISMATCH``     the capability names another agent, or its
                                issuer is not trusted
    ``CAPABILITY_REVOKED``      the capability or an ancestor is revoked
    ``CAPABILITY_EXPIRED``      ``expires_at`` has passed
    ``DELEGATION_MISMATCH``     the declared ``parent_fingerprint`` disagrees
                                with the recorded lineage parent
    ``DELEGATION_CHAIN_BROKEN`` the lineage cannot be walked, an ancestor is
                                revoked, or the chain repeats a fingerprint
    ``DELEGATION_WIDENING``     the capability is not an attenuation of its
                                recorded parent
    ``PROVENANCE_MISMATCH``     the capability names a signing key this control
                                plane has no record of, or a retired one
    ``PROVENANCE_UNTRUSTED``    a component the agent depends on is revoked,
                                suspicious, or unknown
    ``POSTURE_CONTRADICTION``   posture is suspicious, high_risk, compromised
                                or contained
    ``BEHAVIOR_ANOMALY``        a sensitive action observed under a posture
                                that does not account for it
    ``EVIDENCE_CONTRADICTION``  two observed events of one type disagree, or an
                                inference reappears as an observation without a
                                declared promotion
    ``REPLAY_DETECTED``         the lifecycle recorder holds a replay event for
                                this agent
    ``TIME_TRAVEL``             a capability is issued in the future, or issued
                                after it expires
    ``UNKNOWN``                 a check raised; the fact it would have
                                established is unestablished
    ==========================  ================================================
    """

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


#: The provenance vocabulary, under this package's historical name.
#:
#: This was a second ``str``/``Enum`` declaring the same five members as
#: :class:`firewall.platform.Provenance`. Because both subclassed
#: ``str``, the duplicate compared equal member-by-member to the
#: canonical one, so nothing broke visibly -- which is exactly the
#: problem. Two definitions can drift apart while continuing to appear to
#: agree, and there is then no single answer to "is this fact observed?".
#: PROVENANCE_INTEGRITY in :mod:`firewall.invariants` reports any such
#: duplicate.
#:
#: It is an alias rather than a deletion because ``firewall.correlation``
#: and ``firewall.deception`` import ``ProvenanceLevel`` from here, and
#: the point of the change is to collapse the two definitions onto one
#: object, not to rename anything. ``ProvenanceLevel is Provenance`` now
#: holds, so the algebra in :mod:`firewall.platform` -- ``combine``,
#: ``coerce``, ``is_factual`` -- applies to these members directly.
ProvenanceLevel = Provenance


#: Triage levels. ``low < medium < high < critical`` orders severity;
#: ``unknown`` sits outside that order and means the risk was not
#: established. It is the default because an agent no check succeeded
#: against is not a low-risk agent.
RISK_LEVELS = ("low", "medium", "high", "critical", "unknown")


#: Postures that are themselves a finding. ``suspicious`` was absent from
#: the previous list, so the one posture that exists to say "something is
#: off" produced no signal.
_ADVERSE_POSTURES = ("suspicious", "high_risk", "compromised", "contained")

#: Postures under which the sensitive actions below are unaccounted for.
_NOMINAL_POSTURES = ("healthy", "degraded", "recovering")

#: Action types that warrant a signal when the posture does not explain
#: them. These are names a caller supplies; the signal is ``inferred``
#: because the mapping from an action label to intent is a judgement.
_SENSITIVE_ACTIONS = (
    "privilege_escalation",
    "credential_access",
    "lateral_movement",
)


@dataclass(frozen=True)
class SecuritySignal:
    """One deterministic security signal with explicit provenance.

    ``provenance`` and ``confidence`` are the two halves of
    :class:`firewall.platform.Confidence`, flattened so a signal
    serializes as one object rather than a nested one. The algebra --
    ``combine``, ``is_factual`` -- comes from :mod:`firewall.platform`;
    this is not a second copy of it.

    ``confidence`` is required exactly for ``inferred`` and ``simulated``
    and forbidden otherwise. A recorded fact has no probability attached,
    and ``unknown`` provenance means no claim is being made about the
    agent at all -- attaching ``0.0`` to either, as the previous default
    did, reads as "certainly false".
    """

    discrepancy_type: DiscrepancyType
    provenance: ProvenanceLevel
    agent_id: str
    description: str
    evidence: tuple[dict[str, Any], ...] = ()
    confidence: Optional[float] = None
    timestamp: float = 0.0
    related_signals: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        level = Provenance(self.provenance)
        object.__setattr__(self, "provenance", level)

        scored = level in (Provenance.INFERRED, Provenance.SIMULATED)

        if scored:
            if self.confidence is None:
                raise ValueError(
                    f"{level.value} signal must state a confidence"
                )
            if isinstance(self.confidence, bool) or not isinstance(
                self.confidence, (int, float)
            ):
                raise TypeError("confidence must be a number")
            if not 0.0 <= float(self.confidence) <= 1.0:
                raise ValueError("confidence must be within [0.0, 1.0]")
            object.__setattr__(self, "confidence", float(self.confidence))
        elif self.confidence is not None:
            raise ValueError(
                f"{level.value} signal must not state a confidence: a "
                "fact carries no probability and an unestablished fact "
                "carries no claim"
            )

    @property
    def factual(self) -> bool:
        """True only for ``observed`` and ``derived``."""

        return is_factual(self.provenance)

    def to_dict(self) -> dict[str, Any]:
        return {
            "discrepancy_type": self.discrepancy_type.value,
            "provenance": self.provenance.value,
            "agent_id": self.agent_id,
            "description": self.description,
            "evidence": [dict(e) for e in self.evidence],
            "confidence": self.confidence,
            "factual": self.factual,
            "timestamp": self.timestamp,
            "related_signals": list(self.related_signals),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AgentSecurityProfile:
    """Aggregated security findings for one agent.

    ``identity_verified`` is three-valued: see the module docstring.

    ``gaps`` names every check that could not be performed, in words. A
    profile with gaps is never ``risk_level="low"``.

    ``trust_score`` and ``risk_level`` are triage. Nothing authorizes on
    them; ``FirewallSDK.authorize`` does not read this type.
    """

    agent_id: str
    signals: tuple[SecuritySignal, ...] = ()
    identity_verified: Optional[bool] = None
    identity_status: str = "unknown"
    active_tasks: tuple[str, ...] = ()
    live_capabilities: tuple[str, ...] = ()
    delegation_depth: int = 0
    posture: str = "unknown"
    trust_score: float = 1.0
    risk_level: str = "unknown"
    gaps: tuple[str, ...] = ()
    last_evaluated: float = 0.0

    def __post_init__(self) -> None:
        if self.risk_level not in RISK_LEVELS:
            raise ValueError(f"unknown risk level: {self.risk_level!r}")
        if not 0.0 <= float(self.trust_score) <= 1.0:
            raise ValueError("trust_score must be within [0.0, 1.0]")

    @property
    def factual_signals(self) -> tuple[SecuritySignal, ...]:
        """Signals backed by ``observed`` or ``derived`` provenance."""

        return tuple(s for s in self.signals if s.factual)

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
            "gaps": list(self.gaps),
            "last_evaluated": self.last_evaluated,
        }


def assess_risk(
    signals: tuple[SecuritySignal, ...] | list[SecuritySignal],
    *,
    gaps: tuple[str, ...] | list[str] = (),
) -> tuple[float, str]:
    """Derive ``(trust_score, risk_level)`` from signals and gaps.

    A pure function so the derivation can be tested without building a
    control plane, and so there is one place where the ordering rules
    live.

    Two rules the previous inline version broke:

    *Unknown is not trusted.* It weighted three discrepancy types and
    ignored the other fifteen, so an unknown identity, an untrusted
    issuer, an expired capability, a revoked delegation ancestor and a
    task belonging to somebody else all left ``trust_score`` at 1.0 and
    ``risk_level`` at ``"low"``. ``DELEGATION_WIDENING`` was one of the
    three it did weight, and nothing emitted it.

    *A gap is not a pass.* ``risk_level`` is never ``"low"`` while any
    check failed to run. ``"low"`` requires no findings and no gaps: every
    check ran and every one of them passed.
    """

    score = 1.0
    factual_severe = False
    factual_any = False
    unknown_any = bool(gaps)
    established_any = False

    for signal in signals:
        weight = _SIGNAL_WEIGHTS.get(signal.discrepancy_type, 0.9)

        if signal.provenance is Provenance.UNKNOWN:
            # Nothing was established. Do not treat it as a finding
            # against the agent, and do not treat it as a pass either.
            unknown_any = True
            score *= 0.9
            continue

        established_any = True

        if signal.factual:
            factual_any = True
            if signal.discrepancy_type in _SEVERE:
                factual_severe = True
            score *= weight
        else:
            # An inference scales by its own stated confidence: a 0.5
            # guess must not move the score as far as a certainty.
            confidence = signal.confidence if signal.confidence is not None else 0.0
            score *= 1.0 - (1.0 - weight) * confidence

    score = max(0.0, min(1.0, score))

    if factual_severe:
        # Every weight in ``_SEVERE`` is at most 0.4, so the score is
        # always below 0.5 once one of them lands. A score condition here
        # could not vary, and a conditional that cannot vary reads as
        # nuance that does not exist.
        level = "critical"
    elif factual_any:
        level = "high" if score < 0.5 else "medium"
    elif established_any:
        # A finding that is not a fact -- an inference, or something
        # derived about state that was itself unproven. Inference is not
        # observation, so it does not reach the factual levels; it is
        # still a finding, so it does not read as a pass.
        level = "medium"
    elif unknown_any:
        # Nothing was established and something was not checked. The risk
        # is genuinely unknown, which is not the same as low.
        level = "unknown"
    else:
        level = "low"

    return score, level


#: How far one factual finding moves ``trust_score``. Multiplicative, so
#: independent findings compound rather than saturating at the worst one.
_SIGNAL_WEIGHTS: dict[DiscrepancyType, float] = {
    DiscrepancyType.IDENTITY_MISMATCH: 0.2,
    DiscrepancyType.IDENTITY_UNVERIFIED: 0.5,
    DiscrepancyType.TASK_MISMATCH: 0.4,
    DiscrepancyType.TASK_UNAUTHORIZED: 0.6,
    DiscrepancyType.CAPABILITY_MISMATCH: 0.3,
    DiscrepancyType.CAPABILITY_REVOKED: 0.2,
    DiscrepancyType.CAPABILITY_EXPIRED: 0.5,
    DiscrepancyType.DELEGATION_MISMATCH: 0.3,
    DiscrepancyType.DELEGATION_CHAIN_BROKEN: 0.3,
    DiscrepancyType.DELEGATION_WIDENING: 0.2,
    DiscrepancyType.PROVENANCE_MISMATCH: 0.5,
    DiscrepancyType.PROVENANCE_UNTRUSTED: 0.4,
    DiscrepancyType.POSTURE_CONTRADICTION: 0.4,
    DiscrepancyType.BEHAVIOR_ANOMALY: 0.6,
    DiscrepancyType.EVIDENCE_CONTRADICTION: 0.4,
    DiscrepancyType.REPLAY_DETECTED: 0.2,
    DiscrepancyType.TIME_TRAVEL: 0.2,
    DiscrepancyType.UNKNOWN: 0.9,
}

#: Findings that are, on their own, enough to escalate past ``medium``.
#: Each names a control that has demonstrably been contradicted rather
#: than merely a state worth watching.
_SEVERE = frozenset({
    DiscrepancyType.IDENTITY_MISMATCH,
    DiscrepancyType.CAPABILITY_REVOKED,
    DiscrepancyType.DELEGATION_WIDENING,
    DiscrepancyType.DELEGATION_MISMATCH,
    DiscrepancyType.REPLAY_DETECTED,
    DiscrepancyType.TIME_TRAVEL,
    DiscrepancyType.PROVENANCE_UNTRUSTED,
})


class AdversarialAgentDefense:
    """Evaluates an agent for security discrepancies.

    Every subsystem is optional. What is *not* optional is saying which
    ones were absent: a missing registry becomes a gap and, where the
    absence leaves a security question open, a signal at ``unknown``
    provenance. The evaluator never reports a clean profile because it
    had nothing to check with.
    """

    def __init__(
        self,
        sdk: FirewallSDK,
        *,
        identity_registry: Optional[IdentityRegistry] = None,
        task_registry: Optional[TaskRegistry] = None,
        posture_engine: Optional[PostureEngine] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
        provenance_registry: Optional[ProvenanceRegistry] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise TypeError("sdk must be a FirewallSDK")

        self._sdk = sdk
        self._identity_registry = identity_registry
        self._task_registry = task_registry
        self._posture_engine = posture_engine
        self._evidence_graph = evidence_graph
        self._provenance_registry = provenance_registry
        self._clock = clock or time.time
        self._lock = threading.RLock()

        self._profiles: dict[str, AgentSecurityProfile] = {}

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

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
        """Evaluate one agent and cache the resulting profile.

        Inputs are optional. An input that is not supplied is not a pass:
        the checks that needed it are recorded as gaps.
        """

        timestamp = float(now) if now is not None else float(self._clock())
        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        identity_verified: Optional[bool] = None
        try:
            id_signals, id_gaps, identity_verified = self._verify_identity(
                agent_id, claimed_identity, timestamp
            )
            signals.extend(id_signals)
            gaps.extend(id_gaps)
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            unknown_signals, unknown_gaps = self._unknown(
                agent_id, timestamp, "identity verification", exc
            )
            signals.extend(unknown_signals)
            gaps.extend(unknown_gaps)
            identity_verified = None

        checks: tuple[tuple[str, Callable[[], tuple[list, list]]], ...] = (
            ("task verification", lambda: self._verify_task(
                agent_id, declared_task, timestamp)),
            ("capability verification", lambda: self._verify_capability(
                agent_id, presented_capability, timestamp)),
            ("delegation verification", lambda: self._verify_delegation(
                agent_id, presented_capability, timestamp)),
            ("signing-key provenance", lambda: self._verify_signing_key(
                agent_id, presented_capability, timestamp)),
            ("component provenance", lambda: self._verify_components(
                agent_id, timestamp)),
            ("posture analysis", lambda: self._analyze_posture(
                agent_id, observed_action, timestamp)),
            ("evidence contradiction detection",
             lambda: self._detect_evidence_contradictions(agent_id, timestamp)),
            ("replay detection", lambda: self._detect_replay(
                agent_id, timestamp)),
        )

        for name, check in checks:
            try:
                check_signals, check_gaps = check()
            except Exception as exc:  # noqa: BLE001 - reported, never swallowed
                check_signals, check_gaps = self._unknown(
                    agent_id, timestamp, name, exc
                )
            signals.extend(check_signals)
            gaps.extend(check_gaps)

        facts, fact_gaps = self._collect_facts(
            agent_id, presented_capability, timestamp
        )
        gaps.extend(fact_gaps)

        trust_score, risk_level = assess_risk(tuple(signals), gaps=tuple(gaps))

        profile = AgentSecurityProfile(
            agent_id=agent_id,
            signals=tuple(signals),
            identity_verified=identity_verified,
            identity_status=facts["identity_status"],
            active_tasks=facts["active_tasks"],
            live_capabilities=facts["live_capabilities"],
            delegation_depth=facts["delegation_depth"],
            posture=facts["posture"],
            trust_score=trust_score,
            risk_level=risk_level,
            gaps=tuple(gaps),
            last_evaluated=timestamp,
        )

        with self._lock:
            self._profiles[agent_id] = profile

        return profile

    def _unknown(
        self,
        agent_id: str,
        timestamp: float,
        check_name: str,
        exc: BaseException,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Turn a failed check into a visible unknown.

        The previous version used ``except Exception: pass`` in six
        places. A profile produced that way was byte-identical to one
        from a clean evaluation.
        """

        return (
            [SecuritySignal(
                discrepancy_type=DiscrepancyType.UNKNOWN,
                provenance=ProvenanceLevel.UNKNOWN,
                agent_id=agent_id,
                description=f"{check_name} could not be completed: {exc}",
                timestamp=timestamp,
                metadata={
                    "check": check_name,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )],
            [
                f"{check_name} raised {type(exc).__name__}: the facts it "
                "would have established are unknown"
            ],
        )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def _verify_identity(
        self,
        agent_id: str,
        claimed_identity: Optional[dict[str, Any]],
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str], Optional[bool]]:
        """Check a claimed identity against the registry.

        The third element is the tri-state for
        :attr:`AgentSecurityProfile.identity_verified`. ``True`` requires
        an actual check to have passed. A registry record merely
        *existing* is not verification -- it says a name is known, not
        that the party presenting it holds the key -- so an evaluation
        with no ``claimed_identity`` returns ``None``, not ``True``.

        ``claimed_identity`` may carry ``key_fingerprint`` and/or
        ``attestation``. An attestation is a base64 signature over the
        registered identity's canonical payload, as produced by
        ``IdentityRegistry.self_attestation``; verifying it is the only
        cryptographic proof of possession available here, and it is what
        makes ``True`` mean something.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if self._identity_registry is None:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.IDENTITY_UNVERIFIED,
                provenance=ProvenanceLevel.UNKNOWN,
                agent_id=agent_id,
                description="No identity registry available for verification",
                timestamp=timestamp,
                metadata={"reason": "no_registry"},
            ))
            gaps.append(
                "no identity registry was configured: whether this agent is "
                "who it claims to be is unknown"
            )
            return signals, gaps, None

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
            return signals, gaps, False

        verified: Optional[bool] = None

        if identity.status != "active":
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.IDENTITY_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    f"Identity status is {identity.status}, not active"
                ),
                timestamp=timestamp,
                metadata={"status": identity.status, "reason": "not_active"},
            ))
            verified = False

        if claimed_identity is None:
            if verified is None:
                gaps.append(
                    f"a registry record exists for {agent_id} and is active, "
                    "but no claim was presented to check against it: a known "
                    "name is not a verified identity"
                )
            return signals, gaps, verified

        claimed_fp = claimed_identity.get("key_fingerprint")
        attestation = claimed_identity.get("attestation")
        checked = False
        proved = False

        if claimed_fp is not None:
            checked = True
            if claimed_fp != identity.key_fingerprint:
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.IDENTITY_MISMATCH,
                    provenance=ProvenanceLevel.OBSERVED,
                    agent_id=agent_id,
                    description=(
                        "Claimed key fingerprint does not match registered "
                        "identity"
                    ),
                    timestamp=timestamp,
                    metadata={
                        "claimed_fingerprint": claimed_fp,
                        "registered_fingerprint": identity.key_fingerprint,
                        "reason": "fingerprint_mismatch",
                    },
                ))
                verified = False

        if attestation is not None:
            checked = True
            if identity.status != "active":
                # ``IdentityRegistry.verify`` refuses revoked and retired
                # identities by design, so it would return False for a
                # genuine attestation here. Reporting that as
                # "attestation does not verify" would brand authentic
                # evidence as forged; the honest answer is that
                # authenticity can no longer be re-established.
                gaps.append(
                    f"{agent_id} presented an attestation that cannot be "
                    f"checked because the identity is {identity.status}: the "
                    "registry refuses non-active keys, so a failure here "
                    "would not be proof of forgery"
                )
            else:
                accepted = self._identity_registry.verify(
                    agent_id, identity.payload(), str(attestation)
                )
                if not accepted:
                    signals.append(SecuritySignal(
                        discrepancy_type=DiscrepancyType.IDENTITY_MISMATCH,
                        provenance=ProvenanceLevel.OBSERVED,
                        agent_id=agent_id,
                        description=(
                            "Presented attestation does not verify against "
                            "the registered identity key"
                        ),
                        timestamp=timestamp,
                        metadata={"reason": "attestation_failed"},
                    ))
                    verified = False
                else:
                    proved = True
        else:
            gaps.append(
                f"{agent_id} presented no attestation: a matching fingerprint "
                "shows the claimant knows the public key, which is public, "
                "not that it holds the private one"
            )

        if not checked:
            gaps.append(
                f"{agent_id} presented a claim carrying neither "
                "key_fingerprint nor attestation: nothing in it was checkable"
            )
            return signals, gaps, verified

        # ``True`` requires proof of possession. A fingerprint match alone
        # leaves this ``None``: the registered fingerprint is public, so
        # reciting it is not evidence of holding the private key. The gap
        # above already says so; returning ``True`` here would say the
        # opposite in the field the callers actually read.
        if verified is None and proved:
            verified = True

        return signals, gaps, verified

    # ------------------------------------------------------------------
    # Task
    # ------------------------------------------------------------------

    def _verify_task(
        self,
        agent_id: str,
        declared_task: Optional[str],
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if declared_task is None:
            gaps.append(
                "no task was declared: whether this agent is acting inside "
                "an authorized task is unknown"
            )
            return signals, gaps

        if self._task_registry is None:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TASK_UNAUTHORIZED,
                provenance=ProvenanceLevel.UNKNOWN,
                agent_id=agent_id,
                description="No task registry available for verification",
                timestamp=timestamp,
                metadata={"declared_task": declared_task, "reason": "no_registry"},
            ))
            gaps.append(
                f"no task registry was configured: task {declared_task} "
                "could not be checked"
            )
            return signals, gaps

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
            return signals, gaps

        if task.agent_id != agent_id:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TASK_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    f"Task {declared_task} belongs to agent {task.agent_id}, "
                    f"not {agent_id}"
                ),
                timestamp=timestamp,
                metadata={
                    "declared_task": declared_task,
                    "task_owner": task.agent_id,
                },
            ))

        # Not ``elif``: a task that belongs to somebody else *and* is
        # closed is two findings. The previous chain reported only the
        # first, so an agent claiming another agent's finished task
        # looked like a single ownership problem.
        if task.status != "active":
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TASK_UNAUTHORIZED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Task {declared_task} status is {task.status}",
                timestamp=timestamp,
                metadata={
                    "declared_task": declared_task,
                    "task_status": task.status,
                },
            ))

        return signals, gaps

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------

    def _verify_capability(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Check a presented capability against issuance and lifecycle state.

        Expiry and time-travel are judged against ``timestamp``, the same
        clock reading the rest of the evaluation uses. The previous
        version called ``self._clock()`` again here, so an evaluation
        pinned with ``now=`` still compared expiry against wall-clock
        time and was not reproducible.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if capability is None:
            gaps.append(
                "no capability was presented: nothing is known about what "
                "authority this agent is exercising"
            )
            return signals, gaps

        if capability.agent_id != agent_id:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    f"Capability agent_id {capability.agent_id} does not "
                    f"match {agent_id}"
                ),
                timestamp=timestamp,
                metadata={
                    "capability_agent": capability.agent_id,
                    "expected_agent": agent_id,
                },
            ))

        if self._sdk.is_effectively_revoked(capability):
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_REVOKED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description="Capability is effectively revoked (self or ancestor)",
                timestamp=timestamp,
                metadata={"fingerprint": self._sdk.fingerprint(capability)},
            ))

        if timestamp >= capability.expires_at:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_EXPIRED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Capability expired at {capability.expires_at}",
                timestamp=timestamp,
                metadata={
                    "expires_at": capability.expires_at,
                    "now": timestamp,
                },
            ))

        if not self._sdk.is_issuer_trusted(capability.issuer):
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.CAPABILITY_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    f"Capability issuer not trusted: {capability.issuer}"
                ),
                timestamp=timestamp,
                metadata={"issuer": capability.issuer, "reason": "untrusted_issuer"},
            ))

        if capability.issued_at > capability.expires_at:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TIME_TRAVEL,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    "Capability is issued after it expires: "
                    f"{capability.issued_at} > {capability.expires_at}"
                ),
                timestamp=timestamp,
                metadata={
                    "issued_at": capability.issued_at,
                    "expires_at": capability.expires_at,
                    "reason": "issued_after_expiry",
                },
            ))

        if capability.issued_at > timestamp:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.TIME_TRAVEL,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    f"Capability is issued in the future: "
                    f"{capability.issued_at} > {timestamp}"
                ),
                timestamp=timestamp,
                metadata={
                    "issued_at": capability.issued_at,
                    "now": timestamp,
                    "reason": "issued_in_future",
                },
            ))

        return signals, gaps

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------

    def _verify_delegation(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Check the lineage, the declared parent, and attenuation.

        Widening is judged with
        :func:`firewall.continuous_auth.is_narrower_than` -- the predicate
        the DELEGATION_MONOTONICITY invariant is stated in -- rather than a
        second comparison written here. Two implementations of "is this
        narrower?" would be two answers to one security question.

        Not :func:`firewall.attenuation.can_attenuate`: that one requires
        ``child.agent_id == parent.agent_id``, because attenuation is one
        holder narrowing its own authority. Delegation hands authority to
        a *different* holder -- ``delegate_capability`` refuses a delegatee
        equal to the delegator -- so judging a delegation with it would
        report every legitimate cross-agent delegation as widening.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if capability is None:
            return signals, gaps

        fingerprint = self._sdk.fingerprint(capability)
        lineage = self._sdk.delegation_lineage

        try:
            chain = lineage.chain(fingerprint)
        except Exception as exc:  # noqa: BLE001 - reported as a finding
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.DELEGATION_CHAIN_BROKEN,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=f"Delegation chain error: {exc}",
                timestamp=timestamp,
                metadata={"fingerprint": fingerprint, "error": str(exc)},
            ))
            return signals, gaps

        for ancestor_fp in chain:
            if self._sdk.revocation.is_revoked(ancestor_fp):
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.DELEGATION_CHAIN_BROKEN,
                    provenance=ProvenanceLevel.DERIVED,
                    agent_id=agent_id,
                    description=f"Delegation ancestor revoked: {ancestor_fp}",
                    timestamp=timestamp,
                    metadata={
                        "revoked_ancestor": ancestor_fp,
                        "chain": list(chain),
                    },
                ))

        if len(set(chain)) != len(chain):
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.DELEGATION_CHAIN_BROKEN,
                provenance=ProvenanceLevel.DERIVED,
                agent_id=agent_id,
                description="Delegation chain contains a cycle",
                timestamp=timestamp,
                metadata={"chain": list(chain)},
            ))

        recorded_parent = lineage.parent_of(fingerprint)
        declared_parent = capability.parent_fingerprint

        if declared_parent != recorded_parent:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.DELEGATION_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    "Capability declares parent "
                    f"{declared_parent or 'none'} but the recorded lineage "
                    f"parent is {recorded_parent or 'none'}"
                ),
                timestamp=timestamp,
                metadata={
                    "fingerprint": fingerprint,
                    "declared_parent": declared_parent,
                    "recorded_parent": recorded_parent,
                },
            ))

        if recorded_parent is None:
            return signals, gaps

        parent = self._sdk.known_capabilities().get(recorded_parent)

        if parent is None:
            gaps.append(
                f"lineage records parent {recorded_parent} for {fingerprint} "
                "but this SDK holds no capability with that fingerprint: "
                "whether the child is an attenuation of it cannot be checked"
            )
            return signals, gaps

        narrowing = is_narrower_than(parent, capability)

        if not narrowing.monotonic:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.DELEGATION_WIDENING,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    "Capability is not narrower than its recorded parent: "
                    f"{narrowing.reason}"
                ),
                timestamp=timestamp,
                metadata={
                    "fingerprint": fingerprint,
                    "parent_fingerprint": recorded_parent,
                    "reason": narrowing.reason,
                    "parent_constraints": dict(parent.constraints),
                    "child_constraints": dict(capability.constraints),
                },
            ))

        return signals, gaps

    # ------------------------------------------------------------------
    # Provenance: signing key, then components
    # ------------------------------------------------------------------

    def _verify_signing_key(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Trace a capability's signing key to this control plane's key store.

        The previous version of this check tested ``key_id is None`` and
        reported it as a ``PROVENANCE_MISMATCH`` at ``inferred``
        provenance with a hardcoded confidence of 0.5. ``key_id`` is
        ``Optional`` by design in :class:`~firewall.capability.Capability`,
        so that fired on legitimately-issued capabilities and asserted a
        probability nothing had computed. Absence is now a gap; a
        ``key_id`` the key store does not know is the finding.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if capability is None:
            return signals, gaps

        key_id = capability.key_id

        if key_id is None:
            gaps.append(
                "capability declares no key_id: its signing key cannot be "
                "traced to an entry in this control plane's key store"
            )
            return signals, gaps

        known = tuple(self._sdk.keys.key_ids())

        if key_id not in known:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.PROVENANCE_MISMATCH,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    f"Capability names signing key {key_id}, which this "
                    "control plane has no record of"
                ),
                timestamp=timestamp,
                metadata={"key_id": key_id, "reason": "unknown_key"},
            ))
            return signals, gaps

        if not self._sdk.keys.is_active(key_id):
            # Retirement blocks *issuance* -- ``FirewallSDK.issue`` raises
            # "key is retired" -- but ``authorize`` does not consult key
            # activity, so a capability signed before retirement is still
            # authorizable and is not a discrepancy. Nor is retirement
            # evidence that this capability was signed afterwards: the key
            # store records no retirement timestamp, so "signed after
            # retirement" is unprovable here.
            gaps.append(
                f"capability was signed with key {key_id}, which is now "
                "retired: whether it was signed before or after retirement "
                "cannot be determined because no retirement time is recorded"
            )

        return signals, gaps

    def _verify_components(
        self,
        agent_id: str,
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Check the trust state of components the agent depends on.

        This is what the previous ``_verify_provenance`` said it would do
        -- its body carried the comment "This would integrate with
        firewall.provenance registry / For now, ..." -- and now does.
        ``ProvenanceRegistry.trust_state`` is the authority on component
        trust, including transitive dependencies; this method reports what
        it says rather than recomputing it.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if self._provenance_registry is None:
            gaps.append(
                "no component provenance registry was configured: the trust "
                "state of the models, tools and packages this agent depends "
                "on is unknown"
            )
            return signals, gaps

        components = self._provenance_registry.for_agent(agent_id)

        if not components:
            gaps.append(
                f"no components are recorded against {agent_id}: an agent "
                "with no declared dependencies is indistinguishable from one "
                "whose dependencies were never registered"
            )
            return signals, gaps

        for component in components:
            component_id = component.get("component_id")
            state = self._provenance_registry.trust_state(str(component_id))
            status = state.get("status")

            if status == "trusted":
                continue

            if status == "revoked":
                provenance = ProvenanceLevel.OBSERVED
            elif status == "suspicious":
                # Derived: a deterministic consequence of the recorded
                # dependency edges, not a guess.
                provenance = ProvenanceLevel.DERIVED
            else:
                # "unknown" and anything the registry adds later. Unknown
                # is not trusted, and it is not a claim about the
                # component either.
                provenance = ProvenanceLevel.UNKNOWN
                gaps.append(
                    f"component {component_id} has trust state {status!r}: "
                    "it is neither trusted nor known to be untrusted"
                )

            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.PROVENANCE_UNTRUSTED,
                provenance=provenance,
                agent_id=agent_id,
                description=(
                    f"Component {component_id} trust state is {status}"
                ),
                timestamp=timestamp,
                metadata={
                    "component_id": component_id,
                    "component_kind": component.get("kind"),
                    "status": status,
                    "findings": list(state.get("findings", ())),
                },
            ))

        return signals, gaps

    # ------------------------------------------------------------------
    # Posture and behaviour
    # ------------------------------------------------------------------

    def _analyze_posture(
        self,
        agent_id: str,
        observed_action: Optional[dict[str, Any]],
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Report adverse posture, and actions a posture does not account for.

        ``suspicious`` is included in :data:`_ADVERSE_POSTURES`. The
        previous list was ``("compromised", "contained", "high_risk")``,
        which omitted the one posture whose entire purpose is to say
        something is off.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if self._posture_engine is None:
            gaps.append(
                "no posture engine was configured: this agent's posture is "
                "unknown"
            )
            return signals, gaps

        posture_state = self._posture_engine.state(agent_id)
        posture = posture_state.posture

        if posture in _ADVERSE_POSTURES:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.POSTURE_CONTRADICTION,
                provenance=ProvenanceLevel.DERIVED,
                agent_id=agent_id,
                description=f"Agent posture is {posture}",
                timestamp=timestamp,
                metadata={
                    "posture": posture,
                    "signals": list(posture_state.signals),
                },
            ))
        elif posture == "unknown":
            gaps.append(
                f"the posture engine holds no posture for {agent_id}: an "
                "agent that has never been assessed is not a healthy agent"
            )

        if observed_action is None:
            gaps.append(
                "no action was observed: nothing was compared against the "
                f"{posture} posture"
            )
            return signals, gaps

        action_type = observed_action.get("type", "unknown")

        if action_type in _SENSITIVE_ACTIONS and posture in _NOMINAL_POSTURES:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.BEHAVIOR_ANOMALY,
                provenance=ProvenanceLevel.INFERRED,
                agent_id=agent_id,
                description=(
                    f"Observed {action_type} action is not accounted for by "
                    f"{posture} posture"
                ),
                confidence=0.6,
                timestamp=timestamp,
                metadata={"action": dict(observed_action), "posture": posture},
            ))
        elif action_type == "unknown":
            gaps.append(
                "the observed action declares no type: whether it is "
                "consistent with the posture is unknown"
            )

        return signals, gaps

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def _detect_evidence_contradictions(
        self,
        agent_id: str,
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Look for evidence that disagrees with other evidence.

        Two detections, both previously broken:

        *Conflicting observations.* The old key was
        ``f"{event_type}:{json.dumps(payload)}"`` and the comparison it
        guarded was ``prev["payload"] != event.payload``. Two events
        collide on that key only when their payloads serialize
        identically, so the comparison could never be true and the
        detection could never fire. The key is now the event type alone.

        *Laundered inference.* The old rule flagged every ``observed``
        event that followed an ``inference`` of the same type without
        declaring ``promoted_from``. An observation does not have to
        descend from an inference, so that fired in normal operation. The
        rule now requires the payloads to be *identical*: an inference
        restated verbatim as an observation, with no declared promotion,
        is the laundering this is meant to catch. It stays ``inferred``,
        because an identical payload is suggestive, not conclusive. An
        observation that declares ``promoted_from`` is not flagged: the
        promotion is on the record, which is the whole point.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        if self._evidence_graph is None:
            gaps.append(
                "no evidence graph was configured: contradictions between "
                "recorded events could not be looked for"
            )
            return signals, gaps

        agent_events = [
            event for event in self._evidence_graph.events()
            if event.subject == agent_id
        ]

        if not agent_events:
            gaps.append(
                f"the evidence graph holds no events about {agent_id}: an "
                "agent with no recorded history is not a clean agent"
            )
            return signals, gaps

        observed_by_type: dict[str, dict[str, Any]] = {}

        for event in agent_events:
            if _kind_of(event) != EvidenceKind.OBSERVED.value:
                continue

            previous = observed_by_type.get(event.event_type)

            if previous is None:
                observed_by_type[event.event_type] = {
                    "event_id": event.event_id,
                    "payload": event.payload,
                }
                continue

            if previous["payload"] != event.payload:
                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
                    provenance=ProvenanceLevel.OBSERVED,
                    agent_id=agent_id,
                    description=(
                        "Two observed events of type "
                        f"{event.event_type} record different payloads"
                    ),
                    timestamp=timestamp,
                    metadata={
                        "event_type": event.event_type,
                        "event_id_1": previous["event_id"],
                        "event_id_2": event.event_id,
                        "payload_1": previous["payload"],
                        "payload_2": event.payload,
                    },
                ))

        inferences = [
            event for event in agent_events
            if _kind_of(event) == EvidenceKind.INFERENCE.value
        ]

        for inference in inferences:
            for later in agent_events:
                if _kind_of(later) != EvidenceKind.OBSERVED.value:
                    continue
                if later.timestamp <= inference.timestamp:
                    continue
                if later.event_type != inference.event_type:
                    continue
                # Compare with the promotion marker removed, so a declared
                # promotion still counts as "the same payload" and is then
                # excused by the next check. Comparing the raw payloads
                # would make that check unreachable: a payload identical to
                # the inference's cannot also carry a marker naming it.
                if _without_promotion(later.payload) != _without_promotion(
                    inference.payload
                ):
                    continue
                if later.payload.get("promoted_from") == inference.event_id:
                    continue

                signals.append(SecuritySignal(
                    discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
                    provenance=ProvenanceLevel.INFERRED,
                    agent_id=agent_id,
                    description=(
                        "An inference reappears verbatim as an observation "
                        "with no declared promotion"
                    ),
                    confidence=0.5,
                    timestamp=timestamp,
                    metadata={
                        "event_type": inference.event_type,
                        "inference_event_id": inference.event_id,
                        "observed_event_id": later.event_id,
                        "explicit_promotion": False,
                    },
                ))
                break

        return signals, gaps

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def _detect_replay(
        self,
        agent_id: str,
        timestamp: float,
    ) -> tuple[list[SecuritySignal], list[str]]:
        """Report replays the SDK has already recorded.

        ``FirewallSDK.consume_nonce`` writes a ``REPLAYED`` lifecycle
        event when a nonce is presented twice. This reads that record; it
        does not re-derive replay from capability shape, which would be a
        second answer to a question the data plane has already answered.
        """

        signals: list[SecuritySignal] = []
        gaps: list[str] = []

        replays = [
            event
            for event in self._sdk.lifecycle.of_type(LifecycleEventType.REPLAYED)
            if event.agent_id == agent_id
        ]

        if not replays:
            return signals, gaps

        for event in replays:
            signals.append(SecuritySignal(
                discrepancy_type=DiscrepancyType.REPLAY_DETECTED,
                provenance=ProvenanceLevel.OBSERVED,
                agent_id=agent_id,
                description=(
                    "Lifecycle recorder holds a replay event for capability "
                    f"{event.fingerprint}"
                ),
                timestamp=timestamp,
                metadata={
                    "fingerprint": event.fingerprint,
                    "capability": event.capability,
                    "recorded_at": event.timestamp,
                    "details": dict(event.details or {}),
                },
            ))

        return signals, gaps

    # ------------------------------------------------------------------
    # Descriptive facts
    # ------------------------------------------------------------------

    def _collect_facts(
        self,
        agent_id: str,
        capability: Optional[Capability],
        timestamp: float,
    ) -> tuple[dict[str, Any], list[str]]:
        """Gather the descriptive fields of the profile.

        Each lookup that fails becomes a gap. The previous version wrapped
        four of these in ``except Exception: pass``, so an empty
        ``live_capabilities`` tuple meant either "this agent holds no live
        capability" or "enumerating them raised", with no way to tell.
        """

        gaps: list[str] = []
        facts: dict[str, Any] = {
            "identity_status": "unknown",
            "active_tasks": (),
            "live_capabilities": (),
            "delegation_depth": 0,
            "posture": "unknown",
        }

        if self._identity_registry is not None:
            try:
                identity = self._identity_registry.get(agent_id)
                if identity is not None:
                    facts["identity_status"] = identity.status
            except Exception as exc:  # noqa: BLE001 - reported as a gap
                gaps.append(f"identity status lookup failed: {exc}")

        if self._task_registry is not None:
            try:
                facts["active_tasks"] = tuple(
                    task.task_id
                    for task in self._task_registry.tasks_for_agent(agent_id)
                    if task.status == "active"
                )
            except Exception as exc:  # noqa: BLE001 - reported as a gap
                gaps.append(f"active task enumeration failed: {exc}")

        try:
            registry = self._sdk.known_capabilities()
            facts["live_capabilities"] = tuple(
                cap.capability
                for cap in registry.values()
                if cap.agent_id == agent_id
                and not self._sdk.is_effectively_revoked(cap)
            )
        except Exception as exc:  # noqa: BLE001 - reported as a gap
            gaps.append(
                f"live capability enumeration failed: {exc}; an empty list "
                "here does not mean the agent holds none"
            )

        if capability is not None:
            try:
                chain = self._sdk.delegation_lineage.chain(
                    self._sdk.fingerprint(capability)
                )
                facts["delegation_depth"] = len(chain)
            except Exception as exc:  # noqa: BLE001 - reported as a gap
                gaps.append(
                    f"delegation depth could not be computed: {exc}; the "
                    "reported depth of 0 is not a measurement"
                )

        if self._posture_engine is not None:
            try:
                facts["posture"] = self._posture_engine.state(agent_id).posture
            except Exception as exc:  # noqa: BLE001 - reported as a gap
                gaps.append(f"posture lookup failed: {exc}")

        return facts, gaps

    # ------------------------------------------------------------------
    # Cached profiles
    # ------------------------------------------------------------------

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


def _without_promotion(payload: Any) -> dict[str, Any]:
    """A payload with the ``promoted_from`` marker removed.

    Used so "the same payload" and "declares a promotion" are independent
    questions rather than mutually exclusive ones.
    """

    if not isinstance(payload, dict):
        return {}

    return {key: value for key, value in payload.items()
            if key != "promoted_from"}


def _kind_of(event: Any) -> str:
    """The evidence kind as a plain string.

    ``EvidenceEvent.kind`` may hold either an :class:`EvidenceKind` or the
    string it was loaded from, so comparisons normalize first.
    """

    kind = getattr(event, "kind", None)
    return kind.value if isinstance(kind, EvidenceKind) else str(kind)


def detect_contradiction(
    signal_a: SecuritySignal,
    signal_b: SecuritySignal,
) -> Optional[SecuritySignal]:
    """Report the one contradiction two signals can actually establish.

    Both signals must be about the same agent, both must be factual, and
    one must say the registry has no record of the agent while the other
    reports a mismatch against a record it does have. Those two cannot
    both be true, so the result is ``derived``: a deterministic
    consequence of two recorded findings.

    Two rules were removed rather than kept:

    *"Capability revoked but anomalous behavior observed"* was labelled a
    contradiction. It is not one -- a revoked capability and anomalous
    behaviour corroborate each other. Escalation is
    :func:`assess_risk`'s job, and reporting corroboration as
    contradiction put a false claim in the evidence record.

    *"Posture compromised but trust high"* was a comment, an ``if`` and a
    ``pass``, with "This would need trust score from profile". It never
    returned anything. A profile-level check is not a two-signal
    comparison and does not belong in this signature.
    """

    if signal_a.agent_id != signal_b.agent_id:
        return None

    if not (signal_a.factual and signal_b.factual):
        return None

    pairs = ((signal_a, signal_b), (signal_b, signal_a))

    for unverified, mismatch in pairs:
        if unverified.discrepancy_type is not DiscrepancyType.IDENTITY_UNVERIFIED:
            continue
        if unverified.metadata.get("reason") != "not_found":
            continue
        if mismatch.discrepancy_type is not DiscrepancyType.IDENTITY_MISMATCH:
            continue

        return SecuritySignal(
            discrepancy_type=DiscrepancyType.EVIDENCE_CONTRADICTION,
            provenance=ProvenanceLevel.DERIVED,
            agent_id=signal_a.agent_id,
            description=(
                "The registry is reported both as having no record of this "
                "agent and as holding a record that disagrees with its claim"
            ),
            timestamp=max(signal_a.timestamp, signal_b.timestamp),
            related_signals=(
                unverified.discrepancy_type.value,
                mismatch.discrepancy_type.value,
            ),
            metadata={
                "unverified_reason": unverified.metadata.get("reason"),
                "mismatch_reason": mismatch.metadata.get("reason"),
            },
        )

    return None
