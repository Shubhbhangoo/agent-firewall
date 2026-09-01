"""v2.2 adversarial agent defense (:mod:`firewall.adversarial`).

What these tests exist to prevent, in order of how badly it would hurt:

*A profile that reads clean because nothing was checked.* The evaluator
takes six optional subsystems. Every absence is a named gap, and the
gaps here are asserted, not merely counted -- a fail-open default is
invisible in a signal count.

*``identity_verified=True`` without proof of possession.* It is
three-valued, and ``True`` requires a verified attestation. A registry
record existing, or a claimant reciting the public fingerprint, is not
verification. The old implementation computed it as "no
IDENTITY_UNVERIFIED signal was raised", so a *proven* key mismatch --
which raises IDENTITY_MISMATCH -- reported ``True``.

*Detections that cannot fire.* ``test_every_discrepancy_type_is_emitted``
fails if any :class:`DiscrepancyType` loses its emitter, because an enum
member nothing raises is a documented detection that does not happen.
Three of the eighteen were in that state.

*Detections that always fire.* A check that reports every legitimate
operation is worse than no check, so the honest-negative cases are here
too: a lawful cross-agent delegation, and an observation that follows an
inference for ordinary reasons.

*Risk becoming authority.* The last test proves a ``critical`` profile
neither denies a request policy allows nor allows one policy denies.
:meth:`FirewallSDK.authorize` does not read this module.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Optional

import pytest

from firewall.adversarial import (
    RISK_LEVELS,
    AdversarialAgentDefense,
    AgentSecurityProfile,
    DiscrepancyType,
    ProvenanceLevel,
    SecuritySignal,
    assess_risk,
    detect_contradiction,
)
from firewall.capability import Capability
from firewall.evidence_graph import EvidenceGraph
from firewall.ident.registry import IdentityRegistry
from firewall.platform import Provenance
from firewall.posture.engine import PostureEngine, PostureSignal
from firewall.provenance.registry import ProvenanceRegistry
from firewall.sdk import FirewallSDK
from firewall.task.registry import TaskRegistry

#: Every clock in these tests is pinned. Capability expiry and the
#: time-travel checks are judged against the evaluation's own
#: ``now=``, so a wall-clock reading anywhere would make the suite
#: order- and date-dependent.
_NOW = 1_000_000.0

#: One second after issuance: inside every capability's validity window.
_LATER = _NOW + 1.0

_KEY_ID = "adversarial-key"


def _sdk() -> FirewallSDK:
    """A control plane with a pinned clock and one signing key."""

    sdk = FirewallSDK(clock=lambda: _NOW)
    sdk.generate_key(_KEY_ID)
    return sdk


def _private(sdk: FirewallSDK):
    return sdk.keys.get(_KEY_ID).private_key


def _cap(
    sdk: FirewallSDK,
    *,
    agent: str = "agent-1",
    constraints: Optional[dict] = None,
) -> Capability:
    """A capability whose validity window is pinned to ``_NOW``.

    ``FirewallSDK.issue`` timestamps from the wall clock unless told
    otherwise, and the time-travel check compares ``issued_at`` against
    the evaluation's ``now=``. Leaving it to the wall clock would make
    every capability here look issued in the far future.
    """

    return sdk.issue(
        agent=agent,
        capability="payments.send",
        constraints=dict(constraints) if constraints is not None
        else {"amount_max": 100},
        issued_at=_NOW,
        expires_at=_NOW + 3_600.0,
    )


def _defense(sdk: FirewallSDK, **subsystems: Any) -> AdversarialAgentDefense:
    return AdversarialAgentDefense(sdk, clock=lambda: _NOW, **subsystems)


def _identities(agent: str = "agent-1") -> IdentityRegistry:
    registry = IdentityRegistry(clock=lambda: _NOW)
    registry.create(agent)
    return registry


def _types(profile: AgentSecurityProfile) -> tuple[str, ...]:
    return tuple(s.discrepancy_type.value for s in profile.signals)


def _of(
    profile: AgentSecurityProfile,
    discrepancy: DiscrepancyType,
) -> tuple[SecuritySignal, ...]:
    return tuple(
        s for s in profile.signals if s.discrepancy_type is discrepancy
    )


# ----------------------------------------------------------------------
# One emitter per discrepancy type
# ----------------------------------------------------------------------


def _s_identity_unverified() -> AgentSecurityProfile:
    """No identity registry: the question cannot be answered at all."""

    return _defense(_sdk()).evaluate_agent("agent-1", now=_LATER)


def _s_identity_mismatch() -> AgentSecurityProfile:
    """A claim whose fingerprint is not the registered one."""

    return _defense(
        _sdk(), identity_registry=_identities()
    ).evaluate_agent(
        "agent-1",
        claimed_identity={"key_fingerprint": "0" * 64},
        now=_LATER,
    )


def _s_task_unauthorized() -> AgentSecurityProfile:
    return _defense(
        _sdk(), task_registry=TaskRegistry(clock=lambda: _NOW)
    ).evaluate_agent("agent-1", declared_task="task-never-created", now=_LATER)


def _s_task_mismatch() -> AgentSecurityProfile:
    tasks = TaskRegistry(clock=lambda: _NOW)
    task = tasks.create(agent_id="agent-2")
    return _defense(_sdk(), task_registry=tasks).evaluate_agent(
        "agent-1", declared_task=task.task_id, now=_LATER
    )


def _s_capability_mismatch() -> AgentSecurityProfile:
    sdk = _sdk()
    return _defense(sdk).evaluate_agent(
        "agent-1", presented_capability=_cap(sdk, agent="agent-2"), now=_LATER
    )


def _s_capability_revoked() -> AgentSecurityProfile:
    sdk = _sdk()
    cap = _cap(sdk)
    sdk.revoke(cap, reason="operator revoked it")
    return _defense(sdk).evaluate_agent(
        "agent-1", presented_capability=cap, now=_LATER
    )


def _s_capability_expired() -> AgentSecurityProfile:
    sdk = _sdk()
    cap = _cap(sdk)
    return _defense(sdk).evaluate_agent(
        "agent-1", presented_capability=cap, now=cap.expires_at + 1.0
    )


def _s_time_travel() -> AgentSecurityProfile:
    """Evaluated before the capability claims to have been issued."""

    sdk = _sdk()
    cap = _cap(sdk)
    return _defense(sdk).evaluate_agent(
        "agent-1", presented_capability=cap, now=cap.issued_at - 1.0
    )


def _s_delegation_mismatch() -> AgentSecurityProfile:
    """A declared parent the lineage has no record of."""

    sdk = _sdk()
    cap = replace(_cap(sdk), parent_fingerprint="1" * 64)
    return _defense(sdk).evaluate_agent(
        "agent-1", presented_capability=cap, now=_LATER
    )


def _s_delegation_chain_broken() -> AgentSecurityProfile:
    sdk = _sdk()
    parent = _cap(sdk)
    delegation = sdk.delegate(
        parent, _private(sdk), delegatee="agent-2",
        constraints={"amount_max": 50},
    )
    sdk.revoke(parent, reason="parent authority withdrawn")
    return _defense(sdk).evaluate_agent(
        "agent-2", presented_capability=delegation.child, now=_LATER
    )


def _s_delegation_widening() -> AgentSecurityProfile:
    """A lineage edge to a parent the child is not narrower than.

    ``delegate_capability`` refuses to mint this, so the tampered state is
    built by registering the lineage edge directly -- the same call
    ``FirewallSDK.delegate`` makes.
    """

    sdk = _sdk()
    parent = _cap(sdk, constraints={"amount_max": 10})
    parent_fp = sdk.fingerprint(parent)
    wide = replace(
        _cap(sdk, agent="agent-2", constraints={"amount_max": 1_000}),
        parent_fingerprint=parent_fp,
    )
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(wide), parent_fingerprint=parent_fp
    )
    return _defense(sdk).evaluate_agent(
        "agent-2", presented_capability=wide, now=_LATER
    )


def _s_provenance_mismatch() -> AgentSecurityProfile:
    """A signing key this control plane has no record of."""

    sdk = _sdk()
    cap = replace(_cap(sdk), key_id="key-this-plane-never-had")
    return _defense(sdk).evaluate_agent(
        "agent-1", presented_capability=cap, now=_LATER
    )


def _s_provenance_untrusted() -> AgentSecurityProfile:
    registry = ProvenanceRegistry(clock=lambda: _NOW)
    component = registry.register(
        kind="model", name="planner", version="1",
        metadata={"agent_id": "agent-1"},
    )
    registry.trust(component.component_id, reason="reviewed")
    registry.revoke(component.component_id, reason="backdoor found")
    return _defense(
        _sdk(), provenance_registry=registry
    ).evaluate_agent("agent-1", now=_LATER)


def _posture(agent: str, severity: int) -> PostureEngine:
    engine = PostureEngine()
    engine.ingest(
        agent,
        PostureSignal(
            name="signal", severity=severity, description="recorded evidence"
        ),
        now=_NOW,
    )
    return engine


def _s_posture_contradiction() -> AgentSecurityProfile:
    """``suspicious`` is adverse. The old list omitted it."""

    return _defense(
        _sdk(), posture_engine=_posture("agent-1", 3)
    ).evaluate_agent("agent-1", now=_LATER)


def _s_behavior_anomaly() -> AgentSecurityProfile:
    """A sensitive action a healthy posture does not account for."""

    return _defense(
        _sdk(), posture_engine=_posture("agent-1", 1)
    ).evaluate_agent(
        "agent-1",
        observed_action={"type": "credential_access", "target": "vault"},
        now=_LATER,
    )


def _s_evidence_contradiction() -> AgentSecurityProfile:
    """Two observations of the same event type that disagree."""

    graph = EvidenceGraph(signer=None)
    graph.append("observed", "agent-1", "tool_call", {"rows": 1}, now=_NOW)
    graph.append(
        "observed", "agent-1", "tool_call", {"rows": 9}, now=_NOW + 1.0
    )
    return _defense(_sdk(), evidence_graph=graph).evaluate_agent(
        "agent-1", now=_LATER
    )


def _s_replay_detected() -> AgentSecurityProfile:
    """The SDK recorded a replayed nonce; this reads that record."""

    sdk = _sdk()
    cap = _cap(sdk)
    assert sdk.consume_nonce("agent-1", cap, "nonce-1") is True
    assert sdk.consume_nonce("agent-1", cap, "nonce-1") is False
    return _defense(sdk).evaluate_agent("agent-1", now=_LATER)


class _ExplodingTaskRegistry:
    """A subsystem that fails. Its failure must be visible."""

    def get(self, task_id: str) -> Any:
        raise RuntimeError("task registry backend unavailable")


def _s_unknown() -> AgentSecurityProfile:
    return _defense(
        _sdk(), task_registry=_ExplodingTaskRegistry()
    ).evaluate_agent("agent-1", declared_task="task-1", now=_LATER)


_SCENARIOS: dict[DiscrepancyType, Callable[[], AgentSecurityProfile]] = {
    DiscrepancyType.IDENTITY_MISMATCH: _s_identity_mismatch,
    DiscrepancyType.IDENTITY_UNVERIFIED: _s_identity_unverified,
    DiscrepancyType.TASK_MISMATCH: _s_task_mismatch,
    DiscrepancyType.TASK_UNAUTHORIZED: _s_task_unauthorized,
    DiscrepancyType.CAPABILITY_MISMATCH: _s_capability_mismatch,
    DiscrepancyType.CAPABILITY_REVOKED: _s_capability_revoked,
    DiscrepancyType.CAPABILITY_EXPIRED: _s_capability_expired,
    DiscrepancyType.DELEGATION_MISMATCH: _s_delegation_mismatch,
    DiscrepancyType.DELEGATION_CHAIN_BROKEN: _s_delegation_chain_broken,
    DiscrepancyType.DELEGATION_WIDENING: _s_delegation_widening,
    DiscrepancyType.PROVENANCE_MISMATCH: _s_provenance_mismatch,
    DiscrepancyType.PROVENANCE_UNTRUSTED: _s_provenance_untrusted,
    DiscrepancyType.POSTURE_CONTRADICTION: _s_posture_contradiction,
    DiscrepancyType.BEHAVIOR_ANOMALY: _s_behavior_anomaly,
    DiscrepancyType.EVIDENCE_CONTRADICTION: _s_evidence_contradiction,
    DiscrepancyType.REPLAY_DETECTED: _s_replay_detected,
    DiscrepancyType.TIME_TRAVEL: _s_time_travel,
    DiscrepancyType.UNKNOWN: _s_unknown,
}


@pytest.mark.parametrize(
    "discrepancy", list(_SCENARIOS), ids=lambda d: d.value
)
def test_scenario_emits_its_discrepancy_type(discrepancy: DiscrepancyType):
    profile = _SCENARIOS[discrepancy]()
    assert discrepancy.value in _types(profile), (
        f"{discrepancy.value} was not emitted; got {_types(profile)}"
    )


def test_every_discrepancy_type_is_emitted():
    """An enum member nothing raises is a detection that does not happen.

    Three of the eighteen were unreachable before this file existed:
    ``DELEGATION_WIDENING`` (nothing computed attenuation),
    ``PROVENANCE_UNTRUSTED`` (the component check was a comment) and
    ``UNKNOWN`` (failures were swallowed).
    """

    assert set(_SCENARIOS) == set(DiscrepancyType)


@pytest.mark.parametrize(
    "discrepancy", list(_SCENARIOS), ids=lambda d: d.value
)
def test_no_finding_leaves_the_profile_reading_low_risk(
    discrepancy: DiscrepancyType,
):
    """Any emitted discrepancy moves risk off ``low``.

    The previous risk table weighted three of the eighteen types, so a
    revoked capability, an expired capability, an untrusted issuer, a
    stolen task and an unknown identity all left ``risk_level="low"``.
    """

    profile = _SCENARIOS[discrepancy]()
    assert profile.risk_level != "low"
    assert profile.risk_level in RISK_LEVELS


def test_a_signal_that_establishes_nothing_is_not_a_finding_against_the_agent():
    """``unknown`` provenance is neither a pass nor an accusation."""

    profile = _s_identity_unverified()
    assert _types(profile) == ("identity_unverified",)
    assert profile.signals[0].provenance is Provenance.UNKNOWN
    assert profile.factual_signals == ()
    assert profile.risk_level == "unknown"


# ----------------------------------------------------------------------
# identity_verified is three-valued, and True means proof of possession
# ----------------------------------------------------------------------


def _reasons(profile: AgentSecurityProfile) -> tuple[Any, ...]:
    return tuple(s.metadata.get("reason") for s in profile.signals)


def test_no_identity_registry_leaves_verification_unestablished():
    profile = _defense(_sdk()).evaluate_agent("agent-1", now=_LATER)
    assert profile.identity_verified is None
    assert any("no identity registry was configured" in g
               for g in profile.gaps)


def test_a_registry_record_alone_is_not_a_verified_identity():
    """A record says a name is known, not that this party holds the key."""

    profile = _defense(
        _sdk(), identity_registry=_identities()
    ).evaluate_agent("agent-1", now=_LATER)
    assert profile.identity_verified is None
    assert profile.identity_status == "active"
    assert any("a known name is not a verified identity" in g
               for g in profile.gaps)


def test_a_matching_fingerprint_alone_is_not_proof_of_possession():
    """The registered fingerprint is public. Reciting it proves nothing."""

    registry = _identities()
    identity = registry.require("agent-1")
    profile = _defense(_sdk(), identity_registry=registry).evaluate_agent(
        "agent-1",
        claimed_identity={"key_fingerprint": identity.key_fingerprint},
        now=_LATER,
    )
    assert profile.identity_verified is None
    assert _of(profile, DiscrepancyType.IDENTITY_MISMATCH) == ()
    assert any("not that it holds the private one" in g for g in profile.gaps)


def test_a_verified_attestation_is_proof_of_possession():
    registry = _identities()
    identity = registry.require("agent-1")
    profile = _defense(_sdk(), identity_registry=registry).evaluate_agent(
        "agent-1",
        claimed_identity={
            "key_fingerprint": identity.key_fingerprint,
            "attestation": registry.self_attestation("agent-1"),
        },
        now=_LATER,
    )
    assert profile.identity_verified is True
    assert _of(profile, DiscrepancyType.IDENTITY_MISMATCH) == ()
    assert not any("private one" in g for g in profile.gaps)


def test_a_proven_fingerprint_mismatch_is_not_reported_as_verified():
    """The defect this rewrite exists for.

    ``identity_verified`` was "no IDENTITY_UNVERIFIED signal was raised".
    A fingerprint mismatch raises IDENTITY_MISMATCH, not
    IDENTITY_UNVERIFIED, so the strongest impersonation evidence the
    module can produce came back as ``identity_verified=True``.
    """

    profile = _s_identity_mismatch()
    assert profile.identity_verified is False
    assert "fingerprint_mismatch" in _reasons(profile)


def test_an_unknown_agent_is_not_verified():
    profile = _defense(
        _sdk(), identity_registry=_identities()
    ).evaluate_agent("agent-not-registered", now=_LATER)
    assert profile.identity_verified is False
    assert "not_found" in _reasons(profile)


def test_a_revoked_identity_is_not_verified():
    registry = _identities()
    registry.revoke("agent-1", reason="key compromise")
    profile = _defense(_sdk(), identity_registry=registry).evaluate_agent(
        "agent-1", now=_LATER
    )
    assert profile.identity_verified is False
    assert "not_active" in _reasons(profile)


def test_an_attestation_from_a_revoked_identity_is_a_gap_not_a_forgery():
    """A lifecycle event must not retroactively brand evidence as forged.

    ``IdentityRegistry.verify`` refuses revoked and retired identities by
    design, so calling it here would return False for a *genuine*
    attestation. Reporting that as "attestation does not verify" would be
    a false forgery finding, so the check is skipped and said aloud.
    """

    registry = _identities()
    attestation = registry.self_attestation("agent-1")
    identity = registry.require("agent-1")
    registry.revoke("agent-1", reason="rotated out")

    profile = _defense(_sdk(), identity_registry=registry).evaluate_agent(
        "agent-1",
        claimed_identity={
            "key_fingerprint": identity.key_fingerprint,
            "attestation": attestation,
        },
        now=_LATER,
    )

    assert profile.identity_verified is False
    assert "attestation_failed" not in _reasons(profile)
    assert "not_active" in _reasons(profile)
    assert any("would not be proof of forgery" in g for g in profile.gaps)


def test_a_forged_attestation_is_a_mismatch():
    """A signature over the right payload by the wrong key is a finding."""

    registry = _identities()
    registry.create("agent-2")
    identity = registry.require("agent-1")

    profile = _defense(_sdk(), identity_registry=registry).evaluate_agent(
        "agent-1",
        claimed_identity={
            "key_fingerprint": identity.key_fingerprint,
            "attestation": registry.self_attestation("agent-2"),
        },
        now=_LATER,
    )

    assert profile.identity_verified is False
    assert "attestation_failed" in _reasons(profile)


def test_a_claim_with_nothing_checkable_is_a_gap():
    profile = _defense(
        _sdk(), identity_registry=_identities()
    ).evaluate_agent("agent-1", claimed_identity={"note": "hi"}, now=_LATER)
    assert profile.identity_verified is None
    assert any("nothing in it was checkable" in g for g in profile.gaps)


def test_a_failing_identity_registry_does_not_report_a_verified_identity():
    class _Exploding:
        def get(self, agent_id: str) -> Any:
            raise RuntimeError("identity store unreachable")

    profile = _defense(_sdk(), identity_registry=_Exploding()).evaluate_agent(
        "agent-1", claimed_identity={"key_fingerprint": "0" * 64}, now=_LATER
    )
    assert profile.identity_verified is None
    assert "unknown" in _types(profile)
    assert any("identity verification raised RuntimeError" in g
               for g in profile.gaps)


# ----------------------------------------------------------------------
# assess_risk: triage, and never a pass by omission
# ----------------------------------------------------------------------


def _signal(
    discrepancy: DiscrepancyType,
    provenance: ProvenanceLevel,
    *,
    confidence: Optional[float] = None,
    agent: str = "agent-1",
    reason: Optional[str] = None,
) -> SecuritySignal:
    return SecuritySignal(
        discrepancy_type=discrepancy,
        provenance=provenance,
        agent_id=agent,
        description="constructed for a risk-table test",
        confidence=confidence,
        timestamp=_LATER,
        metadata={"reason": reason} if reason is not None else {},
    )


def test_a_clean_evaluation_with_no_gaps_is_the_only_low():
    assert assess_risk(()) == (1.0, "low")


def test_a_gap_alone_leaves_the_risk_unknown_not_low():
    score, level = assess_risk((), gaps=("the posture engine was absent",))
    assert level == "unknown"
    assert score == 1.0


def test_an_unestablished_signal_never_reads_as_low():
    _, level = assess_risk(
        (_signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.UNKNOWN),)
    )
    assert level == "unknown"


def test_an_inference_is_a_finding_but_not_a_factual_one():
    score, level = assess_risk(
        (_signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                 confidence=0.6),)
    )
    assert level == "medium"
    assert score == pytest.approx(1.0 - (1.0 - 0.6) * 0.6)


def test_a_lower_confidence_inference_moves_the_score_less():
    weak, _ = assess_risk(
        (_signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                 confidence=0.1),)
    )
    strong, _ = assess_risk(
        (_signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                 confidence=1.0),)
    )
    assert weak > strong


def test_a_factual_finding_reaches_the_factual_levels():
    _, high = assess_risk(
        (_signal(DiscrepancyType.CAPABILITY_MISMATCH, Provenance.OBSERVED),)
    )
    _, medium = assess_risk(
        (_signal(DiscrepancyType.TASK_UNAUTHORIZED, Provenance.OBSERVED),)
    )
    assert high == "high"
    assert medium == "medium"


def test_a_contradicted_control_is_critical():
    for discrepancy in (
        DiscrepancyType.IDENTITY_MISMATCH,
        DiscrepancyType.CAPABILITY_REVOKED,
        DiscrepancyType.DELEGATION_WIDENING,
        DiscrepancyType.DELEGATION_MISMATCH,
        DiscrepancyType.REPLAY_DETECTED,
        DiscrepancyType.TIME_TRAVEL,
        DiscrepancyType.PROVENANCE_UNTRUSTED,
    ):
        _, level = assess_risk((_signal(discrepancy, Provenance.OBSERVED),))
        assert level == "critical", discrepancy.value


def test_independent_findings_compound():
    """Multiplicative, so two findings are worse than the worse of them."""

    one, _ = assess_risk(
        (_signal(DiscrepancyType.TASK_UNAUTHORIZED, Provenance.OBSERVED),)
    )
    two, _ = assess_risk((
        _signal(DiscrepancyType.TASK_UNAUTHORIZED, Provenance.OBSERVED),
        _signal(DiscrepancyType.TASK_MISMATCH, Provenance.OBSERVED),
    ))
    assert two < one


def test_every_discrepancy_type_has_a_weight():
    """An unweighted type would be a detection that does not move risk."""

    from firewall.adversarial import _SIGNAL_WEIGHTS

    assert set(_SIGNAL_WEIGHTS) == set(DiscrepancyType)
    assert all(0.0 < weight <= 1.0 for weight in _SIGNAL_WEIGHTS.values())


def test_assess_risk_returns_a_declared_level():
    for discrepancy in DiscrepancyType:
        _, level = assess_risk((_signal(discrepancy, Provenance.OBSERVED)
                                if discrepancy is not DiscrepancyType.UNKNOWN
                                else _signal(discrepancy, Provenance.UNKNOWN),))
        assert level in RISK_LEVELS


# ----------------------------------------------------------------------
# Type-level invariants
# ----------------------------------------------------------------------


def test_an_inference_must_state_a_confidence():
    with pytest.raises(ValueError, match="must state a confidence"):
        _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED)


def test_a_simulation_must_state_a_confidence():
    with pytest.raises(ValueError, match="must state a confidence"):
        _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.SIMULATED)


def test_a_recorded_fact_must_not_state_a_confidence():
    with pytest.raises(ValueError, match="must not state a confidence"):
        _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED,
                confidence=0.9)


def test_an_unestablished_signal_must_not_state_a_confidence():
    """The old default was ``confidence=0.0``, which reads "certainly not"."""

    with pytest.raises(ValueError, match="must not state a confidence"):
        _signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.UNKNOWN,
                confidence=0.0)


def test_confidence_outside_the_unit_interval_is_rejected():
    with pytest.raises(ValueError, match=r"within \[0.0, 1.0\]"):
        _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                confidence=1.5)


def test_confidence_must_be_a_number():
    with pytest.raises(TypeError, match="must be a number"):
        _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                confidence=True)


def test_provenance_is_normalized_from_its_wire_form():
    signal = SecuritySignal(
        discrepancy_type=DiscrepancyType.IDENTITY_MISMATCH,
        provenance="observed",
        agent_id="agent-1",
        description="loaded from serialized form",
    )
    assert signal.provenance is Provenance.OBSERVED
    assert signal.factual is True


def test_serialization_says_whether_a_signal_is_factual():
    fact = _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED)
    guess = _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                    confidence=0.6)

    assert fact.to_dict()["factual"] is True
    assert fact.to_dict()["confidence"] is None
    assert guess.to_dict()["factual"] is False
    assert guess.to_dict()["confidence"] == 0.6


def test_factual_signals_excludes_inference_and_the_unestablished():
    profile = AgentSecurityProfile(
        agent_id="agent-1",
        signals=(
            _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED),
            _signal(DiscrepancyType.EVIDENCE_CONTRADICTION,
                    Provenance.DERIVED),
            _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                    confidence=0.6),
            _signal(DiscrepancyType.UNKNOWN, Provenance.UNKNOWN),
        ),
    )
    assert len(profile.signals) == 4
    assert tuple(s.provenance for s in profile.factual_signals) == (
        Provenance.OBSERVED, Provenance.DERIVED,
    )


def test_a_profile_rejects_an_undeclared_risk_level():
    with pytest.raises(ValueError, match="unknown risk level"):
        AgentSecurityProfile(agent_id="agent-1", risk_level="fine")


def test_a_profile_rejects_a_trust_score_outside_the_unit_interval():
    with pytest.raises(ValueError, match=r"within \[0.0, 1.0\]"):
        AgentSecurityProfile(agent_id="agent-1", trust_score=1.5)


def test_an_empty_profile_is_not_a_clean_bill_of_health():
    """Defaults must not assert anything that was never checked."""

    profile = AgentSecurityProfile(agent_id="agent-1")
    assert profile.identity_verified is None
    assert profile.risk_level == "unknown"
    assert profile.identity_status == "unknown"
    assert profile.posture == "unknown"
    assert profile.to_dict()["identity_verified"] is None


# ----------------------------------------------------------------------
# Failures are visible, and a working evaluation looks different
# ----------------------------------------------------------------------


class _Exploding:
    """Stands in for any subsystem, and fails whatever it is asked."""

    def get(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("backend unreachable")

    def tasks_for_agent(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("backend unreachable")

    def state(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("backend unreachable")

    def events(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("backend unreachable")

    def for_agent(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("backend unreachable")


def test_every_failing_check_is_named():
    """``except Exception: pass`` appeared in six places before this."""

    boom = _Exploding()
    profile = _defense(
        _sdk(),
        identity_registry=boom,
        task_registry=boom,
        posture_engine=boom,
        evidence_graph=boom,
        provenance_registry=boom,
    ).evaluate_agent("agent-1", declared_task="task-1", now=_LATER)

    named = {
        s.metadata.get("check")
        for s in _of(profile, DiscrepancyType.UNKNOWN)
    }
    assert named == {
        "identity verification",
        "task verification",
        "component provenance",
        "posture analysis",
        "evidence contradiction detection",
    }
    assert profile.identity_verified is None
    assert profile.risk_level == "unknown"
    assert all(s.provenance is Provenance.UNKNOWN for s in profile.signals)
    assert any("posture lookup failed" in g for g in profile.gaps)


def _clean() -> tuple[AgentSecurityProfile, FirewallSDK, Capability]:
    """A fully-configured evaluation in which every check passes.

    This is the only shape that may report ``risk_level="low"``, and
    building it is what makes the gap assertions elsewhere meaningful:
    without it, "no gaps" could be unreachable rather than merely rare.
    """

    sdk = _sdk()
    cap = _cap(sdk)

    identities = _identities()
    identity = identities.require("agent-1")

    tasks = TaskRegistry(clock=lambda: _NOW)
    tasks.create(agent_id="agent-1", task_id="task-clean")

    postures = _posture("agent-1", 1)

    graph = EvidenceGraph(signer=None)
    graph.append("observed", "agent-1", "tool_call", {"rows": 1}, now=_NOW)

    components = ProvenanceRegistry(clock=lambda: _NOW)
    component = components.register(
        kind="model", name="planner", version="1",
        metadata={"agent_id": "agent-1"},
    )
    components.trust(component.component_id, reason="reviewed")

    profile = _defense(
        sdk,
        identity_registry=identities,
        task_registry=tasks,
        posture_engine=postures,
        evidence_graph=graph,
        provenance_registry=components,
    ).evaluate_agent(
        "agent-1",
        claimed_identity={
            "key_fingerprint": identity.key_fingerprint,
            "attestation": identities.self_attestation("agent-1"),
        },
        declared_task="task-clean",
        presented_capability=cap,
        observed_action={"type": "read", "target": "ledger"},
        now=_LATER,
    )

    return profile, sdk, cap


def test_a_fully_checked_agent_reports_no_gaps():
    profile, _, _ = _clean()
    assert profile.gaps == ()
    assert profile.signals == ()
    assert profile.identity_verified is True
    assert profile.identity_status == "active"
    assert profile.risk_level == "low"
    assert profile.trust_score == 1.0
    assert profile.posture == "healthy"
    assert profile.live_capabilities == ("payments.send",)
    assert profile.active_tasks == ("task-clean",)


def test_a_lawful_cross_agent_delegation_is_not_reported_as_widening():
    """A check that fires on every legitimate delegation is worse than none.

    ``firewall.attenuation.can_attenuate`` requires the holder to be
    unchanged, because attenuation is one agent narrowing its own
    authority. Delegation hands authority to a different agent, so judging
    it with that predicate would flag every real delegation.
    """

    sdk = _sdk()
    parent = _cap(sdk, constraints={"amount_max": 100})
    delegation = sdk.delegate(
        parent, _private(sdk), delegatee="agent-2",
        constraints={"amount_max": 50},
    )

    profile = _defense(sdk).evaluate_agent(
        "agent-2", presented_capability=delegation.child, now=_LATER
    )

    assert _of(profile, DiscrepancyType.DELEGATION_WIDENING) == ()
    assert _of(profile, DiscrepancyType.DELEGATION_MISMATCH) == ()
    assert _of(profile, DiscrepancyType.DELEGATION_CHAIN_BROKEN) == ()
    assert profile.delegation_depth == 1


def test_evaluation_is_reproducible_from_a_pinned_now():
    """Expiry is judged against ``now=``, not a fresh clock reading."""

    first, _, _ = _clean()
    second, _, _ = _clean()
    assert first.to_dict() == second.to_dict()


# ----------------------------------------------------------------------
# Evidence: the two repaired detections
# ----------------------------------------------------------------------


def _graph_profile(
    events: tuple[tuple[str, str, dict[str, Any], float], ...],
) -> AgentSecurityProfile:
    graph = EvidenceGraph(signer=None)
    for kind, event_type, payload, when in events:
        graph.append(kind, "agent-1", event_type, payload, now=when)
    return _defense(_sdk(), evidence_graph=graph).evaluate_agent(
        "agent-1", now=_LATER
    )


def test_conflicting_observations_of_one_event_type_are_detected():
    """Previously unreachable: the dict key embedded the payload JSON.

    Two events collided on that key only when their payloads serialized
    identically, and the guarded comparison asked whether they differed.
    """

    profile = _s_evidence_contradiction()
    found = _of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION)
    assert len(found) == 1
    assert found[0].provenance is Provenance.OBSERVED
    assert found[0].metadata["payload_1"] != found[0].metadata["payload_2"]
    assert found[0].metadata["event_type"] == "tool_call"


def test_two_observations_that_agree_are_not_a_contradiction():
    profile = _graph_profile((
        ("observed", "tool_call", {"rows": 1}, _NOW),
        ("observed", "tool_call", {"rows": 1}, _NOW + 1.0),
    ))
    assert _of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION) == ()


def test_observations_of_different_event_types_are_not_compared():
    profile = _graph_profile((
        ("observed", "tool_call", {"rows": 1}, _NOW),
        ("observed", "policy_change", {"rows": 9}, _NOW + 1.0),
    ))
    assert _of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION) == ()


def test_an_inference_restated_verbatim_as_an_observation_is_flagged():
    """Inference is not observation. Promotion has to be declared."""

    profile = _graph_profile((
        ("inference", "risk_estimate", {"level": "high"}, _NOW),
        ("observed", "risk_estimate", {"level": "high"}, _NOW + 1.0),
    ))
    found = _of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION)
    assert len(found) == 1
    assert found[0].provenance is Provenance.INFERRED
    assert found[0].confidence == 0.5
    assert found[0].metadata["explicit_promotion"] is False


def test_an_ordinary_observation_after_an_inference_is_not_flagged():
    """The old rule fired here, which is to say in normal operation.

    It flagged every ``observed`` event following an ``inference`` of the
    same type. Nothing requires an observation to descend from a guess.
    """

    profile = _graph_profile((
        ("inference", "risk_estimate", {"level": "high"}, _NOW),
        ("observed", "risk_estimate", {"level": "low"}, _NOW + 1.0),
    ))
    assert _of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION) == ()


def test_a_declared_promotion_is_not_flagged():
    graph = EvidenceGraph(signer=None)
    inference = graph.append(
        "inference", "agent-1", "risk_estimate", {"level": "high"}, now=_NOW
    )
    graph.append(
        "observed", "agent-1", "risk_estimate",
        {"level": "high", "promoted_from": inference.event_id},
        now=_NOW + 1.0,
    )
    profile = _defense(_sdk(), evidence_graph=graph).evaluate_agent(
        "agent-1", now=_LATER
    )
    assert _of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION) == ()


def test_a_promotion_naming_the_wrong_inference_is_still_flagged():
    graph = EvidenceGraph(signer=None)
    graph.append(
        "inference", "agent-1", "risk_estimate", {"level": "high"}, now=_NOW
    )
    graph.append(
        "observed", "agent-1", "risk_estimate",
        {"level": "high", "promoted_from": "0" * 64}, now=_NOW + 1.0,
    )
    profile = _defense(_sdk(), evidence_graph=graph).evaluate_agent(
        "agent-1", now=_LATER
    )
    assert len(_of(profile, DiscrepancyType.EVIDENCE_CONTRADICTION)) == 1


def test_an_agent_with_no_recorded_history_is_a_gap_not_a_clean_record():
    graph = EvidenceGraph(signer=None)
    graph.append("observed", "someone-else", "tool_call", {}, now=_NOW)
    profile = _defense(_sdk(), evidence_graph=graph).evaluate_agent(
        "agent-1", now=_LATER
    )
    assert any("is not a clean agent" in g for g in profile.gaps)


# ----------------------------------------------------------------------
# detect_contradiction: one rule, because one rule is what it can prove
# ----------------------------------------------------------------------


def test_two_findings_that_cannot_both_be_true_derive_a_contradiction():
    absent = _signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.OBSERVED,
                     reason="not_found")
    present = _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED,
                      reason="fingerprint_mismatch")

    result = detect_contradiction(absent, present)

    assert result is not None
    assert result.discrepancy_type is DiscrepancyType.EVIDENCE_CONTRADICTION
    assert result.provenance is Provenance.DERIVED
    assert result.confidence is None
    assert result.metadata["unverified_reason"] == "not_found"


def test_the_contradiction_rule_does_not_depend_on_argument_order():
    absent = _signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.OBSERVED,
                     reason="not_found")
    present = _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED,
                      reason="fingerprint_mismatch")
    assert detect_contradiction(present, absent) is not None


def test_corroborating_findings_are_not_reported_as_a_contradiction():
    """A removed rule. Escalation is the risk table's job, not this one.

    "Capability revoked but anomalous behaviour observed" was labelled a
    contradiction. The two agree with each other; calling that a
    contradiction put a false claim into the evidence record.
    """

    revoked = _signal(DiscrepancyType.CAPABILITY_REVOKED, Provenance.OBSERVED)
    anomaly = _signal(DiscrepancyType.BEHAVIOR_ANOMALY, Provenance.INFERRED,
                      confidence=0.6)
    assert detect_contradiction(revoked, anomaly) is None


def test_findings_about_different_agents_are_not_compared():
    absent = _signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.OBSERVED,
                     reason="not_found", agent="agent-1")
    present = _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED,
                      reason="fingerprint_mismatch", agent="agent-2")
    assert detect_contradiction(absent, present) is None


def test_nothing_unestablished_can_contradict_anything():
    """A missing registry is not evidence about the agent."""

    absent = _signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.UNKNOWN,
                     reason="not_found")
    present = _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED,
                      reason="fingerprint_mismatch")
    assert detect_contradiction(absent, present) is None


def test_an_unverified_identity_for_another_reason_is_not_a_contradiction():
    other = _signal(DiscrepancyType.IDENTITY_UNVERIFIED, Provenance.OBSERVED,
                    reason="key_unreadable")
    present = _signal(DiscrepancyType.IDENTITY_MISMATCH, Provenance.OBSERVED,
                      reason="fingerprint_mismatch")
    assert detect_contradiction(other, present) is None


# ----------------------------------------------------------------------
# Cached profiles
# ----------------------------------------------------------------------


def test_profiles_are_cached_per_agent_and_clearable():
    defense = _defense(_sdk())

    assert defense.get_profile("agent-1") is None

    first = defense.evaluate_agent("agent-1", now=_LATER)
    defense.evaluate_agent("agent-2", now=_LATER)

    assert defense.get_profile("agent-1") is first
    assert set(defense.get_all_profiles()) == {"agent-1", "agent-2"}

    defense.clear_profile("agent-1")
    assert defense.get_profile("agent-1") is None
    assert set(defense.get_all_profiles()) == {"agent-2"}

    defense.clear_all_profiles()
    assert defense.get_all_profiles() == {}


def test_a_cached_profile_cannot_be_edited_through_the_accessor():
    defense = _defense(_sdk())
    defense.evaluate_agent("agent-1", now=_LATER)

    defense.get_all_profiles().clear()

    assert defense.get_profile("agent-1") is not None


# ----------------------------------------------------------------------
# The boundary: a profile is evidence, never authority
# ----------------------------------------------------------------------


def _critical(sdk: FirewallSDK, cap: Capability) -> AgentSecurityProfile:
    """The worst profile this module can produce for ``cap``'s holder.

    The finding is a proven identity mismatch: factual, severe, and
    about the claim rather than the capability. Nothing in it bears on
    whether the capability is valid, so any movement it caused in
    :meth:`FirewallSDK.authorize` would be this module granting or
    removing authority.
    """

    profile = _defense(sdk, identity_registry=_identities()).evaluate_agent(
        "agent-1",
        claimed_identity={"key_fingerprint": "0" * 64},
        presented_capability=cap,
        now=_LATER,
    )

    assert profile.risk_level == "critical"
    assert profile.identity_verified is False
    return profile


def test_a_critical_profile_does_not_deny_a_request_policy_allows():
    sdk = _sdk()
    cap = _cap(sdk)

    before = sdk.authorize(cap, "payments.send", {"amount": 50})
    assert before.allowed

    _critical(sdk, cap)

    after = sdk.authorize(cap, "payments.send", {"amount": 50})
    assert after.allowed
    assert after.reason == before.reason


def test_a_critical_profile_does_not_allow_a_request_policy_denies():
    sdk = _sdk()
    cap = _cap(sdk)
    _critical(sdk, cap)

    result = sdk.authorize(cap, "payments.send", {"amount": 500})

    # The reason is asserted because an incidental denial -- expiry, a
    # tripped refusal, an untrusted issuer -- would pass a bare
    # ``not allowed`` while proving nothing about the constraint.
    assert not result.allowed
    assert result.reason == "constraint_denied"


def test_a_low_profile_does_not_allow_a_request_policy_denies():
    """The direction that matters.

    ``risk_level == "low"`` is the strongest reassurance this module can
    offer, and it is still not permission: the constraint on the
    capability decides. The forbidden shape is
    ``risk < threshold -> ALLOW``.
    """

    profile, sdk, cap = _clean()
    assert profile.risk_level == "low"
    assert profile.trust_score == 1.0

    # The allowed probe first: a denial trips ``RefusalState``, and a
    # refusal afterwards would prove nothing about the constraint.
    assert sdk.authorize(cap, "payments.send", {"amount": 50}).allowed

    denied = sdk.authorize(cap, "payments.send", {"amount": 500})

    assert not denied.allowed
    assert denied.reason == "constraint_denied"


def test_evaluation_does_not_revoke_what_it_finds_suspicious():
    """Analysis observes. Response is a separate, authorized act."""

    sdk = _sdk()
    cap = _cap(sdk)
    fingerprint = sdk.fingerprint(cap)

    _critical(sdk, cap)

    assert not sdk.revocation.is_revoked(fingerprint)


def test_the_authorization_path_does_not_import_this_module():
    """MODEL_NON_AUTHORITY, checked structurally.

    The verdict comparisons above can only cover the findings they
    construct. This covers every finding at once: a decision path that
    cannot see a profile cannot be moved by one.
    """

    import inspect

    import firewall.sdk

    assert "adversarial" not in inspect.getsource(firewall.sdk)
