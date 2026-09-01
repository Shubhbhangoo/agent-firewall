"""Tests for the v2.2 deception/integrity engine.

The engine's whole value is that it reports disagreement between
independent claims *without* resolving it, and reports "unknown" when it
cannot establish a fact. Both of those are fail-closed properties, so
they are tested as security behaviour rather than as formatting.

The engine is never an authorization authority. It produces
``IntegrityReport`` evidence; ``FirewallSDK.authorize`` remains the only
thing that decides. The last test in this file pins that.
"""

from __future__ import annotations

import pytest

from firewall.deception import (
    ClaimStatus,
    ClaimType,
    DeceptionIntegrityEngine,
)
from firewall.ident import IdentityRegistry
from firewall.posture import PostureEngine
from firewall.sdk import FirewallSDK
from firewall.task import TaskRegistry


def _identities() -> IdentityRegistry:
    registry = IdentityRegistry()
    registry.create("agent-a")
    return registry


def _sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key("k")
    return sdk


def _engine(
    sdk: FirewallSDK,
    *,
    identity: IdentityRegistry | None = None,
    tasks: TaskRegistry | None = None,
    posture: PostureEngine | None = None,
) -> DeceptionIntegrityEngine:
    return DeceptionIntegrityEngine(
        sdk,
        identity_registry=identity,
        task_registry=tasks,
        posture_engine=posture,
    )


# ----------------------------------------------------------------------
# Unknown is not trusted
# ----------------------------------------------------------------------


def test_unknown_agent_is_not_reported_as_high_integrity():
    """An agent nothing is known about must not read as trustworthy.

    The failure this pins is a fail-open one: with no claims every
    counter is zero, so a ladder that checks only the populated cases
    falls through to its most favourable rung.
    """

    engine = _engine(_sdk())

    report = engine.assess_integrity("never-seen")

    assert report.claims == ()
    assert report.overall_integrity == "unknown"


def test_unknown_posture_does_not_count_as_a_verified_fact():
    """``PostureEngine`` answers for every agent, including unknown ones.

    ``state()`` returns the ``"unknown"`` posture rather than raising, so
    an agent the engine has never seen still yields one posture claim.
    That claim must not be VERIFIED -- otherwise the single synthesised
    answer is the only evidence in the report and it reads as health.
    """

    engine = _engine(_sdk(), posture=PostureEngine())

    report = engine.assess_integrity("never-seen")

    postures = [
        claim
        for claim in report.claims
        if claim.claim_type == ClaimType.POSTURE
    ]

    assert len(postures) == 1
    assert postures[0].content["posture"] == "unknown"
    assert postures[0].status == ClaimStatus.UNKNOWN
    assert report.overall_integrity == "unknown"


def test_high_integrity_requires_every_claim_verified():
    """One unknown claim caps the report below ``high``."""

    identity = _identities()
    sdk = _sdk()
    sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    engine = _engine(sdk, identity=identity, posture=PostureEngine())

    report = engine.assess_integrity("agent-a")

    assert report.unknown_claims == 1  # the unknown posture
    assert report.verified_claims >= 2
    assert report.contradicted_claims == 0
    assert report.overall_integrity == "medium"


# ----------------------------------------------------------------------
# Contradiction detection
# ----------------------------------------------------------------------


def test_revoked_identity_with_live_capability_is_a_contradiction():
    """Authority must not outlive the principal it was issued to.

    The identity registry is the only authority on whether an agent's
    identity is usable. A capability that is still un-revoked under a
    revoked identity is a disagreement between two independent sources,
    and the engine must say so.
    """

    identity = _identities()
    sdk = _sdk()
    sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    engine = _engine(sdk, identity=identity)

    clean = engine.assess_integrity("agent-a")
    assert clean.contradictions == ()

    identity.revoke("agent-a")
    report = engine.assess_integrity("agent-a")

    assert len(report.contradictions) == 1
    contradiction = report.contradictions[0]
    assert contradiction.severity == "critical"
    assert "revoked" in contradiction.description
    assert report.overall_integrity == "low"


def test_active_identity_with_live_capability_is_not_a_contradiction():
    """The normal case must stay quiet.

    The rule this replaced compared a capability claim's ``agent_id``
    against the identity's, but capability claims are collected per
    agent and never carry that key -- so the comparison was vacuously
    true and emitted a ``critical`` finding for every capability held.
    A detector that fires on the healthy path has no signal.
    """

    identity = _identities()
    sdk = _sdk()
    for index in range(3):
        sdk.issue(
            agent="agent-a",
            capability=f"tool.call.{index}",
            constraints={"amount_max": 10},
        )

    engine = _engine(sdk, identity=identity)

    report = engine.assess_integrity("agent-a")

    assert report.contradictions == ()
    assert report.overall_integrity == "high"


def test_revoked_capability_alone_is_not_a_contradiction():
    """Revocation working as intended is agreement, not disagreement."""

    identity = _identities()
    sdk = _sdk()
    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    sdk.revoke(capability)

    engine = _engine(sdk, identity=identity)

    report = engine.assess_integrity("agent-a")

    assert report.contradictions == ()


def test_contradictions_are_reported_not_resolved():
    """The engine records both sides and changes neither claim's source.

    "Does not resolve contradictions by guessing" is the module's stated
    contract. Concretely: a contradicted claim keeps its own provenance
    and its own ``source``, and gains only the cross-references.
    """

    identity = _identities()
    sdk = _sdk()
    sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    engine = _engine(sdk, identity=identity)
    identity.revoke("agent-a")

    report = engine.assess_integrity("agent-a")
    contradiction = report.contradictions[0]

    assert contradiction.resolved is False
    assert contradiction.resolution == ""

    by_id = {claim.claim_id: claim for claim in report.claims}
    accuser = by_id[contradiction.claim_a.claim_id]
    accused = by_id[contradiction.claim_b.claim_id]

    assert accuser.source == "identity_registry"
    assert accused.source == "capability_registry"
    assert accused.status == ClaimStatus.CONTRADICTED
    assert accuser.claim_id in accused.contradicted_by
    assert accused.claim_id in accuser.contradicts


# ----------------------------------------------------------------------
# Collectors must not fabricate an empty answer
# ----------------------------------------------------------------------


def test_task_claims_are_actually_collected():
    """The task collector must produce claims when tasks exist.

    It previously read ``task.parent_task_id`` -- ``Task`` has
    ``parent_task`` -- inside ``except Exception: pass``, so it always
    returned zero claims and the report was indistinguishable from an
    agent with no tasks at all.
    """

    identity = _identities()
    tasks = TaskRegistry(identity_registry=identity)
    task = tasks.create(
        agent_id="agent-a",
        permissions={"allowed_actions": ["read"]},
    )

    engine = _engine(_sdk(), identity=identity, tasks=tasks)

    report = engine.assess_integrity("agent-a")
    task_claims = [
        claim
        for claim in report.claims
        if claim.claim_type == ClaimType.TASK
    ]

    assert len(task_claims) == 1
    assert task_claims[0].content["task_id"] == task.task_id
    assert task_claims[0].content["parent_task"] is None
    assert task_claims[0].status == ClaimStatus.VERIFIED


def test_identity_and_posture_collectors_require_injection():
    """The registries are injected, never read off the SDK.

    ``FirewallSDK`` does not own the identity, task or posture
    registries, so the earlier ``hasattr(self._sdk, ...)`` form was
    always false and three collectors could never fire. Injection is
    also what keeps this engine outside the SDK's control plane, which
    CONTROL_PLANE_INTEGRITY requires.
    """

    identity = _identities()
    sdk = _sdk()

    without = _engine(sdk).assess_integrity("agent-a")
    assert not [
        claim
        for claim in without.claims
        if claim.claim_type == ClaimType.IDENTITY
    ]

    with_injection = _engine(sdk, identity=identity).assess_integrity(
        "agent-a"
    )
    assert [
        claim
        for claim in with_injection.claims
        if claim.claim_type == ClaimType.IDENTITY
    ]


# ----------------------------------------------------------------------
# Not an authorization authority
# ----------------------------------------------------------------------


def test_integrity_report_does_not_decide_authorization():
    """A ``low`` integrity report neither grants nor removes authority.

    ``FirewallSDK.authorize`` is the only decision point. The engine's
    output is evidence a caller may act on; it is not consulted by the
    gate chain and cannot change a verdict on its own.
    """

    identity = _identities()
    sdk = _sdk()
    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    engine = _engine(sdk, identity=identity)
    identity.revoke("agent-a")

    report = engine.assess_integrity("agent-a")
    assert report.overall_integrity == "low"

    # The capability itself was never revoked, so authorize still
    # allows: the integrity finding did not silently deny.
    allowed = sdk.authorize(
        capability,
        action="payments.send",
        request={"amount": 10},
    )
    assert allowed.allowed is True

    # And a real revocation still denies, with no help from the engine.
    sdk.revoke(capability)
    denied = sdk.authorize(
        capability,
        action="payments.send",
        request={"amount": 10},
    )
    assert denied.allowed is False
