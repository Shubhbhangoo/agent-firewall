"""v2.4 §10: attack the shipped Aegis, and pin what held.

The mission's adversarial list, worked through against the real
implementation rather than against a description of it. Races and
concurrent budget consumption live in
``tests/test_v2_4_aegis_concurrency.py``; delegation widening at the
attenuation predicate lives in ``tests/test_v2_4_attenuation_narrowing.py``;
the residual order and the evidenced edge live in
``tests/test_v2_4_aegis_state.py``. What is left is here: authority
resurrection, stale envelopes, simulation that disagrees with the boundary,
stale graph data, contradictory evidence, malformed state, the confused
deputy, serialization, numeric edges, time manipulation, recursive and deep
delegation, graph explosion, and pathological state as a denial-of-service
lever.

Two rules shape every test.

**The attack must be attempted, not described.** Each test performs the
hostile operation against the real objects and then asserts what came out.
A test that only checks a guard exists would pass against a guard wired to
nothing.

**The assertion is always about authority, never about tidiness.** Aegis is
allowed to end up with a state label that under-reports, a blast radius
that is incomplete, or a preflight that abstains. What it is not allowed to
do is produce an allow. So the closing assertion of nearly every test below
is a call to ``FirewallSDK.authorize()``.
"""

from __future__ import annotations

import math
import threading

import pytest

from firewall.aegis.blast import MAX_NODES, blast_radius
from firewall.aegis.controller import AegisController
from firewall.aegis.envelope import bottom_envelope
from firewall.aegis.preflight import (
    Impact,
    Recommendation,
    StageStatus,
    preflight,
)
from firewall.aegis.state import AegisState, IllegalTransition, canonical_allow_for
from firewall.capability import Capability, capability_fingerprint
from firewall.sdk import FirewallSDK
from firewall.simulation.report import UNCHANGED, CaseOutcome, SimulationReport

KEY_ID = "adversarial-key"


@pytest.fixture
def sdk():
    instance = FirewallSDK(aegis_enabled=True)
    instance.generate_key(KEY_ID)
    yield instance
    instance.close()


def _grant(sdk, *, agent="agent-a", amount_max=100, **kwargs):
    """Issue and register in one step. Returns ``(capability, fingerprint)``."""

    capability = sdk.issue(
        agent=agent,
        capability="payments.send",
        constraints={"amount_max": amount_max},
        **kwargs,
    )
    fingerprint = sdk.fingerprint(capability)
    sdk.aegis.register(
        fingerprint,
        agent_id=capability.agent_id,
        capability=capability.capability,
    )

    return capability, fingerprint


def _clean_simulation():
    """A real report whose one case is reproducible, faithful and unchanged.

    Built from :class:`~firewall.simulation.report.SimulationReport` and
    :class:`~firewall.simulation.report.CaseOutcome` rather than a stub,
    because a stub would let the simulation stage pass on a shape the
    simulator never emits. Used only where a test needs preflight to be as
    permissive as it is capable of being.
    """

    return SimulationReport(
        before={},
        after={},
        diff={},
        description=("no rule change",),
        outcomes=(
            CaseOutcome(
                case_id="case-1",
                action="payments.send",
                capability="payments.send",
                agent="agent-a",
                agents=("agent-a",),
                depth=0,
                change=UNCHANGED,
                before_allowed=True,
                after_allowed=True,
            ),
        ),
    )


# ======================================================================
# Authority resurrection
# ======================================================================


class TestAuthorityResurrection:
    """Nothing brings a withdrawn grant back."""

    def test_re_registering_a_revoked_grant_does_not_reset_it(self, sdk):
        capability, fingerprint = _grant(sdk)
        sdk.aegis.mark_revoked(fingerprint, reason="revoked")

        again = sdk.aegis.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        assert again.state is AegisState.REVOKED
        assert again.terminal is True

    def test_a_canonical_allow_cannot_lift_a_revoked_grant(self, sdk):
        """The strongest form: real evidence, and it still does not resurrect.

        The evidence is a genuine ``authorize()`` allow for this exact
        fingerprint -- the only object ``canonical_allow_for`` accepts -- and
        it is presented *after* Aegis latched ``REVOKED``. If evidence were
        sufficient on its own, this would move the grant.
        """

        capability, fingerprint = _grant(sdk)
        evidence = sdk.authorize(capability, "payments.send", {"amount": 10})

        assert evidence.allowed is True
        assert canonical_allow_for(fingerprint, evidence) is True

        sdk.aegis.mark_revoked(fingerprint, reason="revoked")
        sdk.aegis.observe_authorization(fingerprint, evidence)

        assert sdk.aegis.grant(fingerprint).state is AegisState.REVOKED

    def test_clearing_every_restriction_does_not_restore_a_revocation(self, sdk):
        """``clear`` widens by design; it does not reach the registry.

        The store is one enforcement channel and the revocation registry is
        another. An operator with store access must not be able to undo a
        revocation by emptying the store, so the closing assertion is the
        boundary's, not the store's.
        """

        capability, fingerprint = _grant(sdk)
        sdk.revoke(capability, reason="revoked at the registry")
        sdk.aegis.suspend(
            fingerprint,
            key="aegis:halt",
            reason="and suspended in Aegis",
        )

        removed = sdk.aegis.store.clear(fingerprint)

        assert removed
        assert sdk.aegis.store.restrictions_for(fingerprint) == ()

        outcome = sdk.authorize(capability, "payments.send", {"amount": 10})

        assert outcome.allowed is False
        assert outcome.reason == "capability_revoked"

    def test_lifting_after_revocation_does_not_reach_revalidating(self, sdk):
        capability, fingerprint = _grant(sdk)
        sdk.aegis.suspend(fingerprint, key="aegis:halt", reason="halted")
        sdk.aegis.mark_revoked(fingerprint, reason="then revoked")

        removed = sdk.aegis.lift(fingerprint, "aegis:halt")

        # The restriction really is gone -- ``lift`` is honest about what it
        # removed -- and the state stayed terminal anyway.
        assert removed
        assert sdk.aegis.grant(fingerprint).state is AegisState.REVOKED

    def test_a_stale_grant_object_cannot_be_replayed(self, sdk):
        """Grants are immutable, so a captured one is a *copy*, not a handle.

        The resurrection this forecloses is the obvious one: hold a
        reference to the grant as it was before the revocation and hand it
        back. ``transition`` returns a new object and the controller stores
        it, so the old reference describes a past state and mutating it is
        impossible.
        """

        _, fingerprint = _grant(sdk)
        before = sdk.aegis.grant(fingerprint)
        sdk.aegis.mark_revoked(fingerprint, reason="revoked")

        assert before.state is AegisState.ISSUED
        assert sdk.aegis.grant(fingerprint).state is AegisState.REVOKED

        with pytest.raises(Exception):
            object.__setattr__  # noqa: B018 - present; the setattr below is the test
            before.state = AegisState.ACTIVE  # type: ignore[misc]

        # And the captured object cannot walk forward either: it is already
        # past, and its own machine refuses the widening edge.
        with pytest.raises(IllegalTransition):
            sdk.aegis.grant(fingerprint).transition(
                AegisState.ACTIVE,
                "resurrect",
                at=0.0,
            )


# ======================================================================
# Stale envelopes
# ======================================================================


class TestStaleEnvelopes:
    def test_an_envelope_captured_before_a_revocation_is_not_authority(
        self, sdk
    ):
        capability, _ = _grant(sdk)
        stale = sdk.authority_envelope(capability)

        assert stale.bottom is False
        assert stale.may_admit("payments.send", {"amount": 10}) is True

        sdk.revoke(capability, reason="revoked after the snapshot")

        # The stale object still says the same thing -- it is a value, and
        # values do not update.
        assert stale.may_admit("payments.send", {"amount": 10}) is True
        # A freshly derived one does not.
        assert sdk.authority_envelope(capability).excludes() == "revoked"
        # And the boundary follows the world, not the snapshot.
        assert (
            sdk.authorize(capability, "payments.send", {"amount": 10}).reason
            == "capability_revoked"
        )

    def test_an_envelope_cannot_be_used_as_a_verdict(self, sdk):
        capability, _ = _grant(sdk)
        envelope = sdk.authority_envelope(capability)

        with pytest.raises(TypeError):
            bool(envelope)

        with pytest.raises(TypeError):
            if envelope:  # noqa: SIM103 - the raise is the assertion
                pass

    def test_restrictions_are_not_folded_into_the_envelope(self, sdk):
        """A documented incompleteness, pinned so it stays documented.

        ``authority_envelope`` describes the *capability*; Aegis restrictions
        are separate state, lifted separately. So an envelope can admit a
        request the boundary refuses. That is sound -- the envelope
        over-approximates, and ENVELOPE_SOUNDNESS only requires that what it
        *excludes* is denied -- but a reader who mistook it for the whole
        picture would draw the wrong conclusion, so the gap is a test.
        """

        capability, fingerprint = _grant(sdk)
        sdk.aegis.suspend(fingerprint, key="aegis:halt", reason="halted")

        envelope = sdk.authority_envelope(capability)

        assert envelope.may_admit("payments.send", {"amount": 10}) is True
        assert (
            sdk.authorize(capability, "payments.send", {"amount": 10}).allowed
            is False
        )

    def test_an_unresolvable_chain_yields_the_bottom_envelope(self, sdk):
        """Unknown is not wide. A chain that cannot be resolved admits nothing."""

        capability, _ = _grant(sdk)
        forged = Capability(
            agent_id=capability.agent_id,
            capability=capability.capability,
            constraints=dict(capability.constraints),
            issuer=capability.issuer,
            issued_at=capability.issued_at,
            expires_at=capability.expires_at,
            public_key=capability.public_key,
            signature=capability.signature,
            key_id=capability.key_id,
            tool=capability.tool,
            nonce=capability.nonce,
            parent_fingerprint="f" * 64,
        )

        envelope = sdk.authority_envelope(forged)

        assert envelope.bottom is True
        assert envelope.excludes("payments.send", {"amount": 1}) is not None
        assert (
            sdk.authorize(forged, "payments.send", {"amount": 1}).allowed
            is False
        )


# ======================================================================
# Simulation is not authority
# ======================================================================


class TestSimulationIsNotAuthority:
    def test_a_preflight_cannot_be_used_as_a_verdict(self):
        result = preflight("payments.send", {"amount": 1})

        with pytest.raises(TypeError):
            bool(result)

    def test_preflight_allow_does_not_survive_a_standing_restriction(self, sdk):
        """Preflight and the boundary disagree, and the boundary wins.

        Constructed so preflight is as permissive as it is *able* to be --
        every one of the six stages supplied and established -- and then a
        suspension is written after the analysis. Supplying all six matters:
        with any stage unavailable the recommendation is ``REVIEW`` and the
        test would pass for the wrong reason, proving only that preflight
        abstained rather than that a genuine ALLOW is inert.
        """

        capability, fingerprint = _grant(sdk)
        analysis = sdk.aegis.preflight(
            "payments.send",
            {"amount": 10},
            fingerprints=[fingerprint],
            envelope=sdk.authority_envelope(capability),
            chain_resolved=True,
            depth=1,
            blast=sdk.aegis.blast_radius(fingerprint),
            simulation=_clean_simulation(),
            evidence_findings=[],
        )

        assert analysis.recommendation is Recommendation.ALLOW
        assert analysis.established is True

        sdk.aegis.suspend(fingerprint, key="aegis:halt", reason="halted")

        outcome = sdk.authorize(capability, "payments.send", {"amount": 10})

        assert outcome.allowed is False
        assert outcome.reason == "aegis_suspended:aegis:halt"

    def test_preflight_deny_does_not_deny(self, sdk):
        """The other direction, which is the one that could hide a bypass.

        Analysis refusing while the boundary allows is not a bug: analysis is
        conservative and incomplete, and it has no channel to the decision.
        The test exists because a reader might expect a DENY recommendation
        to bind, and an implementation that made it bind would be the second
        authorization engine the design refuses to be.
        """

        capability, fingerprint = _grant(sdk)
        analysis = sdk.aegis.preflight(
            "payments.send",
            {"amount": 10},
            fingerprints=[fingerprint],
            envelope=bottom_envelope("analysis says no"),
            chain_resolved=False,
        )

        assert analysis.recommendation is not Recommendation.ALLOW
        assert (
            sdk.authorize(capability, "payments.send", {"amount": 10}).allowed
            is True
        )

    def test_nothing_established_is_not_allow(self):
        """``UNKNOWN`` does not become ``SAFE``.

        Called with no envelope, no chain facts, no blast radius and no
        evidence: every stage is unavailable. The recommendation must not be
        ALLOW, and the impact must not be a low one.
        """

        result = preflight("payments.send", {"amount": 1})

        assert result.recommendation is not Recommendation.ALLOW
        assert result.impact is not Impact.LOW_IMPACT
        assert result.established is False
        assert any(
            stage.status is StageStatus.UNAVAILABLE for stage in result.stages
        )

    def test_a_simulation_report_that_cannot_be_read_does_not_establish(self):
        for hostile in (object(), "allowed", {"safe": True}, 1, True):
            result = preflight(
                "payments.send",
                {"amount": 1},
                simulation=hostile,
            )

            assert result.recommendation is not Recommendation.ALLOW, hostile


# ======================================================================
# Stale and hostile graph data
# ======================================================================


class TestGraphData:
    def test_a_graph_that_raises_is_recorded_unanalyzable(self, sdk):
        """The *attribute lookup* is guarded, not only the call.

        A lazily-resolving or remote graph proxy raises from
        ``__getattr__``, so ``getattr(graph, "blast_radius", None)`` raises
        before any call is attempted. ``blast_radius`` documents that it
        never raises; before v2.4 that held for the call and not for the
        lookup.
        """

        class _Hostile:
            def reachable_from(self, *args, **kwargs):
                raise RuntimeError("graph unavailable")

            def __getattr__(self, name):
                raise RuntimeError("graph unavailable")

        _, fingerprint = _grant(sdk)
        radius = sdk.aegis.blast_radius(fingerprint, graph=_Hostile())

        # The failure is reported, not swallowed into a smaller radius.
        assert radius.unanalyzable
        assert radius.fingerprint == fingerprint
        assert [
            (item.kind, item.detail)
            for item in radius.unanalyzable
            if item.kind == "graph_error"
        ] == [("graph_error", "RuntimeError looking up blast_radius")]
        assert radius.complete is False

    def test_an_unanalyzable_radius_does_not_classify_as_low_impact(self, sdk):
        class _Hostile:
            def __getattr__(self, name):
                raise RuntimeError("graph unavailable")

        _, fingerprint = _grant(sdk)
        radius = sdk.aegis.blast_radius(fingerprint, graph=_Hostile())
        analysis = preflight(
            "payments.send",
            {"amount": 1},
            blast=radius,
        )

        assert analysis.impact is not Impact.LOW_IMPACT
        assert analysis.recommendation is not Recommendation.ALLOW

    def test_stale_lineage_edges_do_not_widen_anything(self, sdk):
        """An incomplete edge set understates reach -- and grants nothing.

        Blast radius is analysis (§6), so an out-of-date lineage makes it
        *less* informative, never more permissive. Pinned because the
        tempting shortcut -- treating a small radius as evidence of safety --
        is exactly the ``risk < threshold -> ALLOW`` shape the mission
        forbids.
        """

        capability, fingerprint = _grant(sdk)
        child = sdk.delegate(
            capability,
            sdk.active_key().private_key,
            delegatee="agent-child",
            constraints={"amount_max": 50},
        ).child
        child_fingerprint = sdk.fingerprint(child)

        # Deliberately not telling it about the edge that exists.
        radius = sdk.aegis.blast_radius(fingerprint, lineage_edges=())

        assert child_fingerprint not in radius.descendants

        # And the child is still bound by its parent's restriction, which is
        # enforcement rather than analysis.
        sdk.aegis.suspend(fingerprint, key="aegis:halt", reason="halted")
        assert (
            sdk.authorize(child, "payments.send", {"amount": 10}).reason
            == "aegis_suspended:aegis:halt"
        )


# ======================================================================
# Evidence: missing, stale, contradictory
# ======================================================================


class TestHostileEvidence:
    def test_another_capabilitys_allow_is_not_evidence(self, sdk):
        """The confused deputy, in evidence form.

        Both allows are genuine. Presenting one against the other's
        fingerprint must not move anything, which is why
        ``canonical_allow_for`` binds the trace's ``capability_id``.
        """

        first, first_fingerprint = _grant(sdk, agent="agent-a")
        _, second_fingerprint = _grant(sdk, agent="agent-b")

        borrowed = sdk.authorize(first, "payments.send", {"amount": 10})

        assert borrowed.allowed is True
        assert canonical_allow_for(second_fingerprint, borrowed) is False

        sdk.aegis.observe_authorization(second_fingerprint, borrowed)

        assert sdk.aegis.grant(second_fingerprint).state is AegisState.ISSUED
        assert sdk.aegis.grant(first_fingerprint).state is AegisState.ACTIVE

    def test_a_forged_verdict_shaped_object_is_not_evidence(self, sdk):
        class _LooksLikeAnAllow:
            allowed = True
            reason = "authorized"

            def __init__(self, fingerprint):
                self.trace = {"capability_id": fingerprint}

            def __bool__(self):
                return True

        _, fingerprint = _grant(sdk)
        forged = _LooksLikeAnAllow(fingerprint)

        assert canonical_allow_for(fingerprint, forged) is False

        sdk.aegis.observe_authorization(fingerprint, forged)

        assert sdk.aegis.grant(fingerprint).state is AegisState.ISSUED

    def test_evidence_findings_prevent_an_allow_recommendation(self):
        result = preflight(
            "payments.send",
            {"amount": 1},
            chain_resolved=True,
            depth=1,
            evidence_findings=["an attestation could not be verified"],
        )

        assert result.recommendation is not Recommendation.ALLOW

    def test_a_revalidation_without_evidence_stays_in_revalidating(self, sdk):
        """``REVALIDATING -> ACTIVE`` is the one widening edge, and it is gated.

        Time passing, further calls, and a denial all fail to supply what the
        edge needs. Only an allow for this fingerprint does.

        The denial is deliberately a ``namespace_denied`` rather than a
        ``constraint_denied``: a constraint denial is memoized into refusal
        state for the agent's whole action class, so the closing allow would
        come back ``refusal_state`` and the test would prove nothing about
        the edge. That memoization is v2.3 behaviour and is correct -- it
        subtracts authority -- so the test routes around it rather than
        asking for it to change.
        """

        capability, fingerprint = _grant(sdk)
        sdk.aegis.begin_revalidation(fingerprint, reason="re-asking")

        sdk.aegis.observe_authorization(fingerprint, None)
        sdk.aegis.observe_authorization(fingerprint, True)
        denial = sdk.authorize(capability, "email.send", {"amount": 10})
        assert denial.allowed is False
        assert denial.reason == "namespace_denied"
        sdk.aegis.observe_authorization(fingerprint, denial)

        assert sdk.aegis.grant(fingerprint).state is AegisState.REVALIDATING

        allow = sdk.authorize(capability, "payments.send", {"amount": 10})
        assert allow.allowed is True
        assert sdk.aegis.grant(fingerprint).state is AegisState.ACTIVE


# ======================================================================
# Malformed state
# ======================================================================


class _BrokenStore:
    """A restriction store whose every read raises."""

    def fingerprints(self):
        raise RuntimeError("store unreadable")

    def excludes(self, *args, **kwargs):
        raise RuntimeError("store unreadable")

    def any_suspended(self, *args, **kwargs):
        raise RuntimeError("store unreadable")

    def restrictions_for(self, *args, **kwargs):
        raise RuntimeError("store unreadable")

    def apply(self, *args, **kwargs):
        raise RuntimeError("store unreadable")

    def describe(self):
        raise RuntimeError("store unreadable")


class TestMalformedState:
    def test_an_unreadable_store_denies_rather_than_skipping_aegis(self):
        controller = AegisController(store=_BrokenStore())
        sdk = FirewallSDK(aegis=controller)

        try:
            sdk.generate_key(KEY_ID)
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            controller.register(
                fingerprint,
                agent_id="agent-a",
                capability="payments.send",
            )

            outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

            assert outcome.allowed is False
            assert outcome.reason.startswith("aegis_state_unavailable")
        finally:
            sdk.close()

    def test_a_controller_whose_tracked_raises_denies(self):
        class _Hostile(AegisController):
            def tracked(self):
                raise RuntimeError("state unreadable")

        controller = _Hostile()
        sdk = FirewallSDK(aegis=controller)

        try:
            sdk.generate_key(KEY_ID)
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )

            outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

            assert outcome.allowed is False
            assert outcome.reason == "aegis_state_unavailable"
        finally:
            sdk.close()

    def test_a_controller_whose_restriction_reason_raises_denies(self):
        """The gate's own read, not the store's.

        ``_gate_aegis`` documents that it is total, and a supplied
        controller -- ``FirewallSDK(aegis=...)`` accepts any object of the
        right shape -- is exactly where that promise gets tested. Before
        v2.4 this raised straight out of ``authorize()``: no decision, no
        flight record, no Aegis observation, and a caller left to invent a
        meaning for the exception.
        """

        class _Hostile(AegisController):
            def restriction_reason(self, fingerprints, action, request):
                raise RuntimeError("reason unreadable")

        controller = _Hostile()
        sdk = FirewallSDK(aegis=controller)

        try:
            sdk.generate_key(KEY_ID)
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            controller.register(
                fingerprint,
                agent_id="agent-a",
                capability="payments.send",
            )

            outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

            assert outcome.allowed is False
            assert outcome.reason == "aegis_state_unavailable:RuntimeError"
        finally:
            sdk.close()

    def test_a_commit_recheck_that_cannot_read_denies(self):
        """The re-read inside the transaction is guarded too.

        ``_gate_transaction`` re-reads suspension after the gate chain has
        passed, to close the window between the decision and the commit. An
        unguarded raise there is worse than one in ``_gate_aegis``: the
        request has already been accepted by every gate, so the exception
        escapes from the point where a caller is most likely to treat a
        crash as a transient error and retry.
        """

        class _HostileAtCommit(AegisController):
            def suspended_in(self, fingerprints):
                raise RuntimeError("unreadable at commit")

        controller = _HostileAtCommit()
        sdk = FirewallSDK(aegis=controller)

        try:
            sdk.generate_key(KEY_ID)
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            controller.register(
                fingerprint,
                agent_id="agent-a",
                capability="payments.send",
            )

            outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

            assert outcome.allowed is False
            assert (
                outcome.reason == "aegis_state_unavailable_at_commit:RuntimeError"
            )
        finally:
            sdk.close()

    @pytest.mark.parametrize(
        "hostile",
        [None, "", b"abcd", 0, 1.5, [], {}, object()],
    )
    def test_a_hostile_fingerprint_never_raises_out_of_the_read_path(
        self, sdk, hostile
    ):
        controller = sdk.aegis

        assert controller.restriction_reason(
            [hostile],
            "payments.send",
            {"amount": 1},
        ) in (None, "aegis_state_unavailable")
        assert controller.suspended_in([hostile]) is None
        assert controller.observe_authorization(hostile, None) is None
        assert controller.grant(hostile) is None

    def test_registering_a_hostile_fingerprint_is_refused_loudly(self, sdk):
        # The operator path raises; the authorization path never does. Both
        # halves of that contract are load-bearing, so both are checked.
        for hostile in (None, "", 0, object()):
            with pytest.raises((ValueError, TypeError)):
                sdk.aegis.register(
                    hostile,
                    agent_id="agent-a",
                    capability="payments.send",
                )

    def test_a_grant_is_not_a_verdict(self, sdk):
        _, fingerprint = _grant(sdk)

        with pytest.raises(TypeError):
            bool(sdk.aegis.grant(fingerprint))


# ======================================================================
# Confused deputy
# ======================================================================


class TestConfusedDeputy:
    def test_a_restriction_binds_the_fingerprint_it_names(self, sdk):
        """Two agents, same capability string, same constraints.

        Only the fingerprints differ, and the restriction must follow the
        fingerprint. A restriction keyed on the capability *name* would
        halt an unrelated agent -- or, in the other direction, let the
        restricted agent act through a sibling.
        """

        first, first_fingerprint = _grant(sdk, agent="agent-a")
        second, _ = _grant(sdk, agent="agent-b")

        sdk.aegis.suspend(
            first_fingerprint,
            key="aegis:halt",
            reason="only agent-a is halted",
        )

        assert (
            sdk.authorize(first, "payments.send", {"amount": 10}).allowed
            is False
        )
        assert (
            sdk.authorize(second, "payments.send", {"amount": 10}).allowed
            is True
        )

    def test_a_capability_from_another_sdk_is_refused(self):
        """A signature from a key this boundary does not trust is not authority."""

        theirs = FirewallSDK()
        mine = FirewallSDK()

        try:
            theirs.generate_key("their-key")
            mine.generate_key("my-key")

            foreign = theirs.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )

            outcome = mine.authorize(foreign, "payments.send", {"amount": 10})

            assert outcome.allowed is False
            assert outcome.reason in (
                "invalid_signature",
                "verification_error",
            )
        finally:
            theirs.close()
            mine.close()

    def test_a_child_cannot_act_with_its_parents_ceiling(self, sdk):
        parent, _ = _grant(sdk, amount_max=100)
        child = sdk.delegate(
            parent,
            sdk.active_key().private_key,
            delegatee="agent-child",
            constraints={"amount_max": 10},
        ).child

        assert (
            sdk.authorize(child, "payments.send", {"amount": 100}).allowed
            is False
        )
        assert (
            sdk.authorize(parent, "payments.send", {"amount": 100}).allowed
            is True
        )


# ======================================================================
# Serialization
# ======================================================================


class TestSerialization:
    def test_a_serialized_capability_is_not_a_capability(self, sdk):
        capability, _ = _grant(sdk)

        for shape in (
            capability.to_dict(),
            capability.to_json(),
            list(capability.to_dict().items()),
        ):
            outcome = sdk.authorize(shape, "payments.send", {"amount": 10})

            assert outcome.allowed is False
            assert outcome.reason == "invalid_capability"

    def test_a_mutated_constraint_dict_does_not_widen_authority(self, sdk):
        """``Capability`` is frozen but ``constraints`` is a mutable dict.

        So the field cannot be reassigned and the mapping *can* be edited in
        place. The signature covers the constraints, so the edit is detected
        -- but note where: the fingerprint changes too, which means the edit
        also slips out from under any Aegis restriction registered on the
        original. Both are checked, because the escape is only harmless as
        long as the cryptographic gate still refuses.
        """

        capability, fingerprint = _grant(sdk, amount_max=10)
        sdk.aegis.suspend(fingerprint, key="aegis:halt", reason="halted")

        capability.constraints["amount_max"] = 10**9
        mutated_fingerprint = capability_fingerprint(capability)

        # The restriction no longer matches -- and it does not need to.
        assert mutated_fingerprint != fingerprint

        outcome = sdk.authorize(capability, "payments.send", {"amount": 10**6})

        assert outcome.allowed is False
        assert outcome.reason in (
            "invalid_signature",
            "verification_error",
        )

    def test_a_reconstructed_capability_with_a_swapped_field_is_refused(
        self, sdk
    ):
        capability, _ = _grant(sdk, amount_max=10)

        forged = Capability(
            agent_id=capability.agent_id,
            capability=capability.capability,
            constraints={"amount_max": 10**9},
            issuer=capability.issuer,
            issued_at=capability.issued_at,
            expires_at=capability.expires_at,
            public_key=capability.public_key,
            signature=capability.signature,
            key_id=capability.key_id,
            tool=capability.tool,
            nonce=capability.nonce,
            parent_fingerprint=capability.parent_fingerprint,
        )

        outcome = sdk.authorize(forged, "payments.send", {"amount": 10**6})

        assert outcome.allowed is False
        assert outcome.reason in (
            "invalid_signature",
            "verification_error",
        )

    def test_describe_output_carries_no_cryptographic_material(self, sdk):
        capability, fingerprint = _grant(sdk)
        sdk.aegis.suspend(fingerprint, key="aegis:halt", reason="halted")

        rendered = repr(sdk.aegis.describe())

        assert capability.signature not in rendered
        assert capability.public_key not in rendered


# ======================================================================
# Numeric edge cases
# ======================================================================


class TestNumericEdges:
    @pytest.mark.parametrize(
        "amount",
        [
            float("nan"),
            float("inf"),
            float("-inf"),
            -1,
            -0.0,
            True,
            "10",
            None,
            10**400,
            [10],
            {"amount": 10},
        ],
    )
    def test_a_hostile_amount_is_never_allowed_past_a_ceiling(
        self, sdk, amount
    ):
        capability, _ = _grant(sdk, amount_max=10)

        outcome = sdk.authorize(
            capability,
            "payments.send",
            {"amount": amount},
        )

        # Every input must produce a decision rather than an exception. Two
        # of these used to produce one: ``10**400`` reached
        # ``math.isfinite`` in ``_check_constraints``, which converts to
        # float first and raises ``OverflowError`` -- so ``authorize()``
        # returned nothing, recorded no flight, and made no Aegis
        # observation.
        assert isinstance(outcome.allowed, bool)

        if isinstance(amount, bool):
            # A bool *is* an int in Python and both sides of the system order
            # it as one, so ``True`` is 1 and 1 is under a ceiling of 10.
            # The allow is deliberate: ``firewall/aegis/envelope.py`` records
            # that refusing bools is the boundary's call to make first,
            # because an envelope excluding what the boundary admits would
            # break ENVELOPE_SOUNDNESS in its unsound direction.
            assert outcome.allowed is True
            return

        must_deny = (
            # Not a number at all.
            not isinstance(amount, (int, float))
            # Unorderable. ``nan`` satisfies every bound by negation and
            # ``-inf`` is only "under" the ceiling by accident; neither is a
            # reading the ceiling can be applied to.
            or (isinstance(amount, float) and not math.isfinite(amount))
            # Over the ceiling. Compared directly: Python orders a
            # 400-digit int against 10 exactly, and ``float(10**400)``
            # would raise rather than answer.
            or amount > 10
        )

        if must_deny:
            assert outcome.allowed is False, amount

    def test_an_unorderable_amount_cannot_poison_a_budget(self, sdk):
        """The budget accumulator refuses what it cannot add.

        Deliberately issued *without* an ``amount_max``: with a ceiling
        present the constraint gate refuses first and the budget layer is
        never reached, so the test would pass without exercising the thing
        it names. Without one, the authorization succeeds on its own terms
        and the hostile amount arrives at the reservation.

        ``10**400`` is here because it used to raise ``OverflowError`` out
        of ``authorize_with_delegation_budget``'s ``float(amount)``.
        """

        capability = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={},
        )
        sdk.configure_delegation_budget(capability, max_total_amount=50.0)

        for hostile in (float("nan"), float("inf"), float("-inf"), 10**400):
            outcome = sdk.authorize_with_delegation_budget(
                capability,
                "payments.send",
                {"amount": hostile},
            )

            assert outcome.allowed is False, hostile
            assert outcome.reason == "invalid_budget_amount", hostile
            assert sdk.delegation_budget_total(capability) == 0.0, hostile

        # And the ceiling still binds. A NaN that had reached the total
        # would have made every later ``total + amount > max`` comparison
        # False and admitted an unbounded number of reservations.
        allowed = [
            sdk.authorize_with_delegation_budget(
                capability,
                "payments.send",
                {"amount": 10},
            ).allowed
            for _ in range(8)
        ]

        assert allowed == [True] * 5 + [False] * 3
        assert sdk.delegation_budget_total(capability) == 50.0

    def test_an_unusable_clock_excludes_rather_than_admits(self, sdk):
        capability, _ = _grant(sdk)
        envelope = sdk.authority_envelope(capability)

        for hostile in (float("nan"), float("inf"), float("-inf"), "now"):
            assert (
                envelope.excludes("payments.send", {"amount": 1}, hostile)
                == "clock_unusable"
            ), hostile


# ======================================================================
# Time manipulation
# ======================================================================


class TestTimeManipulation:
    def test_an_expired_capability_is_refused(self, sdk):
        """An expired grant is refused, and cannot be minted inverted.

        ``sign_capability`` refuses ``expires_at <= issued_at`` outright, so
        an expired capability can only exist by having aged: both stamps in
        the past, in order. Both halves are asserted, because the mint-time
        refusal is the reason the aged case is the only one that needs a
        gate.
        """

        import time

        now = time.time()

        with pytest.raises(ValueError):
            sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
                expires_at=now - 60.0,
            )

        capability = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
            issued_at=now - 120.0,
            expires_at=now - 60.0,
        )

        outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

        assert outcome.allowed is False
        assert outcome.reason == "expired"

    def test_a_capability_issued_in_the_future_is_refused(self, sdk):
        import time

        moment = time.time() + 3600.0
        capability = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
            issued_at=moment,
            expires_at=moment + 3600.0,
        )

        outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

        assert outcome.allowed is False
        assert outcome.reason == "not_yet_valid"

    def test_a_clock_that_runs_backwards_does_not_widen_aegis_state(self):
        """A rewound clock produces odd timestamps, never a wider grant.

        Aegis stamps transitions from its injected clock. If a rewind could
        reorder the recorded history into something the machine considers
        legal-but-different, the audit that reads history as data would be
        reading a fiction. The state machine does not consult timestamps at
        all -- transitions are checked on residual authority -- so the check
        is that the walk stays legal and the state stays put.
        """

        readings = iter([1_000.0, 900.0, 800.0, 700.0, 600.0, 500.0])
        controller = AegisController(clock=lambda: next(readings, 0.0))
        controller.register(
            "a" * 64,
            agent_id="agent-a",
            capability="payments.send",
        )

        controller.narrow(
            "a" * 64,
            key="aegis:ceiling",
            reason="narrowed",
            constraints={"amount_max": 5},
        )
        controller.suspend("a" * 64, key="aegis:halt", reason="halted")

        grant = controller.grant("a" * 64)

        assert grant.state is AegisState.SUSPENDED
        assert controller.history_findings() == ()

        with pytest.raises(IllegalTransition):
            controller.begin_revalidation("a" * 64, reason="widen me")

    @pytest.mark.parametrize(
        "elapsed",
        [
            float("nan"),
            -1.0,
            float("-inf"),
            10**400,
            "10",
            None,
            True,
            object(),
        ],
    )
    def test_an_unplaceable_elapsed_reading_takes_the_strongest_stage(
        self,
        elapsed,
    ):
        """A schedule that cannot be positioned is read at its most severe stage.

        ``stage_at`` is handed elapsed time rather than a clock, so it cannot
        be fooled directly -- but it can be handed a reading from a clock
        that moved backwards, or a value it cannot place at all. Every such
        reading resolves to :attr:`strongest_stage`, because a schedule
        whose position is unknown has not been shown to be in its permissive
        phase.

        ``10**400`` is here as a regression: it is mathematically finite and
        ordered, but ``float(10**400)`` raises ``OverflowError``, which used
        to escape ``stage_at`` and break the totality the docstring promises.
        """

        from firewall.aegis.decay import DecaySchedule, DecayStage

        schedule = DecaySchedule(
            narrow_after=10.0,
            suspend_after=20.0,
            constraints={"amount_max": 5},
        )

        assert schedule.strongest_stage is DecayStage.SUSPEND
        assert schedule.stage_at(elapsed) is DecayStage.SUSPEND

    def test_a_decay_schedule_that_cannot_be_placed_applies_its_strongest_stage(
        self,
    ):
        """The same rule, one layer up, in the sweep that writes restrictions.

        Constructs a state the public API does not produce -- a schedule with
        no grant behind it, so ``created_at`` is unknown and elapsed cannot
        be computed. It is reached through ``_schedules`` deliberately: this
        is the malformed-state case, and the assertion is that the sweep
        resolves it towards suspension rather than towards the permissive
        phase, and that a state move it could not make is *reported* rather
        than swallowed.
        """

        from firewall.aegis.decay import DecaySchedule

        controller = AegisController()
        schedule = DecaySchedule(
            narrow_after=10.0,
            suspend_after=20.0,
            constraints={"amount_max": 5},
        )
        controller._schedules["b" * 64] = schedule

        records = controller.apply_decay(now=1_000.0)

        assert len(records) == 1
        record = records[0]
        assert record.applied
        assert all(item.suspends for item in record.applied)
        # There is no grant to label, so the record reports no state either
        # side rather than inventing one. ``failures`` is empty and that is
        # correct: nothing failed. State is not an enforcement channel here.
        assert record.state_before is None
        assert record.state_after is None
        assert record.failures == ()
        # Enforcement is the half that matters, and it landed: the same read
        # ``_gate_transaction`` performs at commit now names this
        # fingerprint, with no tracked grant behind it.
        assert controller.grant("b" * 64) is None
        assert controller.suspended_in(["b" * 64]) is not None
        assert (
            controller.restriction_reason(
                ["b" * 64],
                "payments.send",
                {"amount": 1},
            )
            is not None
        )


# ======================================================================
# Recursive and deep delegation
# ======================================================================


class TestDeepDelegation:
    def test_a_deep_chain_resolves_and_stays_narrow(self, sdk):
        private_key = sdk.active_key().private_key
        current, _ = _grant(sdk, amount_max=100)
        depth = 40

        for index in range(depth):
            current = sdk.delegate(
                current,
                private_key,
                delegatee=f"agent-{index}",
                constraints={"amount_max": 100 - index},
            ).child

        envelope = sdk.authority_envelope(current)

        assert envelope.depth == depth + 1

        # The allow is asserted *first*, deliberately. The denial below is a
        # ``constraint_denied``, which v2.3 memoizes into refusal state for
        # the agent's whole action class -- so once it has been asked, every
        # later request from this agent for this action comes back
        # ``refusal_state`` regardless of amount. Asking in the other order
        # would look like a failure of chain resolution.
        assert (
            sdk.authorize(
                current,
                "payments.send",
                {"amount": 100 - depth + 1},
            ).allowed
            is True
        )

        # The tip is the narrowest member, not the widest.
        over = sdk.authorize(current, "payments.send", {"amount": 100})
        assert over.allowed is False
        assert over.reason == "constraint_denied"

        # And the memoization, pinned where it was discovered: the safe
        # direction, but a real availability lever an operator must know
        # about.
        after = sdk.authorize(
            current,
            "payments.send",
            {"amount": 100 - depth + 1},
        )
        assert after.allowed is False
        assert after.reason == "refusal_state"

    def test_a_depth_ceiling_refuses_the_deep_chain(self, sdk):
        private_key = sdk.active_key().private_key
        current, _ = _grant(sdk, amount_max=100)

        for index in range(10):
            current = sdk.delegate(
                current,
                private_key,
                delegatee=f"agent-{index}",
                constraints={"amount_max": 50},
            ).child

        sdk.max_delegation_depth = 3
        outcome = sdk.authorize(current, "payments.send", {"amount": 10})

        assert outcome.allowed is False
        assert outcome.reason == "delegation_depth_exceeded"

    def test_a_self_parented_capability_terminates(self, sdk):
        """A capability claiming itself as its own parent must not loop.

        The fingerprint depends on ``parent_fingerprint``, so a genuinely
        self-referential capability cannot be constructed by signing -- the
        value would have to be known before it is computed. What *can* be
        constructed is a forged one, and the resolver must refuse it in
        bounded time rather than walking a cycle.
        """

        capability, fingerprint = _grant(sdk)
        forged = Capability(
            agent_id=capability.agent_id,
            capability=capability.capability,
            constraints=dict(capability.constraints),
            issuer=capability.issuer,
            issued_at=capability.issued_at,
            expires_at=capability.expires_at,
            public_key=capability.public_key,
            signature=capability.signature,
            key_id=capability.key_id,
            tool=capability.tool,
            nonce=capability.nonce,
            parent_fingerprint=fingerprint,
        )

        finished = threading.Event()
        outcome: list = []

        def attempt():
            outcome.append(
                sdk.authorize(forged, "payments.send", {"amount": 1})
            )
            finished.set()

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        finished.wait(timeout=20)

        assert finished.is_set(), "chain resolution did not terminate"
        assert outcome[0].allowed is False


# ======================================================================
# Graph explosion and pathological state
# ======================================================================


class TestPathologicalState:
    def test_blast_radius_is_bounded_by_its_node_cap(self, sdk):
        """A hostile lineage cannot make analysis run forever.

        ``MAX_NODES`` bounds the walk, and exceeding it is *reported* rather
        than silently truncated -- an unbounded analysis is a denial of
        service, and a silently truncated one is a false reassurance.

        The edges are ``(child, parent)``, matching
        ``DelegationLineage.snapshot()``: every one of these names ``root``
        as its parent, so the walk has ``MAX_NODES + 500`` children to take
        at depth 1.
        """

        _, root = _grant(sdk)
        edges = [(f"{index:064x}", root) for index in range(MAX_NODES + 500)]

        radius = blast_radius(root, lineage_edges=edges)

        assert len(radius.descendants) <= MAX_NODES
        assert radius.unanalyzable
        assert {item.kind for item in radius.unanalyzable} >= {"node_cap"}
        # Incompleteness is the point: a caller must not read this small
        # ``reach`` as bounded impact.
        assert radius.complete is False

    def test_a_restriction_flood_escalates_to_one_suspension(self, sdk):
        """The per-grant cap turns unbounded growth into a denial.

        A caller that can write restrictions could otherwise grow the set
        without limit and make every later read expensive. The store caps the
        set and escalates to a single suspension instead: memory is bounded,
        and the trade is availability for the grant, which is the safe
        direction.
        """

        capability, fingerprint = _grant(sdk)

        for index in range(200):
            sdk.aegis.store.apply(
                __import__(
                    "firewall.aegis.restriction",
                    fromlist=["narrow"],
                ).narrow(
                    fingerprint,
                    key=f"aegis:flood:{index}",
                    reason="flooding",
                    constraints={"amount_max": index + 1},
                )
            )

        restrictions = sdk.aegis.store.restrictions_for(fingerprint)

        assert len(restrictions) == 1
        assert restrictions[0].suspends is True

        outcome = sdk.authorize(capability, "payments.send", {"amount": 1})

        assert outcome.allowed is False
        assert outcome.reason.startswith("aegis_suspended")

    def test_many_grants_stay_auditable(self, sdk):
        controller = sdk.aegis

        for index in range(500):
            controller.register(
                f"{index:064x}",
                agent_id=f"agent-{index}",
                capability="payments.send",
            )

        assert controller.history_findings() == ()
        assert len(controller.grants()) == 500
        # And describing the whole estate terminates and stays a plain dict.
        assert isinstance(controller.describe(), dict)

    def test_an_enormous_request_payload_does_not_raise(self, sdk):
        capability, _ = _grant(sdk, amount_max=10)
        payload = {"amount": 1, "notes": ["x" * 512 for _ in range(2_000)]}

        outcome = sdk.authorize(capability, "payments.send", payload)

        assert isinstance(outcome.allowed, bool)

    def test_a_deeply_nested_request_payload_does_not_raise(self, sdk):
        capability, _ = _grant(sdk, amount_max=10)

        nested: dict = {"amount": 1}
        cursor = nested
        for _ in range(200):
            cursor["inner"] = {}
            cursor = cursor["inner"]

        outcome = sdk.authorize(capability, "payments.send", nested)

        assert isinstance(outcome.allowed, bool)
