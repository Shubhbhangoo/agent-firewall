"""v2.4: the Aegis controller -- lifecycle, execution, decay, totality.

The controller is the only mutable Aegis state, and the only object the
SDK holds. Three properties are load-bearing enough to be tested
separately from the state machine they sit on:

**Authority flows one way.** ``observe_authorization`` is the only method
that supplies evidence for the one widening edge, and it consumes a
verdict the boundary already produced. Every test that moves a grant up
the residual order here goes through a real ``FirewallSDK.authorize()``.

**State is not an enforcement channel.** ``SUSPENDED`` denies because
``suspend`` writes a suspending restriction, not because the state says
so. So every method that moves a grant into a restricted state is checked
for the matching restriction, and a state move that is refused must leave
the restriction standing -- removing it to keep the bookkeeping tidy would
widen authority.

**The authorization path never raises.** ``restriction_reason``,
``suspended_in``, ``observe_authorization`` and ``execute`` are total: a
broken store, a hostile argument or a raising hook produces a recorded
failure and a closed decision, not an exception into the gate chain.
"""

from __future__ import annotations

import pytest

from firewall.aegis.controller import (
    NARROW_KEY_PREFIX,
    SUSPEND_KEY_PREFIX,
    AegisController,
    ExecutionRecord,
)
from firewall.aegis.decay import DecaySchedule, DecayStage, stages_are_monotone
from firewall.aegis.response import (
    AdaptiveResponse,
    Classification,
    Contribution,
    SecurityContextSnapshot,
    classify,
)
from firewall.aegis.restriction import suspend as build_suspend
from firewall.aegis.state import AegisState, IllegalTransition
from firewall.continuous_auth import RevalidationTrigger
from firewall.sdk import FirewallSDK

FINGERPRINT = "a" * 64
OTHER = "b" * 64


class _Clock:
    """A hand-driven clock, so decay is tested without sleeping."""

    def __init__(self, now: float = 1_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _controller(**kwargs) -> AegisController:
    controller = AegisController(**kwargs)
    controller.register(
        FINGERPRINT,
        agent_id="agent-a",
        capability="payments.send",
    )

    return controller


def _classification(
    response: AdaptiveResponse,
    *,
    trigger: str = "environment_changed",
) -> Classification:
    """A hand-built classification, to drive one executor path at a time.

    ``classify`` is exercised on its own below. Constructing the input
    here keeps the executor tests from depending on which trigger happens
    to map to which response.
    """

    return Classification(
        response=response,
        trigger=trigger,
        contributions=(
            Contribution(
                rule="test",
                response=response,
                detail=f"driving the {response.value} path",
            ),
        ),
    )


def _snapshot(**overrides) -> SecurityContextSnapshot:
    base = dict(
        timestamp=1_000.0,
        capability_fingerprint=FINGERPRINT,
        agent_id="agent-a",
        action="payments.send",
        request_hash="h",
        identity_status="verified",
        identity_version=1,
        capability_revoked=False,
        capability_expired=False,
        delegation_chain_valid=True,
        delegation_depth=1,
        max_delegation_depth=3,
        posture="normal",
        trust_findings=0,
        risk_level="low",
        policy_version="v1",
        environment="{}",
        provenance_state="observed",
        incident_active=False,
    )
    base.update(overrides)

    return SecurityContextSnapshot(**base)


# ======================================================================
# Registration
# ======================================================================


class TestRegistration:
    def test_a_registered_grant_starts_issued(self):
        controller = AegisController()
        grant = controller.register(
            FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
        )

        assert grant.state is AegisState.ISSUED
        assert controller.tracked() is True

    def test_a_fresh_controller_tracks_nothing(self):
        # The gate abstains cheaply on this, so a deployment that never
        # used Aegis gets the v2.3 decision sequence unchanged.
        assert AegisController().tracked() is False

    def test_re_registering_does_not_reset_state(self):
        """Re-registration is idempotent, and that is a security property.

        A revoked grant that could be re-registered into ``ISSUED`` would
        be an authority resurrection with extra steps -- and registration
        is the one Aegis entry point a caller can reach without holding any
        evidence at all.
        """

        controller = _controller(revoke_hook=lambda fingerprint: None)
        controller.execute(FINGERPRINT, _classification(AdaptiveResponse.REVOKE))

        assert controller.grant(FINGERPRINT).state is AegisState.REVOKED

        again = controller.register(
            FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
        )

        assert again.state is AegisState.REVOKED

    def test_an_empty_fingerprint_is_refused(self):
        # The operator path raises: registering nothing and being told it
        # worked would leave a caller believing Aegis is watching.
        for bad in ("", None, 0):
            with pytest.raises(ValueError):
                AegisController().register(
                    bad,
                    agent_id="agent-a",
                    capability="payments.send",
                )

    def test_grants_returns_a_copy(self):
        controller = _controller()
        snapshot = controller.grants()
        snapshot.clear()

        assert controller.grant(FINGERPRINT) is not None

    def test_an_unknown_fingerprint_has_no_grant(self):
        assert _controller().grant(OTHER) is None


# ======================================================================
# observe_authorization: the only evidenced path
# ======================================================================


class TestObserveAuthorization:
    def test_a_canonical_allow_moves_issued_to_active(self):
        sdk = FirewallSDK(aegis_enabled=True)
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)

            # Registration is explicit: ``issue`` does not enrol a grant in
            # Aegis, so an SDK with a controller still tracks only what an
            # operator asked it to track.
            sdk.aegis.register(
                fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
            )

            # The SDK observes for itself on every outcome, so the grant is
            # ACTIVE by the time authorize returns.
            assert sdk.aegis.grant(fingerprint).state is AegisState.ISSUED

            allow = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10},
            )

            assert allow.allowed is True
            assert sdk.aegis.grant(fingerprint).state is AegisState.ACTIVE
        finally:
            sdk.close()

    def test_a_denial_records_nothing(self):
        """An ordinary denial is the system working, not a change in standing.

        Suspending on a denial is the tempting mistake: it would make one
        over-ceiling request escalate into a restriction that outlives the
        request, so a caller probing its own limits would lock itself out.
        """

        sdk = FirewallSDK(aegis_enabled=True)
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            sdk.aegis.register(
                fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
            )

            denied = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10_000},
            )

            assert denied.allowed is False
            grant = sdk.aegis.grant(fingerprint)
            assert grant.state is AegisState.ISSUED
            assert grant.history == ()
        finally:
            sdk.close()

    def test_an_unknown_fingerprint_is_ignored(self):
        assert _controller().observe_authorization(OTHER, True) is None

    def test_a_non_verdict_does_not_move_the_grant(self):
        """``ISSUED -> ACTIVE`` needs evidence too. Regression, v2.4.

        ``AegisGrant.transition`` demands a canonical allow only on an edge
        that *widens*, and ``ISSUED -> ACTIVE`` has equal residual authority
        -- so it was legal unconditionally and the ``evidence`` argument was
        never read. Any object at all relabelled the grant ``ACTIVE``.

        The residual order is not the whole guarantee, because ``ACTIVE`` is
        a claim as well as a level: ``state.py`` defines it as "at least one
        canonical allow observed". ``observe_authorization`` therefore checks
        the evidence itself, before either move.
        """

        controller = _controller()

        for hostile in (
            True,
            1,
            "authorized",
            {"allowed": True},
            None,
            object(),
        ):
            grant = controller.observe_authorization(FINGERPRINT, hostile)

            assert grant is not None
            assert grant.state is AegisState.ISSUED, hostile
            assert grant.history == (), hostile

    def test_a_real_denial_does_not_move_the_grant(self):
        """The SDK observes every outcome, not only allows. Regression, v2.4.

        ``_observe_aegis`` passes the result of every gate, so a genuine
        ``AuthorizationResult`` that denied reached the ISSUED edge and
        relabelled the grant ``ACTIVE`` -- the opposite of what
        ``observe_authorization`` documents. This is the same defect as
        ``test_a_non_verdict_does_not_move_the_grant``, minimized to the case
        the SDK actually produces rather than a hostile object.
        """

        sdk = FirewallSDK()
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            denied = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10_000},
            )
        finally:
            sdk.close()

        assert denied.allowed is False

        controller = _controller()
        grant = controller.observe_authorization(FINGERPRINT, denied)

        assert grant.state is AegisState.ISSUED
        assert grant.history == ()

    def test_it_is_total_on_a_hostile_fingerprint(self):
        # It runs inside the authorization path, where raising would turn
        # an unauthorized request into an exception with no verdict.
        controller = _controller()

        for bad in (None, "", 0, [], object()):
            assert controller.observe_authorization(bad, True) is None

    def test_it_does_not_move_a_restricted_grant(self):
        """A restricted grant needs its restriction lifted first.

        Otherwise a single allow -- which the gate would have to have
        produced *despite* the restriction -- would clear a narrowing
        nobody decided to clear.
        """

        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:test",
            reason="narrowed",
            constraints={"amount_max": 1},
        )

        sdk = FirewallSDK()
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            allow = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10},
            )
        finally:
            sdk.close()

        grant = controller.observe_authorization(FINGERPRINT, allow)

        # Refused twice over: the state is NARROWED rather than ISSUED or
        # REVALIDATING, and the allow names a different capability anyway.
        assert grant.state is AegisState.NARROWED


# ======================================================================
# Restrictions, not states, are what deny
# ======================================================================


class TestRestrictionsEnforce:
    def test_a_narrowing_is_written_and_enforced(self):
        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:test",
            reason="over budget",
            constraints={"amount_max": 5},
        )

        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 50},
            )
            is not None
        )
        # Within the narrowed ceiling, Aegis has no objection -- and "no
        # objection" is not an allow, it is the remaining gates still
        # running.
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 1},
            )
            is None
        )

    def test_a_suspension_excludes_everything(self):
        controller = _controller()
        controller.suspend(
            FINGERPRINT,
            key="aegis:test",
            reason="incident opened",
        )

        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 1},
            )
            is not None
        )

    def test_a_refused_state_move_leaves_the_restriction_standing(self):
        """The restriction survives when the transition does not.

        Narrowing a suspended grant is an illegal state move -- residual
        authority would increase. The narrowing itself can only subtract,
        so it stays applied; removing it to keep the state tidy would widen
        authority to preserve bookkeeping.
        """

        controller = _controller()
        controller.suspend(
            FINGERPRINT,
            key="aegis:suspend-first",
            reason="suspended",
        )

        with pytest.raises(IllegalTransition):
            controller.narrow(
                FINGERPRINT,
                key="aegis:narrow-after",
                reason="narrowed after suspension",
                constraints={"amount_max": 5},
            )

        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_lifting_lands_in_revalidating_and_not_active(self):
        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:test",
            reason="narrowed",
            constraints={"amount_max": 5},
        )
        removed = controller.lift(FINGERPRINT, "aegis:test")

        assert removed
        assert controller.grant(FINGERPRINT).state is AegisState.REVALIDATING
        # The obstacle is gone, and standing is not restored: only a
        # canonical allow can do that.
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 50},
            )
            is None
        )

    def test_lifting_an_unknown_key_removes_nothing(self):
        """A phantom lift is refused. Regression, v2.4.

        ``lift`` used to move the grant to ``REVALIDATING`` recording
        ``lifted="aegis:other"`` even though the store removed nothing --
        defeating the exact rule ``state.py`` gives for LIFT_EDGES, that
        naming the restriction stops "a caller [clearing] a restriction it
        does not know exists". The real narrowing stayed in the store while
        the grant sat on the launch pad for the one widening edge, so the
        next canonical allow inside the narrowing would have produced an
        ``ACTIVE`` grant that was still restricted.
        """

        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:test",
            reason="narrowed",
            constraints={"amount_max": 5},
        )

        assert controller.lift(FINGERPRINT, "aegis:other") == ()
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 50},
            )
            is not None
        )

    def test_a_partial_lift_does_not_reach_revalidating(self):
        """One key of two lifted leaves the grant restricted. Regression, v2.4.

        ``REVALIDATING`` is the launch pad for the only edge that widens,
        and ``state.py`` defines ``ACTIVE`` as a canonical allow with *no
        restriction*. A grant that still carries a narrowing can be allowed
        inside it, so a lift that clears one of two restrictions must not
        put the grant one evidenced allow away from ``ACTIVE``.
        """

        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:one",
            reason="narrowed by the first rule",
            constraints={"amount_max": 5},
        )
        controller.narrow(
            FINGERPRINT,
            key="aegis:two",
            reason="narrowed by the second rule",
            constraints={"amount_max": 2},
        )

        assert len(controller.lift(FINGERPRINT, "aegis:one")) == 1
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 3},
            )
            is not None
        )

        # Clearing the last one is what earns REVALIDATING.
        assert len(controller.lift(FINGERPRINT, "aegis:two")) == 1
        assert controller.grant(FINGERPRINT).state is AegisState.REVALIDATING

    def test_lifting_a_narrowing_under_a_suspension_stays_suspended(self):
        """The state follows the store down, never up. Regression, v2.4.

        A grant narrowed and then suspended is ``SUSPENDED``; lifting only
        the narrowing must not report a grant closer to standing than the
        store enforces. The reverse correction is impossible by
        construction, because ``SUSPENDED -> NARROWED`` widens and the
        machine refuses it.
        """

        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:narrow",
            reason="narrowed",
            constraints={"amount_max": 5},
        )
        controller.suspend(
            FINGERPRINT,
            key="aegis:halt",
            reason="suspended",
        )

        assert len(controller.lift(FINGERPRINT, "aegis:narrow")) == 1
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_a_surviving_suspension_pulls_a_narrowed_grant_down(self):
        """Lifting into a suspension reduces the state rather than holding it.

        The suspension can be written while the grant is ``NARROWED`` and
        the state move refused -- ``narrow``/``suspend`` write the
        restriction first on purpose -- so the store can enforce more than
        the state claims. A lift is the moment that discrepancy is
        observable, and it resolves downwards.
        """

        controller = _controller()
        controller.narrow(
            FINGERPRINT,
            key="aegis:narrow",
            reason="narrowed",
            constraints={"amount_max": 5},
        )
        # Written directly, so the grant stays NARROWED while the store
        # holds a suspension: the state under-reports the restriction.
        controller.store.apply(
            build_suspend(
                FINGERPRINT,
                key="aegis:halt",
                reason="suspended out of band",
                at=0.0,
            )
        )
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED

        controller.lift(FINGERPRINT, "aegis:narrow")

        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED


# ======================================================================
# The authorization path is total
# ======================================================================


class TestTotality:
    class _BrokenStore:
        def excludes(self, *args, **kwargs):
            raise RuntimeError("store is unreadable")

        def any_suspended(self, *args, **kwargs):
            raise RuntimeError("store is unreadable")

        def fingerprints(self):
            return ()

    def test_an_unreadable_store_denies_rather_than_raising(self):
        """A gate that cannot read Aegis state must deny, not skip Aegis.

        Skipping would be the fail-open reading: the restriction might be
        exactly the one that should have denied this request.
        """

        controller = AegisController(store=self._BrokenStore())

        reason = controller.restriction_reason(
            [FINGERPRINT],
            "payments.send",
            {"amount": 1},
        )

        assert reason is not None
        assert reason.startswith("aegis_state_unavailable")
        assert controller.suspended_in([FINGERPRINT]) == (
            "aegis_state_unavailable"
        )

    def test_unreadable_fingerprints_deny_rather_than_raising(self):
        class _Hostile:
            def __iter__(self):
                raise TypeError("not iterable after all")

        reason = _controller().restriction_reason(
            _Hostile(),
            "payments.send",
            {"amount": 1},
        )

        assert reason == "aegis_state_unavailable:fingerprints_unreadable"

    def test_no_fingerprints_is_no_objection(self):
        # Not an allow: an empty chain means Aegis was asked about nothing.
        assert (
            _controller().restriction_reason([], "payments.send", {"amount": 1})
            is None
        )

    def test_non_string_fingerprints_are_skipped_not_fatal(self):
        controller = _controller()
        controller.suspend(
            FINGERPRINT,
            key="aegis:test",
            reason="suspended",
        )

        assert (
            controller.restriction_reason(
                [None, 0, "", FINGERPRINT],
                "payments.send",
                {"amount": 1},
            )
            is not None
        )


# ======================================================================
# The five executor paths
# ======================================================================


class TestExecution:
    def test_keep_changes_nothing(self):
        controller = _controller()
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.KEEP),
        )

        assert record.acted is False
        assert record.applied == ()
        assert record.failures == ()
        assert controller.grant(FINGERPRINT).state is AegisState.ISSUED

    def test_revalidate_writes_no_restriction(self):
        """Re-asking the boundary is not a narrowing.

        ``REVALIDATING`` is the bottom of the residual order, so the move
        cannot widen -- and because it writes no restriction it does not
        deny either. The grant simply has no standing until an
        authorization is observed.
        """

        seen = []
        controller = _controller(revalidate_hook=seen.append)
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.REVALIDATE),
        )

        assert record.revalidation_requested is True
        assert record.applied == ()
        assert record.failures == ()
        assert seen == [FINGERPRINT]
        assert controller.grant(FINGERPRINT).state is AegisState.REVALIDATING
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 1},
            )
            is None
        )

    def test_a_missing_revalidation_hook_is_recorded(self):
        controller = _controller()
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.REVALIDATE),
        )

        assert record.revalidation_requested is True
        assert any("no revalidation hook" in item for item in record.failures)
        # The state still moved. The failure is that nobody was told, not
        # that Aegis carried on treating its knowledge as current.
        assert controller.grant(FINGERPRINT).state is AegisState.REVALIDATING

    def test_a_raising_revalidation_hook_is_recorded_not_raised(self):
        def hostile(fingerprint):
            raise RuntimeError("monitor is down")

        controller = _controller(revalidate_hook=hostile)
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.REVALIDATE),
        )

        assert any(
            "RuntimeError calling the revalidation hook" in item
            for item in record.failures
        )
        assert controller.grant(FINGERPRINT).state is AegisState.REVALIDATING

    def test_revalidating_a_restricted_grant_leaves_it_restricted(self):
        """A change calling for revalidation is not a decision to lift.

        Reaching ``REVALIDATING`` from ``NARROWED`` requires naming the
        restriction being cleared. An executor that supplied one on its own
        would let any environmental change quietly undo a narrowing.
        """

        controller = _controller(revalidate_hook=lambda fingerprint: None)
        controller.narrow(
            FINGERPRINT,
            key="aegis:test",
            reason="narrowed",
            constraints={"amount_max": 5},
        )
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.REVALIDATE),
        )

        assert record.revalidation_requested is True
        assert any(
            "without lifting a restriction" in item for item in record.failures
        )
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 50},
            )
            is not None
        )

    def test_narrow_writes_a_keyed_restriction(self):
        controller = _controller()
        record = controller.execute(
            FINGERPRINT,
            _classification(
                AdaptiveResponse.NARROW,
                trigger="posture_changed",
            ),
            constraints={"amount_max": 5},
        )

        assert record.response is AdaptiveResponse.NARROW
        # Keyed by trigger, so the restriction that a change wrote can be
        # lifted by name when the change is reversed.
        assert [item.key for item in record.applied] == [
            f"{NARROW_KEY_PREFIX}:posture_changed"
        ]
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 50},
            )
            is not None
        )

    def test_a_narrow_with_nothing_to_narrow_to_escalates(self):
        """The rejected alternative is a restriction that restricts nothing.

        It would appear in the explanation as a narrowing and admit every
        request the unnarrowed grant admitted -- a false guarantee, which is
        worse than either honest reading. Escalating keeps the record true
        and errs toward less authority.
        """

        controller = _controller()
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.NARROW),
        )

        assert record.response is AdaptiveResponse.SUSPEND
        assert any("escalated" in item for item in record.failures)
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_suspend_writes_a_suspending_restriction(self):
        controller = _controller()
        record = controller.execute(
            FINGERPRINT,
            _classification(
                AdaptiveResponse.SUSPEND,
                trigger="incident_opened",
            ),
        )

        assert [item.key for item in record.applied] == [
            f"{SUSPEND_KEY_PREFIX}:incident_opened"
        ]
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_a_restriction_lands_even_when_the_state_move_is_refused(self):
        # Suspended first, so NARROWED is an illegal move. The narrowing
        # still applies and the record says both things happened.
        controller = _controller()
        controller.suspend(FINGERPRINT, key="aegis:first", reason="suspended")

        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.NARROW),
            constraints={"amount_max": 5},
        )

        assert record.applied
        assert any("is enforced but the state" in item for item in record.failures)
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED


# ======================================================================
# REVOKE: the registry is the authority, Aegis only records
# ======================================================================


class TestRevokeExecution:
    def test_a_working_hook_latches_revoked(self):
        called = []
        controller = _controller(revoke_hook=called.append)
        record = controller.execute(
            FINGERPRINT,
            _classification(
                AdaptiveResponse.REVOKE,
                trigger="capability_revoked",
            ),
        )

        assert called == [FINGERPRINT]
        assert record.revoked is True
        assert record.failures == ()
        assert controller.grant(FINGERPRINT).state is AegisState.REVOKED
        # The denial is still the restriction. REVOKED records what the
        # registry did; it is not the thing that refuses the request.
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_no_hook_suspends_and_refuses_to_latch(self):
        """Aegis will not record a finality the system does not enforce.

        The revocation registry is the authority on revocation. Latching
        ``REVOKED`` without it would put a terminal state -- no outgoing
        edges, no way back -- on a capability ``_gate_revocation`` still
        reads as live. Suspending denies now and stays reversible.
        """

        controller = _controller()
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.REVOKE),
        )

        assert record.revoked is False
        assert any("no revoke hook is wired" in item for item in record.failures)
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_a_raising_hook_is_recorded_and_still_denies(self):
        def hostile(fingerprint):
            raise RuntimeError("registry unreachable")

        controller = _controller(revoke_hook=hostile)
        record = controller.execute(
            FINGERPRINT,
            _classification(AdaptiveResponse.REVOKE),
        )

        assert record.revoked is False
        assert any(
            "RuntimeError calling the revoke hook" in item
            for item in record.failures
        )
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_revoked_is_terminal_for_every_operator_method(self):
        controller = _controller(revoke_hook=lambda fingerprint: None)
        controller.execute(FINGERPRINT, _classification(AdaptiveResponse.REVOKE))

        with pytest.raises(IllegalTransition):
            controller.begin_revalidation(FINGERPRINT)

        with pytest.raises(IllegalTransition):
            controller.expire(FINGERPRINT)

        with pytest.raises(IllegalTransition):
            controller.narrow(
                FINGERPRINT,
                key="aegis:after-revocation",
                reason="narrowed",
                constraints={"amount_max": 1},
            )

        assert controller.grant(FINGERPRINT).state is AegisState.REVOKED

    def test_an_allow_does_not_resurrect_a_revoked_grant(self):
        """The evidenced edge starts at ``REVALIDATING``, which is unreachable.

        A revoked grant that a later allow could move is authority
        resurrection, and it is refused twice: ``observe_authorization``
        only moves from ``ISSUED`` or ``REVALIDATING``, and the state
        machine has no outgoing edge from a terminal state either way.
        """

        sdk = FirewallSDK(aegis_enabled=True)
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            sdk.aegis.register(
                fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
            )
            sdk.aegis.mark_revoked(fingerprint, reason="operator revoked")

            allow = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10},
            )

            # The boundary still owns the verdict, and the registry has no
            # entry, so this allow is genuine -- and it changes nothing.
            assert allow.allowed is True
            assert sdk.aegis.grant(fingerprint).state is AegisState.REVOKED
        finally:
            sdk.close()


# ======================================================================
# An unreadable classification is an unreadable input
# ======================================================================


class TestUnreadableClassification:
    """``execute`` suspends when it cannot read what it was asked to do.

    Found by attacking the shipped executor. Every other unreadable input
    in Aegis writes a restriction -- an unreadable store denies, a decay
    schedule that cannot be positioned applies its strongest stage, a
    change with no observable *after* classifies as ``SUSPEND``, a
    revocation that could not be executed suspends -- and this branch
    returned a record saying ``SUSPEND`` while applying nothing and leaving
    the grant exactly as authoritative as before.

    Two defects in one: the only unreadable input in Aegis that cost
    nothing, and an ``ExecutionRecord`` that named an outcome that had not
    happened, which is the false explanation §17 exists to prevent.
    """

    def test_a_non_classification_suspends_for_real(self):
        for hostile in (
            None,
            "narrow",
            AdaptiveResponse.NARROW,
            {"response": "keep"},
            object(),
        ):
            controller = _controller()
            record = controller.execute(FINGERPRINT, hostile)

            assert isinstance(record, ExecutionRecord)
            assert record.response is AdaptiveResponse.SUSPEND
            assert "execute requires a Classification" in record.failures

            # The report and the state agree, and the grant is denied.
            assert record.acted is True
            assert record.state_after is AegisState.SUSPENDED
            assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
            assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT, hostile

    def test_the_suspension_is_keyed_so_it_can_be_lifted(self):
        # Fail-closed on a caller's bug must not be a one-way door: the
        # operator who fixes the caller needs a name to lift.
        controller = _controller()
        record = controller.execute(FINGERPRINT, None)

        assert [item.key for item in record.applied] == [
            f"{SUSPEND_KEY_PREFIX}:unreadable_classification"
        ]

        controller.lift(FINGERPRINT, f"{SUSPEND_KEY_PREFIX}:unreadable_classification")

        assert controller.suspended_in([FINGERPRINT]) is None
        # Lifting removes the obstacle without restoring standing.
        assert controller.grant(FINGERPRINT).state is AegisState.REVALIDATING

    def test_an_untracked_fingerprint_is_still_restricted(self):
        # There is no grant to move, so the store is the only place the
        # denial can live -- and the gate reads the store.
        controller = AegisController()
        record = controller.execute(FINGERPRINT, None)

        assert record.state_before is None
        assert record.state_after is None
        assert record.applied
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_a_hostile_fingerprint_is_recorded_not_raised(self):
        controller = AegisController()
        record = controller.execute(None, None)

        assert record.applied == ()
        assert any(
            "ValueError suspending after an unreadable classification" in item
            for item in record.failures
        )

    def test_a_terminal_grant_is_left_terminal(self):
        controller = _controller(revoke_hook=lambda fingerprint: None)
        controller.execute(FINGERPRINT, _classification(AdaptiveResponse.REVOKE))

        record = controller.execute(FINGERPRINT, "nonsense")

        assert record.applied
        assert any("is enforced but the state" in item for item in record.failures)
        assert controller.grant(FINGERPRINT).state is AegisState.REVOKED


# ======================================================================
# Classification is analysis, and KEEP has to be earned
# ======================================================================


class TestClassification:
    def test_keep_is_reachable_when_nothing_changed(self):
        """The positive control for the whole classifier.

        Without it, every test below is satisfiable by a classifier that
        never returns ``KEEP`` -- which would be safe and useless, and would
        turn every periodic sweep into a restriction.
        """

        snapshot = _snapshot()
        result = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=snapshot,
            after=snapshot,
        )

        assert result.response is AdaptiveResponse.KEEP
        assert result.acts is False

    def test_a_real_change_does_not_keep(self):
        result = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=_snapshot(),
            after=_snapshot(environment='{"region": "elsewhere"}'),
        )

        assert result.response is not AdaptiveResponse.KEEP

    def test_no_observation_at_all_suspends(self):
        # Asked about a change and given nothing to compare: unknown is not
        # trusted, so the strongest reading applies.
        result = classify(RevalidationTrigger.ENVIRONMENT_CHANGED)

        assert result.response is AdaptiveResponse.SUSPEND

    def test_a_missing_after_snapshot_suspends(self):
        result = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=_snapshot(),
        )

        assert result.response is AdaptiveResponse.SUSPEND

    def test_a_missing_before_snapshot_revalidates(self):
        # Current state is observable and no change can be established, so
        # re-asking the boundary is the honest answer.
        result = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            after=_snapshot(),
        )

        assert result.response is AdaptiveResponse.REVALIDATE

    def test_a_degraded_dependency_never_keeps(self):
        snapshot = _snapshot(degraded_dependencies=("attack-graph",))
        result = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=snapshot,
            after=snapshot,
        )

        # ``degraded`` names the dependencies rather than answering yes/no:
        # §17 needs the explanation to say *what* could not be established.
        assert result.degraded == ("attack-graph",)
        assert result.response is not AdaptiveResponse.KEEP

    def test_an_unrecognised_trigger_revalidates(self):
        snapshot = _snapshot()

        for hostile in ("aegis_allow", "", None, 0, object()):
            result = classify(hostile, before=snapshot, after=snapshot)

            assert result.response is AdaptiveResponse.REVALIDATE, hostile

    def test_classify_on_the_controller_changes_no_state(self):
        controller = _controller()
        snapshot = _snapshot()

        controller.classify(
            RevalidationTrigger.INCIDENT_OPENED,
            before=snapshot,
            after=snapshot,
        )

        # Asking what changed is not acting on it: that is why classify and
        # execute are separate call sites.
        assert controller.grant(FINGERPRINT).state is AegisState.ISSUED
        assert controller.suspended_in([FINGERPRINT]) is None


# ======================================================================
# Scheduled decay
# ======================================================================


class TestDecay:
    @staticmethod
    def _scheduled(clock: _Clock) -> AegisController:
        controller = AegisController(clock=clock)
        controller.register(
            FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            schedule=DecaySchedule(
                narrow_after=60,
                suspend_after=120,
                constraints={"amount_max": 5},
            ),
        )

        return controller

    def test_nothing_decays_before_the_first_offset(self):
        clock = _Clock()
        controller = self._scheduled(clock)
        clock.advance(30)

        assert controller.apply_decay() == ()
        assert controller.decay_stage(FINGERPRINT) is DecayStage.NONE
        assert controller.grant(FINGERPRINT).state is AegisState.ISSUED

    def test_the_narrow_stage_narrows(self):
        clock = _Clock()
        controller = self._scheduled(clock)
        clock.advance(60)

        records = controller.apply_decay()

        assert [item.response for item in records] == [AdaptiveResponse.NARROW]
        assert controller.decay_stage(FINGERPRINT) is DecayStage.NARROW
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert (
            controller.restriction_reason(
                [FINGERPRINT],
                "payments.send",
                {"amount": 50},
            )
            is not None
        )

    def test_the_suspend_stage_suspends(self):
        clock = _Clock()
        controller = self._scheduled(clock)
        clock.advance(120)

        records = controller.apply_decay()

        assert [item.response for item in records] == [AdaptiveResponse.SUSPEND]
        assert controller.decay_stage(FINGERPRINT) is DecayStage.SUSPEND
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED
        assert controller.suspended_in([FINGERPRINT]) == FINGERPRINT

    def test_the_sweep_is_idempotent_within_a_stage(self):
        """Running the sweep twice writes one restriction.

        The store deduplicates on content and a decay restriction's content
        is a pure function of its stage, so a monitor sweeping every second
        does not accumulate state. The second sweep still reports, because
        the schedule is still due -- reporting nothing would suggest the
        decay had been undone.
        """

        clock = _Clock()
        controller = self._scheduled(clock)
        clock.advance(60)

        first = controller.apply_decay()
        second = controller.apply_decay()

        assert len(first) == 1
        assert len(second) == 1
        assert controller.grant(FINGERPRINT).state is AegisState.NARROWED
        assert len(controller.grant(FINGERPRINT).history) == 1

    def test_decay_only_ever_strengthens(self):
        """The stronger stage adds to the weaker; it does not replace it.

        Both restrictions carry the schedule's key, so an operator who
        lifts the decay lifts all of it -- deliberately, by name. What must
        not happen is the suspension silently discarding the narrowing,
        because then a later lift of the suspension alone would restore the
        ceiling the narrowing had removed.
        """

        clock = _Clock()
        controller = self._scheduled(clock)

        clock.advance(60)
        controller.apply_decay()
        clock.advance(60)
        controller.apply_decay()

        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED

        kinds = sorted(
            item.kind.value
            for item in controller.store.restrictions_for(FINGERPRINT)
        )
        assert kinds == ["narrow", "suspend"]

    def test_an_untracked_schedule_applies_its_strongest_stage(self):
        """A schedule that cannot be positioned in time is not permissive.

        There is no ``created_at`` to measure from, so elapsed time is
        ``nan``. Treating that as "early" would let a lost grant record sit
        in the permissive phase forever.
        """

        clock = _Clock()
        controller = AegisController(clock=clock)
        controller.register(
            OTHER,
            agent_id="agent-a",
            capability="payments.send",
            schedule=DecaySchedule(suspend_after=1_000_000),
        )
        # Reaching into ``_grants`` because there is no public way to
        # produce this state -- ``register`` always creates the grant. The
        # condition is real: a schedule outliving its grant is what a
        # partial restore or a pruned grant table looks like.
        controller._grants.pop(OTHER)

        records = controller.apply_decay()

        assert [item.response for item in records] == [AdaptiveResponse.SUSPEND]
        assert controller.decay_stage(OTHER) is DecayStage.SUSPEND
        assert controller.suspended_in([OTHER]) == OTHER

    def test_a_clock_that_moves_backwards_does_not_restore_authority(self):
        clock = _Clock()
        controller = self._scheduled(clock)
        clock.advance(120)
        controller.apply_decay()

        clock.now = 0.0

        # stage_at refuses a negative elapsed and returns the strongest
        # stage, so rewinding the clock re-applies the suspension rather
        # than reverting to NONE.
        assert controller.decay_stage(FINGERPRINT) is DecayStage.SUSPEND
        assert controller.apply_decay()
        assert controller.grant(FINGERPRINT).state is AegisState.SUSPENDED

    def test_stages_are_monotone_over_a_real_schedule(self):
        schedule = DecaySchedule(
            narrow_after=60,
            suspend_after=120,
            constraints={"amount_max": 5},
        )

        assert stages_are_monotone(schedule, [0, 30, 59, 60, 119, 120, 10_000])
        # Including the readings a broken clock produces.
        assert stages_are_monotone(schedule, [0, float("nan")])
        assert schedule.stage_at(-1) is DecayStage.SUSPEND

    def test_an_unscheduled_grant_has_no_stage(self):
        assert _controller().decay_stage(FINGERPRINT) is None

    def test_a_non_schedule_is_refused(self):
        controller = AegisController()

        with pytest.raises(TypeError):
            controller.register(
                FINGERPRINT,
                agent_id="agent-a",
                capability="payments.send",
                schedule={"suspend_after": 60},
            )


# ======================================================================
# The audit surface
# ======================================================================


class TestAudit:
    def test_a_real_walk_produces_no_history_findings(self):
        """The path AEGIS_STATE_TRANSITIONS audits, walked end to end.

        Narrow, lift, then re-authorize through the boundary -- the same
        traversal the invariant exerciser performs, checked here against a
        controller driven by hand so the invariant and the controller are
        not each other's only witness.
        """

        sdk = FirewallSDK(aegis_enabled=True)
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            controller = sdk.aegis

            controller.register(
                fingerprint,
                agent_id=capability.agent_id,
                capability=capability.capability,
            )
            controller.narrow(
                fingerprint,
                key="aegis:test",
                reason="narrowed for the walk",
                constraints={"amount_max": 5},
            )
            controller.lift(fingerprint, "aegis:test")

            allow = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10},
            )

            assert allow.allowed is True
            assert controller.grant(fingerprint).state is AegisState.ACTIVE
            assert controller.history_findings() == ()

            walked = [
                (item.from_state.value, item.to_state.value)
                for item in controller.grant(fingerprint).history
            ]
            assert walked == [
                ("issued", "narrowed"),
                ("narrowed", "revalidating"),
                ("revalidating", "active"),
            ]
        finally:
            sdk.close()

    def test_describe_reports_hooks_and_findings(self):
        controller = _controller(revoke_hook=lambda fingerprint: None)
        described = controller.describe()

        assert described["hooks"] == {"revoke": True, "revalidate": False}
        assert described["history_findings"] == []
        assert FINGERPRINT in described["grants"]

    def test_describe_is_not_a_handle_into_the_state(self):
        controller = _controller()
        described = controller.describe()
        described["grants"].clear()

        assert controller.grant(FINGERPRINT) is not None
