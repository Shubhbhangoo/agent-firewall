"""v2.4 §10 corrections: one regression test per defect that was shipped.

Every test in this file exists because the attack in
``tests/test_v2_4_aegis_adversarial.py`` succeeded against v2.3 code. The
adversarial file is written as an attack and reads like one; this file is
written as a pin and reads like one. Each class names the defect, the layer
that was wrong, and the property the fix establishes -- so a later change
that reintroduces the behaviour fails against a test that explains what it
broke rather than against an opaque assertion.

Two architectural causes produced all eight.

**An unorderable numeric value satisfies every bound.** Bounds are enforced
by negation -- ``deny if actual > ceiling`` -- and every comparison against
``nan`` is False, so a ``nan`` ceiling bounded nothing while looking
restrictive, and a ``nan`` child passed an attenuation check that ``inf``
and ``10**9`` both failed. The same family produced three crash sites,
because ``math.isfinite`` converts its argument to a float before answering
and ``float(10**400)`` raises ``OverflowError`` instead of returning. A
400-digit integer arrives straight out of ``json.loads``.

**A documented totality promise was not implemented.** ``_gate_aegis``, the
commit-time re-read in ``_gate_transaction``, ``blast_radius``,
``AegisController.grant`` and ``DecaySchedule.stage_at`` each promised in
their own docstrings that they answer rather than raise. Each had at least
one path that raised. The controller is injectable -- ``FirewallSDK(aegis=
...)`` accepts any object of the right shape -- so "the bundled controller
does not raise" was never the guarantee the callers were relying on.

What these tests do not establish: that no other unorderable value exists,
and that no other read path raises. They pin the ones that were found.
``tests/test_v2_4_aegis_fuzz.py`` searches for more.
"""

from __future__ import annotations

import pytest

from firewall.aegis.blast import blast_radius
from firewall.aegis.controller import AegisController
from firewall.aegis.decay import DecaySchedule, DecayStage
from firewall.sdk import FirewallSDK

KEY_ID = "corrections-key"

#: Finite, ordered, and larger than any float. ``10**400 > 100`` is True
#: and cheap; ``float(10**400)`` raises ``OverflowError``.
HUGE = 10**400

NAN = float("nan")
INF = float("inf")


@pytest.fixture
def sdk():
    instance = FirewallSDK(aegis_enabled=True)
    instance.generate_key(KEY_ID)
    yield instance
    instance.close()


def _capability(sdk, **constraints):
    return sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints=dict(constraints),
    )


# ======================================================================
# 1. An integer too large for a float crashed three layers
# ======================================================================


class TestUnrepresentableIntegerAnswers:
    """``firewall/authorization.py``, ``aegis/envelope.py``, budget reservation.

    Cause: ``math.isfinite(actual)`` and ``float(actual)`` were asked about
    a value that is finite and ordered but not float-representable. The
    question is unanswerable; the comparison is not. The fix stops asking it
    and compares directly, which Python evaluates exactly for an int against
    a float.

    Establishes: every one of these surfaces returns an answer. It does not
    establish that the answer is a denial in general -- ``HUGE`` is denied
    here because it exceeds the ceiling, not because it is large.
    """

    def test_the_boundary_returns_a_decision(self, sdk):
        capability = _capability(sdk, amount_max=100)

        outcome = sdk.authorize(capability, "payments.send", {"amount": HUGE})

        assert outcome.allowed is False
        assert outcome.reason == "constraint_denied"

    def test_the_envelope_returns_a_reason(self, sdk):
        capability = _capability(sdk, amount_max=100)
        envelope = sdk.authority_envelope(capability)

        assert (
            envelope.excludes("payments.send", {"amount": HUGE})
            == "ceiling_exceeded:amount"
        )
        assert envelope.may_admit("payments.send", {"amount": HUGE}) is False

    def test_the_envelope_still_admits_a_huge_value_under_a_huge_ceiling(
        self,
        sdk,
    ):
        """The fix must not have turned "large" into "excluded".

        ENVELOPE_SOUNDNESS runs one way only: the envelope may admit what
        the boundary denies, but it must never exclude what the boundary
        admits. A ceiling of ``HUGE * 2`` admits ``HUGE`` at the boundary,
        so the envelope must not object.
        """

        capability = _capability(sdk, amount_max=HUGE * 2)
        envelope = sdk.authority_envelope(capability)

        assert envelope.excludes("payments.send", {"amount": HUGE}) is None
        assert (
            sdk.authorize(capability, "payments.send", {"amount": HUGE}).allowed
            is True
        )

    def test_the_budget_reservation_returns_a_decision(self, sdk):
        # No ``amount_max``: with one, the constraint gate refuses first and
        # the budget conversion is never reached.
        capability = _capability(sdk)
        sdk.configure_delegation_budget(capability, max_total_amount=50.0)

        outcome = sdk.authorize_with_delegation_budget(
            capability,
            "payments.send",
            {"amount": HUGE},
        )

        assert outcome.allowed is False
        assert outcome.reason == "invalid_budget_amount"
        assert sdk.delegation_budget_total(capability) == 0.0

    def test_the_decay_schedule_returns_a_stage(self):
        schedule = DecaySchedule(
            narrow_after=10.0,
            suspend_after=20.0,
            constraints={"amount_max": 5},
        )

        assert schedule.stage_at(HUGE) is DecayStage.SUSPEND
        assert schedule.restriction_at("a" * 64, HUGE) is not None


# ======================================================================
# 2. A NaN ceiling bounded nothing
# ======================================================================


class TestUnorderableCeilingDenies:
    """``firewall/authorization.py::_check_constraints``.

    Cause: ``actual > nan`` is False for every ``actual``, and the ceiling
    is enforced by negating that comparison. A capability whose constraints
    read as restrictive admitted everything.

    Establishes: an unorderable *bound* refuses rather than admits. ``inf``
    is deliberately unaffected -- it is ordered and genuinely means
    unbounded, so a capability that says so keeps saying so.
    """

    def test_a_nan_ceiling_denies_a_large_amount(self, sdk):
        capability = _capability(sdk, amount_max=NAN)

        outcome = sdk.authorize(capability, "payments.send", {"amount": 10**9})

        assert outcome.allowed is False
        assert outcome.reason == "constraint_denied"

    def test_a_nan_ceiling_denies_a_small_amount_too(self, sdk):
        """Not "denies what exceeds it" -- there is no it to exceed."""

        capability = _capability(sdk, amount_max=NAN)

        assert (
            sdk.authorize(capability, "payments.send", {"amount": 1}).allowed
            is False
        )

    def test_an_inf_ceiling_still_means_unbounded(self, sdk):
        capability = _capability(sdk, amount_max=INF)

        outcome = sdk.authorize(capability, "payments.send", {"amount": 10**9})

        assert outcome.allowed is True
        assert outcome.reason == "authorized"

    def test_a_nan_request_value_is_denied_under_a_real_ceiling(self, sdk):
        """The mirror case: an unorderable *value* against an ordered bound."""

        capability = _capability(sdk, amount_max=100)

        for hostile in (NAN, INF, float("-inf")):
            outcome = sdk.authorize(
                capability,
                "payments.send",
                {"amount": hostile},
            )

            assert outcome.allowed is False, hostile


# ======================================================================
# 3. A NaN child passed the attenuation predicate
# ======================================================================


class TestUnorderableDelegationIsNotNarrower:
    """``firewall/delegation.py::_constraints_are_narrower``.

    Cause: the same negated comparison, in the predicate that decides
    whether a delegation may be signed. A child claiming ``amount_max: nan``
    was minted while ``inf`` and ``10**9`` were both correctly refused.

    The effect was contained -- ``authorize()`` evaluates every ancestor's
    constraints, so the parent's real ceiling still bound the child at
    request time -- but a signed capability was in circulation whose own
    stated ceiling bounded nothing. Anything reading the child in isolation
    (an operator, an export, a UI, a future consumer that trusts the leaf)
    would read it as narrower than its parent.

    Establishes: a bound that cannot be shown to be narrower is refused at
    mint time. The predicate's job is to *demonstrate* narrowing, and
    unknown is not narrower.
    """

    @pytest.mark.parametrize("hostile", [NAN, INF, 10**9, HUGE])
    def test_a_wider_or_unorderable_child_is_refused(self, sdk, hostile):
        parent = _capability(sdk, amount_max=100)
        private_key = sdk.active_key().private_key

        with pytest.raises(ValueError, match="cannot broaden"):
            sdk.delegate(
                parent,
                private_key,
                delegatee="agent-child",
                constraints={"amount_max": hostile},
            )

    def test_a_nan_parent_cannot_be_narrowed_either(self, sdk):
        """Symmetric, and for the same reason.

        A ``nan`` *parent* ceiling cannot demonstrate that any child is
        narrower than it, so the delegation is refused rather than granted
        on the strength of a comparison that is False in both directions.
        Refusing is the direction that cannot widen.
        """

        parent = _capability(sdk, amount_max=NAN)
        private_key = sdk.active_key().private_key

        with pytest.raises(ValueError, match="cannot broaden"):
            sdk.delegate(
                parent,
                private_key,
                delegatee="agent-child",
                constraints={"amount_max": 10},
            )

    def test_a_genuinely_narrower_child_is_still_minted(self, sdk):
        """The fix must not have refused the ordinary case."""

        parent = _capability(sdk, amount_max=100)
        child = sdk.delegate(
            parent,
            sdk.active_key().private_key,
            delegatee="agent-child",
            constraints={"amount_max": 10},
        ).child

        assert child.constraints["amount_max"] == 10
        assert (
            sdk.authorize(child, "payments.send", {"amount": 5}).allowed is True
        )


# ======================================================================
# 4-8. Documented totality that was not implemented
# ======================================================================


class TestReadPathsAnswerRatherThanRaise:
    """Five promises, each written in a docstring before it was true.

    The exact reasons for the two ``authorize()`` surfaces are pinned in
    ``tests/test_v2_4_aegis_adversarial.py::TestMalformedState``, alongside
    the attacks that found them; what is pinned here is the narrower claim
    that each read path is *total* -- it returns a value for every input,
    including inputs the type annotation does not admit.
    """

    @pytest.mark.parametrize(
        "hostile",
        [None, "", b"abcd", 0, 1.5, [], {}, set(), object()],
    )
    def test_grant_is_total(self, hostile):
        """``AegisController.grant`` raised ``TypeError`` on an unhashable.

        Reached from ``explain`` and from the developer console with
        fingerprints derived from whatever a caller handed the boundary, so a
        raise there turns a malformed request into a crashed operator tool.
        The write path still refuses loudly; only the read path is total.
        """

        controller = AegisController()

        assert controller.grant(hostile) is None

    def test_register_still_refuses_loudly(self):
        """The other half of the contract, so totality cannot spread to it."""

        controller = AegisController()

        for hostile in (None, "", 0, object()):
            with pytest.raises((ValueError, TypeError)):
                controller.register(
                    hostile,
                    agent_id="agent-a",
                    capability="payments.send",
                )

    def test_blast_radius_is_total_over_a_hostile_graph(self):
        """The guard covers the attribute lookup, not just the call."""

        class _Proxy:
            def __getattr__(self, name):
                raise RuntimeError("proxy is not resolvable")

        radius = blast_radius("a" * 64, graph=_Proxy())

        assert radius.complete is False
        assert any(item.kind == "graph_error" for item in radius.unanalyzable)

    @pytest.mark.parametrize(
        "hostile",
        [NAN, -1.0, float("-inf"), HUGE, "10", None, True, object()],
    )
    def test_stage_at_is_total(self, hostile):
        schedule = DecaySchedule(suspend_after=20.0)

        assert schedule.stage_at(hostile) is DecayStage.SUSPEND
