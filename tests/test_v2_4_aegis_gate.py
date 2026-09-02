"""v2.4: Aegis at the boundary -- ``_gate_aegis`` and the commit re-check.

``tests/test_v2_4_aegis_controller.py`` tests the controller in isolation;
this file tests the two places the SDK actually consults it, end to end
through ``FirewallSDK.authorize()``:

* ``_gate_aegis``, which reads the restriction store for the capability
  *and every ancestor* and may only deny or abstain, and
* the commit-time re-check inside ``_gate_transaction``, which re-reads
  suspension immediately before consuming budget -- the TOCTOU window §9
  requires closing, because the cryptographic gate between the two reads is
  the slowest step in the pipeline.

Three properties are pinned throughout.

**Aegis only ever subtracts.** Every test that ends in an allow is an allow
the SDK would have produced with no controller attached at all; the
Aegis-off comparison is made explicitly rather than assumed. A restriction
can turn an allow into a denial and nothing else.

**A restriction on an ancestor binds the descendant.** Narrowing a parent
must not be escapable by presenting the child, which is the delegation half
of "a child never widens its parent".

**Every Aegis denial is attributable.** The developer console derives its
pipeline trace from the denial reason alone, so a reason it cannot place is
rendered as *unattributed*. An unattributable Aegis denial would leave an
operator with a refused request, a restriction key, and no indication which
gate refused it.
"""

from __future__ import annotations

import pytest

from firewall.aegis.controller import AegisController
from firewall.aegis.state import AegisState
from firewall.sdk import FirewallSDK
from firewall.ui.introspect import attribute_reason, phase_trace

KEY_ID = "gate-key"


class _Estate:
    """A root, a child delegated from it, and a controller tracking both."""

    def __init__(self, controller=None):
        self.sdk = FirewallSDK(
            aegis=controller,
            aegis_enabled=controller is None,
        )
        private_key = self.sdk.generate_key(KEY_ID).private_key

        self.root = self.sdk.issue(
            agent="agent-root",
            capability="payments.send",
            constraints={"amount_max": 100},
        )
        self.child = self.sdk.delegate(
            self.root,
            private_key,
            delegatee="agent-child",
            constraints={"amount_max": 50},
        ).child

        self.root_fingerprint = self.sdk.fingerprint(self.root)
        self.child_fingerprint = self.sdk.fingerprint(self.child)

        self.aegis = self.sdk.aegis
        self.aegis.register(
            self.root_fingerprint,
            agent_id=self.root.agent_id,
            capability=self.root.capability,
        )
        self.aegis.register(
            self.child_fingerprint,
            agent_id=self.child.agent_id,
            capability=self.child.capability,
        )

    def send(self, capability, amount=10):
        return self.sdk.authorize(
            capability,
            "payments.send",
            {"amount": amount},
        )

    def close(self) -> None:
        self.sdk.close()


@pytest.fixture
def estate():
    built = _Estate()
    yield built
    built.close()


# ======================================================================
# The gate can only subtract
# ======================================================================


class TestGateSubtractsOnly:
    def test_an_unrestricted_grant_is_unaffected(self, estate):
        assert estate.send(estate.root).allowed is True
        assert estate.send(estate.child).allowed is True

    def test_the_allow_matches_an_sdk_with_no_controller(self):
        """Aegis-off equivalence: no restrictions, no difference.

        The gate abstains by returning ``None``, and an abstention has to
        be indistinguishable from the controller not being there. If it
        were not, enabling Aegis would change decisions on its own -- which
        is the second authorization engine the whole design refuses to be.
        """

        with_aegis = _Estate()
        without = FirewallSDK()
        try:
            without.generate_key(KEY_ID)
            plain = without.issue(
                agent="agent-root",
                capability="payments.send",
                constraints={"amount_max": 100},
            )

            for amount in (10, 100, 101, 10_000):
                mine = with_aegis.send(with_aegis.root, amount)
                theirs = without.authorize(
                    plain,
                    "payments.send",
                    {"amount": amount},
                )

                assert mine.allowed is theirs.allowed, amount
                assert mine.reason == theirs.reason, amount
        finally:
            with_aegis.close()
            without.close()

    def test_an_untracked_controller_abstains(self):
        """A controller tracking nothing is not a controller denying everything.

        ``_gate_aegis`` short-circuits on ``tracked()``, so the common
        deployment -- Aegis enabled, no grant enrolled yet -- must behave
        exactly like no Aegis at all.
        """

        sdk = FirewallSDK(aegis_enabled=True)
        try:
            sdk.generate_key(KEY_ID)
            capability = sdk.issue(
                agent="agent-root",
                capability="payments.send",
                constraints={"amount_max": 100},
            )

            assert sdk.aegis.tracked() == 0
            assert (
                sdk.authorize(
                    capability,
                    "payments.send",
                    {"amount": 10},
                ).allowed
                is True
            )
        finally:
            sdk.close()

    def test_a_narrowing_denies_outside_and_permits_inside(self, estate):
        estate.aegis.narrow(
            estate.root_fingerprint,
            key="aegis:ceiling",
            reason="narrowed to 5 by an operator",
            constraints={"amount_max": 5},
        )

        denied = estate.send(estate.root, amount=50)
        assert denied.allowed is False
        assert denied.reason == "aegis_constraint_denied:aegis:ceiling"

        # Inside the narrowing the boundary still decides for itself.
        allowed = estate.send(estate.root, amount=1)
        assert allowed.allowed is True
        assert allowed.reason == "authorized"

        # And the allow does not clear the narrowing. An allow *inside* a
        # narrowing is evidence that this request was permitted, not
        # evidence that the restriction should go: ``observe_authorization``
        # moves only from ``ISSUED`` or ``REVALIDATING``, so reaching
        # ``ACTIVE`` needs an operator to lift the restriction first.
        assert (
            estate.aegis.grant(estate.root_fingerprint).state
            is AegisState.NARROWED
        )
        assert estate.send(estate.root, amount=50).allowed is False

    def test_a_suspension_denies_everything(self, estate):
        estate.aegis.suspend(
            estate.root_fingerprint,
            key="aegis:halt",
            reason="incident opened",
        )

        for amount in (1, 10, 100):
            outcome = estate.send(estate.root, amount)

            assert outcome.allowed is False, amount
            assert outcome.reason == "aegis_suspended:aegis:halt", amount

    def test_a_pattern_restriction_denies_a_foreign_action(self, estate):
        estate.aegis.narrow(
            estate.root_fingerprint,
            key="aegis:actions",
            reason="narrowed to reads",
            patterns=["payments.read"],
        )

        outcome = estate.sdk.authorize(
            estate.root,
            "payments.send",
            {"amount": 1},
        )

        assert outcome.allowed is False
        assert outcome.reason == "aegis_action_not_permitted:aegis:actions"


# ======================================================================
# An ancestor's restriction binds the descendant
# ======================================================================


class TestAncestorRestrictions:
    def test_suspending_the_parent_denies_the_child(self, estate):
        """The delegation half of "a child never widens its parent".

        Presenting the child must not escape a restriction on the root. The
        gate reads the whole chain, so the reason names the *parent's* key
        even though the request carried the child.
        """

        estate.aegis.suspend(
            estate.root_fingerprint,
            key="aegis:halt",
            reason="parent suspended",
        )

        outcome = estate.send(estate.child)

        assert outcome.allowed is False
        assert outcome.reason == "aegis_suspended:aegis:halt"

    def test_narrowing_the_parent_binds_the_child(self, estate):
        estate.aegis.narrow(
            estate.root_fingerprint,
            key="aegis:ceiling",
            reason="parent narrowed to 5",
            constraints={"amount_max": 5},
        )

        # The child's own signed ceiling is 50 and it asks for 20: inside
        # its own grant, outside its parent's current envelope.
        outcome = estate.send(estate.child, amount=20)

        assert outcome.allowed is False
        assert outcome.reason == "aegis_constraint_denied:aegis:ceiling"

    def test_restricting_the_child_leaves_the_parent_alone(self, estate):
        """Restrictions flow down the chain, not up.

        A narrowing on a delegate says nothing about the delegator, and a
        gate that walked upwards would let a compromised child suspend the
        agent that granted it.
        """

        estate.aegis.suspend(
            estate.child_fingerprint,
            key="aegis:halt",
            reason="child suspended",
        )

        assert estate.send(estate.child).allowed is False
        assert estate.send(estate.root).allowed is True

    def test_the_envelope_narrows_across_the_edge(self, estate):
        """The child's envelope stays inside the parent's. ENVELOPE_MONOTONICITY
        checks this over the estate; here it is checked over one known edge
        with known numbers, so a regression names the edge rather than a
        census.
        """

        parent = estate.sdk.authority_envelope(estate.root)
        child = estate.sdk.authority_envelope(estate.child)

        assert parent.bottom is False
        assert child.bottom is False
        assert child.is_subset_of(parent) is True
        # And not vacuously: the child really is the tighter of the two.
        assert parent.is_subset_of(child) is False


# ======================================================================
# The commit-time re-check
# ======================================================================


class _SuspendAfterTheGate(AegisController):
    """Suspends the instant ``_gate_aegis`` has finished reading it.

    Models the race the commit-time re-check exists for: an operator
    suspension landing while ``_gate_cryptographic_authority`` verifies
    signatures over the chain. The store, the restriction, and the
    ``suspended_in`` read that catches it are all the real ones -- only the
    timing is made deterministic, because a test that raced a real thread
    would pass whether or not the re-check existed.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.suspend_next = None
        self.gate_reads = 0

    def restriction_reason(self, fingerprints, action, request):
        reason = super().restriction_reason(fingerprints, action, request)
        self.gate_reads += 1

        if reason is None and self.suspend_next is not None:
            target, self.suspend_next = self.suspend_next, None
            self.suspend(
                target,
                key="aegis:race",
                reason="suspension landed while the chain was being verified",
            )

        return reason


class TestCommitTimeRecheck:
    def test_a_suspension_landing_mid_flight_is_caught_at_commit(self):
        estate = _Estate(_SuspendAfterTheGate())
        try:
            estate.aegis.suspend_next = estate.root_fingerprint

            outcome = estate.send(estate.root)

            assert estate.aegis.gate_reads == 1
            assert outcome.allowed is False
            assert outcome.reason == (
                f"aegis_suspended_at_commit:{estate.root_fingerprint}"
            )
        finally:
            estate.close()

    def test_without_the_race_the_same_request_is_allowed(self):
        # The control. Without it the test above would pass against a gate
        # that denied for some unrelated reason.
        estate = _Estate(_SuspendAfterTheGate())
        try:
            assert estate.aegis.suspend_next is None
            assert estate.send(estate.root).allowed is True
        finally:
            estate.close()

    def test_a_parent_suspended_mid_flight_denies_the_child(self):
        estate = _Estate(_SuspendAfterTheGate())
        try:
            estate.aegis.suspend_next = estate.root_fingerprint

            outcome = estate.send(estate.child)

            assert outcome.allowed is False
            assert outcome.reason == (
                f"aegis_suspended_at_commit:{estate.root_fingerprint}"
            )
        finally:
            estate.close()

    def test_a_narrowing_landing_mid_flight_is_not_re_checked(self):
        """The re-check is suspension only, and the limit is documented.

        Only the cheapest total question is asked inside the transaction: a
        full constraint evaluation there would widen the very window it
        closes. So a *narrowing* that lands after ``_gate_aegis`` is not
        caught by this request -- it binds the next one. This test exists
        to pin that as a known bound rather than let it look like a bug
        someone should quietly "fix" by re-running the whole evaluation in
        the transaction.
        """

        class _NarrowAfterTheGate(_SuspendAfterTheGate):
            def restriction_reason(self, fingerprints, action, request):
                reason = AegisController.restriction_reason(
                    self,
                    fingerprints,
                    action,
                    request,
                )
                self.gate_reads += 1

                if reason is None and self.suspend_next is not None:
                    target, self.suspend_next = self.suspend_next, None
                    self.narrow(
                        target,
                        key="aegis:race",
                        reason="narrowing landed mid-flight",
                        constraints={"amount_max": 1},
                    )

                return reason

        estate = _Estate(_NarrowAfterTheGate())
        try:
            estate.aegis.suspend_next = estate.root_fingerprint

            # This request completes: the narrowing arrived too late for it.
            assert estate.send(estate.root, amount=50).allowed is True

            # The next one sees it.
            late = estate.send(estate.root, amount=50)
            assert late.allowed is False
            assert late.reason == "aegis_constraint_denied:aegis:race"
        finally:
            estate.close()


# ======================================================================
# Every Aegis denial is attributable
# ======================================================================


class TestAttribution:
    @pytest.mark.parametrize(
        "reason,gate",
        [
            ("aegis_state_unavailable", "_gate_aegis"),
            ("aegis_state_unavailable:RuntimeError", "_gate_aegis"),
            (
                "aegis_state_unavailable:fingerprints_unreadable",
                "_gate_aegis",
            ),
            ("aegis_suspended:aegis:halt", "_gate_aegis"),
            ("aegis_constraint_denied:aegis:ceiling", "_gate_aegis"),
            ("aegis_action_not_permitted:aegis:actions", "_gate_aegis"),
            ("aegis_restriction_unreadable:aegis:odd", "_gate_aegis"),
            ("aegis_suspended_at_commit:" + "a" * 64, "_gate_transaction"),
            # v2.4 §10: the commit-time re-read is guarded, and its denial
            # is spelled apart from the ``_gate_aegis`` one so the console
            # points at the gate that actually refused.
            (
                "aegis_state_unavailable_at_commit:RuntimeError",
                "_gate_transaction",
            ),
        ],
    )
    def test_each_aegis_reason_names_its_gate(self, reason, gate):
        assert attribute_reason(reason) == gate

    def test_a_real_denial_stops_the_rendered_pipeline_at_aegis(self, estate):
        estate.aegis.suspend(
            estate.root_fingerprint,
            key="aegis:halt",
            reason="incident opened",
        )
        outcome = estate.send(estate.root)

        trace = phase_trace(
            estate.sdk,
            allowed=outcome.allowed,
            reason=outcome.reason,
        )
        status = {node["id"]: node["status"] for node in trace}

        assert status["_gate_aegis"] == "denied"
        # Everything before it was passed, and the cryptographic gate after
        # it was never reached -- which is the point of the placement.
        assert status["_gate_revocation"] == "passed"
        assert status["_gate_cryptographic_authority"] == "not_reached"

    def test_no_aegis_reason_is_unattributed(self, estate):
        """The reasons are collected from the code, not from a hand list.

        A new restriction kind that produced a new ``aegis_*`` reason would
        otherwise render as *unattributed* in the console with nothing
        failing.
        """

        from pathlib import Path

        import firewall.aegis.restriction as module

        source = Path(module.__file__).read_text(encoding="utf-8")
        produced = {
            line.split('f"')[1].split("{")[0]
            for line in source.splitlines()
            if 'return f"aegis_' in line
        }

        assert produced
        for prefix in produced:
            assert attribute_reason(f"{prefix}some-key") == "_gate_aegis", (
                prefix
            )
