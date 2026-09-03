"""v2.3: the strict invariant gate can pass, so it is worth failing.

``python -m firewall.invariants --strict`` was unusable in CI. Seven of
the sixteen invariants are claims about live state -- a signed delegation
edge, an attenuation, a propagated revocation, an applied policy
transformation, a simulation that ran, an authority envelope projected
either side of a lineage edge, a recorded Aegis history -- and a
source-only run has none of them, so strict exited 2 on every invocation.
A gate that always fails is a gate that gets removed, which left the
state-dependent invariants checked only by
``tests/test_v2_2_invariants.py`` and not by the command CI runs.

``firewall.invariants.exercise`` builds the state. The properties under
test here are that it builds it *through the SDK's public API*, that the
estate is awkward in the places that matter (a mid-chain revocation, an
attenuation with no signed parent, an unrevoked peer branch, an Aegis
grant walked back to ``ACTIVE`` the long way), that a green exercised run
does not overclaim, and that the estate cannot be used to make the suite
pass vacuously.
"""

from __future__ import annotations

import pytest

from firewall.invariants import __main__ as entry
from firewall.invariants import (
    AEGIS_EXERCISE_KEY,
    CANONICAL_ESTATE_CAVEAT,
    INVARIANTS,
    Estate,
    ExerciseError,
    InvariantStatus,
    canonical_estate,
    check_all,
    check_exercised,
    narrowing_policy_history,
)
from firewall.invariants.exercise import (
    EXERCISE_KEY_ID,
    unexercised_names,
)
from firewall.sdk import FirewallSDK


@pytest.fixture(scope="module")
def exercised_report():
    """One exercised run, shared by the tests that only read it.

    A full run scans the source tree and replays a simulation, so
    rebuilding it per test costs seconds for no extra coverage. The report
    is immutable data; the estate it described is already closed.
    """

    return check_exercised()


@pytest.fixture
def estate() -> Estate:
    built = canonical_estate()
    yield built
    built.close()


def _status(report, name: str) -> InvariantStatus:
    for item in report.results:
        if item.name == name:
            return item.status
    raise AssertionError(f"{name} is not in the report")


# ======================================================================
# The estate reaches every state-dependent invariant
# ======================================================================


class TestCanonicalEstate:
    def test_all_sixteen_invariants_hold_on_it(self, exercised_report):
        report = exercised_report

        assert len(report.results) == 16
        assert report.holds is True
        assert report.violations == ()
        assert report.unverifiable == ()

    def test_nothing_is_left_unexercised(self, exercised_report):
        # A state-dependent invariant the estate does not reach would
        # narrow the strict gate below sixteen without saying so.
        assert unexercised_names(exercised_report.results) == ()

    def test_every_state_dependent_invariant_is_reached(
        self, exercised_report
    ):
        report = exercised_report

        for entry_ in INVARIANTS:
            if entry_.needs_state:
                assert _status(report, entry_.name) is (
                    InvariantStatus.HOLDS
                ), entry_.name

    def test_a_fresh_sdk_still_leaves_six_unverifiable(self):
        # The exerciser is the thing that changes the answer. A fresh SDK
        # is enough for SIMULATION_ISOLATION, which builds its own cases,
        # and not for the six invariants that read lineage, attenuation,
        # envelopes either side of an edge, revocation, policy history and
        # a recorded Aegis history.
        #
        # Pinned as an ordered list, not a set: the order is the report
        # order, so a state-dependent invariant inserted without an
        # exerciser branch changes this list rather than passing unnoticed.
        sdk = FirewallSDK()
        try:
            report = check_all(sdk)
        finally:
            sdk.close()

        assert [item.name for item in report.unverifiable] == [
            "DELEGATION_MONOTONICITY",
            "CAPABILITY_MONOTONICITY",
            "ENVELOPE_MONOTONICITY",
            "REVOCATION_MONOTONICITY",
            "POLICY_NON_WIDENING",
            "AEGIS_STATE_TRANSITIONS",
        ]
        assert report.holds is False


class TestEstateShape:
    def test_the_revocation_is_mid_chain(self, estate):
        # A revoked leaf would satisfy REVOCATION_MONOTONICITY
        # vacuously: there would be no descendant to propagate to.
        assert estate.revoked_agents == (
            "agent-child",
            "agent-grandchild",
        )

    def test_the_grandchild_is_effectively_revoked(self, estate):
        revoked = [
            capability
            for capability in estate.sdk.known_capabilities().values()
            if capability.agent_id == "agent-grandchild"
        ]

        assert revoked
        assert all(
            estate.sdk.is_effectively_revoked(capability)
            for capability in revoked
        )

    def test_the_policy_history_narrows_in_two_dimensions(self):
        history = narrowing_policy_history()

        assert len(history) == 1
        old, new = history[0]
        assert old.constraints["action"] == ["send", "refund"]
        assert new.constraints["action"] == ["send"]
        assert (
            new.constraints["lineage"]["delegation_depth"]["lte"]
            < old.constraints["lineage"]["delegation_depth"]["lte"]
        )

    def test_the_estate_signs_with_its_own_key(self, estate):
        assert estate.sdk.active_key().key_id == EXERCISE_KEY_ID

    def test_one_branch_survives_the_revocation(self, estate):
        """ENVELOPE_MONOTONICITY needs an edge with two live endpoints.

        A revoked capability projects the bottom envelope, and bottom is
        contained in everything -- so an estate in which every edge had a
        revoked endpoint would satisfy the containment claim with nothing
        left to contain. The peer branch is the edge that makes the
        invariant say something.
        """

        peers = [
            capability
            for capability in estate.sdk.known_capabilities().values()
            if capability.agent_id == "agent-peer"
        ]

        assert len(peers) == 1
        peer = peers[0]

        assert estate.sdk.is_revoked(peer) is False
        assert estate.sdk.is_effectively_revoked(peer) is False

        # Found through the lineage rather than by agent id, because the
        # attenuation is also issued to agent-root and would otherwise be
        # indistinguishable from the delegation's parent.
        known = estate.sdk.known_capabilities()
        peer_fingerprint = estate.sdk.fingerprint(peer)
        parents = [
            known[record.parent_fingerprint]
            for record in estate.sdk.delegation_lineage.snapshot()
            if record.child_fingerprint == peer_fingerprint
            and record.parent_fingerprint in known
        ]

        assert len(parents) == 1
        assert estate.sdk.is_effectively_revoked(parents[0]) is False

        # Both endpoints project a real bound, so the containment the
        # invariant checks across this edge is not bottom-in-anything.
        assert estate.sdk.authority_envelope(peer).bottom is False
        assert estate.sdk.authority_envelope(parents[0]).bottom is False

    def test_the_aegis_grant_reaches_active_the_long_way(self, estate):
        """The evidenced edge is traversed, not merely present in the algebra.

        ``REVALIDATING -> ACTIVE`` is the one transition that raises
        residual authority, and the only one that demands a canonical
        ``FirewallSDK.authorize()`` allow. An estate that registered a grant
        and left it ``ISSUED`` would let AEGIS_STATE_TRANSITIONS audit a
        history containing no widening at all -- which is exactly the case
        its evidence rule exists to constrain.
        """

        assert estate.aegis_exercised is True

        controller = estate.sdk.aegis
        assert controller is not None

        fingerprints = list(controller.grants())
        assert len(fingerprints) == 1

        grant = controller.grant(fingerprints[0])
        assert grant is not None
        assert grant.state.value == "active"

        walked = [
            (item.from_state.value, item.to_state.value)
            for item in grant.history
        ]
        assert walked == [
            ("issued", "narrowed"),
            ("narrowed", "revalidating"),
            ("revalidating", "active"),
        ]

        narrowing, lift, restoration = grant.history

        # The narrowing is what put the grant below ACTIVE; the lift only
        # removed the obstacle. Neither carries evidence, because neither
        # raises authority.
        assert narrowing.evidence is None
        assert lift.lifted == AEGIS_EXERCISE_KEY
        assert lift.evidence is None

        # The restoration does, and it is a digest of a real verdict rather
        # than a flag the exerciser set.
        assert isinstance(restoration.evidence, str)
        assert len(restoration.evidence) == 64

    def test_an_existing_sdk_can_be_exercised(self):
        sdk = FirewallSDK()
        try:
            built = canonical_estate(sdk)

            assert built.sdk is sdk
            assert built.policy_history
        finally:
            sdk.close()

    def test_an_aegis_off_sdk_is_reported_rather_than_overridden(self):
        """Aegis is opt-in, and the exerciser does not switch it on.

        Installing a controller on a caller's SDK would change the
        configuration under test, and reaching past ``sdk.aegis`` to do it
        would be the control-plane access CONTROL_PLANE_INTEGRITY forbids.
        So the Aegis half is skipped, ``aegis_exercised`` says so, and
        AEGIS_STATE_TRANSITIONS reports ``UNVERIFIABLE`` -- a true
        statement about that SDK rather than a defect.
        """

        sdk = FirewallSDK()
        try:
            built = canonical_estate(sdk)

            assert sdk.aegis is None
            assert built.aegis_exercised is False

            report = check_all(
                built.sdk,
                policy_history=list(built.policy_history),
            )

            # Every other state-dependent invariant is still reached: the
            # skip is scoped to the one claim that needs a controller.
            assert [item.name for item in report.unverifiable] == [
                "AEGIS_STATE_TRANSITIONS"
            ]
            assert report.violations == ()
            assert report.holds is False
        finally:
            sdk.close()

    def test_the_estate_closes_idempotently(self):
        built = canonical_estate()

        built.close()
        built.close()

    def test_check_exercised_closes_the_estate_it_built(self):
        # The report must not be a handle back into a live SDK.
        report = check_exercised()

        assert not hasattr(report, "sdk")


# ======================================================================
# A failure to build is a defect, not a missing wiring
# ======================================================================


class TestExerciseFailure:
    def test_a_refused_step_raises_rather_than_half_building(self):
        class _RefusingSDK(FirewallSDK):
            def delegate(self, *args, **kwargs):
                raise RuntimeError("delegation refused")

        sdk = _RefusingSDK()
        try:
            with pytest.raises(ExerciseError) as caught:
                canonical_estate(sdk)
        finally:
            sdk.close()

        assert "delegation refused" in str(caught.value)

    def test_unpropagated_revocation_is_named_as_the_defect(self):
        class _LeakySDK(FirewallSDK):
            def is_effectively_revoked(self, capability) -> bool:
                return False

        sdk = _LeakySDK()
        try:
            with pytest.raises(ExerciseError) as caught:
                canonical_estate(sdk)
        finally:
            sdk.close()

        message = str(caught.value)
        assert "REVOCATION_MONOTONICITY" in message
        # The estate is not the thing at fault, and the message says so.
        assert "the firewall is not" in message


# ======================================================================
# The command line: exit codes and what they claim
# ======================================================================


class TestEntryPoint:
    def test_exercise_and_strict_exit_zero(self, capsys):
        assert entry.main(["--exercise", "--strict"]) == entry.EXIT_OK

        out = capsys.readouterr().out
        assert "16 holds" in out
        assert "0 unverifiable" in out

    def test_source_only_strict_still_refuses_to_pass(self):
        # Unchanged from v2.2: without state, strict is exit 2.
        assert (
            entry.main(["--strict"]) == entry.EXIT_UNVERIFIABLE
        )

    def test_exercised_output_states_its_scope(self, capsys):
        entry.main(["--exercise"])

        assert CANONICAL_ESTATE_CAVEAT in capsys.readouterr().out

    def test_source_only_output_makes_no_estate_claim(self, capsys):
        entry.main([])

        assert CANONICAL_ESTATE_CAVEAT not in capsys.readouterr().out

    def test_exercised_json_carries_the_caveat(self, capsys):
        import json

        entry.main(["--exercise", "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert payload["caveat"] == CANONICAL_ESTATE_CAVEAT
        assert len(payload["results"]) == 16

    def test_a_broken_estate_is_a_failure_not_an_unverifiable(
        self, monkeypatch, capsys
    ):
        def explode():
            raise ExerciseError("the firewall refused to issue")

        monkeypatch.setattr(entry, "check_exercised", explode)

        assert entry.main(["--exercise"]) == entry.EXIT_VIOLATED
        assert "could not be built" in capsys.readouterr().out

    def test_the_exercise_flag_is_documented(self, capsys):
        with pytest.raises(SystemExit):
            entry.main(["--help"])

        assert "--exercise" in capsys.readouterr().out


# ======================================================================
# Exercising grants nothing
# ======================================================================


class TestExerciseIsNotAuthority:
    def test_the_estate_holds_no_verdict(self, estate):
        assert not hasattr(estate, "allowed")
        assert not hasattr(estate, "authorize")

    def test_a_holding_report_authorizes_nothing(self, estate):
        report = check_all(
            estate.sdk,
            policy_history=list(estate.policy_history),
        )

        assert report.holds is True
        # The revoked chain is still revoked. A green suite does not
        # restore authority it merely described.
        for capability in estate.sdk.known_capabilities().values():
            if capability.agent_id == "agent-grandchild":
                assert estate.sdk.is_effectively_revoked(capability)

    def test_the_exercise_module_constructs_no_authorization_result(self):
        from pathlib import Path

        import firewall.invariants.exercise as module

        source = Path(module.__file__).read_text(encoding="utf-8")

        assert "AuthorizationResult(" not in source
        assert "allowed=True" not in source


_NUMBER_WORDS = {
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
    13: "thirteen",
    14: "fourteen",
    15: "fifteen",
    16: "sixteen",
    17: "seventeen",
    18: "eighteen",
    19: "nineteen",
    20: "twenty",
}


class TestTheCIGateDescribesItself:
    """The workflow's own words are checked, because they went stale twice.

    ``security.yml`` names the strict step "Gate all sixteen invariants on
    an exercised estate" and explains in a comment how many are
    state-dependent. Both numbers were corrected by hand in v2.4 and both
    went stale again the moment v2.5 registered a sixteenth invariant --
    a gate whose name misdescribes it is a gate people stop reading, and
    nothing was checking the name.

    This is a documentation-truth test, not a security property. It does
    not establish that the gate runs, that it fails on a violation, or
    that CI is configured to require it; ``TestEntryPoint`` covers the
    exit codes and the workflow itself covers the wiring.
    """

    def _workflow(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "security.yml"
        )

        assert path.is_file(), f"the security gate workflow is missing: {path}"

        return path.read_text(encoding="utf-8")

    def test_the_strict_step_name_counts_the_registered_invariants(self):
        expected = _NUMBER_WORDS[len(INVARIANTS)]
        step = f"Gate all {expected} invariants on an exercised estate"

        assert step in self._workflow(), (
            f"security.yml must say {expected!r}: the registry holds "
            f"{len(INVARIANTS)} invariants"
        )

    def test_the_source_step_comment_counts_the_state_dependent_ones(self):
        # The source-only run reports these as unverifiable rather than
        # failing, and the comment above the step says how many that is.
        # Derived from a real run rather than from a second hand-kept
        # constant, so registering a state-dependent invariant moves it.
        report = check_all()
        unverifiable = sum(
            1
            for name in (spec.name for spec in INVARIANTS)
            if _status(report, name) is InvariantStatus.UNVERIFIABLE
        )
        expected = _NUMBER_WORDS[unverifiable]

        assert f"the {expected} state-dependent invariants" in self._workflow(), (
            f"security.yml must say {expected!r}: a source-only run "
            f"reports {unverifiable} invariants unverifiable"
        )
