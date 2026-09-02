"""v2.3: the strict invariant gate can pass, so it is worth failing.

``python -m firewall.invariants --strict`` was unusable in CI. Five of
the eleven invariants are claims about live state -- a signed delegation
edge, an attenuation, a propagated revocation, an applied policy
transformation, a simulation that ran -- and a source-only run has none
of them, so strict exited 2 on every invocation. A gate that always fails
is a gate that gets removed, which left the five state-dependent
invariants checked only by ``tests/test_v2_2_invariants.py`` and not by
the command CI runs.

``firewall.invariants.exercise`` builds the state. The properties under
test here are that it builds it *through the SDK's public API*, that the
estate is awkward in the places that matter (a mid-chain revocation, an
attenuation with no signed parent), that a green exercised run does not
overclaim, and that the estate cannot be used to make the suite pass
vacuously.
"""

from __future__ import annotations

import pytest

from firewall.invariants import __main__ as entry
from firewall.invariants import (
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
    def test_all_eleven_invariants_hold_on_it(self, exercised_report):
        report = exercised_report

        assert len(report.results) == 11
        assert report.holds is True
        assert report.violations == ()
        assert report.unverifiable == ()

    def test_nothing_is_left_unexercised(self, exercised_report):
        # A state-dependent invariant the estate does not reach would
        # narrow the strict gate below eleven without saying so.
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

    def test_a_fresh_sdk_still_leaves_four_unverifiable(self):
        # The exerciser is the thing that changes the answer. A fresh SDK
        # is enough for SIMULATION_ISOLATION, which builds its own cases,
        # and not for the four invariants that read lineage, attenuation,
        # revocation and policy history.
        sdk = FirewallSDK()
        try:
            report = check_all(sdk)
        finally:
            sdk.close()

        assert [item.name for item in report.unverifiable] == [
            "DELEGATION_MONOTONICITY",
            "CAPABILITY_MONOTONICITY",
            "REVOCATION_MONOTONICITY",
            "POLICY_NON_WIDENING",
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

    def test_an_existing_sdk_can_be_exercised(self):
        sdk = FirewallSDK()
        try:
            built = canonical_estate(sdk)

            assert built.sdk is sdk
            assert built.policy_history
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
        assert "11 holds" in out
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
        assert len(payload["results"]) == 11

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
