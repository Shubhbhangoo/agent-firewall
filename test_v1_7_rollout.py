"""Tests for the v1.7 staged rollout state machine (``firewall.simulation.rollout``).

Rollout is governance, not authorization: it decides whether a *rule set*
has earned the right to take effect. These tests pin the gates that keep
"simulate before you enforce" honest:

* nothing is enforced on an unexamined guess -- ``promote`` before
  ``simulate`` is refused;
* a change that newly denies recorded traffic, or that the simulator
  could not fully stand behind, is refused without an explicit
  acknowledgement recorded in the history;
* evidence goes stale the moment the live rules move, and stale evidence
  cannot promote;
* promotion snapshots the previous rules so rollback is always exact;
* every transition is appended to an immutable history.

No pre-existing test is modified by this file.
"""

from __future__ import annotations

import pytest

from firewall.sdk import FirewallSDK
from firewall.simulation import (
    CaseRecorder,
    Rollout,
    RolloutError,
    RolloutStage,
    RuleSet,
)
from firewall.simulation.rollout import (
    Rollout as RolloutClass,
)


# ======================================================================
# Fixtures and helpers
# ======================================================================


@pytest.fixture()
def sdk() -> FirewallSDK:
    instance = FirewalkingSDK()
    instance.generate_key("test-key")
    return instance


def FirewalkingSDK() -> FirewallSDK:
    return FirewallSDK(
        trusted_issuers={"trusted-issuer"}
    )


def record_chain_cases(
    sdk: FirewallSDK,
    *chains: tuple[str, ...],
) -> CaseRecorder:
    """Authorize real chains and return a recorder holding the cases."""

    recorder = CaseRecorder()
    pk = sdk.active_key().private_key

    for agents in chains:
        root = sdk.issue(
            agent=agents[0],
            capability="pay.send",
            private_key=pk,
            issuer="trusted-issuer",
        )
        members = [root]

        for delegatee in agents[1:]:
            members.append(
                sdk.delegate(
                    members[-1],
                    pk,
                    delegatee=delegatee,
                ).child
            )

        decision = sdk.authorize(
            members[-1],
            "pay.send",
            {},
        )
        recorder.record(
            sdk,
            members[-1],
            "pay.send",
            {},
            decision,
        )

    return recorder


# ======================================================================
# Construction
# ======================================================================


def test_rollout_requires_a_ruleset_candidate() -> None:
    sdk = FirewalkingSDK()

    with pytest.raises(RolloutError):
        Rollout(sdk, "not-a-ruleset")  # type: ignore[arg-type]


def test_rollout_requires_a_label() -> None:
    sdk = FirewalkingSDK()

    with pytest.raises(RolloutError):
        Rollout(sdk, RuleSet(), label=" ")


def test_a_new_rollout_starts_in_observe() -> None:
    sdk = FirewalkingSDK()
    rollout = Rollout(sdk, RuleSet())

    assert rollout.stage is RolloutStage.OBSERVE
    assert rollout.report is None
    assert rollout.evidence_is_current is False


def test_observe_stage_records_the_proposal() -> None:
    sdk = FirewalkingSDK()
    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
        label="depth-2",
    )

    assert rollout.history[0]["event"] == "proposed"
    assert rollout.history[0]["label"] == "depth-2"
    assert rollout.history[0]["stage"] == "observe"


# ======================================================================
# observe -> warn
# ======================================================================


def test_simulate_moves_the_rollout_to_warn(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    report = rollout.simulate(
        recorder.cases()
    )

    assert rollout.stage is RolloutStage.WARN
    assert rollout.report is report
    assert rollout.evidence_is_current
    assert rollout.history[-1]["event"] == (
        "simulated"
    )


def test_simulate_never_touches_the_target_sdk(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=1),
    )
    rollout.simulate(recorder.cases())

    assert sdk.max_delegation_depth is None


# ======================================================================
# warn -> enforce: the gates
# ======================================================================


def test_promote_before_simulate_is_refused(
    sdk: FirewallSDK,
) -> None:
    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )

    with pytest.raises(RolloutError) as exc:
        rollout.promote()

    assert "simulate before promoting" in str(
        exc.value
    )
    assert rollout.stage is RolloutStage.OBSERVE


def test_a_change_that_newly_denies_requires_acknowledgement(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())

    with pytest.raises(RolloutError) as exc:
        rollout.promote()

    assert "newly denied" in str(exc.value)
    assert sdk.max_delegation_depth is None
    assert rollout.stage is RolloutStage.WARN


def test_an_unverifiable_change_requires_acknowledgement(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    # Hand-edited case: the observed decision is not recorded, so the
    # simulator cannot stand behind it.
    from firewall.simulation.case import RequestCase

    case = next(iter(recorder.cases()))

    unverifiable = RequestCase(
        **{
            **case.to_dict(),
            "case_id": "unverifiable",
            "baseline_reason": None,
        }
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    report = rollout.simulate([unverifiable])

    assert report.totals["excluded"] == 1

    with pytest.raises(RolloutError) as exc:
        rollout.promote()

    assert "could not be verified" in str(
        exc.value
    )


def test_acknowledgement_allows_a_blocking_promotion(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())

    restore_point = rollout.promote(
        acknowledge=True,
        actor="operator",
    )

    assert rollout.stage is RolloutStage.ENFORCE
    assert sdk.max_delegation_depth == 2
    assert restore_point.max_delegation_depth is None

    enforced = [
        entry
        for entry in rollout.history
        if entry["event"] == "enforced"
    ]
    assert len(enforced) == 1
    assert enforced[0]["detail"][
        "acknowledged"
    ] is True
    assert enforced[0]["detail"]["actor"] == (
        "operator"
    )
    assert enforced[0]["detail"][
        "restore_point"
    ]["max_delegation_depth"] is None


def test_a_safe_change_promotes_without_acknowledgement(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    # Trusting an additional issuer denies nothing and needs no ack.
    candidate = RuleSet(
        trusted_issuers={
            "trusted-issuer",
            "extra-issuer",
        }
    )

    rollout = Rollout(
        sdk,
        candidate,
    )
    rollout.simulate(recorder.cases())

    rollout.promote()

    assert rollout.stage is RolloutStage.ENFORCE
    assert sdk.is_issuer_trusted("extra-issuer")


def test_promote_twice_is_refused(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)

    with pytest.raises(RolloutError):
        rollout.promote()


# ======================================================================
# Stale evidence
# ======================================================================


def test_stale_evidence_cannot_promote(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=1),
    )
    rollout.simulate(recorder.cases())

    # The live rules move after the simulation ran.
    sdk.max_delegation_depth = 3

    assert not rollout.evidence_is_current

    with pytest.raises(RolloutError) as exc:
        rollout.promote(acknowledge=True)

    assert "live rules changed" in str(exc.value)
    assert rollout.stage is RolloutStage.WARN


def test_resimulation_refreshes_stale_evidence(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=1),
    )
    rollout.simulate(recorder.cases())

    sdk.max_delegation_depth = 3
    assert not rollout.evidence_is_current

    rollout.simulate(recorder.cases())

    assert rollout.evidence_is_current
    # The simulation now compares against depth 3 as the baseline.
    assert rollout.report.before[
        "max_delegation_depth"
    ] == 3


def test_simulate_is_refused_after_enforcement(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)

    with pytest.raises(RolloutError) as exc:
        rollout.simulate(recorder.cases())

    assert "already enforced" in str(exc.value)


# ======================================================================
# enforce -> reverted: rollback
# ======================================================================


def test_rollback_restores_the_exact_prior_rules(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    # The world before: a depth ceiling of 3 is already in force.
    sdk.max_delegation_depth = 3
    sdk.trust_issuer("kept-issuer")

    candidate = RuleSet(
        max_delegation_depth=2,
        trusted_issuers={
            "trusted-issuer",
            "kept-issuer",
        },
    )

    rollout = Rollout(sdk, candidate)
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)

    assert sdk.max_delegation_depth == 2

    restored = rollout.rollback(actor="operator")

    assert rollout.stage is RolloutStage.REVERTED
    assert restored.max_delegation_depth == 3
    assert sdk.max_delegation_depth == 3
    # Unrelated trust is preserved exactly.
    assert sdk.is_issuer_trusted("kept-issuer")

    rolled_back = [
        entry
        for entry in rollout.history
        if entry["event"] == "rolled_back"
    ]
    assert rolled_back[0]["detail"]["actor"] == (
        "operator"
    )
    assert rolled_back[0]["detail"]["restored"][
        "max_delegation_depth"
    ] == 3


def test_rollback_before_enforcement_is_refused(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())

    with pytest.raises(RolloutError) as exc:
        rollout.rollback()

    assert "not enforced" in str(exc.value)


def test_rollback_twice_is_refused(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)
    rollout.rollback()

    with pytest.raises(RolloutError):
        rollout.rollback()


def test_a_reverted_rollout_cannot_promote_or_resimulate(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)
    rollout.rollback()

    with pytest.raises(RolloutError):
        rollout.promote()

    with pytest.raises(RolloutError):
        rollout.simulate(recorder.cases())


def test_withdraw_abandons_an_unenforced_candidate(
    sdk: FirewallSDK,
) -> None:
    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )

    rollout.withdraw(actor="operator")

    assert rollout.stage is RolloutStage.REVERTED
    assert rollout.history[-1]["event"] == (
        "withdrawn"
    )

    # Withdrawing twice is a no-op, not an error.
    rollout.withdraw()


def test_withdraw_is_refused_after_enforcement(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)

    with pytest.raises(RolloutError) as exc:
        rollout.withdraw()

    assert "roll back instead" in str(exc.value)


# ======================================================================
# Projection and history
# ======================================================================


def test_state_reports_the_full_picture(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
        label="depth-2",
    )
    rollout.simulate(recorder.cases())

    state = rollout.state()

    assert state["label"] == "depth-2"
    assert state["stage"] == "warn"
    assert state["evidence_is_current"] is True
    assert state["candidate"][
        "max_delegation_depth"
    ] == 2
    assert state["report"]["totals"] is not None
    assert state["restore_point"] is None
    assert state["history"][0]["event"] == (
        "proposed"
    )
    assert state["history"][-1]["event"] == (
        "simulated"
    )


def test_state_exposes_the_restore_point_after_enforcement(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())
    rollout.promote(acknowledge=True)

    state = rollout.state()

    assert state["stage"] == "enforce"
    assert state["restore_point"][
        "max_delegation_depth"
    ] is None
    assert state["blocking"] != []


def test_history_is_append_only_and_ordered(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a",),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())

    seqs = [
        entry["seq"] for entry in rollout.history
    ]

    assert seqs == [1, 2]
    assert [
        entry["event"]
        for entry in rollout.history
    ] == ["proposed", "simulated"]


def test_history_is_immutable_to_callers() -> None:
    sdk = FirewalkingSDK()

    rollout = Rollout(sdk, RuleSet())

    # Mutating the returned projection must not rewrite what was
    # recorded: the history is a deep copy, not a live view.
    history = rollout.history
    history[0]["event"] = "tampered"  # type: ignore[index]
    history[0]["detail"]["candidate"] = {}  # type: ignore[index]

    assert rollout.history[0]["event"] == "proposed"
    assert "candidate" in rollout.history[0][
        "detail"
    ]


def test_current_reflects_the_target_sdk(
    sdk: FirewallSDK,
) -> None:
    sdk.max_delegation_depth = 5

    rollout = Rollout(sdk, RuleSet())

    assert rollout.current().max_delegation_depth == 5


def test_blocking_findings_are_exposed_before_promotion(
    sdk: FirewallSDK,
) -> None:
    recorder = record_chain_cases(
        sdk,
        ("agent-a", "agent-b", "agent-c"),
    )

    rollout = Rollout(
        sdk,
        RuleSet(max_delegation_depth=2),
    )
    rollout.simulate(recorder.cases())

    state = rollout.state()

    assert any(
        "newly denied" in finding
        for finding in state["blocking"]
    )


def test_rollout_class_alias_is_the_same_type() -> None:
    assert Rollout is RolloutClass
