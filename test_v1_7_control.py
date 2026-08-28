"""Tests for the v1.7 control-plane integration
(``firewall.ui.control``): record -> simulate -> promote -> rollback.

The control plane is the console's only write path, so the v1.7 workflow
must inherit its discipline:

* checking a request records a replayable case *after* the verdict
  exists, so recording can never influence a decision;
* ``simulate`` never touches the live SDK -- candidate rules live only
  inside throwaway replay workspaces;
* a partial proposal inherits the rules currently in force instead of
  reading as "untrust everything";
* ``promote`` re-runs the simulation itself against the rules actually in
  force, refuses a change that newly denies recorded traffic without an
  explicit acknowledgement, and records every attempt in the audit log;
* ``rollback`` restores the exact rules displaced by the promotion.

No pre-existing test is modified by this file.
"""

from __future__ import annotations

import pytest

from firewall.sdk import FirewallSDK
from firewall.ui.control import (
    ControlError,
    ControlPlane,
)


# ======================================================================
# Fixtures and helpers
# ======================================================================


@pytest.fixture()
def sdk() -> FirewallSDK:
    instance = FirewallSDK(
        trusted_issuers={"trusted-issuer"}
    )
    instance.generate_key("test-key")
    return instance


@pytest.fixture()
def plane(sdk: FirewallSDK) -> ControlPlane:
    return ControlPlane(sdk)


def connect(
    plane: ControlPlane,
    *,
    agent: str = "agent-alpha",
    capability: str = "payments.send",
) -> dict:
    return plane.connect_agent(
        {
            "agent": agent,
            "capability": capability,
            "constraints": {"amount_max": 1000},
        }
    )


def check(
    plane: ControlPlane,
    fingerprint: str,
    *,
    action: str = "payments.send",
    request: dict | None = None,
) -> dict:
    # The connected capability carries amount_max=1000, so a request must
    # name an amount to be allowed.
    return plane.check(
        {
            "fingerprint": fingerprint,
            "action": action,
            "request": (
                {"amount": 50}
                if request is None
                else request
            ),
        }
    )


def connect_deep_chain(
    plane: ControlPlane,
) -> dict:
    """Connect an agent and delegate twice, returning the leaf view."""

    root = connect(plane, agent="agent-a")
    child = plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-b",
        }
    )
    grand = plane.delegate(
        {
            "fingerprint": child["fingerprint"],
            "delegatee": "agent-c",
        }
    )
    return grand


# ======================================================================
# Recording through check()
# ======================================================================


def test_check_records_a_replayable_case(
    plane: ControlPlane,
) -> None:
    view = connect(plane)
    check(plane, view["fingerprint"])

    cases = plane.cases()

    assert len(cases) == 1
    assert cases[0]["root_agent"] == "agent-alpha"
    assert cases[0]["action"] == "payments.send"
    assert cases[0]["baseline_allowed"] is True
    assert cases[0]["baseline_reason"] == (
        "authorized"
    )

    projection = plane.simulation()
    assert projection["recorded_cases"] == 1


def test_check_records_a_denial_too(
    plane: ControlPlane,
) -> None:
    view = connect(plane)

    # The connected capability is capped at amount_max 1000.
    check(
        plane,
        view["fingerprint"],
        request={"amount": 99999},
    )

    case = plane.cases()[0]

    assert case["baseline_allowed"] is False


def test_identical_checks_collapse_to_one_case(
    plane: ControlPlane,
) -> None:
    view = connect(plane)

    check(plane, view["fingerprint"])
    check(plane, view["fingerprint"])

    assert len(plane.cases()) == 1


def test_a_delegated_chain_records_all_hops(
    plane: ControlPlane,
) -> None:
    grand = connect_deep_chain(plane)

    check(plane, grand["fingerprint"])

    case = plane.cases()[0]

    assert case["root_agent"] == "agent-a"
    assert [hop["delegatee"] for hop in case["hops"]] == [
        "agent-b",
        "agent-c",
    ]
    assert 1 + len(case["hops"]) == 3


# ======================================================================
# simulate: read-only, inheritance, and validation
# ======================================================================


def test_simulate_reports_the_change_without_touching_the_sdk(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    grand = connect_deep_chain(plane)
    check(plane, grand["fingerprint"])

    result = plane.simulate(
        {"max_delegation_depth": 2}
    )

    report = result["report"]

    assert report["totals"]["newly_denied"] == 1
    assert report["blast_radius"]["agents"] == [
        "agent-c"
    ]

    # The live SDK is untouched by the simulation.
    assert sdk.max_delegation_depth is None

    current = result["current"]
    assert current["max_delegation_depth"] is None
    assert result["candidate"][
        "max_delegation_depth"
    ] == 2


def test_simulate_is_audited(
    plane: ControlPlane,
) -> None:
    result = plane.simulate({})

    entries = [
        entry
        for entry in plane.audit()
        if entry["action"] == "simulate"
    ]

    assert len(entries) == 1
    assert entries[0]["ok"] is True


def test_a_partial_proposal_inherits_current_rules(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    """A depth-only payload must not read as 'untrust every issuer'."""

    connect(plane, agent="agent-a")
    sdk.trust_issuer("kept-issuer")

    result = plane.simulate(
        {"max_delegation_depth": 1}
    )

    candidate = result["candidate"]

    assert candidate["max_delegation_depth"] == 1
    assert "kept-issuer" in candidate[
        "trusted_issuers"
    ]


def test_simulate_accepts_an_explicit_issuer_list(
    plane: ControlPlane,
) -> None:
    connect(plane, agent="agent-a")

    result = plane.simulate(
        {
            "trusted_issuers": [
                "trusted-issuer",
                "new-issuer",
            ]
        }
    )

    assert result["candidate"][
        "trusted_issuers"
    ] == ["new-issuer", "trusted-issuer"]


def test_simulate_rejects_a_non_list_issuer_set(
    plane: ControlPlane,
) -> None:
    with pytest.raises(ControlError):
        plane.simulate(
            {"trusted_issuers": "trusted-issuer"}
        )


def test_simulate_rejects_an_invalid_depth(
    plane: ControlPlane,
) -> None:
    with pytest.raises(ControlError):
        plane.simulate(
            {"max_delegation_depth": 0}
        )


# ======================================================================
# promote: simulate-before-enforce on the control plane
# ======================================================================


def test_promote_runs_its_own_simulation(
    plane: ControlPlane,
) -> None:
    """The simulation is not optional and not caller-supplied."""

    grand = connect_deep_chain(plane)
    check(plane, grand["fingerprint"])

    with pytest.raises(ControlError) as exc:
        plane.promote(
            {"max_delegation_depth": 2}
        )

    assert "newly denied" in str(exc.value)

    # The SDK was not changed by the refused promotion.
    assert plane.sdk.max_delegation_depth is None


def test_promote_refuses_a_newly_denying_change_without_ack(
    plane: ControlPlane,
) -> None:
    grand = connect_deep_chain(plane)
    check(plane, grand["fingerprint"])

    with pytest.raises(ControlError):
        plane.promote(
            {"max_delegation_depth": 2}
        )

    # The refusal is audited.
    refused = [
        entry
        for entry in plane.audit()
        if entry["action"] == "promote"
    ]
    assert len(refused) == 1
    assert refused[0]["ok"] is False


def test_promote_with_acknowledgement_enforces(
    plane: ControlPlane,
) -> None:
    grand = connect_deep_chain(plane)
    check(plane, grand["fingerprint"])

    result = plane.promote(
        {
            "max_delegation_depth": 2,
            "acknowledge": True,
            "label": "cap depth at 2",
        }
    )

    rollout = result["rollout"]

    assert rollout["stage"] == "enforce"
    assert rollout["label"] == "cap depth at 2"
    assert plane.sdk.max_delegation_depth == 2

    # The acknowledgement is written into the rollout history.
    enforced = [
        entry
        for entry in rollout["history"]
        if entry["event"] == "enforced"
    ]
    assert enforced[0]["detail"]["acknowledged"] is (
        True
    )

    # The promotion itself is audited.
    promoted = [
        entry
        for entry in plane.audit()
        if entry["action"] == "promote"
        and entry["ok"]
    ]
    assert len(promoted) == 1
    assert promoted[0]["detail"][
        "acknowledged"
    ] is True


def test_promote_requires_a_boolean_acknowledgement(
    plane: ControlPlane,
) -> None:
    with pytest.raises(ControlError):
        plane.promote(
            {
                "max_delegation_depth": 2,
                "acknowledge": "yes",  # type: ignore[arg-type]
            }
        )


def test_rollback_restores_the_exact_prior_rules(
    plane: ControlPlane,
) -> None:
    grand = connect_deep_chain(plane)
    check(plane, grand["fingerprint"])

    plane.sdk.trust_issuer("kept-issuer")
    plane.sdk.max_delegation_depth = 3

    plane.promote(
        {
            "max_delegation_depth": 2,
            "acknowledge": True,
        }
    )

    assert plane.sdk.max_delegation_depth == 2

    result = plane.rollback()

    assert result["rollout"]["stage"] == "reverted"
    assert result["rules"][
        "max_delegation_depth"
    ] == 3
    assert plane.sdk.max_delegation_depth == 3
    # Unrelated trust survives the round trip.
    assert plane.sdk.is_issuer_trusted(
        "kept-issuer"
    )


def test_rollback_without_a_promotion_is_an_error(
    plane: ControlPlane,
) -> None:
    with pytest.raises(ControlError) as exc:
        plane.rollback()

    assert "nothing has been promoted" in str(
        exc.value
    )


def test_rollback_is_audited(
    plane: ControlPlane,
) -> None:
    connect(plane)
    plane.promote(
        {
            "max_delegation_depth": 2,
            "acknowledge": True,
        }
    )
    plane.rollback()

    entries = [
        entry
        for entry in plane.audit()
        if entry["action"] == "rollback"
    ]

    assert len(entries) == 1
    assert entries[0]["ok"] is True


def test_an_untrusting_promotion_needs_acknowledgement(
    plane: ControlPlane,
) -> None:
    """The revocation/issuer-untrust path on the control plane."""

    view = connect(plane)
    check(plane, view["fingerprint"])

    with pytest.raises(ControlError):
        plane.promote(
            {"trusted_issuers": []}
        )

    result = plane.promote(
        {
            "trusted_issuers": [],
            "acknowledge": True,
        }
    )

    assert result["rollout"]["stage"] == "enforce"
    assert not plane.sdk.is_issuer_trusted(
        "trusted-issuer"
    )

    plane.rollback()

    assert plane.sdk.is_issuer_trusted(
        "trusted-issuer"
    )


def test_simulation_projection_exposes_the_rollout(
    plane: ControlPlane,
) -> None:
    assert plane.simulation()["rollout"] is None

    connect(plane)
    plane.promote(
        {
            "max_delegation_depth": 2,
            "acknowledge": True,
        }
    )

    projection = plane.simulation()

    assert projection["recorded_cases"] >= 0
    assert projection["rollout"]["stage"] == (
        "enforce"
    )


def test_the_rollout_survives_across_endpoint_calls(
    plane: ControlPlane,
) -> None:
    connect(plane)
    plane.promote(
        {
            "max_delegation_depth": 2,
            "acknowledge": True,
        }
    )

    # A later unrelated call must not lose the restore point.
    plane.rules()

    result = plane.rollback()

    assert result["rollout"]["stage"] == "reverted"
