"""One definition of "narrower", enforced at the attenuation boundary.

``firewall/attenuation.py`` used to carry its own numeric rule -- ``child
<= parent``, applied to every number regardless of the key's suffix --
while ``delegate``, ``continuous_auth.predicates`` and the authorization
boundary itself used the suffix-aware predicate in
``firewall/delegation.py``. Two implementations of one security concept,
and they disagreed in three ways that a caller could reach through the
public SDK with no capability beyond the issuer key ``attenuate()``
already requires.

None of the three was a privilege escalation: ``_gate_delegation_
monotonicity`` uses the correct predicate, so every resulting child was
denied at the boundary. What they were is worse in a different way.
``can_attenuate()`` -- a public predicate -- returned ``True`` for a
widening; ``attenuate()`` minted capabilities that could never authorize
anything; and because ``attenuate()`` registers a lineage edge whenever
the child fingerprint differs from the parent's, one legitimate call
drove live state into a ``VIOLATED`` CAPABILITY_MONOTONICITY.

Each section below is one of the three, reproduced first at the
predicate and then end to end through ``FirewallSDK``. The invariant
assertion is deliberately "not VIOLATED" rather than "HOLDS": with the
widening refused there is no lineage edge left to examine, so the
honest reading of a single-attenuation estate is UNVERIFIABLE. A
legitimate narrowing, which does register an edge, is asserted HOLDS at
the end.
"""

from __future__ import annotations

import pytest

from firewall.attenuation import (
    _constraints_attenuated,
    can_attenuate,
)
from firewall.capability import (
    generate_capability_key_pair,
    sign_capability,
)
from firewall.delegation import _constraints_are_narrower
from firewall.invariants import InvariantStatus, invariant
from firewall.sdk import FirewallSDK

PROBE = {
    "allowed_actions": "payments.send",
    "amount": 50,
}


@pytest.fixture()
def sdk():
    instance = FirewallSDK()
    try:
        yield instance
    finally:
        instance.close()


def _signed_pair(parent_constraints, child_constraints):
    """A parent and a hand-signed child, bypassing ``attenuate``'s check.

    ``attenuate_capability`` refuses to return a child that fails
    ``can_attenuate``, so a test that wants to ask ``can_attenuate``
    about a widening has to sign the child itself. Everything else about
    the pair -- agent, issuer, key, capability, window -- is identical,
    so the constraints are the only thing under test.
    """

    private_key, _ = generate_capability_key_pair()

    shared = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "issuer": "trusted-issuer",
        "issued_at": 1000,
        "expires_at": 2000,
    }

    parent = sign_capability(
        private_key,
        constraints=parent_constraints,
        **shared,
    )

    child = sign_capability(
        private_key,
        constraints=child_constraints,
        **shared,
    )

    return parent, child


def _attenuation_is_refused(instance, parent_constraints, child_constraints):
    """Attempt the attenuation; return whether the SDK refused it."""

    private_key = instance.generate_key("regression-key").private_key

    parent = instance.issue(
        agent="finance-agent",
        capability="payments.send",
        constraints=parent_constraints,
    )

    with pytest.raises(ValueError):
        instance.attenuate(
            parent,
            private_key,
            constraints=child_constraints,
        )

    return parent


# ---------------------------------------------------------------------------
# Class 1: a lowered ``_min`` floor is a widening.
# ---------------------------------------------------------------------------


def test_lowered_min_floor_is_not_a_narrowing():
    parent = {"amount_min": 100}
    child = {"amount_min": 1}

    assert not _constraints_attenuated(parent, child)
    assert not _constraints_are_narrower(parent, child)


def test_lowered_min_floor_rejected_by_can_attenuate():
    parent, child = _signed_pair(
        {"amount_min": 100},
        {"amount_min": 1},
    )

    assert not can_attenuate(parent, child)


def test_lowered_min_floor_refused_by_sdk(sdk):
    _attenuation_is_refused(
        sdk,
        {"amount_min": 100, "allowed_actions": ["payments.send"]},
        {"amount_min": 1, "allowed_actions": ["payments.send"]},
    )

    result = invariant("CAPABILITY_MONOTONICITY").check(sdk)

    assert result.status is not InvariantStatus.VIOLATED


# ---------------------------------------------------------------------------
# Class 2: a bare numeric must be equal, because the boundary compares it
# for equality. ``amount: 100 -> 50`` is a different grant, not a
# narrower one -- it stops admitting what the parent admitted.
# ---------------------------------------------------------------------------


def test_lowered_bare_numeric_is_not_a_narrowing():
    parent = {"amount": 100}
    child = {"amount": 50}

    assert not _constraints_attenuated(parent, child)
    assert not _constraints_are_narrower(parent, child)


def test_lowered_bare_numeric_rejected_by_can_attenuate():
    parent, child = _signed_pair(
        {"amount": 100},
        {"amount": 50},
    )

    assert not can_attenuate(parent, child)


def test_lowered_bare_numeric_refused_by_sdk(sdk):
    _attenuation_is_refused(
        sdk,
        {"amount": 100, "allowed_actions": ["payments.send"]},
        {"amount": 50, "allowed_actions": ["payments.send"]},
    )

    result = invariant("CAPABILITY_MONOTONICITY").check(sdk)

    assert result.status is not InvariantStatus.VIOLATED


# ---------------------------------------------------------------------------
# Class 3: ``True -> False``. ``bool`` is a subclass of ``int``, so the
# old numeric branch fired first and ``False <= True`` held; the
# ``isinstance(parent, bool)`` branch underneath it was unreachable.
# ---------------------------------------------------------------------------


def test_flipped_bool_is_not_a_narrowing():
    parent = {"require_mfa": True}
    child = {"require_mfa": False}

    assert not _constraints_attenuated(parent, child)
    assert not _constraints_are_narrower(parent, child)


def test_flipped_bool_rejected_by_can_attenuate():
    parent, child = _signed_pair(
        {"require_mfa": True},
        {"require_mfa": False},
    )

    assert not can_attenuate(parent, child)


def test_flipped_bool_refused_by_sdk(sdk):
    _attenuation_is_refused(
        sdk,
        {"require_mfa": True, "allowed_actions": ["payments.send"]},
        {"require_mfa": False, "allowed_actions": ["payments.send"]},
    )

    result = invariant("CAPABILITY_MONOTONICITY").check(sdk)

    assert result.status is not InvariantStatus.VIOLATED


def test_bool_is_not_treated_as_a_number_in_either_direction():
    """``False -> True`` is a widening too, not just ``True -> False``.

    The old rule accepted ``True -> False`` and rejected ``False ->
    True``, which is the signature of an ordering comparison leaking
    into a value that has no ordering. Both directions are now refused.

    ``True -> 1`` is *accepted*, and that is correct rather than a
    residual leak: the boundary compares an unsuffixed scalar with
    ``!=``, and ``1 == True`` in Python, so the child admits exactly the
    requests the parent admitted. The predicate agrees with the boundary,
    which is the whole property under test -- it does not impose a
    stricter type discipline than the thing it has to model.
    """

    assert not _constraints_attenuated({"require_mfa": True}, {"require_mfa": False})
    assert not _constraints_attenuated({"require_mfa": False}, {"require_mfa": True})

    assert _constraints_attenuated({"require_mfa": True}, {"require_mfa": 1})
    assert _constraints_attenuated({"flag": 1}, {"flag": True})


# ---------------------------------------------------------------------------
# The predicate is now one predicate. If these drift apart again, the
# three classes above come back.
# ---------------------------------------------------------------------------


AGREEMENT_CASES = [
    ({"amount_max": 100}, {"amount_max": 50}),
    ({"amount_max": 100}, {"amount_max": 100}),
    ({"amount_max": 100}, {"amount_max": 200}),
    ({"amount_min": 100}, {"amount_min": 200}),
    ({"amount_min": 100}, {"amount_min": 100}),
    ({"amount_min": 100}, {"amount_min": 1}),
    ({"amount": 100}, {"amount": 100}),
    ({"amount": 100}, {"amount": 50}),
    ({"amount": 100}, {"amount": 200}),
    ({"require_mfa": True}, {"require_mfa": True}),
    ({"require_mfa": True}, {"require_mfa": False}),
    ({"require_mfa": False}, {"require_mfa": True}),
    ({"region": "eu"}, {"region": "eu"}),
    ({"region": "eu"}, {"region": "us"}),
    ({"actions": ["a", "b"]}, {"actions": ["a"]}),
    ({"actions": ["a"]}, {"actions": ["a", "b"]}),
    ({"amount_max": 100}, {}),
    ({}, {"amount_max": 100}),
    ({"lineage": {"amount_max": 10}}, {"lineage": {"amount_max": 5}}),
    ({"lineage": {"amount_max": 10}}, {"lineage": {"amount_max": 50}}),
    ({"lineage": {"amount_max": 10}}, {"lineage": 10}),
]


@pytest.mark.parametrize("parent,child", AGREEMENT_CASES)
def test_attenuation_and_delegation_agree(parent, child):
    assert _constraints_attenuated(parent, child) == _constraints_are_narrower(
        parent,
        child,
    )


def test_attenuation_predicate_is_the_delegation_predicate():
    """Not merely equal on a case list -- the same function object.

    A behavioural parametrization can only sample. This pins the
    structural fact that makes the sampling unnecessary: there is one
    implementation, and ``attenuation`` calls it.
    """

    import firewall.attenuation as attenuation

    assert attenuation._constraints_are_narrower is _constraints_are_narrower
    assert not hasattr(attenuation, "_constraint_is_narrower")


# ---------------------------------------------------------------------------
# The fix must not have closed the door on real attenuation.
# ---------------------------------------------------------------------------


def test_legitimate_attenuation_still_works_and_holds(sdk):
    private_key = sdk.generate_key("regression-key").private_key

    parent = sdk.issue(
        agent="finance-agent",
        capability="payments.send",
        constraints={
            "amount_max": 100,
            "amount_min": 5,
            "require_mfa": True,
            "allowed_actions": ["payments.send", "payments.refund"],
        },
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={
            "amount_max": 50,
            "amount_min": 10,
            "require_mfa": True,
            "allowed_actions": ["payments.send"],
        },
    )

    assert can_attenuate(parent, child)
    assert child.constraints["amount_max"] == 50

    result = invariant("CAPABILITY_MONOTONICITY").check(sdk)

    assert result.status is InvariantStatus.HOLDS


def test_attenuated_child_is_usable_at_the_boundary(sdk):
    """The point of the fix: a minted child can actually authorize.

    Every child the old predicate wrongly accepted was dead on arrival
    -- ``_gate_delegation_monotonicity`` denied it. A child the fixed
    predicate accepts is one the boundary also accepts.
    """

    private_key = sdk.generate_key("regression-key").private_key

    parent = sdk.issue(
        agent="finance-agent",
        capability="payments.send",
        constraints={
            "amount_max": 100,
            "allowed_actions": ["payments.send"],
        },
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={
            "amount_max": 50,
            "allowed_actions": ["payments.send"],
        },
    )

    assert sdk.authorize(child, "payments.send", dict(PROBE)).allowed

    over_ceiling = dict(PROBE)
    over_ceiling["amount"] = 75

    assert not sdk.authorize(child, "payments.send", over_ceiling).allowed
