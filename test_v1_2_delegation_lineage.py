from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from firewall.delegation_lineage import (
    DelegationLineage,
    DelegationLineageError,
    LineageCycleError,
)
from firewall.sdk import FirewallSDK


def make_sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key(
        "lineage-key"
    )
    return sdk


# ============================================================
# LINEAGE UNIT TESTS
# ============================================================


def test_register_parent():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    assert (
        lineage.parent_of("child")
        == "parent"
    )


def test_chain_returns_all_ancestors():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="root",
    )

    lineage.register(
        child_fingerprint="grandchild",
        parent_fingerprint="child",
    )

    assert lineage.chain(
        "grandchild"
    ) == (
        "child",
        "root",
    )


def test_descendant_detection():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="root",
    )

    lineage.register(
        child_fingerprint="grandchild",
        parent_fingerprint="child",
    )

    assert lineage.is_descendant_of(
        child_fingerprint="child",
        ancestor_fingerprint="root",
    )

    assert lineage.is_descendant_of(
        child_fingerprint="grandchild",
        ancestor_fingerprint="root",
    )

    assert lineage.is_descendant_of(
        child_fingerprint="grandchild",
        ancestor_fingerprint="child",
    )


def test_unrelated_capabilities_are_not_descendants():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="root",
    )

    assert not lineage.is_descendant_of(
        child_fingerprint="child",
        ancestor_fingerprint="other",
    )


def test_self_parent_rejected():
    lineage = DelegationLineage()

    with pytest.raises(
        LineageCycleError
    ):
        lineage.register(
            child_fingerprint="same",
            parent_fingerprint="same",
        )


def test_conflicting_parent_rejected():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="root",
    )

    with pytest.raises(
        DelegationLineageError
    ):
        lineage.register(
            child_fingerprint="child",
            parent_fingerprint="other",
        )


def test_snapshot():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    snapshot = lineage.snapshot()

    assert snapshot == (
        snapshot[0],
        snapshot[1],
    )

    assert {
        (
            item.child_fingerprint,
            item.parent_fingerprint,
        )
        for item in snapshot
    } == {
        ("b", "a"),
        ("c", "b"),
    }


def test_clear():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="root",
    )

    lineage.clear()

    assert lineage.chain(
        "child"
    ) == ()


def test_concurrent_registration_is_safe():
    lineage = DelegationLineage()

    def register(index: int):
        lineage.register(
            child_fingerprint=f"child-{index}",
            parent_fingerprint="root",
        )

    with ThreadPoolExecutor(
        max_workers=16
    ) as executor:
        list(
            executor.map(
                register,
                range(100),
            )
        )

    assert len(
        lineage.snapshot()
    ) == 100


# ============================================================
# SDK REVOCATION LINEAGE TESTS
# ============================================================


def test_parent_revocation_invalidates_child():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    assert sdk.verify(
        parent
    ) is True

    assert sdk.verify(
        child
    ) is True

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    assert sdk.is_revoked(
        parent
    ) is True

    assert sdk.verify(
        child
    ) is False


def test_authorization_of_child_fails_after_parent_revocation():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    before = sdk.authorize(
        child,
        "payments.send",
        {},
    )

    assert before.allowed is True

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    after = sdk.authorize(
        child,
        "payments.send",
        {},
    )

    assert after.allowed is False

    assert (
        after.reason
        == "capability_revoked"
    )


def test_intermediate_revocation_invalidates_descendant():
    sdk = make_sdk()

    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    first = sdk.delegate(
        root,
        key.private_key,
        delegatee="agent-b",
    )

    second = sdk.delegate(
        first.child,
        key.private_key,
        delegatee="agent-c",
    )

    assert sdk.verify(
        second.child
    ) is True

    sdk.revoke(
        first.child,
        reason="intermediate compromised",
    )

    assert sdk.verify(
        second.child
    ) is False


def test_root_revocation_invalidates_grandchild():
    sdk = make_sdk()

    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    first = sdk.delegate(
        root,
        key.private_key,
        delegatee="agent-b",
    )

    second = sdk.delegate(
        first.child,
        key.private_key,
        delegatee="agent-c",
    )

    third = sdk.delegate(
        second.child,
        key.private_key,
        delegatee="agent-d",
    )

    sdk.revoke(
        root,
        reason="root compromised",
    )

    assert sdk.verify(
        third.child
    ) is False


def test_unrelated_capability_survives_parent_revocation():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    unrelated = sdk.issue(
        agent="agent-a",
        capability="payments.lookup",
    )

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    assert sdk.verify(
        parent
    ) is False

    assert sdk.verify(
        unrelated
    ) is True


def test_child_cannot_be_resurrected():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    for _ in range(10):
        result = sdk.authorize(
            child,
            "payments.send",
            {},
        )

        assert result.allowed is False


def test_replaying_child_does_not_bypass_lineage_revocation():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    assert sdk.consume_nonce(
        "agent-b",
        child,
        "fresh-child-nonce",
    ) is False


def test_lineage_is_registered_for_delegation():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    parent_fp = sdk.fingerprint(
        parent
    )

    child_fp = sdk.fingerprint(
        delegation.child
    )

    assert (
        sdk.delegation_lineage.parent_of(
            child_fp
        )
        == parent_fp
    )


def test_parent_revocation_works_after_multiple_delegations():
    sdk = make_sdk()

    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    current = root

    for agent in (
        "agent-b",
        "agent-c",
        "agent-d",
        "agent-e",
    ):
        delegation = sdk.delegate(
            current,
            key.private_key,
            delegatee=agent,
        )

        current = delegation.child

    sdk.revoke(
        root,
        reason="root compromised",
    )

    assert sdk.verify(
        current
    ) is False