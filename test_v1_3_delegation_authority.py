from __future__ import annotations

import time

import pytest

from firewall.capability import capability_fingerprint
from firewall.delegation_lineage import DelegationLineage
from firewall.revocation import AlreadyRevokedError
from firewall.sdk import FirewallSDK


def make_sdk(*, max_depth: int = 64):
    sdk = FirewallSDK(
        delegation_lineage=DelegationLineage(
            max_depth=max_depth,
        )
    )
    sdk.generate_key("test-key")
    return sdk


def make_parent(
    sdk,
    *,
    agent="agent-a",
    capability="payments.send",
    constraints=None,
    issued_at=None,
    expires_at=None,
):
    now = time.time()

    if issued_at is None:
        issued_at = now

    if expires_at is None:
        expires_at = now + 3600

    return sdk.issue(
        agent=agent,
        capability=capability,
        constraints=constraints or {},
        issued_at=issued_at,
        expires_at=expires_at,
    )


def delegate(
    sdk,
    parent,
    delegatee,
    constraints=None,
):
    return sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee=delegatee,
        constraints=constraints,
    )


def test_sdk_delegate_registers_lineage():
    sdk = make_sdk()

    parent = make_parent(sdk)
    delegation = delegate(sdk, parent, "agent-b")

    parent_fp = capability_fingerprint(parent)
    child_fp = capability_fingerprint(delegation.child)

    assert sdk.delegation_lineage.parent_of(child_fp) == parent_fp
    assert sdk.delegation_lineage.chain(child_fp) == (
        parent_fp,
    )


def test_parent_revocation_denies_direct_child():
    sdk = make_sdk()

    parent = make_parent(
        sdk,
        constraints={"amount_max": 1000},
    )

    child = delegate(
        sdk,
        parent,
        "agent-b",
    ).child

    assert sdk.authorize(
        child,
        "payments.send",
        {"amount": 100},
    ).allowed

    sdk.revoke(parent, reason="parent revoked")

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 100},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_parent_revocation_denies_grandchild():
    sdk = make_sdk()

    parent = make_parent(
        sdk,
        constraints={"amount_max": 1000},
    )

    child = delegate(
        sdk,
        parent,
        "agent-b",
        {"amount_max": 500},
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 250},
    ).child

    assert sdk.authorize(
        grandchild,
        "payments.send",
        {"amount": 100},
    ).allowed

    sdk.revoke(parent, reason="root revoked")

    result = sdk.authorize(
        grandchild,
        "payments.send",
        {"amount": 100},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_child_revocation_does_not_revoke_parent():
    sdk = make_sdk()

    parent = make_parent(sdk)
    child = delegate(
        sdk,
        parent,
        "agent-b",
    ).child

    sdk.revoke(child, reason="child revoked")

    parent_result = sdk.authorize(
        parent,
        "payments.send",
        {},
    )

    child_result = sdk.authorize(
        child,
        "payments.send",
        {},
    )

    assert parent_result.allowed
    assert not child_result.allowed
    assert child_result.reason == "capability_revoked"


def test_child_revocation_denies_grandchild():
    sdk = make_sdk()

    parent = make_parent(sdk)

    child = delegate(
        sdk,
        parent,
        "agent-b",
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
    ).child

    sdk.revoke(
        child,
        reason="intermediate revoked",
    )

    result = sdk.authorize(
        grandchild,
        "payments.send",
        {},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_sibling_delegation_is_isolated():
    sdk = make_sdk()

    parent = make_parent(sdk)

    child_a = delegate(
        sdk,
        parent,
        "agent-b",
    ).child

    child_b = delegate(
        sdk,
        parent,
        "agent-c",
    ).child

    sdk.revoke(child_a)

    result_a = sdk.authorize(
        child_a,
        "payments.send",
        {},
    )

    result_b = sdk.authorize(
        child_b,
        "payments.send",
        {},
    )

    assert not result_a.allowed
    assert result_a.reason == "capability_revoked"
    assert result_b.allowed


def test_is_effectively_revoked_detects_parent():
    sdk = make_sdk()

    parent = make_parent(sdk)
    child = delegate(
        sdk,
        parent,
        "agent-b",
    ).child

    assert not sdk.is_effectively_revoked(child)

    sdk.revoke(parent)

    assert sdk.is_effectively_revoked(parent)
    assert sdk.is_effectively_revoked(child)


def test_is_effectively_revoked_detects_deep_ancestor():
    sdk = make_sdk()

    parent = make_parent(sdk)

    child = delegate(
        sdk,
        parent,
        "agent-b",
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
    ).child

    sdk.revoke(parent)

    assert sdk.is_effectively_revoked(grandchild)


def test_unrelated_delegation_tree_is_not_affected():
    sdk = make_sdk()

    root_a = make_parent(
        sdk,
        agent="agent-a",
    )

    root_b = make_parent(
        sdk,
        agent="agent-x",
    )

    child_a = delegate(
        sdk,
        root_a,
        "agent-b",
    ).child

    child_b = delegate(
        sdk,
        root_b,
        "agent-y",
    ).child

    sdk.revoke(root_a)

    assert not sdk.authorize(
        child_a,
        "payments.send",
        {},
    ).allowed

    assert sdk.authorize(
        child_b,
        "payments.send",
        {},
    ).allowed


def test_nested_delegation_preserves_lineage_order():
    sdk = make_sdk()

    root = make_parent(sdk)

    child = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
    ).child

    root_fp = capability_fingerprint(root)
    child_fp = capability_fingerprint(child)
    grandchild_fp = capability_fingerprint(grandchild)

    assert sdk.delegation_lineage.chain(
        grandchild_fp
    ) == (
        child_fp,
        root_fp,
    )


def test_nested_delegation_cannot_broaden_constraints():
    sdk = make_sdk()

    root = make_parent(
        sdk,
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    ).child

    with pytest.raises(ValueError):
        delegate(
            sdk,
            child,
            "agent-c",
            {"amount_max": 1000},
        )


def test_nested_delegation_can_further_attenuate():
    sdk = make_sdk()

    root = make_parent(
        sdk,
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 250},
    ).child

    assert grandchild.constraints["amount_max"] == 250


def test_verify_delegation_works():
    sdk = make_sdk()

    parent = make_parent(sdk)
    delegation = delegate(
        sdk,
        parent,
        "agent-b",
    )

    assert sdk.verify_delegation(delegation)


def test_active_child_can_authorize():
    sdk = make_sdk()

    parent = make_parent(
        sdk,
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate(
        sdk,
        parent,
        "agent-b",
        {"amount_max": 500},
    ).child

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 400},
    )

    assert result.allowed


def test_child_constraint_is_enforced():
    sdk = make_sdk()

    parent = make_parent(
        sdk,
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate(
        sdk,
        parent,
        "agent-b",
        {"amount_max": 500},
    ).child

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 600},
    )

    assert not result.allowed


def test_revoked_ancestor_blocks_valid_child_request():
    sdk = make_sdk()

    parent = make_parent(
        sdk,
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate(
        sdk,
        parent,
        "agent-b",
        {"amount_max": 500},
    ).child

    sdk.revoke(parent)

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_multiple_levels_point_to_correct_parent():
    sdk = make_sdk()

    root = make_parent(sdk)

    level_1 = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    level_2 = delegate(
        sdk,
        level_1,
        "agent-c",
    ).child

    level_3 = delegate(
        sdk,
        level_2,
        "agent-d",
    ).child

    assert sdk.delegation_lineage.parent_of(
        capability_fingerprint(level_1)
    ) == capability_fingerprint(root)

    assert sdk.delegation_lineage.parent_of(
        capability_fingerprint(level_2)
    ) == capability_fingerprint(level_1)

    assert sdk.delegation_lineage.parent_of(
        capability_fingerprint(level_3)
    ) == capability_fingerprint(level_2)


def test_revoking_root_blocks_entire_tree():
    sdk = make_sdk()

    root = make_parent(sdk)

    child_a = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    child_b = delegate(
        sdk,
        root,
        "agent-c",
    ).child

    grandchild = delegate(
        sdk,
        child_a,
        "agent-d",
    ).child

    sdk.revoke(root)

    for capability in (
        child_a,
        child_b,
        grandchild,
    ):
        result = sdk.authorize(
            capability,
            "payments.send",
            {},
        )

        assert not result.allowed
        assert result.reason == "capability_revoked"


def test_repeated_revocation_raises_already_revoked():
    sdk = make_sdk()

    root = make_parent(sdk)

    sdk.revoke(root)

    with pytest.raises(AlreadyRevokedError):
        sdk.revoke(root)

    assert sdk.is_effectively_revoked(root)


def test_revoked_child_does_not_revoke_sibling():
    sdk = make_sdk()

    root = make_parent(sdk)

    child_a = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    child_b = delegate(
        sdk,
        root,
        "agent-c",
    ).child

    sdk.revoke(child_a)

    assert sdk.is_effectively_revoked(child_a)
    assert not sdk.is_effectively_revoked(child_b)


def test_lineage_snapshot_contains_registered_edges():
    sdk = make_sdk()

    root = make_parent(sdk)

    child = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    snapshot = sdk.delegation_lineage.snapshot()

    assert len(snapshot) == 1

    assert snapshot[0].child_fingerprint == (
        capability_fingerprint(child)
    )

    assert snapshot[0].parent_fingerprint == (
        capability_fingerprint(root)
    )


def test_lineage_chain_is_empty_for_root():
    sdk = make_sdk()

    root = make_parent(sdk)

    assert sdk.delegation_lineage.chain(
        capability_fingerprint(root)
    ) == ()


def test_root_is_not_descendant_of_itself():
    sdk = make_sdk()

    root = make_parent(sdk)
    root_fp = capability_fingerprint(root)

    assert not sdk.delegation_lineage.is_descendant_of(
        child_fingerprint=root_fp,
        ancestor_fingerprint=root_fp,
    )


def test_child_is_descendant_of_root():
    sdk = make_sdk()

    root = make_parent(sdk)

    child = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    assert sdk.delegation_lineage.is_descendant_of(
        child_fingerprint=capability_fingerprint(child),
        ancestor_fingerprint=capability_fingerprint(root),
    )


def test_deep_child_is_descendant_of_all_ancestors():
    sdk = make_sdk()

    root = make_parent(sdk)

    child = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
    ).child

    grandchild_fp = capability_fingerprint(grandchild)

    assert sdk.delegation_lineage.is_descendant_of(
        child_fingerprint=grandchild_fp,
        ancestor_fingerprint=capability_fingerprint(child),
    )

    assert sdk.delegation_lineage.is_descendant_of(
        child_fingerprint=grandchild_fp,
        ancestor_fingerprint=capability_fingerprint(root),
    )


def test_delegation_tree_cannot_escape_root_constraints():
    sdk = make_sdk()

    root = make_parent(
        sdk,
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 250},
    ).child

    assert grandchild.constraints["amount_max"] == 250

    with pytest.raises(ValueError):
        delegate(
            sdk,
            grandchild,
            "agent-d",
            {"amount_max": 1001},
        )


def test_maximum_lineage_depth_boundary():
    sdk = make_sdk(max_depth=2)

    root = make_parent(sdk)

    child = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
    ).child

    assert sdk.delegation_lineage.chain(
        capability_fingerprint(grandchild)
    ) == (
        capability_fingerprint(child),
        capability_fingerprint(root),
    )


def test_revoked_parent_blocks_new_child_authorization():
    sdk = make_sdk()

    root = make_parent(sdk)

    sdk.revoke(root)

    child = delegate(
        sdk,
        root,
        "agent-b",
    ).child

    result = sdk.authorize(
        child,
        "payments.send",
        {},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"