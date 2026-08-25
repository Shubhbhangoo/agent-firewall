from __future__ import annotations

import time

import pytest

from firewall.capability import capability_fingerprint
from firewall.delegation_lineage import DelegationLineage
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK(
        delegation_lineage=DelegationLineage(),
    )
    sdk.generate_key("test-key")
    return sdk


def make_root(sdk, constraints):
    now = time.time()

    return sdk.issue(
        agent="agent-root",
        capability="payments.send",
        constraints=constraints,
        issued_at=now,
        expires_at=now + 3600,
    )


def delegate(sdk, parent, agent, constraints=None):
    return sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee=agent,
        constraints=constraints,
    ).child


def test_nested_delegation_cannot_restore_authority():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    with pytest.raises(ValueError):
        delegate(
            sdk,
            child,
            "agent-c",
            {"amount_max": 1000},
        )


def test_child_cannot_launder_root_authority():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 100},
    )

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 101},
    )

    assert not result.allowed


def test_grandchild_cannot_launder_parent_authority():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 100},
    )

    result = sdk.authorize(
        grandchild,
        "payments.send",
        {"amount": 101},
    )

    assert not result.allowed


def test_namespace_cannot_be_escalated():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
    )

    assert not sdk.authorize(
        child,
        "payments.delete",
        {},
    ).allowed


def test_delegation_cannot_change_capability_namespace():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
    )

    assert child.capability == root.capability


def test_deep_chain_cannot_escape_root():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 250},
    )

    great_grandchild = delegate(
        sdk,
        grandchild,
        "agent-d",
        {"amount_max": 100},
    )

    result = sdk.authorize(
        great_grandchild,
        "payments.send",
        {"amount": 101},
    )

    assert not result.allowed


def test_parent_revocation_cannot_be_bypassed_by_new_delegation():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    sdk.revoke(root)

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_revoked_intermediate_cannot_be_bypassed():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    sdk.revoke(child)

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 250},
    )

    result = sdk.authorize(
        grandchild,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_sibling_cannot_inherit_revoked_sibling_authority():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child_a = delegate(
        sdk,
        root,
        "agent-a",
        {"amount_max": 100},
    )

    child_b = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    sdk.revoke(child_a)

    assert not sdk.authorize(
        child_a,
        "payments.send",
        {"amount": 1},
    ).allowed

    assert sdk.authorize(
        child_b,
        "payments.send",
        {"amount": 400},
    ).allowed


def test_root_constraint_remains_effective_through_many_delegations():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 50},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 40},
    )

    grandchild = delegate(
        sdk,
        child,
        "agent-c",
        {"amount_max": 30},
    )

    result = sdk.authorize(
        grandchild,
        "payments.send",
        {"amount": 31},
    )

    assert not result.allowed


def test_effective_authority_fails_closed_for_missing_ancestor():
    sdk = make_sdk()

    root = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root,
        "agent-b",
        {"amount_max": 500},
    )

    child_fp = capability_fingerprint(child)

    sdk._capability_registry.pop(
        capability_fingerprint(root),
        None,
    )

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert "delegation" in result.reason


def test_unrelated_tree_cannot_authorize_as_ancestor():
    sdk = make_sdk()

    root_a = make_root(
        sdk,
        {"amount_max": 100},
    )

    root_b = make_root(
        sdk,
        {"amount_max": 1000},
    )

    child = delegate(
        sdk,
        root_a,
        "agent-b",
        {"amount_max": 50},
    )

    assert sdk.authorize(
        root_b,
        "payments.send",
        {"amount": 900},
    ).allowed

    assert not sdk.authorize(
        child,
        "payments.send",
        {"amount": 51},
    ).allowed