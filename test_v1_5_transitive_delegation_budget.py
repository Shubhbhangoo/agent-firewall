from __future__ import annotations

import threading

from firewall.capability import capability_fingerprint
from firewall.sdk import FirewallSDK


def make_sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key("budget-key")
    return sdk


def make_root(sdk: FirewallSDK):
    return sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )


def configure_budget(
    sdk: FirewallSDK,
    root,
) -> None:
    sdk.configure_delegation_budget(
        root,
        max_total_amount=100,
    )


def test_root_budget_is_shared_with_child():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    first = sdk.authorize_with_delegation_budget(
        root,
        "payments.send",
        {"amount": 60},
    )

    second = sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 40},
    )

    assert first.allowed
    assert second.allowed
    assert sdk.delegation_budget_total(child) == 100


def test_child_cannot_spend_beyond_root_budget():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    first = sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 70},
    )

    assert first.allowed

    denied = sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 31},
    )

    assert not denied.allowed
    assert denied.reason == "delegation_budget_exceeded"
    assert sdk.delegation_budget_total(child) == 70


def test_grandchild_shares_root_budget():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    grandchild = sdk.delegate(
        child,
        sdk.active_key().private_key,
        delegatee="agent-c",
    ).child

    assert sdk.authorize_with_delegation_budget(
        root,
        "payments.send",
        {"amount": 30},
    ).allowed

    assert sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 30},
    ).allowed

    assert sdk.authorize_with_delegation_budget(
        grandchild,
        "payments.send",
        {"amount": 40},
    ).allowed

    denied = sdk.authorize_with_delegation_budget(
        grandchild,
        "payments.send",
        {"amount": 1},
    )

    assert not denied.allowed
    assert denied.reason == "delegation_budget_exceeded"
    assert sdk.delegation_budget_total(grandchild) == 100


def test_failed_child_attempt_does_not_consume_budget():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    assert sdk.authorize_with_delegation_budget(
        root,
        "payments.send",
        {"amount": 100},
    ).allowed

    denied = sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 1},
    )

    assert not denied.allowed
    assert denied.reason == "delegation_budget_exceeded"
    assert sdk.delegation_budget_total(child) == 100

    denied_again = sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 1},
    )

    assert not denied_again.allowed
    assert denied_again.reason == "delegation_budget_exceeded"
    assert sdk.delegation_budget_total(child) == 100


def test_concurrent_children_cannot_overspend_root_budget():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    children = []
    current = root

    for index in range(10):
        current = sdk.delegate(
            current,
            sdk.active_key().private_key,
            delegatee=f"agent-{index}",
        ).child
        children.append(current)

    results = []
    errors = []
    lock = threading.Lock()

    def worker(capability):
        try:
            result = sdk.authorize_with_delegation_budget(
                capability,
                "payments.send",
                {"amount": 20},
            )
        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(result)

    threads = [
        threading.Thread(
            target=worker,
            args=(child,),
        )
        for child in children
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert len(results) == 10

    allowed = [
        result
        for result in results
        if result.allowed
    ]

    denied = [
        result
        for result in results
        if not result.allowed
    ]

    assert len(allowed) == 5
    assert len(denied) == 5

    assert all(
        result.reason == "delegation_budget_exceeded"
        for result in denied
    )

    assert sdk.delegation_budget_total(root) == 100


def test_unrelated_root_capabilities_have_independent_budgets():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    root_b = sdk.issue(
        agent="agent-b",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    sdk.configure_delegation_budget(
        root_a,
        max_total_amount=100,
    )

    sdk.configure_delegation_budget(
        root_b,
        max_total_amount=100,
    )

    assert sdk.authorize_with_delegation_budget(
        root_a,
        "payments.send",
        {"amount": 100},
    ).allowed

    assert sdk.authorize_with_delegation_budget(
        root_b,
        "payments.send",
        {"amount": 100},
    ).allowed

    assert sdk.delegation_budget_total(root_a) == 100
    assert sdk.delegation_budget_total(root_b) == 100


def test_budget_tracks_root_lineage_not_child_fingerprints():
    sdk = make_sdk()

    root = make_root(sdk)
    configure_budget(sdk, root)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    root_fp = capability_fingerprint(
        root
    )

    child_fp = capability_fingerprint(
        child
    )

    assert root_fp != child_fp

    assert sdk.authorize_with_delegation_budget(
        root,
        "payments.send",
        {"amount": 30},
    ).allowed

    assert sdk.authorize_with_delegation_budget(
        child,
        "payments.send",
        {"amount": 70},
    ).allowed

    assert sdk.delegation_budget_total(root) == 100
    assert sdk.delegation_budget_total(child) == 100


def test_unconfigured_lineage_is_denied():
    sdk = make_sdk()
    root = make_root(sdk)

    result = sdk.authorize_with_delegation_budget(
        root,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == (
        "delegation_budget_not_configured"
    )


def test_negative_budget_amount_is_denied():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    result = sdk.authorize_with_delegation_budget(
        root,
        "payments.send",
        {"amount": -1},
    )

    assert not result.allowed
    assert result.reason == (
        "invalid_budget_amount"
    )


def test_unauthorized_action_does_not_consume_budget():
    sdk = make_sdk()
    root = make_root(sdk)
    configure_budget(sdk, root)

    result = sdk.authorize_with_delegation_budget(
        root,
        "payments.write",
        {"amount": 50},
    )

    assert not result.allowed
    assert result.reason == "namespace_denied"
    assert sdk.delegation_budget_total(root) == 0
