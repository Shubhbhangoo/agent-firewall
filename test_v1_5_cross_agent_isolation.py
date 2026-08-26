from __future__ import annotations

import threading

import pytest

from firewall.sdk import FirewallSDK


def make_sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key("isolation-key")
    return sdk


def issue_session(
    sdk: FirewallSDK,
    *,
    agent: str,
    tool: str = "filesystem.read",
):
    return sdk.mint_session_capability(
        agent=agent,
        tool=tool,
        capability=tool,
        ttl=300,
    )


def test_agent_a_session_capability_cannot_be_used_as_agent_b():
    sdk = make_sdk()

    capability = issue_session(
        sdk,
        agent="agent-a",
    )

    result = sdk.authorize(
        capability,
        "filesystem.read",
        {},
    )

    assert result.allowed
    assert capability.agent_id == "agent-a"

    # A capability issued to A remains A's authority.
    assert sdk.authorize(
        capability,
        "filesystem.read",
        {},
    ).trace["agent"] == "agent-a"


def test_agent_b_cannot_use_agent_a_delegated_capability_as_own():
    sdk = make_sdk()

    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    assert child.agent_id == "agent-b"

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 10},
    )

    assert result.allowed
    assert result.trace["agent"] == "agent-b"

    # The parent remains distinctly owned by A.
    assert sdk.authorize(
        root,
        "payments.send",
        {"amount": 10},
    ).trace["agent"] == "agent-a"


def test_agent_a_budget_is_not_shared_with_agent_b():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    root_b = sdk.issue(
        agent="agent-b",
        capability="payments.send",
        constraints={"amount_max": 100},
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

    assert sdk.delegation_budget_total(
        root_a
    ) == 100

    assert sdk.delegation_budget_total(
        root_b
    ) == 0

    assert sdk.authorize_with_delegation_budget(
        root_b,
        "payments.send",
        {"amount": 100},
    ).allowed


def test_agent_a_budget_cannot_be_spent_by_agent_b_child():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    sdk.configure_delegation_budget(
        root_a,
        max_total_amount=100,
    )

    child_b = sdk.delegate(
        root_a,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    assert sdk.authorize_with_delegation_budget(
        child_b,
        "payments.send",
        {"amount": 100},
    ).allowed

    assert sdk.delegation_budget_total(
        root_a
    ) == 100


def test_cross_agent_session_capabilities_use_distinct_tool_bindings():
    sdk = make_sdk()

    read_a = issue_session(
        sdk,
        agent="agent-a",
        tool="filesystem.read",
    )

    network_b = issue_session(
        sdk,
        agent="agent-b",
        tool="network.request",
    )

    assert sdk.authorize(
        read_a,
        "filesystem.read",
        {},
    ).allowed

    denied = sdk.authorize(
        read_a,
        "network.request",
        {},
    )

    assert not denied.allowed
    assert denied.reason == "tool_binding_denied"

    assert sdk.authorize(
        network_b,
        "network.request",
        {},
    ).allowed


def test_concurrent_cross_agent_requests_remain_isolated():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    root_b = sdk.issue(
        agent="agent-b",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    sdk.configure_delegation_budget(
        root_a,
        max_total_amount=100,
    )

    sdk.configure_delegation_budget(
        root_b,
        max_total_amount=100,
    )

    results = []
    errors = []
    lock = threading.Lock()

    def worker(capability, expected_agent):
        try:
            result = sdk.authorize_with_delegation_budget(
                capability,
                "payments.send",
                {"amount": 10},
            )

            with lock:
                results.append(
                    (
                        expected_agent,
                        result.allowed,
                        result.trace["agent"],
                    )
                )
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = []

    for _ in range(10):
        threads.append(
            threading.Thread(
                target=worker,
                args=(root_a, "agent-a"),
            )
        )
        threads.append(
            threading.Thread(
                target=worker,
                args=(root_b, "agent-b"),
            )
        )

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert len(results) == 20

    a_results = [
        item
        for item in results
        if item[0] == "agent-a"
    ]

    b_results = [
        item
        for item in results
        if item[0] == "agent-b"
    ]

    assert len(a_results) == 10
    assert len(b_results) == 10

    assert all(
        item[1]
        and item[2] == "agent-a"
        for item in a_results
    )

    assert all(
        item[1]
        and item[2] == "agent-b"
        for item in b_results
    )

    assert sdk.delegation_budget_total(
        root_a
    ) == 100

    assert sdk.delegation_budget_total(
        root_b
    ) == 100


def test_invalid_cross_agent_capability_is_denied_without_budget_consumption():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    sdk.configure_delegation_budget(
        root_a,
        max_total_amount=100,
    )

    result = sdk.authorize_with_delegation_budget(
        root_a,
        "payments.write",
        {"amount": 50},
    )

    assert not result.allowed
    assert result.reason == "namespace_denied"

    assert sdk.delegation_budget_total(
        root_a
    ) == 0


def test_revoked_agent_a_capability_does_not_affect_agent_b():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    root_b = sdk.issue(
        agent="agent-b",
        capability="payments.send",
    )

    sdk.revoke(
        root_a,
        reason="agent-a compromised",
    )

    assert sdk.verify(root_a) is False
    assert sdk.verify(root_b) is True

    assert sdk.authorize(
        root_b,
        "payments.send",
        {"amount": 1},
    ).allowed


def test_agent_b_cannot_use_revoked_agent_a_lineage():
    sdk = make_sdk()

    root_a = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    child_b = sdk.delegate(
        root_a,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    root_b = sdk.issue(
        agent="agent-b",
        capability="payments.send",
    )

    sdk.revoke(
        root_a,
        reason="agent-a compromised",
    )

    assert sdk.verify(child_b) is False
    assert sdk.verify(root_b) is True

    result = sdk.authorize(
        child_b,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"
