from __future__ import annotations

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.delegation import (
    Delegation,
)

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.sdk import FirewallSDK


def make_key():
    private_key, _ = (
        generate_capability_key_pair()
    )

    return private_key


def make_capability(
    sdk,
):
    private_key = make_key()

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.*",
    )

    return capability, private_key


# ============================================================
# Successful delegation
# ============================================================


def test_delegate_creates_delegated_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    delegation = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    assert isinstance(
        delegation,
        Delegation,
    )

    delegated = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )

    assert len(delegated) == 1

    event = delegated[0]

    assert (
        event.fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    assert event.agent_id == (
        capability.agent_id
    )

    assert event.capability == (
        capability.capability
    )

    assert event.issuer == (
        capability.issuer
    )

    assert event.details[
        "delegatee"
    ] == "agent-b"

    assert event.details[
        "delegation"
    ] is True

    assert event.details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        delegation.child
    )

    sdk.close()


def test_delegate_emits_exactly_one_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    before = lifecycle.size()

    delegation = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    assert (
        lifecycle.size()
        == before + 1
    )

    delegated = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )

    assert len(delegated) == 1

    assert delegated[0].details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        delegation.child
    )

    sdk.close()


def test_multiple_delegations_emit_multiple_events():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    first = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    second = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-c",
    )

    delegated = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )

    assert len(delegated) == 2

    assert delegated[0].details[
        "delegatee"
    ] == "agent-b"

    assert delegated[0].details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        first.child
    )

    assert delegated[1].details[
        "delegatee"
    ] == "agent-c"

    assert delegated[1].details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        second.child
    )

    sdk.close()


# ============================================================
# Failed delegation
# ============================================================


def test_failed_delegation_creates_no_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, _ = (
        make_capability(sdk)
    )

    before = lifecycle.size()

    with pytest.raises(Exception):
        sdk.delegate(
            capability,
            "not-a-private-key",
            delegatee="agent-b",
        )

    assert (
        lifecycle.size()
        == before
    )

    assert (
        lifecycle.of_type(
            LifecycleEventType.DELEGATED
        )
        == ()
    )

    sdk.close()


def test_same_agent_delegation_creates_no_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    before = lifecycle.size()

    with pytest.raises(
        ValueError
    ):
        sdk.delegate(
            capability,
            private_key,
            delegatee="agent-a",
        )

    assert (
        lifecycle.size()
        == before
    )

    assert (
        lifecycle.of_type(
            LifecycleEventType.DELEGATED
        )
        == ()
    )

    sdk.close()


# ============================================================
# Event identity
# ============================================================


def test_delegate_event_uses_parent_fingerprint():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    delegation = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    event = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )[0]

    assert (
        event.fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    assert (
        event.details[
            "child_fingerprint"
        ]
        == sdk.fingerprint(
            delegation.child
        )
    )

    sdk.close()


def test_delegate_preserves_parent_scope_in_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    delegation = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    event = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )[0]

    assert event.capability == (
        capability.capability
    )

    assert event.capability == (
        "payments.*"
    )

    assert (
        event.details[
            "child_fingerprint"
        ]
        == sdk.fingerprint(
            delegation.child
        )
    )

    sdk.close()


def test_delegate_preserves_parent_agent_identity():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    event = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )[0]

    assert event.agent_id == (
        "agent-a"
    )

    assert event.details[
        "delegatee"
    ] == "agent-b"

    sdk.close()


def test_delegate_preserves_parent_issuer():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    event = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )[0]

    assert event.issuer == (
        capability.issuer
    )

    sdk.close()


# ============================================================
# Default recorder
# ============================================================


def test_default_sdk_records_delegation_event():
    sdk = FirewallSDK()

    capability, private_key = (
        make_capability(sdk)
    )

    delegation = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    delegated = sdk.lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )

    assert len(delegated) == 1

    assert delegated[0].details[
        "delegatee"
    ] == "agent-b"

    assert delegated[0].details[
        "delegation"
    ] is True

    assert delegated[0].details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        delegation.child
    )

    sdk.close()


# ============================================================
# Lifecycle ordering
# ============================================================


def test_issue_then_delegate_order():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    delegation = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    events = lifecycle.events()

    assert len(events) == 2

    assert (
        events[0].event_type
        == LifecycleEventType.ISSUED
    )

    assert (
        events[1].event_type
        == LifecycleEventType.DELEGATED
    )

    assert (
        events[0].fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    assert (
        events[1].fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    assert (
        events[1].details[
            "child_fingerprint"
        ]
        == sdk.fingerprint(
            delegation.child
        )
    )

    sdk.close()


def test_two_delegations_preserve_order():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability, private_key = (
        make_capability(sdk)
    )

    first = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-b",
    )

    second = sdk.delegate(
        capability,
        private_key,
        delegatee="agent-c",
    )

    delegated = lifecycle.of_type(
        LifecycleEventType.DELEGATED
    )

    assert [
        event.details["delegatee"]
        for event in delegated
    ] == [
        "agent-b",
        "agent-c",
    ]

    assert delegated[0].details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        first.child
    )

    assert delegated[1].details[
        "child_fingerprint"
    ] == sdk.fingerprint(
        second.child
    )

    sdk.close()