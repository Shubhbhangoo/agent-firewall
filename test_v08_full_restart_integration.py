from __future__ import annotations

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.sdk import FirewallSDK


def make_key():
    private_key, _ = (
        generate_capability_key_pair()
    )
    return private_key


def test_full_sdk_restart_preserves_revocation_and_lifecycle(
    tmp_path,
):
    revocation_path = (
        tmp_path / "revocations.db"
    )

    lifecycle_path = (
        tmp_path / "lifecycle.db"
    )

    first = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    capability = first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    first.authorize(
        capability,
        "payments.send",
        {
            "amount": 10,
        },
    )

    first.revoke(
        capability,
        reason="compromised",
    )

    denied = first.authorize(
        capability,
        "payments.send",
        {
            "amount": 10,
        },
    )

    assert denied.allowed is False

    first_events = (
        first.lifecycle_events()
    )

    assert [
        event.event_type
        for event in first_events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    ]

    assert first.is_revoked(
        capability
    ) is True

    first.close()

    second = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    assert second.is_revoked(
        capability
    ) is True

    restored_events = (
        second.lifecycle_events()
    )

    assert restored_events == (
        first_events
    )

    result = second.authorize(
        capability,
        "payments.send",
        {
            "amount": 10,
        },
    )

    assert result.allowed is False

    assert result.reason == (
        "capability_revoked"
    )

    events_after_restart = (
        second.lifecycle_events()
    )

    assert [
        event.event_type
        for event in events_after_restart
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
        LifecycleEventType.DENIED,
    ]

    second.close()


def test_new_sdk_event_appends_to_restored_history(
    tmp_path,
):
    revocation_path = (
        tmp_path / "revocations.db"
    )

    lifecycle_path = (
        tmp_path / "lifecycle.db"
    )

    first = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    first.close()

    second = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    capability = second.issue(
        private_key=make_key(),
        agent="agent-b",
        capability="payments.refund",
    )

    events = second.lifecycle_events()

    assert len(events) == 2

    assert events[0].event_type == (
        LifecycleEventType.ISSUED
    )

    assert events[1].event_type == (
        LifecycleEventType.ISSUED
    )

    assert events[1].agent_id == (
        "agent-b"
    )

    assert events[1].fingerprint == (
        second.fingerprint(capability)
    )

    second.close()


def test_revocation_and_lifecycle_remain_capability_scoped(
    tmp_path,
):
    revocation_path = (
        tmp_path / "revocations.db"
    )

    lifecycle_path = (
        tmp_path / "lifecycle.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    first = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    second = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.refund",
    )

    sdk.revoke(
        first,
        reason="compromised",
    )

    result = sdk.authorize(
        second,
        "payments.refund",
        {},
    )

    assert result.allowed is True

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].fingerprint == (
        sdk.fingerprint(second)
    )

    assert sdk.is_revoked(
        first
    ) is True

    assert sdk.is_revoked(
        second
    ) is False

    sdk.close()


def test_restart_does_not_duplicate_persistent_state(
    tmp_path,
):
    revocation_path = (
        tmp_path / "revocations.db"
    )

    lifecycle_path = (
        tmp_path / "lifecycle.db"
    )

    first = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    capability = first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    first.revoke(
        capability,
        reason="test",
    )

    assert len(
        first.lifecycle_events()
    ) == 2

    first.close()

    second = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    assert len(
        second.lifecycle_events()
    ) == 2

    assert second.is_revoked(
        capability
    ) is True

    second.close()

    third = FirewallSDK(
        revocation_store_path=revocation_path,
        lifecycle_store_path=lifecycle_path,
    )

    assert len(
        third.lifecycle_events()
    ) == 2

    assert third.is_revoked(
        capability
    ) is True

    third.close()