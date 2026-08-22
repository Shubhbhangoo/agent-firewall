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


def test_sdk_persists_issued_event(tmp_path):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    capability = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    events = sdk.lifecycle_events()

    assert len(events) == 1
    assert (
        events[0].event_type
        == LifecycleEventType.ISSUED
    )

    assert (
        events[0].fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    sdk.close()


def test_sdk_restores_lifecycle_after_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = FirewallSDK(
        lifecycle_store_path=path
    )

    capability = first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    first.authorize(
        capability,
        "payments.send",
        {"amount": 10},
    )

    expected = first.lifecycle_events()

    first.close()

    second = FirewallSDK(
        lifecycle_store_path=path
    )

    restored = second.lifecycle_events()

    assert restored == expected

    second.close()


def test_sdk_persists_full_lifecycle(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    key = make_key()

    capability = sdk.issue(
        private_key=key,
        agent="agent-a",
        capability="payments.send",
    )

    sdk.authorize(
        capability,
        "payments.send",
        {"amount": 10},
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    sdk.authorize(
        capability,
        "payments.send",
        {"amount": 10},
    )

    events = sdk.lifecycle_events()

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    ]

    sdk.close()

    restarted = FirewallSDK(
        lifecycle_store_path=path
    )

    restored = restarted.lifecycle_events()

    assert [
        event.event_type
        for event in restored
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    ]

    restarted.close()


def test_sdk_persistence_does_not_duplicate_history(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = FirewallSDK(
        lifecycle_store_path=path
    )

    first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    assert len(
        first.lifecycle_events()
    ) == 1

    first.close()

    second = FirewallSDK(
        lifecycle_store_path=path
    )

    assert len(
        second.lifecycle_events()
    ) == 1

    second.close()

    third = FirewallSDK(
        lifecycle_store_path=path
    )

    assert len(
        third.lifecycle_events()
    ) == 1

    third.close()


def test_sdk_persistence_survives_new_events_after_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = FirewallSDK(
        lifecycle_store_path=path
    )

    first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    first.close()

    second = FirewallSDK(
        lifecycle_store_path=path
    )

    second.issue(
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

    assert events[0].agent_id == (
        "agent-a"
    )

    assert events[1].agent_id == (
        "agent-b"
    )

    second.close()


def test_sdk_lifecycle_store_is_exposed(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    assert sdk.lifecycle_store is not None
    assert sdk.lifecycle.store is (
        sdk.lifecycle_store
    )

    sdk.close()


def test_custom_lifecycle_recorder_is_not_replaced(
    tmp_path,
):
    from firewall.lifecycle import (
        LifecycleRecorder,
    )

    recorder = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=recorder,
        lifecycle_store_path=None,
    )

    assert sdk.lifecycle is recorder
    assert sdk.lifecycle_store is None

    sdk.close()


def test_recorder_and_store_paths_are_mutually_exclusive(
    tmp_path,
):
    from firewall.lifecycle import (
        LifecycleRecorder,
    )

    recorder = LifecycleRecorder()

    try:
        FirewallSDK(
            lifecycle_recorder=recorder,
            lifecycle_store_path=(
                tmp_path / "lifecycle.db"
            ),
        )
    except ValueError as exc:
        assert "either" in str(exc)
    else:
        raise AssertionError(
            "expected ValueError"
        )


def test_sdk_close_closes_persistent_lifecycle_store(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    store = sdk.lifecycle_store

    assert store.closed is False

    sdk.close()

    assert store.closed is True


def test_sdk_default_lifecycle_remains_in_memory():
    sdk = FirewallSDK()

    assert sdk.lifecycle_store is None
    assert sdk.lifecycle.store is None

    sdk.close()


def test_sdk_lifecycle_history_can_be_filtered_after_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = FirewallSDK(
        lifecycle_store_path=path
    )

    capability = first.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    first.authorize(
        capability,
        "payments.send",
        {},
    )

    first.close()

    second = FirewallSDK(
        lifecycle_store_path=path
    )

    used = second.lifecycle.of_type(
        LifecycleEventType.USED
    )

    issued = second.lifecycle.of_type(
        LifecycleEventType.ISSUED
    )

    by_fingerprint = (
        second.lifecycle.for_fingerprint(
            second.fingerprint(
                capability
            )
        )
    )

    assert len(issued) == 1
    assert len(used) == 1
    assert len(by_fingerprint) == 2

    second.close()


def test_sdk_persistent_history_preserves_event_details(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = FirewallSDK(
        lifecycle_store_path=path
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
            "payment": {
                "amount": 25,
                "currency": "USD",
            }
        },
    )

    expected = first.lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    first.close()

    second = FirewallSDK(
        lifecycle_store_path=path
    )

    actual = second.lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    assert actual.details == (
        expected.details
    )

    second.close()