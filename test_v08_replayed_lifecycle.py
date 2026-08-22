from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.sdk import FirewallSDK


def make_capability(sdk):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )


def test_first_nonce_use_does_not_emit_replayed():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(sdk)

    result = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert result is True

    assert lifecycle.of_type(
        LifecycleEventType.REPLAYED
    ) == ()

    sdk.close()


def test_second_nonce_use_emits_replayed():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(sdk)

    first = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    second = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert first is True
    assert second is False

    events = lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    assert len(events) == 1

    event = events[0]

    assert event.fingerprint == (
        sdk.fingerprint(
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

    assert event.reason == (
        "replay_detected"
    )

    assert event.details == {
        "agent": "agent-a",
        "nonce": "nonce-1",
    }

    sdk.close()


def test_different_nonce_is_not_replay():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(sdk)

    first = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    second = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-2",
    )

    assert first is True
    assert second is True

    assert lifecycle.of_type(
        LifecycleEventType.REPLAYED
    ) == ()

    sdk.close()


def test_replay_is_bound_to_agent():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(sdk)

    first = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    second = sdk.consume_nonce(
        "agent-b",
        capability,
        "nonce-1",
    )

    assert first is True
    assert second is True

    assert lifecycle.of_type(
        LifecycleEventType.REPLAYED
    ) == ()

    sdk.close()


def test_revoked_capability_does_not_emit_replayed():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(sdk)

    sdk.revoke(
        capability,
        reason="compromised",
    )

    result = sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert result is False

    assert lifecycle.of_type(
        LifecycleEventType.REPLAYED
    ) == ()

    sdk.close()


def test_multiple_replays_emit_multiple_events():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(sdk)

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-2",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-2",
    )

    events = lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    assert len(events) == 2

    assert events[0].details[
        "nonce"
    ] == "nonce-1"

    assert events[1].details[
        "nonce"
    ] == "nonce-2"

    sdk.close()


def test_default_sdk_records_replayed_event():
    sdk = FirewallSDK()

    capability = make_capability(sdk)

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    events = sdk.lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    assert len(events) == 1

    sdk.close()