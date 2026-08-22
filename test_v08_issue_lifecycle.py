import pytest

from firewall.capability import (
    generate_capability_key_pair,
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


def test_issue_creates_issued_event():
    lifecycle = LifecycleRecorder(
        clock=lambda: 100.0
    )

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
        issuer="trusted-issuer",
        issued_at=90.0,
        expires_at=190.0,
    )

    events = lifecycle.events()

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        == LifecycleEventType.ISSUED
    )

    assert (
        event.fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    assert event.agent_id == "agent-a"
    assert (
        event.capability
        == "payments.send"
    )
    assert (
        event.issuer
        == "trusted-issuer"
    )

    assert event.details == {
        "issued_at": 90.0,
        "expires_at": 190.0,
    }

    sdk.close()


def test_issue_emits_exactly_one_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    assert lifecycle.size() == 1

    sdk.close()


def test_multiple_issues_emit_multiple_events():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
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

    events = lifecycle.events()

    assert len(events) == 2

    assert events[0].fingerprint == (
        sdk.fingerprint(first)
    )

    assert events[1].fingerprint == (
        sdk.fingerprint(second)
    )

    sdk.close()


def test_failed_issue_creates_no_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    with pytest.raises(TypeError):
        sdk.issue(
            private_key="not-a-key",
            agent="agent-a",
            capability="payments.send",
        )

    assert lifecycle.size() == 0

    sdk.close()


def test_custom_lifecycle_recorder_is_used():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    assert sdk.lifecycle is lifecycle

    capability = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
    )

    assert lifecycle.size() == 1

    assert (
        lifecycle.events()[0].fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    sdk.close()


def test_default_lifecycle_recorder_exists():
    sdk = FirewallSDK()

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


def test_issue_preserves_capability_data():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100
        },
        issuer="trusted-issuer",
        issued_at=100.0,
        expires_at=200.0,
    )

    event = lifecycle.events()[0]

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
        "issued_at"
    ] == capability.issued_at

    assert event.details[
        "expires_at"
    ] == capability.expires_at

    sdk.close()