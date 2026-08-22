from __future__ import annotations

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.sdk import FirewallSDK


def make_capability(
    sdk,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    return capability


def test_successful_authorization_creates_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 25,
        },
    )

    assert result.allowed is True

    events = lifecycle.of_type(
        LifecycleEventType.USED
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

    assert event.details == {
        "action": "payments.send",
        "request": {
            "amount": 25,
        },
    }

    sdk.close()


def test_denied_authorization_creates_no_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


def test_constraint_denial_creates_no_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 101,
        },
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


def test_revoked_capability_creates_no_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 25,
        },
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


def test_multiple_successful_authorizations_create_multiple_used_events():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    first = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 10,
        },
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 20,
        },
    )

    assert first.allowed is True
    assert second.allowed is True

    used = lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 2

    assert used[0].details[
        "request"
    ] == {
        "amount": 10,
    }

    assert used[1].details[
        "request"
    ] == {
        "amount": 20,
    }

    sdk.close()


def test_issue_then_used_order():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 25,
        },
    )

    events = lifecycle.events()

    assert len(events) == 2

    assert (
        events[0].event_type
        == LifecycleEventType.ISSUED
    )

    assert (
        events[1].event_type
        == LifecycleEventType.USED
    )

    assert (
        events[0].fingerprint
        == events[1].fingerprint
    )

    sdk.close()


def test_used_event_preserves_action():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 10,
        },
    )

    event = lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    assert event.details[
        "action"
    ] == "payments.send"

    sdk.close()


def test_invalid_capability_creates_no_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    result = sdk.authorize(
        "not-a-capability",
        "payments.send",
        {},
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


def test_used_event_has_capability_identity():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 50,
        },
    )

    event = lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    assert event.agent_id == (
        capability.agent_id
    )

    assert event.capability == (
        capability.capability
    )

    assert event.issuer == (
        capability.issuer
    )

    sdk.close()


def test_default_sdk_records_used_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 5,
        },
    )

    assert result.allowed is True

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].fingerprint == (
        sdk.fingerprint(
            capability
        )
    )

    sdk.close()