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
        constraints={
            "amount_max": 100,
        },
    )


def test_denied_namespace_creates_event():
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

    denied = lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1

    event = denied[0]

    assert event.fingerprint == (
        sdk.fingerprint(
            capability
        )
    )

    assert event.reason == (
        "namespace_denied"
    )

    assert event.details == {
        "action": "admin.delete",
        "request": {},
    }

    sdk.close()


def test_denied_constraint_creates_event():
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

    denied = lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1

    assert denied[0].reason == (
        "constraint_denied"
    )

    sdk.close()


def test_denied_revocation_creates_event():
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
            "amount": 10,
        },
    )

    assert result.allowed is False

    denied = lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1

    assert denied[0].reason == (
        "capability_revoked"
    )

    sdk.close()


def test_successful_use_creates_used_not_denied():
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
            "amount": 10,
        },
    )

    assert result.allowed is True

    assert lifecycle.of_type(
        LifecycleEventType.DENIED
    ) == ()

    assert len(
        lifecycle.of_type(
            LifecycleEventType.USED
        )
    ) == 1

    sdk.close()


def test_multiple_denials_create_multiple_events():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    denied = lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 2

    sdk.close()


def test_denial_preserves_request():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    request = {
        "amount": 999,
        "currency": "USD",
    }

    result = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    assert result.allowed is False

    event = lifecycle.of_type(
        LifecycleEventType.DENIED
    )[0]

    assert event.details[
        "request"
    ] == request

    sdk.close()


def test_default_sdk_records_denied():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert result.allowed is False

    denied = sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1

    sdk.close()