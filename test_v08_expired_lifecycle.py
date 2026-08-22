from __future__ import annotations

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
    *,
    issued_at,
    expires_at,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
        issued_at=issued_at,
        expires_at=expires_at,
    )


def test_expired_capability_creates_expired_event():
    lifecycle = LifecycleRecorder(
        clock=lambda: 200.0
    )

    sdk = FirewallSDK(
        clock=lambda: 200.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert result.reason == "expired"

    expired = lifecycle.of_type(
        LifecycleEventType.EXPIRED
    )

    assert len(expired) == 1

    event = expired[0]

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

    assert event.reason == "expired"

    assert event.details == {
        "action": "payments.send",
        "request": {},
        "expires_at": 150.0,
    }

    sdk.close()


def test_nonexpired_capability_does_not_emit_expired():
    lifecycle = LifecycleRecorder(
        clock=lambda: 100.0
    )

    sdk = FirewallSDK(
        clock=lambda: 100.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=50.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is True

    assert lifecycle.of_type(
        LifecycleEventType.EXPIRED
    ) == ()

    sdk.close()


def test_namespace_denial_is_not_expired():
    lifecycle = LifecycleRecorder(
        clock=lambda: 100.0
    )

    sdk = FirewallSDK(
        clock=lambda: 100.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=50.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert result.allowed is False
    assert (
        result.reason
        == "namespace_denied"
    )

    assert lifecycle.of_type(
        LifecycleEventType.EXPIRED
    ) == ()

    denied = lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1
    assert denied[0].reason == (
        "namespace_denied"
    )

    sdk.close()


def test_expiration_takes_precedence_over_namespace_denial():
    lifecycle = LifecycleRecorder(
        clock=lambda: 200.0
    )

    sdk = FirewallSDK(
        clock=lambda: 200.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert result.allowed is False
    assert result.reason == "expired"

    expired = lifecycle.of_type(
        LifecycleEventType.EXPIRED
    )

    denied = lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(expired) == 1
    assert denied == ()

    sdk.close()


def test_expiration_emits_one_event_per_attempt():
    lifecycle = LifecycleRecorder(
        clock=lambda: 200.0
    )

    sdk = FirewallSDK(
        clock=lambda: 200.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    expired = lifecycle.of_type(
        LifecycleEventType.EXPIRED
    )

    assert len(expired) == 2

    sdk.close()


def test_expiration_preserves_request():
    lifecycle = LifecycleRecorder(
        clock=lambda: 200.0
    )

    sdk = FirewallSDK(
        clock=lambda: 200.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    request = {
        "amount": 25,
        "currency": "USD",
    }

    result = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    assert result.allowed is False

    event = lifecycle.of_type(
        LifecycleEventType.EXPIRED
    )[0]

    assert event.details[
        "request"
    ] == request

    sdk.close()


def test_expired_capability_never_creates_used_event():
    lifecycle = LifecycleRecorder(
        clock=lambda: 200.0
    )

    sdk = FirewallSDK(
        clock=lambda: 200.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    assert len(
        lifecycle.of_type(
            LifecycleEventType.EXPIRED
        )
    ) == 1

    sdk.close()


def test_expired_event_preserves_capability_identity():
    lifecycle = LifecycleRecorder(
        clock=lambda: 200.0
    )

    sdk = FirewallSDK(
        clock=lambda: 200.0,
        lifecycle_recorder=lifecycle,
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    event = lifecycle.of_type(
        LifecycleEventType.EXPIRED
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


def test_default_sdk_records_expired_event():
    sdk = FirewallSDK(
        clock=lambda: 200.0
    )

    capability = make_capability(
        sdk,
        issued_at=100.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False

    expired = sdk.lifecycle.of_type(
        LifecycleEventType.EXPIRED
    )

    assert len(expired) == 1

    sdk.close()