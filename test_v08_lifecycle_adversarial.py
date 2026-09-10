from __future__ import annotations

import copy
import threading

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


def make_capability(
    sdk,
    *,
    agent="agent-a",
    capability="payments.send",
    constraints=None,
    issued_at=None,
    expires_at=None,
):
    return sdk.issue(
        private_key=make_key(),
        agent=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
        issued_at=issued_at,
        expires_at=expires_at,
    )


# ============================================================
# Event isolation
# ============================================================


def test_denied_request_never_creates_used_event():
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

    assert len(
        lifecycle.of_type(
            LifecycleEventType.DENIED
        )
    ) == 1

    sdk.close()


def test_expired_request_never_creates_used_event():
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


def test_revoked_request_never_creates_used_event():
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
        {},
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    assert len(
        lifecycle.of_type(
            LifecycleEventType.DENIED
        )
    ) == 1

    sdk.close()


# ============================================================
# Tampering
# ============================================================


def test_tampered_capability_creates_no_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    data = capability.to_dict()

    data["capability"] = (
        "admin.delete"
    )

    tampered = sdk.deserialize(
        data
    )

    result = sdk.authorize(
        tampered,
        "admin.delete",
        {},
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


def test_tampered_capability_creates_denied_or_verification_failure():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    data = capability.to_dict()

    data["agent_id"] = "attacker"

    tampered = sdk.deserialize(
        data
    )

    result = sdk.authorize(
        tampered,
        "payments.send",
        {},
    )

    assert result.allowed is False

    assert lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


# ============================================================
# Lifecycle mutation resistance
# ============================================================


def test_event_details_are_snapshot_copies():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    request = {
        "amount": 10
    }

    sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    request["amount"] = 999999

    event = lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    assert event.details[
        "request"
    ]["amount"] == 10

    sdk.close()


def test_nested_request_mutation_does_not_change_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    request = {
        "payment": {
            "amount": 10
        }
    }

    sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    request["payment"]["amount"] = 999

    event = lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    assert event.details[
        "request"
    ]["payment"]["amount"] == 10

    sdk.close()


# ============================================================
# Cross-capability isolation
# ============================================================


def test_used_event_is_bound_to_correct_capability():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    first = make_capability(
        sdk,
        capability="payments.send",
    )

    second = make_capability(
        sdk,
        capability="payments.refund",
    )

    sdk.authorize(
        first,
        "payments.send",
        {},
    )

    sdk.authorize(
        second,
        "payments.refund",
        {},
    )

    used = lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 2

    assert used[0].fingerprint == (
        sdk.fingerprint(first)
    )

    assert used[1].fingerprint == (
        sdk.fingerprint(second)
    )

    sdk.close()


def test_revocation_does_not_cross_capabilities():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    first = make_capability(
        sdk,
        capability="payments.send",
    )

    second = make_capability(
        sdk,
        capability="payments.refund",
    )

    sdk.revoke(first)

    result = sdk.authorize(
        second,
        "payments.refund",
        {},
    )

    assert result.allowed is True

    sdk.close()


# ============================================================
# Replay lifecycle adversarial
# ============================================================


def test_replay_event_only_on_actual_replay():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-2",
    )

    assert lifecycle.of_type(
        LifecycleEventType.REPLAYED
    ) == ()

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    replayed = lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    assert len(replayed) == 1

    assert replayed[0].details[
        "nonce"
    ] == "nonce-1"

    sdk.close()


def test_replay_does_not_create_used_event():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

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

    assert lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    sdk.close()


# ============================================================
# Ordering
# ============================================================


def test_issue_revoke_deny_order():
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

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    events = lifecycle.events()

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    ]

    sdk.close()


def test_issue_used_order():
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
        {},
    )

    events = lifecycle.events()

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
    ]

    sdk.close()


def test_issue_expired_order():
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

    events = lifecycle.events()

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.EXPIRED,
    ]

    sdk.close()


# ============================================================
# Concurrent authorization
# ============================================================


def test_concurrent_successful_authorization_events_are_complete():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    capability = make_capability(
        sdk
    )

    results = []
    lock = threading.Lock()

    def worker():
        result = sdk.authorize(
            capability,
            "payments.send",
            {},
        )

        with lock:
            results.append(
                result.allowed
            )

    threads = [
        threading.Thread(
            target=worker
        )
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(results) == 20
    assert all(results)

    used = lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 20

    sdk.close()


# ============================================================
# Capability replacement
# ============================================================


def test_reissue_does_not_inherit_old_lifecycle_identity():
    lifecycle = LifecycleRecorder()

    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    old = make_capability(
        sdk
    )

    sdk.revoke(old)

    new = make_capability(
        sdk
    )

    result = sdk.authorize(
        new,
        "payments.send",
        {},
    )

    assert result.allowed is True

    assert sdk.fingerprint(
        old
    ) != sdk.fingerprint(
        new
    )

    used = lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].fingerprint == (
        sdk.fingerprint(new)
    )

    sdk.close()


# ============================================================
# No accidental lifecycle duplication
# ============================================================


def test_one_authorization_has_only_one_terminal_event():
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
        {},
    )

    terminal = [
        event
        for event in lifecycle.events()
        if event.event_type
        in {
            LifecycleEventType.USED,
            LifecycleEventType.DENIED,
            LifecycleEventType.EXPIRED,
        }
    ]

    assert len(terminal) == 1

    sdk.close()


def test_one_expired_authorization_has_only_one_terminal_event():
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

    terminal = [
        event
        for event in lifecycle.events()
        if event.event_type
        in {
            LifecycleEventType.USED,
            LifecycleEventType.DENIED,
            LifecycleEventType.EXPIRED,
        }
    ]

    assert len(terminal) == 1
    assert (
        terminal[0].event_type
        == LifecycleEventType.EXPIRED
    )

    sdk.close()


# ============================================================
# Full lifecycle
# ============================================================


def test_full_issue_use_revoke_deny_lifecycle():
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
        {},
    )

    assert first.allowed is True

    sdk.revoke(
        capability,
        reason="compromised",
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert second.allowed is False

    events = lifecycle.events()

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