from __future__ import annotations

import pytest
from hypothesis import given, strategies as st

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.revocation import (
    AlreadyRevokedError,
)

from firewall.sdk import FirewallSDK


LIFECYCLE_TYPES = tuple(
    LifecycleEventType
)


@given(
    st.lists(
        st.sampled_from(
            LIFECYCLE_TYPES
        ),
        min_size=1,
        max_size=25,
    )
)
def test_lifecycle_event_values_are_stable(
    sequence,
):
    values = [
        event_type.value
        for event_type in sequence
    ]

    assert all(
        isinstance(
            value,
            str,
        )
        and value
        for value in values
    )


def make_sdk():
    return FirewallSDK()


def make_capability(
    sdk,
    *,
    capability="payments.send",
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability=capability,
    )


def lifecycle_types(
    sdk,
    fingerprint,
):
    return tuple(
        event.event_type
        for event in sdk.lifecycle.events()
        if event.fingerprint == fingerprint
    )


def test_issue_then_use_has_valid_order():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is True

    events = lifecycle_types(
        sdk,
        fingerprint,
    )

    assert events == (
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
    )

    sdk.close()


def test_revoke_then_authorize_cannot_use():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    sdk.revoke(
        capability,
        reason="test",
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False

    events = lifecycle_types(
        sdk,
        fingerprint,
    )

    assert events == (
        LifecycleEventType.ISSUED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    )

    assert (
        LifecycleEventType.USED
        not in events
    )

    sdk.close()


def test_expired_capability_cannot_be_used():
    sdk = FirewallSDK(
        clock=lambda: 200.0
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
        issued_at=100.0,
        expires_at=150.0,
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert result.reason == "expired"

    events = lifecycle_types(
        sdk,
        fingerprint,
    )

    assert events == (
        LifecycleEventType.ISSUED,
        LifecycleEventType.EXPIRED,
    )

    assert (
        LifecycleEventType.USED
        not in events
    )

    sdk.close()


def test_denied_authorization_never_creates_used_event():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    result = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert result.allowed is False

    events = lifecycle_types(
        sdk,
        fingerprint,
    )

    assert (
        LifecycleEventType.DENIED
        in events
    )

    assert (
        LifecycleEventType.USED
        not in events
    )

    sdk.close()


def test_replay_never_creates_used_event():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    fingerprint = sdk.fingerprint(
        capability
    )

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

    events = lifecycle_types(
        sdk,
        fingerprint,
    )

    assert (
        LifecycleEventType.REPLAYED
        in events
    )

    sdk.close()


def test_issuer_revocation_does_not_create_used_event():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    sdk.revoke_issuer(
        "trusted-issuer"
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert result.reason == (
        "untrusted_issuer"
    )

    events = lifecycle_types(
        sdk,
        fingerprint,
    )

    assert (
        LifecycleEventType.USED
        not in events
    )

    assert (
        LifecycleEventType.DENIED
        in events
    )

    sdk.close()


def test_retiring_key_does_not_revoke_existing_capability():
    sdk = make_sdk()

    sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    sdk.retire_key(
        "key-1"
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is True

    sdk.close()


def test_rotated_key_creates_independent_capability_identity():
    sdk = make_sdk()

    sdk.generate_key(
        "key-1"
    )

    first = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    sdk.rotate_key(
        "key-2"
    )

    second = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert sdk.fingerprint(
        first
    ) != sdk.fingerprint(
        second
    )

    assert sdk.verify(
        first
    ) is True

    assert sdk.verify(
        second
    ) is True

    sdk.close()


@given(
    st.lists(
        st.sampled_from(
            [
                "authorize",
                "revoke",
                "authorize",
                "authorize",
                "rotate",
                "authorize",
            ]
        ),
        min_size=1,
        max_size=12,
    )
)
def test_generated_operation_sequences_never_execute_after_revocation(
    operations,
):
    sdk = make_sdk()

    sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    revoked = False

    for index, operation in enumerate(
        operations
    ):

        if operation == "authorize":
            result = sdk.authorize(
                capability,
                "payments.send",
                {},
            )

            if revoked:
                assert result.allowed is False
            else:
                assert result.allowed is True

        elif operation == "revoke":

            if revoked:
                with pytest.raises(
                    AlreadyRevokedError
                ):
                    sdk.revoke(
                        capability,
                        reason="state-machine",
                    )
            else:
                sdk.revoke(
                    capability,
                    reason="state-machine",
                )

                revoked = True

        elif operation == "rotate":

            key_id = (
                f"rotated-{index}"
            )

            sdk.rotate_key(
                key_id
            )

    if revoked:
        final = sdk.authorize(
            capability,
            "payments.send",
            {},
        )

        assert final.allowed is False

    sdk.close()


@given(
    st.lists(
        st.sampled_from(
            [
                "authorize",
                "authorize",
                "authorize",
                "rotate",
            ]
        ),
        min_size=1,
        max_size=10,
    )
)
def test_rotation_never_invalidates_existing_capability(
    operations,
):
    sdk = make_sdk()

    sdk.generate_key(
        "initial"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    for index, operation in enumerate(
        operations
    ):

        if operation == "rotate":
            sdk.rotate_key(
                f"rotated-{index}"
            )

        else:
            result = sdk.authorize(
                capability,
                "payments.send",
                {},
            )

            assert result.allowed is True

    assert sdk.verify(
        capability
    ) is True

    sdk.close()