from __future__ import annotations

import pytest

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.sdk import FirewallSDK


def test_sdk_can_issue_with_managed_active_key():
    sdk = FirewallSDK()

    key = sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert key.key_id == "key-1"
    assert sdk.verify(
        capability
    ) is True

    issued = sdk.lifecycle.of_type(
        LifecycleEventType.ISSUED
    )

    assert issued[0].details[
        "key_id"
    ] == "key-1"

    sdk.close()


def test_sdk_managed_key_rotation_changes_signing_key():
    sdk = FirewallSDK()

    first = sdk.generate_key(
        "key-1"
    )

    capability_1 = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    second = sdk.rotate_key(
        "key-2"
    )

    capability_2 = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert first.public_key.public_bytes_raw() != (
        second.public_key.public_bytes_raw()
    )

    assert capability_1.public_key != (
        capability_2.public_key
    )

    assert sdk.verify(
        capability_1
    ) is True

    assert sdk.verify(
        capability_2
    ) is True

    sdk.close()


def test_sdk_cannot_issue_with_retired_key():
    sdk = FirewallSDK()

    sdk.generate_key(
        "key-1"
    )

    sdk.retire_key(
        "key-1"
    )

    with pytest.raises(
        ValueError,
        match="key is retired",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            key_id="key-1",
        )

    sdk.close()


def test_sdk_can_issue_with_explicit_active_key():
    sdk = FirewallSDK()

    sdk.generate_key(
        "key-1"
    )

    sdk.rotate_key(
        "key-2"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        key_id="key-2",
    )

    assert sdk.verify(
        capability
    ) is True

    sdk.close()


def test_sdk_rejects_private_key_and_key_id_together():
    sdk = FirewallSDK()

    key = sdk.generate_key(
        "key-1"
    )

    with pytest.raises(
        ValueError,
        match="either private_key or key_id",
    ):
        sdk.issue(
            private_key=key.private_key,
            key_id="key-1",
            agent="agent-a",
            capability="payments.send",
        )

    sdk.close()


def test_legacy_private_key_issuance_still_works():
    sdk = FirewallSDK()

    key = sdk.generate_key(
        "managed-key"
    )

    capability = sdk.issue(
        private_key=key.private_key,
        agent="agent-a",
        capability="payments.send",
    )

    assert sdk.verify(
        capability
    ) is True

    sdk.close()


def test_issuer_can_be_revoked():
    sdk = FirewallSDK()

    sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="trusted-issuer",
    )

    assert sdk.verify(
        capability
    ) is True

    sdk.revoke_issuer(
        "trusted-issuer"
    )

    assert sdk.is_issuer_trusted(
        "trusted-issuer"
    ) is False

    assert sdk.verify(
        capability
    ) is False

    sdk.close()


def test_revoked_issuer_blocks_authorization():
    sdk = FirewallSDK()

    sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="trusted-issuer",
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

    sdk.close()


def test_trusting_issuer_restores_new_issuance():
    sdk = FirewallSDK(
        trusted_issuers=set()
    )

    sdk.trust_issuer(
        "issuer-a"
    )

    sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    assert sdk.verify(
        capability
    ) is True

    sdk.close()


def test_untrusted_issuer_cannot_issue():
    sdk = FirewallSDK(
        trusted_issuers=set()
    )

    sdk.generate_key(
        "key-1"
    )

    with pytest.raises(
        ValueError,
        match="issuer is not trusted",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
            issuer="issuer-a",
        )

    sdk.close()


def test_rotated_old_capability_remains_verifiable():
    sdk = FirewallSDK()

    sdk.generate_key(
        "key-1"
    )

    old_capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    sdk.rotate_key(
        "key-2"
    )

    assert sdk.verify(
        old_capability
    ) is True

    sdk.close()


def test_retiring_signing_key_does_not_implicitly_revoke_capability():
    sdk = FirewallSDK()

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

    assert sdk.verify(
        capability
    ) is True

    assert sdk.is_revoked(
        capability
    ) is False

    sdk.close()