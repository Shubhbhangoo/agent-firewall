from __future__ import annotations

from firewall.capability import (
    sign_capability,
)

from firewall.sdk import (
    FirewallSDK,
)


def make_sdk():
    sdk = FirewallSDK()

    sdk.generate_key(
        "key-1"
    )

    sdk.trust_issuer(
        "issuer-a"
    )

    return sdk


def test_managed_capability_contains_key_id():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    assert capability.key_id == (
        "key-1"
    )


def test_managed_capability_verifies():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    assert sdk.verify(
        capability
    ) is True


def test_wrong_key_id_is_rejected():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    forged = capability.__class__(
        agent_id=capability.agent_id,
        capability=capability.capability,
        constraints=capability.constraints,
        issuer=capability.issuer,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        public_key=capability.public_key,
        signature=capability.signature,
        key_id="wrong-key",
    )

    assert sdk.verify(
        forged
    ) is False


def test_wrong_public_key_for_key_id_is_rejected():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    other_sdk = FirewallSDK()

    other_sdk.generate_key(
        "other-key"
    )

    other_key = (
        other_sdk.active_key()
    )

    forged = capability.__class__(
        agent_id=capability.agent_id,
        capability=capability.capability,
        constraints=capability.constraints,
        issuer=capability.issuer,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        public_key=(
            other_key.public_key.public_bytes_raw()
            .decode("latin1")
            .encode("latin1")
        ).decode("latin1"),
        signature=capability.signature,
        key_id="key-1",
    )

    # The malformed public-key representation must not
    # accidentally validate.
    assert sdk.verify(
        forged
    ) is False


def test_unknown_managed_key_is_rejected():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    forged = capability.__class__(
        agent_id=capability.agent_id,
        capability=capability.capability,
        constraints=capability.constraints,
        issuer=capability.issuer,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        public_key=capability.public_key,
        signature=capability.signature,
        key_id="unknown",
    )

    assert sdk.verify(
        forged
    ) is False


def test_rotation_produces_new_key_identity():
    sdk = make_sdk()

    first = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    sdk.rotate_key(
        "key-2"
    )

    second = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer="issuer-a",
    )

    assert first.key_id == (
        "key-1"
    )

    assert second.key_id == (
        "key-2"
    )

    assert first.key_id != (
        second.key_id
    )

    assert sdk.verify(
        first
    ) is True

    assert sdk.verify(
        second
    ) is True


def test_legacy_capability_without_key_id_still_verifies():
    sdk = FirewallSDK()

    key = (
        sdk.generate_key(
            "managed"
        )
    )

    legacy = sign_capability(
        private_key=key.private_key,
        agent_id="agent-a",
        capability="payments.send",
        issuer="trusted-issuer",
        key_id=None,
    )

    assert legacy.key_id is None

    assert sdk.verify(
        legacy
    ) is True