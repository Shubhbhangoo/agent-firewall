import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.revocation import (
    AlreadyRevokedError,
    RevocationRegistry,
    RevokedCapabilityError,
)

from firewall.sdk import FirewallSDK


def make_sdk():
    return FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        }
    )


def make_capability(
    sdk,
    *,
    agent="finance-agent",
    capability="payments.send",
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent=agent,
        capability=capability,
    )


# ============================================================
# Registry injection
# ============================================================


def test_sdk_creates_revocation_registry():
    sdk = make_sdk()

    assert isinstance(
        sdk.revocation,
        RevocationRegistry,
    )


def test_sdk_accepts_custom_registry():
    registry = RevocationRegistry()

    sdk = FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        },
        revocation_registry=registry,
    )

    assert sdk.revocation is registry


# ============================================================
# Fingerprinting
# ============================================================


def test_sdk_fingerprint():
    sdk = make_sdk()
    capability = make_capability(sdk)

    fingerprint = sdk.fingerprint(
        capability
    )

    assert isinstance(
        fingerprint,
        str,
    )

    assert len(
        fingerprint
    ) == 64


def test_same_capability_same_fingerprint():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    first = sdk.fingerprint(
        capability
    )

    second = sdk.fingerprint(
        capability
    )

    assert first == second


# ============================================================
# Revocation
# ============================================================


def test_revoke_capability():
    sdk = make_sdk()
    capability = make_capability(sdk)

    record = sdk.revoke(
        capability,
        reason="compromised",
    )

    assert (
        record.fingerprint
        == sdk.fingerprint(
            capability
        )
    )

    assert record.reason == (
        "compromised"
    )


def test_is_revoked_false_initially():
    sdk = make_sdk()
    capability = make_capability(sdk)

    assert sdk.is_revoked(
        capability
    ) is False


def test_is_revoked_true_after_revoke():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(capability)

    assert sdk.is_revoked(
        capability
    ) is True


def test_double_revoke_rejected():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(
        capability
    )

    with pytest.raises(
        AlreadyRevokedError
    ):
        sdk.revoke(
            capability
        )


# ============================================================
# Active requirement
# ============================================================


def test_require_active_allows_active():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.require_active(
        capability
    )


def test_require_active_rejects_revoked():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(
        capability
    )

    with pytest.raises(
        RevokedCapabilityError
    ):
        sdk.require_active(
            capability
        )


# ============================================================
# Verification
# ============================================================


def test_valid_capability_verifies():
    sdk = make_sdk()
    capability = make_capability(sdk)

    assert sdk.verify(
        capability
    ) is True


def test_revoked_capability_fails_verify():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(
        capability
    )

    assert sdk.verify(
        capability
    ) is False


# ============================================================
# Authorization
# ============================================================


def test_active_capability_authorizes():
    sdk = make_sdk()
    capability = make_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is True


def test_revoked_capability_denied():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(
        capability
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert (
        result.reason
        == "capability_revoked"
    )


def test_is_authorized_false_after_revoke():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(
        capability
    )

    assert not sdk.is_authorized(
        capability,
        "payments.send",
        {},
    )


# ============================================================
# Replay interaction
# ============================================================


def test_revoked_capability_cannot_consume_nonce():
    sdk = make_sdk()
    capability = make_capability(sdk)

    sdk.revoke(
        capability
    )

    assert sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-1",
    ) is False


def test_active_capability_can_consume_nonce():
    sdk = make_sdk()
    capability = make_capability(sdk)

    assert sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-1",
    ) is True


# ============================================================
# Transport interaction
# ============================================================


def test_revoked_capability_cannot_decode_verified():
    sdk = make_sdk()
    capability = make_capability(sdk)

    token = sdk.encode(
        capability
    )

    sdk.revoke(
        capability
    )

    with pytest.raises(
        RevokedCapabilityError
    ):
        sdk.decode_verified(
            token
        )


def test_active_capability_decode_verified():
    sdk = make_sdk()
    capability = make_capability(sdk)

    token = sdk.encode(
        capability
    )

    restored = sdk.decode_verified(
        token
    )

    assert (
        restored.to_dict()
        == capability.to_dict()
    )


# ============================================================
# Capability isolation
# ============================================================


def test_revoking_one_capability_does_not_revoke_another():
    sdk = make_sdk()

    first = make_capability(
        sdk,
        capability="payments.send",
    )

    second = make_capability(
        sdk,
        capability="payments.refund",
    )

    sdk.revoke(
        first
    )

    assert sdk.is_revoked(
        first
    )

    assert not sdk.is_revoked(
        second
    )


def test_revocation_is_bound_to_fingerprint():
    sdk = make_sdk()

    first = make_capability(
        sdk
    )

    second = make_capability(
        sdk
    )

    assert (
        sdk.fingerprint(first)
        != sdk.fingerprint(second)
    )

    sdk.revoke(
        first
    )

    assert sdk.is_revoked(first)
    assert not sdk.is_revoked(second)


# ============================================================
# MCP / HTTP inheritance
# ============================================================


def test_revoked_capability_denied_through_mcp():
    from firewall.mcp import (
        MCPFirewall,
        MCPRequest,
    )

    sdk = make_sdk()
    firewall = MCPFirewall(sdk)

    capability = make_capability(
        sdk
    )

    token = sdk.encode(
        capability
    )

    sdk.revoke(
        capability
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={},
        capability_token=token,
        nonce="mcp-revoked",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False


def test_revoked_capability_denied_through_http():
    from firewall.http import (
        HTTPFirewall,
        HTTPRequest,
    )

    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk
    )

    token = sdk.encode(
        capability
    )

    sdk.revoke(
        capability
    )

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=token,
        nonce="http-revoked",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False


# ============================================================
# No unrevoke
# ============================================================


def test_sdk_has_no_unrevoke_operation():
    sdk = make_sdk()

    assert not hasattr(
        sdk,
        "unrevoke",
    )