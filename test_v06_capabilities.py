import base64
import json

import pytest

from firewall.capability import (
    Capability,
    CapabilityVerifier,
    capability_fingerprint,
    generate_capability_key_pair,
    sign_capability,
)


def make_capability(
    private_key,
    **overrides,
):
    values = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "constraints": {
            "amount_max": 100,
        },
        "issuer": "trusted-issuer",
        "issued_at": 1000,
        "expires_at": 2000,
    }

    values.update(overrides)

    return sign_capability(
        private_key,
        **values,
    )


# ============================================================
# Valid capabilities
# ============================================================


def test_valid_capability_verifies():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is True


def test_valid_capability_with_empty_constraints():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={},
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is True


def test_valid_capability_with_multiple_constraints():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
            "recipient": "merchant",
        },
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is True


# ============================================================
# Signature tampering
# ============================================================


def test_invalid_signature_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "signature": "bad",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_malformed_signature_base64_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "signature": "!!!not-base64!!!",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_empty_signature_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "signature": "",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


# ============================================================
# Agent tampering
# ============================================================


def test_agent_tampering_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "agent_id": "attacker",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_empty_agent_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(ValueError):
        make_capability(
            private_key,
            agent_id="",
        )


def test_non_string_agent_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(ValueError):
        make_capability(
            private_key,
            agent_id=None,
        )


# ============================================================
# Capability tampering
# ============================================================


def test_capability_tampering_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.admin",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_empty_capability_rejected_at_creation():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(ValueError):
        make_capability(
            private_key,
            capability="",
        )


def test_capability_replay_with_different_tool_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.refund",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


# ============================================================
# Constraint tampering
# ============================================================


def test_constraint_tampering_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "constraints": {
                "amount_max": 1000000,
            },
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_constraint_addition_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "constraints": {
                "amount_max": 100,
                "admin": True,
            },
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_constraint_removal_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "constraints": {
                "amount_max": 100,
            },
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_non_dict_constraints_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(TypeError):
        make_capability(
            private_key,
            constraints=[
                "payments.send"
            ],
        )


# ============================================================
# Issuer
# ============================================================


def test_wrong_issuer_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        issuer="evil-issuer",
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is False


def test_issuer_tampering_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "issuer": "evil-issuer",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer", "evil-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_empty_issuer_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(ValueError):
        make_capability(
            private_key,
            issuer="",
        )


def test_multiple_trusted_issuers():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        issuer="issuer-b",
    )

    verifier = CapabilityVerifier(
        {
            "issuer-a",
            "issuer-b",
        },
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is True


# ============================================================
# Time validity
# ============================================================


def test_expired_capability_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 2000,
    )

    assert verifier.verify(
        capability
    ) is False


def test_not_yet_valid_capability_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 999,
    )

    assert verifier.verify(
        capability
    ) is False


def test_future_issued_at_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        issued_at=2000,
        expires_at=3000,
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is False


def test_equal_issue_and_expiry_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(ValueError):
        make_capability(
            private_key,
            issued_at=1500,
            expires_at=1500,
        )


def test_expiry_before_issue_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(ValueError):
        make_capability(
            private_key,
            issued_at=2000,
            expires_at=1000,
        )


def test_expired_exactly_at_boundary():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        issued_at=1000,
        expires_at=2000,
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1999.999,
    )

    assert verifier.verify(
        capability
    ) is True


# ============================================================
# Public key
# ============================================================


def test_wrong_public_key_rejected():
    private_key, _ = generate_capability_key_pair()
    other_private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    other_public_key = (
        other_private_key
        .public_key()
        .public_bytes_raw()
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "public_key": base64.b64encode(
                other_public_key
            ).decode("ascii"),
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_malformed_public_key_base64_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "public_key": "!!!not-base64!!!",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_wrong_key_cannot_sign_existing_capability():
    private_key, _ = generate_capability_key_pair()
    other_private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    forged_signature = other_private_key.sign(
        capability.signing_payload()
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "signature": base64.b64encode(
                forged_signature
            ).decode("ascii"),
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


# ============================================================
# Replay / signed-field binding
# ============================================================


def test_signature_replay_with_changed_expiry_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "expires_at": 999999,
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_signature_replay_with_changed_issuer_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "issuer": "another-issuer",
        }
    )

    verifier = CapabilityVerifier(
        {
            "trusted-issuer",
            "another-issuer",
        },
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_signature_replay_with_changed_public_key_rejected():
    private_key, _ = generate_capability_key_pair()
    other_private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    other_public_key = (
        other_private_key
        .public_key()
        .public_bytes_raw()
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "public_key": base64.b64encode(
                other_public_key
            ).decode("ascii"),
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


def test_issued_at_tampering_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "issued_at": 1200,
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        tampered
    ) is False


# ============================================================
# Serialization
# ============================================================


def test_capability_can_be_serialized():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    data = capability.to_dict()

    assert data["agent_id"] == (
        "finance-agent"
    )

    assert data["capability"] == (
        "payments.send"
    )

    assert data["signature"]


def test_capability_json_round_trip():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    encoded = capability.to_json()

    decoded = json.loads(
        encoded
    )

    restored = Capability(
        **decoded
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        restored
    ) is True


def test_round_trip_preserves_payload():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    restored = Capability(
        **json.loads(
            capability.to_json()
        )
    )

    assert (
        restored.signing_payload()
        == capability.signing_payload()
    )


# ============================================================
# Signature uniqueness
# ============================================================


def test_different_constraints_produce_different_signatures():
    private_key, _ = generate_capability_key_pair()

    first = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    second = make_capability(
        private_key,
        constraints={
            "amount_max": 200,
        },
    )

    assert first.signature != (
        second.signature
    )


def test_different_agents_produce_different_signatures():
    private_key, _ = generate_capability_key_pair()

    first = make_capability(
        private_key,
        agent_id="agent-a",
    )

    second = make_capability(
        private_key,
        agent_id="agent-b",
    )

    assert first.signature != (
        second.signature
    )


def test_different_capabilities_produce_different_signatures():
    private_key, _ = generate_capability_key_pair()

    first = make_capability(
        private_key,
        capability="payments.send",
    )

    second = make_capability(
        private_key,
        capability="payments.refund",
    )

    assert first.signature != (
        second.signature
    )


# ============================================================
# Fingerprint
# ============================================================


def test_fingerprint_is_stable():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    first = capability_fingerprint(
        capability
    )

    second = capability_fingerprint(
        capability
    )

    assert first == second


def test_different_capabilities_have_different_fingerprints():
    private_key, _ = generate_capability_key_pair()

    first = make_capability(
        private_key,
        capability="payments.send",
    )

    second = make_capability(
        private_key,
        capability="payments.refund",
    )

    assert (
        capability_fingerprint(first)
        != capability_fingerprint(second)
    )


# ============================================================
# Defensive verification
# ============================================================


def test_non_capability_object_rejected():
    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        None
    ) is False


def test_dictionary_rejected():
    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        {}
    ) is False


def test_empty_trusted_issuer_list_allows_valid_signature():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    verifier = CapabilityVerifier(
        set(),
        clock=lambda: 1500,
    )

    assert verifier.verify(
        capability
    ) is True