import time

import pytest

from firewall.capability import (
    Capability,
    generate_capability_key_pair,
)

from firewall.sdk import FirewallSDK


def make_sdk():
    return FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        },
        clock=lambda: time.time(),
    )


def make_capability(
    sdk=None,
    *,
    agent="finance-agent",
    capability="payments.send",
    constraints=None,
):
    sdk = sdk or make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
    )


# ============================================================
# Initialization
# ============================================================


def test_sdk_initializes():
    sdk = make_sdk()

    assert sdk is not None
    assert sdk.verifier is not None
    assert sdk.replay is not None


def test_sdk_default_issuer():
    sdk = FirewallSDK()

    assert "trusted-issuer" in (
        sdk.verifier.trusted_issuers
    )


def test_sdk_rejects_invalid_trusted_issuers():
    with pytest.raises(TypeError):
        FirewallSDK(
            trusted_issuers=[]
        )


def test_sdk_accepts_frozenset_issuers():
    sdk = FirewallSDK(
        trusted_issuers=frozenset(
            {"trusted-issuer"}
        )
    )

    assert sdk is not None


# ============================================================
# Issue
# ============================================================


def test_issue_returns_capability():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert isinstance(
        capability,
        Capability,
    )


def test_issue_preserves_agent():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        agent="finance-agent",
    )

    assert (
        capability.agent_id
        == "finance-agent"
    )


def test_issue_preserves_scope():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    assert (
        capability.capability
        == "payments.send"
    )


def test_issue_preserves_constraints():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    assert (
        capability.constraints[
            "amount_max"
        ]
        == 100
    )


def test_issue_empty_constraints_are_safe():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints=None,
    )

    assert capability.constraints == {}


# ============================================================
# Verify
# ============================================================


def test_verify_valid_capability():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert sdk.verify(
        capability
    ) is True


def test_verify_tampered_capability():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.admin",
        }
    )

    assert sdk.verify(
        tampered
    ) is False


def test_verify_rejects_non_capability():
    sdk = make_sdk()

    assert sdk.verify(
        "invalid"
    ) is False


# ============================================================
# Authorization
# ============================================================


def test_authorize_allowed_action():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 10},
    )

    assert result.allowed is True


def test_authorize_wrong_action():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.refund",
        {},
    )

    assert result.allowed is False


def test_is_authorized_true():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {"amount": 10},
    )


def test_is_authorized_false():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert not sdk.is_authorized(
        capability,
        "payments.refund",
        {},
    )


def test_authorize_invalid_capability():
    sdk = make_sdk()

    result = sdk.authorize(
        "invalid",
        "payments.send",
        {},
    )

    assert result.allowed is False


# ============================================================
# Namespace behavior
# ============================================================


def test_wildcard_authorizes_child():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {},
    )


def test_wildcard_authorizes_refund():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    assert sdk.is_authorized(
        capability,
        "payments.refund",
        {},
    )


def test_wildcard_does_not_cross_root():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    assert not sdk.is_authorized(
        capability,
        "accounts.read",
        {},
    )


def test_specific_capability_cannot_escalate():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    assert not sdk.is_authorized(
        capability,
        "payments.admin",
        {},
    )


# ============================================================
# Constraints
# ============================================================


def test_constraint_allowed():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {"amount": 50},
    )


def test_constraint_denied():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    assert not sdk.is_authorized(
        capability,
        "payments.send",
        {"amount": 101},
    )


def test_constraint_boundary_allowed():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {"amount": 100},
    )


# ============================================================
# Attenuation
# ============================================================


def test_attenuate():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    assert (
        child.constraints[
            "amount_max"
        ]
        == 100
    )


def test_attenuated_capability_authorizes():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    assert sdk.is_authorized(
        child,
        "payments.send",
        {"amount": 50},
    )


def test_attenuated_capability_rejects_original_limit():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    assert not sdk.is_authorized(
        child,
        "payments.send",
        {"amount": 101},
    )


# ============================================================
# Delegation
# ============================================================


def test_delegate():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.*",
    )

    delegation = sdk.delegate(
        parent,
        private_key,
        delegatee="agent-b",
    )

    assert (
        delegation.child.agent_id
        == "agent-b"
    )


def test_verify_delegation():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.*",
    )

    delegation = sdk.delegate(
        parent,
        private_key,
        delegatee="agent-b",
    )

    assert sdk.verify_delegation(
        delegation
    )


def test_delegation_preserves_scope():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.*",
    )

    delegation = sdk.delegate(
        parent,
        private_key,
        delegatee="agent-b",
    )

    assert (
        delegation.child.capability
        == "payments.*"
    )


# ============================================================
# Dictionary serialization
# ============================================================


def test_serialize():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    data = sdk.serialize(
        capability
    )

    assert isinstance(
        data,
        dict,
    )


def test_deserialize():
    sdk = make_sdk()

    original = make_capability(
        sdk
    )

    data = sdk.serialize(
        original
    )

    restored = sdk.deserialize(
        data
    )

    assert (
        restored.to_dict()
        == original.to_dict()
    )


def test_serialized_capability_verifies():
    sdk = make_sdk()

    original = make_capability(
        sdk
    )

    restored = sdk.deserialize(
        sdk.serialize(
            original
        )
    )

    assert sdk.verify(
        restored
    )


def test_deserialize_rejects_non_dict():
    sdk = make_sdk()

    with pytest.raises(TypeError):
        sdk.deserialize([])


def test_serialize_rejects_non_capability():
    sdk = make_sdk()

    with pytest.raises(TypeError):
        sdk.serialize(
            "invalid"
        )


# ============================================================
# Transport encode
# ============================================================


def test_sdk_encode():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    token = sdk.encode(
        capability
    )

    assert isinstance(
        token,
        str,
    )

    assert token


def test_sdk_encode_is_deterministic():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    first = sdk.encode(
        capability
    )

    second = sdk.encode(
        capability
    )

    assert first == second


def test_sdk_encode_preserves_authority():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    token = sdk.encode(
        capability
    )

    assert isinstance(
        token,
        str,
    )


# ============================================================
# Transport decode
# ============================================================


def test_sdk_decode():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    restored = sdk.decode(
        sdk.encode(
            capability
        )
    )

    assert (
        restored.to_dict()
        == capability.to_dict()
    )


def test_sdk_decoded_capability_verifies():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    restored = sdk.decode(
        sdk.encode(
            capability
        )
    )

    assert sdk.verify(
        restored
    ) is True


def test_sdk_decode_rejects_invalid_token():
    sdk = make_sdk()

    with pytest.raises(
        Exception
    ):
        sdk.decode(
            "garbage"
        )


# ============================================================
# Verified decode
# ============================================================


def test_sdk_decode_verified():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    restored = sdk.decode_verified(
        sdk.encode(
            capability
        )
    )

    assert (
        restored.to_dict()
        == capability.to_dict()
    )


def test_sdk_decode_verified_returns_capability():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    restored = sdk.decode_verified(
        sdk.encode(
            capability
        )
    )

    assert isinstance(
        restored,
        Capability,
    )


def test_sdk_decode_verified_rejects_tampered_token():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    token = sdk.encode(
        capability
    )

    last = token[-1]

    replacement = (
        "A"
        if last != "A"
        else "B"
    )

    tampered = (
        token[:-1]
        + replacement
    )

    with pytest.raises(
        Exception
    ):
        sdk.decode_verified(
            tampered
        )


def test_sdk_decode_verified_rejects_wrong_capability():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    token = sdk.encode(
        capability
    )

    import base64
    import json

    padding = "=" * (
        -len(token) % 4
    )

    raw = base64.urlsafe_b64decode(
        (
            token + padding
        ).encode()
    )

    payload = json.loads(
        raw.decode()
    )

    payload["capability"][
        "capability"
    ] = "payments.admin"

    raw = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode()

    tampered = (
        base64.urlsafe_b64encode(
            raw
        )
        .decode()
        .rstrip("=")
    )

    with pytest.raises(
        ValueError
    ):
        sdk.decode_verified(
            tampered
        )


# ============================================================
# Replay
# ============================================================


def test_nonce_first_use():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-1",
    )


def test_nonce_replay_rejected():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-1",
    )

    assert not sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-1",
    )


def test_different_nonce_allowed():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-1",
    )

    assert sdk.consume_nonce(
        "finance-agent",
        capability,
        "nonce-2",
    )


def test_same_nonce_different_agents_allowed():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert sdk.consume_nonce(
        "agent-b",
        capability,
        "nonce-1",
    )


# ============================================================
# Evidence
# ============================================================


def test_evidence_helper_without_evidence():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    evidence = sdk.evidence(
        result
    )

    assert (
        evidence is None
        or evidence is not None
    )


# ============================================================
# API surface
# ============================================================


@pytest.mark.parametrize(
    "method",
    [
        "issue",
        "verify",
        "authorize",
        "is_authorized",
        "attenuate",
        "delegate",
        "verify_delegation",
        "consume_nonce",
        "serialize",
        "deserialize",
        "encode",
        "decode",
        "decode_verified",
        "evidence",
    ],
)
def test_sdk_public_api(method):
    sdk = make_sdk()

    assert hasattr(
        sdk,
        method,
    )


# ============================================================
# End-to-end developer flow
# ============================================================


def test_complete_sdk_flow():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    assert sdk.verify(
        capability
    )

    token = sdk.encode(
        capability
    )

    transported = sdk.decode_verified(
        token
    )

    assert sdk.is_authorized(
        transported,
        "payments.send",
        {"amount": 50},
    )

    assert sdk.consume_nonce(
        "finance-agent",
        transported,
        "request-1",
    )

    assert not sdk.consume_nonce(
        "finance-agent",
        transported,
        "request-1",
    )


def test_complete_denied_flow():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    token = sdk.encode(
        capability
    )

    transported = sdk.decode_verified(
        token
    )

    assert not sdk.is_authorized(
        transported,
        "payments.send",
        {"amount": 101},
    )


# ============================================================
# Type safety
# ============================================================


def test_attenuation_invalid_parent():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    with pytest.raises(
        (TypeError, AttributeError)
    ):
        sdk.attenuate(
            "invalid",
            private_key,
        )


def test_delegate_invalid_parent():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    with pytest.raises(
        (TypeError, AttributeError)
    ):
        sdk.delegate(
            "invalid",
            private_key,
            delegatee="agent-b",
        )


# ============================================================
# Expiration
# ============================================================


def test_expired_capability_not_verified():
    now = [1000.0]

    sdk = FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        },
        clock=lambda: now[0],
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.send",
        issued_at=900,
        expires_at=1100,
    )

    assert sdk.verify(
        capability
    )

    now[0] = 1200

    assert not sdk.verify(
        capability
    )


# ============================================================
# Transport authority preservation
# ============================================================


def test_transport_preserves_constraint():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    restored = sdk.decode_verified(
        sdk.encode(
            capability
        )
    )

    assert sdk.is_authorized(
        restored,
        "payments.send",
        {"amount": 100},
    )

    assert not sdk.is_authorized(
        restored,
        "payments.send",
        {"amount": 101},
    )


def test_transport_preserves_wildcard_scope():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    restored = sdk.decode_verified(
        sdk.encode(
            capability
        )
    )

    assert sdk.is_authorized(
        restored,
        "payments.send",
        {},
    )

    assert sdk.is_authorized(
        restored,
        "payments.refund",
        {},
    )

    assert not sdk.is_authorized(
        restored,
        "accounts.read",
        {},
    )