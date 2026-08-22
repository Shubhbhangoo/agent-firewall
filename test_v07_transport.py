import base64
import json

import pytest

from firewall.capability import (
    Capability,
    generate_capability_key_pair,
)

from firewall.sdk import FirewallSDK

from firewall.transport import (
    DEFAULT_MAX_TOKEN_SIZE,
    TransportError,
    decode_capability,
    encode_capability,
    is_transport_token,
    round_trip,
    token_size,
)


def make_sdk():
    return FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        }
    )


def make_capability(
    *,
    capability="payments.send",
    constraints=None,
    agent="finance-agent",
):
    sdk = make_sdk()

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
# Basic encoding
# ============================================================


def test_encode_returns_string():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    assert isinstance(
        token,
        str,
    )


def test_encode_is_not_empty():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    assert token


def test_token_is_url_safe():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    allowed = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_"
    )

    assert all(
        char in allowed
        for char in token
    )


def test_token_contains_no_padding():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    assert "=" not in token


# ============================================================
# Round trip
# ============================================================


def test_round_trip():
    capability = make_capability()

    restored = round_trip(
        capability
    )

    assert restored.to_dict() == (
        capability.to_dict()
    )


def test_decode_returns_capability():
    capability = make_capability()

    restored = decode_capability(
        encode_capability(
            capability
        )
    )

    assert isinstance(
        restored,
        Capability,
    )


def test_signature_is_preserved():
    capability = make_capability()

    restored = round_trip(
        capability
    )

    assert (
        restored.signature
        == capability.signature
    )


def test_public_key_is_preserved():
    capability = make_capability()

    restored = round_trip(
        capability
    )

    assert (
        restored.public_key
        == capability.public_key
    )


def test_agent_is_preserved():
    capability = make_capability(
        agent="agent-a"
    )

    restored = round_trip(
        capability
    )

    assert (
        restored.agent_id
        == "agent-a"
    )


def test_scope_is_preserved():
    capability = make_capability(
        capability="payments.*"
    )

    restored = round_trip(
        capability
    )

    assert (
        restored.capability
        == "payments.*"
    )


def test_constraints_are_preserved():
    capability = make_capability(
        constraints={
            "amount_max": 100,
            "currency": "USD",
        }
    )

    restored = round_trip(
        capability
    )

    assert (
        restored.constraints
        == capability.constraints
    )


# ============================================================
# Determinism
# ============================================================


def test_encoding_is_deterministic():
    capability = make_capability()

    first = encode_capability(
        capability
    )

    second = encode_capability(
        capability
    )

    assert first == second


def test_round_trip_is_deterministic():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    assert (
        encode_capability(
            decode_capability(token)
        )
        == token
    )


# ============================================================
# Invalid input
# ============================================================


def test_encode_rejects_invalid_type():
    with pytest.raises(TypeError):
        encode_capability(
            "invalid"
        )


def test_decode_rejects_invalid_type():
    with pytest.raises(TypeError):
        decode_capability(
            123
        )


def test_decode_rejects_empty_token():
    with pytest.raises(
        TransportError
    ):
        decode_capability("")


def test_decode_rejects_bad_characters():
    with pytest.raises(
        TransportError
    ):
        decode_capability(
            "not+a+valid+token"
        )


def test_decode_rejects_random_text():
    with pytest.raises(
        TransportError
    ):
        decode_capability(
            "this-is-not-a-token"
        )


def test_decode_rejects_invalid_base64():
    with pytest.raises(
        TransportError
    ):
        decode_capability(
            "!!!"
        )


# ============================================================
# Payload tampering
# ============================================================


def test_tampering_changes_decoded_capability():
    capability = make_capability(
        capability="payments.send"
    )

    token = encode_capability(
        capability
    )

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

    tampered_raw = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode()

    tampered_token = (
        base64.urlsafe_b64encode(
            tampered_raw
        )
        .decode()
        .rstrip("=")
    )

    restored = decode_capability(
        tampered_token
    )

    assert (
        restored.capability
        == "payments.admin"
    )

    # Transport does not silently claim
    # cryptographic validity.
    sdk = make_sdk()

    assert sdk.verify(
        restored
    ) is False

def test_signature_tampering_fails_verification():
    capability = make_capability()

    token = encode_capability(
        capability
    )

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
        "signature"
    ] = "tampered"

    tampered_raw = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode()

    tampered_token = (
        base64.urlsafe_b64encode(
            tampered_raw
        )
        .decode()
        .rstrip("=")
    )

    restored = decode_capability(
        tampered_token
    )

    sdk = make_sdk()

    assert sdk.verify(
        restored
    ) is False


# ============================================================
# Versioning
# ============================================================


def test_wrong_transport_version_rejected():
    capability = make_capability()

    token = encode_capability(
        capability
    )

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

    payload["v"] = 999

    raw = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode()

    token = (
        base64.urlsafe_b64encode(
            raw
        )
        .decode()
        .rstrip("=")
    )

    with pytest.raises(
        TransportError
    ):
        decode_capability(
            token
        )


# ============================================================
# Required fields
# ============================================================


@pytest.mark.parametrize(
    "field",
    [
        "agent_id",
        "capability",
        "constraints",
        "issuer",
        "issued_at",
        "expires_at",
        "public_key",
        "signature",
    ],
)
def test_missing_required_field_rejected(
    field,
):
    capability = make_capability()

    data = capability.to_dict()
    del data[field]

    payload = {
        "v": 1,
        "capability": data,
    }

    raw = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode()

    token = (
        base64.urlsafe_b64encode(
            raw
        )
        .decode()
        .rstrip("=")
    )

    with pytest.raises(
        TransportError
    ):
        decode_capability(
            token
        )


# ============================================================
# Size limits
# ============================================================


def test_token_size_positive():
    capability = make_capability()

    assert token_size(
        capability
    ) > 0


def test_oversized_token_rejected():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    with pytest.raises(
        TransportError
    ):
        decode_capability(
            token,
            max_size=10,
        )


def test_oversized_encode_rejected():
    capability = make_capability()

    with pytest.raises(
        TransportError
    ):
        encode_capability(
            capability,
            max_size=10,
        )


def test_default_max_size_is_reasonable():
    assert DEFAULT_MAX_TOKEN_SIZE > 1024


# ============================================================
# Special / Unicode values
# ============================================================


def test_unicode_agent_round_trip():
    capability = make_capability(
        agent="agent-😀"
    )

    restored = round_trip(
        capability
    )

    assert (
        restored.agent_id
        == "agent-😀"
    )


def test_unicode_constraint_round_trip():
    capability = make_capability(
        constraints={
            "label": "païment"
        }
    )

    restored = round_trip(
        capability
    )

    assert (
        restored.constraints
        == capability.constraints
    )


# ============================================================
# Helper
# ============================================================


def test_is_transport_token_true():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    assert is_transport_token(
        token
    ) is True


def test_is_transport_token_false():
    assert is_transport_token(
        "garbage"
    ) is False


def test_is_transport_token_rejects_non_string():
    assert is_transport_token(
        None
    ) is False


# ============================================================
# SDK interoperability
# ============================================================


def test_transport_result_works_with_sdk():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.send",
    )

    token = encode_capability(
        capability
    )

    restored = decode_capability(
        token
    )

    assert sdk.verify(
        restored
    ) is True


def test_transport_authorization_works_with_sdk():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.send",
    )

    token = encode_capability(
        capability
    )

    restored = decode_capability(
        token
    )

    result = sdk.authorize(
        restored,
        "payments.send",
        {"amount": 10},
    )

    assert result.allowed is True


def test_transport_preserves_authority_boundaries():
    sdk = make_sdk()

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="payments.send",
    )

    restored = decode_capability(
        encode_capability(
            capability
        )
    )

    assert not sdk.is_authorized(
        restored,
        "payments.admin",
        {},
    )


# ============================================================
# No private-key leakage
# ============================================================


def test_transport_does_not_contain_private_key():
    capability = make_capability()

    token = encode_capability(
        capability
    )

    assert "private_key" not in token
    assert "PRIVATE" not in token