import pytest

from firewall.attenuation import (
    attenuate_capability,
    can_attenuate,
)

from firewall.capability import (
    Capability,
    CapabilityVerifier,
    generate_capability_key_pair,
    sign_capability,
)


def make_parent(
    private_key,
    **overrides,
):
    values = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "constraints": {
            "amount_max": 1000,
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


def test_same_capability_is_valid_attenuation():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = attenuate_capability(
        parent,
        private_key,
    )

    assert can_attenuate(
        parent,
        child,
    )


def test_lower_amount_limit_is_valid():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    assert child.constraints[
        "amount_max"
    ] == 100

    assert can_attenuate(
        parent,
        child,
    )


def test_higher_amount_limit_is_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    with pytest.raises(ValueError):
        attenuate_capability(
            parent,
            private_key,
            constraints={
                "amount_max": 1000,
            },
        )


def test_expiry_can_be_shortened():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = attenuate_capability(
        parent,
        private_key,
        expires_at=1500,
    )

    assert child.expires_at == 1500

    assert can_attenuate(
        parent,
        child,
    )


def test_expiry_cannot_be_extended():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    with pytest.raises(ValueError):
        attenuate_capability(
            parent,
            private_key,
            expires_at=3000,
        )


def test_different_agent_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = Capability(
        **{
            **parent.to_dict(),
            "agent_id": "attacker",
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_different_issuer_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = Capability(
        **{
            **parent.to_dict(),
            "issuer": "evil-issuer",
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_different_public_key_rejected():
    private_key, _ = generate_capability_key_pair()
    other_private_key, _ = (
        generate_capability_key_pair()
    )

    parent = make_parent(private_key)

    child = make_parent(
        other_private_key
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_different_capability_scope_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        capability="payments.send",
    )

    child = Capability(
        **{
            **parent.to_dict(),
            "capability": "payments.admin",
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_removed_constraint_is_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    child = Capability(
        **{
            **parent.to_dict(),
            "constraints": {
                "amount_max": 100,
            },
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_added_constraint_is_allowed():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    assert can_attenuate(
        parent,
        child,
    )


def test_multiple_constraints_can_be_narrowed():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
            "currency": "USD",
        },
    )

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
            "recipient": "merchant",
        },
    )

    assert can_attenuate(
        parent,
        child,
    )


def test_invalid_parent_is_rejected():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(TypeError):
        attenuate_capability(
            "not-a-capability",
            private_key,
        )


def test_child_is_signed():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verifier.verify(
        child
    ) is True


def test_child_signature_cannot_be_tampered():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    tampered = Capability(
        **{
            **child.to_dict(),
            "constraints": {
                "amount_max": 10000,
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


def test_attenuation_can_be_chained():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
        },
    )

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 500,
        },
    )

    grandchild = attenuate_capability(
        child,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    assert can_attenuate(
        parent,
        child,
    )

    assert can_attenuate(
        child,
        grandchild,
    )

    assert can_attenuate(
        parent,
        grandchild,
    )


def test_grandchild_cannot_escalate():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
        },
    )

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 500,
        },
    )

    with pytest.raises(ValueError):
        attenuate_capability(
            child,
            private_key,
            constraints={
                "amount_max": 900,
            },
        )


def test_child_cannot_start_before_parent():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        issued_at=1500,
        expires_at=2000,
    )

    child = Capability(
        **{
            **parent.to_dict(),
            "issued_at": 1000,
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_child_can_start_at_same_time():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        issued_at=1000,
        expires_at=2000,
    )

    child = Capability(
        **{
            **parent.to_dict(),
            "issued_at": 1000,
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is True


def test_child_cannot_outlive_parent():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        expires_at=2000,
    )

    child = Capability(
        **{
            **parent.to_dict(),
            "expires_at": 3000,
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is False


def test_child_can_expire_at_same_time():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        expires_at=2000,
    )

    child = Capability(
        **{
            **parent.to_dict(),
            "expires_at": 2000,
        }
    )

    assert can_attenuate(
        parent,
        child,
    ) is True