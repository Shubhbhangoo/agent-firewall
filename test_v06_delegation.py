import pytest

from firewall.capability import (
    Capability,
    CapabilityVerifier,
    generate_capability_key_pair,
    sign_capability,
)

from firewall.delegation import (
    Delegation,
    can_delegate,
    delegate_capability,
    verify_delegation,
)


def make_parent(
    private_key,
    **overrides,
):
    values = {
        "agent_id": "agent-a",
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


def make_verifier():
    return CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1400,
    )


def test_valid_delegation():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
        },
        expires_at=1500,
    )

    assert isinstance(
        delegation,
        Delegation,
    )

    assert delegation.parent == parent
    assert delegation.child.agent_id == "agent-b"


def test_delegation_is_valid():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
        },
        expires_at=1500,
    )

    assert delegation.is_valid() is True


def test_delegated_capability_verifies():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
        },
        expires_at=1500,
    )

    verifier = make_verifier()

    assert verifier.verify(
        delegation.child
    ) is True


def test_parent_must_be_capability():
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(TypeError):
        delegate_capability(
            "invalid",
            private_key,
            "agent-b",
        )


def test_empty_delegatee_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    with pytest.raises(ValueError):
        delegate_capability(
            parent,
            private_key,
            "",
        )


def test_same_agent_delegatee_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    with pytest.raises(ValueError):
        delegate_capability(
            parent,
            private_key,
            "agent-a",
        )


def test_delegatee_is_bound_to_child():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert (
        delegation.child.agent_id
        == "agent-b"
    )

    assert (
        delegation.delegatee
        == "agent-b"
    )


def test_delegation_cannot_extend_expiry():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        expires_at=2000,
    )

    with pytest.raises(ValueError):
        delegate_capability(
            parent,
            private_key,
            "agent-b",
            expires_at=3000,
        )


def test_delegation_can_shorten_expiry():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        expires_at=2000,
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        expires_at=1500,
    )

    assert delegation.child.expires_at == 1500


def test_delegation_cannot_increase_amount():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    with pytest.raises(ValueError):
        delegate_capability(
            parent,
            private_key,
            "agent-b",
            constraints={
                "amount_max": 1000,
            },
        )


def test_delegation_can_reduce_amount():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
        },
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
        },
    )

    assert (
        delegation.child.constraints["amount_max"]
        == 100
    )


def test_delegation_can_add_restrictive_constraint():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
        },
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    assert (
        delegation.child.constraints["currency"]
        == "USD"
    )


def test_delegation_cannot_remove_constraint():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
            "currency": "USD",
        },
    )

    with pytest.raises(ValueError):
        delegate_capability(
            parent,
            private_key,
            "agent-b",
            constraints={
                "amount_max": 1000,
            },
        )


def test_delegation_preserves_capability_scope():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert (
        delegation.child.capability
        == parent.capability
    )


def test_delegation_cannot_change_scope():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = Capability(
        **{
            **parent.to_dict(),
            "agent_id": "agent-b",
            "capability": "payments.admin",
        }
    )

    delegation = Delegation(
        parent=parent,
        child=child,
        delegator="agent-a",
        delegatee="agent-b",
    )

    assert delegation.is_valid() is False


def test_delegation_preserves_issuer():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert (
        delegation.child.issuer
        == parent.issuer
    )


def test_delegation_cannot_change_issuer():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = Capability(
        **{
            **parent.to_dict(),
            "agent_id": "agent-b",
            "issuer": "evil-issuer",
        }
    )

    delegation = Delegation(
        parent=parent,
        child=child,
        delegator="agent-a",
        delegatee="agent-b",
    )

    assert delegation.is_valid() is False


def test_wrong_delegator_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = delegate_capability(
        parent,
        private_key,
        "agent-b",
    ).child

    delegation = Delegation(
        parent=parent,
        child=child,
        delegator="attacker",
        delegatee="agent-b",
    )

    assert delegation.is_valid() is False


def test_wrong_delegatee_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    child = delegate_capability(
        parent,
        private_key,
        "agent-b",
    ).child

    delegation = Delegation(
        parent=parent,
        child=child,
        delegator="agent-a",
        delegatee="attacker",
    )

    assert delegation.is_valid() is False


def test_parent_signature_is_verified():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert verify_delegation(
        delegation,
        make_verifier(),
    ) is True


def test_tampered_parent_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    tampered_parent = Capability(
        **{
            **parent.to_dict(),
            "capability": "payments.admin",
        }
    )

    tampered = Delegation(
        parent=tampered_parent,
        child=delegation.child,
        delegator="agent-a",
        delegatee="agent-b",
    )

    assert verify_delegation(
        tampered,
        make_verifier(),
    ) is False


def test_tampered_child_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    tampered_child = Capability(
        **{
            **delegation.child.to_dict(),
            "constraints": {
                "amount_max": 999999,
            },
        }
    )

    tampered = Delegation(
        parent=parent,
        child=tampered_child,
        delegator="agent-a",
        delegatee="agent-b",
    )

    assert verify_delegation(
        tampered,
        make_verifier(),
    ) is False


def test_delegation_cannot_be_used_by_attacker():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    forged = Capability(
        **{
            **delegation.child.to_dict(),
            "agent_id": "attacker",
        }
    )

    tampered = Delegation(
        parent=parent,
        child=forged,
        delegator="agent-a",
        delegatee="agent-b",
    )

    assert tampered.is_valid() is False


def test_delegation_chain_can_be_created():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
        },
    )

    first = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 500,
        },
    )

    second = delegate_capability(
        first.child,
        private_key,
        "agent-c",
        constraints={
            "amount_max": 100,
        },
    )

    assert second.child.agent_id == "agent-c"
    assert (
        second.child.constraints["amount_max"]
        == 100
    )


def test_delegation_chain_cannot_escalate():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        constraints={
            "amount_max": 1000,
        },
    )

    first = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 500,
        },
    )

    with pytest.raises(ValueError):
        delegate_capability(
            first.child,
            private_key,
            "agent-c",
            constraints={
                "amount_max": 900,
            },
        )


def test_can_delegate_accepts_capability():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    assert can_delegate(parent) is True


def test_can_delegate_rejects_invalid_object():
    assert can_delegate(None) is False


def test_delegation_is_bound_to_parent_agent():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert delegation.delegator == "agent-a"
    assert delegation.parent.agent_id == "agent-a"


def test_child_is_not_parent():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert delegation.child != delegation.parent


def test_delegation_has_independent_signature():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(private_key)

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert (
        delegation.child.signature
        != parent.signature
    )


def test_expired_delegation_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_parent(
        private_key,
        expires_at=1500,
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        expires_at=1500,
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: 1500,
    )

    assert verify_delegation(
        delegation,
        verifier,
    ) is False