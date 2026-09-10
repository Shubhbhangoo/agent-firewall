import pytest

from firewall.authorization import (
    AuthorizationResult,
    authorize,
    is_authorized,
)

from firewall.capability import (
    Capability,
    CapabilityVerifier,
    generate_capability_key_pair,
    sign_capability,
)

from firewall.delegation import (
    delegate_capability,
    verify_delegation,
)


def make_keys():
    return generate_capability_key_pair()


def make_capability(
    private_key,
    **overrides,
):
    values = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "constraints": {},
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
        clock=lambda: 1500,
    )


def test_exact_capability_authorizes():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    result = authorize(
        capability,
        "payments.send",
    )

    assert result.allowed is True
    assert result.reason == "authorized"


def test_wrong_capability_is_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    result = authorize(
        capability,
        "payments.refund",
    )

    assert result.allowed is False
    assert result.reason == "namespace_denied"


def test_wildcard_capability_authorizes_child():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    result = authorize(
        capability,
        "payments.send",
    )

    assert result.allowed is True


def test_wildcard_does_not_authorize_other_root():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    result = authorize(
        capability,
        "accounts.read",
    )

    assert result.allowed is False


def test_constraint_allows_valid_request():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    result = authorize(
        capability,
        "payments.send",
        {"amount": 50},
    )

    assert result.allowed is True


def test_constraint_denies_excess_amount():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    result = authorize(
        capability,
        "payments.send",
        {"amount": 101},
    )

    assert result.allowed is False
    assert result.reason == "constraint_denied"


def test_missing_constraint_value_is_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    result = authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False


def test_currency_constraint():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "currency": "USD",
        },
    )

    assert is_authorized(
        capability,
        "payments.send",
        {"currency": "USD"},
    )

    assert not is_authorized(
        capability,
        "payments.send",
        {"currency": "EUR"},
    )


def test_multiple_constraints():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    assert is_authorized(
        capability,
        "payments.send",
        {
            "amount": 50,
            "currency": "USD",
        },
    )

    assert not is_authorized(
        capability,
        "payments.send",
        {
            "amount": 50,
            "currency": "EUR",
        },
    )


def test_nested_constraints():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "payment": {
                "amount_max": 100,
            },
        },
    )

    assert is_authorized(
        capability,
        "payments.send",
        {
            "payment": {
                "amount": 50,
            }
        },
    )


def test_nested_constraint_rejects_excess():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        constraints={
            "payment": {
                "amount_max": 100,
            },
        },
    )

    assert not is_authorized(
        capability,
        "payments.send",
        {
            "payment": {
                "amount": 101,
            }
        },
    )


def test_expired_capability_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        expires_at=1400,
    )

    result = authorize(
        capability,
        "payments.send",
        verifier=make_verifier(),
        clock=lambda: 1500,
    )

    assert result.allowed is False
    assert result.reason == "expired"


def test_not_yet_valid_capability_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        issued_at=2000,
        expires_at=3000,
    )

    result = authorize(
        capability,
        "payments.send",
        clock=lambda: 1500,
    )

    assert result.allowed is False
    assert result.reason == "not_yet_valid"


def test_valid_time_window_allows():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        issued_at=1000,
        expires_at=2000,
    )

    assert is_authorized(
        capability,
        "payments.send",
        clock=lambda: 1500,
    )


def test_signature_verification_allows_valid_capability():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
    )

    result = authorize(
        capability,
        "payments.send",
        verifier=make_verifier(),
    )

    assert result.allowed is True


def test_tampered_capability_is_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.admin",
        }
    )

    result = authorize(
        tampered,
        "payments.admin",
        verifier=make_verifier(),
    )

    assert result.allowed is False
    assert result.reason == "invalid_signature"


def test_wrong_issuer_is_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        issuer="evil-issuer",
    )

    result = authorize(
        capability,
        "payments.send",
        verifier=make_verifier(),
    )

    assert result.allowed is False


def test_invalid_capability_object_denied():
    result = authorize(
        "not-a-capability",
        "payments.send",
    )

    assert result.allowed is False
    assert result.reason == "invalid_capability"


def test_invalid_request_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
    )

    result = authorize(
        capability,
        "payments.send",
        request=[],
    )

    assert result.allowed is False
    assert result.reason == "invalid_request"


def test_invalid_action_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    result = authorize(
        capability,
        "payments..send",
    )

    assert result.allowed is False


def test_empty_action_denied():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    result = authorize(
        capability,
        "",
    )

    assert result.allowed is False


def test_specific_permission_cannot_escalate():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    assert not is_authorized(
        capability,
        "payments.admin",
    )


def test_payments_capability_cannot_access_accounts():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    assert not is_authorized(
        capability,
        "accounts.delete",
    )


def test_attenuated_capability_authorizes_narrow_action():
    private_key, _ = make_keys()

    parent = make_capability(
        private_key,
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    from firewall.attenuation import attenuate_capability

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    assert is_authorized(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert not is_authorized(
        child,
        "payments.send",
        {"amount": 101},
    )


def test_delegated_capability_authorizes_delegatee():
    private_key, _ = make_keys()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
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

    assert delegation.child.agent_id == "agent-b"

    assert is_authorized(
        delegation.child,
        "payments.send",
        {"amount": 50},
    )


def test_delegated_capability_cannot_exceed_constraint():
    private_key, _ = make_keys()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
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

    assert not is_authorized(
        delegation.child,
        "payments.send",
        {"amount": 101},
    )


def test_delegation_verification():
    private_key, _ = make_keys()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert verify_delegation(
        delegation,
        make_verifier(),
    )


def test_expired_delegated_capability_denied():
    private_key, _ = make_keys()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
        expires_at=2000,
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        expires_at=1400,
    )

    result = authorize(
        delegation.child,
        "payments.send",
        clock=lambda: 1500,
    )

    assert result.allowed is False
    assert result.reason == "expired"


def test_delegated_namespace_cannot_escalate():
    private_key, _ = make_keys()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.send",
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    assert not is_authorized(
        delegation.child,
        "payments.admin",
    )


def test_result_is_boolean_compatible():
    private_key, _ = make_keys()

    capability = make_capability(
        private_key,
    )

    result = authorize(
        capability,
        "payments.send",
    )

    assert isinstance(
        result,
        AuthorizationResult,
    )

    assert bool(result) is True