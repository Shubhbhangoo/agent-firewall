from __future__ import annotations

from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("key-1")
    return sdk


def test_real_capability_and_policy():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "and": [
                {
                    "currency": {
                        "eq": "USD",
                    }
                },
                {
                    "amount": {
                        "lte": 100,
                    }
                },
            ]
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "currency": "USD",
            "amount": 50,
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "currency": "USD",
            "amount": 150,
        },
    ) is False


def test_real_capability_or_policy():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "or": [
                {
                    "region": {
                        "eq": "us-east",
                    }
                },
                {
                    "region": {
                        "eq": "us-west",
                    }
                },
            ]
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "region": "us-east",
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "region": "eu-west",
        },
    ) is False


def test_real_capability_not_policy():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "not": {
                "environment": {
                    "eq": "sandbox",
                }
            }
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "environment": "production",
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "environment": "sandbox",
        },
    ) is False


def test_real_capability_nested_composition():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "and": [
                {
                    "or": [
                        {
                            "region": {
                                "eq": "us-east",
                            }
                        },
                        {
                            "region": {
                                "eq": "us-west",
                            }
                        },
                    ]
                },
                {
                    "not": {
                        "environment": {
                            "eq": "sandbox",
                        }
                    }
                },
            ]
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "region": "us-east",
            "environment": "production",
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "region": "us-east",
            "environment": "sandbox",
        },
    ) is False

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "region": "eu-west",
            "environment": "production",
        },
    ) is False


def test_legacy_constraints_still_work():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "amount": 50,
            "currency": "USD",
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "amount": 150,
            "currency": "USD",
        },
    ) is False


def test_policy_denial_remains_constraint_denied():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 101,
        },
    )

    assert result.allowed is False
    assert result.reason == "constraint_denied"