from __future__ import annotations

from firewall.authorization import (
    authorize,
)
from firewall.capability import (
    sign_capability,
)
from firewall.sdk import (
    FirewallSDK,
)


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("key-1")
    return sdk


def test_eq_policy_is_enforced():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "currency": {
                "eq": "USD",
            },
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "currency": "USD",
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "currency": "EUR",
        },
    ) is False


def test_numeric_policy_is_enforced():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "gte": 10,
                "lte": 100,
            },
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "amount": 50,
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "amount": 150,
        },
    ) is False


def test_membership_policy_is_enforced():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "region": {
                "in": [
                    "us-east",
                    "us-west",
                ],
            },
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


def test_nested_policy_is_enforced():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "payment": {
                "currency": {
                    "eq": "USD",
                },
                "amount": {
                    "lte": 100,
                },
            },
        },
    )

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "payment": {
                "currency": "USD",
                "amount": 50,
            },
        },
    ) is True

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {
            "payment": {
                "currency": "USD",
                "amount": 200,
            },
        },
    ) is False


def test_existing_v1_constraints_still_work():
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