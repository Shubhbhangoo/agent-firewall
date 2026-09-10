from __future__ import annotations

import pytest

from firewall.policy import (
    PolicyDefinitionError,
    evaluate_policy,
)


def test_eq():
    result = evaluate_policy(
        {
            "currency": {
                "eq": "USD",
            },
        },
        {
            "currency": "USD",
        },
    )

    assert result.allowed is True
    assert result.reason == "authorized"


def test_eq_denied():
    result = evaluate_policy(
        {
            "currency": {
                "eq": "USD",
            },
        },
        {
            "currency": "EUR",
        },
    )

    assert result.allowed is False
    assert result.reason == "policy_denied"
    assert result.key == "currency"
    assert result.operator == "eq"


def test_neq():
    result = evaluate_policy(
        {
            "environment": {
                "neq": "sandbox",
            },
        },
        {
            "environment": "production",
        },
    )

    assert result.allowed is True


def test_neq_denied():
    result = evaluate_policy(
        {
            "environment": {
                "neq": "sandbox",
            },
        },
        {
            "environment": "sandbox",
        },
    )

    assert result.allowed is False


def test_in():
    result = evaluate_policy(
        {
            "region": {
                "in": [
                    "us-east",
                    "us-west",
                ],
            },
        },
        {
            "region": "us-east",
        },
    )

    assert result.allowed is True


def test_in_denied():
    result = evaluate_policy(
        {
            "region": {
                "in": [
                    "us-east",
                    "us-west",
                ],
            },
        },
        {
            "region": "eu-west",
        },
    )

    assert result.allowed is False


def test_not_in():
    result = evaluate_policy(
        {
            "region": {
                "not_in": [
                    "blocked",
                    "unknown",
                ],
            },
        },
        {
            "region": "us-east",
        },
    )

    assert result.allowed is True


def test_not_in_denied():
    result = evaluate_policy(
        {
            "region": {
                "not_in": [
                    "blocked",
                    "unknown",
                ],
            },
        },
        {
            "region": "blocked",
        },
    )

    assert result.allowed is False


def test_gte():
    result = evaluate_policy(
        {
            "amount": {
                "gte": 10,
            },
        },
        {
            "amount": 25,
        },
    )

    assert result.allowed is True


def test_gte_denied():
    result = evaluate_policy(
        {
            "amount": {
                "gte": 10,
            },
        },
        {
            "amount": 5,
        },
    )

    assert result.allowed is False


def test_lte():
    result = evaluate_policy(
        {
            "amount": {
                "lte": 100,
            },
        },
        {
            "amount": 75,
        },
    )

    assert result.allowed is True


def test_lte_denied():
    result = evaluate_policy(
        {
            "amount": {
                "lte": 100,
            },
        },
        {
            "amount": 125,
        },
    )

    assert result.allowed is False


def test_multiple_operators_are_anded():
    result = evaluate_policy(
        {
            "amount": {
                "gte": 10,
                "lte": 100,
            },
        },
        {
            "amount": 50,
        },
    )

    assert result.allowed is True


def test_multiple_operators_fail_when_one_fails():
    result = evaluate_policy(
        {
            "amount": {
                "gte": 10,
                "lte": 100,
            },
        },
        {
            "amount": 150,
        },
    )

    assert result.allowed is False


def test_contains():
    result = evaluate_policy(
        {
            "scopes": {
                "contains": "payments",
            },
        },
        {
            "scopes": [
                "payments",
                "read",
            ],
        },
    )

    assert result.allowed is True


def test_contains_denied():
    result = evaluate_policy(
        {
            "scopes": {
                "contains": "admin",
            },
        },
        {
            "scopes": [
                "payments",
                "read",
            ],
        },
    )

    assert result.allowed is False


def test_missing_field_denied():
    result = evaluate_policy(
        {
            "currency": {
                "eq": "USD",
            },
        },
        {},
    )

    assert result.allowed is False
    assert result.reason == "policy_denied"


def test_nested_policy():
    result = evaluate_policy(
        {
            "payment": {
                "currency": {
                    "eq": "USD",
                },
                "amount": {
                    "lte": 100,
                },
            },
        },
        {
            "payment": {
                "currency": "USD",
                "amount": 50,
            },
        },
    )

    assert result.allowed is True


def test_nested_policy_denied():
    result = evaluate_policy(
        {
            "payment": {
                "currency": {
                    "eq": "USD",
                },
                "amount": {
                    "lte": 100,
                },
            },
        },
        {
            "payment": {
                "currency": "USD",
                "amount": 200,
            },
        },
    )

    assert result.allowed is False


def test_literal_value_remains_supported():
    result = evaluate_policy(
        {
            "currency": "USD",
        },
        {
            "currency": "USD",
        },
    )

    assert result.allowed is True


def test_literal_value_denied():
    result = evaluate_policy(
        {
            "currency": "USD",
        },
        {
            "currency": "EUR",
        },
    )

    assert result.allowed is False


def test_unknown_mapping_is_treated_as_nested_policy():
    result = evaluate_policy(
        {
            "payment": {
                "method": {
                    "between": [
                        "card",
                        "cash",
                    ],
                },
            },
        },
        {
            "payment": {
                "method": {
                    "between": [
                        "card",
                        "cash",
                    ],
                },
            },
        },
    )

    assert result.allowed is True


def test_empty_policy_allows():
    result = evaluate_policy(
        {},
        {},
    )

    assert result.allowed is True


def test_policy_must_be_mapping():
    with pytest.raises(
        PolicyDefinitionError,
        match="policy must be a mapping",
    ):
        evaluate_policy(
            [],
            {},
        )


def test_invalid_request_is_denied():
    result = evaluate_policy(
        {
            "currency": {
                "eq": "USD",
            },
        },
        [],
    )

    assert result.allowed is False
    assert result.reason == "invalid_request"