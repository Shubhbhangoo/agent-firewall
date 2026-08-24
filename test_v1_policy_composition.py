from __future__ import annotations

import pytest

from firewall.policy import (
    PolicyDefinitionError,
    evaluate_policy,
)


def test_and_allows_when_all_rules_pass():
    result = evaluate_policy(
        {
            "and": [
                {"currency": {"eq": "USD"}},
                {"amount": {"lte": 100}},
            ],
        },
        {
            "currency": "USD",
            "amount": 50,
        },
    )

    assert result.allowed is True


def test_and_denies_when_one_rule_fails():
    result = evaluate_policy(
        {
            "and": [
                {"currency": {"eq": "USD"}},
                {"amount": {"lte": 100}},
            ],
        },
        {
            "currency": "USD",
            "amount": 150,
        },
    )

    assert result.allowed is False
    assert result.reason == "policy_denied"


def test_or_allows_when_one_rule_passes():
    result = evaluate_policy(
        {
            "or": [
                {"region": {"eq": "us-east"}},
                {"region": {"eq": "us-west"}},
            ],
        },
        {
            "region": "us-west",
        },
    )

    assert result.allowed is True


def test_or_denies_when_all_rules_fail():
    result = evaluate_policy(
        {
            "or": [
                {"region": {"eq": "us-east"}},
                {"region": {"eq": "us-west"}},
            ],
        },
        {
            "region": "eu-west",
        },
    )

    assert result.allowed is False


def test_not_inverts_success():
    result = evaluate_policy(
        {
            "not": {
                "environment": {
                    "eq": "sandbox",
                },
            },
        },
        {
            "environment": "production",
        },
    )

    assert result.allowed is True


def test_not_inverts_failure():
    result = evaluate_policy(
        {
            "not": {
                "environment": {
                    "eq": "sandbox",
                },
            },
        },
        {
            "environment": "sandbox",
        },
    )

    assert result.allowed is False


def test_nested_composition():
    result = evaluate_policy(
        {
            "and": [
                {
                    "or": [
                        {"region": {"eq": "us-east"}},
                        {"region": {"eq": "us-west"}},
                    ]
                },
                {
                    "not": {
                        "environment": {
                            "eq": "sandbox"
                        }
                    }
                },
            ],
        },
        {
            "region": "us-east",
            "environment": "production",
        },
    )

    assert result.allowed is True


def test_nested_composition_denies():
    result = evaluate_policy(
        {
            "and": [
                {
                    "or": [
                        {"region": {"eq": "us-east"}},
                        {"region": {"eq": "us-west"}},
                    ]
                },
                {
                    "not": {
                        "environment": {
                            "eq": "sandbox"
                        }
                    }
                },
            ],
        },
        {
            "region": "us-east",
            "environment": "sandbox",
        },
    )

    assert result.allowed is False


def test_and_requires_list():
    with pytest.raises(
        PolicyDefinitionError,
        match="and",
    ):
        evaluate_policy(
            {
                "and": {
                    "currency": {"eq": "USD"}
                }
            },
            {
                "currency": "USD"
            },
        )


def test_or_requires_list():
    with pytest.raises(
        PolicyDefinitionError,
        match="or",
    ):
        evaluate_policy(
            {
                "or": {
                    "currency": {"eq": "USD"}
                }
            },
            {
                "currency": "USD"
            },
        )


def test_not_requires_single_mapping():
    with pytest.raises(
        PolicyDefinitionError,
        match="not",
    ):
        evaluate_policy(
            {
                "not": [
                    {"currency": {"eq": "USD"}}
                ]
            },
            {
                "currency": "USD"
            },
        )


def test_empty_and_allows():
    result = evaluate_policy(
        {"and": []},
        {},
    )

    assert result.allowed is True


def test_empty_or_denies():
    result = evaluate_policy(
        {"or": []},
        {},
    )

    assert result.allowed is False


def test_invalid_composition_operator():
    with pytest.raises(
        PolicyDefinitionError
    ):
        evaluate_policy(
            {
                "xor": [
                    {"currency": {"eq": "USD"}},
                    {"currency": {"eq": "EUR"}},
                ]
            },
            {
                "currency": "USD"
            },
        )