import yaml

from firewall.engine import Firewall


def make_firewall(tmp_path, rules):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return Firewall(str(policy_file))


def test_string_does_not_match_numeric_amount(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        }],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": "500"},
    )

    assert result.action == "deny"


def test_boolean_does_not_match_numeric_amount(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        }],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": True},
    )

    assert result.action == "deny"


def test_list_does_not_match_numeric_amount(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        }],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": [500]},
    )

    assert result.action == "deny"


def test_dictionary_does_not_match_numeric_amount(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        }],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": {"value": 500}},
    )

    assert result.action == "deny"


def test_nan_does_not_match_amount_rule(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        }],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": float("nan")},
    )

    assert result.action == "deny"


def test_infinity_does_not_match_amount_rule(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        }],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": float("inf")},
    )

    assert result.action == "deny"


def test_nested_argument_does_not_match_flat_argument(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "test.tool",
            "arguments": {
                "environment": "production",
            },
            "action": "deny",
        }],
    )

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {
            "environment": {
                "value": "production",
            }
        },
    )

    assert result.action == "deny"


def test_list_argument_does_not_match_scalar_argument(tmp_path):
    fw = make_firewall(
        tmp_path,
        [{
            "tool": "test.tool",
            "arguments": {
                "environment": "production",
            },
            "action": "deny",
        }],
    )

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {
            "environment": ["production"],
        },
    )

    assert result.action == "deny"