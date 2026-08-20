import pytest

from firewall.engine import Firewall


def make_policy(tmp_path, rules):
    policy_file = tmp_path / "policies.yaml"

    import yaml

    policy_file.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return policy_file


def test_null_rule_is_rejected(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [None],
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_tool_list_is_rejected(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [
            {
                "tool": ["payments.send"],
                "action": "deny",
            }
        ],
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_action_list_is_rejected(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": ["deny"],
            }
        ],
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_arguments_must_be_dictionary(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "arguments": ["production"],
                "action": "deny",
            }
        ],
    )

    fw = Firewall(str(policy_file))

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {"environment": "production"},
    )

    assert result.action == "deny"


def test_amount_threshold_string_is_rejected(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "amount_gte": "1000",
                "action": "deny",
            }
        ],
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_amount_threshold_boolean_is_rejected(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "amount_gte": True,
                "action": "deny",
            }
        ],
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_amount_gt_boolean_is_rejected(tmp_path):
    policy_file = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "amount_gt": True,
                "action": "deny",
            }
        ],
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))