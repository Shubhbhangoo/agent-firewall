import yaml

from firewall.engine import Firewall


def make_firewall(tmp_path, rules):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return Firewall(str(policy_file))


def test_identity_and_amount_must_both_match(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 100,
                "action": "approval",
            }
        ],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "approval"


def test_correct_agent_wrong_amount_does_not_match(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 100,
                "action": "approval",
            }
        ],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "deny"


def test_wrong_agent_correct_amount_does_not_match(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 100,
                "action": "approval",
            }
        ],
    )

    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "deny"


def test_identity_specific_deny_beats_identity_specific_approval(
    tmp_path,
):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 100,
                "action": "approval",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 500,
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "deny"


def test_identity_specific_rule_does_not_affect_other_agent(
    tmp_path,
):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 100,
                "action": "approval",
            },
            {
                "tool": "payments.send",
                "action": "allow",
            },
        ],
    )

    result = fw.check(
        "other-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "allow"


def test_identity_and_path_conditions_can_combine(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "github.delete_file",
                "agent": "trusted-agent",
                "path": "production.env",
                "action": "deny",
            }
        ],
    )

    result = fw.check(
        "trusted-agent",
        "github.delete_file",
        {"path": "production.env"},
    )

    assert result.action == "deny"


def test_wrong_path_does_not_match_identity_path_rule(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "github.delete_file",
                "agent": "trusted-agent",
                "path": "production.env",
                "action": "deny",
            }
        ],
    )

    result = fw.check(
        "trusted-agent",
        "github.delete_file",
        {"path": "README.md"},
    )

    assert result.action == "deny"