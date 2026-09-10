import yaml

from firewall.engine import Firewall


def make_firewall(tmp_path, rules):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return Firewall(str(policy_file))


def test_specific_deny_beats_general_allow(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "github.delete_file",
                "action": "allow",
            },
            {
                "tool": "github.delete_file",
                "agent": "attacker-agent",
                "path": "production.env",
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "attacker-agent",
        "github.delete_file",
        {"path": "production.env"},
    )

    assert result.action == "deny"


def test_specific_approval_beats_general_allow(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "amount_gte": 100,
                "action": "approval",
            },
        ],
    )

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "approval"


def test_specific_rule_does_not_affect_unmatched_request(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "github.delete_file",
                "action": "allow",
            },
            {
                "tool": "github.delete_file",
                "agent": "attacker-agent",
                "path": "production.env",
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "trusted-agent",
        "github.delete_file",
        {"path": "README.md"},
    )

    assert result.action == "allow"


def test_more_specific_deny_beats_less_specific_deny_allow_mix(
    tmp_path,
):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "allow",
            },
            {
                "tool": "test.tool",
                "agent": "trusted-agent",
                "action": "deny",
            },
            {
                "tool": "test.tool",
                "agent": "trusted-agent",
                "arguments": {
                    "environment": "production",
                },
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {"environment": "production"},
    )

    assert result.action == "deny"


def test_specific_rule_does_not_match_partial_arguments(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "allow",
            },
            {
                "tool": "test.tool",
                "agent": "trusted-agent",
                "arguments": {
                    "environment": "production",
                    "mode": "destructive",
                },
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {
            "environment": "production",
            "mode": "safe",
        },
    )

    assert result.action == "allow"