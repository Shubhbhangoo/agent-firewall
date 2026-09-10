import yaml

from firewall.engine import Firewall


def make_firewall(tmp_path, rules):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return Firewall(str(policy_file))


def test_deny_beats_allow(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "allow",
            },
            {
                "tool": "test.tool",
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_approval_beats_allow(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "allow",
            },
            {
                "tool": "test.tool",
                "action": "approval",
            },
        ],
    )

    result = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert result.action == "approval"


def test_deny_beats_approval(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "approval",
            },
            {
                "tool": "test.tool",
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_specific_deny_beats_general_allow(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "allow",
            },
            {
                "tool": "test.tool",
                "arguments": {
                    "environment": "production",
                },
                "action": "deny",
            },
        ],
    )

    result = fw.check(
        "test-agent",
        "test.tool",
        {
            "environment": "production",
        },
    )

    assert result.action == "deny"


def test_specific_allow_does_not_override_general_deny(tmp_path):
    fw = make_firewall(
        tmp_path,
        [
            {
                "tool": "test.tool",
                "action": "deny",
            },
            {
                "tool": "test.tool",
                "arguments": {
                    "environment": "development",
                },
                "action": "allow",
            },
        ],
    )

    result = fw.check(
        "test-agent",
        "test.tool",
        {
            "environment": "development",
        },
    )

    assert result.action == "deny"