import pytest

from firewall.engine import Firewall


def test_policy_file_must_contain_rules(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
foo: bar
""",
        encoding="utf-8",
    )

    fw = Firewall(str(policy_file))

    assert fw.rules == []


def test_rules_must_be_a_list(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  tool: test.tool
  action: allow
""",
        encoding="utf-8",
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_rule_must_be_a_dictionary(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - "not a rule"
""",
        encoding="utf-8",
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_rule_requires_tool(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - action: allow
""",
        encoding="utf-8",
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_invalid_action_is_rejected(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: explode
""",
        encoding="utf-8",
    )

    with pytest.raises((TypeError, ValueError)):
        Firewall(str(policy_file))


def test_empty_rules_are_allowed(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules: []
""",
        encoding="utf-8",
    )

    fw = Firewall(str(policy_file))

    assert fw.rules == []