from firewall.engine import Firewall


def test_policy_changes_on_disk_do_not_automatically_change_loaded_rules(
    tmp_path,
):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow
""",
        encoding="utf-8",
    )

    fw = Firewall(str(policy_file))

    first = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert first.action == "allow"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: deny
""",
        encoding="utf-8",
    )

    second = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert second.action == "allow"


def test_new_firewall_instance_loads_updated_policy(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow
""",
        encoding="utf-8",
    )

    fw1 = Firewall(str(policy_file))

    assert fw1.check(
        "test-agent",
        "test.tool",
        {},
    ).action == "allow"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: deny
""",
        encoding="utf-8",
    )

    fw2 = Firewall(str(policy_file))

    assert fw2.check(
        "test-agent",
        "test.tool",
        {},
    ).action == "deny"


def test_partial_policy_file_does_not_modify_loaded_rules(
    tmp_path,
):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    action: allow
""",
        encoding="utf-8",
    )

    fw = Firewall(str(policy_file))

    policy_file.write_text(
        """
rules:
""",
        encoding="utf-8",
    )

    result = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert result.action == "allow"