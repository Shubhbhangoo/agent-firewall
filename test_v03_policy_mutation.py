from firewall.engine import Firewall


def test_runtime_rule_mutation_can_change_decision():
    fw = Firewall()

    original = fw.check(
        "test-agent",
        "github.read_file",
        {"path": "README.md"},
    )

    assert original.action == "allow"

    fw.rules.clear()

    result = fw.check(
        "attacker-agent",
        "github.read_file",
        {"path": "README.md"},
    )

    assert result.action == "deny"


def test_runtime_rule_append_is_observed():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "action": "allow",
    })

    result = fw.check(
        "test-agent",
        "test.tool",
        {},
    )

    assert result.action == "allow"


def test_runtime_rule_can_override_existing_policy():
    fw = Firewall()

    fw.rules.append({
        "tool": "github.read_file",
        "action": "deny",
    })

    result = fw.check(
        "test-agent",
        "github.read_file",
        {"path": "README.md"},
    )

    assert result.action == "deny"