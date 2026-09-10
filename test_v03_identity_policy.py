from firewall.engine import Firewall


def test_identity_is_available_to_firewall():
    fw = Firewall()

    result = fw.check(
        "trusted-agent",
        "github.read_file",
        {"path": "README.md"},
    )

    assert result.action == "allow"


def test_different_agents_currently_get_same_tool_decision():
    fw = Firewall()

    trusted = fw.check(
        "trusted-agent",
        "github.read_file",
        {"path": "README.md"},
    )

    attacker = fw.check(
        "attacker-agent",
        "github.read_file",
        {"path": "README.md"},
    )

    assert trusted.action == attacker.action


def test_agent_identity_does_not_change_deny_policy():
    fw = Firewall()

    trusted = fw.check(
        "trusted-agent",
        "github.delete_file",
        {"path": "production.env"},
    )

    attacker = fw.check(
        "attacker-agent",
        "github.delete_file",
        {"path": "production.env"},
    )

    assert trusted.action == "deny"
    assert attacker.action == "deny"


def test_agent_identity_does_not_change_payment_policy():
    fw = Firewall()

    trusted = fw.check(
        "trusted-agent",
        "payments.send",
        {"amount": 2000},
    )

    attacker = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": 2000},
    )

    assert trusted.action == "deny"
    assert attacker.action == "deny"


def test_matching_agent_policy_is_allowed():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "agent": "trusted-agent",
        "action": "allow",
    })

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "allow"


def test_non_matching_agent_policy_does_not_match():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "agent": "trusted-agent",
        "action": "allow",
    })

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_agent_policy_can_deny_specific_agent():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "agent": "attacker-agent",
        "action": "deny",
    })

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_agent_matching_is_exact():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "agent": "trusted-agent",
        "action": "allow",
    })

    result = fw.check(
        "trusted-agent ",
        "test.tool",
        {},
    )

    assert result.action == "deny"