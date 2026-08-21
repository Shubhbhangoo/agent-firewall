from firewall.engine import Firewall


def test_identity_deny_beats_identity_allow():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "allow",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "deny",
        },
    ])

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_identity_deny_beats_general_allow():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "allow",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "deny",
        },
    ])

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_identity_allow_cannot_override_general_deny():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "deny",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "allow",
        },
    ])

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_identity_approval_beats_general_allow():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "allow",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "approval",
        },
    ])

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "approval"


def test_identity_deny_beats_general_approval():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "approval",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "deny",
        },
    ])

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_identity_policy_does_not_affect_other_agents():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "deny",
        },
        {
            "tool": "test.tool",
            "action": "allow",
        },
    ])

    result = fw.check(
        "other-agent",
        "test.tool",
        {},
    )

    assert result.action == "allow"


def test_multiple_identity_rules_use_strongest_restriction():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "allow",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "approval",
        },
        {
            "tool": "test.tool",
            "agent": "trusted-agent",
            "action": "deny",
        },
    ])

    result = fw.check(
        "trusted-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"