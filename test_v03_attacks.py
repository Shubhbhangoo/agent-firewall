from firewall.engine import Firewall


def test_nested_argument_bypass_is_denied():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "arguments": {
            "environment": "production",
        },
        "action": "deny",
    })

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {
            "environment": {
                "value": "production",
            },
        },
    )

    assert result.action == "deny"


def test_list_argument_bypass_is_denied():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "arguments": {
            "environment": "production",
        },
        "action": "deny",
    })

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {
            "environment": ["production"],
        },
    )

    assert result.action == "deny"


def test_null_argument_bypass_is_denied():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "arguments": {
            "environment": "production",
        },
        "action": "deny",
    })

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {
            "environment": None,
        },
    )

    assert result.action == "deny"


def test_boolean_argument_bypass_is_denied():
    fw = Firewall()

    fw.rules.append({
        "tool": "test.tool",
        "arguments": {
            "enabled": True,
        },
        "action": "deny",
    })

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {
            "enabled": 1,
        },
    )

    assert result.action == "deny"