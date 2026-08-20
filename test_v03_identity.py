from firewall.engine import Firewall


def test_agent_name_does_not_bypass_tool_policy():
    fw = Firewall()

    result = fw.check(
        "trusted-agent",
        "github.delete_file",
        {"path": "production.env"},
    )

    assert result.action == "deny"


def test_admin_name_does_not_bypass_payment_policy():
    fw = Firewall()

    result = fw.check(
        "admin-agent",
        "payments.send",
        {"amount": 2000},
    )

    assert result.action == "deny"


def test_unknown_agent_cannot_execute_unknown_tool():
    fw = Firewall()

    result = fw.check(
        "admin-agent",
        "payments.fake",
        {"amount": 500},
    )

    assert result.action == "deny"


def test_agent_name_does_not_change_existing_decision():
    fw = Firewall()

    agents = [
        "attacker-agent",
        "trusted-agent",
        "admin-agent",
        "finance-agent",
        "",
        "trusted-agent ",
    ]

    for agent in agents:
        result = fw.check(
            agent,
            "github.delete_file",
            {"path": "production.env"},
        )

        assert result.action == "deny"