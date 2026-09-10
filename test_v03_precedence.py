from firewall.engine import Firewall


def test_multiple_allows_do_not_override_deny():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "allow",
        },
        {
            "tool": "test.tool",
            "action": "allow",
        },
        {
            "tool": "test.tool",
            "action": "deny",
        },
    ])

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_multiple_approvals_do_not_override_deny():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "approval",
        },
        {
            "tool": "test.tool",
            "action": "approval",
        },
        {
            "tool": "test.tool",
            "action": "deny",
        },
    ])

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_late_allow_cannot_override_earlier_deny():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "deny",
        },
        {
            "tool": "test.tool",
            "action": "allow",
        },
    ])

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_late_approval_cannot_override_earlier_deny():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "test.tool",
            "action": "deny",
        },
        {
            "tool": "test.tool",
            "action": "approval",
        },
    ])

    result = fw.check(
        "attacker-agent",
        "test.tool",
        {},
    )

    assert result.action == "deny"


def test_payment_threshold_conflict_denies_highest_amount():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "allow",
        },
        {
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "approval",
        },
        {
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "deny",
        },
    ])

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "deny"


def test_overlapping_payment_rules_use_strongest_match():
    fw = Firewall()

    fw.rules.extend([
        {
            "tool": "payments.send",
            "amount_gte": 100,
            "action": "approval",
        },
        {
            "tool": "payments.send",
            "amount_gte": 500,
            "action": "deny",
        },
    ])

    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "deny"