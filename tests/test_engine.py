from firewall.engine import Firewall


def test_read_allowed():
    fw = Firewall()
    result = fw.check("test-agent", "github.read_file", {"path": "README.md"})
    assert result.action == "allow"


def test_production_delete_denied():
    fw = Firewall()
    result = fw.check(
        "test-agent",
        "github.delete_file",
        {"path": "production.env"},
    )
    assert result.action == "deny"


def test_small_payment_allowed():
    fw = Firewall()
    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 20},
    )
    assert result.action == "allow"


def test_medium_payment_requires_approval():
    fw = Firewall()
    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 500},
    )
    assert result.action == "approval"


def test_large_payment_denied():
    fw = Firewall()
    result = fw.check(
        "finance-agent",
        "payments.send",
        {"amount": 2000},
    )
    assert result.action == "deny"


def test_invalid_payment_denied():
    fw = Firewall()

    attacks = [
        {"amount": -500},
        {"amount": 0},
        {"amount": "2000"},
        {},
        {"amount": None},
        {"amount": True},
    ]

    for arguments in attacks:
        result = fw.check(
            "attacker-agent",
            "payments.send",
            arguments,
        )
        assert result.action == "deny"


def test_unknown_tool_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.fake",
        {"amount": 500},
    )
    assert result.action == "deny"


def test_nan_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": float("nan")},
    )
    assert result.action == "deny"


def test_infinity_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": float("inf")},
    )
    assert result.action == "deny"


def test_negative_infinity_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": float("-inf")},
    )
    assert result.action == "deny"


def test_boolean_amount_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": True},
    )
    assert result.action == "deny"


def test_list_amount_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": [500]},
    )
    assert result.action == "deny"


def test_dict_amount_denied():
    fw = Firewall()
    result = fw.check(
        "attacker-agent",
        "payments.send",
        {"amount": {"value": 500}},
    )
    assert result.action == "deny"


def test_tool_name_confusion_denied():
    fw = Firewall()

    attacks = [
        "Payments.Send",
        "payments.send/",
        "payments.send.fake",
        "payments.send ",
        "payments.send\n",
        "payments/../send",
    ]

    for tool in attacks:
        result = fw.check(
            "attacker-agent",
            tool,
            {"amount": 500},
        )

        assert result.action == "deny"