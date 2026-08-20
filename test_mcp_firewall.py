from firewall.engine import Firewall


TOOL_POLICY_MAP = {
    "read_file": "github.read_file",
    "delete_file": "github.delete_file",
    "send_payment": "payments.send",
}


def test_read_file_maps_to_github_policy():
    assert TOOL_POLICY_MAP["read_file"] == "github.read_file"


def test_delete_file_maps_to_github_policy():
    assert TOOL_POLICY_MAP["delete_file"] == "github.delete_file"


def test_send_payment_maps_to_payment_policy():
    assert TOOL_POLICY_MAP["send_payment"] == "payments.send"


def test_mapped_read_tool_is_allowed():
    fw = Firewall()

    policy_tool = TOOL_POLICY_MAP["read_file"]

    result = fw.check(
        "test-agent",
        policy_tool,
        {"path": "README.md"},
    )

    assert result.action == "allow"


def test_mapped_delete_tool_is_denied():
    fw = Firewall()

    policy_tool = TOOL_POLICY_MAP["delete_file"]

    result = fw.check(
        "test-agent",
        policy_tool,
        {"path": "production.env"},
    )

    assert result.action == "deny"


def test_mapped_payment_uses_payment_policy():
    fw = Firewall()

    policy_tool = TOOL_POLICY_MAP["send_payment"]

    result = fw.check(
        "finance-agent",
        policy_tool,
        {"amount": 2000},
    )

    assert result.action == "deny"