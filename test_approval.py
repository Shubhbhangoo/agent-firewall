from mcp_firewall import protected_call


def test_approval_rejected_does_not_call_tool(monkeypatch):
    called = False

    def fake_tool(**arguments):
        nonlocal called
        called = True
        return "TOOL EXECUTED"

    monkeypatch.setattr(
        "mcp_firewall.ask_for_approval",
        lambda tool, arguments: False,
    )

    result = protected_call(
        "finance-agent",
        "payments.send",
        {"amount": 500},
        fake_tool,
    )

    assert result["error"] == "Rejected by human"
    assert called is False


def test_approval_accepted_calls_tool(monkeypatch):
    called = False

    def fake_tool(**arguments):
        nonlocal called
        called = True
        return "TOOL EXECUTED"

    monkeypatch.setattr(
        "mcp_firewall.ask_for_approval",
        lambda tool, arguments: True,
    )

    result = protected_call(
        "finance-agent",
        "payments.send",
        {"amount": 500},
        fake_tool,
    )

    assert result == "TOOL EXECUTED"
    assert called is True