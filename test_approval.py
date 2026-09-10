import json

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


def test_approval_rejection_is_audited(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        """
rules:
  - tool: payments.send
    amount_gt: 100
    action: approval
""",
        encoding="utf-8",
    )

    import mcp_firewall
    from firewall.engine import Firewall

    mcp_firewall.fw = Firewall(str(policy_file))

    monkeypatch.setattr(
        "mcp_firewall.ask_for_approval",
        lambda tool, arguments: False,
    )

    result = mcp_firewall.protected_call(
        "finance-agent",
        "payments.send",
        {"amount": 500},
        lambda **arguments: "TOOL EXECUTED",
    )

    assert result["error"] == "Rejected by human"

    lines = (tmp_path / "audit.log").read_text(
        encoding="utf-8"
    ).splitlines()

    entries = [json.loads(line) for line in lines]

    assert any(
        entry["decision"] == "approval"
        for entry in entries
    )


def test_approval_acceptance_is_audited(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        """
rules:
  - tool: payments.send
    amount_gt: 100
    action: approval
""",
        encoding="utf-8",
    )

    import mcp_firewall
    from firewall.engine import Firewall

    mcp_firewall.fw = Firewall(str(policy_file))

    monkeypatch.setattr(
        "mcp_firewall.ask_for_approval",
        lambda tool, arguments: True,
    )

    result = mcp_firewall.protected_call(
        "finance-agent",
        "payments.send",
        {"amount": 500},
        lambda **arguments: "TOOL EXECUTED",
    )

    assert result == "TOOL EXECUTED"

    lines = (tmp_path / "audit.log").read_text(
        encoding="utf-8"
    ).splitlines()

    entries = [json.loads(line) for line in lines]

    assert any(
        entry["decision"] == "approval"
        for entry in entries
    )