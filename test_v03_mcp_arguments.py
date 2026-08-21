import pytest

from mcp_server import protected_tool_call


@pytest.mark.anyio
async def test_mcp_delete_path_traversal_is_blocked():
    called = False

    async def real_tool(path):
        nonlocal called
        called = True
        return f"DELETING: {path}"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file",
        {"path": "../production.env"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_delete_absolute_path_is_blocked():
    called = False

    async def real_tool(path):
        nonlocal called
        called = True
        return f"DELETING: {path}"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file",
        {"path": "C:\\production.env"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_unknown_argument_does_not_bypass_firewall():
    called = False

    async def real_tool(**arguments):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file",
        {
            "path": "production.env",
            "bypass": True,
        },
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_tool_name_variation_is_blocked():
    called = False

    async def real_tool(**arguments):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file ",
        {"path": "production.env"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_payment_string_amount_is_blocked():
    called = False

    async def real_tool(amount):
        nonlocal called
        called = True
        return "PAYMENT EXECUTED"

    result = await protected_tool_call(
        "finance-agent",
        "send_payment",
        {"amount": "2000"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_payment_boolean_amount_is_blocked():
    called = False

    async def real_tool(amount):
        nonlocal called
        called = True
        return "PAYMENT EXECUTED"

    result = await protected_tool_call(
        "finance-agent",
        "send_payment",
        {"amount": True},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False