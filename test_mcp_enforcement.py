import pytest

from mcp_server import protected_tool_call


@pytest.mark.anyio
async def test_mcp_read_is_allowed():
    async def real_tool(path):
        return f"READING: {path}"

    result = await protected_tool_call(
        "test-agent",
        "read_file",
        {"path": "README.md"},
        real_tool,
    )

    assert result == "READING: README.md"


@pytest.mark.anyio
async def test_mcp_delete_is_blocked():
    called = False

    async def real_tool(path):
        nonlocal called
        called = True
        return f"DELETING: {path}"

    result = await protected_tool_call(
        "test-agent",
        "delete_file",
        {"path": "production.env"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_unknown_tool_is_blocked():
    called = False

    async def real_tool(**arguments):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "unknown_tool",
        {},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_large_payment_is_blocked():
    called = False

    async def real_tool(amount):
        nonlocal called
        called = True
        return f"PAYMENT EXECUTED: ${amount:.2f}"

    result = await protected_tool_call(
        "finance-agent",
        "send_payment",
        {"amount": 2000},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_tool_name_case_bypass_is_blocked():
    called = False

    async def real_tool(path):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "Delete_File",
        {"path": "production.env"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_tool_name_suffix_bypass_is_blocked():
    called = False

    async def real_tool(path):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file.fake",
        {"path": "production.env"},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_extra_arguments_do_not_bypass_policy():
    called = False

    async def real_tool(path, **kwargs):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file",
        {
            "path": "production.env",
            "bypass": True,
            "admin": True,
        },
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False


@pytest.mark.anyio
async def test_mcp_missing_arguments_fail_closed():
    called = False

    async def real_tool(path):
        nonlocal called
        called = True
        return "EXECUTED"

    result = await protected_tool_call(
        "attacker-agent",
        "delete_file",
        {},
        real_tool,
    )

    assert result["error"] == "Blocked by firewall"
    assert called is False