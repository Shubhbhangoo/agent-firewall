from mcp.server import MCPServer

from firewall.engine import Firewall


server = MCPServer("TestServer")
firewall = Firewall()


TOOL_POLICY_MAP = {
    "read_file": "github.read_file",
    "delete_file": "github.delete_file",
    "send_payment": "payments.send",
}


def ask_for_approval(tool, arguments):
    print("\n HUMAN APPROVAL REQUIRED")
    print(f"Tool: {tool}")
    print(f"Arguments: {arguments}")

    answer = input("Allow this action? [y/N]: ").strip().lower()

    return answer == "y"


async def protected_tool_call(
    agent,
    tool,
    arguments,
    real_tool,
):
    policy_tool = TOOL_POLICY_MAP.get(tool)

    if policy_tool is None:
        return {
            "error": "Blocked by firewall",
            "reason": "Unknown MCP tool"
        }

    decision = firewall.check(
        agent,
        policy_tool,
        arguments,
    )

    print(
        f"\n[FIREWALL] {tool} -> "
        f"{decision.action.upper()}"
    )

    if decision.action == "deny":
        return {
            "error": "Blocked by firewall",
            "reason": decision.reason,
        }

    if decision.action == "approval":
        approved = ask_for_approval(
            policy_tool,
            arguments,
        )

        if not approved:
            return {
                "error": "Rejected by human",
                "reason": "Human denied the action",
            }

    return await real_tool(**arguments)


@server.tool()
async def read_file(path: str) -> str:
    """Read a file."""

    async def real_tool(path):
        return f"READING: {path}"

    result = await protected_tool_call(
        "mcp-agent",
        "read_file",
        {"path": path},
        real_tool,
    )

    return result


@server.tool()
async def delete_file(path: str) -> str:
    """Delete a file."""

    async def real_tool(path):
        return f"DELETING: {path}"

    result = await protected_tool_call(
        "mcp-agent",
        "delete_file",
        {"path": path},
        real_tool,
    )

    return result


@server.tool()
async def send_payment(amount: float) -> str:
    """Simulate sending a payment. No real money is moved."""

    async def real_tool(amount):
        return f"PAYMENT EXECUTED: ${amount:.2f}"

    result = await protected_tool_call(
        "finance-agent",
        "send_payment",
        {"amount": amount},
        real_tool,
    )

    return result


if __name__ == "__main__":
    server.run("stdio")