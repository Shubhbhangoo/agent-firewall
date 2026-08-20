import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from firewall.engine import Firewall


GITHUB_SERVER = (
    r"E:\FOLK FINANCE\github-mcp-server_Windows_x86_64"
    r"\github-mcp-server.exe"
)

GITHUB_OWNER = "shubhbhangoo"
GITHUB_REPO = "agent-firewall-test"


server_params = StdioServerParameters(
    command=GITHUB_SERVER,
    args=["stdio"],
)


async def main():
    firewall = Firewall()

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()

            tools = await session.list_tools()

            print("Available MCP tools:")

            for tool in tools.tools:
                print(f" - {tool.name}")

            # -------------------------
            # REAL GITHUB READ
            # -------------------------

            read_tool = "github.get_file_contents"

            read_arguments = {
                "owner": GITHUB_OWNER,
                "repo": GITHUB_REPO,
                "path": "README.md",
            }

            decision = firewall.check(
                "test-agent",
                read_tool,
                read_arguments,
            )

            print("\nTesting REAL GITHUB READ...")
            print(f"Firewall: {decision.action.upper()}")

            if decision.action == "allow":

                result = await session.call_tool(
                    "get_file_contents",
                    arguments=read_arguments,
                )

                print("MCP:", result)

            else:
                print("MCP: BLOCKED")

            # -------------------------
            # REAL GITHUB DELETE
            # -------------------------

            delete_tool = "github.delete_file"

            delete_arguments = {
                "owner": GITHUB_OWNER,
                "repo": GITHUB_REPO,
                "path": "README.md",
                "message": "Firewall delete test",
                "branch": "master",
            }

            decision = firewall.check(
                "test-agent",
                delete_tool,
                delete_arguments,
            )

            print("\nTesting REAL GITHUB DELETE...")
            print(f"Firewall: {decision.action.upper()}")
            print(f"Reason: {decision.reason}")

            if decision.action == "allow":

                print("WARNING: Firewall allowed delete.")

                result = await session.call_tool(
                    "delete_file",
                    arguments=delete_arguments,
                )

                print("MCP:", result)

            else:

                print("MCP: BLOCKED")
                print("GitHub delete was never called.")


if __name__ == "__main__":
    asyncio.run(main())