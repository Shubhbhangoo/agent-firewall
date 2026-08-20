import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from firewall.engine import Firewall


GITHUB_SERVER = (
    r"E:\FOLK FINANCE\github-mcp-server_Windows_x86_64"
    r"\github-mcp-server.exe"
)

OWNER = "shubhbhangoo"
REPO = "agent-firewall-test"


def test_real_github_read_allowed():
    asyncio.run(_test_read())


def test_real_github_delete_blocked():
    asyncio.run(_test_delete())


async def _test_read():
    firewall = Firewall()

    server_params = StdioServerParameters(
        command=GITHUB_SERVER,
        args=["stdio"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()

            decision = firewall.check(
                "test-agent",
                "github.get_file_contents",
                {
                    "owner": OWNER,
                    "repo": REPO,
                    "path": "README.md",
                },
            )

            assert decision.action == "allow"

            result = await session.call_tool(
                "get_file_contents",
                arguments={
                    "owner": OWNER,
                    "repo": REPO,
                    "path": "README.md",
                },
            )

            assert result.is_error is False


async def _test_delete():
    firewall = Firewall()

    server_params = StdioServerParameters(
        command=GITHUB_SERVER,
        args=["stdio"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()

            decision = firewall.check(
                "test-agent",
                "github.delete_file",
                {
                    "owner": OWNER,
                    "repo": REPO,
                    "path": "README.md",
                    "message": "Firewall test",
                    "branch": "master",
                },
            )

            assert decision.action == "deny"