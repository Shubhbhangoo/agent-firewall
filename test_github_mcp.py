import asyncio
import os

import pytest

from mcp import (
    ClientSession,
    StdioServerParameters,
)
from mcp.client.stdio import (
    stdio_client,
)


GITHUB_MCP_SERVER = os.environ.get(
    "GITHUB_MCP_SERVER",
    r"E:\FOLK FINANCE\github-mcp-server_Windows_x86_64\github-mcp-server.exe",
)


def github_mcp_available() -> bool:
    return bool(
        GITHUB_MCP_SERVER
        and os.path.isfile(
            GITHUB_MCP_SERVER
        )
    )


def make_server_params():
    return StdioServerParameters(
        command=GITHUB_MCP_SERVER,
        args=["stdio"],
        env=dict(
            os.environ
        ),
    )


@pytest.mark.skipif(
    not github_mcp_available(),
    reason=(
        "GitHub MCP server executable "
        "is not available in this environment"
    ),
)
def test_real_github_read_allowed():
    asyncio.run(
        _test_read()
    )


async def _test_read():
    server_params = (
        make_server_params()
    )

    async with stdio_client(
        server_params
    ) as (
        read,
        write,
    ):
        async with ClientSession(
            read,
            write,
        ) as session:

            await session.initialize()

            result = await session.call_tool(
                "get_file_contents",
                {
                    "owner": "octocat",
                    "repo": "Hello-World",
                    "path": "README",
                },
            )

            assert result is not None


def test_real_github_delete_is_environment_dependent():
    """
    The raw GitHub MCP server is not itself the security boundary.

    On environments with the executable available, this test documents
    that the server can expose delete functionality. Firewall policy
    tests are responsible for proving dangerous operations are blocked.
    """

    if not github_mcp_available():
        pytest.skip(
            "GitHub MCP server executable unavailable"
        )

    asyncio.run(
        _test_delete_available()
    )


async def _test_delete_available():
    server_params = (
        make_server_params()
    )

    async with stdio_client(
        server_params
    ) as (
        read,
        write,
    ):
        async with ClientSession(
            read,
            write,
        ) as session:

            await session.initialize()

            tools = await session.list_tools()

            tool_names = {
                tool.name
                for tool in tools.tools
            }

            assert "delete_file" in (
                tool_names
            )


def test_mcp_server_path_is_not_required_for_unit_suite():
    """
    The unit/security suite must remain runnable in CI
    environments that do not contain the developer's
    local GitHub MCP executable.
    """

    if os.name != "nt":
        assert (
            github_mcp_available()
            is False
        )