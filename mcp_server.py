from mcp.server import MCPServer


server = MCPServer("TestServer")


@server.tool()
async def read_file(path: str) -> str:
    """Read a file."""
    return f"READING: {path}"


@server.tool()
async def delete_file(path: str) -> str:
    """Delete a file."""
    return f"DELETING: {path}"


@server.tool()
async def send_payment(amount: float) -> str:
    """Simulate sending a payment. No real money is moved."""
    return f"PAYMENT EXECUTED: ${amount:.2f}"


if __name__ == "__main__":
    server.run("stdio")