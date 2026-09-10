"""Universal agent integration layer (v1.9).

One common adapter model for protecting agents across environments:
Python loops, custom loops, MCP, OpenAI-compatible interfaces,
LangChain/LangGraph-style systems, and HTTP/API agents. Adapters share
identity/protect/observe/context mechanics, degrade gracefully when an
environment cannot provide something, and never hold authority of their
own -- every protected call runs through the real ``FirewallSDK``
authorization pipeline.
"""

from firewall.agents.base import (
    AgentAdapter,
    AgentIntegrationError,
)
from firewall.agents.adapters import (
    ADAPTERS_BY_ENVIRONMENT,
    HTTPAgentAdapter,
    LangChainAgentAdapter,
    MCPAgentAdapter,
    OpenAIAgentAdapter,
    PythonAgentAdapter,
    create_adapter,
)

__all__ = [
    "ADAPTERS_BY_ENVIRONMENT",
    "AgentAdapter",
    "AgentIntegrationError",
    "HTTPAgentAdapter",
    "LangChainAgentAdapter",
    "MCPAgentAdapter",
    "OpenAIAgentAdapter",
    "PythonAgentAdapter",
    "create_adapter",
]
