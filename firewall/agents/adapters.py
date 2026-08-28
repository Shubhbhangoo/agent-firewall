"""Concrete agent adapters (v1.9).

Each adapter speaks for one agent environment and inherits the shared
protection/observation mechanics from :class:`AgentAdapter`. Adapters
are thin: they translate the environment's shape (HTTP request,
MCP message, OpenAI tool call, LangChain step, or a plain Python call)
into the common model, and they degrade gracefully when the
environment provides no identity, parent, or correlation id.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from firewall.adapters import normalize_tool_call
from firewall.agents.base import (
    AgentAdapter,
    AgentIntegrationError,
)


class PythonAgentAdapter(AgentAdapter):
    """Protects a plain Python agent loop.

    The agent's tool calls are plain callables or dict-shaped calls;
    ``protect`` wraps them with authorization.
    """

    environment = "python"

    def protect_callable(
        self,
        handler: Callable[..., Any],
        *,
        name: Optional[str] = None,
        action: Optional[str] = None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
    ):
        """Protect a plain Python callable used as a tool."""

        return self.protect(
            handler,
            name=name,
            action=action,
            request_builder=request_builder,
        )

    def call(
        self,
        tool_call: Any,
        *,
        handler: Callable[..., Any],
        capability=None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
    ):
        """Run one tool call through authorization.

        ``tool_call`` may be a ``{name, arguments}`` mapping or a
        normalized ``GenericToolCall``; ``handler`` is required.
        """

        call = normalize_tool_call(tool_call)

        adapter = self.protect(
            handler,
            name=call.name,
            capability=capability,
            request_builder=request_builder,
        )

        return adapter.execute(call)


class HTTPAgentAdapter(AgentAdapter):
    """Protects HTTP/API-based agents.

    ``endpoint_to_action`` maps an HTTP route to an authorization
    action; when the mapping is missing the adapter degrades to
    deny-with-explanation rather than guessing an action.
    """

    environment = "http"

    def __init__(
        self,
        *,
        sdk,
        agent_id: Optional[str] = None,
        recorder=None,
        correlation_id: Optional[str] = None,
        parent_agent: Optional[str] = None,
        endpoint_to_action: Optional[dict[str, str]] = None,
    ) -> None:
        super().__init__(
            sdk=sdk,
            agent_id=agent_id,
            recorder=recorder,
            correlation_id=correlation_id,
            parent_agent=parent_agent,
        )
        self._endpoint_to_action = dict(
            endpoint_to_action or {}
        )

    def protect_endpoint(
        self,
        endpoint: str,
        handler: Callable[..., Any],
        *,
        capability=None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
    ) -> Callable[..., Any]:
        """Wrap an HTTP handler so requests are authorized first.

        The endpoint must be mapped to an action; without a mapping the
        wrapper refuses with an explanation (never guesses).
        """

        action = self._endpoint_to_action.get(endpoint)

        if action is None:
            def refuse(*args, **kwargs):
                raise PermissionError(
                    f"endpoint {endpoint} has no mapped "
                    "authorization action; refusing without guessing"
                )

            return refuse

        adapter = self.protect(
            handler,
            name=endpoint,
            action=action,
            capability=capability,
            request_builder=request_builder,
        )

        def wrapped(*args, **kwargs):
            return adapter.execute(
                normalize_tool_call(
                    name=endpoint,
                    arguments=kwargs or {},
                )
            )

        return wrapped

    def authorize_request(
        self,
        *,
        endpoint: str,
        request: dict[str, Any],
    ):
        """Authorize one HTTP request without executing anything.

        Returns the raw ``AuthorizationResult`` from the real pipeline.
        """

        action = self._endpoint_to_action.get(endpoint)

        if action is None:
            raise AgentIntegrationError(
                f"endpoint {endpoint} has no mapped action"
            )

        capabilities = [
            item
            for item in getattr(
                self._sdk, "_capability_registry", {}
            ).values()
            if item.agent_id == self._agent_id
        ]

        if not capabilities:
            raise AgentIntegrationError(
                f"no capability for agent {self._agent_id!r}"
            )

        return self._sdk.authorize(
            capabilities[0],
            action,
            request,
        )


class MCPAgentAdapter(AgentAdapter):
    """Protects MCP-based systems.

    MCP tool calls are authorized through the same
    ``FirewallSDK`` pipeline via the shared adapter mechanics; the
    environment-specific transport (the existing ``firewall.mcp``
    module) remains responsible for wire handling.
    """

    environment = "mcp"

    def protect_mcp_tool(
        self,
        name: str,
        handler: Callable[..., Any],
        *,
        action: Optional[str] = None,
        capability=None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
    ):
        return self.protect(
            handler,
            name=name,
            action=action,
            capability=capability,
            request_builder=request_builder,
        )


class OpenAIAgentAdapter(AgentAdapter):
    """Protects OpenAI-compatible agent interfaces.

    Tool calls arrive in the OpenAI shape (``{name, arguments}`` JSON);
    the adapter normalizes them and authorizes through the real
    pipeline before the tool runs.
    """

    environment = "openai"

    def protect_openai_tool(
        self,
        name: str,
        handler: Callable[..., Any],
        *,
        action: Optional[str] = None,
        capability=None,
    ):
        return self.protect(
            handler,
            name=name,
            action=action,
            capability=capability,
        )

    def call_tool(
        self,
        tool_call: dict[str, Any],
        *,
        handler: Callable[..., Any],
        capability=None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
    ):
        call = normalize_tool_call(tool_call)
        adapter = self.protect(
            handler,
            name=call.name,
            capability=capability,
            request_builder=request_builder,
        )
        return adapter.execute(call)


class LangChainAgentAdapter(AgentAdapter):
    """Protects LangChain/LangGraph-style systems.

    Structure-only adapter: it does not import langchain (so it works
    without the dependency) but accepts the shape LangChain tool calls
    share (``name`` + ``args``/``arguments``) and authorizes them
    identically.
    """

    environment = "langchain"

    def protect_langchain_tool(
        self,
        name: str,
        handler: Callable[..., Any],
        *,
        action: Optional[str] = None,
        capability=None,
    ):
        return self.protect(
            handler,
            name=name,
            action=action,
            capability=capability,
        )

    def call_tool(
        self,
        tool_call: Any,
        *,
        handler: Callable[..., Any],
        capability=None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
    ):
        # LangChain tool calls carry name + args (or arguments).
        if isinstance(tool_call, dict):
            name = tool_call.get("name")
            arguments = tool_call.get(
                "args",
                tool_call.get("arguments", {}),
            )
            call = normalize_tool_call(
                name=name,
                arguments=arguments,
            )
        else:
            call = normalize_tool_call(tool_call)

        adapter = self.protect(
            handler,
            name=call.name,
            capability=capability,
            request_builder=request_builder,
        )
        return adapter.execute(call)


#: Adapter classes by environment name, for registry-based creation.
ADAPTERS_BY_ENVIRONMENT: dict[str, type] = {
    "python": PythonAgentAdapter,
    "http": HTTPAgentAdapter,
    "mcp": MCPAgentAdapter,
    "openai": OpenAIAgentAdapter,
    "langchain": LangChainAgentAdapter,
}


def create_adapter(
    environment: str,
    **kwargs: Any,
) -> AgentAdapter:
    """Create an adapter for ``environment`` by name.

    Raises :class:`AgentIntegrationError` for an unknown environment so
    callers fail fast rather than silently running unprotected.
    """

    adapter_class = ADAPTERS_BY_ENVIRONMENT.get(
        environment
    )

    if adapter_class is None:
        raise AgentIntegrationError(
            f"unknown agent environment: {environment!r}; "
            f"known: {', '.join(sorted(ADAPTERS_BY_ENVIRONMENT))}"
        )

    return adapter_class(**kwargs)
