"""Universal agent integration layer (v1.9).

One common adapter model for protecting agents across environments --
Python agent loops, custom loops, MCP-based systems, OpenAI-compatible
interfaces, LangChain/LangGraph-style systems, and HTTP/API agents.

Every adapter shares the same contract:

* **identity** -- who the agent is (best effort; ``None`` when unknown),
* **capabilities** -- the capabilities it holds (from the SDK registry),
* **protect** -- wrap a tool call so it is authorized by the real
  ``FirewallSDK`` pipeline before it executes (via the v0.9
  ``GenericToolAdapter``), recording the decision in the flight
  recorder,
* **observe** -- record tool results and security events after the
  fact,
* **context** -- parent/child relationships and correlation ids,
* **degrade gracefully** -- when an environment cannot provide
  something (identity, parent, correlation id), the adapter returns
  ``None``/empty and says so; missing evidence is never fabricated and
  never silently treated as trustworthy.

The adapter holds no authority of its own. It can only call the SDK
APIs a Python caller could call, and authorization always runs through
the existing pipeline.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

from firewall.capability import Capability
from firewall.recorder import EventType, FlightRecorder
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool


class AgentIntegrationError(ValueError):
    """Raised for a malformed adapter request."""


class AgentAdapter:
    """Base adapter: identity, protection, observation, context.

    Subclasses override the environment-specific accessors; the base
    implements the shared protection and observation mechanics so every
    environment enforces authorization identically.
    """

    #: The environment this adapter speaks for (e.g. ``python``,
    #: ``http``, ``mcp``, ``openai``, ``langchain``).
    environment: str = "generic"

    def __init__(
        self,
        *,
        sdk: FirewallSDK,
        agent_id: Optional[str] = None,
        recorder: Optional[FlightRecorder] = None,
        correlation_id: Optional[str] = None,
        parent_agent: Optional[str] = None,
    ) -> None:
        if not isinstance(sdk, FirewallSDK):
            raise AgentIntegrationError(
                "sdk must be a FirewallSDK"
            )

        if recorder is not None and not isinstance(
            recorder, FlightRecorder
        ):
            raise AgentIntegrationError(
                "recorder must be a FlightRecorder"
            )

        self._sdk = sdk
        self._agent_id = agent_id
        self._recorder = recorder
        self._correlation_id = correlation_id
        self._parent_agent = parent_agent

    # ------------------------------------------------------------------
    # Identity (environment-specific; override in subclasses)
    # ------------------------------------------------------------------

    def identity(self) -> dict[str, Any]:
        """What the environment can tell us about this agent.

        Returns only what is actually known. Unknown fields are ``None``
        -- never guessed, never defaulted to a trustable value.
        """

        return {
            "agent_id": self._agent_id,
            "environment": self.environment,
            "correlation_id": self._correlation_id,
            "parent_agent": self._parent_agent,
            "complete": self._agent_id is not None,
        }

    def capabilities(self) -> tuple[str, ...]:
        """Capabilities this agent holds, per the SDK's registry.

        Read-only. The registry is the same one the authorization gates
        use.
        """

        if self._agent_id is None:
            return ()

        found: set[str] = set()

        for capability in self._sdk.known_capabilities().values():
            if (
                isinstance(capability, Capability)
                and capability.agent_id == self._agent_id
                and not self._sdk.is_effectively_revoked(capability)
            ):
                found.add(capability.capability)

        return tuple(sorted(found))

    # ------------------------------------------------------------------
    # Protection
    # ------------------------------------------------------------------

    def protect(
        self,
        handler: Callable[..., Any],
        *,
        name: Optional[str] = None,
        capability: Optional[Capability] = None,
        action: Optional[str] = None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
        chain_id: Optional[str] = None,
    ):
        """Wrap ``handler`` so every call is authorized first.

        Delegates to the v0.9 :class:`GenericToolAdapter` mechanics:
        the capability is presented to ``FirewallSDK.authorize()`` and
        the handler runs only when the real pipeline allows it. The
        decision is recorded post-hoc in the flight recorder.
        """

        from firewall.adapters import GenericToolAdapter

        if capability is None:
            capabilities = [
                item
                for item in self._sdk.known_capabilities().values()
                if isinstance(item, Capability)
                and item.agent_id == self._agent_id
            ]

            if not capabilities:
                raise AgentIntegrationError(
                    f"no capability available for agent "
                    f"{self._agent_id!r}; issue one first"
                )

            capability = capabilities[0]

        if name is None:
            name = getattr(handler, "__name__", None)

        if not isinstance(name, str) or not name.strip():
            raise AgentIntegrationError(
                "tool name must be a non-empty string"
            )

        adapter = GenericToolAdapter(
            sdk=self._sdk,
            capability=capability,
            handler=handler,
            name=name,
            action=action,
            request_builder=request_builder,
            chain_id=chain_id,
        )

        # Observe the verdicts the adapter produces. The recorder only
        # ever sees decisions after the fact. Dict-shaped calls are
        # normalized so callers can pass either a mapping or a
        # GenericToolCall.
        from firewall.adapters import normalize_tool_call

        original = adapter.execute

        def observed(call):
            call = normalize_tool_call(call)
            result = original(call)
            self._observe_tool_call(
                call.name,
                dict(call.arguments),
                result,
            )
            return result

        adapter.execute = observed  # type: ignore[method-assign]
        return adapter

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def record(
        self,
        event_type: EventType,
        payload: dict[str, Any],
        *,
        agent: Optional[str] = None,
    ) -> None:
        """Record a security event into the flight recorder.

        Best effort: a recorder failure must never break the agent.
        """

        if self._recorder is None:
            return

        try:
            self._recorder.record(
                event_type,
                payload,
                agent=agent if agent is not None else self._agent_id,
            )
        except Exception:
            return

    def _observe_tool_call(
        self,
        name: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> None:
        """Record a tool execution result after the fact."""

        self.record(
            EventType.TOOL_RESULT,
            {
                "tool": name,
                "arguments": dict(arguments),
                "outcome": (
                    "ok"
                    if result is not None
                    else "empty"
                ),
            },
        )

    def observe_step(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        result: Any = None,
        error: Optional[str] = None,
    ) -> None:
        """Observe one agent step (tool result / error)."""

        payload: dict[str, Any] = {
            "tool": tool,
            "arguments": dict(arguments),
        }

        if error is not None:
            payload["error"] = str(error)[:500]
            payload["outcome"] = "error"
        else:
            payload["outcome"] = "ok"

        self.record(
            EventType.TOOL_RESULT,
            payload,
        )

    # ------------------------------------------------------------------
    # Context (environment-specific; override in subclasses)
    # ------------------------------------------------------------------

    def context(self) -> dict[str, Any]:
        """Execution context the environment can provide."""

        return {
            "environment": self.environment,
            "correlation_id": self._correlation_id,
            "parent_agent": self._parent_agent,
        }

    def set_correlation_id(self, correlation_id: str) -> None:
        if not isinstance(correlation_id, str) or not correlation_id.strip():
            raise AgentIntegrationError(
                "correlation_id must be a non-empty string"
            )
        self._correlation_id = correlation_id

    def set_parent(self, parent_agent: str) -> None:
        if not isinstance(parent_agent, str) or not parent_agent.strip():
            raise AgentIntegrationError(
                "parent_agent must be a non-empty string"
            )
        self._parent_agent = parent_agent

    # ------------------------------------------------------------------
    # SDK access (read-only for adapters)
    # ------------------------------------------------------------------

    @property
    def sdk(self) -> FirewallSDK:
        return self._sdk

    @property
    def recorder(self) -> Optional[FlightRecorder]:
        return self._recorder

    @property
    def agent_id(self) -> Optional[str]:
        return self._agent_id
