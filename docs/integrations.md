# v1.9 Integrations Guide

The universal agent integration layer (`firewall.agents`) lets Agent
Firewall protect agents across environments with one shared model:
identity, capabilities, protect, observe, and context. Every protected
call is authorized by the real `FirewallSDK` pipeline before the tool
runs, and every outcome is recorded in the flight recorder afterward.

## Quick start (Python agent)

```python
from firewall.agents import PythonAgentAdapter
from firewall.recorder import FlightRecorder
from firewall.sdk import FirewallSDK

recorder = FlightRecorder(session_id="my-session", agent="agent-a")
sdk = FirewallSDK(recorder=recorder)
sdk.generate_key("key-1")

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    constraints={"amount_max": 100},
)

adapter = PythonAgentAdapter(
    sdk=sdk,
    agent_id="agent-a",
    recorder=recorder,
    correlation_id="campaign-1",
)

def charge(amount):
    return f"charged {amount}"

def request_builder(args):
    return {"amount": args.get("amount")}

protected = adapter.protect(
    charge,
    name="payments.send",
    capability=capability,
    request_builder=request_builder,
)

protected({"name": "payments.send", "arguments": {"amount": 20}})  # allowed
# permission errors raise PermissionError with the SDK's reason
```

The protected tool now enforces the same constraints, revocation,
delegation, and risk gates as any other SDK authorization, and the
decision is captured in the artifact.

## Other environments

All adapters share the same constructor keywords (`sdk`, `agent_id`,
`recorder`, `correlation_id`, `parent_agent`).

### HTTP/API agents

```python
from firewall.agents import HTTPAgentAdapter

adapter = HTTPAgentAdapter(
    sdk=sdk,
    agent_id="agent-a",
    endpoint_to_action={"/charge": "payments.send"},
)

wrapped = adapter.protect_endpoint("/charge", charge, capability=capability)
wrapped(amount=5)  # authorized as payments.send

# Unmapped endpoints refuse with an explanation, never a guess.
```

`authorize_request(endpoint=..., request=...)` authorizes without
executing, returning the raw `AuthorizationResult`.

### MCP systems

```python
from firewall.agents import MCPAgentAdapter

adapter = MCPAgentAdapter(sdk=sdk, agent_id="agent-a")
protected = adapter.protect_mcp_tool(
    "payments.send", charge, capability=capability,
    request_builder=request_builder,
)
```

Wire handling stays in the existing `firewall.mcp` transport; the
adapter owns authorization.

### OpenAI-compatible interfaces

```python
from firewall.agents import OpenAIAgentAdapter

adapter = OpenAIAgentAdapter(sdk=sdk, agent_id="agent-a")
adapter.call_tool(
    {"name": "payments.send", "arguments": {"amount": 10}},
    handler=charge,
    capability=capability,
    request_builder=request_builder,
)
```

### LangChain / LangGraph-style systems

```python
from firewall.agents import LangChainAgentAdapter

adapter = LangChainAgentAdapter(sdk=sdk, agent_id="agent-a")
adapter.call_tool(
    {"name": "payments.send", "args": {"amount": 5}},   # langchain shape
    handler=charge,
    capability=capability,
    request_builder=request_builder,
)
```

The langchain adapter is structure-only: it works without the langchain
dependency installed, accepting the `name` + `args`/`arguments` shape.

### Registry

```python
from firewall.agents import create_adapter

adapter = create_adapter("python", sdk=sdk, agent_id="agent-a")
```

Unknown environments raise immediately, so an agent is never silently
left unprotected.

## Graceful degradation

The adapter contract never fabricates information:

- No agent id provided -> `identity()["complete"] is False`,
  `capabilities() == ()`.
- Unmapped HTTP endpoint -> the wrapper refuses with a `PermissionError`
  explaining that no authorization action is mapped.
- A tool call that is not a mapping or `GenericToolCall` -> `TypeError`.
- A recorder failure -> the call still succeeds (the recorder is
  observational).

Missing evidence is never treated as trusted evidence: an agent without
an identity is simply not attributed, and its actions are still
authorized (or denied) by the real pipeline.

## Recording

Every adapter can `record(EventType, payload)` into the flight recorder
(identity, parent, correlation ids flow through `context()`). Protected
calls automatically record `tool_result` events after execution, so the
resulting artifact tells the full story: issued, authorized, used,
result.
