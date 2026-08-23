# Agent Firewall

Agent Firewall is a security and authorization layer for AI agents and automated tool use.

It provides authenticated agent identities, cryptographic capabilities, namespace authorization, constraints, delegation and attenuation, replay protection, MCP and HTTP authorization boundaries, policy enforcement, audit logging, decision evidence, lifecycle tracking, persistent security state, and developer-facing tool adapters.

## v0.9

v0.9 turns the v0.8 security core into a more usable developer platform without replacing the underlying authorization model.

### Developer-facing APIs

The simplest protection path uses an already-issued signed capability:

```python
from firewall.protect import protect

@protect(
    sdk=sdk,
    capability=capability,
)
def send_payment(amount):
    return amount
```

Protected callables always pass through `FirewallSDK.authorize()` before handler execution. A denied request does not reach the handler.

For reusable tool objects:

```python
from firewall.tools import ProtectedTool

tool = ProtectedTool(
    sdk=sdk,
    capability=capability,
    handler=send_payment,
)
```

### Tool adapters

v0.9 provides vendor-specific translation layers over the same security core:

```python
from firewall.adapters import (
    OpenAITool,
    AnthropicTool,
    GenericToolAdapter,
)
```

The adapters translate tool definitions and call payloads, but authorization remains inside `FirewallSDK`. They do not create permissions or bypass capability checks.

A vendor-neutral call can be normalized into `GenericToolCall`:

```python
from firewall.adapters import normalize_tool_call

call = normalize_tool_call(
    {
        "name": "payments.send",
        "arguments": {"amount": 50},
    }
)
```

### Lifecycle investigation

v0.9 adds a read-only explanation layer over lifecycle history:

```python
from firewall.explain import explain

result = explain(
    sdk.lifecycle,
    sdk.fingerprint(capability),
)

print(result.latest_type)
print(result.revoked)
print(result.denied)
```

This exposes what happened to a capability without introducing a second authorization engine.

### CLI

The package now installs a `firewall` command:

```bash
firewall --help
firewall init --path firewall.yaml
firewall validate firewall.yaml
firewall inspect-token <token>
firewall explain lifecycle.db
```

The CLI is backed by the same Python APIs used by the SDK.

### Packaging

v0.9 adds a standard `pyproject.toml` build configuration and console entry point:

```bash
pip install -e .
firewall --help
```

Development installs can include the property-based testing dependency:

```bash
pip install -e ".[dev]"
```

### Property-based security testing

v0.9 adds Hypothesis-based tests covering normalization, lifecycle snapshots, persistence round trips, authorization stability, and capability transport. The suite complements the repository's existing adversarial tests rather than replacing them.

### Performance baseline

The v0.9 benchmark suite measures capability verification, SDK authorization, tool wrappers, vendor adapters, and SQLite lifecycle storage. The current local baseline is documented in [`docs/v0.9-benchmarks.md`](docs/v0.9-benchmarks.md).

## v0.8 lifecycle and persistence

v0.8 introduced explicit capability lifecycle events and durable lifecycle state.

```text
ISSUED
DELEGATED
ATTENUATED
USED
REPLAYED
REVOKED
DENIED
EXPIRED
```

Persistent SDK state can be configured with:

```python
sdk = FirewallSDK(
    revocation_store_path="revocations.db",
    lifecycle_store_path="lifecycle.db",
)
```

Lifecycle history and revocation state survive SDK restart.

## Capabilities

Capabilities are cryptographically signed permissions.

```python
capability = sdk.issue(
    private_key=private_key,
    agent="finance-agent",
    capability="payments.send",
    constraints={
        "amount_max": 100,
    },
)
```

A capability is verified before authorization is granted.

## Namespaces

Capabilities support hierarchical namespace matching:

```text
payments.send
payments.refund
payments.*
```

A wildcard can authorize descendants without granting unrelated namespaces.

```text
payments.*     -> payments.send      allowed
payments.*     -> payments.refund    allowed
payments.send  -> payments.admin     denied
payments.*     -> accounts.read      denied
```

## HTTP authorization

The HTTP boundary maps ordinary HTTP requests into the firewall namespace model.

```text
POST /payments
        ↓
http.POST.payments
```

Nested paths are represented as namespace segments:

```text
POST /payments/refund
        ↓
http.POST.payments.refund
```

The HTTP boundary verifies the capability, binds it to the requesting agent, checks namespace and constraints, and applies replay protection before allowing handler execution.

## MCP authorization

The MCP boundary applies the same capability authorization model to MCP tool execution.

Tool authorization is checked before execution, preserving the firewall's namespace, constraint, identity, and replay semantics across the protocol boundary.

## Attenuation and delegation

Capabilities can be narrowed and delegated without increasing authority.

```text
parent:
payments.*
amount_max = 1000

child:
payments.*
amount_max = 100
```

Delegation is bound to the authorized delegatee and cannot be used to change identity, broaden scope, or extend expiration.

## Replay protection

Replay protection binds a replay key to:

```text
agent identity
capability fingerprint
nonce
```

The first valid use is accepted. Reusing the same key is rejected.

## Decision evidence

Authorization decisions can carry structured evidence describing why a decision was made.

Sensitive values such as private keys, secrets, tokens, passwords, seeds, and mnemonics are filtered from evidence details.

## Tests

The v0.9 branch contains a large regression and adversarial suite spanning the capability SDK, lifecycle and persistence layers, tool adapters, CLI, property-based testing, MCP, HTTP, and restart behavior.

Run the full suite with:

```bash
pytest -q
```

The v0.9 development checkpoint has **1602 passing tests** before the benchmark-only run.

## Project status

**v0.9 is in release preparation.**

The next release work is focused on documentation, benchmark publication, final packaging verification, and release tagging.

Before production deployment, review capability issuance, trusted issuers, agent identity configuration, policy configuration, replay settings, persistence paths, and operational logging.
