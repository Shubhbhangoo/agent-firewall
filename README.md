# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.1

Agent Firewall v1.1.0 extends the stable v1.0 security core with persistent replay protection, signing-key identity binding, policy operators and composition, concurrency hardening, security fuzzing, and hardened MCP authorization boundaries.

## Installation

Install the stable package from PyPI:

```bash
pip install agent-firewall-security
```

The PyPI distribution name is `agent-firewall-security` and the Python import package is `firewall`.

```python
from firewall.sdk import FirewallSDK
```

## Quick Start

```python
from firewall.sdk import FirewallSDK

sdk = FirewallSDK()
sdk.generate_key("key-1")

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

result = sdk.authorize(
    capability,
    "payments.send",
    {},
)

print(result.allowed)
```

## Core Security Model

Agent Firewall uses capabilities as the authority presented for an operation.

Authorization is not granted merely because a capability exists. The firewall verifies capability validity, cryptographic integrity, issuer trust, expiration, revocation state, requested action, constraints, and replay state where applicable.

## Policy Engine

v1.1 adds explicit policy operators:

- `eq`
- `neq`
- `in`
- `not_in`
- `gte`
- `lte`
- `contains`

Example:

```python
capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    constraints={
        "amount": {
            "gte": 10,
            "lte": 100,
        },
        "currency": {
            "eq": "USD",
        },
    },
)
```

Policies can also be composed with:

```python
constraints = {
    "and": [
        {"currency": {"eq": "USD"}},
        {"amount": {"lte": 100}},
    ]
}
```

Supported composition operators are `and`, `or`, and `not`.

Existing v1.0 forms such as `amount_max`, `amount_min`, lists, nested constraints, and literal equality remain supported.

## Key Management and Identity Binding

v1.1 managed capabilities include a stable `key_id` bound into the signed capability data.

```python
sdk.generate_key("key-1")

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

print(capability.key_id)
```

Managed capability verification binds:

```text
issuer + key_id + public_key + signature
```

Rotating a key creates a new key identity for new managed capabilities while existing capabilities remain independently verifiable until they expire or are explicitly revoked.

## Persistent Key Storage

Managed signing keys can survive normal SDK restart through encrypted SQLite storage.

```python
import os
from firewall.sdk import FirewallSDK

master_key = os.urandom(32)

sdk = FirewallSDK(
    key_store_path="firewall-keys.db",
    master_key=master_key,
)

sdk.generate_key("key-1")
```

Private signing-key material is encrypted at rest. The master key is supplied by the application and is not stored by Agent Firewall.

## Persistent Replay Protection

v1.1 can persist replay state across SDK restarts:

```python
sdk = FirewallSDK(
    replay_store_path="firewall-replay.db",
)
```

A consumed nonce remains consumed across normal restart until its validity window expires.

```python
accepted = sdk.consume_nonce(
    "agent-a",
    capability,
    "request-123",
)
```

Concurrent consumption of the same replay key is serialized so only one request can win.

## Revocation

```python
sdk.revoke(
    capability,
    reason="compromised",
)
```

Revocation is one-way. A revoked capability cannot become authorized again because of SDK restart, key rotation, lifecycle history, or cached state.

## MCP Security Adapter

The MCP adapter sits at the authorization boundary immediately before a tool is executed.

```python
from firewall.mcp import MCPFirewall

firewall = MCPFirewall(
    sdk,
    require_nonce=True,
)
```

The adapter verifies the capability, binds it to the request agent, enforces replay protection, evaluates the requested tool against the capability, and only then invokes the handler.

Denied requests never reach the handler.

## Replay Protection

The SDK provides nonce consumption for replay protection:

```python
accepted = sdk.consume_nonce(
    "agent-a",
    capability,
    "request-123",
)
```

A replayed nonce is rejected.

## Expiration

Capabilities can be issued with explicit expiration:

```python
capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    expires_at=2000000000,
)
```

Expired capabilities cannot authorize new operations.

## Attenuation and Delegation

Capabilities can be attenuated:

```python
child = sdk.attenuate(
    capability,
    private_key,
    constraints={
        "amount_max": 50,
    },
)
```

Capabilities can also be delegated:

```python
delegation = sdk.delegate(
    capability,
    private_key,
    delegatee="agent-b",
)
```

## Legacy API Compatibility

The direct private-key issuance API remains supported:

```python
sdk.issue(
    private_key=private_key,
    agent="agent-a",
    capability="payments.send",
)
```

Existing v1.0 capability formats without `key_id` remain compatible with the legacy verification path.

## Adapters

Agent Firewall provides adapters for common tool-call formats while preserving the shared authorization core.

Supported adapters include:

- Generic tool adapter
- MCP firewall adapter
- OpenAI tool adapter
- Anthropic tool adapter

## CLI

The public `firewall` command provides:

```text
firewall init
firewall validate
firewall inspect-token
firewall explain
```

Show CLI help:

```bash
firewall --help
```

## Security Hardening

v1.1 includes dedicated coverage for:

- persistent replay state
- issuer and signing-key identity binding
- concurrent replay consumption
- concurrent revocation and authorization
- concurrent key rotation
- malformed and oversized input fuzzing
- malformed policy definitions
- MCP execution-boundary enforcement
- cross-cutting security invariants
- fail-closed persistence behavior

## Security Invariants

Important invariants include:

```text
REVOKED  -> USED    forbidden
EXPIRED  -> USED    forbidden
REPLAYED -> USED    forbidden
DENIED   -> USED    forbidden
```

Key-management invariants include:

```text
retired key -> new managed issuance     forbidden
rotation    -> old capability invalid  forbidden
store fail  -> fresh authority         forbidden
```

## Testing

The project includes:

- unit tests
- integration tests
- property-based tests
- state-machine tests
- persistence restart tests
- persistence corruption tests
- policy tests
- concurrency tests
- security fuzzing
- adapter security tests
- performance benchmarks

Run the complete suite:

```bash
pytest -q
```

The v1.1 release regression suite contains 1,812 passing tests.

## Continuous Integration

The security workflow runs the regression suite across Python 3.10, 3.11, and 3.12.

## Package

PyPI distribution:

```text
agent-firewall-security
```

Install:

```bash
pip install agent-firewall-security
```

Python import package:

```text
firewall
```

GitHub repository:

```text
Shubhbhangoo/agent-firewall
```

## Documentation

Additional documentation:

- `docs/v1.0-api-contract.md`
- `docs/v1.0-security.md`
- `docs/v1.0-key-management.md`
- `CHANGELOG.md`

## Version

Current stable version:

```text
1.1.0
```

## License

See the repository license file for licensing information.
