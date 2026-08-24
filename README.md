# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.2

Agent Firewall v1.2.0 extends the stable v1.1 security core with cumulative runtime security context, delegation lineage and revocation cascades, adversarial escalation protections, deterministic semantic-chain authorization, and atomic semantic authorization transactions.

The v1.2 release focuses on a key security distinction: an individual action can be within its local limits while the accumulated sequence of actions can still form a protected workflow. Semantic-chain protection is explicit and deterministic. It does not use an LLM or probabilistic inference.

## Installation

Install the stable v1.2.0 release from PyPI:

```bash
pip install agent-firewall-security==1.2.0
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

v1.2 adds runtime security state that can evaluate cumulative behavior and explicitly configured semantic workflows in addition to individual request authorization.

## Security Context

`SecurityContext` provides optional per-agent runtime controls for cumulative security state, including action counts, cumulative amounts, denial tracking, and capability usage tracking.

This allows policies to account for accumulated activity rather than evaluating every request in isolation.

## Delegation Lineage

v1.2 tracks delegation ancestry so descendant capabilities remain connected to their parent authority.

When a parent capability is revoked, capabilities derived from that parent are invalidated through the delegation lineage. Revoking an intermediate delegated capability also invalidates its descendants.

This prevents a child capability from becoming an independent authority after its parent has been compromised or revoked.

## Semantic Chain Security

Some security decisions cannot be represented by a single request constraint.

For example, a workflow such as:

```text
payments.lookup
payments.prepare
payments.send
```

can represent a protected semantic outcome even when each individual request is within its own primitive limits.

v1.2 provides an explicit `SemanticChainContext` and `SemanticRule` model for deterministic workflow protection.

Example:

```python
from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticRule,
)

semantic_context = SemanticChainContext(
    agent="agent-a",
    rules=(
        SemanticRule(
            outcome="payments.transfer",
            sequence=(
                "payments.lookup",
                "payments.prepare",
                "payments.send",
            ),
            resource_key="account",
            allowed=False,
        ),
    ),
)

sdk = FirewallSDK(
    semantic_context=semantic_context,
)
```

Semantic state is scoped by agent and explicit `chain_id` values. Different chains do not inherit each other's semantic history.

Semantic matching can track deterministic resource identity, ordered stages, capability fingerprints, terminal outcomes, and cumulative facts such as amount.

Semantic protection is opt-in. When no semantic context is configured, existing authorization behavior remains unchanged.

## Atomic Semantic Authorization

Semantic state transitions use an explicit transaction boundary.

The authorization path is effectively:

```text
primitive authorization
        -> semantic authorization
        -> downstream SecurityContext authorization
        -> semantic commit
```

If downstream authorization rejects the request, the semantic transaction is aborted rather than leaving a partially committed semantic state.

Concurrent semantic authorization attempts are serialized so a race cannot bypass the semantic guard.

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

v1.2 additionally tracks delegation lineage for revocation propagation.

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

v1.2 includes dedicated coverage for:

- cumulative runtime security state
- parent and descendant revocation through delegation lineage
- semantic workflow escalation
- semantic resource consistency
- explicit chain isolation
- semantic transaction commit and abort ordering
- concurrent semantic authorization
- refusal-state interactions
- replay and fresh-nonce adversarial cases
- adapter authorization boundaries
- capability substitution and escalation attempts
- persistence and concurrency security invariants

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

Semantic-chain invariants include:

```text
different chain_id -> shared semantic state       forbidden
resource mismatch -> matching protected workflow  forbidden
semantic success + downstream failure -> commit   forbidden
concurrent semantic race -> unauthorized bypass  forbidden
```

Semantic rules are explicit and deterministic. The SDK does not infer semantic intent with an LLM.

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
- delegation-lineage tests
- semantic-chain tests
- semantic transaction tests
- adversarial escalation tests
- final semantic security audit tests
- performance benchmarks

Run the complete suite:

```bash
pytest -q
```

The v1.2.0 release regression suite contains **1,921 passing tests**.

## Continuous Integration

The security workflow runs the full regression suite across Python 3.10, 3.11, and 3.12, including the v1.2 branch.

## Package

PyPI distribution:

```text
agent-firewall-security
```

Stable v1.2.0 install:

```bash
pip install agent-firewall-security==1.2.0
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
1.2.0
```

## License

See the repository license file for licensing information.
