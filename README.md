# Agent Firewall

Agent Firewall is a security and authorization layer for AI agents and automated tool use.

It provides authenticated agent identities, capability-based authorization, namespace controls, constraint enforcement, delegation and attenuation, replay protection, MCP authorization, HTTP authorization, policy enforcement, audit logging, decision evidence, and persistent security state.

## v0.8

v0.8 extends the capability security model with explicit lifecycle tracking and durable lifecycle state.

### v0.8 lifecycle

Every capability can now be represented through a defined lifecycle:

```text
ISSUED
   ↓
DELEGATED
   ↓
ATTENUATED
   ↓
USED
   ↓
REPLAYED
   ↓
REVOKED
   ↓
DENIED
   ↓
EXPIRED
```

The lifecycle events are recorded with capability fingerprints and structured metadata. Terminal authorization outcomes are distinguished from successful use, replay detection, revocation, and expiration.

### v0.8 persistence

v0.8 adds SQLite-backed lifecycle persistence alongside persistent capability revocation.

```text
Agent Firewall SDK
       │
       ├── capability authorization
       │
       ├── revocation registry
       │       └── SQLite revocation store
       │
       └── lifecycle recorder
               └── SQLite lifecycle store
```

Lifecycle history survives SDK and recorder restart. The SDK can be configured with:

```python
sdk = FirewallSDK(
    revocation_store_path="revocations.db",
    lifecycle_store_path="lifecycle.db",
)
```

The existing in-memory behavior remains the default when no lifecycle store path is supplied.

### v0.8 lifecycle controls

- Capability issuance lifecycle events
- Delegation lifecycle events
- Attenuation lifecycle events
- Successful-use lifecycle events
- Replay detection lifecycle events
- Revocation lifecycle events
- Authorization-denial lifecycle events
- Expiration lifecycle events
- SQLite lifecycle persistence
- Lifecycle restoration after restart
- Cross-layer revocation and lifecycle persistence
- Concurrent lifecycle writes
- Lifecycle corruption detection
- Nested request snapshot protection
- Public package exports for v0.8 primitives

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

## Attenuation

Capabilities can be narrowed without increasing authority.

```text
parent:
payments.*
amount_max = 1000

child:
payments.*
amount_max = 100
```

An attenuated capability cannot extend its expiration, broaden its scope, or increase an existing constraint.

## Delegation

A capability can be delegated to another agent with reduced authority.

```text
agent-a
  |
  +-- delegates payments.* with amount_max=100
          |
          +-- agent-b
```

Delegation is bound to the authorized delegatee and cannot be used to change identity, increase authority, or extend expiration.

## Replay protection

Replay protection binds a replay key to:

```text
agent identity
capability fingerprint
nonce
```

The first valid use is accepted. Reusing the same key is rejected.

Replay detection is represented in the lifecycle stream as `REPLAYED`.

## Decision evidence

Authorization decisions can carry structured evidence describing why a decision was made.

Evidence can include:

- agent identity
- capability
- namespace match
- constraint result
- time validity
- policy
- request ID
- authorization reason

Sensitive fields such as private keys, secrets, tokens, passwords, seeds, and mnemonics are filtered from evidence details.

## Persistence model

Revocation and lifecycle state use separate stores so the two histories can be reasoned about independently while still being integrated by the SDK.

A persistent SDK instance can be restarted without losing:

- revoked capability state
- lifecycle history
- lifecycle ordering
- lifecycle details

See:

- [`docs/v0.8-architecture.md`](docs/v0.8-architecture.md)
- [`docs/v0.8-threat-model.md`](docs/v0.8-threat-model.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Existing controls

Agent Firewall also provides:

- policy-based allow, deny, and approval decisions
- approval request binding
- budget enforcement
- rate limiting
- persistent firewall state
- tamper-evident audit logging
- compatibility with legacy string-based capabilities

## Tests

The v0.8 branch has a comprehensive regression and adversarial suite covering the capability SDK, lifecycle state, lifecycle persistence, MCP boundary, HTTP boundary, restart behavior, and security edge cases.

The current release checkpoint contains **1438 passing tests**.

Run the full suite with:

```bash
pytest -q
```

## Project status

**v0.8.0 is released and security-tested.**

The v0.8 branch contains the capability SDK, transport layer, MCP and HTTP authorization boundaries, explicit capability lifecycle tracking, persistent revocation, persistent lifecycle history, and adversarial regression coverage.

Before production deployment, review capability issuance, trusted issuers, agent identity configuration, policy configuration, replay settings, persistence paths, and operational logging.
