# Agent Firewall

Agent Firewall is a security and authorization layer for AI agents and automated tool use.

It provides authenticated agent identities, capability-based authorization, namespace controls, constraint enforcement, delegation and attenuation, replay protection, MCP authorization, HTTP authorization, policy enforcement, audit logging, and decision evidence.

## v0.7

v0.7 extends capability security to external tool and protocol boundaries.

### v0.7 security boundaries

- Capability SDK
- Signed capability transport tokens
- Capability verification before authorization
- Namespace-based authorization
- Capability attenuation
- Capability delegation
- Replay protection
- MCP authorization boundary
- HTTP authorization boundary
- HTTP method and path to firewall namespace mapping
- Request constraint enforcement
- Agent-to-capability identity binding
- Adversarial security testing
- Decision evidence
- Audit logging

The controls are layered. Passing one layer does not automatically bypass another.

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

The v0.7 HTTP boundary maps ordinary HTTP requests into the firewall namespace model.

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

Malformed paths, path traversal patterns, method confusion, invalid capabilities, cross-agent use, replay, and unauthorized handlers are rejected.

## MCP authorization

The v0.7 MCP boundary applies the same capability authorization model to MCP tool execution.

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

Replay protection is concurrency-safe and expires old entries.

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

The v0.7 development branch has a comprehensive regression suite covering the capability SDK, transport, MCP boundary, HTTP boundary, and adversarial security cases.

Run the full suite with:

```bash
pytest -q
```

Run the HTTP adversarial suite with:

```bash
pytest test_v07_http_adversarial.py -v
```

## Project status

**v0.7 is feature-complete and security-tested.**

The v0.7 branch contains the MCP and HTTP authorization boundaries alongside the capability SDK and transport layer.

Before production deployment, review capability issuance, trusted issuers, agent identity configuration, policy configuration, replay settings, and operational logging.
