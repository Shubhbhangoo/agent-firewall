# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool execution.

Agent Firewall combines policy enforcement with cryptographically signed capabilities, controlled delegation, replay protection, decision evidence, persistent security state, rate limits, budgets, approvals, and tamper-evident audit logging.

## v0.6

v0.6 is the capability-security release. It turns capabilities into a first-class authorization layer and integrates them directly into the firewall engine.

### Security flow

A protected tool request can pass through these controls:

```text
Agent identity
      ↓
Capability signature
      ↓
Capability scope / namespace
      ↓
Constraints
      ↓
Expiration
      ↓
Policy
      ↓
Replay protection
      ↓
Rate limits / budgets
      ↓
Approval
      ↓
Decision evidence + audit
```

The controls are layered. Passing one control does not bypass the others.

## Signed capabilities

Capabilities are cryptographically signed permissions bound to an agent and issuer.

```python
capability = sign_capability(
    private_key=private_key,
    agent_id="finance-agent",
    capability="payments.send",
    constraints={"amount_max": 100},
    issuer="trusted-issuer",
)
```

The firewall verifies the capability before authorizing the tool action.

## Namespaces

Capabilities use explicit namespaces with optional descendant wildcards:

```text
payments.send
payments.refund
payments.*
```

Examples:

```text
payments.*     → payments.send     ✅
payments.*     → payments.refund   ✅
payments.send  → payments.admin    ❌
payments.*     → accounts.read     ❌
```

Namespace matching is designed to prevent prefix confusion and wildcard escalation.

## Attenuation

A capability can be narrowed without increasing authority.

```text
Parent:
  payments.*
  amount_max = 1000

Child:
  payments.*
  amount_max = 100
```

Attenuation prevents:

- increasing limits
- extending expiration
- broadening capability scope
- removing restrictions in a way that increases authority

## Delegation

A capability can be delegated to another agent with equal or reduced authority.

```text
agent-a
   │
   └── delegates payments.* / amount_max=100
             │
             └── agent-b
```

Delegation is bound to the intended delegatee and preserves issuer, signing authority, scope, constraints, and expiration boundaries.

## Replay protection

v0.6 adds nonce-based replay protection.

Replay keys are bound to:

```text
agent identity
capability fingerprint
nonce
```

The first valid use is accepted. Reuse of the same replay key is rejected. The replay cache is concurrency-safe and removes expired entries.

## Decision evidence

Every firewall decision can carry structured evidence explaining the result.

Evidence can include:

```text
agent_id
capability
namespace_match
constraints_ok
time_valid
policy
request_id
reason
```

Evidence supports deterministic JSON serialization and SHA-256 fingerprints. Sensitive values such as private keys, passwords, tokens, seeds, and mnemonics are filtered from evidence details.

## Existing firewall controls

v0.6 preserves the established policy controls from earlier releases:

- allow / deny / approval decisions
- approval request binding and single-use approvals
- per-agent budgets
- rate limits
- persistent security state across restart
- tamper-evident audit logging
- legacy string-based capability compatibility

## Testing

The v0.6 release passes the complete repository test suite:

```text
737 passed
```

Run everything:

```powershell
pytest -q
```

Run the final adversarial suite:

```powershell
pytest test_v06_final_adversarial.py -v
```

## Project status

- `v0.5` is the previous stable release.
- `v0.6` is the current capability-security release.

Security-sensitive deployments should review policy configuration, capability issuance, identity verification, approval workflows, and operational logging before production use.

## License

See the repository license file for licensing terms.
