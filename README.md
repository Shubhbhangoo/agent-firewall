# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.4.0

v1.4 is the architecture-hardening release following the v1.3.1 security patch.

This release strengthens cumulative budget enforcement, persistence, concurrency, recovery, and authorization atomicity across the semantic and security layers.

### Highlights

- Cross-chain cumulative semantic budgets with `max_total_amount`.
- Atomic cross-chain budget reservations under the existing semantic lock.
- Persistent `SecurityContext` state across SDK/process restart.
- Integrity-checked security state with atomic file replacement.
- Cross-process persistent-budget locking to prevent lost updates and double-spend races.
- Fail-closed handling for corrupted, truncated, tampered, or incompatible persisted state.
- Stable audit-log path resolution independent of process working directory.
- Authorization atomicity coverage across `SemanticChainContext` and `SecurityContext`.
- Persistence recovery and interruption testing.
- Expanded concurrency and adversarial security regression coverage.

## Installation

### v1.4.0

```bash
pip install agent-firewall-security==1.4.0
```

Latest stable:

```bash
pip install agent-firewall-security
```

Python import package:

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
    {"amount": 20},
)

print(result.allowed)
```

## Core Security Model

Agent Firewall uses signed capabilities as the authority presented for an operation. Authorization verifies capability validity, cryptographic integrity, issuer trust, expiration, revocation, constraints, and replay state where applicable.

Delegated capabilities are evaluated against their effective authority chain rather than being treated as isolated bearer objects.

## Delegation and Revocation

Delegation is tracked as:

```text
child fingerprint -> parent fingerprint -> ancestor
```

The complete chain is evaluated at authorization time. Revocation of a parent or intermediate authority propagates to descendants.

v1.3.1 added persistent delegation lineage and ancestor-aware legacy revocation. v1.4 preserves those guarantees while extending persistence and concurrency hardening around runtime security state.

## Attenuation

Capabilities can be narrowed without widening authority:

```python
child = sdk.attenuate(
    capability,
    private_key,
    constraints={
        "amount_max": 50,
    },
)
```

Genuinely distinct attenuated capabilities participate in the same lineage used for effective revocation. No-op attenuation remains backward compatible when it produces the same signed capability.

## Semantic Chain Security

`SemanticChainContext` provides deterministic workflow protection for multi-step sequences.

Semantic history is scoped by explicit `chain_id` values, while v1.4 can enforce a cumulative amount budget across all chains in the context:

```python
from firewall.semantic_chain import SemanticChainContext

semantic = SemanticChainContext(
    agent="agent-a",
    max_total_amount=1000,
)
```

The cross-chain budget is checked atomically under the existing semantic lock. Failed transactions release their reservation, and concurrent chains cannot overspend the configured limit.

## Persistent Security Context

v1.4 adds optional persistence for cumulative security state:

```python
from firewall.security_context import SecurityContext

security = SecurityContext(
    agent="agent-a",
    max_total_amount=1000,
    state_path="security-state.json",
)
```

Persisted state includes action count, cumulative amount, denial count, and used capability fingerprints.

State is integrity checked and written through atomic replacement. Corrupted or incompatible state fails closed instead of silently resetting to zero.

Persistent contexts sharing the same state file use a sidecar file lock around the read-check-mutate-write sequence to prevent lost updates across processes.

The SDK can create a persistent context with:

```python
security = sdk.create_security_context(
    agent="agent-a",
    max_total_amount=1000,
    state_path="security-state.json",
)
```

## Authorization Atomicity

When both semantic and runtime security contexts are enabled, the authorization path is:

```text
primitive authorization
        -> semantic authorization
        -> SecurityContext budget check + record
        -> semantic commit
```

If downstream security authorization fails, the semantic transaction is aborted. Concurrent and failure-path regression coverage verifies that neither layer is left with a partially committed state.

## Audit Logging

The legacy firewall audit log uses a stable path derived from the policy location rather than the process working directory. This prevents daemon restarts or working-directory changes from silently creating a separate hash chain.

Audit entries maintain an integrity hash chain and can be verified with the firewall's audit-chain verification path.

## Security Hardening

v1.4 adds regression coverage for:

- cross-chain cumulative budgets
- concurrent budget races
- persistent budget restart recovery
- cross-process persistent state races
- corrupted and tampered persistent state
- failed atomic writes
- stale temporary files
- authorization atomicity between semantic and security state
- audit-log path stability across working-directory changes
- delegation and attenuation revocation behavior from v1.3.1

## Testing

Run the complete suite:

```bash
pytest -q
```

The local v1.4 validation run contains **2,106 passing tests**.

## CI

Security CI runs the full regression suite on Python 3.10, 3.11, and 3.12 for the maintained release branches, including `v1.4`.

## Package

PyPI distribution:

```text
agent-firewall-security
```

Install v1.4.0:

```bash
pip install agent-firewall-security==1.4.0
```

Repository:

```text
https://github.com/Shubhbhangoo/agent-firewall
```

## Version

```text
1.4.0
```

## License

See the repository license file for licensing information.
