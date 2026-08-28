# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.6.1 North Star + Developer Console

v1.6.1 builds on **North Star**, the canonical authorization orchestration architecture for the SDK, and adds an isolated local developer/security console with an audited control plane for trusted local development.

North Star composes the existing security mechanisms without replacing their individual enforcement semantics. The authorization path is organized as deterministic, fail-closed gates covering refusal, risk, issuer trust, revocation, time validity, delegation lineage, optional delegation-depth policy, cryptographic authority, and the terminal security transaction.

### North Star highlights

- Explicit ordered authorization gates replace a monolithic authorization flow while preserving existing security behavior.
- `DelegationAuthority` is the canonical representation of effective delegation lineage during authorization.
- Missing ancestors, cycles, excessive depth, revocation, and cryptographic authority remain fail-closed.
- Optional `max_delegation_depth` provides an authorization-time lineage-depth policy without changing default behavior.
- Risk, security, semantic, and refusal contexts are carried through a per-request authorization context.
- North Star's compatibility boundary preserves `authorize()` as the decision authority while exposing a canonical orchestration path.
- North Star can publish safe delegation posture metadata such as effective delegation depth.
- The migration is additive: existing SDK mechanisms remain authoritative for their own security semantics.

### Developer security console

v1.6.1 adds a local developer/security console under `firewall/ui/`.

It visualizes and, when explicitly enabled, controls the real security system rather than implementing a second authorization engine:

- North Star authorization pipeline and gate status
- allow/deny decisions
- delegation authority and lineage
- revocation state
- risk and security posture
- lifecycle/security events
- safe capability metadata
- genuine demo scenarios driven by the real SDK
- audited agent connection and capability management
- authorization rule and delegation-depth configuration
- issue, delegate, attenuate, and revoke operations through existing SDK APIs

The console uses only the Python standard library plus vanilla HTML/CSS/JavaScript. No frontend build system or additional runtime dependency is required.

Start the read-only console locally with:

```bash
python -m firewall.ui
```

For the audited local control plane:

```bash
python -m firewall.ui --control
```

Control-plane writes require a bearer token and are routed through existing `FirewallSDK` APIs. Mutations are recorded in the local audit stream. The control plane is intended for trusted local development and must not be exposed as an unauthenticated production service.

Cryptographic private keys and signatures are excluded from console responses.

v1.6.1 validation reaches **2,453 passing tests** with zero failures.

## v1.7 Simulate Before You Enforce

v1.7 adds a rule-simulation engine under `firewall.simulation` and a
staged rollout (`observe -> warn -> enforce`) so a rule change can be
evaluated before it takes effect.

The workflow is record, simulate, promote, roll back:

- The console records every request it authorizes as a replayable case
  (material facts only -- no signatures or keys), after the verdict
  exists.
- A proposed rule change (delegation-depth ceiling, trusted-issuer set)
  is replayed against recorded traffic in throwaway workspaces by the
  real authorization pipeline, and the report shows exactly which
  requests would change outcome.
- Nothing is enforced on an unexamined guess; a change that newly denies
  recorded traffic, or that the simulator could not fully verify, is
  refused without an explicit acknowledgement written into the rollout
  history.
- Enforcing snapshots the previous rules, so rollback is always exact.

The console control plane exposes `simulate`, `promote`, and `rollback`
with the existing bearer-token and audit discipline, and the `firewall`
CLI adds `firewall simulate` as a CI gate.

See `docs/v1.7-simulation.md` for the full workflow.

## Installation

### v1.6.1

```bash
pip install agent-firewall-security==1.6.1
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

## North Star Authorization

North Star is available through the SDK compatibility boundary:

```python
result = sdk.authorize_north_star(
    capability,
    "payments.send",
    {"amount": 20},
)
```

The North Star path preserves the established authorization decision while making the orchestration structure explicit. Delegation posture is available as safe decision metadata when the effective authority chain can be resolved.

For an opt-in authorization-time lineage-depth policy:

```python
sdk = FirewallSDK(
    max_delegation_depth=4,
)
```

A request whose effective `DelegationAuthority.depth` exceeds the configured limit is denied with `delegation_depth_exceeded`. The default is disabled, preserving existing behavior for callers that do not configure a maximum.

See `docs/v1.6-security-invariants.md` for the security properties North Star must preserve and `docs/v1.6-north-star.md` for the architecture and migration model.

## Security Console Architecture

The v1.6.1 console follows this boundary:

```text
UI
 |
v
Authenticated local control boundary
 |
v
Existing FirewallSDK / North Star
 |
v
SecurityDecision + audit
```

The UI does not reimplement cryptographic verification, revocation, delegation resolution, policy evaluation, budgets, or authorization decisions. Control-plane mutations call existing SDK APIs and are audited rather than creating a parallel authorization engine.

The control plane uses a local bearer token and loopback binding by default. It is a trusted local developer interface, not a general-purpose production management service.

## Session Capabilities

v1.5 can mint short-lived capabilities bound to a concrete tool:

```python
session_cap = sdk.mint_session_capability(
    agent="agent-a",
    tool="filesystem.read",
    capability="filesystem.read",
    ttl=300,
)
```

The capability expires from a fresh session timestamp and cannot authorize a different tool.

## Tool Output Trust Boundary

Tool output is data, not authority. Protected tools mark returned text as untrusted while preserving normal string behavior.

## Core Security Model

Agent Firewall uses signed capabilities as the authority presented for an operation. Authorization verifies capability validity, cryptographic integrity, issuer trust, expiration, revocation, constraints, effective delegation authority, and replay state where applicable.

Delegated capabilities are evaluated against their effective authority chain rather than being treated as isolated bearer objects.

## Delegation, Budgets, and Revocation

Delegation is tracked as:

```text
child fingerprint -> parent fingerprint -> ancestor
```

The complete chain is evaluated at authorization time. Revocation of a parent or intermediate authority propagates to descendants.

v1.5 adds a cumulative lineage budget owned by the root capability:

```python
sdk.configure_delegation_budget(
    capability,
    max_total_amount=100,
)

sdk.authorize_with_delegation_budget(
    child_capability,
    "payments.send",
    {"amount": 40},
)
```

Parent, child, and grandchild capabilities consume the same lineage budget. Separate root capabilities maintain separate budgets.

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

Genuinely distinct attenuated capabilities participate in the same lineage used for effective revocation. No-op attenuation remains backward compatible when it produces the same signed capability and fingerprint as its parent.

## Authorization Traces

Authorization results expose a deliberately minimal security trace:

```python
result.trace
```

The trace intentionally excludes signatures, public keys, raw request payloads, and full constraint data.

## Semantic Chain Security

`SemanticChainContext` provides deterministic workflow protection for multi-step sequences.

Semantic history is scoped by explicit `chain_id` values, while v1.4 can enforce a cumulative amount budget across all chains in the context.

## Persistent Security Context

v1.4 adds optional persistence for cumulative security state through `SecurityContext(state_path=...)`. Persisted state includes action count, cumulative amount, denial count, and used capability fingerprints.

State is integrity checked and written through atomic replacement. Corrupted or incompatible state fails closed instead of silently resetting to zero.

## Numeric Security Hardening

Security-sensitive numeric inputs are required to be finite. Session TTLs, capability timestamps, verifier clocks, and delegation-budget amounts reject `NaN`, positive infinity, and negative infinity.

## Command-Line Interface

The package installs a `firewall` command with configuration validation, capability-token inspection, and persisted lifecycle inspection:

```bash
firewall init
firewall validate firewall.yaml
firewall inspect-token <token>
firewall explain lifecycle.db
firewall explain lifecycle.db --fingerprint <fingerprint>
firewall explain lifecycle.db --event-type DENIED --json
firewall simulate cases.json --max-depth 2
```

The CLI is intended for operational inspection and configuration workflows. Capability inspection should be treated as sensitive operational data, and lifecycle output should be handled according to the same security and privacy requirements as the underlying audit state.

See `docs/v1.6-cli.md` for command reference, console usage, and security boundaries.

## Audit Logging

The legacy firewall audit log uses a stable path derived from the policy location rather than the process working directory. Audit entries maintain an integrity hash chain and can be verified with the firewall's audit-chain verification path.

## Testing

Run the complete suite:

```bash
pytest -q
```

The v1.6.1 branch includes dedicated regression coverage for North Star equivalence, delegation authority, optional delegation-depth policy, observability, the developer console, the control plane, and the existing v1.5 security mechanisms.

The current v1.6.1 validation result is **2,453 passed**.

## CI

Security CI runs the full regression suite on Python 3.10, 3.11, and 3.12
for maintained release branches, including the v1.6.1-ui control-plane
branch and the v1.7 simulation branch.

CLI CI exercises the installed `firewall` command end to end on the same
matrix: configuration init/validate, the v1.7 `simulate` exit contract
(`0` safe / `1` not safe / `2` unusable inputs), JSON output, and the
CLI-focused regression suites.

## Package

PyPI distribution:

```text
agent-firewall-security
```

Install v1.7.0:

```bash
pip install agent-firewall-security==1.7.0
```

Repository:

```text
https://github.com/Shubhbhangoo/agent-firewall
```

## Version

```text
1.7.0
```

## License

See the repository license file for licensing information.
