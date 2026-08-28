# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.8 Portable, Verifiable Security Memory

v1.8 adds an **Agent Security Flight Recorder**: the security-relevant
lifecycle of an agent is captured as an ordered, tamper-evident chain of
events, anchored by Ed25519 signed checkpoints, and exported as a
portable `.afw` artifact that can leave the machine and be verified by
someone who does not trust the recorder.

```bash
pip install agent-firewall-security==1.8.0
```

The workflow:

```bash
# Record a session (through the real SDK) and write the artifact
firewall record --out session.afw --agent agent-demo

# Verify it independently: chain, hashes, signatures, completeness
firewall verify session.afw                  # status: verified

# Reconstruct the security story
firewall timeline session.afw                # chronological story
firewall trajectory session.afw              # posture transitions + evidence
firewall graph session.afw --agent agent-demo --why payments.send

# Counterfactual analysis: what if the policy had been different?
firewall replay session.afw --rules proposed-rules.json

# Package an incident for sharing (verification carried verbatim)
firewall incident create session.afw --title "credential access" --out incident.json
```

Verification distinguishes five states and never conflates them:
`verified` + `failed` + `unverifiable` + `incomplete` + `redacted`.
Missing evidence is reported, never treated as trustworthy. The browser
console gains a recorder panel with the timeline, trajectory, graph,
containment, and replay laboratory; CLI and browser are one system over
the same modules.

The v1.8 architecture is strictly observational/analytical above the
existing authorization pipeline. The recorder records after decisions
exist and can never influence one; replay runs in throwaway workspaces;
containment is the only new write path and it is routed through the
SDK's own revocation and risk mechanisms -- never around `authorize()`.

See `docs/v1.8-artifact-format.md`, `docs/v1.8-verification.md`,
`docs/v1.8-security-model.md`, `docs/v1.8-cli.md`, and
`docs/v1.8-console.md`.

## v1.9 Agent Security Network

v1.9 turns Agent Firewall into a cross-agent **security system**: given
verified `.afw` artifacts from many sessions, it answers what agents can
do, what they are doing, what could happen if they were compromised, and
how to respond safely.

```bash
pip install agent-firewall-security==1.9.0
```

```bash
# Build a network from verified artifacts (failed artifacts are refused)
firewall network init --out network.json
firewall network ingest session-a.afw session-b.afw --state network.json

# Cross-agent intelligence
firewall network graph network.json --agent agent-a --reach
firewall network graph network.json --who-can-reach /etc/shadow
firewall network correlate network.json

# Deterministic, evidence-backed behavioral detection
firewall detect network.json --min-severity medium

# Attack-path discovery (reachable is not exploitable)
firewall attack-path network.json --agent agent-a --to /etc/shadow

# Isolated scenario simulation (what if this agent is compromised?)
firewall network simulate network.json scenario.json

# Policy-driven graduated response through the SDK's own mechanisms
firewall respond network.json --policy policy.json
```

Every fact in the network carries a provenance basis that is never
conflated: `observed` (recorded), `derived` (computed), `inferred`
(heuristic detection), `simulated` (scenario), `unknown` (missing).
A universal integration layer (`firewall.agents`) protects Python,
HTTP, MCP, OpenAI-compatible, and LangChain-style agents through one
adapter model, and the browser console gains a Security Operations
panel over the same modules.

See `docs/v1.9-architecture.md`, `docs/integrations.md`,
`docs/security-intelligence.md`, `docs/v1.9-cli.md`,
`docs/browser-console.md`, and `docs/v1.9-threat-model.md`.

## v1.7 Simulate Before You Enforce

v1.7 adds a rule-simulation engine under `firewall.simulation` and a staged rollout (`observe -> warn -> enforce`) so rule changes can be evaluated before they take effect.

The workflow is record, simulate, promote, and roll back:

- The console records every request it authorizes as a replayable case containing material facts only, with no signatures or key material, after the verdict exists.
- A proposed delegation-depth or trusted-issuer change is replayed against recorded traffic in isolated throwaway workspaces using the real authorization pipeline.
- Simulation reports which recorded requests would change outcome and marks cases that cannot be verified instead of silently counting them.
- Promotion is simulation-first and acknowledgement-gated when a change would newly deny recorded traffic or evidence is otherwise insufficient.
- Enforcing snapshots the previous rules so rollback is exact.

The console control plane exposes `simulate`, `promote`, and `rollback` with the existing bearer-token and audit discipline. The `firewall` CLI adds `firewall simulate` as a conservative CI gate.

See `docs/v1.7-simulation.md` for the complete workflow, fidelity model, CLI reference, control-plane endpoints, and security boundary.

### North Star authorization

v1.7 retains **North Star**, the canonical authorization orchestration architecture introduced in v1.6.1. North Star composes the existing security mechanisms without replacing their enforcement semantics. The authorization path is organized as deterministic, fail-closed gates covering refusal, risk, issuer trust, revocation, time validity, delegation lineage, optional delegation-depth policy, cryptographic authority, and the terminal security transaction.

Key properties include:

- `DelegationAuthority` is the canonical representation of effective delegation lineage during authorization.
- Missing ancestors, cycles, excessive depth, revocation, and cryptographic authority remain fail-closed.
- Optional `max_delegation_depth` provides an authorization-time lineage-depth policy without changing default behavior.
- Risk, security, semantic, and refusal contexts are carried through a per-request authorization context.
- `authorize()` remains the decision authority while exposing a canonical orchestration path.
- Existing SDK mechanisms remain authoritative for their own security semantics.

## Developer Security Console

v1.6.1 added a local developer/security console under `firewall/ui/`. It visualizes and, when explicitly enabled, controls the real security system rather than implementing a second authorization engine.

It provides:

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

## Installation

Latest release:

```bash
pip install agent-firewall-security==1.9.0
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

## Rule Simulation

Recorded cases can be evaluated before a rule change is enforced:

```bash
firewall simulate cases.json --max-depth 2
firewall simulate cases.json --rules proposed-rules.json --baseline current-rules.json
firewall simulate cases.json --rules proposed-rules.json --json
```

Exit status is deliberately conservative:

- `0`: nothing that works today would be denied and every case was verified.
- `1`: the change is not safe to enforce silently.
- `2`: the inputs could not be used.

See `docs/v1.7-simulation.md` for the full simulation and rollout model.

## Security Model

Agent Firewall uses signed capabilities as the authority presented for an operation. Authorization verifies capability validity, cryptographic integrity, issuer trust, expiration, revocation, constraints, effective delegation authority, and replay state where applicable.

Delegated capabilities are evaluated against their effective authority chain rather than being treated as isolated bearer objects.

### Delegation, budgets, and revocation

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

### Attenuation

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

### Tool output trust boundary

Tool output is data, not authority. Protected tools mark returned text as untrusted while preserving normal string behavior.

### Authorization traces

Authorization results expose a deliberately minimal security trace:

```python
result.trace
```

The trace intentionally excludes signatures, public keys, raw request payloads, and full constraint data.

### Semantic chain security

`SemanticChainContext` provides deterministic workflow protection for multi-step sequences.

Semantic history is scoped by explicit `chain_id` values, while v1.4 can enforce a cumulative amount budget across all chains in the context.

### Persistent security context

v1.4 adds optional persistence for cumulative security state through `SecurityContext(state_path=...)`. Persisted state includes action count, cumulative amount, denial count, and used capability fingerprints.

State is integrity checked and written through atomic replacement. Corrupted or incompatible state fails closed instead of silently resetting to zero.

### Numeric security hardening

Security-sensitive numeric inputs are required to be finite. Session TTLs, capability timestamps, verifier clocks, and delegation-budget amounts reject `NaN`, positive infinity, and negative infinity.

## Command-Line Interface

The package installs a `firewall` command with configuration validation, capability-token inspection, persisted lifecycle inspection, and v1.7 rule simulation:

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

See `docs/v1.6-cli.md` for the command reference and `docs/v1.7-simulation.md` for simulation details.

## Security Console Architecture

The console follows this boundary:

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

The UI does not reimplement cryptographic verification, revocation, delegation resolution, budgets, policy evaluation, or authorization decisions. Control-plane mutations call existing SDK APIs and are audited rather than creating a parallel authorization engine.

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

## Testing

Run the complete suite:

```bash
pytest -q
```

The v1.7 branch includes dedicated regression coverage for rule simulation, replay fidelity, staged rollout, control-plane integration, the CLI exit contract, the developer console, North Star, and the existing security mechanisms.

The v1.9 validation result is **2,700+ passing tests**, including dedicated v1.8 recorder, verifier, adversarial, fixture, projection, and integration suites.

## CI

Security CI runs the regression suite on Python 3.10, 3.11, and 3.12 for maintained release branches, including the v1.7 simulation branch.

CLI CI exercises the installed `firewall` command end to end on the same matrix, including configuration init/validate, the v1.7 `simulate` exit contract, JSON output, and CLI-focused regression suites.

## Package

PyPI distribution:

```text
agent-firewall-security
```

Repository:

```text
https://github.com/Shubhbhangoo/agent-firewall
```

## Version

```text
1.9.0
```

## License

See the repository license file for licensing information.
