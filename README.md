# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.3.1

Agent Firewall v1.3.1 is a security patch release following the v1.3.0 delegated-authority rollout. It hardens delegation and attenuation across both the SDK and legacy authorization paths, while preserving existing v1.0-v1.3 behavior.

v1.3.1 adds persistent delegation lineage and capability records for SDK restart recovery, ancestor-aware revocation in the legacy `Firewall` path, and revocation propagation for genuinely distinct attenuated capabilities.

The release also adds dedicated audit regression coverage for delegation persistence, legacy revocation, attenuation revocation, semantic transaction safety, lineage-depth behavior, audit-log behavior, and cross-chain budget semantics.

## Installation

Install the v1.3.1 release from PyPI:

```bash
pip install agent-firewall-security==1.3.1
```

For the latest stable package:

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

For delegated capabilities, v1.3 and v1.3.1 additionally evaluate the effective authority represented by the complete delegation chain.

## Effective Delegated Authority

A delegation creates a parent-child authority relationship:

```text
root capability
      |
      v
child capability
      |
      v
grandchild capability
```

During SDK authorization, the complete resolved chain is evaluated:

```text
child
  -> parent
      -> ancestor
          -> root
```

The request must satisfy every capability in that chain.

For example:

```text
root:       amount_max = 1000
child:      amount_max = 500
grandchild: amount_max = 250
```

The effective authority of the grandchild cannot exceed `250`, even if an individual descendant were constructed with a broader local constraint.

Namespace restrictions are enforced across the chain as well.

If an expected ancestor cannot be resolved from the SDK capability registry, authorization fails closed with a delegation-chain error rather than treating the descendant as an independent authority.

## Delegation Lineage

The runtime `DelegationLineage` registry tracks:

```text
child fingerprint -> parent fingerprint -> ancestor
```

The lineage implementation provides parent lookup, complete ancestry traversal, descendant checks, snapshots, cycle detection, maximum-depth enforcement, and thread-safe access.

v1.3.1 adds persistent delegation lineage and signed capability records through the optional SDK delegation store so a delegated capability does not silently become root authority after restart.

Revocation remains owned by the SDK revocation registry. Effective authorization consults the resolved delegation chain so revoked ancestors cannot be bypassed by descendants.

Revoking an intermediate delegated capability also invalidates its descendants.

## Adversarial Delegation Security

v1.3 explicitly tests attempts to:

- launder broader constraints through nested delegation
- escalate capability namespaces
- escape authority restrictions through deep delegation
- bypass revoked parents
- bypass revoked intermediate capabilities
- contaminate sibling delegation trees
- use unrelated capability trees as ancestors
- authorize with missing ancestor state

v1.3.1 extends this coverage to:

- persistence across SDK restart
- legacy `Firewall` ancestor-aware revocation
- attenuation-parent revocation propagation
- no-op attenuation compatibility
- delegation and attenuation lineage persistence

These cases are required to fail closed.

## Concurrency Security

v1.3 adds race-condition coverage for:

- concurrent authorization
- authorization during revocation
- concurrent sibling authorization
- concurrent delegation registration
- concurrent lineage reads
- concurrent root revocation
- repeated authorization after revocation

The lineage registry uses synchronized access so concurrent reads and writes do not silently corrupt ancestry state.

## Security Context

`SecurityContext` provides optional per-agent runtime controls for cumulative security state, including action counts, cumulative amounts, denial tracking, and capability usage tracking.

This allows policies to account for accumulated activity rather than evaluating every request in isolation.

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

Policies can also be composed with `and`, `or`, and `not`.

Existing v1.0 forms such as `amount_max`, `amount_min`, lists, nested constraints, and literal equality remain supported.

## Key Management and Identity Binding

v1.1 managed capabilities include a stable `key_id` bound into the signed capability data.

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
```

Private signing-key material is encrypted at rest. The master key is supplied by the application and is not stored by Agent Firewall.

## Persistent Delegation Storage

v1.3.1 can persist delegation lineage and the signed capability records needed to reconstruct effective delegated authority:

```python
sdk = FirewallSDK(
    delegation_store_path="firewall-delegations.db",
    key_store_path="firewall-keys.db",
    master_key=master_key,
)
```

The delegation store persists child-to-parent lineage and signed capability records. Private signing-key material remains in the key store and is never written to the delegation store.

## Persistent Replay Protection

v1.1 can persist replay state across SDK restarts:

```python
sdk = FirewallSDK(
    replay_store_path="firewall-replay.db",
)
```

A consumed nonce remains consumed across normal restart until its validity window expires.

## Revocation

```python
sdk.revoke(
    capability,
    reason="compromised",
)
```

Revocation is one-way. A revoked capability cannot become authorized again because of SDK restart, key rotation, lifecycle history, or cached state.

v1.3.1 also ensures that parent revocation propagates through delegated and genuinely distinct attenuated descendants.

## MCP Security Adapter

The MCP adapter sits at the authorization boundary immediately before a tool is executed.

```python
from firewall.mcp import MCPFirewall

firewall = MCPFirewall(
    sdk,
    require_nonce=True,
)
```

Denied requests never reach the handler.

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

v1.3.1 treats a genuinely narrower attenuation as a child in the same lineage used for effective revocation. A no-op attenuation that produces the exact same signed capability remains backward compatible and does not create a self-parent cycle.

Capabilities can also be delegated:

```python
delegation = sdk.delegate(
    capability,
    private_key,
    delegatee="agent-b",
)
```

v1.3 extends delegation from lineage tracking and revocation propagation to complete effective-authority enforcement during authorization.

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

v1.3 includes dedicated coverage for:

- effective delegated authority
- complete parent and ancestor authorization
- delegation constraint attenuation
- namespace non-escalation
- fail-closed missing ancestor resolution
- delegation cycle and depth protection
- parent and descendant revocation
- adversarial constraint laundering
- deep delegation escalation
- revoked-parent and revoked-intermediate bypasses
- sibling and unrelated-tree isolation
- concurrent authorization and revocation
- concurrent delegation and lineage access
- refusal-state interactions
- replay and fresh-nonce adversarial cases
- adapter authorization boundaries
- persistence and concurrency security invariants

v1.3.1 adds dedicated security-audit regression coverage around delegation persistence, legacy authorization-path consistency, attenuation revocation propagation, semantic transaction lock lifecycle, lineage boundary semantics, audit-log behavior, and cross-chain budget behavior.

## Security Invariants

Important invariants include:

```text
REVOKED  -> USED    forbidden
EXPIRED  -> USED    forbidden
REPLAYED -> USED    forbidden
DENIED   -> USED    forbidden
```

Delegation invariants include:

```text
child authority > parent authority        forbidden
namespace escalation                      forbidden
revoked ancestor -> descendant authorized forbidden
missing ancestor -> descendant authorized forbidden
delegation cycle                          forbidden
excessive delegation depth                forbidden
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
- effective-authority tests
- adversarial escalation tests
- adversarial concurrency tests
- semantic-chain tests
- semantic transaction tests
- final security audit tests
- performance benchmarks

Run the complete suite:

```bash
pytest -q
```

The local v1.3.1 validation run contains **2,073 passing tests**.

## Continuous Integration

The security workflow runs the full regression suite across Python 3.10, 3.11, and 3.12, including the v1.3 branch.

## Package

PyPI distribution:

```text
agent-firewall-security
```

v1.3.1 install:

```bash
pip install agent-firewall-security==1.3.1
```

For the latest stable release:

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

Current release:

```text
1.3.1
```

## License

See the repository license file for licensing information.
