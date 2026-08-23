# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.0

Agent Firewall v1.0 is the first stable release.

It provides capability authorization, cryptographic verification, revocation, replay protection, lifecycle recording, managed signing-key rotation, persistent security state, and adapter-level enforcement.

## Installation

Install from PyPI:

```bash
pip install agent-firewall-security

The Python package is imported as:

from firewall.sdk import FirewallSDK
Quick Start
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
Core Security Model

Agent Firewall uses capabilities as the authority presented for an operation.

Authorization is not granted merely because a capability exists.

The firewall verifies the relevant security state before allowing an operation, including:

capability validity
cryptographic verification
issuer trust
expiration
revocation state
requested action
request constraints
replay state where applicable
Capabilities

Capabilities can be issued for specific agents and actions.

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

Capabilities can also carry constraints and expiration information.

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    constraints={
        "currency": "USD",
        "max_amount": 100,
    },
)
Authorization
result = sdk.authorize(
    capability,
    "payments.send",
    {
        "currency": "USD",
        "amount": 25,
    },
)

if result.allowed:
    print("authorized")
else:
    print(result.reason)

A boolean helper is also available:

allowed = sdk.is_authorized(
    capability,
    "payments.send",
    {
        "currency": "USD",
        "amount": 25,
    },
)
Key Management

v1.0 supports managed Ed25519 signing keys.

Create a key:

sdk.generate_key("key-1")

Issue using the active key:

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

Select a specific active key:

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    key_id="key-1",
)

Inspect the active key:

active = sdk.active_key()

print(active.key_id)
print(active.active)
Key Rotation

Rotate to a new signing key:

sdk.rotate_key("key-2")

After rotation, new managed-key capabilities use the new active key.

Previously issued capabilities are not automatically revoked.

first = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

sdk.rotate_key("key-2")

second = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

Both capabilities remain independently verifiable unless another security rule causes one to be denied.

Key Retirement

Retire a managed signing key:

sdk.retire_key("key-1")

A retired key cannot be used for new managed-key issuance.

Retirement does not automatically revoke capabilities that were already issued with that key.

If there is no active managed signing key, managed-key issuance fails explicitly.

The SDK does not silently generate a replacement signing authority.

Persistent Key Storage

Managed signing keys can survive normal SDK restart through encrypted SQLite storage.

import os

from firewall.sdk import FirewallSDK

master_key = os.urandom(32)

sdk = FirewallSDK(
    key_store_path="firewall-keys.db",
    master_key=master_key,
)

sdk.generate_key("key-1")

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
)

After restart:

sdk = FirewallSDK(
    key_store_path="firewall-keys.db",
    master_key=master_key,
)

print(
    sdk.active_key().key_id
)

Private signing-key material is encrypted at rest.

The master key is supplied by the application and is not stored by Agent Firewall.

Master Key

The master key must be exactly 32 bytes.

import os

master_key = os.urandom(32)

Applications are responsible for securely storing and supplying the master key.

Losing the master key makes encrypted private signing-key material unrecoverable.

Persistence Failure Behavior

Persistent security state is treated as authoritative.

The SDK fails explicitly when persistent state cannot be trusted.

Examples include:

wrong master key
corrupted encrypted key material
corrupted database schema
unavailable key store
closed key store
multiple active signing keys
missing active signing key

The SDK must not silently switch to a fresh or weaker security state.

Issuer Trust

Issuer trust can be managed directly:

sdk.trust_issuer("issuer-a")

Revoke issuer trust:

sdk.revoke_issuer("issuer-a")

Check trust:

trusted = sdk.is_issuer_trusted(
    "issuer-a"
)

When persistent key storage is enabled, issuer trust state survives normal SDK restart.

Revocation

Capabilities can be explicitly revoked:

sdk.revoke(
    capability,
    reason="compromised",
)

Check revocation:

sdk.is_revoked(
    capability
)

Revocation is one-way.

A revoked capability cannot become authorized again because of:

SDK restart
key rotation
key retirement
lifecycle history
cached state
Replay Protection

The SDK provides nonce consumption for replay protection:

accepted = sdk.consume_nonce(
    "agent-a",
    capability,
    "request-123",
)

A replayed nonce is rejected.

Expiration

Capabilities can be issued with explicit expiration:

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    expires_at=2000000000,
)

Expired capabilities cannot authorize new operations.

Attenuation

Capabilities can be attenuated to reduce authority:

child = sdk.attenuate(
    capability,
    private_key,
    constraints={
        "max_amount": 50,
    },
)
Delegation

Capabilities can be delegated:

delegation = sdk.delegate(
    capability,
    private_key,
    delegatee="agent-b",
)

Delegations can be verified:

valid = sdk.verify_delegation(
    delegation
)
Transport

Capabilities can be encoded and decoded for transport:

token = sdk.encode(
    capability
)

Decode:

capability = sdk.decode(
    token
)

For verified decoding:

capability = sdk.decode_verified(
    token
)

Verified decoding rejects revoked, untrusted, or cryptographically invalid capabilities.

Legacy API

The existing direct private-key issuance API remains supported.

sdk.issue(
    private_key=private_key,
    agent="agent-a",
    capability="payments.send",
)

This mode does not require managed key storage.

Managed key persistence applies to keys controlled through CapabilityKeyManager.

Adapters

Agent Firewall provides adapters for common tool-call formats while preserving the shared authorization core.

Supported adapters include:

Generic tool adapter
OpenAI tool adapter
Anthropic tool adapter

The adapter layer normalizes external tool-call representations into the same security model.

CLI

The public firewall command provides:

firewall init
firewall validate
firewall inspect-token
firewall explain

Show CLI help:

firewall --help
Security Invariants

The v1.0 suite verifies important invariants including:

REVOKED  -> USED    forbidden
EXPIRED  -> USED    forbidden
REPLAYED -> USED    forbidden
DENIED   -> USED    forbidden

Key-management invariants include:

retired key -> new managed issuance     forbidden
rotation    -> old capability revoked  forbidden
store fail  -> fresh authority         forbidden

When persistent security state cannot be verified reliably, the system fails closed.

Testing

The project includes:

unit tests
integration tests
property-based tests
state-machine tests
persistence restart tests
persistence corruption tests
adapter interoperability tests
security regression tests
performance benchmarks

Run the complete test suite:

pytest -q
Continuous Integration

The security workflow runs the complete regression suite across:

Python 3.10
Python 3.11
Python 3.12

CI runs on pushes and pull requests for the protected release branches.

Package

PyPI distribution:

agent-firewall-security

Python import package:

firewall

GitHub repository:

agent-firewall
Documentation

Additional v1.0 documentation:

docs/v1.0-api-contract.md
docs/v1.0-security.md
docs/v1.0-key-management.md
CHANGELOG.md
Version

Current stable version:

1.0.0
License

See the repository license file for licensing information.