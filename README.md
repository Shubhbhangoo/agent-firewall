 Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between agents and the actions they are allowed to perform.

## v1.0

Agent Firewall v1.0 is the first stable release.

### Core security

- Capability-based authorization
- Cryptographic capability verification
- Capability attenuation
- Capability delegation
- Capability revocation
- Replay protection
- Lifecycle recording
- Expiration enforcement
- Issuer trust management
- Signing-key rotation
- Key retirement
- Fail-closed authorization semantics

### Persistent security state

v1.0 supports persistent managed signing keys and issuer trust state.

```python
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

Private signing keys are encrypted at rest.

The master key is supplied by the application and is never stored by Agent Firewall.

Key rotation
sdk.rotate_key("key-2")

Rotation creates a new active signing key and retires the previous one.

Previously issued capabilities are not automatically revoked.

Issuer trust
sdk.trust_issuer("issuer-a")
sdk.revoke_issuer("issuer-a")

Issuer trust state can survive SDK restart when persistent key storage is enabled.

Legacy issuance

The existing direct-key API remains supported:

sdk.issue(
    private_key=private_key,
    agent="agent-a",
    capability="payments.send",
)
CLI
firewall init
firewall validate
firewall inspect-token
firewall explain
Security testing

The project includes:

unit tests
integration tests
property-based tests
state-machine tests
persistence failure tests
adapter interoperability tests
benchmark coverage

The CI security matrix runs the complete test suite on Python 3.10, 3.11, and 3.12.

Installation
pip install agent-firewall
Documentation

See:

docs/v1.0-api-contract.md
docs/v1.0-security.md
docs/v1.0-key-management.md

### `CHANGELOG.md`

Create or update:

```md
# Changelog

All notable changes to Agent Firewall are documented here.

## [1.0.0] - 2026-08-23

### Added

- Stable v1.0 public API contract
- Managed capability signing keys
- Signing-key rotation
- Signing-key retirement
- Persistent encrypted signing-key storage
- Persistent issuer trust state
- Issuer trust and revocation management
- Persistent lifecycle and revocation support
- Generic tool adapter
- OpenAI tool adapter
- Anthropic tool adapter
- Capability normalization
- Capability explanation and denial reporting
- CLI commands:
  - `firewall init`
  - `firewall validate`
  - `firewall inspect-token`
  - `firewall explain`
- Property-based security tests
- Lifecycle state-machine security tests
- Persistence failure and corruption tests
- CI security regression matrix
- Python 3.10, 3.11, and 3.12 CI coverage
- v1.0 security and key-management documentation

### Security

- Authorization fails closed when critical security state cannot be verified.
- Persistent key-store failures do not silently fall back to cached or newly generated signing authority.
- Retiring or rotating a key does not implicitly grant or revoke capability authority.
- Revoked, expired, replayed, and denied capabilities cannot transition into successful use.
- Private signing-key material is encrypted at rest in persistent storage.

### Compatibility

- Existing direct `private_key=` capability issuance remains supported.
- v0.9 CLI commands remain available.
- Existing adapter security semantics continue to use the same authorization core.