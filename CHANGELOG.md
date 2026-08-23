# Changelog

All notable changes to Agent Firewall are documented here.

## [1.0.0] - 2026-08-23

### Added

- Stable v1.0 public API contract.
- Capability-based authorization and verification.
- Capability attenuation and delegation.
- Capability revocation and expiration enforcement.
- Replay protection.
- Lifecycle recording and explanation support.
- Issuer trust management.
- Managed Ed25519 signing keys.
- Signing-key rotation and retirement.
- Persistent encrypted signing-key storage using SQLite.
- Persistent issuer trust and revocation state.
- Generic tool adapter.
- OpenAI tool adapter.
- Anthropic tool adapter.
- Capability normalization.
- CLI commands:
  - `firewall init`
  - `firewall validate`
  - `firewall inspect-token`
  - `firewall explain`
- Property-based security testing.
- Lifecycle state-machine testing.
- Persistence corruption and failure testing.
- Adapter interoperability testing.
- Performance benchmark coverage.
- CI security regression matrix for Python 3.10, 3.11, and 3.12.
- v1.0 security and key-management documentation.

### Security

- Authorization fails closed when critical security state cannot be verified.
- Persistent key-store failures do not silently fall back to cached signing authority.
- Persistent key-store failures do not silently create a new signing authority.
- Wrong master keys fail explicitly.
- Corrupted persistent key material fails explicitly.
- Corrupted persistent database state fails explicitly.
- Closed persistent stores fail explicitly.
- Multiple active signing keys are rejected.
- Retired keys cannot issue new managed capabilities.
- Key rotation does not automatically revoke previously issued capabilities.
- Revoked capabilities cannot return to an authorized state.
- Expired capabilities cannot be used.
- Replay attempts cannot become successful authorization.
- Denied lifecycle states cannot transition into successful use.
- Private signing-key material is encrypted at rest.

### Compatibility

- Existing direct `private_key=` capability issuance remains supported.
- Existing v0.9 CLI commands remain available.
- Existing adapter security semantics continue to use the shared authorization core.
- Persistent and in-memory key-management modes are supported.

### Documentation

- Added v1.0 API contract.
- Added v1.0 security model documentation.
- Added v1.0 key-management documentation.
- Added v1.0 release and package metadata.

### Testing

- Expanded the suite with property-based security tests.
- Added lifecycle state-machine tests.
- Added persistent key restart tests.
- Added persistence corruption and failure tests.
- Added adapter interoperability tests.
- Added CI regression coverage across supported Python versions.
