# Changelog

All notable changes to Agent Firewall are documented here.

## [0.4.0] - 2026-08-21

### Added

- Cryptographic agent identity support
- Public-key and signature fields on agent identities
- Trusted issuer verification
- Explicit authenticated-identity enforcement
- Identity-bound authorization checks
- Key lifecycle management
- Active, rotated, revoked, retired, and unknown key states
- Key rotation and retirement operations
- Persistent key revocation state
- Concurrent revocation handling
- Identity-aware audit logging
- SHA-256 audit integrity hashes
- Chained audit records using previous-entry hashes
- Audit-chain verification
- Audit-chain persistence across firewall restarts
- Audit tampering attack tests
- Expanded v0.4 adversarial security coverage

### Security

- Unauthenticated identities are denied before policy authorization
- Cryptographic identity verification is enforced when configured
- Authorization remains bound to the verified agent identity
- Revoked and retired keys are not accepted
- Audit records are tamper-evident through integrity hashes
- Audit records form a cryptographic chain
- Modified, reordered, deleted, malformed, or forged audit records can be detected
- Audit-chain state survives verifier and firewall restarts
- Existing strongest-restriction precedence remains:
  `allow < approval < deny`

### Testing

The v0.4.0 test suite contains:

**264 passing tests**

Coverage includes:

- Policy enforcement
- Policy validation
- Policy conflicts
- Policy precedence
- Policy specificity
- Agent identity
- Cryptographic identity
- Identity spoofing
- Identity authentication
- Identity-policy binding
- Key management
- Key lifecycle
- Key revocation
- Revocation persistence
- Revocation concurrency
- Identity-aware auditing
- Audit integrity
- Audit-chain integrity
- Audit-chain verification
- Audit persistence
- Audit tampering attacks
- MCP enforcement
- MCP argument attacks
- Argument type attacks
- Policy mutation
- Policy reload behavior
- Concurrency
- Performance

### Audit Chain

Audit entries now form a persistent chain:

```text
Entry 1 -> Entry 2 -> Entry 3 -> ...
   H1         H2         H3
```

Each entry stores the integrity hash of its own record and the hash of the preceding record. The chain can be verified after a firewall restart.

### Compatibility

The v0.4 work preserves the existing v0.3 policy engine, MCP enforcement, approval flow, argument validation, precedence behavior, and security test coverage while extending identity and audit security.

## [0.3.0] - 2026-08-21

### Added

- Identity-aware policy enforcement
- Agent-specific policy matching
- Identity and argument condition combinations
- Policy specificity testing
- Identity policy conflict testing
- MCP argument security testing
- Argument type security testing
- Policy mutation security testing
- Policy reload testing
- Concurrent request testing
- Performance benchmarks
- Expanded adversarial security test coverage

### Security

- Hardened policy precedence handling
- Strongest applicable restriction continues to win:
  `allow < approval < deny`
- Added exact agent identity matching
- Added validation for policy identity values
- Hardened payment argument validation
- Added protection against malformed and unexpected argument types
- Added MCP boundary attack tests
- Added path traversal and tool-name variation tests
- Added fail-closed behavior coverage

### Testing

The v0.3.0 test suite contains:

**145 passing tests**

Coverage includes:

- Policy enforcement
- Policy validation
- Policy conflicts
- Policy precedence
- Policy specificity
- Agent identity
- Identity conflicts
- Identity + argument policies
- MCP enforcement
- MCP argument attacks
- Argument type attacks
- Policy mutation
- Policy reload behavior
- Concurrency
- Performance

### Performance

Development benchmark results:

```text
1000 requests:       ~0.56 seconds
1000 mixed requests: ~0.66 seconds
```
