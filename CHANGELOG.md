# Changelog

All notable changes to Agent Firewall are documented here.

## [1.3.0] - 2026-08-25

### Added

- Effective delegated-authority enforcement across the complete capability lineage.
- Runtime capability registry for resolving delegated parents and ancestors.
- Full delegation lineage traversal from child capability to root capability.
- Fail-closed authorization when a required delegation ancestor cannot be resolved.
- Delegation-chain enforcement for namespaces and constraints, preventing authority restoration through nested delegation.
- Adversarial escalation coverage for constraint laundering, namespace escalation, deep delegation escape, revoked-parent bypass, revoked-intermediate bypass, sibling isolation, unrelated delegation trees, and missing ancestors.
- Concurrency security coverage for authorization, revocation, delegation registration, lineage reads, sibling isolation, and repeated post-revocation authorization.

### Security

- A delegated capability can no longer authorize an operation that any capability in its parent chain would deny.
- Delegation cannot broaden authority beyond the constraints and namespace established by its ancestors.
- Revoked ancestors remain authoritative for descendant authorization decisions.
- Missing delegation ancestry fails closed instead of silently treating the child as independent authority.
- Delegation lineage cycle and maximum-depth protections remain enforced.
- Concurrent authorization and revocation paths are covered against race-induced fail-open behavior.

### Compatibility

- Existing capability authorization and constraint semantics remain supported.
- Existing direct `private_key=` issuance remains supported.
- Existing attenuation and delegation APIs remain supported.
- Existing revocation, replay, key-management, semantic-chain, risk, refusal-state, and adapter security behavior remains covered by the regression suite.

### Testing

- Expanded the full regression suite to **2,050 passing tests** in the local v1.3 validation run.
- Added effective delegated-authority tests.
- Added adversarial escalation tests.
- Added adversarial concurrency and race-condition tests.
- Preserved the existing v1.2 and earlier security regression coverage.

### Packaging

- Updated package version to `1.3.0`.
- Updated Security CI to run against the `v1.3` branch.

## [1.2.0] - 2026-08-24

### Added

- Cumulative runtime `SecurityContext` for tracking action counts, cumulative amounts, denials, and capability usage.
- Delegation lineage tracking for parent and descendant capabilities.
- Revocation propagation through delegation lineage, including intermediate-parent revocation.
- Adversarial escalation coverage for nonce, refusal-state, capability-substitution, adapter, and concurrency scenarios.
- Deterministic `SemanticChainContext` for explicit multi-step security workflows.
- `SemanticRule` support for ordered semantic workflows and protected outcomes.
- Explicit semantic `chain_id` boundaries to prevent state inheritance between independent workflows.
- Deterministic semantic resource tracking and consistency checks.
- Capability-fingerprint tracking inside semantic chains.
- `SemanticChainTransaction` for atomic semantic state transitions.
- Final v1.2 semantic security audit coverage.

### Security

- Parent capability revocation invalidates delegated descendants.
- Revoking an intermediate delegated capability invalidates its descendants.
- Cumulative security state is evaluated without allowing downstream authorization failures to leave partially committed semantic state.
- Semantic workflow state is isolated by agent and explicit chain ID.
- Protected semantic workflows are evaluated deterministically from explicit rules rather than inferred by an LLM.
- Semantic transactions are committed only after downstream authorization succeeds.
- Concurrent semantic authorization is serialized to prevent race-based bypasses.
- Fresh nonces do not erase established semantic chain state.
- Capability fingerprints remain visible in semantic chain state so capability substitution cannot silently disappear from the recorded workflow.
- Existing v1.1 refusal, replay, revocation, key-management, policy, and adapter security invariants remain covered by the full regression suite.

### Compatibility

- Existing v1.1 authorization and constraint semantics remain supported.
- Semantic-chain protection is opt-in through `SemanticChainContext`.
- Existing authorization behavior remains unchanged when no semantic context is configured.
- Existing direct `private_key=` capability issuance remains supported.
- Existing managed key rotation and retirement semantics remain supported.
- Existing adapter authorization continues to use the shared security core.

### Testing

- Expanded the regression suite to **1,921 passing tests**.
- Added delegation-lineage regression coverage.
- Added semantic-chain workflow tests.
- Added semantic transaction commit/abort tests.
- Added adversarial semantic escalation tests.
- Added concurrency coverage for semantic authorization.
- Added final v1.2 semantic security audit tests.
- Preserved the existing v1.1 security regression coverage.

### Packaging

- Updated package version to `1.2.0`.
- Published `agent-firewall-security==1.2.0` to PyPI.
- Updated continuous integration to test the `v1.2` branch across Python 3.10, 3.11, and 3.12.

## [1.1.0] - 2026-08-24

### Added

- Persistent replay protection across normal SDK restarts.
- Signing-key identity binding for managed capabilities.
- Policy operators:
  - `eq`
  - `neq`
  - `in`
  - `not_in`
  - `gte`
  - `lte`
  - `contains`
- Policy composition:
  - `and`
  - `or`
  - `not`
- MCP firewall authorization and execution-boundary hardening.
- Concurrency security coverage for replay, revocation, key generation, and key rotation.
- Property-based security fuzzing for malformed policies, tokens, constraints, requests, and replay inputs.
- Cross-cutting v1.1 security audit coverage.

### Security

- Persistent replay state remains authoritative across restart.
- Concurrent consumption of the same replay key permits only one successful consumer.
- Managed capability identity is bound to the signing key used to issue it.
- Malformed policy composition fails closed.
- MCP authorization completes before a tool handler can execute.
- Invalid capabilities, replay attempts, revoked capabilities, and unauthorized tool calls are denied.
- Security-critical persistence failures do not silently create fresh authority.
- Concurrent security-state transitions are covered by regression tests.

### Compatibility

- Existing v1.0 authorization and constraint semantics remain supported.
- Existing direct `private_key=` capability issuance remains supported.
- Existing managed key rotation and retirement semantics remain supported.
- Existing adapter authorization continues to use the shared security core.

### Testing

- Expanded the regression suite to 1,812 passing tests.
- Added policy operator and composition integration tests.
- Added persistent replay restart tests.
- Added concurrency and race-condition tests.
- Added security fuzzing coverage.
- Added MCP hardening and execution-boundary tests.
- Added cross-cutting security audit tests.

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
