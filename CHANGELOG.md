# Changelog

All notable changes to Agent Firewall are documented here.

## [1.6.0] - 2026-08-26

### Added

- Introduced the North Star authorization architecture as the SDK's canonical orchestration boundary.
- Decomposed SDK authorization into an explicit deterministic sequence of fail-closed gates.
- Added canonical `DelegationAuthority` propagation through the authorization context.
- Added optional authorization-time `max_delegation_depth` policy enforcement.
- Added per-request propagation of risk, security, semantic, and refusal context through `_AuthorizationContext`.
- Added a terminal transaction gate covering semantic transaction commit/abort, security-context authorization, delegation-budget consumption, and successful lifecycle state.
- Added North Star delegation-posture observability through safe `SecurityDecision.metadata`.
- Added dedicated North Star equivalence, delegation-depth, and observability regression suites.
- Added CLI documentation for configuration validation, capability-token inspection, and lifecycle inspection.

### Security

- North Star preserves existing security mechanisms instead of duplicating or bypassing their enforcement semantics.
- Delegation lineage is resolved through the SDK's authoritative `_authorization_chain()` and represented canonically as `DelegationAuthority`.
- Revocation precedence remains authoritative, including cases where a revoked capability also has a broken delegation chain.
- Missing ancestors and lineage failures remain fail-closed.
- Optional delegation-depth enforcement is disabled by default and cannot widen authority.
- The transactional tail remains atomic with respect to semantic and security state, including abort-on-denial behavior.
- North Star observability metadata contains only safe posture information and cannot alter the authorization decision.
- Existing cryptographic verification, attenuation, replay, policy, risk, refusal, lifecycle, and budget semantics remain in force.

### Testing

- Preserved the 2,204-test baseline through the North Star migration.
- Added four authorization-equivalence tests, bringing the verified suite to 2,208 tests.
- Added 14 delegation-depth policy tests, bringing the verified suite to 2,222 tests.
- Added eight North Star observability tests, bringing the verified suite to **2,230 passing tests**.
- Full-suite validation completed with zero failures.

### Compatibility

- Existing `FirewallSDK.authorize()` remains supported.
- `authorize_north_star()` preserves the established authorization decision semantics.
- The default `max_delegation_depth=None` behavior preserves existing authorization behavior.
- Existing delegation, attenuation, revocation, replay, budget, semantic, security-context, lifecycle, adapter, and MCP APIs remain supported.

### Packaging

- Updated package version to `1.6.0`.
- Updated README, security policy, and North Star documentation for the v1.6 architecture.

## [1.5.0] - 2026-08-26

### Added

- Session-scoped capability minting with explicit tool binding and fresh TTL-derived expiration.
- Lifecycle coverage for session capability minting, expiration, tool binding, attenuation, and delegation.
- Explicit untrusted tool-output marking through `firewall.tools` so tool-returned instructions remain data rather than authority.
- Minimal capability-aware authorization traces containing capability identity, agent, action, reason, and optional tool binding.
- Cumulative transitive delegation budgets rooted at the originating capability fingerprint.
- Atomic sharing of lineage budgets across parent, child, and deeper delegated capabilities.
- Cross-agent isolation coverage for session capabilities, budgets, tool bindings, concurrent authorization, and revocation.
- Expanded delegation revocation propagation coverage across root, intermediate, leaf, and sibling branches.
- Finite-number validation for capability timestamps, verifier clocks, session TTLs, and delegation-budget amounts.

### Security

- A session capability minted for one tool cannot authorize a different tool.
- Tool output cannot acquire capability authority merely by containing instructions, credential-like text, or capability-shaped data.
- Authorization traces exclude signatures, public keys, raw request payloads, and full constraint data.
- Parent, child, and grandchild capabilities consume the same cumulative lineage budget rather than receiving independent budgets.
- Concurrent descendants cannot overspend a shared lineage budget.
- Root revocation propagates through the complete delegation chain.
- Intermediate revocation invalidates all descendants while preserving unrelated sibling branches.
- Independent root capabilities maintain separate budget and revocation state.
- `NaN`, positive infinity, and negative infinity are rejected in security-sensitive numeric inputs.

### Testing

- Added session capability minting regression coverage.
- Added session capability lifecycle regression coverage.
- Added untrusted tool-output and prompt-injection regression coverage.
- Added capability-aware authorization trace regression coverage.
- Added transitive delegation-budget and concurrency regression coverage.
- Added multi-level revocation propagation regression coverage.
- Added cross-agent isolation regression coverage.
- Added finite numeric validation regression coverage for `NaN` and infinities.
- Full v1.5 validation remained green through the feature hardening cycle.

### Compatibility

- Existing v1.4 semantic and runtime security context behavior remains supported.
- Existing attenuation, delegation, revocation, replay, key-management, adapter, and MCP authorization APIs remain supported.
- Existing direct capability issuance continues to work through the public SDK.

### Packaging

- Updated package version to `1.5.0`.
- Updated security CI coverage to the `v1.5` branch.
- Updated release and security documentation for the v1.5 capability-boundary model.

## [1.4.0] - 2026-08-26

### Added

- Cross-chain cumulative semantic amount budgets through `SemanticChainContext.max_total_amount`.
- Optional persistent `SecurityContext` state through `state_path`.
- SDK helper support for creating a persistent `SecurityContext`.
- Persistent security-state integrity verification and atomic replacement.
- Cross-process locking for shared persistent security state.
- Authorization atomicity coverage between semantic state and runtime security budgets.
- Persistence recovery coverage for stale temporary files, interrupted writes, failed atomic replacement, and tampered state.

### Security

- Cross-chain semantic budgets are enforced atomically under the existing semantic context lock.
- Concurrent chains cannot overspend a shared semantic cumulative budget.
- Persistent security budget state survives normal process restart.
- Concurrent independent `SecurityContext` instances sharing a state file cannot both authorize from stale state and exceed the configured budget.
- Corrupted, truncated, tampered, incompatible, or agent-mismatched persistent state fails closed.
- A failed persistent write rolls back the in-memory security mutation.
- Stable audit-log path resolution prevents process working-directory changes from splitting the audit hash chain into separate logs.
- Semantic transactions abort when downstream security authorization fails, preventing partial authorization state.

### Testing

- Expanded the local v1.4 regression suite to **2,106 passing tests**.
- Added cross-chain budget tests.
- Added budget concurrency and race-condition tests.
- Added persistent budget restart tests.
- Added persistent-state corruption and recovery tests.
- Added cross-process persistent-state race tests.
- Added semantic/security authorization atomicity tests.
- Added stable audit-log path regression coverage.

### Compatibility

- Existing `SecurityContext` behavior remains supported when `state_path` is omitted.
- Existing in-memory `SemanticChainContext` behavior remains supported when `max_total_amount` is omitted.
- Existing v1.3.1 delegation, attenuation, revocation, replay, key-management, and adapter behavior remains covered by the regression suite.

## [1.3.1] - 2026-08-25

### Security

- Persisted delegation lineage and signed capability records so delegated authority can be reconstructed after SDK restart instead of silently becoming root authority.
- Hardened the legacy `Firewall` authorization path so revocation of a parent capability also blocks its delegated descendants.
- Extended effective revocation to genuinely distinct attenuated capabilities by registering attenuation parent-child lineage.
- Preserved no-op attenuation compatibility when attenuation produces the exact same signed capability and fingerprint as its parent.
- Added dedicated security-audit regression coverage for delegation persistence, legacy revocation, attenuation revocation, semantic transaction lifecycle, lineage-depth boundaries, audit-log behavior, and cross-chain budget semantics.

### Fixed

- Corrected effective-authority handling across SDK restart boundaries.
- Corrected ancestor-aware revocation consistency between the SDK and legacy firewall paths.
- Corrected parent revocation propagation through distinct attenuated descendants.
- Preserved established lineage-depth semantics after validating the audit finding against the existing multi-agent regression contract.

### Testing

- Expanded the local v1.3.1 validation suite to **2,073 passing tests**.
- Added F1 delegation-persistence audit tests.
- Added F2 lineage-depth audit coverage.
- Added F3 legacy revocation audit coverage.
- Added F4 semantic transaction and concurrency audit coverage.
- Added F5 attenuation revocation audit coverage.
- Added F6 audit-log behavior coverage.
- Added F7 cross-chain budget behavior coverage for the v1.4 design backlog.

### Packaging

- Updated package version to `1.3.1`.
- Prepared the v1.3 branch for the `agent-firewall-security==1.3.1` release.
