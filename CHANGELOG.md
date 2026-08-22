# Changelog

All notable changes to Agent Firewall are documented here.

## [Unreleased]

## [v0.8.0]

Major expansion of capability lifecycle tracking, persistence, restart safety, and adversarial security coverage.

### Capability lifecycle

- Added explicit lifecycle events for capability issuance (`ISSUED`).
- Added delegation lifecycle events (`DELEGATED`).
- Added attenuation lifecycle events (`ATTENUATED`).
- Added successful authorization/use lifecycle events (`USED`).
- Added replay-detection lifecycle events (`REPLAYED`).
- Added revocation lifecycle events (`REVOKED`).
- Added authorization-denial lifecycle events (`DENIED`).
- Added expiration lifecycle events (`EXPIRED`).
- Bound lifecycle events to capability fingerprints and structured metadata.
- Added lifecycle ordering and terminal-outcome invariants.

### Lifecycle persistence

- Added `SQLiteLifecycleStore`.
- Added persistent lifecycle event history with restart recovery.
- Preserved lifecycle insertion order across restart.
- Added fingerprint and event-type queries.
- Added concurrent write protection.
- Added lifecycle corruption detection.
- Preserved nested lifecycle details through JSON round trips.
- Added recorder integration with persistent lifecycle stores.

### SDK persistence

- Added `lifecycle_store_path` to `FirewallSDK`.
- Added persistent lifecycle history at the SDK boundary.
- Added cross-layer restart coverage for lifecycle and revocation state.
- Preserved in-memory lifecycle behavior when persistence is not configured.

### Revocation

- Added persistent capability revocation storage and restart recovery.
- Bound revocation to capability fingerprints.
- Prevented revocation from crossing agents, scopes, or reissued capabilities.
- Preserved revocation through SDK and engine restart.

### Security hardening

- Added adversarial lifecycle testing.
- Added lifecycle mutation-resistance tests for nested request data.
- Added concurrency tests for lifecycle authorization and revocation.
- Added corruption-detection tests for persistent lifecycle state.
- Added cross-capability and cross-agent isolation tests.
- Added restart resurrection tests.
- Added full lifecycle reconstruction tests.

### Public API

- Added public package exports for the v0.8 SDK, lifecycle, revocation, and persistence primitives.
- Added regression coverage for the public import surface.

### Validation

- Full v0.8 regression suite passed with **1438 tests**.
- Lifecycle persistence and adversarial persistence suites passed.
- SDK persistence and cross-layer restart suites passed.

## [v0.7]

Major expansion of capability security to protocol and transport boundaries.

### Capability SDK

- Added the developer-facing `FirewallSDK` interface.
- Added capability issuance and verification through the SDK.
- Added capability attenuation and delegation helpers.
- Added serialization and deserialization helpers.
- Added transport encode/decode helpers.
- Added verified transport decoding.
- Added replay-protection integration.
- Added authorization and evidence helpers.

### Capability transport

- Added signed capability transport tokens.
- Added deterministic URL-safe transport encoding.
- Added transport size limits.
- Added malformed-token rejection.
- Added required-field validation.
- Added protection against transport tampering and signature tampering.
- Preserved capability authority, constraints, issuer, agent, and signature across transport.

### MCP authorization

- Added the v0.7 MCP security adapter.
- Added capability authorization at the MCP tool boundary.
- Bound MCP requests to authorized agents and capabilities.
- Preserved namespace and constraint enforcement across MCP execution.
- Added replay protection at the protocol boundary.
- Prevented unauthorized tool execution.

### HTTP authorization

- Added the v0.7 HTTP authorization boundary.
- Added deterministic HTTP method/path to firewall namespace mapping.
- Added capability verification before request execution.
- Bound capabilities to requesting agent identities.
- Added HTTP constraint enforcement.
- Added nonce-based replay protection.
- Added Bearer-token and HTTP-header parsing.
- Prevented unauthorized handlers from executing.
- Rejected malformed paths and namespace-invalid path segments.
- Rejected method and path confusion attacks.
- Prevented wildcard scope from crossing unrelated namespaces.

### Security hardening

- Added adversarial testing for cross-agent substitution.
- Added token and signature tampering tests.
- Added replay and nonce-burning tests.
- Added path traversal and path confusion tests.
- Added HTTP method confusion tests.
- Added constraint-bypass tests.
- Added expired-capability execution tests.
- Added handler-boundary tests proving denied requests do not execute.
- Added MCP and HTTP integration coverage.

### Validation

- Full v0.7 regression suite is green.
- HTTP authorization and adversarial suites are green.
- v0.7 includes the capability SDK, transport, MCP boundary, and HTTP boundary.

## [v0.6]

Major security and authorization expansion.

### Capabilities

- Added cryptographically signed capability objects.
- Added capability verification.
- Bound capabilities to agent identities and issuers.
- Added capability fingerprints.
- Added defensive validation for malformed capability data.

### Namespace authorization

- Added capability namespaces.
- Added exact namespace matching.
- Added descendant wildcard matching.
- Added namespace containment and narrowing checks.
- Added protection against prefix confusion and wildcard escalation.

### Attenuation

- Added capability attenuation.
- Child capabilities can only preserve or reduce authority.
- Prevented constraint removal that could increase authority.
- Prevented expiration extension.
- Prevented capability-scope escalation.

### Delegation

- Added controlled capability delegation between agents.
- Bound delegation to a specific delegatee.
- Prevented delegated authority escalation.
- Added delegation-chain verification.
- Added issuer, signing-key, scope, and expiration checks.

### Authorization

- Added a unified capability authorization layer.
- Added namespace, constraint, signature, and time validation.
- Added structured authorization results and failure reasons.
- Integrated capability authorization into the firewall engine while preserving legacy behavior.

### Engine integration

- Integrated v0.6 capabilities into `Firewall.check()`.
- Preserved v0.5 policy matching, budgets, rate limits, approvals, persistence, and audit logging.
- Added backward compatibility for legacy string capabilities.

### Decision evidence

- Added structured decision evidence.
- Added evidence for allow, deny, and approval decisions.
- Added agent, capability, namespace, constraint, time, policy, and request metadata.
- Added deterministic JSON serialization.
- Added evidence fingerprints.
- Added filtering of sensitive values from evidence details.

### Replay protection

- Added nonce generation and replay keys.
- Bound replay keys to agent identity and capability fingerprints.
- Added concurrency-safe replay consumption.
- Added expiry-based cleanup.
- Integrated replay checks into the firewall execution path.

### Security testing

- Added extensive v0.6 unit tests.
- Added integration tests across capabilities, namespaces, attenuation, delegation, authorization, evidence, and replay protection.
- Added adversarial security tests covering forgery, tampering, escalation, replay, concurrency, and legacy compatibility.

### Validation

- Full v0.6 repository suite passed with 737 tests.

## [v0.5]

- Added persistent firewall security state.
- Added approval workflows.
- Added state persistence across restart.
- Added adversarial security testing.
- Added v0.5 documentation.
- Released as v0.5.

## [v0.4]

Previous stable release.

## [v0.3.0]

Previous project milestone.

## [v0.2.0]

Previous project milestone.
