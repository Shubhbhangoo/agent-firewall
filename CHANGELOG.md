Changelog

All notable changes to Agent Firewall are documented here.

[Unreleased]

v0.6

Major security and authorization expansion.

Capabilities

Added cryptographically signed capability objects.

Added capability verification.

Bound capabilities to agent identities and issuers.

Added capability fingerprints.

Added defensive validation for malformed capability data.

Namespace authorization

Added capability namespaces.

Added exact namespace matching.

Added descendant wildcard matching.

Added namespace containment and narrowing checks.

Added protection against prefix confusion and wildcard escalation.

Attenuation

Added capability attenuation.

Child capabilities can only preserve or reduce authority.

Prevented constraint removal that could increase authority.

Prevented expiration extension.

Prevented capability-scope escalation.

Delegation

Added controlled capability delegation between agents.

Bound delegation to a specific delegatee.

Prevented delegated authority escalation.

Added delegation-chain verification.

Added issuer, signing-key, scope, and expiration checks.

Authorization

Added a unified capability authorization layer.

Added namespace, constraint, signature, and time validation.

Added structured authorization results and failure reasons.

Integrated capability authorization into the firewall engine while preserving legacy behavior.

Engine integration

Integrated v0.6 capabilities into Firewall.check().

Preserved v0.5 policy matching, budgets, rate limits, approvals, persistence, and audit logging.

Added backward compatibility for legacy string capabilities.

Decision evidence

Added structured decision evidence.

Added evidence for allow, deny, and approval decisions.

Added agent, capability, namespace, constraint, time, policy, and request metadata.

Added deterministic JSON serialization.

Added evidence fingerprints.

Added filtering of sensitive values from evidence details.

Replay protection

Added nonce generation and replay keys.

Bound replay keys to agent identity and capability fingerprints.

Added concurrency-safe replay consumption.

Added expiry-based cleanup.

Integrated replay checks into the firewall execution path.

Security testing

Added extensive v0.6 unit tests.

Added integration tests across capabilities, namespaces, attenuation, delegation, authorization, evidence, and replay protection.

Added adversarial security tests covering forgery, tampering, escalation, replay, concurrency, and legacy compatibility.

Validation

Full repository suite passes with 737 tests.

[v0.5]

Added persistent firewall security state.

Added approval workflows.

Added state persistence across restart.

Added adversarial security testing.

Added v0.5 documentation.

Released as v0.5.

[v0.4]

Previous stable release.

[v0.3.0]

Previous project milestone.

[v0.2.0]

Previous project milestone.