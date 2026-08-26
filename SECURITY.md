# Security Policy

## Supported Versions

Security fixes are maintained on the current release branch. The active v1.6 release line is:

| Version | Supported |
| --- | --- |
| 1.6.x | Yes |
| 1.5.x | Security fixes only as practical |
| 1.4.x | Security fixes only as practical |
| < 1.4 | No |

## Reporting a Vulnerability

Please do not open a public GitHub issue for an undisclosed security vulnerability.

Report security issues through the repository's private security reporting mechanism on GitHub. Include a clear description of the affected component, the security impact, reproduction steps or a minimal proof of concept, and the version or commit where the issue was observed.

Please avoid including real credentials, production API keys, personal data, or other secrets in the report.

## v1.6 Security Boundary

v1.6 introduces North Star as the canonical authorization orchestration layer for the SDK. North Star coordinates existing security mechanisms without replacing their individual enforcement semantics.

The security-critical authorization boundary includes:

- Signed capability verification and issuer trust.
- Capability expiration and time validity.
- Delegation lineage and effective `DelegationAuthority`.
- Missing-ancestor and lineage-cycle failure handling.
- Transitive revocation propagation.
- Optional authorization-time delegation-depth policy.
- Replay protection where configured by the existing authorization mechanisms.
- Tool and agent binding.
- Constraint and policy enforcement.
- Security and delegation budgets.
- Risk, semantic, and refusal controls.
- Lifecycle and authorization transaction integrity.
- Safe authorization observability without exposing signatures, keys, raw requests, or complete constraint data.

North Star authorization is ordered and fail-closed. A mechanism that cannot establish valid authority must not be converted into permission by the orchestration layer.

The default `max_delegation_depth=None` setting preserves existing authorization behavior. When configured, excessive effective lineage depth is denied without weakening any existing authority constraint.

## Developer Console Boundary

v1.6.1 adds an isolated local developer/security console under `firewall/ui/`.

The console is an **observation and visualization layer, not an authorization engine**:

- It does not implement or duplicate authorization checks.
- Authorization remains governed by `FirewallSDK.authorize_north_star()` and the existing security pipeline.
- Attached SDK mode is observational and refuses to perform authorization evaluations from the unauthenticated console.
- Demo scenarios use disposable in-memory SDK workspaces.
- Private keys, signatures, raw request payloads, and other sensitive cryptographic material are excluded from console responses.
- The console binds to loopback and is intended for trusted local development and debugging.
- The console is not an authenticated production control plane and must not be exposed to untrusted networks without an independently secured deployment boundary.

The console uses only the Python standard library and vanilla browser assets. Static serving enforces root containment to prevent path traversal.

## v1.5 Security Boundary

v1.5 established the following security-critical boundaries:

- Signed capability verification, issuer trust, expiration, and revocation.
- Tool-bound session capabilities.
- Delegation lineage and transitive authority enforcement.
- Cumulative delegation budgets shared across an entire capability lineage.
- Untrusted tool output entering agent context.
- Capability-aware authorization traces.
- Cross-agent isolation.
- Security-sensitive numeric values, including timestamps, TTLs, clocks, and budget amounts.

## CLI Security

The `firewall` CLI provides operational inspection and configuration commands. Capability-token inspection and lifecycle inspection can expose security-sensitive metadata and should be used only in trusted operational environments.

CLI output does not grant authority, and the CLI is not an alternate authorization path. Protected execution remains governed by the SDK and existing firewall security mechanisms.

When reporting CLI-related vulnerabilities, include the command, input shape, affected version, and whether the issue can cross from operational inspection into an authorization or confidentiality boundary.

## Disclosure

Please allow maintainers reasonable time to investigate and prepare a fix before public disclosure. Coordinated disclosure details can be agreed with the reporter after the initial triage.
