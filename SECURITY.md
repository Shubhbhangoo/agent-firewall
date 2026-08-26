# Security Policy

## Supported Versions

Security fixes are maintained on the current release branch. The active v1.5 release line is:

| Version | Supported |
| --- | --- |
| 1.5.x | Yes |
| 1.4.x | Security fixes only as practical |
| < 1.4 | No |

## Reporting a Vulnerability

Please do not open a public GitHub issue for an undisclosed security vulnerability.

Report security issues through the repository's private security reporting mechanism on GitHub. Include a clear description of the affected component, the security impact, reproduction steps or a minimal proof of concept, and the version or commit where the issue was observed.

Please avoid including real credentials, production API keys, personal data, or other secrets in the report.

## v1.5 Security Boundary

v1.5 treats the following as security-critical boundaries:

- Signed capability verification, issuer trust, expiration, and revocation.
- Tool-bound session capabilities.
- Delegation lineage and transitive authority enforcement.
- Cumulative delegation budgets shared across an entire capability lineage.
- Untrusted tool output entering agent context.
- Capability-aware authorization traces.
- Cross-agent isolation.
- Security-sensitive numeric values, including timestamps, TTLs, clocks, and budget amounts.

The project aims to fail closed when these controls cannot establish valid authority.

## Disclosure

Please allow maintainers reasonable time to investigate and prepare a fix before public disclosure. Coordinated disclosure details can be agreed with the reporter after the initial triage.
