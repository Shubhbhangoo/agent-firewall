
## `CHANGELOG.md`

```markdown
# Changelog

All notable changes to Agent Firewall are documented here.

## [v0.5] - 2026-08-21

### Added

#### Capability-based authorization

- Added agent capabilities.
- Added single-capability policy requirements.
- Added multi-capability policy requirements.
- Bound capabilities to authenticated agent identities.
- Added capability tampering protection.
- Prevented unknown capabilities from granting access.

#### Rate limiting

- Added per-agent rate limits.
- Added per-tool rate limits.
- Added configurable rate-limit windows.
- Added thread-safe rate-limit enforcement.
- Added persistent rate-limit state.
- Added protection against argument-based rate-limit bypasses.

#### Budget enforcement

- Added per-agent and per-tool budgets.
- Added budget consumption tracking.
- Added persistent budget state.
- Added concurrent budget enforcement.
- Prevented requests from exceeding configured budgets.

#### Approval workflows

- Added approval-based policy actions.
- Added request-bound approvals.
- Added agent-bound approvals.
- Prevented approval reuse.
- Prevented approval transfer between agents.
- Integrated approvals with budget enforcement.

#### Persistent state

- Added persistent security state.
- Added state integrity verification.
- Added atomic state writes.
- Added recovery handling for invalid state.
- Added persistence tests across process restarts.

#### Security testing

- Added adversarial integration tests.
- Added capability, budget, and rate-limit combinations.
- Added approval security combinations.
- Added concurrent enforcement tests.
- Added persistent-state attack tests.
- Added combined policy conflict tests.

### Security

- Strengthened identity-to-capability binding.
- Strengthened policy enforcement boundaries.
- Added protection against capability escalation.
- Added protection against approval replay.
- Added protection against cross-agent approval.
- Added protection against budget and rate-limit bypasses.
- Added persistent-state integrity validation.

### Testing

The v0.5 checkpoint contains:

**390 passing tests**

Coverage includes:

- Identity security
- Cryptographic verification
- Policy validation
- Policy attacks
- Policy conflicts
- MCP enforcement
- Capabilities
- Rate limiting
- Budgets
- Approvals
- Persistence
- Audit integrity
- Concurrency
- Adversarial integration

## [v0.4]

Previous stable development milestone.

See the repository history for the complete v0.4 changes.

## [v0.3.0]

Previous release.

See the repository history for details.

## [v0.2.0]

Previous release.

See the repository history for details.