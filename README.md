# Agent Firewall


A security-focused authorization firewall for AI agents and tool calls.


Agent Firewall sits between an agent and the tools it wants to use. It evaluates each request against explicit security policies before allowing, denying, or requiring approval for the operation.


## Features


### Identity security


- Agent identity verification
- Cryptographic identity binding
- Issuer validation
- Identity-to-policy binding
- Key lifecycle and revocation support
- Protection against identity spoofing


### Capability-based authorization


Policies can require specific capabilities before an agent can access a tool.


Example:


```yaml
rules:
  - tool: payments.send
    agent: finance-agent
    capability: payments.write
    action: allow

Multiple capabilities can also be required:

rules:
  - tool: payments.send
    agent: finance-agent
    capabilities:
      - payments.write
      - payments.approve
    action: allow

Capabilities are bound to the authenticated agent identity and cannot simply be added or modified without invalidating the identity signature.

Rate limiting

Tools can have per-agent rate limits:

rules:
  - tool: payments.send
    agent: finance-agent
    action: allow
    rate_limit: 5
    rate_limit_window: 60

This allows five requests per window for the specific agent and tool.

Rate-limit state is protected against concurrent access and can persist across process restarts.

Budget enforcement

Policies can restrict how much an agent can spend:

rules:
  - tool: payments.send
    agent: finance-agent
    action: allow
    budget: 100

Requests that would exceed the configured budget are denied.

Budget usage is tracked per agent and tool and persists across restarts.

Human approval

Sensitive operations can require approval:

rules:
  - tool: payments.send
    agent: finance-agent
    action: approval

Approval requests are bound to the original request and agent.

Approvals:

Cannot be reused
Cannot be transferred to another agent
Are bound to the request they approve
Do not automatically survive a restart
Can interact with budget enforcement
Policy enforcement

The firewall supports:

Allow rules
Deny rules
Approval rules
Agent-specific rules
Capability requirements
Argument matching
Amount constraints
Policy precedence
Conflict resolution
Policy validation
Policy mutation protection
Persistent security state

Security state can survive process restarts.

Persistent state includes:

Budget usage
Rate-limit state

State integrity is verified before loading persisted security information.

State writes use atomic replacement to reduce the risk of partially written state.

Audit logging

Security decisions are recorded in an append-only audit log.

Audit entries contain integrity hashes and previous-entry hashes, allowing the audit chain to be verified.

Example:

firewall.verify_audit_chain()
Example

A policy can combine multiple controls:

rules:
  - tool: payments.send
    agent: finance-agent
    capabilities:
      - payments.write
      - payments.approve
    action: allow
    budget: 100
    rate_limit: 5
    rate_limit_window: 60

The firewall evaluates the agent identity, capabilities, policy, rate limit, budget, and request arguments before allowing the operation.

Testing

The project currently contains 390 tests covering:

Policy enforcement
Policy conflicts
Policy attacks
Identity security
Cryptographic identity verification
Identity spoofing
Key lifecycle
Key revocation
Capability authorization
Rate limiting
Budget enforcement
Approval workflows
Persistent state
Audit integrity
Concurrency
Adversarial combinations
MCP enforcement
Argument validation

Run the complete test suite with:

pytest

Expected result for the v0.5 checkpoint:

390 passed
Project status

Current release:

v0.5

v0.5 represents a major security and authorization milestone for Agent Firewall.

The project is under active development.

License

See the repository for licensing information.