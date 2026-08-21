d


Agent Firewall
Agent Firewall is a security and authorization layer for AI agents and automated tool use.

It provides policy enforcement, authenticated agent identities, capability-based authorization, approval workflows, persistent security state, audit logging, and layered controls designed to prevent unauthorized tool execution.

v0.6
v0.6 adds capability-based security as a first-class authorization layer.

Security model
An authorization request can pass through multiple controls:

Agent identity verification

Capability signature verification

Capability namespace matching

Constraint enforcement

Capability attenuation

Capability delegation

Replay protection

Policy matching

Rate limits

Budgets

Human approval

Audit logging

Decision evidence

The controls are layered. Passing one layer does not automatically bypass the others.

Capabilities
Capabilities are cryptographically signed permissions.

Example:

capability = sign_capability(
    private_key=private_key,
    agent_id="finance-agent",
    capability="payments.send",
    constraints={
        "amount_max": 100,
    },
    issuer="trusted-issuer",
)
A capability can be verified before a tool is executed.

Namespaces
Capabilities support namespace matching:

payments.send
payments.refund
payments.*
A wildcard can authorize descendants without granting unrelated namespaces.

For example:

payments.*     -> payments.send      allowed
payments.*     -> payments.refund    allowed
payments.send  -> payments.admin     denied
payments.*     -> accounts.read      denied
Attenuation
Capabilities can be narrowed without increasing authority.

For example:

parent:
payments.*
amount_max = 1000

child:
payments.*
amount_max = 100
An attenuated capability cannot extend its expiration, broaden its scope, or increase an existing constraint.

Delegation
A capability can be delegated to another agent with reduced authority.

Example:

agent-a
  |
  +-- delegates payments.* with amount_max=100
          |
          +-- agent-b
Delegation is bound to the authorized delegatee and cannot be used to change identity, increase authority, or extend expiration.

Replay protection
v0.6 supports nonce-based replay protection.

A replay key is bound to:

agent identity
capability fingerprint
nonce
The first valid use is accepted. Reusing the same key is rejected.

Replay protection is concurrency-safe and expires old entries.

Decision evidence
Authorization decisions carry structured evidence describing why the decision was made.

Evidence can include:

agent_id
capability
namespace_match
constraints_ok
time_valid
policy
request_id
reason
Evidence can be serialized and fingerprinted. Sensitive fields such as private keys, secrets, tokens, passwords, seeds, and mnemonics are filtered from evidence details.

Existing controls
Agent Firewall also provides:

policy-based allow, deny, and approval decisions

approval request binding

budget enforcement

rate limiting

persistent firewall state

tamper-evident audit logging

compatibility with legacy string-based capabilities

Tests
The v0.6 development branch currently passes:

737 tests
Run the full suite with:

pytest -q
Run a focused suite with:

pytest test_v06_final_adversarial.py -v
Project status
v0.5 is released.

v0.6 is in final release-hardening and documentation preparation.

Security-sensitive deployments should review policy configuration, identity verification, capability issuance, and operational logging before production use.