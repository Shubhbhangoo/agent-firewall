# Agent Firewall v0.4.0

A policy-based security layer for AI agents and MCP tools.

Agent Firewall sits between an AI agent and the tools it can access. Every tool request is evaluated against security policies before the tool is allowed to execute.

## What it does

- Allow trusted tool actions
- Deny dangerous actions
- Require human approval for sensitive actions
- Validate tool arguments
- Validate policy configuration
- Support authenticated agent identities
- Bind authorization decisions to agent identity
- Verify cryptographic agent identities
- Manage key lifecycle states
- Revoke and persist revoked keys
- Persist key lifecycle state
- Fail closed when no policy matches
- Resolve conflicting policies using strongest restriction
- Log security decisions with request IDs
- Protect MCP tool calls
- Detect audit-log tampering
- Chain audit records cryptographically
- Verify audit chains after restart
- Test adversarial, spoofing, tampering, and bypass scenarios
- Test concurrent requests
- Benchmark firewall performance

## Architecture

```text
AI Agent
   |
   v
MCP Client
   |
   v
Agent Firewall
   |
   +-- ALLOW ------+
   |               |
   +-- DENY        |
   |               v
   +-- APPROVAL -> MCP Server
                       |
                       v
                 External Tool
```

The firewall evaluates every request before the MCP tool is called.

## Policy Engine

Policies are defined in `policies.yaml`.

```yaml
rules:
  - tool: github.get_file_contents
    action: allow

  - tool: github.delete_file
    action: deny

  - tool: payments.send
    amount_gt: 100
    action: approval

  - tool: payments.send
    amount_gte: 1000
    action: deny
```

The firewall uses the strongest applicable restriction:

```text
allow < approval < deny
```

## Identity and Authorization

Policies can target a specific agent identity.

```yaml
rules:
  - tool: github.delete_file
    agent: trusted-agent
    action: allow

  - tool: github.delete_file
    agent: attacker-agent
    action: deny
```

Identity conditions are matched exactly. Identity can also be combined with argument conditions:

```yaml
rules:
  - tool: payments.send
    agent: finance-agent
    amount_gte: 100
    action: approval

  - tool: payments.send
    agent: finance-agent
    amount_gte: 1000
    action: deny
```

All conditions in a rule must match before the rule applies.

v0.4 adds cryptographic identity support, including public-key and signature fields, issuer verification, authenticated-identity enforcement, key lifecycle states, rotation, retirement, revocation, and persistent revocation state.

## Security Behavior

The firewall fails closed when no matching policy exists.

Unauthenticated identities are denied before policy authorization.

Invalid payment values are rejected, including:

- Negative values
- Zero
- Strings
- Missing amounts
- `NaN`
- Infinity
- Booleans
- Lists
- Dictionaries

Policy configuration is also validated. Invalid policy values such as non-numeric payment thresholds are rejected during initialization.

## Key Lifecycle

Agent public keys can move through explicit lifecycle states:

```text
active -> rotated
active -> revoked
active -> retired
```

Unknown keys remain distinct from active keys. Revoked and retired keys cannot be accepted as valid identities.

Revocation state can be persisted and survives verifier restarts.

## MCP Integration

Agent Firewall has been tested against MCP tools and a real GitHub MCP server.

Protected operations are blocked before the MCP server receives the request.

The MCP enforcement tests verify that blocked requests do not execute the underlying tool.

## Human Approval

Sensitive actions can require human approval.

```text
AI Agent
   |
   v
Agent Firewall
   |
   +--> APPROVAL
           |
           v
      Human Decision
        /       \
       /         \
    Allow       Reject
      |            |
      v            v
   MCP Tool      Block
```

Rejected approval requests never execute the underlying tool.

## Tamper-Evident Audit Logging

Security decisions are written to `audit.log`.

Each audit entry contains information such as:

- Request ID
- Timestamp
- Agent
- Tool
- Arguments
- Decision
- Reason
- Public key when available
- Issuer when available
- Integrity hash
- Previous-entry hash

Each entry receives a SHA-256 integrity hash. Entries are chained so that every entry records the hash of the previous entry.

```text
Entry 1
  previous_hash = ""
  integrity_hash = H1
       |
       v
Entry 2
  previous_hash = H1
  integrity_hash = H2
       |
       v
Entry 3
  previous_hash = H2
  integrity_hash = H3
```

The chain is persisted through firewall restarts and can be verified with:

```python
firewall.verify_audit_chain()
```

Verification detects modified records, forged hashes, broken links, reordered records, deleted middle entries, malformed records, and other chain inconsistencies.

## Security Testing

The project includes adversarial tests covering:

- Policy bypass attempts
- Argument type confusion
- Nested arguments
- Path traversal attempts
- Tool-name variations
- Unknown tools
- Payment validation
- Policy conflicts
- Policy specificity
- Identity spoofing
- Identity authentication
- Cryptographic identity verification
- Identity-policy binding
- Key lifecycle management
- Key revocation
- Revocation persistence
- Revocation concurrency
- Audit integrity
- Audit-chain integrity
- Audit-chain verification
- Audit persistence across restart
- Audit tampering attacks
- Policy mutation
- Policy reload behavior
- MCP enforcement
- MCP argument attacks
- Concurrent requests
- Performance

## Performance

The project includes development performance benchmarks.

Previous local development baseline:

```text
1000 requests:       ~0.56 seconds
1000 mixed requests: ~0.66 seconds
```

These are development benchmarks, not production performance guarantees.

## Running Tests

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the complete test suite:

```powershell
pytest
```

For performance output:

```powershell
pytest -s
```

Current v0.4 test suite:

```text
264 passed
```

## Project Structure

```text
agent-firewall/
├── firewall/
│   ├── engine.py
│   └── identity.py
├── tests/
│   └── test_engine.py
├── policies.yaml
├── mcp_firewall.py
├── mcp_server.py
├── test_approval.py
├── test_audit.py
├── test_github_mcp.py
├── test_mcp_enforcement.py
├── test_mcp_firewall.py
├── test_policy_attacks.py
├── test_policy_conflicts.py
├── test_policy_validation.py
├── test_v03_argument_types.py
├── test_v03_attacks.py
├── test_v03_concurrency.py
├── test_v03_identity.py
├── test_v03_identity_arguments.py
├── test_v03_identity_conflicts.py
├── test_v03_identity_policy.py
├── test_v03_mcp_arguments.py
├── test_v03_performance.py
├── test_v03_policy_attacks.py
├── test_v03_policy_mutation.py
├── test_v03_policy_reload.py
├── test_v03_precedence.py
├── test_v03_specificity.py
├── test_v04_identity.py
├── test_v04_identity_audit.py
├── test_v04_identity_binding.py
├── test_v04_identity_crypto.py
├── test_v04_identity_policy_binding.py
├── test_v04_identity_spoofing.py
├── test_v04_identity_verifier.py
├── test_v04_key_lifecycle.py
├── test_v04_key_management.py
├── test_v04_key_revocation.py
├── test_v04_revocation_concurrency.py
├── test_v04_revocation_persistence.py
├── test_v04_audit_integrity.py
├── test_v04_audit_chain.py
├── test_v04_audit_chain_verification.py
├── test_v04_audit_persistence.py
├── test_v04_audit_attacks.py
├── requirements.txt
├── CHANGELOG.md
└── README.md
```

## Status

**v0.4.0**

v0.4 focuses on strengthening identity security and making security decisions tamper-evident and recoverable across restarts.

Major areas include:

- Cryptographic agent identity
- Identity-bound authorization
- Key lifecycle management
- Key revocation and persistence
- Identity-aware audit logging
- SHA-256 audit integrity hashes
- Chained audit records
- Audit-chain verification
- Audit persistence across restarts
- Audit tampering detection
- Expanded adversarial security testing

The current v0.4 test suite contains **264 passing tests**.

## Security

This project is experimental software intended for security research and testing.

Do not use it as the sole security control for production systems without independently reviewing, testing, and hardening the implementation.

## License

License to be added.
