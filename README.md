# Agent Firewall v0.3.0

A policy-based security layer for AI agents and MCP tools.

Agent Firewall sits between an AI agent and the tools it can access. Every tool request is evaluated against security policies before the tool is allowed to execute.

## What it does

- Allow trusted tool actions
- Deny dangerous actions
- Require human approval for sensitive actions
- Validate tool arguments
- Validate policy configuration
- Support identity-aware policies
- Fail closed when no policy matches
- Resolve conflicting policies using strongest restriction
- Log security decisions with request IDs
- Protect MCP tool calls
- Test adversarial and bypass scenarios
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

## Identity-Aware Policies

Policies can optionally target a specific agent.

```yaml
rules:
  - tool: github.delete_file
    agent: trusted-agent
    action: allow

  - tool: github.delete_file
    agent: attacker-agent
    action: deny
```

Identity conditions are matched exactly.

Identity can also be combined with argument conditions:

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

## Security Behavior

The firewall fails closed when no matching policy exists.

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

Policy configuration is also validated.

Invalid policy values such as non-numeric payment thresholds are rejected during initialization.

## Policy Conflicts

When multiple policies match the same request, the strongest restriction wins:

```text
allow < approval < deny
```

This prevents a permissive policy from overriding a stronger restriction.

Policy specificity, identity conditions, argument conditions, and conflicting rules are covered by the security test suite.

## MCP Integration

Agent Firewall has been tested against MCP tools and a real GitHub MCP server.

Example allowed operation:

```text
github.get_file_contents
        |
        v
Agent Firewall
        |
        +--> ALLOW
        |
        v
GitHub MCP Server
        |
        v
README.md
```

Protected operations are blocked before the MCP server receives the request:

```text
github.delete_file
        |
        v
Agent Firewall
        |
        +--> DENY
        |
        X
MCP tool is never called
```

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

## Audit Logging

Security decisions are written to `audit.log`.

Each entry contains information such as:

- Request ID
- Timestamp
- Agent
- Tool
- Arguments
- Decision
- Reason

Example:

```json
{
  "request_id": "example-request-id",
  "timestamp": "2026-08-21T00:00:00",
  "agent": "finance-agent",
  "tool": "payments.send",
  "arguments": {
    "amount": 500
  },
  "decision": "approval",
  "reason": "Policy matched for payments.send"
}
```

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
- Identity policy conflicts
- Identity + argument policies
- Policy mutation
- Policy reload behavior
- MCP enforcement
- MCP argument attacks
- Concurrent requests

## Performance

The v0.3 test suite includes basic performance benchmarks.

Current local baseline:

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

Current v0.3 test suite:

```text
145 passed
```

## Project Structure

```text
agent-firewall/
├── firewall/
│   └── engine.py
├── tests/
│   └── test_engine.py
├── policies.yaml
├── mcp_firewall.py
├── mcp_server.py
├── test_approval.py
├── test_audit.py
├── test_attacks.py
├── test_firewall.py
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
├── requirements.txt
└── README.md
```

## Status

**v0.3.0**

This release focuses on hardening the authorization layer for AI agents and MCP tools.

Current focus areas include:

- Policy enforcement
- Identity-aware authorization
- MCP tool protection
- Security testing
- Policy validation
- Audit logging
- Concurrency testing
- Performance testing

The current test suite contains **145 passing tests**.

## Security

This project is experimental software intended for security research and testing.

Do not use it as the sole security control for production systems without independently reviewing, testing, and hardening the implementation.

## License

License to be added.