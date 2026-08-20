# Agent Firewall


A policy-based security layer for AI agents and MCP tools.


Agent Firewall sits between an AI agent and the tools it can access. Every tool request is evaluated against security policies before it is allowed to execute.


## What it does


- Allow trusted tool actions
- Deny dangerous actions
- Require human approval for sensitive actions
- Validate tool arguments
- Support generic argument matching
- Fail closed when no policy matches
- Resolve conflicting policies using strongest restriction
- Validate policy configuration
- Generate unique request IDs for audit logs
- Audit security decisions
- Protect MCP tool execution
- Test MCP boundary bypass attempts


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
   |               |
   +-- APPROVAL --> Human
                       |
                       v
                  MCP Server
                       |
                       v
                  External Tool

The firewall evaluates a request before the MCP tool is called.

Policy Example

Policies are defined in policies.yaml.

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

The firewall uses the strongest applicable restriction:

allow < approval < deny
Generic Argument Policies

Policies can match specific tool arguments:

rules:
  - tool: test.tool
    arguments:
      environment: production
      mode: destructive
    action: deny

All specified arguments must match.

Extra arguments do not bypass the policy.

Security Behavior

The firewall fails closed when no matching policy exists.

Invalid payment values are rejected, including:

Negative values
Zero
Strings
Missing amounts
NaN
Infinity
Booleans
Lists
Dictionaries

Tool names are matched exactly.

Case changes, suffixes, path-style variations, and other tool-name confusion attempts do not bypass policy enforcement.

Policy Validation

Policy configuration is validated when the firewall starts.

Invalid policies are rejected, including:

Non-list rules
Non-dictionary rules
Rules without a tool
Rules without an action
Invalid policy actions

Supported actions are:

allow
approval
deny
Human Approval

Sensitive actions can require explicit human approval.

Tool request
     |
     v
  Firewall
     |
     v
 APPROVAL
     |
     v
Human decision
   /     \
 YES      NO
  |        |
  v        v
Execute   Block

A rejected approval never executes the underlying tool.

Audit Logging

Security decisions are written to audit.log.

Each entry contains:

Request ID
Timestamp
Agent
Tool
Arguments
Decision
Reason

Example:

{
  "request_id": "uuid",
  "timestamp": "2026-08-21T00:00:00",
  "agent": "finance-agent",
  "tool": "payments.send",
  "arguments": {
    "amount": 500
  },
  "decision": "approval",
  "reason": "Policy matched for payments.send"
}

Request IDs allow individual security decisions to be traced through the audit log.

MCP Integration

Agent Firewall protects MCP tool execution through a policy mapping layer:

MCP tool             Firewall policy


read_file       -->  github.read_file


delete_file     -->  github.delete_file


send_payment    -->  payments.send

A protected operation is blocked before the underlying tool executes:

delete_file
     |
     v
Agent Firewall
     |
     +--> DENY
     |
     X
Tool never executes

The project has also been tested against a real GitHub MCP server.

Testing

Run the complete test suite:

pytest

The current suite contains unit, policy, security, approval, audit, MCP enforcement, and integration tests.

Current status:

73 tests passing
Project Structure
agent-firewall/
|
├── firewall/
│   └── engine.py
|
├── tests/
│   └── test_engine.py
|
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
├── requirements.txt
└── README.md
Status

Current development version: v0.2

The project focuses on policy enforcement, MCP security, human approval, auditability, security testing, and establishing a reliable authorization layer for AI agents.

Security

This project is experimental software.

Do not use it as the sole security control for production systems without independently reviewing and testing the implementation.

License

License to be added.



Then run:


```powershell
pytest

If you still get 73 passed, commit:

git add README.md
git commit -m "Update v0.2 documentation"
git push