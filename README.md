# Agent Firewall


A policy-based security layer for AI agents and MCP tools.


Agent Firewall sits between an AI agent and the tools it can access. Every tool request is evaluated against security policies before it is allowed to execute.


## What it does


- Allow trusted tool actions
- Deny dangerous actions
- Require human approval for sensitive actions
- Validate tool arguments
- Fail closed when no policy matches
- Resolve conflicting policies using strongest restriction
- Log security decisions
- Protect real MCP tool calls


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

The firewall evaluates a request before the MCP tool is called.

Example Policy

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
MCP Integration

Agent Firewall has been tested against a real GitHub MCP server.

Tested behavior:

github.get_file_contents
        |
        +--> ALLOW
        |
        v
GitHub MCP Server
        |
        v
README.md

A protected operation is blocked before the MCP server receives the request:

github.delete_file
        |
        v
Agent Firewall
        |
        +--> DENY
        |
        X
MCP tool is never called
Installation

Clone the repository and create a virtual environment:

python -m venv .venv

Activate it on Windows:

.venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt
Running Tests

Run the complete test suite:

pytest

The current test suite includes unit, policy, security, and real MCP integration tests.

Project Structure
agent-firewall/
├── firewall/
│   └── engine.py
├── tests/
│   └── test_engine.py
├── policies.yaml
├── mcp_firewall.py
├── mcp_test_client.py
├── test_attacks.py
├── test_firewall.py
├── test_github_mcp.py
├── test_policy_attacks.py
├── test_policy_conflicts.py
├── requirements.txt
└── README.md
Status

This is an early v0.1 prototype.

The project is currently focused on policy enforcement, MCP integration, security testing, and establishing a reliable authorization layer for AI agents.

Security

This project is experimental software. Do not use it as the sole security control for production systems without independently reviewing and testing the implementation.

License

License to be added.



Then save it and run:


```powershell
pytest

If 16 passed, commit it:

git add README.md
git commit -m "Improve project documentation"
git push