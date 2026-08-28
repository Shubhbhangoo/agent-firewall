"""Prepend the v1.8 section to README.md and update version numbers."""

import io

PATH = "README.md"
source = io.open(PATH, encoding="utf-8").read()

# 1. Insert v1.8 section right after the H1.
old = """# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.7 Simulate Before You Enforce"""

new = """# Agent Firewall

Security and authorization infrastructure for AI agents and automated tool use.

Agent Firewall provides a capability-based security layer between an agent and the actions it is allowed to perform.

## v1.8 Portable, Verifiable Security Memory

v1.8 adds an **Agent Security Flight Recorder**: the security-relevant
lifecycle of an agent is captured as an ordered, tamper-evident chain of
events, anchored by Ed25519 signed checkpoints, and exported as a
portable `.afw` artifact that can leave the machine and be verified by
someone who does not trust the recorder.

```bash
pip install agent-firewall-security==1.8.0
```

The workflow:

```bash
# Record a session (through the real SDK) and write the artifact
firewall record --out session.afw --agent agent-demo

# Verify it independently: chain, hashes, signatures, completeness
firewall verify session.afw                  # status: verified

# Reconstruct the security story
firewall timeline session.afw                # chronological story
firewall trajectory session.afw              # posture transitions + evidence
firewall graph session.afw --agent agent-demo --why payments.send

# Counterfactual analysis: what if the policy had been different?
firewall replay session.afw --rules proposed-rules.json

# Package an incident for sharing (verification carried verbatim)
firewall incident create session.afw --title "credential access" --out incident.json
```

Verification distinguishes five states and never conflates them:
`verified` · `failed` · `unverifiable` · `incomplete` · `redacted`.
Missing evidence is reported, never treated as trustworthy. The browser
console gains a recorder panel with the timeline, trajectory, graph,
containment, and replay laboratory; CLI and browser are one system over
the same modules.

The v1.8 architecture is strictly observational/analytical above the
existing authorization pipeline. The recorder records after decisions
exist and can never influence one; replay runs in throwaway workspaces;
containment is the only new write path and it is routed through the
SDK's own revocation and risk mechanisms -- never around `authorize()`.

See `docs/v1.8-artifact-format.md`, `docs/v1.8-verification.md`,
`docs/v1.8-security-model.md`, `docs/v1.8-cli.md`, and
`docs/v1.8-console.md`.

## v1.7 Simulate Before You Enforce"""

assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 2. Update installation pins.
old = """```bash
pip install agent-firewall-security==1.7.0
```"""
new = """```bash
pip install agent-firewall-security==1.8.0
```"""
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 3. Update version block.
old = """## Version

```text
1.7.0
```"""
new = """## Version

```text
1.8.0
```"""
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# 4. Update the testing paragraph.
old = """The v1.7 validation result is **2,580 passing tests**."""
new = """The v1.8 validation result is **2,580+ passing tests**, including
dedicated v1.8 recorder, verifier, adversarial, fixture, projection, and
integration suites."""
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(source)
print("patched README.md")
