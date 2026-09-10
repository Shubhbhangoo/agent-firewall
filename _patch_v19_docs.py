"""Update README, SECURITY.md, CHANGELOG, pyproject, and CI for v1.9."""

import io

# 1. README
path = "README.md"
source = io.open(path, encoding="utf-8").read()

old = """## v1.7 Simulate Before You Enforce"""
assert source.count(old) == 1, source.count(old)

new = """## v1.9 Agent Security Network

v1.9 turns Agent Firewall into a cross-agent **security system**: given
verified `.afw` artifacts from many sessions, it answers what agents can
do, what they are doing, what could happen if they were compromised, and
how to respond safely.

```bash
pip install agent-firewall-security==1.9.0
```

```bash
# Build a network from verified artifacts (failed artifacts are refused)
firewall network init --out network.json
firewall network ingest session-a.afw session-b.afw --state network.json

# Cross-agent intelligence
firewall network graph network.json --agent agent-a --reach
firewall network graph network.json --who-can-reach /etc/shadow
firewall network correlate network.json

# Deterministic, evidence-backed behavioral detection
firewall detect network.json --min-severity medium

# Attack-path discovery (reachable is not exploitable)
firewall attack-path network.json --agent agent-a --to /etc/shadow

# Isolated scenario simulation (what if this agent is compromised?)
firewall network simulate network.json scenario.json

# Policy-driven graduated response through the SDK's own mechanisms
firewall respond network.json --policy policy.json
```

Every fact in the network carries a provenance basis that is never
conflated: `observed` (recorded), `derived` (computed), `inferred`
(heuristic detection), `simulated` (scenario), `unknown` (missing).
A universal integration layer (`firewall.agents`) protects Python,
HTTP, MCP, OpenAI-compatible, and LangChain-style agents through one
adapter model, and the browser console gains a Security Operations
panel over the same modules.

See `docs/v1.9-architecture.md`, `docs/integrations.md`,
`docs/security-intelligence.md`, `docs/v1.9-cli.md`,
`docs/browser-console.md`, and `docs/v1.9-threat-model.md`.

## v1.7 Simulate Before You Enforce"""
source = source.replace(old, new, 1)

old = "pip install agent-firewall-security==1.8.0"
new = "pip install agent-firewall-security==1.9.0"
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

old = "## Version\n\n```text\n1.8.0\n```"
new = "## Version\n\n```text\n1.9.0\n```"
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

old = "The v1.8 validation result is **2,580+ passing tests**"
new = "The v1.9 validation result is **2,700+ passing tests**"
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("README patched")

# 2. SECURITY.md version table.
path = "SECURITY.md"
source = io.open(path, encoding="utf-8").read()

old = """| 1.8.x | Yes |
| 1.7.x | Yes |"""
new = """| 1.9.x | Yes |
| 1.8.x | Yes |"""
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)

# Insert the v1.9 boundary BEFORE the v1.8 header (only one exists).
old = """## v1.8 Security Boundary"""
assert source.count(old) == 1, source.count(old)

new = """## v1.9 Security Boundary

v1.9 adds the Agent Security Network: cross-agent correlation,
behavioral detection, attack-path analysis, scenario simulation, and
graduated response. Everything new is observational/analytical above
the existing authorization pipeline, except the response controller,
which is routed through the SDK's own revocation and risk mechanisms.

- Every artifact ingested into the network is verified first. A failed
  or unverifiable artifact is refused; its facts never enter the graph.
  The correlation index bundles artifacts by shared metadata ids, but a
  bundle is a label, never proof of a real relationship -- verification
  statuses are always reported.
- Every network fact carries a provenance basis that is never
  conflated: `observed` (recorded), `derived` (computed), `inferred`
  (behavioral heuristics), `simulated` (scenario), `unknown` (missing).
  Post-ingest additions must be explicitly inferred/simulated; claiming
  observed provenance is rejected.
- Behavioral detections are deterministic, explainable heuristics with
  named evidence; they are never presented as facts or as AI scoring.
- Attack-path statuses distinguish `simulated` / `reachable` /
  `policy-permitted` / `observed`. Reachability is never presented as
  exploitability.
- The scenario simulator runs in isolated throwaway workspaces seeded
  from recorded facts; it never modifies live authorization state, and
  its outcomes are labeled `simulated`. Contradictions are reported
  `unverifiable`, never hidden.
- Graduated response (observe -> warn -> restrict -> quarantine ->
  contain) is policy-driven, audited, explainable, fail-closed, and
  reversible where safe. High-impact stages require human approval
  unless the policy explicitly auto-approves. The response controller
  holds no signing keys and can only call the SDK APIs a Python caller
  could call.
- The integration adapters hold no authority of their own, route every
  protected call through the real authorization pipeline, never
  fabricate identity, and refuse unmapped HTTP endpoints with an
  explanation instead of guessing.

## v1.8 Security Boundary"""
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("SECURITY.md patched")

# 3. pyproject.
path = "pyproject.toml"
source = io.open(path, encoding="utf-8").read()
old = 'version = "1.8.0"'
new = 'version = "1.9.0"'
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("pyproject patched")

# 4. CI.
for wf in (".github/workflows/security.yml", ".github/workflows/cli.yml"):
    source = io.open(wf, encoding="utf-8").read()
    source = source.replace(
        "      - v1.8\n",
        "      - v1.8\n      - v1.9\n",
    )
    io.open(wf, "w", encoding="utf-8", newline="\n").write(source)
    print(f"{wf} patched")
