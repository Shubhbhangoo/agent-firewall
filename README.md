# Agent Firewall

**Security, evidence, and accountability infrastructure for autonomous AI agents.**

Agent Firewall is the **Agent Security Control Plane** for AI agents and
automated tool use: capability-based authorization, a cryptographically
verifiable flight recorder, cross-agent security intelligence, and a complete
control plane that connects every consequential action to identity, task,
authority, provenance, policy, decision, evidence, posture, risk, and
response.

```text
IDENTITY -> TASK -> AUTHORITY -> CAPABILITY -> PROVENANCE -> POLICY
-> DECISION -> EXECUTION -> EVIDENCE -> POSTURE -> RISK -> RESPONSE
```

> **v2.1 is the flagship release.** It builds the **Autonomous Agent
> Defense Layer** on top of the v2.0 control plane: a continuously
> operating defense system for autonomous agent ecosystems that
> understands who exists, what they can do, what they are doing, what
> they could reach, what changed, what might go wrong, and how to contain
> it - without ever breaking the authorization boundary.

---

## Installation

Latest release (Python 3.10+):

```bash
pip install agent-firewall-security
```

Pin an exact version for reproducibility:

```bash
pip install agent-firewall-security==2.1.0
```

From source (development):

```bash
git clone https://github.com/Shubhbhangoo/agent-firewall.git
cd agent-firewall
pip install -e ".[dev]"
```

This installs the `firewall` CLI. The package has only three runtime
dependencies: `PyYAML`, `mcp`, and `cryptography`.

---

## Quick Start

Protect one agent in three lines:

```python
from firewall.sdk import FirewallSDK

sdk = FirewallSDK()
sdk.generate_key("key-1")

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    constraints={"amount_max": 100},
)

result = sdk.authorize(capability, "payments.send", {"amount": 20})
print(result.allowed)   # True
```

The same `authorize()` path enforces issuer trust, revocation, delegation
lineage, constraints, replay protection, risk, budgets, and refusal state -
fail-closed, in a deterministic gate order.

Record that session as a portable, independently verifiable artifact:

```bash
firewall record --out session.afw --agent agent-demo
firewall verify session.afw          # status: verified
```

---

## v2.1 - The Autonomous Agent Defense Layer

v2.1 answers the question every *autonomous* agent ecosystem must
answer:

> Who exists, what can they do, what are they doing, what could they
> reach, what changed, what might go wrong, and how to contain it -
> without breaking the authorization boundary.

```bash
# Real-time defense mesh: live identity/trust/capability evaluation
firewall defense evaluate agent-a --registry identities.json
firewall defense quarantine agent-a --reason "incident" --registry identities.json
firewall defense recover agent-a --reason "clean" --registry identities.json
firewall defense reenter agent-a --reason "verified" --registry identities.json

# Agent-to-agent zero trust: mutual auth + scoped, narrowing grants
firewall delegate establish --initiator alice --responder bob \
    --permissions '{"allowed_actions": ["read"]}' --registry identities.json
firewall delegate authorize --actor alice --target bob --action read

# Capability Firewall 2.0: composable constraints, safe attenuation
firewall capability eval policy.json '{"resource": "payments", "action": "send"}'
firewall capability attenuate policy.json --out narrowed.json --narrowing '{"action": ["send"]}'

# Continuous attack graph + digital twin (simulated, isolated)
firewall attack-graph build network.json --out attack-graph.json
firewall attack-graph paths attack-graph.json --target /etc/shadow
firewall twin network.json --kind compromised_agent --agent agent-a

# Tamper-evident evidence graph (signed, hash-linked, explicit kinds)
firewall evidence append --state evidence.json --kind observed \
    --subject agent-a --type decision --payload '{"allowed": true}'
firewall evidence verify --state evidence.json

# Immune system: OBSERVE..VERIFY loop (model output is advisory only)
firewall immune demo --policy immune-policy.json

# Security Research Lab 3.0: attack the control plane itself
firewall research run
firewall research properties

# Performance benchmarks
python -m firewall.benchmarks
```

### What v2.1 adds

| primitive | module | what it gives you |
| --- | --- | --- |
| **Defense mesh** | `firewall.defense` | continuously evaluates identity, trust, and capability per agent; quarantines compromised agents through the v2.0 containment controller; audited recovery and re-entry; fail-closed. |
| **A2A zero trust** | `firewall.a2a` | mutual cryptographic authentication, scoped relationships, task-bound delegation, expiring grants, recursive revocation, cross-agent authorization with an SDK gate. |
| **Attack graph** | `firewall.attackgraph` | continuous attack-path engine: escalation paths, capability combinations, delegation abuse, trust transitivity, chokepoints, blast radius - every path labeled by its weakest basis. |
| **Digital twin** | `firewall.twin` | isolated counterfactuals (compromise, revocation, untrusted tool, delegation, credential exposure) returning reachability deltas, blast radius, containment opportunities, and risk deltas - never touching live state. |
| **Evidence graph** | `firewall.evidence_graph` | signed, hash-linked events with causal ordering, tamper detection, replayable timelines, and explicit evidence kinds; promotion to observed is explicit and signed. |
| **Capability Firewall 2.0** | `firewall.capability2` | composable constraints over resource/scope/action/time/context/identity/task/lineage/provenance/environment; a delegated capability never gains authority. |
| **Immune system** | `firewall.immune` | OBSERVE -> DETECT -> REASON -> SIMULATE -> CONTAIN -> RECOVER -> VERIFY; the reasoner (LLM or default) is advisory only - a deterministic policy rule is required to execute anything. |
| **Research Lab 3.0** | `firewall.research` | 11 adversarial scenarios against the control plane itself plus property tests; every discovered violation becomes a regression test. |
| **Intelligence engine** | `firewall.intel` | correlates evidence, behavior, trust, provenance, posture, attack paths, and response history into explainable hypotheses with recommended containment. |

**The v2.1 guarantee:** the reasoning system never becomes the
authorization authority. Every v2.1 subsystem is observational or
analytical above the v2.0 `FirewallSDK` boundary; analysis feeds context,
the pipeline alone decides, and the immune system's defensive actions
execute only through the v2.0 containment controller and the SDK's own
revocation and risk mechanisms.

See `docs/v2.1-architecture.md`, `docs/v2.1-threat-model.md`,
`docs/v2.1-invariants.md`, `docs/v2.1-migration.md`,
`docs/v2.1-cli.md`, and `docs/v2.1-benchmarks.md`.

## v2.0 - The Agent Security Control Plane

v2.0 answers the question every agent security system must answer:

> Who performed this action, under what authority, for what task, using which
> capability/tool, according to which policy, what happened, what evidence
> proves it, what posture resulted, and what response occurred?

```bash
# Identity: who is this agent (create/rotate/revoke)
firewall identity create agent-a --registry identities.json --passphrase pw
firewall identity show --registry identities.json

# Task-bound authority: what it is doing (delegation only narrows)
firewall task create agent-a --permissions '{"allowed_actions": ["read"]}'
firewall task delegate <task-id> agent-b --permissions '{"allowed_actions": ["read"]}'

# A verifiable security passport (identity + posture, signed)
firewall passport show agent-a --out passport.json
firewall passport verify passport.json --registry identities.json

# Supply-chain provenance (a name is never trust)
firewall provenance register tool payments.send --integrity sha256:...
firewall provenance trust trust tool:payments.send:1.0 --reason reviewed

# Continuous posture, trust graph, and the Security Lab
firewall posture state.json --agent agent-a
firewall trust network.json --radius agent-a
firewall lab sweep network.json
firewall lab counterfactual network.json --agent agent-a --added admin.bypass
```

### What v2.0 adds

| primitive | module | what it gives you |
| --- | --- | --- |
| **Agent identity** | `firewall.ident` | persistent cryptographic identity: create/rotate/revoke/retire, key fingerprints, parent/child, encrypted key storage. Identity never implies authorization - verification fails for forged, stolen, rotated-out, revoked, and unknown identities. |
| **Task-bound authority** | `firewall.task` | actions scoped to a task; delegation chains whose effective permissions are the *intersection* of parent and grant, so A -> B -> C can never escalate; subtree revocation; expiration. |
| **Security passport** | `firewall.passport` | a deterministic, signed, exportable summary of identity + posture + capabilities + tasks + delegated authority + provenance + reach - never containing private keys, verifiable by anyone with the identity key. |
| **Cryptographic attestation** | `firewall.attest` | signed, versioned statements about authority, delegation, decisions, and events, with explicit algorithm metadata (replaceable for post-quantum) and a `verified` / `failed` / `unverifiable` verifier that never conflates them. |
| **Supply-chain provenance** | `firewall.provenance` | integrity and explicit trust for models, tools, MCP servers, skills, plugins, packages, adapters, configuration, and policies. A name is never trust; revoking a component marks its dependents untrusted. |
| **Continuous posture** | `firewall.posture` | evidence-backed states (unknown -> healthy -> degraded -> suspicious -> high_risk -> compromised -> contained -> recovering -> retired) with explainable transitions. |
| **Trust graph** | `firewall.trust` | what-can, who-can, who-delegated, what-changed, blast-radius, and path queries plus inferred danger detection. |
| **Security Lab 2.0** | `firewall.lab` | automated environment sweeps and counterfactuals (tool compromise, capability revocation, policy change) in isolated workspaces - never touching live state. |
| **Adaptive response** | `firewall.response2` | evidence-backed graduated response with TTL, human approval for high-impact stages, auditing, and signed attestation of every decision. |

**The v2.0 guarantee:** identity proves *who*; the authorization pipeline
alone decides *what*. Every new primitive is observational/analytical above
the existing `FirewallSDK` authorization boundary - none of them can authorize,
bypass, or relax a decision.

See `docs/v2.0-architecture.md`, `docs/v2.0-identity.md`,
`docs/v2.0-threat-model.md`, `docs/v2.0-migration.md`,
`docs/v2.0-cli.md`, and `docs/v2.0-boundaries.md`.

---

## What Agent Firewall Does

### 1. The Agent Security Control Plane (v2.0)

The flagship release (see the section above): persistent identity,
task-bound authority, security passports, cryptographic attestation,
supply-chain provenance, continuous posture, a trust graph, the Security
Lab, and adaptive response - all layered over the existing authorization
pipeline and all independently verifiable.

### 2. Authorize - the capability core (v1.0-v1.6)

- **Signed capabilities** are the authority presented for an operation.
  Verification checks cryptographic integrity, issuer trust, expiration,
  revocation, constraints, and replay state.
- **North Star** orchestrates authorization as deterministic, fail-closed
  gates: refusal memo, runtime risk, issuer trust, revocation, time validity,
  delegation lineage, depth policy, cryptographic authority, and the terminal
  security transaction. `FirewallSDK.authorize()` remains the decision
  authority.
- **Delegation** is tracked as `child -> parent -> ancestor`; the full chain is
  evaluated at authorization time, and revoking a parent propagates to every
  descendant. Lineage can be capped with `max_delegation_depth`.
- **Attenuation** narrows capabilities without widening authority
  (`amount_max`, `path_prefix`, tool binding, ...).
- **Budgets**: cumulative delegation-budget amounts are shared across a whole
  lineage and enforced atomically.
- **Tool output is data, not authority** - protected tools mark returned text
  untrusted, so injected instructions never acquire capability authority.

### 3. Simulate before you enforce (v1.7)

```bash
firewall simulate cases.json --max-depth 2
firewall simulate cases.json --rules proposed-rules.json --baseline current-rules.json
```

A rule change (delegation depth, trusted issuers) is replayed against recorded
traffic in isolated throwaway workspaces using the **real authorization
pipeline**. Fidelity is measured, not assumed: cases that cannot be reproduced
are reported, never counted. Staged rollout (`observe -> warn -> enforce`) is
simulation-first, acknowledgement-gated, and exactly rollback-able. Exit code
`0` means "nothing that works today would break and every case was verified".

### 4. Record + verify - portable security memory (v1.8)

The **Agent Security Flight Recorder** captures an agent's security-relevant
lifecycle as an ordered chain of SHA-256-hashed events, anchored by Ed25519
signed checkpoints, and exports it as a portable `.afw` artifact:

```bash
firewall record --out session.afw --agent agent-demo

# Independent verification: chain, hashes, signatures, completeness
firewall verify session.afw
firewall verify session.afw --expect-recorder <fingerprint>
```

Verification returns **five states that are never conflated**:

| status | meaning |
| --- | --- |
| `verified` | every check passed, no redactions |
| `failed` | a concrete integrity violation - do not trust it |
| `unverifiable` | not a recognizable artifact at all |
| `incomplete` | everything present verifies, but the recording was cut short |
| `redacted` | integrity intact, content deliberately removed (declared) |

Secrets never enter an artifact: credential-shaped values are redacted
*before* hashing, and the redaction is declared in the manifest. The `.afw`
format is fully specified in `docs/v1.8-artifact-format.md` so other projects
can implement readers and verifiers independently.

Investigate a session with:

```bash
firewall timeline session.afw          # chronological security story
firewall trajectory session.afw        # posture transitions + evidence
firewall graph session.afw --agent agent-demo --why payments.send
firewall replay session.afw --rules proposed-rules.json   # counterfactual
firewall incident create session.afw --title "credential access"
```

### 5. The Agent Security Network (v1.9)

Given verified `.afw` artifacts from many sessions, Agent Firewall becomes a
cross-agent **security system**: what agents can do, what they are doing, what
could happen if they were compromised, and how to respond safely.

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

Every fact in the network carries a provenance basis that is never conflated:

| basis | meaning |
| --- | --- |
| `observed` | recorded directly in an artifact's event chain |
| `derived` | computed deterministically from observed facts |
| `inferred` | a heuristic behavioral detection (labeled as inference) |
| `simulated` | produced by the scenario simulator in an isolated workspace |
| `unknown` | evidence missing or unverifiable - never promoted to trust |

**A universal integration layer** (`firewall.agents`) protects agents across
environments with one adapter model - Python loops, custom loops, HTTP/API
agents, MCP, OpenAI-compatible interfaces, and LangChain/LangGraph-style
systems. Adapters hold no authority of their own, route every protected call
through the real `FirewallSDK` pipeline, never fabricate identity, and degrade
gracefully when an environment cannot provide information.

---

## Security Model

The architecture is strictly layered. Everything added after v1.6 is
**observational or analytical above the authorization pipeline** - analysis
feeds context, the pipeline alone makes decisions:

```text
signals / history / analysis (recorder, network, posture, lab, trust)
              |
              v
   security context (identity, tasks, risk, refusal, budgets, state)
              |
              v
   existing authoritative authorization (FirewallSDK / North Star)
              |
              v
           final decision
```

Non-negotiables:

- **Monitoring never authorizes.** The recorder, network, posture, and lab are
  observational; none of them can allow an action.
- The recorder records decisions only *after* they exist, and a recorder
  failure can never break an authorization. No recorder attached means zero
  overhead.
- The verifier never conflates missing evidence with trustworthy evidence.
  Failed artifacts are refused at network ingest - their facts never enter the
  graph or the detection engine.
- **Identity never implies authorization.** Verification checks signatures,
  status, and key fingerprints; forged, stolen, rotated-out, revoked, retired,
  and unknown identities fail.
- **Task delegation only narrows.** A -> B -> C chains can never escalate;
  root revocation propagates to the whole subtree.
- Replay, simulation, and the Security Lab run in **isolated throwaway
  workspaces** and never touch a live SDK.
- Containment and response are the only write paths, and they are routed
  through the SDK's own revocation registry and risk context - a contained
  agent is contained because `authorize()` denies it. High-impact responses
  (`quarantine`, `contain`) require human approval unless the policy
  explicitly auto-approves.
- There is no "AI says safe -> allow" path. Ever.

### Delegation, budgets, and revocation

Delegation is tracked as `child fingerprint -> parent fingerprint -> ancestor`.
The complete chain is evaluated at authorization time; revoking a parent or
intermediate authority propagates to descendants.

v1.5 adds a cumulative lineage budget owned by the root capability:

```python
sdk.configure_delegation_budget(capability, max_total_amount=100)
sdk.authorize_with_delegation_budget(child_capability, "payments.send", {"amount": 40})
```

Parent, child, and grandchild capabilities consume the same budget; separate
roots keep separate budgets.

### Attenuation

```python
child = sdk.attenuate(
    capability,
    private_key,
    constraints={"amount_max": 50},
)
```

Genuinely distinct attenuated capabilities share the lineage used for
effective revocation; no-op attenuation stays backward compatible.

### Session capabilities (v1.5)

```python
session_cap = sdk.mint_session_capability(
    agent="agent-a",
    tool="filesystem.read",
    capability="filesystem.read",
    ttl=300,
)
```

Short-lived, tool-bound: it expires from a fresh timestamp and cannot
authorize a different tool.

### Other hardening

- **Authorization traces** exclude signatures, public keys, raw request
  payloads, and full constraint data.
- **Semantic chain security** (`SemanticChainContext`) protects multi-step
  workflows with deterministic, chain-scoped state and atomic
  begin/commit/abort.
- **Persistent security context** (`SecurityContext(state_path=...)`) survives
  restarts with integrity checking; corrupted state fails closed.
- **Numeric hardening**: `NaN`, `+inf`, `-inf` are rejected in every
  security-sensitive number (TTLs, timestamps, clocks, budgets).

---

## The Browser Console

A local developer/security console ships with the package - standard library
server, vanilla HTML/CSS/JS, no build step:

```bash
python -m firewall.ui                  # read-only inspection console
python -m firewall.ui --control        # audited local control plane
```

It shows the real security system - North Star gate status, decisions,
delegation authority, revocation, posture, lifecycle - plus:

- **v2.0 identity & supply-chain panel**: agent identities with lifecycle and
  key fingerprints, verifiable security passports, and supply-chain
  provenance.
- **v1.9 Security Operations panel**: active agents with reach, behavioral
  detections, correlation bundles, sensitive resources, attack-path queries,
  and scenario simulation.
- **v1.8 recorder panel**: verification banner, security timeline, posture
  trajectory, relationship graph, containment state, replay laboratory.

The control plane binds to loopback, requires a startup bearer token, routes
every mutation through existing SDK APIs, and records everything in the audit
stream. It is a trusted local developer interface, not an unauthenticated
production service.

---

## CLI at a glance

```bash
# Configuration & inspection
firewall init
firewall validate firewall.yaml
firewall inspect-token <token>
firewall explain lifecycle.db [--fingerprint <fp>] [--json]

# Control plane (v2.0)
firewall identity create agent-a --registry identities.json --passphrase pw
firewall identity rotate agent-a --registry identities.json
firewall identity revoke agent-a --reason "..." --registry identities.json
firewall task create agent-a --permissions '{"allowed_actions": ["read"]}'
firewall task delegate <task-id> agent-b --permissions '{"allowed_actions": ["read"]}'
firewall passport show agent-a --out passport.json
firewall passport verify passport.json --registry identities.json
firewall attestation verify attestation.json --registry identities.json
firewall provenance register tool payments.send --integrity sha256:...
firewall provenance trust trust tool:payments.send:1.0 --reason reviewed
firewall posture state.json --agent agent-a
firewall trust network.json --radius agent-a
firewall lab sweep network.json
firewall lab counterfactual network.json --agent agent-a --added admin.bypass

# Network (v1.9)
firewall network init | ingest | graph | correlate | simulate
firewall detect network.json [--min-severity medium]
firewall attack-path network.json [--agent a --to target | --summary]
firewall respond network.json [--policy policy.json]

# Record & verify (v1.8)
firewall record [--out session.afw] [--agent agent-demo]
firewall inspect session.afw
firewall verify session.afw [--expect-recorder <fp>]
firewall timeline session.afw
firewall trajectory session.afw
firewall graph session.afw [--agent a --why action | --reach]
firewall replay session.afw [--rules proposed.json]
firewall incident create session.afw [--title "..."] [--redact]
firewall redact session.afw --out redacted.afw

# Simulation & rollout (v1.7)
firewall simulate cases.json [--rules r.json] [--baseline b.json] [--max-depth N]
```

Exit-code contract: `0` success / meaningful positive result; `1` meaningful
negative result (incomplete artifact, no detections, unsafe simulation); `2`
inputs could not be used.

---

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The full regression suite is **2,800+ passing tests** covering the SDK,
capabilities, delegation, revocation, budgets, semantic chains, North Star,
the console and control plane, v1.7 simulation/rollout, the v1.8 recorder/
verifier (including a 25-test adversarial suite with committed malicious
`.afw` fixtures), the v1.9 network (graph poisoning, correlation spoofing,
adapter abuse, simulator isolation), and the v2.0 control plane (forged,
stolen, and revoked identities, delegation escalation through A -> B -> C
chains, passport and attestation forgery, confused-deputy relabeling,
malicious provenance, and lineage-cycle fail-closed behavior).

## CI

Security CI and CLI CI run on Python 3.10, 3.11, and 3.12 for every maintained
release branch. CLI CI exercises the installed `firewall` command end to end,
including the `simulate` exit contract and JSON output.

---

## Documentation

| topic | doc |
| --- | --- |
| v2.0 architecture | `docs/v2.0-architecture.md` |
| v2.0 identity, task, passport, attestation | `docs/v2.0-identity.md` |
| v2.0 threat model | `docs/v2.0-threat-model.md` |
| v2.0 migration guide | `docs/v2.0-migration.md` |
| v2.0 CLI reference | `docs/v2.0-cli.md` |
| v2.0 security boundaries | `docs/v2.0-boundaries.md` |
| v1.9 architecture | `docs/v1.9-architecture.md` |
| integrations guide | `docs/integrations.md` |
| security intelligence, attack paths, simulator | `docs/security-intelligence.md` |
| v1.9 CLI / browser SOC | `docs/v1.9-cli.md`, `docs/browser-console.md` |
| v1.8 artifact format spec | `docs/v1.8-artifact-format.md` |
| verification & replay laboratory | `docs/v1.8-verification.md` |
| security model | `docs/v1.8-security-model.md` |
| v1.8 CLI / console | `docs/v1.8-cli.md`, `docs/v1.8-console.md` |
| threat model | `docs/v1.9-threat-model.md` |
| v1.7 simulation | `docs/v1.7-simulation.md` |

## Package

| | |
| --- | --- |
| PyPI | `agent-firewall-security` |
| Repository | https://github.com/Shubhbhangoo/agent-firewall |
| Version | `2.0.0` |
| License | MIT (see repository license file) |
