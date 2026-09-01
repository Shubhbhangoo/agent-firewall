# Agent Firewall

**Security control-plane infrastructure for autonomous AI agents and automated tool use.**

Agent Firewall is built around one security boundary: **authorization remains deterministic, explicit, and fail-closed**. Identity, provenance, monitoring, behavioral analysis, simulation, evidence, and response provide security context around that boundary, but they do not become an alternative path to authorization.

> **v2.2** makes the control plane adaptive: authority is re-evaluated when the state it rested on changes, contradictions between independent claim sources are reported rather than resolved, and the architectural properties the design rests on are checked by code instead of asserted in prose.

---

## Security model

The central rule is simple:

```text
IDENTITY -> TASK -> AUTHORITY -> CAPABILITY -> PROVENANCE -> POLICY
                                      |
                                      v
                                   DECISION
                                      |
                                      v
                                  EXECUTION
                                      |
                                      v
                         EVIDENCE -> POSTURE -> RISK -> RESPONSE
```

The security system is deliberately layered.

```text
signals / telemetry / history / analysis
                  |
                  v
        security context and evidence
                  |
                  v
      deterministic authorization gate
                  |
                  v
          ALLOW / DENY / REFUSE
                  |
                  v
              execution
```

### The authorization boundary

`FirewallSDK.authorize()` is the authoritative decision path. Security analysis may supply context, but no analyzer, LLM, detector, graph, recorder, or monitoring component can directly grant authority.

The design therefore rejects patterns such as:

```text
LLM says safe -> allow
risk score is low -> allow
agent is trusted -> allow
monitoring saw no attack -> allow
```

Instead:

```text
security evidence -> policy/context -> authorization pipeline -> decision
```

When required evidence is unavailable, verification fails, identity is unknown, or a security control cannot establish the required basis, the safe outcome is refusal.

---

## What v2.2 adds

### Continuous authorization

`firewall.continuous_auth` re-evaluates a granted authority when the state
it rested on changes. Fifteen revalidation triggers cover identity, task,
capability, delegation, provenance, posture, risk, trust, policy,
environment, incident, time, and explicit request.

It is not a second decision engine. Revalidation re-invokes
`FirewallSDK.authorize()` and compares verdicts, and its gating can only
turn an allow into a deny — never the reverse.

Every watched subsystem is an explicit constructor argument. An omitted
dependency makes its change class **undetectable**, which is deliberate
and visible at the call site rather than silently defaulted. A *configured*
dependency that raises is recorded as `PROBE_FAILED` — distinct from
`UNKNOWN`, which means "not wired" — and turns an allow into
`security_dependency_unavailable`.

### Machine-checked invariants

`firewall.invariants` states each architectural property once and checks it
with exactly one function, so an invariant with no check is a missing
registry entry rather than a silently absent property.

```bash
python -m firewall.invariants
```

Status is three-valued. `UNVERIFIABLE` is falsy, makes the whole report
falsy, and makes `assert_all` raise — accepting it would make the assertion
satisfiable by breaking the checker. A source-only run gates the three
structural and three self-contained invariants; the five state-dependent
ones need an exercised SDK.

### Adversarial discrepancy analysis

`firewall.adversarial` compares what an agent claims about itself against
recorded control-plane facts. Profiles default to `unknown` risk and can
never report `low` while a required fact is unestablished. A check that
raises produces an explicit gap rather than a clean profile.

### Deception and contradiction detection

`firewall.deception` compares eight independent classes of claim about an
agent — identity, task, capability, provenance, behaviour, posture,
delegation, authorization — and reports named contradictions between them.
It does not pick a winner: a contradiction is a finding for a human or a
containment operator, not a resolved fact.

### Evidence integrity

`firewall.evidence_integrity` verifies the evidence graph with three-valued
reporting. *Proven tampered*, *could not be checked*, and *passed* are
three separate outcomes. Any tamper finding at all yields `failed`,
regardless of the finding's triage severity.

Statuses, worst first: `failed` (proof of tampering), `unverifiable` (an
event's authenticity is unknown), `incomplete` (authenticity held, some
check could not run), `verified` (every check ran and passed).

### Long-lived security memory

`firewall.security_memory` maintains long-lived hash-linked chains with
signed checkpoints. `EvidenceChain.verified` is a cached result of an actual
`verify_chain()` call, never true by construction and never restored from
disk.

Imports are quarantined. An import that cannot be verified is refused
rather than stored as unverified, and imported chains are held apart from
the local evidence graph rather than merged into it.

### Adversarial digital twin

`firewall.twin.adversarial` searches the recorded security graph for
weaknesses under an explicit node and time budget, so every search
terminates and reports whether it was cut short. Like the rest of the twin
it reads a deep copy and holds no live registry reference.

Every finding carries a `basis`, and a search may never label its own
conclusion `observed` — constructing one raises. A reachable path is
reachability, not exploitability.

### Shared provenance vocabulary

`firewall.platform` holds the vocabulary the v2.2 analytical subsystems
agree on — how strongly something is known, never whether it is permitted.
It re-exports `firewall.network.model.Provenance` rather than declaring a
parallel enum, so a finding's provenance and an attack path's basis stay
directly comparable. Two representations of one security concept are a
hazard; the package exists to avoid adding another.

It is used by `firewall.adversarial` and `firewall.invariants`; the
remaining v2.2 subsystems still carry their own provenance handling and
have not been migrated onto it.

---

## v2.1 defense layer

v2.2 is layered on the v2.1 defense layer rather than replacing it.

### Defense mesh

`firewall.defense` continuously evaluates agent identity, trust, posture, and capabilities. It supports quarantine, audited recovery, re-entry, revocation, and signed transition evidence.

The mesh does not authorize operations. It uses the existing containment and authorization mechanisms to enforce security state.

### Agent-to-agent zero trust

`firewall.a2a` provides:

- mutual cryptographic authentication
- single-use, TTL-bound challenges
- scoped agent relationships
- task-bound delegation
- capability attenuation by intersection
- delegation-chain verification
- expiring grants
- recursive revocation
- trust establishment and teardown
- cross-agent authorization through an optional SDK provider

Delegation can narrow authority, never widen it.

### Attack graph

`firewall.attackgraph` builds bounded attack-path analysis across agents, identities, tasks, capabilities, tools, resources, delegations, provenance, policy, trust, and incidents.

Paths can expose:

- privilege escalation opportunities
- dangerous capability combinations
- delegation abuse
- trust transitivity
- blast radius
- high-risk chokepoints

Every path retains an evidence basis such as `observed`, `derived`, `inferred`, or `simulated`. A path cannot become stronger than its weakest supporting basis.

### Security digital twin

`firewall.twin` performs isolated counterfactual analysis over deep-copied security graphs.

Supported scenarios include:

- compromised agents
- capability revocation
- untrusted tools
- new delegation
- credential exposure

The twin does not hold a live registry reference and does not mutate production state. Results are explicitly marked `simulated`.

### Cryptographic evidence graph

`firewall.evidence_graph` provides signed, hash-linked security events with:

- strict sequence ordering
- causal relationships
- hash and link verification
- signature verification
- tamper detection
- replayable incident timelines
- cryptographic provenance chains

Evidence types remain structurally distinct. An inference is not silently converted into an observation. Promotion to `observed` requires an explicit signed action and reason, while the original event remains intact.

### Capability Firewall 2.0

`firewall.capability2` adds composable constraints over:

- resources
- scopes
- actions
- time
- context
- agent identity
- task identity
- delegation lineage
- provenance
- environment

Attenuation is structural. A delegated capability must be narrower than its parent and cannot acquire authority through delegation.

### Agent immune system

`firewall.immune` implements:

```text
OBSERVE -> DETECT -> REASON -> SIMULATE
    -> CONTAIN -> RECOVER -> VERIFY
```

The reasoner may be an LLM or deterministic default component, but its output is advisory. A deterministic policy rule is required before a defensive action executes. High-impact containment remains subject to the configured approval boundary.

### Security Research Lab 3.0

`firewall.research` attacks the control plane itself using adversarial scenarios covering malicious agents, forged identities, delegation chains, capability escalation, revocation bypass, provenance poisoning, replay, trust manipulation, confused-deputy behavior, cross-agent escalation, and policy conflicts.

Discovered violations can become regression-test seeds.

### Security intelligence

`firewall.intel` correlates evidence, posture, trust, attack paths, chokepoints, and response history into explainable security hypotheses and recommended containment actions.

Intelligence is analysis, not authority.

---

## v2.0 security foundation

v2.1 is layered on the v2.0 control plane rather than replacing it, and
v2.2 is layered on both.

### Cryptographic identity

`firewall.ident` provides persistent agent identities with key rotation, revocation, retirement, fingerprints, and signed state.

**Identity is not authorization.** Possessing a valid identity does not automatically grant a capability.

### Task-bound authority

`firewall.task` binds permissions to tasks and enforces narrowing delegation. A chain such as `A -> B -> C` cannot escalate beyond the authority inherited from its ancestors.

### Security passports and attestation

`firewall.passport` and `firewall.attest` provide signed, exportable security statements about identity, posture, authority, delegation, decisions, and events.

Verification distinguishes valid, failed, and unverifiable evidence rather than treating missing evidence as trustworthy.

### Supply-chain provenance

`firewall.provenance` tracks models, tools, MCP servers, skills, plugins, packages, adapters, configuration, and policies.

A component name is never treated as proof of integrity or trust. Revocation can propagate to dependent components.

### Continuous posture

`firewall.posture` maintains evidence-backed states from `unknown` through healthy, degraded, suspicious, high-risk, compromised, contained, recovering, and retired states.

### Trust and response

`firewall.trust`, `firewall.lab`, and `firewall.response2` provide trust analysis, isolated counterfactuals, and graduated evidence-backed response while preserving the authorization boundary.

---

## Fail-closed guarantees

The architecture is designed around explicit security invariants.

- **Authorization has one canonical decision path.**
- **Monitoring cannot authorize.**
- **Re-evaluation cannot grant.** Continuous authorization can only turn an allow into a deny.
- **Identity does not imply authority.**
- **Delegation cannot escalate authority.**
- **A signed lineage claim outranks the mutable delegation registry.**
- **Revocation propagates through delegation lineage.**
- **Unverified artifacts are not trusted as evidence.**
- **Inference, prediction, simulation, and observation remain distinct.**
- **Simulation and replay do not modify live security state.**
- **Tool output is data, not authority.**
- **LLM output cannot directly authorize or approve a protected operation.**
- **High-impact response actions remain policy and approval gated.**
- **A check that could not run is not a check that passed.**
- **Security failures default toward refusal rather than implicit trust.**

These are implementation properties of the system, not a claim that any deployment is universally secure. Eleven such properties are additionally stated once in `firewall.invariants` and checked by code rather than asserted in prose alone; see [`docs/v2.2-invariants.md`](docs/v2.2-invariants.md).

---

## Evidence model

Security facts are intentionally classified by their basis:

| Basis | Meaning |
| --- | --- |
| `observed` | Directly recorded security evidence |
| `derived` | Deterministically computed from recorded evidence |
| `inferred` | Analytical or heuristic finding |
| `simulated` | Produced by an isolated counterfactual |
| `unknown` | Required evidence is missing or unverifiable |

This distinction matters. A simulated attack path is not evidence that the attack occurred. An inference is not an observation. Unknown is not trusted.

The flight recorder extends this model with portable `.afw` artifacts, cryptographic hashes, signed checkpoints, declared redaction, and independent verification.

```bash
firewall record --out session.afw --agent agent-demo
firewall verify session.afw
firewall timeline session.afw
firewall trajectory session.afw
```

Verification distinguishes states including `verified`, `failed`, `unverifiable`, `incomplete`, and `redacted`.

---

## Installation

Python 3.10+ is required.

```bash
pip install agent-firewall-security==2.2.0
```

Development installation:

```bash
git clone https://github.com/Shubhbhangoo/agent-firewall.git
cd agent-firewall
pip install -e ".[dev]"
```

Runtime dependencies are intentionally small:

- PyYAML
- mcp
- cryptography

---

## Minimal authorization example

```python
from firewall.sdk import FirewallSDK

sdk = FirewallSDK()
sdk.generate_key("key-1")

capability = sdk.issue(
    agent="agent-a",
    capability="payments.send",
    constraints={"amount_max": 100},
)

result = sdk.authorize(
    capability,
    "payments.send",
    {"amount": 20},
)

print(result.allowed)
```

The authorization path evaluates the security conditions required by the capability and policy rather than delegating the final decision to a model or monitoring component.

---

## Command surface

v2.2 adds no new CLI subcommands. Its one new entry point is the invariant
checker, `python -m firewall.invariants`, shown above.

```bash
# Defense mesh
firewall defense evaluate agent-a --registry identities.json
firewall defense quarantine agent-a --reason "incident" --registry identities.json
firewall defense recover agent-a --reason "clean" --registry identities.json
firewall defense reenter agent-a --reason "verified" --registry identities.json

# Agent-to-agent authorization
firewall delegate establish --initiator alice --responder bob \
  --permissions '{"allowed_actions": ["read"]}' \
  --registry identities.json
firewall delegate authorize --actor alice --target bob --action read

# Capability analysis
firewall capability eval policy.json '{"resource":"payments","action":"send"}'
firewall capability attenuate policy.json --out narrowed.json \
  --narrowing '{"action":["send"]}'

# Attack-path analysis
firewall attack-graph build network.json --out attack-graph.json
firewall attack-graph paths attack-graph.json --target /etc/shadow

# Digital twin
firewall twin network.json --kind compromised_agent --agent agent-a

# Evidence
firewall evidence append --state evidence.json --kind observed \
  --subject agent-a --type decision --payload '{"allowed":true}'
firewall evidence verify --state evidence.json

# Immune system
firewall immune demo --policy immune-policy.json

# Security research
firewall research run
firewall research properties

# Benchmarks
python -m firewall.benchmarks
```

---

## Testing and adversarial validation

The repository contains unit, integration, adversarial, hardening, evidence, UI/API, benchmark, and research tests.

The v2.2 test surface covers, among other properties:

- capability attenuation
- delegation narrowing
- structural delegation monotonicity
- signed lineage agreeing with registered lineage
- continuous revalidation through the canonical authorization path
- unavailable security dependencies turning an allow into a deny
- identity and revocation behavior
- attack-path analysis
- digital-twin isolation
- evidence-chain integrity
- tamper detection
- causal ordering
- evidence promotion
- three-valued integrity and invariant reporting
- quarantined evidence import
- UI/API boundaries
- control-route authentication
- legacy v2.1, v2.0 and v1.9 compatibility
- benchmark execution
- credential and private-key scanning

Run the test suite with:

```bash
pytest
```

Check the architectural invariants against the source tree with:

```bash
python -m firewall.invariants
```

Run the benchmark suite with:

```bash
python -m firewall.benchmarks
```

Security testing is treated as part of the implementation rather than as a separate documentation claim.

---

## Architecture boundaries

The following separation is intentional:

```text
                 ANALYSIS / INTELLIGENCE
      +------------------------------------------+
      | telemetry | evidence | posture | intel   |
      | graphs    | twin     | research | LLM    |
      +--------------------+---------------------+
                           |
                           v
                  SECURITY CONTEXT
                           |
                           v
             +---------------------------+
             |     FirewallSDK           |
             | canonical authorization   |
             | deterministic gates       |
             | fail-closed decision      |
             +-------------+-------------+
                           |
                    ALLOW / DENY
                           |
                           v
                       EXECUTION
```

The important property is not how much analysis surrounds the gate. It is that analysis cannot silently become a second authorization mechanism.

---

## Security limitations

Agent Firewall is security infrastructure, not a guarantee that an entire deployment is secure.

It cannot compensate for compromised operating systems, malicious administrators, insecure deployment configuration, compromised cryptographic keys, vulnerabilities in protected applications, or attacks outside the information supplied to the control plane.

The security properties described here depend on correct integration, key management, policy configuration, and preservation of the authorization boundary.

The digital twin, attack graph, intelligence engine, and reasoner produce analysis. Their output must not be interpreted as proof of future behavior or proof that an environment is safe.

---

## Responsible security research

Security findings should be reported privately before public disclosure when they could affect users or downstream deployments.

Please include:

- affected version or commit
- affected component
- reproduction steps
- expected security property
- observed behavior
- impact assessment
- proof-of-concept where appropriate

See [`SECURITY.md`](SECURITY.md) for the project's security reporting policy.

---

## Documentation

Detailed specifications are maintained in the repository:

- `docs/v2.2-architecture.md`
- `docs/v2.2-security-model.md`
- `docs/v2.2-threat-model.md`
- `docs/v2.2-invariants.md`
- `docs/v2.2-migration.md`
- `docs/v2.1-architecture.md`
- `docs/v2.1-threat-model.md`
- `docs/v2.1-invariants.md`
- `docs/v2.1-migration.md`
- `docs/v2.1-cli.md`
- `docs/v2.1-benchmarks.md`
- `docs/v2.0-architecture.md`
- `docs/v2.0-threat-model.md`
- `docs/v1.8-artifact-format.md`

The changelog records release-level changes in `CHANGELOG.md`.

---

## License

MIT
