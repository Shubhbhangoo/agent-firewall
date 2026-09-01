# Agent Firewall

**Security control-plane infrastructure for autonomous AI agents and automated tool use.**

Agent Firewall is built around one security boundary: **authorization remains deterministic, explicit, and fail-closed**. Identity, provenance, monitoring, behavioral analysis, simulation, evidence, and response provide security context around that boundary, but they do not become an alternative path to authorization.

> **v2.1.1** extends the Agent Security Control Plane with an autonomous defense layer for multi-agent systems, capability abuse, compromised identities, delegation risk, attack-path analysis, cryptographic evidence, counterfactual simulation, and policy-gated response.

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

## What v2.1.1 provides

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

v2.1.1 is layered on the v2.0 control plane rather than replacing it.

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
- **Identity does not imply authority.**
- **Delegation cannot escalate authority.**
- **Revocation propagates through delegation lineage.**
- **Unverified artifacts are not trusted as evidence.**
- **Inference, prediction, simulation, and observation remain distinct.**
- **Simulation and replay do not modify live security state.**
- **Tool output is data, not authority.**
- **LLM output cannot directly authorize or approve a protected operation.**
- **High-impact response actions remain policy and approval gated.**
- **Security failures default toward refusal rather than implicit trust.**

These are implementation properties of the system, not a claim that any deployment is universally secure.

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
pip install agent-firewall-security==2.1.1
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

## v2.1.1 command surface

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

The v2.1.1 test surface covers, among other properties:

- capability attenuation
- delegation narrowing
- identity and revocation behavior
- attack-path analysis
- digital-twin isolation
- evidence-chain integrity
- tamper detection
- causal ordering
- evidence promotion
- UI/API boundaries
- control-route authentication
- legacy v2.0 and v1.9 compatibility
- benchmark execution
- credential and private-key scanning

Run the test suite with:

```bash
pytest
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

- `docs/v2.2-architecture.md` (branch `v2.2`, in development)
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
