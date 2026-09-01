# Security Policy

## Supported Versions

Security fixes are maintained on the current release branch. The active release line is:

| Version | Supported |
| --- | --- |
| 2.2.x | Yes |
| 2.1.x | Yes |
| 2.0.x | Yes |
| 1.9.x | Yes |
| 1.6.x | Security fixes only as practical |
| 1.5.x | Security fixes only as practical |
| < 1.5 | No |

## Reporting a Vulnerability

Please do not open a public GitHub issue for an undisclosed security vulnerability.

Report security issues through the repository's private security reporting mechanism on GitHub. Include a clear description of the affected component, the security impact, reproduction steps or a minimal proof of concept, and the version or commit where the issue was observed.

Please avoid including real credentials, production API keys, personal data, or other secrets in the report.

## v2.2 Security Boundary

v2.2 makes the platform **adaptive**: authority is re-evaluated when the
state it rested on changes, contradictions between independent claims are
reported rather than resolved, and the architectural properties the design
rests on are checked by code instead of asserted in prose.

`FirewallSDK.authorize()` remains the only decision authority. The largest
v2.2 addition — continuous authorization — exists specifically to route
re-evaluation back *through* it rather than alongside it: the engine
re-invokes `authorize()` and compares verdicts, and its gating can only
turn an allow into a deny, never the reverse.

- **Eleven invariants are machine-checked, not asserted.**
  `firewall.invariants` states each property once and checks it with
  exactly one function, so an invariant with no check is a missing registry
  entry rather than a silently absent property. `python -m
  firewall.invariants` gates the three structural and three self-contained
  invariants in CI. Status is three-valued: `UNVERIFIABLE` is falsy, makes
  the whole report falsy, and makes `assert_all` raise — accepting it would
  make the assertion satisfiable by breaking the checker.
- **A capability valid at T1 is not automatically valid at T2.** Fifteen
  revalidation triggers over identity, task, capability, delegation,
  provenance, posture, risk, trust, policy, environment, incident, time
  and explicit request. Every watched subsystem is an explicit constructor
  argument: an unwired dependency makes its change class undetectable, and
  that must be visible at the call site rather than silently defaulted.
- **A blinded monitor is not an all-clear.** A *configured* dependency that
  raises is recorded as `PROBE_FAILED` — distinct from `UNKNOWN`, which
  means "not wired" — and turns an allow into
  `security_dependency_unavailable`.
- **The signature outranks the mutable registry.** A delegated
  capability's parent is recorded twice: signed into the child's payload,
  and held in a delegation registry writable by anything holding the SDK.
  Where they disagree, authorization fails closed. A capability signed as a
  delegation can no longer authorize as a root when its lineage edge is
  absent.
- **The authorization path never raises in place of deciding.** An
  unusable action returns `invalid_action`, not a `ValueError`. Action
  names can originate in untrusted tool output.
- **Control-plane state is reachable only through the SDK's API.**
  `known_capabilities()` returns a live read-only view, so no subsystem can
  inject a forged ancestor, delete an inconvenient one, or pin a snapshot
  past a revocation.
- **Unknown is not safe, and a check that did not run is not a pass.**
  Discrepancy profiles default to `unknown` risk and can never report
  `low` while a required fact is unestablished; a raising check produces an
  explicit gap. Evidence verification reports *proven tampered*, *could not
  be checked*, and *passed* as three separate outcomes.
- **Findings are not authority.** Risk scores, trust scores, weakness
  searches, contradiction reports, integrity reports and invariant reports
  are all evidence for a human or a containment operator.
  `FirewallSDK.authorize()` reads none of them.

Documented non-guarantees, stated rather than left to be inferred:
truncation of an evidence chain is undetectable without a signed anchor;
the verifier cannot name which field of a replaced event changed; a
rotated-out signing key is indistinguishable from one that never existed;
change classes whose subsystem was never injected are undetectable; and
the default policy fingerprint covers the trusted-issuer set and the
delegation-depth ceiling only. See
[docs/v2.2-threat-model.md](docs/v2.2-threat-model.md) and
[docs/v2.2-security-model.md](docs/v2.2-security-model.md).

## v2.1 Security Boundary

v2.1 adds the **Autonomous Agent Defense Layer**: a real-time defense
mesh, agent-to-agent zero trust, a continuous attack-path engine, a
security digital twin, a cryptographic evidence graph, Capability
Firewall 2.0, an immune system, the Security Research Lab 3.0, and a
security intelligence engine. Everything is additive over v2.0 and
observational/analytical above the existing authorization pipeline.
The immune system is the only new executor, and it executes only through
the v2.0 containment controller / SDK revocation and risk mechanisms.

- **Identity does not equal authority.** An active identity grants
  nothing; the defense mesh evaluates identity and capability
  separately, and an agent with no live capability is restricted, never
  trusted into action. Presenting a capability-shaped token does not
  confer it (the research lab's `malicious_agent` scenario).
- **Delegation can only narrow** - in capabilities (v1.x
  `_constraints_are_narrower`), tasks (intersection), a2a relationships
  (intersection + `verify_chain`), and Capability Firewall 2.0
  (`is_narrower_than`). A widening grant raises at delegation time.
- **Revocation propagates recursively**: capability lineage
  (`is_effectively_revoked`), a2a relationships (recursive revoke), and
  identities (revoked identities deny mesh evaluation and evidence
  signing).
- **Simulation cannot mutate production state.** The digital twin
  snapshots a serializable attack graph and works on deep copies; it
  holds no live registry reference. Every counterfactual is labeled
  `simulated`.
- **Inference cannot become evidence without explicit provenance.**
  Evidence kinds (`observed` / `inference` / `prediction` /
  `simulation` / `unknown`) are structural. Promotion to `observed`
  requires an explicit signed `promote()` with a reason; the original
  event is never rewritten.
- **Model output cannot authorize itself.** The immune system's
  reasoner (which may be an LLM) returns advice only. Execution
  requires a deterministic policy rule match, and high-impact stages
  (`quarantine`, `contain`) require an approver unless the policy
  explicitly auto-approves.
- **The evidence graph is tamper-evident**: hash-linked signed events
  with causal ordering. Tampering, reordering, deletion, and broken
  causality are reported (`failed` / `unverifiable`); `verified` is
  returned only when every check passes.
- **The research lab attacks the control plane itself**: 11 adversarial
  scenarios run in isolated workspaces; every discovered violation is a
  regression-test seed. Property tests cover attenuation narrowing,
  delegation narrowing, and evidence-chain integrity.
- **The intelligence engine is advisory**: hypotheses carry their
  supporting facts, confidence, and rationale, and are labeled
  `inferred`; model-generated hypotheses are flagged and can never
  authorize anything.
- **Fail closed everywhere**: unknown agents, broken lineages,
  unverifiable evidence, malformed state, expired recovery windows, and
  provider errors all deny.

## v2.0 Security Boundary
v2.0 adds agent identity, task-bound authority, security passports,
cryptographic attestation, supply-chain provenance, continuous posture,
a trust graph, the Security Lab, and adaptive response. Everything is
additive over v1.8/v1.9 and observational/analytical above the existing
authorization pipeline, except response, which routes through the SDK's
own revocation and risk mechanisms.

- Identity is not authorization. Verification checks signatures, status,
  and key fingerprints; forged, stolen, rotated-out, revoked, retired,
  and unknown identities fail. Parent/child identity is provenance, not
  authority.
- Task delegation only narrows: child effective permissions are the
  intersection of the parent's and the grant. Chains (A -> B -> C) can
  never escalate. Root revocation propagates to the whole subtree.
- Passports and attestations are signed over canonical payloads with
  the recorded identity key and never contain private keys. Their
  verifiers distinguish verified / failed / unverifiable and never
  conflate them (unsupported algorithms and unknown identities are
  unverifiable).
- Supply-chain provenance requires explicit trust decisions and
  integrity digests; a name is never trust, and revoking a component
  marks its dependents untrusted.
- Posture is evidence-backed: posture moves only on recorded signals,
  and every transition names its evidence.
- The Security Lab runs in isolated workspaces and never mutates live
  state; its outcomes are simulated.
- Adaptive response is policy-driven, audited, attestable, TTL-bound,
  and requires human approval for high-impact stages unless explicitly
  auto-approved.

## v1.9 Security Boundary

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

## v1.8 Security Boundary

v1.8 adds the Agent Security Flight Recorder and everything built on it
(verification, timeline, trajectory, graph, replay laboratory, incident
packages, containment). All of it is observational or analytical above
the existing authorization pipeline; none of it can authorize anything.

- The recorder records security lifecycle events **after** a decision
  exists and can never influence one. A recorder failure is swallowed
  and can never break an authorization operation. With no recorder
  attached, `authorize()` takes the exact v1.7 path.
- The artifact format (`afw-json-1`) hashes canonical bytes, chains
  every event to every earlier event, and anchors the chain with
  Ed25519 signed checkpoints. The artifact embeds the recorder's public
  key only; private keys never enter an artifact.
- Credential-shaped payload values are redacted **before** hashing and
  the redaction is declared in the artifact manifest. Missing evidence
  is never treated as trustworthy evidence.
- Verification distinguishes five states that must never be conflated:
  `verified`, `failed`, `unverifiable`, `incomplete`, `redacted`. Any
  integrity violation yields `failed`; a never-finalized recording is
  `incomplete`, never silently trustworthy. Verification never
  early-exits, so it leaks no timing signal about which check failed.
- Replay and counterfactual analysis run in isolated throwaway
  workspaces and never touch a live SDK. They reuse the v1.7 simulation
  engine and never reimplement authorization.
- Containment is the only new write path. It is routed through the
  SDK's own revocation registry and risk context -- a contained agent
  is contained because `authorize()` denies it -- and every action is
  authorized (control-plane bearer token), authenticated (actor),
  audited, explainable (reason required), reversible where appropriate,
  and fail-closed (an error during restriction escalates to quarantine).
- The verifier's root of trust is the recorder fingerprint, which must
  be pinned out of band (`--expect-recorder`). An artifact proves it was
  made by the key it names; it cannot prove the key belongs to the agent
  it claims to record.

## v1.6 Security Boundary

v1.6 introduces North Star as the canonical authorization orchestration layer for the SDK. North Star coordinates existing security mechanisms without replacing their individual enforcement semantics.

The security-critical authorization boundary includes:

- Signed capability verification and issuer trust.
- Capability expiration and time validity.
- Delegation lineage and effective `DelegationAuthority`.
- Missing-ancestor and lineage-cycle failure handling.
- Transitive revocation propagation.
- Optional authorization-time delegation-depth policy.
- Replay protection where configured by the existing authorization mechanisms.
- Tool and agent binding.
- Constraint and policy enforcement.
- Security and delegation budgets.
- Risk, semantic, and refusal controls.
- Lifecycle and authorization transaction integrity.
- Safe authorization observability without exposing signatures, keys, raw requests, or complete constraint data.

North Star authorization is ordered and fail-closed. A mechanism that cannot establish valid authority must not be converted into permission by the orchestration layer.

The default `max_delegation_depth=None` setting preserves existing authorization behavior. When configured, excessive effective lineage depth is denied without weakening any existing authority constraint.

## Developer Console and Control-Plane Boundary

v1.6.1 adds an isolated local developer/security console under `firewall/ui/`.

The console is an observation and controlled-management layer, not a second authorization engine:

- Read-only mode is observational and does not perform authorization evaluations from an attached unauthenticated console.
- Control mode requires an explicit bearer token and is bound to loopback by default.
- Control-plane mutations call existing `FirewallSDK` APIs rather than implementing parallel authorization semantics.
- Supported mutations include agent connection, capability issue/delegation/attenuation/revocation, and configured policy such as delegation depth.
- Control-plane operations are recorded in the local audit stream.
- Parameter and constraint inputs are validated before being passed to the existing SDK mechanisms.
- Authorization inspection uses the existing `authorize_north_star()` decision path.
- Private keys, signatures, raw request payloads, and other sensitive cryptographic material are excluded from console responses.
- Demo scenarios use disposable in-memory SDK workspaces.
- The console must not be exposed to untrusted networks or treated as a production multi-tenant management service without an independently secured deployment boundary.

The control-plane bearer token is an administrative boundary for the local console. It is not an agent capability and does not replace capability verification or authorization enforcement.

The console uses only the Python standard library and vanilla browser assets. Static serving enforces root containment to prevent path traversal.

## v1.5 Security Boundary

v1.5 established the following security-critical boundaries:

- Signed capability verification, issuer trust, expiration, and revocation.
- Tool-bound session capabilities.
- Delegation lineage and transitive authority enforcement.
- Cumulative delegation budgets shared across an entire capability lineage.
- Untrusted tool output entering agent context.
- Capability-aware authorization traces.
- Cross-agent isolation.
- Security-sensitive numeric values, including timestamps, TTLs, clocks, and budget amounts.

## CLI Security

The `firewall` CLI provides operational inspection and configuration commands. Capability-token inspection and lifecycle inspection can expose security-sensitive metadata and should be used only in trusted operational environments.

CLI output does not grant authority, and the CLI is not an alternate authorization path. Protected execution remains governed by the SDK and existing firewall security mechanisms.

When reporting CLI-related vulnerabilities, include the command, input shape, affected version, and whether the issue can cross from operational inspection into an authorization or confidentiality boundary.

## Disclosure

Please allow maintainers reasonable time to investigate and prepare a fix before public disclosure. Coordinated disclosure details can be agreed with the reporter after the initial triage.
