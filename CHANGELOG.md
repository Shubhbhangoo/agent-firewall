# Changelog

All notable changes to Agent Firewall are documented here.

## [2.1.1] - 2026-08-30

### Added

- Added the **Autonomous Agent Defense Layer**: nine new subsystems
  layered above the v2.0 authorization pipeline, all observational or
  analytical (with the immune system as the only new executor, routed
  through the v2.0 containment controller).
- Added the **real-time defense mesh** (`firewall.defense`): continuous
  identity verification, dynamic trust evaluation, continuous capability
  evaluation, immediate revocation through the SDK's registry, automatic
  quarantine of compromised agents, audited recovery and re-entry with a
  recovery TTL, fail-closed unknown/forged identity handling, and signed
  attestation of every transition. The mesh never authorizes anything
  itself.
- Added **agent-to-agent zero trust** (`firewall.a2a`): mutual
  cryptographic authentication with single-use TTL-bound challenges,
  scoped relationships, task-bound delegation, capability attenuation by
  intersection (delegation can only narrow), delegation-chain
  verification, expiring grants, recursive revocation, trust
  establishment/teardown, and cross-agent authorization decisions with
  an optional SDK provider as the authoritative gate.
- Added the **autonomous attack-path engine** (`firewall.attackgraph`):
  a continuously evaluated attack graph over agents, identities, tasks,
  authorities, capabilities, tools, resources, delegations, provenance,
  policies, trust, and incidents; privilege-escalation paths, dangerous
  capability combinations, delegation abuse, trust transitivity,
  blast radius, and high-risk chokepoints. Every hop and path carries its
  basis (`observed` / `derived` / `inferred` / `simulated`) and a path's
  basis is its weakest hop; traversal is bounded and terminates on cyclic
  graphs.
- Added the **security digital twin** (`firewall.twin`): isolated
  counterfactuals (agent compromise, capability revocation, untrusted
  tool, delegation, credential exposure) over deep-copied attack graphs.
  The twin holds no live registry reference, never mutates production
  state, and returns explainable reachability deltas, blast radius,
  containment opportunities, policy changes, and risk deltas - all
  labeled `simulated`.
- Added the **cryptographic evidence graph** (`firewall.evidence_graph`):
  signed, hash-linked events with causal parents, strict sequence
  ordering, full-chain verification, tamper detection (hash, link,
  ordering, causality, signature), replayable incident timelines, and
  cryptographic provenance chains. Evidence kinds are structural and
  promotion to `observed` requires an explicit, signed `promote()` with a
  reason; the original event is never rewritten. Signers may be dedicated
  keys or agent identity keys (revocation invalidates).
- Added **Capability Firewall 2.0** (`firewall.capability2`): composable
  constraints over resource, scope, action, time, context, agent
  identity, task identity, delegation lineage, provenance, and
  environment, with operator expressions, safe attenuation, and a
  structural `is_narrower_than` guarantee - a delegated capability never
  gains authority compared with its parent.
- Added the **agent immune system** (`firewall.immune`): the
  OBSERVE -> DETECT -> REASON -> SIMULATE -> CONTAIN -> RECOVER -> VERIFY
  loop. Deterministic detection rules, an advisory reasoner (LLM or
  default), optional twin simulation, policy-gated containment with
  approval for high-impact stages, verification-gated recovery, and
  full evidence recording. **The reasoning system never becomes the
  authorization authority**: model output is advice only and a
  deterministic policy rule is required to execute anything.
- Added the **Security Research Lab 3.0** (`firewall.research`): 11
  automated adversarial scenarios (malicious agents, forged identities,
  delegation chains, capability escalation, revocation bypass,
  provenance poisoning, replay attacks, trust manipulation,
  confused-deputy, cross-agent escalation, policy conflicts) in isolated
  fresh workspaces, plus hypothesis property tests (attenuation
  narrows, delegation narrows, evidence chain stays intact). Every
  discovered violation is a regression-test seed.
- Added the **security intelligence engine** (`firewall.intel`):
  correlates posture, trust findings, attack paths, chokepoints, and
  observed evidence into explainable hypotheses with recommended
  containment actions; model output is flagged and advisory only.
- Added the **v2.1 CLI**: `defense`, `delegate`, `capability`,
  `attack-graph`, `twin`, `evidence`, `immune`, `research`, and
  `recover` command families, all additive over the v2.0 CLI.
- Added the **v2.1 browser panel**: live mesh state, a2a trust graph,
  attack-graph summary, digital-twin counterfactuals, evidence graph,
  and the immune loop, over `GET /api/v21/*` and read-only
  `POST /api/v21/twin` and `/api/v21/immune/cycle`.
- Added `firewall.benchmarks` (`python -m firewall.benchmarks`):
  throughput and latency for evidence append/verify, attack-graph
  build/paths, twin counterfactuals, mesh population evaluation, a2a
  chain authorization, and capability2 evaluation.
- Added 169 v2.1 tests: unit suites per subsystem, an adversarial
  invariant suite, hardening tests (concurrency, race conditions,
  persistence failures, crash recovery, replay, large graphs/populations/
  chains, key rotation during active sessions, revocation during
  execution, malformed crypto/adversarial input), CLI integration, and
  benchmark/UI/secrets-scanning smoke tests.

### Security

- All v2.1 subsystems preserve the v2.0 invariants and the absolute
  boundary: nothing in v2.1 authorizes an action; analysis and
  recommendations feed context, and the `FirewallSDK` pipeline alone
  decides.
- The defense mesh and immune system are fail-closed: unknown agents,
  broken lineages, unverifiable evidence, malformed state, expired
  recovery windows, and provider errors deny.
- The evidence graph never silently promotes inferred/simulated data to
  observed evidence; promotion is explicit, signed, and referenced.
- The digital twin runs on deep copies and cannot mutate production
  authorization state; every counterfactual is labeled `simulated`.
- Model output can recommend but never execute: the immune system
  requires deterministic policy rules and human approval for
  high-impact stages.
- State-file loading was hardened (non-object state files fail closed),
  and evidence payloads now enforce string-length and nesting-depth
  limits.

### Compatibility

- Every v2.0 API, CLI command, state file, and test is unchanged; the
  full v2.0 suite passes as part of the v2.1 gate.
- `FirewallSDK.authorize()` remains the decision authority.
- v2.1 subsystems are additive packages; no v2.0 module was rewritten.

### Packaging

- Bumped package version to `2.1.0`; updated README, SECURITY.md, the
  CHANGELOG, and the docs set for the v2.1 branch.
- Added `docs/v2.1-architecture.md`, `docs/v2.1-threat-model.md`,
  `docs/v2.1-invariants.md`, `docs/v2.1-migration.md`,
  `docs/v2.1-cli.md`, and `docs/v2.1-benchmarks.md`.

## [2.0.0] - 2026-08-31

### Added

- Added the **Agent Security Control Plane**: a complete,
  cryptographically verifiable control plane connecting identity, task,
  authority, capability, provenance, policy, decision, execution,
  evidence, posture, risk, and response.
- Added **agent identity** (`firewall.ident`): a persistent,
  cryptographically bound identity registry with a full lifecycle
  (create, rotate, revoke, retire), identity versioning, key
  fingerprints, parent/child relationships, atomic persistence, and
  optional passphrase-encrypted private keys. Identity never implies
  authorization; verification fails for forged, stolen, rotated-out,
  revoked, retired, and unknown identities.
- Added **task-bound authority** (`firewall.task`): task-scoped
  permissions with lifecycle, expiration, and delegation chains whose
  effective permissions are the intersection of the parent's and the
  grant -- delegation can only narrow, so an A -> B -> C chain can
  never escalate. Root revocation propagates to the whole subtree.
- Added **security passports** (`firewall.passport`): deterministic,
  versioned, signed summaries of an agent's identity, posture, tasks,
  capabilities, delegated authority, provenance, reach, incidents, and
  containment. Passports never contain private keys and verify against
  the recorded identity key.
- Added **cryptographic attestation** (`firewall.attest`): signed,
  versioned statements about identity, authority, delegation, policy
  decisions, execution events, posture transitions, and containment,
  with explicit algorithm metadata and key fingerprints. The verifier
  distinguishes verified / failed / unverifiable and never conflates
  them (unsupported algorithms and unknown identities are
  unverifiable). Algorithms are replaceable for post-quantum migration.
- Added **supply-chain provenance** (`firewall.provenance`): integrity
  and trust tracking for models, tools, MCP servers, skills, plugins,
  packages, adapters, configuration, and policies. A name is never
  trust; registration starts components unknown, trust is explicit, and
  revoking a component marks its dependents untrusted.
- Added **continuous security posture** (`firewall.posture`):
  evidence-backed states (unknown -> healthy -> degraded -> suspicious
  -> high_risk -> compromised -> contained -> recovering -> retired)
  with explainable transitions and a deterministic signal engine.
- Added the **cross-agent trust graph** (`firewall.trust`): what-can,
  who-can, who-delegated, what-changed, blast-radius, and path queries
  plus inferred danger detection (excessive authority, dangerous
  delegation, privilege escalation paths).
- Added **Security Lab 2.0** (`firewall.lab`): automated environment
  sweeps (attack surface, dangers, sensitive resources, containment
  opportunities, policy weaknesses, supply chain) and counterfactual
  questions (tool compromise, capability revocation, delegation expiry,
  policy change, blast radius) in isolated workspaces.
- Added **adaptive response** (`firewall.response2`): evidence-backed
  graduated response with response TTL/expiration, human approval for
  high-impact stages, auditing, and optional signed attestation of every
  response decision.
- Added the **v2.0 CLI**: identity (create/show/rotate/revoke), task
  (create/delegate/show), passport (show/verify), attestation (verify),
  provenance (register/trust/show/verify), posture, trust, and lab
  commands, all additive over the v1.7/v1.8/v1.9 CLI.
- Added the **v2.0 browser panel**: identities with lifecycle and key
  fingerprints, verifiable security passports, and supply-chain
  provenance, over read-only /api/v20 routes and token-gated
  /api/control identity/provenance mutations.
- Added 80 v2.0 tests: core primitives (identity, tasks, attestation,
  passport), intelligence (provenance, posture, trust, lab, adaptive
  response), adversarial (forged/stolen/revoked identities, delegation
  escalation, passport/attestation forgery, confused deputy, malicious
  provenance, lineage cycles), and integration (CLI exit contracts,
  passport round trips, trust/lab over networks, backward
  compatibility).

### Security

- Identity, task, passport, attestation, provenance, posture, trust,
  and lab are observational/analytical above the existing authorization
  pipeline; none of them can authorize an action.
- Task delegation can only narrow authority; lineage cycles and missing
  ancestors fail closed; revoked roots revoke whole subtrees.
- Passports and attestations are signed over canonical payloads with
  the recorded identity key; private keys never enter documents;
  revoked/retired/unknown identities and unsupported algorithms are
  never treated as verified.
- Supply-chain components are never trusted by name; integrity digests
  detect tampering, and revocation propagates to dependents.
- Posture moves only on recorded evidence with named signals.
- The Security Lab runs in isolated workspaces and never mutates live
  state; outcomes are labeled simulated.
- Adaptive response is policy-driven, audited, attestable, TTL-bound,
  and requires human approval for high-impact stages unless explicitly
  auto-approved. Authorization remains the final enforcement boundary.

### Compatibility

- v1.8 artifacts, the verifier, recorder, timeline, trajectory, graph,
  containment, replay laboratory, and incident packages are unchanged.
- v1.9 network commands, SOC panel, and integration adapters are
  unchanged.
- All CLI commands from every prior release keep their exact behavior
  and exit contracts; v2.0 commands are additive.
- `FirewallSDK.authorize()` remains the decision authority.

### Packaging

- Bumped package version to `2.0.0` and updated README, SECURITY.md,
  the CHANGELOG, and CI workflows for the v2.0 branch.
- Added `docs/v2.0-architecture.md`, `docs/v2.0-identity.md`,
  `docs/v2.0-threat-model.md`, `docs/v2.0-migration.md`,
  `docs/v2.0-cli.md`, and `docs/v2.0-boundaries.md`.

## [1.9.0] - 2026-08-30

### Added

- Added the **Agent Security Network** (`firewall.network`): cross-agent
  security intelligence over verified `.afw` artifacts, answering what
  agents can do, what they are doing, what could happen if they were
  compromised, and how to respond safely.
- Added a **provenance model** (`observed` / `derived` / `inferred` /
  `simulated` / `unknown`) that every node, edge, detection, path, and
  simulation carries and that is never conflated. Post-ingest additions
  must be explicitly inferred/simulated; claiming observed provenance
  is rejected.
- Added `AgentNetworkGraph`: merges verified artifacts into one
  evidence-backed graph with derived queries -- reachable, why_can,
  who_can_reach, shortest_path, and shared_paths. Failed or
  unverifiable artifacts are refused at ingest, so their facts never
  enter the network.
- Added `CorrelationIndex`: verifies + ingests artifacts and groups
  them into bundles (shared correlation ids, incidents, agents,
  redaction provenance), always reporting each artifact's verification
  status. A bundle is a label, never proof of a relationship.
- Added the **behavioral detection engine**: deterministic,
  explainable rules (repeated denials, capability escalation,
  unexpected delegation, structural denials, credential-shaped access)
  where every detection states what happened, why, the supporting
  evidence, severity, affected entities, and a recommended response.
- Added **attack-path discovery**: BFS paths with an explicit status
  taxonomy (`simulated` < `reachable` < `policy-permitted` <
  `observed`), sensitive-resource labeling, and break-path suggestions.
  Reachability is never presented as exploitability.
- Added the **scenario simulator**: isolated throwaway workspaces
  seeded from recorded facts answer "what if this agent is
  compromised?" across eight scenario kinds, producing explainable
  reports (initial capabilities, paths, reachable resources, policy
  decisions, events, impact, containment opportunities) labeled
  `simulated`, with contradictions reported `unverifiable` and never
  touching live state.
- Added **graduated response automation** (`firewall.network.response`):
  policy-driven `observe -> warn -> restrict -> quarantine -> contain`
  through the existing containment controller, with human approval for
  high-impact stages, audit records in the flight recorder and control
  plane, and fail-closed evaluation.
- Added the **universal agent integration layer** (`firewall.agents`):
  one `AgentAdapter` contract (identity, capabilities, protect,
  observe, context) with python, http, mcp, openai, and langchain
  adapters. Adapters hold no authority of their own, route every
  protected call through the real authorization pipeline, never
  fabricate identity, and refuse unmapped HTTP endpoints with an
  explanation instead of guessing.
- Added the **v1.9 CLI**: `network init/ingest/graph/correlate/
  simulate`, `detect`, `attack-path`, and `respond`, with network state
  files holding artifact paths and verification statuses only.
- Added the **Security Operations browser panel**: active agents with
  reach, detections with what/why/evidence/response, correlation
  bundles, sensitive-resource summary, attack-path queries, and
  scenario simulation, over `GET /api/soc`, read-only
  `POST /api/soc/attack-paths` and `/api/soc/simulate`, and audited
  `POST /api/control/respond`.
- Added 53 v1.9 regression tests including dedicated adversarial
  coverage for forged artifacts, graph poisoning, correlation spoofing,
  adapter abuse, simulator isolation, and response failure modes.

### Security

- The network ingests only verified evidence: failed/unverifiable
  artifacts are refused, and their facts never enter the graph or the
  detection engine.
- Provenance is first-class: inference, simulation, and derivation are
  never presented as observation, and reachability is never presented
  as exploitability.
- The scenario simulator and attack-path analysis run in isolated
  workspaces over recorded facts and never modify live authorization
  state.
- Graduated response is policy-driven, audited, explainable,
  fail-closed, reversible where safe, and requires human approval for
  high-impact stages unless the policy explicitly auto-approves. The
  response controller holds no signing keys and only calls public SDK
  APIs.
- The integration adapters cannot bypass the authorization pipeline:
  every protected call is authorized by `FirewallSDK` before execution,
  and observations are recorded after the fact.
- All v1.7/v1.8 guarantees are preserved: the recorder remains
  observational, the verifier remains the only trust boundary for
  artifacts, and containment remains routed through the SDK's own
  revocation and risk mechanisms.

### Compatibility

- Every v1.7 and v1.8 CLI command keeps its exact behavior and exit
  contract; v1.9 commands are additive.
- The v1.8 artifact format, verifier, timeline, trajectory, graph,
  containment, replay laboratory, and incident packages are unchanged
  and reused, not duplicated.
- `FirewallSDK.authorize()` remains the decision authority.

### Packaging

- Bumped package version to `1.9.0` and updated README, SECURITY.md,
  the CHANGELOG, and CI workflows for the v1.9 branch.
- Added `docs/v1.9-architecture.md`, `docs/integrations.md`,
  `docs/security-intelligence.md`, `docs/v1.9-cli.md`,
  `docs/browser-console.md`, and `docs/v1.9-threat-model.md`.

## [1.8.0] - 2026-08-29

### Added

- Added the **Agent Security Flight Recorder** (`firewall.recorder`): an
  ordered, tamper-evident chain of security lifecycle events, anchored
  by periodic Ed25519 signed checkpoints, exported as a portable `.afw`
  artifact. Recording is observational by construction: it happens after
  a decision exists and can never influence one.
- Added a versioned, deterministic, language-neutral **artifact format**
  (`firewall.artifact`): canonical JSON encoding (`afw-json-1`), hash
  chain over canonical bytes, signed checkpoint blocks, explicit
  redaction manifest, and provenance for derived artifacts. Fully
  documented in `docs/v1.8-artifact-format.md` so other projects can
  implement readers and verifiers independently.
- Added an **independent verifier** (`firewall.verify`) that recomputes
  every hash, walks every chain link, and checks every signature, with
  five distinct statuses -- `verified`, `failed`, `unverifiable`,
  `incomplete`, `redacted` -- that are never conflated, plus per-check
  findings and optional recorder-fingerprint pinning.
- Added the **agent security timeline** (`firewall.timeline`):
  chronological, inspectable story bound to recorded events, with
  navigation from timeline to event to decision to authority to
  evidence.
- Added the **security trajectory**: evidence-backed posture transitions
  (`trusted -> unusual -> suspicious -> high_risk -> contained ->
  recovered`) where every transition names the recorded event(s) that
  fired it.
- Added the **security relationship graph**: nodes (agents, capabilities,
  issuers, tools, policies, sessions) and edges (issued, delegated,
  attenuated, revoked, allowed, denied, bound) derived from recorded
  events, answering "why could this agent do this?" and "what could it
  reach?".
- Added **active containment** (`firewall.containment`): explicit state
  transitions (`active -> restricted -> suspended -> quarantined ->
  recovered`) that are authorized, authenticated, audited, explainable,
  reversible where appropriate, and fail-closed, enforced through the
  SDK's own revocation and risk mechanisms -- never around the
  authorization pipeline.
- Added the **Security Replay Laboratory** (`firewall.replaylab`):
  reconstructs a recorded session's authorization history through the
  real pipeline in isolated throwaway workspaces and answers
  counterfactual questions ("what would have happened under this
  policy?"), reusing the v1.7 simulation engine.
- Added **incident packages** (`firewall.incident`): one document
  bundling an artifact with its verification report, timeline,
  trajectory, graph, and replay analysis, plus a **redaction export**
  that re-hashes and re-signs a derived artifact under a fresh identity
  without ever needing the original private key.
- Added the **v1.8 CLI** workflow: `firewall record`, `inspect`,
  `verify`, `replay`, `timeline`, `trajectory`, `graph`, `incident
  create`, and `redact`, with a predictable exit-code contract.
- Added the **recorder console**: verification banner, timeline,
  trajectory ladder, graph, containment state, and replay laboratory in
  the browser, plus `GET /api/recorder`, read-only `POST /api/replay`,
  and audited `POST /api/control/containment`.
- Added 110 v1.8 regression tests including a dedicated adversarial
  suite and 10 committed malicious artifact fixtures with a generator
  and expected-status manifest.

### Security

- The recorder, verifier, timeline, trajectory, graph, replay
  laboratory, and incident packages are observational or analytical
  only: none of them authorize anything, and none can bypass, replace,
  or relax `FirewallSDK.authorize()` / North Star.
- Recording captures material security facts only. Credential-shaped
  values are redacted before hashing and declared in the artifact
  manifest; signatures, private keys, and raw secrets never enter an
  artifact.
- The verifier never conflates missing evidence with trustworthy
  evidence: a truncated recording is `incomplete`, a tampered one
  `failed`, a redacted one `redacted` -- never silently `verified`.
- Containment is the only new write path and it is routed through the
  SDK's own revocation registry and risk context; a contained agent is
  contained because `authorize()` denies it.
- Replay and counterfactual analysis run in throwaway workspaces and
  never touch a live SDK; the read-only `/api/replay` route needs no
  control token, while containment requires the bearer token and is
  audited.
- Recorder identity is a root-of-trust decision: verifiers can pin the
  expected recorder fingerprint, and an artifact's embedded public key
  (never its private key) is what signatures verify against.

### Compatibility

- v1.7 behavior is unchanged: `FirewallSDK.authorize()` remains the
  decision authority; North Star, capabilities, delegation, revocation,
  budgets, simulation, and rollout are untouched. No recorder attached
  means zero recording overhead.
- All v1.7 CLI commands (`init`, `validate`, `inspect-token`,
  `explain`, `simulate`) keep their exact behavior and exit contracts.
- The v1.7 simulation engine is reused, not duplicated, by the replay
  laboratory.

### Packaging

- Bumped package version to `1.8.0` and updated README, CHANGELOG,
  CLI/console/security docs, the artifact format specification, and CI
  workflows for the v1.8 branch.

## [1.7.0] - 2026-08-28

### Added

- Added a rule-simulation engine under `firewall.simulation` so a rule
  change can be evaluated before it is enforced.
- Added `RequestCase` and `CaseSet`, replayable records of the material
  facts of an authorization request (capability chain shape, payload, and
  observed decision) that carry no signatures or key material and survive
  a JSON round trip.
- Added `CaseRecorder`, an opt-in rolling window that turns real
  authorization evaluations into cases after the verdict exists, so
  recording can never influence a decision.
- Added `RuleSet`, the two globally scoped rules the existing gates
  already enforce (delegation-depth ceiling and trusted-issuer set), with
  validation mirroring the SDK's own contract.
- Added `simulate`, which replays a case set under two rule sets in
  isolated in-memory workspaces and reports every decision that changed.
- Added fidelity measurement: a case is only counted toward a claim when
  the replay reproduces the decision that was actually observed; expired,
  unrecorded, divergent, and errored cases are reported but never counted.
- Added the `Rollout` governance state machine (`observe -> warn ->
  enforce -> reverted`) with simulation-before-enforcement, stale-evidence
  rejection, acknowledgement-gated promotion, exact restore points, and an
  append-only history.
- Added `firewall simulate` CLI command with conservative CI-gate exit
  status (`0` only when nothing that works today is denied and every case
  was verified).
- Added `simulate`, `promote`, and `rollback` control-plane endpoints
  with the console's existing bearer-token and audit discipline.
- Added a simulate/promote/rollback panel to the security console UI,
  rendering the server's report verbatim, including its caveats.

### Security

- The simulation package decides which requests to replay, under which
  rules, and how to compare outcomes -- it never decides whether a request
  should be allowed.
- Every verdict in a simulation report is produced by the real
  `FirewallSDK.authorize()` running the real gate pipeline; there is no
  second authorization engine or shadow policy language.
- Replay workspaces are isolated per case and per rule set, so refusal
  memoization, replay protection, and delegation budgets cannot leak
  between cases or make the answer depend on case order.
- A rule set cannot be enforced before it has been simulated, stale
  evidence cannot promote, and a change that newly denies recorded
  traffic (or that the simulator could not fully verify) is refused
  without an explicit acknowledgement recorded in the rollout history.
- Enforcing snapshots the previous rules, so rollback is always available
  and always exact.
- `simulate` is read-only with respect to the live SDK; candidate rules
  exist only inside throwaway replay workspaces.
- Case sets carry no cryptographic material and are safe to write to disk
  and review.
- The control-plane `simulate`/`promote`/`rollback` endpoints inherit the
  v1.6.1 gates: they 404 when control is disabled, require the startup
  bearer token, and are recorded in the audit stream.

### Testing

- Added 150 v1.7 regression tests covering the case model, rule-set
  validation and application, the recorder, replay fidelity and counting
  discipline, the delegation-depth and issuer-untrust blast radius,
  rollout gates (simulate-first, acknowledgement, stale evidence, exact
  rollback), control-plane integration, the CLI exit contract, and the
  console UI workflow.
- Full-suite validation reaches **2,580 passing tests** with zero
  failures.

### Compatibility

- Existing v1.6.1 console, control-plane, and North Star behavior is
  unchanged.
- `FirewallSDK.authorize()` remains the decision authority.
- `RuleSet.apply_to` sets the same two knobs a Python caller could set
  directly and returns the previous rules for exact restoration.

### Packaging

- Bumped package version to `1.7.0`.
- Added `docs/v1.7-simulation.md` and documented the `simulate` command in
  the CLI reference.
- Added the v1.7 branch to the Security CI triggers and a dedicated CLI CI
  workflow that exercises the installed `firewall` command end to end,
  including the `simulate` exit contract, on Python 3.10, 3.11, and 3.12.

## [1.6.1] - 2026-08-27

### Added

- Added an isolated developer/security console under `firewall/ui/`.
- Added an audited local control plane for trusted development workflows.
- Added bearer-token authentication for control-plane mutations.
- Added agent connection and capability management through existing SDK APIs.
- Added issue, delegate, attenuate, and revoke operations through the control plane.
- Added authorization rule and delegation-depth configuration through existing SDK policy mechanisms.
- Added parameter/constraint validation with existing authorization enforcement remaining authoritative.
- Added safe read-only projections for capabilities, delegation authority, posture, lifecycle events, and decisions.
- Added a localhost HTTP server using only the Python standard library.
- Added a vanilla HTML/CSS/JavaScript security-console interface with no frontend build step.
- Added a live North Star pipeline visualization derived from the SDK's actual authorization gate sequence.
- Added genuine demo scenarios covering authorization outcomes, delegation, revocation, and delegation-depth policy.
- Added safe authorization and capability observability with cryptographic material redaction.
- Added path-traversal protection for static asset serving.
- Added UI-specific regression and browser smoke coverage.

### Security

- The console does not implement or duplicate the authorization engine.
- Authorization remains governed by `FirewallSDK.authorize_north_star()` and the existing North Star security pipeline.
- Control-plane mutations call existing SDK APIs and do not create a parallel authorization path.
- Control-plane writes require a bearer token and are bound to loopback by default.
- Control-plane operations are recorded in the local audit stream.
- Attached read-only SDK mode remains observational and refuses to perform authorization evaluations from the unauthenticated local console.
- Private keys, signatures, raw request payloads, and other sensitive cryptographic material are excluded from UI responses.
- Demo evaluations use disposable in-memory SDK workspaces and do not enable persistent security state.
- The console is intended for trusted local development and is not an authenticated production multi-tenant control plane.

### Testing

- Added 102 control-plane regression tests.
- Retained 121 console regression tests.
- Full validation reached **2,453 passing tests** with zero failures.
- Added control-plane HTTP authentication, validation, lifecycle, capability, delegation, revocation, rule, and end-to-end coverage.
- Preserved North Star decision-equivalence coverage.

### Packaging

- Bumped package version to `1.6.1`.
- Included `firewall.ui` static assets in built distributions.
- Added the developer console and control-plane documentation and usage guidance.

## [1.6.0] - 2026-08-26

### Added

- Introduced the North Star authorization architecture as the SDK's canonical orchestration boundary.
- Decomposed SDK authorization into an explicit deterministic sequence of fail-closed gates.
- Added canonical `DelegationAuthority` propagation through the authorization context.
- Added optional authorization-time `max_delegation_depth` policy enforcement.
- Added per-request propagation of risk, security, semantic, and refusal context through `_AuthorizationContext`.
- Added a terminal transaction gate covering semantic transaction commit/abort, security-context authorization, delegation-budget consumption, and successful lifecycle state.
- Added North Star delegation-posture observability through safe `SecurityDecision.metadata`.
- Added dedicated North Star equivalence, delegation-depth, and observability regression suites.
- Added CLI documentation for configuration validation, capability-token inspection, and lifecycle inspection.

### Security

- North Star preserves existing security mechanisms instead of duplicating or bypassing their enforcement semantics.
- Delegation lineage is resolved through the SDK's authoritative `_authorization_chain()` and represented canonically as `DelegationAuthority`.
- Revocation precedence remains authoritative, including cases where a revoked capability also has a broken delegation chain.
- Missing ancestors and lineage failures remain fail-closed.
- Optional delegation-depth enforcement is disabled by default and cannot widen authority.
- The transactional tail remains atomic with respect to semantic and security state, including abort-on-denial behavior.
- North Star observability metadata contains only safe posture information and cannot alter the authorization decision.
- Existing cryptographic verification, attenuation, replay, policy, risk, refusal, lifecycle, and budget semantics remain in force.

### Testing

- Preserved the 2,204-test baseline through the North Star migration.
- Added four authorization-equivalence tests, bringing the verified suite to 2,208 tests.
- Added 14 delegation-depth policy tests, bringing the verified suite to 2,222 tests.
- Added eight North Star observability tests, bringing the verified suite to **2,230 passing tests**.
- Full-suite validation completed with zero failures.

### Compatibility

- Existing `FirewallSDK.authorize()` remains supported.
- `authorize_north_star()` preserves the established authorization decision semantics.
- The default `max_delegation_depth=None` behavior preserves existing authorization behavior.
- Existing delegation, attenuation, revocation, replay, budget, semantic, security-context, lifecycle, adapter, and MCP APIs remain supported.

### Packaging

- Updated package version to `1.6.0`.
- Updated README, security policy, and North Star documentation for the v1.6 architecture.

## [1.5.0] - 2026-08-26

### Added

- Session-scoped capability minting with explicit tool binding and fresh TTL-derived expiration.
- Lifecycle coverage for session capability minting, expiration, tool binding, attenuation, and delegation.
- Explicit untrusted tool-output marking through `firewall.tools` so tool-returned instructions remain data rather than authority.
- Minimal capability-aware authorization traces containing capability identity, agent, action, reason, and optional tool binding.
- Cumulative transitive delegation budgets rooted at the originating capability fingerprint.
- Atomic sharing of lineage budgets across parent, child, and deeper delegated capabilities.
- Cross-agent isolation coverage for session capabilities, budgets, tool bindings, concurrent authorization, and revocation.
- Expanded delegation revocation propagation coverage across root, intermediate, leaf, and sibling branches.
- Finite-number validation for capability timestamps, verifier clocks, session TTLs, and delegation-budget amounts.

### Security

- A session capability minted for one tool cannot authorize a different tool.
- Tool output cannot acquire capability authority merely by containing instructions, credential-like text, or capability-shaped data.
- Authorization traces exclude signatures, public keys, raw request payloads, and full constraint data.
- Parent, child, and grandchild capabilities consume the same cumulative lineage budget rather than receiving independent budgets.
- Concurrent descendants cannot overspend a shared lineage budget.
- Root revocation propagates through the complete delegation chain.
- Intermediate revocation invalidates all descendants while preserving unrelated sibling branches.
- Independent root capabilities maintain separate budget and revocation state.
- `NaN`, positive infinity, and negative infinity are rejected in security-sensitive numeric inputs.

### Testing

- Added session capability minting regression coverage.
- Added session capability lifecycle regression coverage.
- Added untrusted tool-output and prompt-injection regression coverage.
- Added capability-aware authorization trace regression coverage.
- Added transitive delegation-budget and concurrency regression coverage.
- Added multi-level revocation propagation regression coverage.
- Added cross-agent isolation regression coverage.
- Added finite numeric validation regression coverage for `NaN` and infinities.
- Full v1.5 validation remained green through the feature hardening cycle.

### Compatibility

- Existing v1.4 semantic and runtime security context behavior remains supported.
- Existing attenuation, delegation, revocation, replay, key-management, adapter, and MCP authorization APIs remain supported.
- Existing direct capability issuance continues to work through the public SDK.

### Packaging

- Updated package version to `1.5.0`.
- Updated security CI coverage to the `v1.5` branch.
- Updated release and security documentation for the v1.5 capability-boundary model.

## [1.4.0] - 2026-08-26

### Added

- Cross-chain cumulative semantic amount budgets through `SemanticChainContext.max_total_amount`.
- Optional persistent `SecurityContext` state through `state_path`.
- SDK helper support for creating a persistent `SecurityContext`.
- Persistent security-state integrity verification and atomic replacement.
- Cross-process locking for shared persistent security state.
- Authorization atomicity coverage between semantic state and runtime security budgets.
- Persistence recovery coverage for stale temporary files, interrupted writes, failed atomic replacement, and tampered state.

### Security

- Cross-chain semantic budgets are enforced atomically under the existing semantic context lock.
- Concurrent chains cannot overspend a shared semantic cumulative budget.
- Persistent security budget state survives normal process restart.
- Concurrent independent `SecurityContext` instances sharing a state file cannot both authorize from stale state and exceed the configured budget.
- Corrupted, truncated, tampered, incompatible, or agent-mismatched persistent state fails closed.
- A failed persistent write rolls back the in-memory security mutation.
- Stable audit-log path resolution prevents process working-directory changes from splitting the audit hash chain into separate logs.
- Semantic transactions abort when downstream security authorization fails, preventing partial authorization state.

### Testing

- Expanded the local v1.4 regression suite to **2,106 passing tests**.
- Added cross-chain budget tests.
- Added budget concurrency and race-condition tests.
- Added persistent budget restart tests.
- Added persistent-state corruption and recovery tests.
- Added cross-process persistent-state race tests.
- Added semantic/security authorization atomicity tests.
- Added stable audit-log path regression coverage.

### Compatibility

- Existing `SecurityContext` behavior remains supported when `state_path` is omitted.
- Existing in-memory `SemanticChainContext` behavior remains supported when `max_total_amount` is omitted.
- Existing v1.3.1 delegation, attenuation, revocation, replay, key-management, and adapter behavior remains covered by the regression suite.

## [1.3.1] - 2026-08-25

### Security

- Persisted delegation lineage and signed capability records so delegated authority can be reconstructed after SDK restart instead of silently becoming root authority.
- Hardened the legacy `Firewall` authorization path so revocation of a parent capability also blocks its delegated descendants.
- Extended effective revocation to genuinely distinct attenuated capabilities by registering attenuation parent-child lineage.
- Preserved no-op attenuation compatibility when attenuation produces the exact same signed capability and fingerprint as its parent.
- Added dedicated security-audit regression coverage for delegation persistence, legacy revocation, attenuation revocation, semantic transaction lifecycle, lineage-depth boundaries, audit-log behavior, and cross-chain budget semantics.

### Fixed

- Corrected effective-authority handling across SDK restart boundaries.
- Corrected ancestor-aware revocation consistency between the SDK and legacy firewall paths.
- Corrected parent revocation propagation through distinct attenuated descendants.
- Preserved established lineage-depth semantics after validating the audit finding against the existing multi-agent regression contract.

### Testing

- Expanded the local v1.3.1 validation suite to **2,073 passing tests**.
- Added F1 delegation-persistence audit tests.
- Added F2 lineage-depth audit coverage.
- Added F3 legacy revocation audit coverage.
- Added F4 semantic transaction and concurrency audit coverage.
- Added F5 attenuation revocation audit coverage.
- Added F6 audit-log behavior coverage.
- Added F7 cross-chain budget behavior coverage for the v1.4 design backlog.

### Packaging

- Updated package version to `1.3.1`.
- Prepared the v1.3 branch for the `agent-firewall-security==1.3.1` release.
