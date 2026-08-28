# Security Policy

## Supported Versions

Security fixes are maintained on the current release branch. The active v1.6 release line is:

| Version | Supported |
| --- | --- |
| 2.0.x | Yes |
| 1.9.x | Yes |
| 1.6.x | Security fixes only as practical |
| 1.5.x | Security fixes only as practical |
| < 1.5 | No |

## Reporting a Vulnerability

Please do not open a public GitHub issue for an undisclosed security vulnerability.

Report security issues through the repository's private security reporting mechanism on GitHub. Include a clear description of the affected component, the security impact, reproduction steps or a minimal proof of concept, and the version or commit where the issue was observed.

Please avoid including real credentials, production API keys, personal data, or other secrets in the report.

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
