# Security Policy

## Supported Versions

Security fixes are maintained on the current release branch. The active release line is:

| Version | Supported |
| --- | --- |
| 3.5.x | Yes |
| 3.4.x | Yes |
| 3.3.x | Yes |
| 3.2.x | Yes |
| 3.1.x | Yes |
| 3.0.x | Yes |
| 2.8.x | Yes |
| 2.7.x | Yes |
| 2.6.x | Yes |
| 2.5.x | Yes |
| 2.4.x | Yes |
| 2.3.x | Yes |
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

## v3.5 Security Boundary

v3.5 closes the assumption v3.4 left in its own honest-non-guarantees list,
and states it in one line: **no single external witness is a root of trust.**

v3.4 moved the trust root out of the firewall's storage -- and admitted what
it had built in doing so: *"A witness that lies. If the witness signs whatever
it is handed, it attests nothing."* One key, one machine, one operator. A
checkpoint became externally confirmed because a thing said so. v3.5 requires
the configured **threshold of distinct trusted witnesses** to independently
authenticate the *identical* anchor state before a checkpoint can be
confirmed. The design and the honest non-guarantees are in
[docs/v3.5-witness-quorum.md](docs/v3.5-witness-quorum.md); the measurements
are in [docs/v3.5-performance.md](docs/v3.5-performance.md).

If you are upgrading for one reason, this is it: **a progression now has to
have N independent witness signatures behind the checkpoint it rests on, not
one.** Every counted receipt must authenticate the same anchor kind, anchor
id, sequence, digest, checkpoint id **and** policy id, and one witness voting
twice is one vote:

| condition | refusal |
| --- | --- |
| fewer distinct trusted witnesses voted than the policy requires | `anchor_quorum_insufficient` |
| trusted witnesses authenticated *different* values for one position | `anchor_quorum_split` |
| one witness signed two different statements about one position | `anchor_witness_equivocation` |
| one witness identity voted a second time | `anchor_witness_duplicate` |
| a receipt was presented under a policy that is not in force | `anchor_policy_mismatch` |
| a receipt is about an anchor, position, checkpoint or policy that is not the bound one | `anchor_checkpoint_mismatch` |
| a genuine receipt for a position quorum has moved past | `anchor_witness_stale` |
| a signature from an unregistered key, or an identity the policy does not name | `anchor_witness_untrusted` |
| a signature that does not verify, or a receipt id that does not re-derive | `anchor_witness_invalid_signature` |
| no round has been confirmed and the gate is on | `anchor_quorum_unconfirmed` |
| the persisted quorum state does not re-derive | `anchor_quorum_unverifiable` |

Each of those is a **refusal**, and there is no quorum verdict that is not.

Two of them are worth reading twice, because they are where the layer earns
its keep. `anchor_quorum_split` is refused **even when the threshold of
agreeing witnesses is present**: with 2-of-3, two agreeing witnesses and one
dissenting one is not a quorum, because what the witnesses collectively said
is "we do not agree". `anchor_witness_equivocation` is **evidence, not an
error to be resolved** -- both signed statements are retained, verifiable and
exposed through `sdk.quorum_equivocations()`, the contradictory vote is
refused, and there is deliberately no code path that picks a winner.

**What v3.5 does not defend against.** Compromise of enough witnesses to meet
the threshold: `2-of-3` is defeated by two compromised witnesses, and no
counting rule can change that. Witnesses that are not independent *in fact* --
three witnesses on one machine, under one account, sharing one key-management
process, are one witness with three names; the protocol counts identities and
cannot observe failure domains. Compromise of the policy-management
authority: whoever can register a policy can register `1-of-1` naming a
witness they control; the layer refuses mutation-in-place and freezes a used
policy, which stops a *silent* downgrade, but that attacker is inside the
trust boundary rather than outside it. A weak threshold chosen by the
operator: `1-of-3` is legal and is exactly as strong as v3.4, and the layer
will not rank thresholds. Availability: if the threshold cannot be met the
deployment stops progressing -- there is no degraded mode, no best-effort
confirmation, and no timeout after which fewer witnesses are accepted. And
the same SHA-256 and Ed25519 assumptions every other layer makes.

**What it cannot do.** `FirewallSDK.authorize()` remains the only ALLOW origin.
The quorum module constructs no `AuthorizationResult`, no ALLOW-path function
references quorum state at all, and every quorum verdict is a refusal or an
abstention. `require_witness_quorum` is read-only after construction and is
honoured on every progression path. The quorum is a *sixth* mechanism beside
the lease store, the effect journal, the verification journal, the attestation
journal, the lineage and the anchor: it authenticates what the anchor
publishes, and it replaces none of them.

**This is not a consensus protocol.** No leader, no term, no view change, no
replicated log, no liveness machinery. If you need agreement among *replicas*
rather than authentication of a *value that already exists*, this layer is not
it, and v3.5 does not pretend otherwise.

**Witness independence is the operator's fact, not this package's.** The
package ships `InProcessQuorumWitness` for the invariant estate, the test
suite and the benchmarks, and its docstring states in its own words that it is
**not an independence claim** -- its key lives in the same process as the
firewall. A deployment that needs the property needs witnesses on storage the
firewall's process cannot write, whose compromise is genuinely independent.

## v3.4 Security Boundary

v3.4 closes the assumption every earlier release shared, and states it in one
line: **a trust root the firewall holds is not a root of trust.**

v3.0 chained the canonical state digest, v3.2 anchored every window, v3.3
chained an execution's whole lineage -- and the *head* of each of those chains
is a row in a store the same process writes. A chain the process can rewrite
is tamper-*evident* only against a tamperer who is not that process, which is
the admission both v3.3 §5.2 and v3.2 §3.2 end their honest lists with. The
design and the honest non-guarantees are in
[docs/v3.4-external-anchoring.md](docs/v3.4-external-anchoring.md); the
measurements are in [docs/v3.4-performance.md](docs/v3.4-performance.md).

If you are upgrading for one reason, this is it: **a progression now has to
agree with a checkpoint a witness outside this process signed and holds.** The
firewall publishes a signed checkpoint of an anchor's monotone position to a
configured witness, records the witness's signed receipt locally, and refuses
any progression that contradicts it:

| condition | refusal |
| --- | --- |
| the live commitment differs from the confirmed one at the same position | `anchor_mismatch` |
| the anchor no longer carries the confirmed commitment at its confirmed position | `anchor_mismatch` |
| the live position is behind the confirmed one, or the confirmed position is gone | `anchor_truncated` |
| nothing has been confirmed for this anchor and the gate is on | `anchor_unconfirmed` |
| the anchor cannot be read, or a reader it needs is not bound | `anchor_missing` |
| the witness cannot be reached, or no witness was configured | `anchor_witness_unavailable` |
| a *new* checkpoint would move an anchor backwards | `anchor_rewind` |
| a signature does not verify, or an id does not re-derive | `anchor_signature_invalid` |

Each of those is a **refusal**, and there is no anchor verdict that is not.

**What v3.4 does not defend against.** A witness that signs whatever it is
handed attests nothing: the layer establishes that the firewall's head matches
what the witness last confirmed, not that the witness is honest, independent in
fact, or operated by anyone other than the attacker. An attacker who can both
rewrite the local store *and* publish a consistent fabricated chain to the
witness has moved the attack from "one process" to "one process plus the
witness" -- that is a bar being raised, and it is a bar, not a wall. With
`require_external_anchor` false, none of this runs and the deployment is
exactly v3.3; the gate is a configuration the operator chooses, and the package
cannot choose it for them. A witness that is down is an execution that cannot
progress, which is fail-closed and a real operational cost. `issued_at` is the
*witness's* statement about time and carries no guarantee -- the monotone
`sequence` is what orders checkpoints, not the clock. And the same SHA-256 and
Ed25519 assumptions every other layer in this package makes.

**What it cannot do.** `FirewallSDK.authorize()` remains the only ALLOW origin.
The anchor layer constructs no `AuthorizationResult`, no ALLOW-path function
references anchor state at all, and every anchor verdict is a refusal -- there
is no code path in the layer that returns `True` where a pre-v3.4 path
returned `False`. `require_external_anchor` is read-only after construction,
and turning it off is honoured on every progression path, the lease path and
the side-effect path alike. The anchor is a *fifth* mechanism beside the lease
store, the effect journal, the verification journal, the attestation journal
and the lineage: it commits to them and refuses when it cannot, and it replaces
none of them.

**Witness independence is the operator's fact, not this package's.** The
package ships the interface and three reference implementations, one of which
(`InProcessWitness`) is documented in its own first line as **not a witness**
and is for the invariant estate and the test suite only. A deployment that
needs the property needs a witness on storage the firewall's process cannot
write.

## v3.3 Security Boundary

v3.3 closes the question every earlier release left open, and states it in
one line: **an execution can only progress when its complete lineage remains
intact, unique, correctly bound and tamper-evident.**

Every release before this one answered a question about one *stage* of an
execution -- v2.7 the continuation of an allow, v2.8 the side effect, v2.9
the verification, v3.1 the external attestation, v3.2 the temporal context
each of those is valid in. Five journals, each correct about its own stage,
and nothing that established the stages belonged to **one execution**, that
they happened in that order, or that nothing was forked, grafted or
re-ordered along the way. The design and the honest non-guarantees are in
[docs/v3.3-execution-lineage.md](docs/v3.3-execution-lineage.md).

If you are upgrading for one reason, this is it: **a completed execution now
carries a single append-only, hash-chained commitment to its whole
sequence.** One lineage per execution identity, one commitment per stage,
each chaining to the one before it from a fixed genesis anchor and carrying
a digest of the evidence that justified that stage. A fork, a
cross-execution substitution, an out-of-order or repeated stage, a deleted
middle link and a truncated tail are each refused *by name* and recorded as
a finding, and an execution that cannot prove its lineage does not progress.

**What v3.3 does not defend against.** The lineage is tamper-*evident*, not
tamper-*proof*: an attacker who can rewrite all four journals *and* the
lineage store consistently is outside it, and raising that bar is what the
v3.1 external-attestation layer is for. A `NOT_ADOPTED` stage that the
execution genuinely did not perform is recorded as a skip and cannot be
distinguished from a skipped stage someone chose not to record, beyond the
rule that a stage the protocol *required* may not be `NOT_ADOPTED`. The
chain rests on SHA-256, with the same standing assumption every other layer
in this package makes.

**What it cannot do.** `FirewallSDK.authorize()` remains the only ALLOW
origin. The lineage layer constructs no `AuthorizationResult`, no ALLOW-path
function references lineage state at all, and every lineage verdict is a
refusal -- there is no code path in the layer that returns `True` where a
pre-v3.3 path returned `False`. `require_lineage` is read-only after
construction, and turning it off is honoured on *every* progression path,
the lease path and the side-effect path alike.

## v3.2 Security Boundary

v3.2 attacks the one dimension every earlier release left open, and states it
in one line: **a security decision is valid only within a provable temporal
context.** A capability window was compared against whatever `time.time()`
said, a lease deadline was stamped from a clock the firewall does not own, an
attestation's maximum age was measured in wall seconds, and a replay entry
expired when wall time passed its deadline. Those are one weakness reached
through four doors: a decision that was valid when it was made can be made to
look valid again by moving the clock it is compared against. The temporal
model, the trusted clocks, the threat boundary and the honest non-guarantees
are in [docs/v3.2-temporal-integrity.md](docs/v3.2-temporal-integrity.md).

If you are upgrading for one reason, this is it: **an allow, a lease, an
attestation and a replay window are now measured in a time base the boundary
can prove.** Every window is anchored twice -- an absolute deadline in
calendar time and an elapsed budget against a monotonic clock -- and both are
compared against a reading audited against that source's own history. A wall
clock set backwards, a monotonic clock that regressed, and a restart behind
the previous process generation's highest wall reading are each a refusal
that names the reason (`temporal_anomaly:*`), and the elapsed budget closes a
lease (`lease_expired:monotonic_budget`) and an attestation
(`attestation_stale_at_completion`) that a rolled-back wall clock still calls
open. It is opt-in in the sense that nothing must be configured: an SDK with
an injected clock gets the audit for free.

- **No second authorization system.** `FirewallSDK.authorize()` remains the
  only allow origin, the temporal layer constructs no `AuthorizationResult`,
  every verdict it produces is a *refusal*, and the invariant's census fails
  if any function that decides an authorization outcome reads a platform
  clock. Temporal logic cannot create, extend or resurrect authority: the
  lease checks add a bound, the attestation check adds a reading, the replay
  ledger adds a reason to refuse, and a decision that outlives its own window
  is refused as `stale_authorization:*`.
- **Absolute instants and relative durations are never confused.** An
  issuer's `expires_at` is calendar time and can only be compared against
  calendar time; a granted duration is the firewall's own and is measured
  against a monotonic clock. Folding one into the other is the defect this
  release exists to make impossible, and a lease's validity reports which
  bound closed it.
- **An anomaly is a refusal, not a warning.** A wall regression past the
  tolerance (`temporal_tolerance_seconds`, one clock quantum by default)
  marks the source
  suspect; a suspect source refuses every window by name, refuses to issue a
  new lease, and refuses to *move* records in a lapse sweep -- because a
  lapse is a state change and the reading that would justify it is the one
  known to be wrong. An anomaly is a statement about the time base and a
  later reading that happens to look fine does not retract it; clearing it
  (`TemporalGuard.clear()`) is an operator act, and it deliberately does not
  lower the high-water marks.
- **A restart cannot move time backwards.** With a watermark store the
  previous generation's highest wall reading is a floor and a boot below it
  marks every sample anomalous; without one the guard still detects a
  regression inside the process, and says plainly what it cannot prove. A
  monotonic reading from another boot is never subtracted from this one: a
  window whose generation differs is evaluated against its absolute deadline
  alone.
- **Every clock a decision is measured in is audited.** Per *named source*,
  so a store's own clock is audited on its own terms and two clocks with
  different bases never flag each other. Every clock-reading store is bound
  to the guard at construction, and an SDK that cannot bind one refuses to
  start -- the failure mode of a missed binding is silent.
- **Recorded windows are auditable after the fact.** Locally stamped
  security timestamps must be ordered, windows well formed, no lease may
  claim a deadline beyond the duration it was granted, no completion may
  post-date its own deadline, and no `ATTESTED` claim may sit outside the
  envelope window it relies on. All of it is re-derived from the records by
  `TEMPORAL_SECURITY_INTEGRITY`, the twenty-third invariant.

Documented non-guarantees added in v3.2: an attacker who owns the host clock
before the firewall starts and can also rewrite the watermark store can
present a consistent frame -- the durable floor raises that bar from
"restart the process" to "rewrite the watermark too and never let real time
catch up", and the documented lever is storage the attested stores cannot
reach; a monotonic clock is not signed, so a process that can rewrite its own
memory and the platform's monotonic source is outside this package's reach; a
raised `temporal_tolerance_seconds` accepts windows up to that much longer in
wall terms, which is why the default is one quantum of the platform's own
clocks -- measured, because `time.time()` and `time.monotonic()` both move
backwards by up to one quantum under concurrency on this platform and a zero
default refused legitimate requests; the default monotone clock is
`perf_counter` for the same measured reason; a
clock fault during the v2.9 effect path leaves the execution terminally
`DENIED` rather than retryable, which is v2.8's behaviour for an unreadable
clock unchanged; the effect-intent window is wall-bounded plus
anomaly-refused rather than monotonic-bounded, because an intent's deadline
does not grant dwell time the way a lease does; and with a persistent replay
store the durable row keeps the wall deadline it always had, with the
residual exposure bounded by the tolerance.

## v3.1 Security Boundary

v3.1 attacks the last boundary the earlier releases left open, and states it
in one line: **the firewall could say "I recorded that the effect succeeded
and my verifier agreed with my record"; it could not say "the payment
processor attests that this transfer settled".** Everything in the
side-effect journal and the verification journal was pushed into them by the
process Agent Firewall runs in. v3.1 accepts Ed25519-signed statements
produced *outside* it, and the security model, the attack surface and the
honest non-guarantees are in
[docs/v3.1-external-attestation.md](docs/v3.1-external-attestation.md).

If you are upgrading for one reason, this is it: **a completion that claims an
external system's state can now be required to point at a statement that
system signed -- about that exact effect, inside a validity window, exactly
once.** A forged envelope, one minted for another effect or attempt, one
signed before the issuer's key was revoked, one presented after its window
closed, one recorded while fresh and relied on later, one naming a different
external request, a nonce reused for a second statement, and a signed
statement that contradicts what the firewall recorded are each a named
refusal -- and a contradiction stays a contradiction rather than being
talked away by a third statement.

- **No second authorization system.** `FirewallSDK.authorize()` remains the
  only allow origin, and no function that decides an authorization outcome
  references attestation state at all:
  `EXTERNAL_STATE_ATTESTATION_SOUNDNESS` walks every module and fails if one
  ever does, so an ALLOW can never come to rest on evidence that originated
  outside the firewall, however well signed. The layer constructs no
  `AuthorizationResult`, writes no journal but its own, and touches no
  control-plane container.
- **An attestation is never a permission.** It is not read by `authorize()`
  or by any gate on the ALLOW path; the only thing it can do elsewhere is
  *refuse* a completion. A signature that arrives after revocation, expiry,
  suspension, or a policy/lineage/epoch change is preserved truthfully as
  `NOT_ATTESTED` and the lease is burned exactly as a v2.8 receipt after
  authority loss burns it -- an external statement is evidence about what
  happened, never a restoration of the authority that allowed it.
- **Who may vouch for what is a closed census.** Only the declared SDK
  methods may register or revoke an external issuer key, and only one method
  may drive the attestation journal and its nonce ledger. A subsystem that
  could register its own public key could mint its own evidence, and a
  subsystem that could write its own claim could skip the ledger; both fail
  the invariant, in both directions.
- **Freshness is checked twice.** An envelope outside its own window, or
  older than the deployment's `attestation_max_age_seconds`, is refused when
  it is presented *and* every recorded claim is re-checked at the moment a
  completion relies on it -- so a claim that was true when it was accepted
  and has since expired is `attestation_expired_at_completion`, not
  satisfied. A clock skew tolerance widens only the window comparisons;
  `max_age` is measured against unadjusted elapsed time.
- **Replay protection survives a restart.** The nonce ledger is a table in
  the same store as the records (`attestation_store_path=`), keyed
  `(issuer_id, nonce)`, because a ledger that dies with the process lasts
  exactly as long as the process did. An in-memory ledger is not replay
  protection.
- **Unavailable evidence fails closed.** An unreadable trust store, an
  unreadable clock, an unwritable journal, an unparseable envelope, an
  unsupported algorithm or format version, an unknown or revoked key and a
  signature that does not verify are each a named refusal and a journaled
  row -- never an exception, and never silence.

Documented non-guarantees added in v3.1: a signature establishes *who* said
something, not whether it is true, so an issuer that signs a false statement
is out of the firewall's reach; a deployment that registers a key its own
process controls has attested its own claim, and no cryptographic check can
tell the difference, so the trust decision stays with the operator; a stolen
external signing key produces statements the firewall will accept until it is
revoked; a rollback of the attestation store file rolls the nonce ledger back
with it, so anchor it on storage an attacker cannot reach (the same advice
the v3.0 state-commitment journal carries); and refusing to complete is the
only action this layer has, so an attacker who can flood it with invalid
envelopes can keep a deployment refusing to complete effects -- which is the
fail-closed direction this package always chooses.

## v3.0 Security Boundary

v3.0 extends the v2.6 proof from *writes* to the *state* those writes
produce. v2.6 proved that an allow is refused when a widening write
completes between its reads; the epoch counter counts writes, and a store
changed without its declared write path moves the state without moving the
counter. v3.0 makes the boundary's own record of its security state
machine-checkable: the property under test is **an authorization decision
must never rely on a security state the firewall cannot prove is
coherent**, and the design, the attack surface and the honest
non-guarantees are in
[docs/v3.0-security-state-integrity.md](docs/v3.0-security-state-integrity.md).

If you are upgrading for one reason, this is it: **a store edited around
its write path now refuses rather than allowing on drifted state.** A
revocation record removed by hand, a lineage edge written around
`register`, an issuer silently re-trusted after `revoke_issuer`, a
delegation-depth ceiling changed behind the setter, a store file rolled
back to an earlier snapshot between restarts, or a crash between a state
write and its durable commitment -- none of these moves the epoch, and
before v3.0 all of them left the live state silently different from the
state the firewall believed it was in. Each is now a `state_incoherent`
denial and a `SECURITY_STATE_COHERENCE` violation.

- **No second authorization system.** `FirewallSDK.authorize()` remains
  the only allow origin. The state-commitment journal stores digests and
  provenance labels, never permissions; like the epoch, its only effect
  on the boundary is to turn an allow into a denial. A forged, frozen,
  missing or unreadable journal cannot manufacture authority -- it can
  only fail to catch a drift, which is the pre-v3.0 behaviour rather than
  a new exposure.
- **Every in-domain write is a committed state transition.** The
  canonical security state is the revocation registry, the issuer trust
  store, the delegation lineage and the delegation-depth ceiling -- the
  four things an ALLOW reads whose silent mutation could widen a future
  verdict. Each declared write path opens a `record_state_commit`
  interval that commits the resulting state to an append-only hash chain;
  `STATE_COMMIT_WRITES` is a census the invariant checks in both
  directions, so a later change cannot add an in-domain write and pass by
  bracketing it.
- **An allow must match the firewall's own record of its state.** The
  terminal gate verifies the live canonical digest against the chain head
  under one journal lock, so the snapshot cannot be assembled from two
  different instants -- no TOCTOU between the security stores. A drifted
  store, a broken chain or an unreadable component aborts the transaction
  and refuses with `state_incoherent:*`; the state is not re-derived and
  the caller can ask again once the operator reconciles the store.
- **The chain attests state, not just activity.** Records are
  genesis-anchored, every record chains to its predecessor by digest, and
  every state digest must re-derive from the per-component digests
  recorded on the same link. An edited or deleted commitment breaks the
  chain and attests nothing; `SECURITY_STATE_COHERENCE`, the
  twenty-first invariant, verifies the chain and the live match on an
  exercised estate.
- **Crash outcomes are refuse, never guess.** A write whose durable
  commitment does not land (a crash between a state write and its
  commitment) leaves the live state ahead of the chain head; on reboot
  every allow is refused until the state is reconciled, not only the one
  the crash concerned. The durable crash and store-file rollback cases
  are pinned in `tests/test_v3_0_state_coherence.py`.

Documented non-guarantees added in v3.0: a consistent rollback of the
stores *and* the journal together is indistinguishable from that earlier
snapshot being the present (the time-machine boundary the epoch has
always had; anchor the journal on storage a store-file rollback cannot
reach to raise the bar); in-process code that can rewrite the journal's
own record list can bless tampered state only by rewriting the whole
suffix of the chain consistently, which is the same boundary; and the
journal lock closes TOCTOU between the security stores *during the
snapshot* -- it does not make the whole authorization atomic, and a
mutation landing after the coherence gate has returned is a new write
arriving after that decision's linearization point.

## v2.6 Security Boundary

v2.6 adds no subsystem and no authorization path. v2.5 attacked the boundary
with hostile *input*; v2.6 attacks it with hostile *timing* — the same
well-formed request, against the same healthy firewall, while the state the
eleven gates read is changed underneath them. The property under test is
**concurrency must never widen authority**, and the design, the ten
self-attack passes and the load figures are in
[docs/v2.6-concurrency.md](docs/v2.6-concurrency.md), whose *Non-guarantees*
section is the honest limit of the claim.

If you are upgrading for one reason, this is it: **an allow was never a
statement about one instant.** `FirewallSDK.authorize()` performs eleven
reads at eleven instants and the verdict asserts something about all of them
at once. That implication holds only while state moves in one direction. A
**widening** write landing between two of those reads produced an allow
describing a composite state that existed at no single instant — not stale,
not wrong about any individual read, but non-linearizable. Every store
already synchronised its own reads; the defect was between them.
`_gate_cryptographic_authority` is gate 10, so the widest part of that
window is a signature verification, by construction.

- **A widening write is now an interval, not an instant.** Every write that
  can widen authority is bracketed in `firewall/authority_epoch.py`, which
  carries a completed count, an in-flight count and a source label. The
  boundary samples at entry and at commit and requires the completed count
  unchanged **and** in-flight zero at both ends. Comparing the counter alone
  would miss a write that started before the request and had not returned,
  where the counter is identical at both ends and the state changed in the
  middle. A window that is not covered is a denial —
  `widened_during_authorization:<source>:<n>`,
  `widening_in_flight_at_entry:<source>`, or
  `widening_in_flight_at_commit:<source>`. The gates are not re-run and the
  firewall does not decide which state was really in force; it refuses to
  issue a verdict whose premise it cannot establish. `unknown ≠ trusted`,
  applied to time.
- **The census is checked in both directions, and so is store identity.**
  `AUTHORITY_EPOCH_COVERAGE`, the seventeenth invariant, fails on a declared
  widening write with no bracket *and* on a bracket in a function that is not
  declared — otherwise a later change could add a widening path and satisfy
  the check by bracketing it, and "these are all of them" would never be
  re-examined. It also requires every epoch-bound store the SDK holds to be
  bound to *that* SDK's epoch: a store rebound elsewhere would leave the
  boundary sampling an epoch nothing writes to, and the divergence check
  would be decoration that never fires.
- **Two more paths that raised instead of deciding, one reachable with
  shipped components.** `SecurityContext.authorize_and_record` reloads
  persisted budget state from disk inside the terminal gate, so a truncated
  file, a failed integrity hash or an `OSError` on the atomic replace all
  raise — and `SecurityBudgetExceeded` is a *subclass* of
  `SecurityContextError`, so the gate caught the one member of the family
  somebody had in mind and let the rest out. The semantic budget ceiling was
  the same shape on the bundled class. Both are now denials naming what
  failed.
- **A rollback that raised took the denial with it.** The terminal gate opens
  a semantic transaction before it finishes deciding, so every later denial
  rolls it back first — and that call was unguarded, inside the very
  `except` handlers whose purpose is to stop an exception replacing a
  verdict. The gate caught the injected failure, converted it into a denial,
  and lost the denial on the way out. The transaction is constructed inside
  the gate rather than held by the SDK, so the sabotage sweep could not reach
  it. A failed rollback now travels on the denial as
  `trace["rollback_error"]` — its own key, because a lost audit record and a
  reservation that would not roll back call for different responses.
- **Forged evidence still moves no grant.** `observe_authorization` is the
  only way an Aegis grant moves toward `ACTIVE`. Under load it was fed
  21,821 forgeries — including a genuine allow belonging to *another*
  capability — and the grant never left `SUSPENDED`; none of 640
  authorizations was allowed. Aegis constrains authority and does not grant
  it.

Documented non-guarantees added in v2.6: check-then-act windows are inherent
and are **not** closed — the epoch narrows the window inside `authorize()`
and says nothing about the time between the verdict returning and the caller
acting on it; a failed rollback is contained, not undone; the epoch's
guarantee is conditional on the census being complete, which is why the
census is an invariant rather than a convention; under a continuous widener
the behaviour is near-total refusal (`denied_fraction` 0.997–1.0 with no
non-epoch denials), which spends availability to protect authority and is
the intended trade; and the load figures come from 32 threads on one machine
with one GIL, so they establish that these shapes raced and produced no
allow, not an absence of races at other scales or across processes.

## v2.8 Security Boundary

v2.8 attacks the boundary v2.7 explicitly documented: between the
`STARTED` transition and the moment the handler's effect lands in the
world there is a window no in-process record can close, because the
firewall does not own the external system. v2.8 does not claim to close
that window. It makes the side-effect boundary **explicit, attestable,
idempotent and recoverable**, so that Agent Firewall's own representation
of an external side effect never claims more certainty, authority or
completion than the protocol actually established. The property under
test is **a side effect must never be represented as successfully
completed unless the firewall can establish what execution authority
existed, what side-effect attempt occurred, and what completion evidence
was observed**; the design, crash matrix and non-guarantees are in
[docs/v2.8-side-effect-commit.md](docs/v2.8-side-effect-commit.md).

If you are upgrading for one reason, this is it: **the protocol is
opt-in, and it only ever makes things stricter.** A caller that never
calls `prepare_effect` sees exactly the v2.7 behaviour and keeps exactly
the v2.7 guarantees (and v2.7 non-guarantees). A caller that **does**
prepare an effect for a lease is then held to the protocol: the plain
v2.7 `complete_execution` on that lease is refused with
`effect_unresolved:<state>` until the effect is resolved by a receipt or
reconciliation, so a durable intent can never be silently completed over
nothing.

- **No second authorization system.** `FirewallSDK.authorize()` remains
  the only allow origin. The side-effect journal is state, not evidence
  and not authority: no intent row, no receipt and no evidence kind can
  grant anything, and every journal progression is preceded by the same
  deny-only continuity validation v2.7 runs on the lease.
- **A modified effect never executes under a recorded intent.** The
  outbox row binds the effect by canonical digest (not by duplicated
  payload); an attempt, receipt or commit presenting a different effect,
  effect type or idempotency key is `effect_mismatch`.
- **A timeout after transmission is never success and never failure.**
  The three-way `UNKNOWN` is the explicit representation of external
  uncertainty. An automatic retry of an unknown side effect is refused
  (it could duplicate a real-world action); the only way out of `UNKNOWN`
  is an explicit, evidence-carrying `reconcile_effect` recording
  confirmed success, confirmed failure, or still unknown.
- **A replayed receipt cannot produce a second completion.** Confirmed
  outcomes are irreversible at the state machine, and
  `SIDE_EFFECT_COMMIT_INTEGRITY`, the nineteenth invariant, checks every
  recorded history for a second terminal entry, for an effect changing
  after authorization, and for `UNKNOWN` recorded as success.
- **Authority changes during effect processing are recorded, not
  rewritten.** A receipt that arrives after a revocation, policy change,
  epoch movement, Aegis suspension or risk revocation still records what
  happened -- with `receipt_authority_valid=False` -- and the execution is
  burned to its terminal failure with `executed=True`. The firewall never
  rewrites history because authority later changed, and never claims the
  effect completed under currently valid authority when it did not.
- **The journal is durable and idempotent.** One lease carries one side
  effect; a SQLite backend shares the execution store's file, so after a
  restart the journal still says what was intended, that an attempt was
  authorized, and that no outcome was observed -- and the deterministic
  crash matrix (`tests/test_v2_8_crash_matrix.py`) pins the state every
  boundary leaves behind. No crash state silently reads as `COMPLETED`.
- **Receipts are observations, and the model says which kind.** Caller
  assertions, handler observations and authenticated provider evidence
  stay distinct in the data model; `provider_evidence` is a label an
  integration earns by actually authenticating the provider's response,
  and an external request/transaction id is preserved as correlation
  evidence, never as proof.

**Known non-guarantee, stated rather than hidden:** the external world
is still not transactional. If the external system processed the request
and the firewall only ever saw a timeout, the effect is `UNKNOWN` until
an external-status query or an operator reconciles it. Internal
deduplication cannot un-send an already-sent external request, and an
external system without its own idempotency key can still receive
duplicates from two different executions of the same logical effect.
Agent Firewall guarantees what its own record claims; it cannot
guarantee what an uncontrolled external system did. See *What v2.8
cannot guarantee* in
[docs/v2.8-side-effect-commit.md](docs/v2.8-side-effect-commit.md).

## v2.7 Security Boundary

v2.7 attacks the boundary v2.6 explicitly left open. v2.6 proved concurrent
authority changes cannot **widen** an authorization decision, and documented
that the guarantee stops when `authorize()` returns and the caller begins
acting. v2.7 closes the gap between ALLOW and the side effect with an
**execution lease**: the recorded continuation of one authorization decision
that must re-establish the authority basis before every recorded progression
of the execution. The property under test is **execution must never occur
under authority that the execution context cannot still establish**; the
design, race definitions and non-guarantees are in
[docs/v2.7-execution-lease.md](docs/v2.7-execution-lease.md).

- **No second authorization system.** `authorize_execution()` calls the
  canonical `FirewallSDK.authorize()` and records a lease only for an allow.
  Every continuity check is deny-only; the lease store constructs no verdict
  and `AUTHORIZATION_UNIQUENESS` still pins the allow origin.
- **A revocation, suspension, expiry, lineage loss, policy change or epoch
  movement between authorization and execution turns the execution into a
  terminal, recorded refusal** -- `REVOKED`, `EXPIRED` or `DENIED` -- never
  a guess and never a silent pass. The lease stops in an explicit failure
  state; a lease revoked after `STARTED` records `executed=True` and is
  **never** written as a clean `COMPLETED`.
- **Exactly-once belongs to the store.** Every phase change is an atomic
  compare-and-set, so one lease reserves once, one execution identity names
  one live execution, and the same allow cannot drive two executions. The
  SQLite backend makes the CAS a single `UPDATE`, so the property and the
  record survive a restart.
- **The lease object is a reference, not a permission.** Forged, copied,
  edited, or stale lease objects are refused against the authoritative store
  record and the live state; a modified binding field is `lease_mismatch`,
  an unknown id is `lease_unknown`. Unreadable security state
  (`revocation_state_unavailable:`, `clock_unavailable:`, ...) is a refusal
  that names the cause, following `unknown != trusted`.
- **`EXECUTION_AUTHORITY_CONTINUITY`, the eighteenth invariant**, machine-
  checks the state-machine algebra, a two-direction source census over who
  may drive the lease store, and the hygiene of every recorded execution
  (no clean `COMPLETED` whose authority flags do not support it).

**Known non-guarantee, stated rather than hidden:** the firewall cannot
atomically control an external side effect. There is a window between the
`STARTED` transition and the moment the handler's effect lands in the world
that no in-process record can close, and a revocation cannot roll back an
external API call the firewall does not control. What v2.7 guarantees is
that the window is now an explicit recorded instant, that authority lost
*before* it is caught, and that an interrupted execution can never be
recorded as a clean completion. See *Non-guarantees* in
[docs/v2.7-execution-lease.md](docs/v2.7-execution-lease.md).

## v2.5 Security Boundary

v2.5 adds no subsystem and no authorization path. Twenty-two attacks were run
against v2.4's shipped code, and the corrections are recorded with their
reproductions in [docs/v2.5-boundary.md](docs/v2.5-boundary.md), whose
*Coverage gaps, stated* section is the non-guarantee list.

If you are upgrading for one reason, this is it: **a `CapabilityVerifier`
constructed without a `clock` made expiry unenforceable.** Signature-only
verification is a legitimate configuration — expiry is the firewall's time
gate to enforce — and that gate responded to an unreadable clock by not
checking the validity window at all, so an expired capability returned
`authorized`. A clock that raised, and a clock returning `nan`, took the same
path. The default configuration never constructed the case, because
`CapabilityVerifier.clock` is `time.time`.

- **A dependency the boundary cannot read is a denial that names it.**
  Twelve paths through `FirewallSDK.authorize()` raised instead of deciding.
  Nine were reads of the firewall's own state rather than of the caller's
  input — refusal state, risk state, issuer trust, revocation, delegation
  lineage, the clock and the evidence sinks — which is why an invariant whose
  probes were all hostile input could not see them; the remaining three were
  malformed arguments that escaped before any gate ran, and the envelope
  projection beside the boundary raised on both kinds. Each now denies with a
  reason naming what failed. What a caller's `except Exception` used to skip
  was not the authorization — it was the refusal.
- **A denial cannot be destroyed by the attempt to record it.** An unwritable
  audit sink replaced the *denial* with an `OSError`. The verdict is now
  preserved and the loss travels with it in `trace["evidence_error"]`. The
  same failure on the allow path withholds the allow as
  `evidence_unavailable:{Type}`, which is the asymmetry the two cases require.
- **The payload the boundary authorized is the object the handler runs.**
  Three model adapters could authorize one request and execute another — by a
  non-idempotent normalization, by a caller mapping that answered differently
  on a second read, and by a hostile `Mapping` re-materialized for the
  handler. The boundary was never bypassed and never wrong; it was asked a
  different question from the one the glue then acted on. Fixed structurally:
  normalize once, then hand the same object to both, and hand a
  `request_builder` a copy so it cannot shape what the handler unpacks.
- **The monitoring surface no longer reports authority the boundary denies.**
  `revalidate()` served a cached allow across an Aegis suspension, a
  narrowing and a latched refusal. No enforcement path consumes that answer as
  permission, so no request was ever admitted on it, but the surface whose
  only job is to notice a withdrawal did not notice.
  `SecurityContextSnapshot` now covers both, and the new
  `REVALIDATION_CONSISTENCY` invariant checks it over six security-state
  changes, each with a negative control.
- **An invariant that could not see what it forbade now can.**
  `AUTHORIZATION_UNIQUENESS` passed with a second authorization path planted
  inside `firewall/sdk.py`. It is now a census of every verdict construction
  in the package against a closed allow-list keyed by module *and* enclosing
  function, with one pinned allow origin. Two other invariants held green over
  the defects above rather than naming them — `FAIL_CLOSED`, whose probes were
  all hostile input, and `ENVELOPE_SOUNDNESS`, which absorbed a raising
  projection into its unresolved census — and both now exercise the paths they
  claim to cover.

Documented non-guarantees added in v2.5: the security-context snapshot is
known to be incomplete, and nothing enumerates the gate's inputs against its
fields, so a new mutable store behind an existing gate can repeat the stale
report the two new fields fixed; the adapter single-read discipline is fixed
at three sites and no invariant can see a fourth adapter reading its payload
twice; the nine new dependency probes each sabotage one read on one
authorization, so simultaneous failure is not what was established;
mid-flight narrowing is a race and every invariant is sequential; and the
published performance figures describe one estate, not a deployment.

## v2.4 Security Boundary

v2.4 makes authority adaptive without making authorization ambiguous. A live
grant can be narrowed, suspended, revalidated or revoked while a task is
running. `FirewallSDK.authorize()` is unchanged as the only decision
authority, and Aegis is off by default — `FirewallSDK(aegis_enabled=True)`
opts in, and with no controller attached the adaptive gate abstains and v2.3
behaviour is exact. See [docs/v2.4-aegis.md](docs/v2.4-aegis.md), whose §16
is the non-guarantee list.

- **Adaptive analysis cannot create authority.** Aegis reaches the
  authorization path through one gate that can only deny or abstain, and
  learns what happened through one callback the SDK invokes *after* the
  decision exists. Because the callback runs after, no Aegis state can be a
  precondition of the allow it observes. No Aegis module may construct an
  `AuthorizationResult`, and that is checked in the source text rather than
  by review.
- **Exactly one transition restores authority, and it requires a real
  allow.** The seven states are ordered by residual authority, and a
  transition is legal only if it does not increase it.
  `REVALIDATING -> ACTIVE` is the sole exception, and it needs an
  `AuthorizationResult` that is allowed, reasoned `authorized`, and traced to
  that capability's fingerprint. `REVOKED` and `EXPIRED` are terminal, checked
  before the ordering rule, so no evidence, clock change or ordering trick
  produces an edge out of either.
- **Restrictions only reduce.** They accumulate as conjuncts, there are two
  kinds, and the only widening operation is an explicit keyed `lift()` an
  operator must invoke. A parent's restriction binds every descendant because
  the match runs over every fingerprint in the chain.
- **An unrecognised change is revalidated, not trusted and not fatal.**
  Fifteen triggers map onto `KEEP < REVALIDATE < NARROW < SUSPEND < REVOKE`
  and combine by lattice join, so the strongest applicable response wins.
  An unknown trigger is `REVALIDATE`: `KEEP` would make an unknown event
  benign, and `REVOKE` would make any unknown string a denial-of-service
  lever. Nothing maps to `KEEP`, which is reachable only by establishing five
  positive conditions — "nothing changed" must be shown, not assumed.
- **Analysis is structurally distinguishable from authorization.**
  Pre-authorization simulation, blast radius, envelopes and classifications
  return objects whose `__bool__` raises, so `if preflight(...)` is an error
  rather than an accidental allow. Simulated evidence is signed with a
  simulation key so it cannot be mistaken for real evidence. Blast radius is
  labelled `derived`, is bounded, and resolves to `UNANALYZABLE` rather than
  returning a partial answer, because incompleteness there always means
  larger.
- **Unknown never resolves to permissive.** An unreadable budget is
  exhausted, not unlimited; an unreadable restriction matches; an
  unestablished issuer trust is `None` rather than `True`; an unresolvable
  chain yields the bottom envelope. No input produces an unknown stage with
  an allow recommendation.
- **The authorization path answers rather than raises.** Every Aegis method
  it can reach is total, and both read sites deny with
  `aegis_state_unavailable` if one does raise — which matters because the
  controller is injectable, so "the bundled controller behaves" was never the
  guarantee callers relied on.
- **Mid-flight change is seen.** Restrictions are read inside the gate and
  suspension is re-read inside the commit transaction. Eight named races are
  tested, including authorize-versus-revoke and delegate-versus-revoke-parent.
- **Envelope soundness is claimed in one direction only.** What the envelope
  excludes, the boundary denies. An envelope that does not exclude a request
  is not a pre-approval, and the API is named so that reading it as one looks
  wrong.

## v2.3 Security Boundary

v2.3 adds no subsystem and no authorization path. Its work was to attack
v2.2's shipped behaviour, fix what broke, and remove analytical output that
read as verified when it was not. `FirewallSDK.authorize()` is unchanged as
the only decision authority; every v2.3 correction narrows what it admits.

- **Three fail-open paths are closed.** A non-finite request value no
  longer satisfies every numeric bound — each bound is enforced by its
  negation, and `NaN` compares `False` against both sides, so
  `{"amount": NaN}` passed an `amount_max` of 100 and an `amount_min` of 10
  at once. A decision taken while a *configured* continuous-auth dependency
  was raising no longer reports as `authorized`; v2.2 gated the
  revalidations but not the initial decision, which made the first answer
  the single permissive one in the sequence. And reconfiguring a delegation
  budget no longer resets the consumed total, which had let an
  administrative call restore an exhausted lineage's whole allowance
  without revoking, re-issuing or signing anything.
- **A number that cannot be ordered cannot be shown to be within a
  bound.** That is the shape all three shared, and it is the same rule as
  "unknown is not trusted" applied to arithmetic. `json.loads` accepts the
  bare tokens `NaN`, `Infinity` and `-Infinity`, so the input arrived
  through ordinary request bodies and tool output.
- **A narrowing configuration change always takes effect.** A budget
  ceiling set below what a lineage has already spent is accepted and admits
  nothing further, rather than being rejected as inconsistent. Refusing a
  narrowing write because the resulting state looks awkward is how a
  containment action fails at the moment it is needed.
- **The strict invariant gate can pass, so CI can fail on it.** Seven of the
  sixteen invariants are claims about live state, and a source-only run
  reaches none of them, so `--strict` exited 2 on every invocation and
  those seven were effectively ungated. `firewall/invariants/exercise.py`
  builds the exercised estate through the SDK's public API only —
  exercising grants no authority — and CI now runs the source-only and
  exercised gates as separate steps. What a green exercised run establishes
  is bounded to that estate and the output says so.
- **One name must not carry two guarantees.** Three renames separate a
  cryptographic result from an analytical one that shared its name:
  `deception.ClaimIntegrityReport` verifies no signature,
  `security_memory.EvidenceCheckpoint` signs a different chain from the
  recorder's `Checkpoint`, and `AgentSecurityProfile.finding_score` runs in
  the opposite direction from `MeshState.trust_score` for an unchecked
  agent — wiring the profile into the mesh's `trust_provider` would have
  delivered an unverified agent as fully trusted.
- **A blinded analyzer is structurally distinguishable from a clean one.**
  Intelligence collection reports every configured source that raised in
  `IntelligenceReport.gaps` instead of swallowing it; policy
  counterfactuals count only cases the simulator could replay and report
  `unknown` when nothing was counted; an unparseable policy is reported as
  `unanalyzable_policy`. Previously a blinded run and a finding-free run
  produced the same empty result.
- **The thirteen self-attack questions are answered by tests, not prose.**
  `tests/test_v2_3_self_attack.py` attempts each attack through the public
  API. Where the system makes no guarantee, the test pins the non-guarantee
  rather than wiring something the platform does not wire.

Documented non-guarantees added in v2.3, stated rather than left to be
inferred:

- **`retire_key` is not containment for a stolen key.** A retired key stops
  signing through the SDK, but capabilities it signed keep verifying —
  including ones forged after retirement by anyone holding the private key.
  Rotation depends on that: invalidating a retired key's signatures would
  kill every capability in flight. Verification asks whether the signature
  is genuine and the issuer trusted, not whether the key is still in
  rotation. Use `revoke_issuer` to contain a compromised signer, and revoke
  the affected capabilities to withdraw what was already handed out.
- **Possession of a trusted signing key is authority.** There is no
  cryptographic answer to that; it is what a signature means. The threat
  model's boundary is the key material. `trust_issuer` does not import an
  issuer's keys, so naming an issuer as trusted is a strictly smaller reach
  than holding one of its private keys — a rogue signer under a trusted
  issuer name is still refused with `invalid_signature`.
- **`known_capabilities()` does not report revocation.** The v2.2 boundary
  below describes the view as preventing a subsystem from pinning a snapshot
  past a revocation. It does not: revocation is not recorded in that
  registry, and a revoked capability stays in the view. Nothing is
  authorized off the view, so this corrects what the view can be read as
  saying rather than closing a hole — but a subsystem that needs revocation
  status must call `is_effectively_revoked` rather than iterate.

See
[docs/v2.3-security-corrections.md](docs/v2.3-security-corrections.md),
[docs/v2.3-self-attack.md](docs/v2.3-self-attack.md),
[docs/v2.3-invariant-gate.md](docs/v2.3-invariant-gate.md) and
[docs/v2.3-migration.md](docs/v2.3-migration.md).

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

- **Sixteen invariants are machine-checked, not asserted.**
  `firewall.invariants` states each property once and checks it with
  exactly one function, so an invariant with no check is a missing registry
  entry rather than a silently absent property. `python -m
  firewall.invariants` gates the nine structural and self-contained
  invariants in CI; the other seven need an exercised estate and are gated
  by `--exercise --strict`. Status is three-valued: `UNVERIFIABLE` is falsy,
  makes the whole report falsy, and makes `assert_all` raise — accepting it
  would make the assertion satisfiable by breaking the checker.
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
  names can originate in untrusted tool output. From v2.5 this also covers
  the boundary's *own* reads: a refusal store, risk context, issuer trust
  store, revocation store, delegation lineage, clock or audit sink that
  cannot be read produces a denial naming the dependency —
  `revocation_state_unavailable:{Type}` and its siblings — rather than an
  exception for the caller's `except Exception` to interpret. A denial
  whose audit write fails keeps its verdict and reports the loss in
  `trace["evidence_error"]`; an allow whose audit write fails is withheld.
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
