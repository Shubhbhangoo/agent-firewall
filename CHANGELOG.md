# Changelog

## [3.5.0]

A witness-quorum release. v3.4 moved the trust root out of the firewall's own
storage, and then said so in its own honest-non-guarantees list: *"A witness
that lies. If the witness signs whatever it is handed, it attests nothing."*
It replaced "trust the firewall" with "trust one thing the firewall cannot
write" -- one key, one machine, one operator. v3.5 removes that single point
of failure. A checkpoint now becomes externally confirmed only when the
configured **threshold of distinct trusted witnesses** independently
authenticates the *identical* anchor state. Property: **no single external
witness is a root of trust**, pinned by `WITNESS_QUORUM_SOUNDNESS`, the
twenty-sixth registered invariant.

This is deliberately **not** a consensus protocol. There is no leader, no
term, no view change, no replicated log and no liveness machinery: v3.5 counts
independent signed statements about a value that already exists. If the
threshold cannot be met the deployment stops progressing, and the layer
reports that rather than working around it.

No second authorization path was added -- `authorize()` remains the only allow
origin, no ALLOW-path function references quorum state at all, and every
quorum verdict is a refusal.

### Added

- **The witness-quorum layer: `firewall/quorum.py`.** `WitnessPolicy` -- a
  threshold plus a set of trusted witness identities, whose `policy_id` is
  *derived* from `(threshold, sorted witness_ids)` over a canonical encoding,
  so a policy is a name its content earns rather than a label the caller
  asserts. `QuorumReceipt` -- one witness's signed statement covering anchor
  kind, anchor id, sequence, digest, checkpoint id **and** policy id, whose
  `receipt_id` re-derives from its own fields. `CheckpointPolicyBinding`,
  `QuorumParticipation`, `QuorumDecision`, `QuorumFinding`, `QuorumStatus` and
  `EquivocationEvidence` -- the round's record. `WitnessQuorumJournal` -- the
  protocol: `register_policy`, `activate_policy`, `bind_checkpoint`,
  `submit_receipt`, `confirm_quorum`. `InProcessQuorumWitness` is shipped for
  tests, benchmarks and the invariant estate, and its docstring states
  plainly that it is **not** an independence claim.
- **Eight ordered checks in `submit_receipt`, and the order is the design.**
  Re-derives; trusted (a registered key *and* an identity the policy names);
  signature verifies; has not already said something different here; a
  checkpoint is bound at this position; the position is current; the statement
  matches the binding exactly; the witness has not already voted. Each
  establishes a property the next assumes, so a receipt that fails an early
  check is never quietly interpreted by a later one.
- **Named refusals, one per failure mode:** `anchor_quorum_insufficient`,
  `anchor_quorum_split`, `anchor_witness_equivocation`,
  `anchor_policy_mismatch`, `anchor_witness_duplicate`, `anchor_witness_stale`,
  `anchor_witness_untrusted`, `anchor_witness_invalid_signature`,
  `anchor_checkpoint_mismatch`, and `anchor_quorum_unconfirmed` /
  `anchor_quorum_unverifiable` for the gate.
- **Equivocation is durable evidence, not an error to be resolved.** If one
  witness signs two different statements about one position, both signed
  receipts are retained, verifiable, and exposed through
  `sdk.quorum_equivocations()`; the contradictory vote is refused and the
  witness is not counted. There is deliberately no code path that picks a
  winner.
- **Dissent is recorded, not dropped.** A trusted witness authenticating a
  *different* value is recorded as dissent, and `anchor_quorum_split` is
  refused **even when the threshold of agreeing witnesses is present** -- a
  quorum that confirmed over dissent would be reporting an agreement that
  does not exist.
- **Confirmation is monotone.** A confirmed position is never un-confirmed,
  enforced in both the journal and the store: an attacker who loses a witness
  cannot take back a confirmation the deployment already relied on.
- **The active policy freezes once it has been used.** A binding made under
  3-of-5 is judged under 3-of-5; `activate_policy` refuses to replace a policy
  a binding already refers to, which is what stops a policy downgrade.
- **`firewall/quorum_store.py`** -- a durable SQLite record with eight tables,
  every one keyed **structurally** rather than by a caller-controlled id. The
  compound primary key on `quorum_receipts` is
  `(anchor_kind, anchor_id, sequence, witness_id, receipt_id)`: "one witness,
  one vote per position" is a shape the storage cannot hold a violation of,
  not a check the layer remembers to perform. On load, every row's dedicated
  columns are cross-checked against its payload; a disagreement quarantines
  the row and **poisons** the anchor, which then refuses with
  `anchor_quorum_unverifiable` and records a `tampered` finding. The store
  never shares a file with another store -- its path is derived by suffix, for
  the reason v3.4 §5 gives about SQLite write-ahead logs.
- **`FirewallSDK` wiring.** `quorum_policy`, `quorum_witness_keys`,
  `quorum_store_path` and `require_witness_quorum` (read-only after
  construction). A quorum-facing API: `quorum_register_policy`,
  `quorum_activate_policy`, `quorum_bind_checkpoint`, `quorum_submit_receipt`,
  `quorum_status`, `quorum_confirm`, `quorum_confirmed`, `quorum_receipts`,
  `quorum_votes`, `quorum_dissent`, `quorum_decisions`, `quorum_policies`,
  `quorum_active_policy`, `quorum_bindings`, `quorum_equivocations`,
  `quorum_findings`, `quorum_participation`, plus `quorum_journal` and
  `quorum_store` for components the SDK does not own.
- **The gate.** `_lineage_gate` now runs the anchor gate *and* the quorum
  gate; with `require_witness_quorum` on, a progression refuses with
  `anchor_quorum_unconfirmed` or `anchor_checkpoint_mismatch` when the
  position it rests on has no confirmed quorum behind it.
- **Invariant #26, `WITNESS_QUORUM_SOUNDNESS`** -- half source census, half
  live state, closed in both directions: every declared driver actually drives
  a quorum mutator, no other function does, no ALLOW-path function references
  quorum state at all, the quorum module constructs no verdict, every finding
  is of a kind the release can explain, and no execution is recorded COMPLETED
  while the position its progression rested on had no confirmed quorum. The
  canonical exercise reports **26 holds, 0 violated, 0 unverifiable**.
- **`tests/test_v3_5_witness_quorum.py`** -- 114 tests, including three
  Hypothesis property tests, attacking 2-of-3 and unanimous success,
  insufficient quorum, invalid signatures, duplicate votes, untrusted
  witnesses, stale receipts, checkpoint and policy mismatch, replay across
  anchors, replay across policies, equivocation, split votes, durability
  across restart, tampered persisted state, the source-census teeth, and the
  invariant going `VIOLATED` when a tooth is pulled.
- **A `quorum` benchmark group** in `firewall/benchmarks.py` -- receipt
  verification, round aggregation, confirmation, the satisfied and failed
  gates, the full pipeline with the quorum on and off as a control arm, the
  invariant sweep, and `authorize()` as the row that must not move.
- **`docs/v3.5-witness-quorum.md`** and **`docs/v3.5-performance.md`**.

### Corrected

- **The v3.5 gate is checkpoint-aligned, not per-stage, and the limitation is
  stated rather than buried.** The first version of the gate required a
  confirmed round at the lineage head's *current* sequence. One SDK call can
  advance a chain through several stages -- the attested pipeline moved a head
  from sequence 1 to 6 in a single call -- so that rule made
  `commit_effect` unsatisfiable from outside the boundary, and a gate that
  cannot be satisfied is a gate that gets switched off. The gate now asks for
  quorum behind the last confirmed anchor checkpoint when one exists at or
  behind the head, which is the same position the v3.4 gate validated a moment
  earlier. A deployment that wants per-stage witnessing takes a round per
  stage; the default does not impose it.
- **`register_policy(..., activate=True)` did not persist the activation.**
  `set_active_policy` was called on the in-memory journal but never reached
  the store, so a restart came back with no policy in force and every receipt
  refused as untrusted. The activation now happens inside `_activate_locked`,
  which both paths share.

### Changed

- **The invariant count is twenty-six.** `tests/test_v2_2_invariants.py`
  names it, `test_v3_2_temporal_integrity.py`,
  `test_v3_3_execution_lineage.py` and `test_v3_4_external_anchor.py` assert
  the registry size, and `test_v2_3_invariant_gate.py` gains
  `WITNESS_QUORUM_SOUNDNESS` to the set a fresh SDK leaves unverifiable --
  fourteen now, where it was thirteen.
- **`README.md`, `SECURITY.md` and `pyproject.toml`** carry the 3.5.0 version
  and the twenty-sixth invariant.
- **Security CI** gates all twenty-six invariants on an exercised estate, up
  from twenty-five, of which seventeen are state-dependent.
- **`_anchor_full_walk`** in `firewall/benchmarks.py` gained an optional
  `quorum` argument so the v3.4 walk and the v3.5 walk measure the same
  pipeline; the v3.4 rows are unchanged when it is not passed.

### Notes

- **A quorum raises the number of things an attacker must reach from one to
  `threshold`; it does not make them unreachable.** `2-of-3` is defeated by
  two compromised witnesses. That is the central honest limitation and it is
  in the design document's §5, not a footnote.
- **Three witnesses on one machine are one witness with three names.** The
  protocol counts identities; whether those identities are separate failure
  domains is a deployment property this package cannot observe and must not
  certify.
- **The layer will not choose the threshold for the operator.** `1-of-3` is
  legal and is exactly as strong as v3.4's single witness. A package that
  decided `2` was "too low" would also be deciding its operator's
  availability budget.
- **Availability is the price.** There is no degraded mode, no "best effort"
  confirmation, and no timeout after which fewer witnesses are accepted. A
  round that loses stays lost.


## [3.4.0]

An external-anchoring release. Every layer before this one raised the cost of
tampering and then, in its own honest-non-guarantees list, admitted the same
thing: the root of trust stayed inside the process. v3.0 chained the canonical
state digest, v3.2 anchored every window, v3.3 chained an execution's whole
lineage -- and the *head* of each of those chains is a row in a store the same
process writes. A chain the process can rewrite is tamper-*evident* only
against a tamperer who is not that process.

v3.4 publishes a signed **checkpoint** of a monotone position to an **anchor
witness** that holds it outside the firewall's storage, and refuses any
progression that contradicts it. Property: **the firewall's own storage is not
the only account of what it has already done**, pinned by
`EXTERNAL_ANCHOR_SOUNDNESS`, the twenty-fifth registered invariant. No second
authorization path was added -- `authorize()` remains the only allow origin,
no ALLOW-path function references anchor state at all, and every anchor
verdict is a refusal.

This release also carries a development increment that had accumulated on the
branch: one latent crash corrected, a crash-class lint gate added, and the
packaging, CI and documentation metadata brought in line with what the
repository already claimed.

### Added

- **The external-anchor layer: `firewall/anchor.py`.** `AnchorCheckpoint` -- a
  signed statement about one anchor at one instant, whose `checkpoint_id`
  re-derives from its own fields so a forged or edited one is visible as a
  disagreement with the id it claims. `AnchorJournal` -- the protocol:
  `publish` (read the anchor, have the witness sign it, refuse a rewind before
  the witness ever sees it), `confirm` (re-derive, verify under a *registered*
  witness key, refuse anything at or below the confirmed sequence), and
  `compare` (the progression gate, which returns a refusal reason or nothing
  -- never a permission). Witnesses: `NullWitness` (refuses everything, and is
  what an SDK with no witness holds), `LocalFileWitness` (a test and
  single-host affordance, and it says so), `RemoteWitness` (an
  operator-supplied transport), and `InProcessWitness`, whose docstring states
  in its first line that **it is not a witness** and that using it in a
  deployment is a silent downgrade to v3.3 with extra steps.
- **`firewall/anchor_store.py`** -- a durable SQLite record of published
  checkpoints and confirmed receipts, keyed by the structural
  `(anchor_kind, anchor_id, sequence)` triple, WAL with `synchronous = FULL`.
  A rejected insert is resolved as a retry (the identical checkpoint resumes)
  or a rewind (a different claim about one position is `anchor_rewind`),
  never silently overwritten.
- **`FirewallSDK` wiring.** `anchor_witness`, `witness_keys`,
  `anchor_store_path` and `require_external_anchor` construction parameters;
  `anchor_publish`, `anchor_confirm`, `anchor_compare`, `anchor_records`,
  `anchor_receipts`, `anchor_findings`; and `bind_anchor_reader` /
  `bind_anchor_prefix_reader` for a deployment anchoring a store of its own.
  The progression gate runs *after* the lineage checks, deliberately: an
  unprovable lineage is already a refusal, and reporting the anchor first
  would tell an operator their witness was unreachable when the real problem
  was a broken chain.
- **Two readers per anchor, and the second one is load-bearing.** A head
  reader says where an anchor is now; a prefix reader says what it committed
  to at a position it has since moved past. A head-only comparison would
  return "agree" for a chain rewritten into a fabricated but internally
  consistent history *longer* than the confirmed one -- the one rewrite this
  layer exists to refuse -- because such a chain presents a head at a higher
  sequence. `compare` asks the prefix reader whenever the head has moved on,
  and a kind with no prefix reader bound is `anchor_missing` rather than
  assumed to agree.
- **Invariant #25, `EXTERNAL_ANCHOR_SOUNDNESS`** -- half source census, half
  live state, like its four predecessors. The census is closed in both
  directions over who may drive the anchor journal, and carries the
  load-bearing negative that no ALLOW-path function references anchor state at
  all. The state half re-derives and re-verifies every recorded checkpoint,
  checks the confirmed set is a subset of the published set with strictly
  increasing sequences, checks every finding is one the release can explain,
  and checks that no COMPLETED execution disagrees with the checkpoint its
  anchor was confirmed at. `--exercise --strict` now reports **twenty-five of
  twenty-five**; the canonical estate publishes and confirms through a witness
  so the state half has something to inspect.
- **`tests/test_v3_4_external_anchor.py`** -- 84 tests attacking the layer from
  both sides, named by what they attack: a consistent rewrite, a rewind to an
  older snapshot, a truncation, a forged receipt, a receipt signed by an
  unregistered key, a receipt replayed from another anchor, a witness that
  answers out of order or about another anchor, a fabricated chain *longer*
  than the confirmed one, an edited and an unsigned stored checkpoint, a
  confirmed checkpoint absent from the published set, a duplicate sequence, an
  unexplained finding kind, an unreadable store, the read-only gate flag, the
  source census failing on an undeclared caller in both directions, and the
  negative that the ALLOW path is unaffected by anchor state.
- **A `anchor` benchmark group** in `firewall/benchmarks.py` -- publish,
  confirm, the comparison alone, the comparison with the head moved on, the
  real gate with the SDK's reader, the invariant sweep, `authorize()` with the
  layer constructed, and the full pipeline with the gate on beside the same
  pipeline with it off as a control arm.
- **`docs/v3.4-external-anchoring.md`** and **`docs/v3.4-performance.md`** --
  the design, and the measurements. The performance document also records a
  measured regression this release found and removed: the gate's lineage
  reader originally scanned every chain in the journal, making each
  progression cost a pass over the whole estate. Resolving one chain by id
  through `LineageJournal.get` is **~330x on the gate and ~3x on the whole
  pipeline**, and removes a cost that would have grown with every execution a
  deployment ever ran.
- **A `ruff` gate over `firewall/`, wired into Security CI.** The rule set
  is deliberately the crash-class only (`E9`, `F63`, `F7`, `F82`): syntax
  errors, invalid format strings, misplaced control flow, and names that
  are not defined in the scope reading them. A `NameError` on an
  authorization path would violate `FAIL_CLOSED`, which requires the
  boundary to deny rather than raise, so the gate runs *before* the
  regression suite rather than after it. Widening the set is a per-family
  decision with the gate re-run in between: the invariant suite parses
  this package's own source, so a mass auto-fix changes the input of a
  security check.
- **PEP 561 support** -- `firewall/py.typed`, a `Typing :: Typed`
  classifier, and a `package-data` entry to ship the marker. Every module
  in the package was already annotated, but without the marker a
  downstream type checker treats each import as `Any` and never reads a
  single one.
- **`LICENSE` (MIT).** The classifier and the README both claimed MIT;
  the file was absent.
- **Python 3.13** in the classifiers, both CI matrices, and the README
  support lines.

### Corrected

- **`firewall.timeline.summarize_event` read an undefined name.** Its
  fallback branch referenced `event_type`, a name that does not exist in
  the function -- the parameter is `event`. Every member of the closed
  `EventType` set has an explicit arm above the fallback, so nothing
  shipped ever reached it, and that is precisely why it survived: the
  function had no test coverage at all, and the defect sat behind a closed
  set where a static reader would not look for it. It would have raised
  `NameError` on the first event of a sixteenth type, on a security
  timeline, in production. The branch now derives its title from
  `event.type.value`, which is the rule the rest of the package follows:
  a value the code does not recognize resolves to something neutral, and
  nothing raises where a value belongs. Found by the new lint gate as
  `F821`, proved to raise on the previous revision, and pinned by two
  tests in `test_v1_8_projections.py` -- one for the fallback's contract,
  one asserting that no current `EventType` member reaches it.
- **`AnchorCheckpoint.from_dict` refused a sequence of zero.** A lineage's
  genesis link sits at sequence 0, so the first checkpoint a deployment
  publishes is a checkpoint at 0. The parser required a positive sequence,
  which made such a checkpoint *storable* -- the store does not validate --
  but *unreadable*, so a durable anchor store failed to load at construction
  and the process refused to start after a perfectly ordinary first run.
  Found by the store round-trip test, and pinned by two regression tests.
- **The anchor store shared a file with whichever durable store the caller
  named.** Its path was resolved by falling back through the same paths the
  other stores use, so an SDK constructed with `state_commit_store_path`
  put the anchor schema *inside* the state-commit journal's file. Two live
  connections to one SQLite database is not a naming preference: SQLite
  folds a write-ahead log back into the main file only when the *last*
  connection closes, so the second connection left the log in place -- and
  a store file rolled back between runs was then silently *replayed* from
  the stale log rather than detected, because the log still held the write
  the rollback was meant to undo. The v3.0 crash test is what found it:
  `SECURITY_STATE_COHERENCE` reported `HOLDS` on a state whose committed
  head had been rolled back. The path is now *derived* -- `journal.db`
  yields `journal.db.anchors` -- so the anchors get a sibling file and
  never another store's own, and the journal is durable only when the
  deployment asked for one (a named file, a supplied witness, or
  `require_external_anchor`), so an SDK that merely has a durable
  revocation store leaves no anchor file behind that nothing reads. Pinned
  by three tests: the sibling path and the absence of an anchor schema in
  the named file, the rule that naming a durable store is not the same as
  asking for anchoring, and the v3.0 crash reached through a v3.4 SDK.
- **`firewall/a2a/auth.py`** carried an unused assignment and a bare
  `except`; the assignment is gone and the handler now names the exception
  family it is deliberately catching.

### Changed

- **CI branch filters are patterns, not enumerations.** `cli.yml` listed
  release branches up to `v2.5` and had never been extended, so from
  `v2.6` onward the CLI workflow did not run on push at all -- five minor
  releases of unchecked CLI surface. `security.yml` had been kept current
  by hand to `v3.3`, which is the same defect waiting for the next
  release. Both now match `v*`, covering every release branch and
  incapable of drifting.
- **`pyproject.toml`** declares `authors`, and a `dev` extra that names
  `anyio` -- the marker the MCP transport tests use, previously satisfied
  only transitively through `mcp`, so a dependency bump could have taken
  the marker with it and left those tests quietly skipped -- and `ruff`.
- **`requirements.txt`** mirrors the union of the runtime dependencies and
  the `dev` extra and says so. It had omitted `hypothesis`, which the
  property and fuzz tests import.
- **pytest configuration** with `--strict-markers` and `--strict-config`,
  so a typo in a marker name or an ini key fails rather than silently
  skipping tests. Deliberately no `testpaths`: the suite spans two
  generations of layout -- the v0.3-v2.1 campaigns at the repository root,
  the v2.2+ campaigns under `tests/` -- and pinning one root would
  silently stop collecting the other, which for a security suite is the
  worst available outcome.
- **README.** The documentation index now lists the v3.0-v3.4 design and
  performance documents, which all existed and none of which were linked;
  the upgrade command points at the current release rather than the `2.9.0`
  it had been left at.

### Notes

- **Only the lineage head is bound by default, and the reason is stated
  rather than left to be discovered.** The design names three anchors, but a
  binding is only usable when the anchor has a genuinely monotone position
  that `compare` can read twice. The lineage chain head has one. The temporal
  watermark store exposes a high-water *mark* and the issuer registry a key
  *set*; neither is a position, so publishing a checkpoint over one and then
  comparing it would manufacture `anchor_mismatch` refusals out of ordinary
  operation. Both remain bindable by an operator whose store does expose a
  monotone position.
- **Anchoring costs ~1.0-1.7 ms per execution** on the reference machine, of
  which the gate itself is ~0.2 ms. The ALLOW path does not move: the row is
  published beside two references precisely so a future change that reaches
  into a decision shows up as a delta rather than as a footnote. See
  `docs/v3.4-performance.md`.


## [3.3.0]

Every release before this one answered a question about one *stage* of an
execution. v2.7 recorded the continuation of an allow as a lease, v2.8 the
side effect, v2.9 the verification, v3.1 the external attestation, v3.2 the
temporal context each of those is valid in. Five journals, each correct
about its own stage -- and nothing that established the stages belonged to
**one execution**, that they happened in that order, or that nothing was
forked, grafted or re-ordered along the way. v3.3 states the property that
was missing:

```text
An execution can only progress when its complete lineage remains intact,
unique, correctly bound and tamper-evident.
```

An **execution lineage** is an append-only, hash-chained commitment to

```text
AUTHORIZED -> EXECUTED -> OBSERVED -> VERIFIED -> ATTESTED -> COMPLETED
```

for exactly one execution identity: one lineage per execution, one
commitment per stage, each chaining to the one before it from a fixed
genesis anchor and carrying a digest of the evidence that justified that
stage. The chain is what makes the sequence tamper-evident; the accumulated
subject binding is what makes it *this* execution's sequence rather than a
plausible-looking reassembly of somebody else's. The design and the honest
non-guarantees are in
[docs/v3.3-execution-lineage.md](docs/v3.3-execution-lineage.md); the
measurements are in [docs/v3.3-performance.md](docs/v3.3-performance.md).

No second authorization system was built. The lineage layer constructs no
`AuthorizationResult`, no ALLOW-path function references lineage state at
all, and every verdict it produces is a refusal -- which the release's
invariant checks, in both directions, over the whole package.

### Added

**The lineage layer (`firewall/lineage.py`, `firewall/lineage_store.py`).**
`LineageStage` (the six stages, as a total order), `LineageOutcome`
(`ADOPTED` / `REFUSED` / `NOT_ADOPTED`), `LineageKind` (`COMMITMENT` /
`SEAL`), and a `LineageJournal` that opens a chain at its `AUTHORIZED`
genesis, advances it one stage at a time, and seals it. A `LineageLink`
carries the fields that make it re-derivable rather than merely stored --
its own id, its position, its stage and ordinal, an evidence digest, the
accumulated binding and its digest, and its parent's id. The genesis chains
from `LINEAGE_ANCHOR`, a constant, so a forged link cannot claim "no
predecessor" by pointing at zeros. `SQLiteLineageStore` keys links by the
structural `(lineage_id, sequence)` pair rather than the declared id, so a
forged `commitment_id` can neither collide with nor displace a real link.

**The accumulation rule (`merge_binding`).** A subject binding grows: a
field may be absent early and present later, and may never change value or
disappear. The second half is the half that catches cross-execution
substitution, and it is refused with the offending field named.

**SDK wiring.** `FirewallSDK` constructs one `LineageJournal` beside the
stores it commits to (`lineage_journal=`, or `lineage_store_path=` for
durable storage; supplying both is refused at construction). Two gates
guard progression: `_lineage_gate`, which demands the chain's head be
exactly the stage before the progression, and `_lineage_gate_satisfied`,
which demands the chain hold a stage *or a later one*, for the operations
that may legitimately arrive at more than one point in the pipeline. Every
refusal is a named string -- `lineage_unavailable`, `lineage_broken:*`,
`lineage_sealed:*`, `lineage_stage_mismatch:*`, `lineage_stage_missing:*` --
and is also recorded as a finding, so an attempted fork is visible as an
attempt rather than only as a refusal in a return value. `require_lineage`
is read-only after construction, like `require_external_attestation` before
it.

**Adoption.** An execution the firewall inherited -- a lease issued by a
previous process generation, or by a caller-supplied store -- has its chain
opened at `AUTHORIZED` and advanced through exactly the stages the journals
show, then sealed if the execution is already terminal. The genesis marks
the chain `adopted`, so an operator can tell the firewall's own executions
from the ones it took over, and the lease record stays the authority either
way.

**Invariant #24, `EXECUTION_LINEAGE_SOUNDNESS`.** Three halves: a source
census over who may drive the lineage journal (and the negative, that no
ALLOW-path function may reference lineage state at all), the integrity of
every stored chain link by link, and the live behaviour -- every recorded
chain agreeing with the lease and the journals it describes, and no
`COMPLETED` execution lacking a chain that holds all six stages with
nothing refused.

### Changed

- The invariant suite is twenty-four, not twenty-three, and the invariant
  gate's exercised estate now reaches a completed execution lineage.
- `firewall/invariants` exports `check_execution_lineage_soundness`.
- `python -m firewall.benchmarks lineage` is a new group: seven rows
  covering the layer's own primitives, the audit, the ALLOW path with the
  layer constructed, and the full attested pipeline with the gate required
  beside the same pipeline with it off.

### Corrected during the v3.3 gates

**`_lineage_gate_satisfied` did not honour `require_lineage=False`.** The
lease path's gate (`_lineage_gate`) short-circuited on the flag; the
side-effect path's gate did not. A caller that had turned the requirement
off was therefore ungated on the lease path and *refused* on the
side-effect path -- at `record_effect_receipt`, with
`lineage_stage_missing:executed` -- breaking the documented contract that
the requirement off is the v3.2 behaviour. Found by the new
`lineage_walk_reference` benchmark row, which exercises the full attested
pipeline with the requirement off. Both gates now answer `None` when the
requirement is off, and a regression test covers the path the existing
"requirement off" test did not.

**Eight documentation files carried invalid UTF-8 bytes** -- lone CP1252
bytes where `µ`, `·`, `±`, `—` and `–` were intended -- so they rendered as
mojibake. Repaired across `docs/`; every markdown file in the repository is
now valid UTF-8.

**A hardcoded invariant count the census sweep missed.**
`tests/test_v3_2_temporal_integrity.py` asserted `len(INVARIANTS) == 23`.
Now twenty-four.

**A load-sensitive concurrency test.** `TestLoad::test_many_threads_many_cycles_stay_consistent`
asserts that a clean pipeline completes every cycle under twelve threads. On
Windows the platform wall clock is quantised at 15.6 ms and, under that load,
can read backwards by more than the default one-quantum
`temporal_tolerance_seconds` -- so the v3.2 temporal guard refused a
legitimate request with `temporal_anomaly:wall_regression` and the test failed
for a reason that has nothing to do with concurrency (reproduced 2 in 20 under
CPU load, and 0 in 3 in isolation). The test now injects a forward-only clock,
which removes the confounder without weakening any check: the guard's
behaviour under a clock that genuinely moves is v3.2's subject and is tested
in `test_v3_2_temporal_integrity.py`.

### Performance

**The invariant suite's source censuses are memoised.** Each of the
twenty-four invariants runs its own census, and each census re-parsed every
module of the package and re-derived the same two per-module owner maps -- so
a single `assert_all` parsed the whole package twenty-four times, and a test
file that runs the suite ten times paid for it ten times over. Two caches
remove that:

- `source.parse_module` is memoised per path. It is a pure function of the
  file's bytes, every caller only reads the tree it returns, and it is only
  ever called on the package's own modules.
- `_qualified_functions` and `_attestation_node_owners` are memoised per
  tree, keyed by `id` with an identity check, since an `ast.Module` is not
  hashable and the tree is held in the cache.

`tests/test_v2_2_invariants.py` went from **451 s to 138 s**; a single
`check_execution_lineage_soundness` from **2196 ms to 644 ms**. Census
*results* are deliberately not cached: the census-teeth tests monkeypatch the
declaration sets and expect the census to observe the patch, so a memoised
census would return a stale answer and quietly stop testing anything.

### Documentation and packaging

- `docs/v3.3-execution-lineage.md` and `docs/v3.3-performance.md`.
- README, SECURITY and CHANGELOG updated for 3.3.0. The SECURITY supported
  versions table had also lost 3.1.x and 3.2.x; it now lists 3.3.x through
  3.0.x.
- `pyproject.toml` at 3.3.0; CI runs the gate against the `v3.3` branch,
  and the exercised-estate step now reads twenty-four invariants.

## [3.2.0]

Every release before this one bounded *what* a decision may rest on. v3.2
bounds *when*:

```text
A security decision is valid only within a provable temporal context.
```

A capability window was compared against whatever `time.time()` said, a lease
deadline was stamped from a clock the firewall does not own, an attestation's
maximum age was measured in wall seconds, a replay entry expired when wall
time passed its deadline. One weakness, four doors: a decision that was valid
when it was made can be made to look valid again by moving the clock it is
compared against. v3.2 audits every clock a decision is measured in, anchors
every window in both an absolute deadline and an elapsed budget, refuses a
wall clock that moved backwards or a monotonic clock that regressed *by name*
rather than believing it, re-checks a decision's window at the moment it is
emitted, floors a restart behind the previous process generation's highest
wall reading, and keeps a durable watermark so lease and replay windows
cannot be extended by a clock change. The design and the honest
non-guarantees are in
[docs/v3.2-temporal-integrity.md](docs/v3.2-temporal-integrity.md); the
measurements are in [docs/v3.2-performance.md](docs/v3.2-performance.md).

No second authorization system was built. The temporal layer constructs no
`AuthorizationResult`, every verdict it produces is a refusal, and no
function that decides an authorization outcome may read a platform clock --
which the release's invariant checks, in both directions, over the whole
package.

### Added

**The temporal layer (`firewall/temporal.py`,
`firewall/temporal_store.py`).** A `TemporalGuard` auditing every named time
source against its own history -- the highest wall reading and the highest
monotonic reading it has ever seen, plus an audit trail of every anomaly.
`TemporalContext` carries a reading and its own verdict; `TemporalWindow`
anchors a validity interval in both time bases; `TemporalError` is what an
unreadable clock produces, so every call site has one refusal for it.
`SQLiteTemporalStore` persists the per-source watermarks -- raised only,
never lowered -- so a restart cannot move time backwards.

**Two-bounded validity everywhere.** A lease now carries
`issued_monotonic`, `ttl_seconds` and `temporal_generation`, and its validity
is the earlier of its wall deadline (clamped by the duration it was granted)
and its elapsed budget; it reports `lease_expired`,
`lease_expired:monotonic_budget` or `lease_expired:monotonic_regression`, and
an anomalous clock refuses without burning the record. An attestation claim
carries `recorded_monotonic` and `temporal_generation`, and its age is the
larger of wall time since the issuer stamped it and elapsed time since this
firewall recorded it -- so a rolled-back clock cannot make an old statement
look young. The in-memory replay ledger bounds each entry the same way.

**Stale-authorization refusal.** The terminal gate re-checks that the
temporal context is still provable, that the capability window has not closed
during the request, and -- when a deployment sets
`temporal_decision_budget_seconds` -- that the request did not exceed its
budget. A decision that outlives its own window is refused as
`stale_authorization:*` rather than emitted.

**SDK surface.** The `temporal_guard`, `temporal_store_path`,
`temporal_tolerance_seconds`, `monotonic_clock` and
`temporal_decision_budget_seconds` construction arguments; the `temporal`
guard, `temporal_state()`, `temporal_store` and the read-only
`temporal_decision_budget_seconds` property; and `bind_temporal` /
`temporal_of` / `sample_temporal` for components the SDK does not own.

**Invariant #23: `TEMPORAL_SECURITY_INTEGRITY`.** A source census over which
code may compare a security deadline (both directions, plus the rule that no
ALLOW-path function reads a platform clock), the integrity of the recorded
windows and locally stamped timestamps, and live behavioural probes on a
scratch SDK -- an honest clock must allow, a rolled-back wall clock and a
regressed monotonic clock must each deny by name, a forward jump must not be
mistaken for an attack, and an elapsed budget must close a lease a rolled-back
wall clock still calls open. Adversarial coverage lives in
`tests/test_v3_2_temporal_integrity.py` (97 tests: clock rollback, clock
jumps, expired leases, delayed execution, stale attestations, replay inside
and outside a window, restart recovery, concurrent expiry races and tampered
timestamps, each also asserted as an invariant finding).

### Changed

- `ExecutionLeaseStore.issue` stamps the monotonic anchors from a validated
  context and refuses to issue inside an anomalous one; `expire_lapsed` uses
  one definition of validity and refuses to move records while the clock is
  untrustworthy. The same rule applies to `EffectJournal.expire_lapsed` and
  `ReplayProtector`.
- Attestation freshness is evaluated by `AttestationJournal.check_window`,
  which takes its reading inside the guard, and
  `AttestationRecord.fresh_at` / `age_at` measure the age in both bases.
  `freshness_failure` gained an optional `effective_age`.
- An authorization's allow path now pays one audited clock sample and one
  terminal re-check -- measured at single-digit microseconds for the sample
  itself, and inside the run-to-run variance of the row it is compared
  against on this machine.

### Corrected during the v3.2 gates

Three defects were found by the release's own gates and fixed rather than
documented around:

- **A sample is now atomic with respect to its own high-water mark.** Readings
  were taken outside the guard's lock and compared inside it, so two threads
  could read 100.0 and 100.5, update the watermarks in the opposite order,
  and have the second thread's honest reading classified as
  `monotonic_regression`. Found by `tests/test_v2_4_aegis_concurrency.py`,
  which was seeing a third outcome in a two-outcome race.
- **The regression tolerance defaults to one quantum of the platform's own
  clocks** rather than to zero. Measured on this platform: `time.time()`
  moved backwards relative to a strict high-water mark in 1192 of 320 000
  concurrent readings (largest 10.2 ms) and `time.monotonic()` in 754 of
  320 000 (largest 16.0 ms), so a zero default refused legitimate requests --
  which is how `tests/test_v2_6_concurrency_never_widens.py` caught it. A
  real rollback is seconds or minutes and is always caught.
- **The default monotone clock is `time.perf_counter`**, not
  `time.monotonic`: it measured zero backward readings at 1e-07 resolution
  where `monotonic` measured 754 at one-quantum magnitude, and an elapsed
  budget is exactly where resolution matters. `monotonic` remains the
  fallback.

One v2.6 test's *calibration* was hardened at the same time: the adapter race
asserted "something executed" in a single round, but one `constraint_denied`
memoizes a refusal for (agent, action), so an over-ceiling request that won
the race starved every legal one -- measured with no temporal anomaly
recorded and no guard suspect. The security assertions are still made in
every round; the calibration now repeats until a legal request has been
observed to win.

### Documentation and packaging

- `docs/v3.2-temporal-integrity.md` (temporal model, trusted clocks,
  monotonicity guarantees, recovery semantics, threat boundary, limitations)
  and `docs/v3.2-performance.md` (directional numbers).
- Updated `CHANGELOG.md`, `README.md`, `SECURITY.md` and `pyproject.toml` to
  3.2.0; the invariant census (`tests/test_v2_2_invariants.py`,
  `tests/test_v2_3_invariant_gate.py`) and the CI gate
  (`.github/workflows/security.yml`) now count twenty-three invariants.
- New `temporal` benchmark group (`temporal_sample`, `temporal_authorize`,
  `temporal_lease_validity`, `temporal_attestation_age`,
  `temporal_under_regression`).

## [3.1.0]

The boundary v3.0 leaves open is not about state the firewall owns. v2.8
recorded what happened, v2.9 established whether the recorded claim could be
trusted, v3.0 proved the security state coherent -- and all three read
records this process wrote. v3.1 closes that gap:

```text
AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED =/= ATTESTED =/= COMPLETED
```

An **external state attestation** is an Ed25519-signed envelope produced
*outside* the firewall, bound to the exact effect, attempt, execution,
capability and external request handle, carrying the issuer's own validity
window and a one-shot nonce. `FirewallSDK.record_attestation()` verifies it
against the *journal row*: a registered and unrevoked issuer key, a
supported algorithm and format version, the scope fields, the correlation
handle the receipt recorded, the window, the asserted outcome against what
was recorded, and the nonce against a durable replay ledger. A completion
can then require it (`attestation_required=True`, or
`require_external_attestation=True` for the deployment), so a lease over an
adopted side effect is never recorded `COMPLETED` without a current,
correlated, uncontradicted, non-replayed attestation. The design and the
honest non-guarantees are in
[docs/v3.1-external-attestation.md](docs/v3.1-external-attestation.md); the
measurements are in [docs/v3.1-performance.md](docs/v3.1-performance.md).

No second authorization system was built. The new layer constructs no
`AuthorizationResult`, is not read by `authorize()` or by any gate on the
ALLOW path, writes no journal but its own, and -- exactly like the
verification stage -- its only effect elsewhere is to turn a completion into
a refusal. An attested verdict may only be recorded while the execution's
authority basis still holds, so an attestation can never resurrect a revoked
or expired execution.

### Added

**The external attestation journal (`firewall/external_attestation.py`,
`firewall/external_attestation_store.py`).** A fourth journal beside the
lease, side-effect and verification journals, holding one immutable row per
claim -- keyed by the digest of effect, attempt, envelope, issuer, key and
verdict -- plus the `(issuer_id, nonce)` replay ledger that makes a signed
statement evidence exactly once. Persistence is opt-in through
`attestation_store_path=` (or a caller-supplied journal), sharing the
configured effect/verification/execution store file otherwise so one restart
recovers all four journals from one database.

**Envelope verification.** `AttestationEnvelope` (a signed block, with the
signature over all of it), `build_attestation()` for the issuer's side,
`verify_envelope_signature()`, `canonical_external_state_digest()`,
`freshness_failure()` (one definition of freshness, used by the presentation
check and by the completion gate) and `ExternalIssuerTrustStore` -- the
operator's trust decision, with monotone registration: a revoked
`(issuer_id, key_id)` cannot be re-registered and a live one cannot be
silently replaced.

**SDK surface.** `trust_external_issuer` / `revoke_external_issuer_key` /
`revoke_external_issuer` / `external_issuer_records`,
`record_attestation`, `attestation_records`, `nonce_claims`, the read-only
`require_external_attestation` property, `attestor=` on `run_effect` (asked
after the receipt, since only then is there an effect to ask about), and the
construction arguments `attestation_journal=`, `attestation_store_path=`,
`external_issuer_trust_store=`, `external_issuer_keys=`,
`require_external_attestation=`, `attestation_max_age_seconds=` and
`attestation_clock_skew_seconds=`.

**Contradiction detection.** An attestation that disagrees with the row's
conclusive observation, or with an earlier conclusive attestation, is
recorded `CONTRADICTED` beside what was already there and blocks completion;
a conclusive attestation over a recorded `UNKNOWN` is a *resolution* and is
accepted, because `UNKNOWN` asserts nothing about what happened. A
contradiction is never resolved away -- every later conclusive statement
disagrees with one of the two, so it stands until an operator reconciles the
record.

**Invariant #22: `EXTERNAL_STATE_ATTESTATION_SOUNDNESS`.** Four source
censuses (journal writers, issuer trust writers, claim starters, and the
negative that no ALLOW-path function references attestation state), record
hygiene for every stored claim, and cross-journal soundness against the
effect row, the receipt's correlation handle, the nonce ledger and the
completion gate. The canonical estate now walks one effect through
prepare -> attempt -> receipt -> verification -> attestation -> commit, so
`python -m firewall.invariants --exercise --strict` gates all twenty-two
invariants. Adversarial coverage lives in
`tests/test_v3_1_external_attestation.py` (89 tests: forged, stale,
replayed, mismatched, contradictory, missing and tampered attestations, plus
the invariant's teeth for each).

### Changed

- `commit_effect` gained `attestation=`, `attestation_required=` and
  `attestation_note=`; `run_effect` gained `attestor=` and
  `attestation_required=`. Both are opt-in: a caller that never presents an
  envelope and never asks for one sees exactly the v3.0 behaviour.
- A completion that requires attestation journals its refusal with the
  reason, so "the deployment required external evidence and did not get a
  current one" is a row an operator can read rather than an absence to
  infer.
- An unreadable attestation clock is named as such
  (`attestation_clock_unavailable`) rather than reported as a journal
  failure.

### Documentation and packaging

- `docs/v3.1-external-attestation.md` (security model, threat boundary, API,
  crash/recovery table, refusal vocabulary, adversarial coverage,
  non-goals) and `docs/v3.1-performance.md` (directional numbers).
- Updated `CHANGELOG.md`, `README.md`, `SECURITY.md` and `pyproject.toml` to
  3.1.0; the invariant census (`tests/test_v2_2_invariants.py`,
  `tests/test_v2_3_invariant_gate.py`) and the CI gate
  (`.github/workflows/security.yml`) now count twenty-two invariants.
- New `attestation` benchmark group (`attestation_record`,
  `attestation_commit`, `attestation_unattested_commit`,
  `attestation_forged_record`).

## [3.0.0]

v2.6 proved that an allow is refused when a *widening write* completes
between its reads. v3.0 extends the proof from writes to the *state*
those writes produce:

```text
An authorization decision must never rely on a security state the
firewall cannot prove is coherent.
```

The epoch counter counts writes; it does not count state. A revocation
record removed by hand, a lineage edge written around `register`, an
issuer silently re-trusted after `revoke_issuer`, a store file rolled
back between restarts, a crash between a state write and its commitment
-- none of these moves the epoch, and all of them leave the live state
different from the state the firewall believes it is in. v3.0 closes
that class: every legitimate write to the canonical in-domain stores
(revocation, issuer trust, delegation lineage, the delegation-depth
ceiling) opens a `record_state_commit` interval that ends in a
hash-chained, state-anchored commitment of the whole canonical digest,
and the ALLOW path refuses (`state_incoherent`) whenever the live digest
diverges from the chain head. The design and the honest non-guarantees
are in
[docs/v3.0-security-state-integrity.md](docs/v3.0-security-state-integrity.md);
the measurements are in [docs/v3.0-performance.md](docs/v3.0-performance.md).

No second authorization system was built. The new layer constructs no
`AuthorizationResult`, and -- exactly like the epoch -- its only effect
on the boundary is to turn an allow into a denial: a forged, frozen or
missing journal cannot manufacture authority, only fail to catch a
drift.

### Added

**The state-commitment journal (`firewall/state_commit.py`,
`firewall/state_commit_store.py`).** An append-only, hash-chained record
of the canonical security state. Each link records the whole-state
digest after a mutation, the per-component digests it derives from, and
the epoch sample at commit time (forensics only). The chain is
genesis-anchored, every record chains to its predecessor, and every
state digest must re-derive from its recorded components -- an edited or
deleted record breaks the chain and attests nothing. Always present in
memory; persistence is opt-in through `state_commit_store_path=` (or a
caller-supplied store), which should live in a different file from the
stores it attests.

**Write-side bracketing of the in-domain stores.** `RevocationRegistry.
revoke`, `IssuerTrustStore.trust`/`revoke`, `DelegationLineage.register`/
`clear` and the SDK's `max_delegation_depth` setter now open a
`record_state_commit` interval that commits the resulting state on exit
-- the write-side sibling of the epoch's `record_widening`, and counted
in the same census style in `STATE_COMMIT_WRITES`.

**The coherence gate on the ALLOW path.** Immediately before an allow is
emitted, the terminal transaction gate verifies the live canonical
digest of the four in-domain stores against the chain head under one
journal lock (no TOCTOU between the security stores). A drifted store, a
broken chain or an unreadable component aborts the semantic transaction
and refuses with `state_incoherent:*`. `FirewallSDK.authorize()` remains
the only ALLOW path.

**SDK surface.** `state_commit_store=` / `state_commit_store_path=`
construction, `state_commit_records()` (read-only accessor), and the
`state_commit` journal wired to the revocation registry, issuer trust
store and delegation lineage at construction.

**Invariant #21: `SECURITY_STATE_COHERENCE`.** Two halves plus a live
verification: a source census over `STATE_COMMIT_WRITES` (checked in
both directions -- a declared write without a commitment bracket is a
violation, and a bracket outside the census is one too), a live check
that every in-domain store the SDK wires is bound to the journal, that
the chain verifies and is genesis-anchored, and that the live canonical
digest equals the chain head. The canonical estate exercises the new
layer through its ordinary use (issue, delegate, revoke, trust, depth
change), so `python -m firewall.invariants --exercise --strict` gates
all twenty-one invariants. Adversarial coverage lives in
`tests/test_v3_0_state_coherence.py`, including the durable crash and
store-file-rollback attacks the epoch cannot see.

### Changed

- `RevocationRegistry.revoke`, `IssuerTrustStore.trust`/`revoke`,
  `DelegationLineage.register`/`clear` and `max_delegation_depth` now
  commit state when the store is bound to a journal; standalone
  (unbound) stores remain honest pass-throughs, matching the epoch's
  `record_widening` semantics.
- Every ALLOW now ends with the coherence verification; a store that was
  silently mutated, rolled back, or left torn by a crash produces
  `state_incoherent:*` denials where the pre-v3.0 boundary would have
  allowed on the drifted state.

### Documentation and packaging

- `docs/v3.0-security-state-integrity.md` (design, the in-domain census,
  the chain, honest non-guarantees) and `docs/v3.0-performance.md`
  (directional numbers).
- Updated `CHANGELOG.md`, `README.md` and `pyproject.toml` to 3.0.0; the
  invariant census (`tests/test_v2_2_invariants.py`,
  `tests/test_v2_3_invariant_gate.py`) and the CI gate
  (`.github/workflows/security.yml`) now count twenty-one invariants.
- New `state` benchmark group (`state_commit_authorize`,
  `state_commit_transition`, `state_commit_tamper`).

## [2.9.0]

v2.8 recorded what happened. v2.9 establishes whether the recorded claim
can be trusted, and draws the separator its predecessor could not:

```text
AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED =/= COMPLETED
```

A verified stage sits between the observed receipt and the completed
execution: the recorded observation is independently checked, the verdict
is journaled in a third journal beside the lease and side-effect
journals, and a clean `COMPLETED` over an adopted side effect now
requires a current `VERIFIED` claim whose evidence has no recorded
contradiction. Verification is bound to the exact effect, attempt and
evidence snapshot; it can neither grant authority nor resurrect a
revoked or expired execution; and `FirewallSDK.authorize()` remains the
only authorization path. The design and the honest non-guarantees are in
[docs/v2.9-effect-verification.md](docs/v2.9-effect-verification.md);
the measurements are in
[docs/v2.9-performance.md](docs/v2.9-performance.md).

The property under test is one sentence: **a recorded side-effect claim
must be verified before the execution that adopted it may be recorded
COMPLETED, and no verification claim may lie about what it speaks about,
who produced it, or the authority it was recorded under.** No second
authorization system was built, and every new check is deny-only.

### Added

**The verification journal (`firewall/effect_verification.py`,
`firewall/verification_store.py`).** A third journal, one immutable row
per claim, where a claim's natural id is the digest of its whole binding
(effect id, attempt id, evidence-snapshot digest, verdict, method). A
record whose stored fields do not re-derive to its own id is refused and
flagged by the invariant. Contradictory evidence is preserved, never
resolved by rewriting; re-recording the identical claim is idempotent.
An optional SQLite backend shares the configured execution/effect store
file, so a restart recovers all three journals from one database.

**The structural verifier and the verdict vocabulary.** `VerifierVerdict`
(`VERIFIED` / `NOT_VERIFIED` / `CONTRADICTED`) and the built-in
`structural_verifier`, which confirms only internal soundness: a claim
correctly bound and observed under currently valid authority. It never
confirms provider-labelled evidence - a label is not proof - and only a
deployment-wired, explicitly named authenticator may. `VERIFIED` is only
recorded while the execution's authority basis holds; a verifier's
`VERIFIED` verdict after revocation or expiry is preserved truthfully as
`NOT_VERIFIED` and the lease is burned, never resurrected.

**SDK surface.** `verify_effect(...)` (the independent check),
`verification_records()`, `verification_store=` /
`verification_store_path=` construction, and verifier/method passthrough
on `commit_effect(...)` and `run_effect(...)`, which now sequence
reserve -> start -> prepare -> attempt -> handler -> receipt -> verify ->
commit. The completion gate refuses a clean `COMPLETED` over an adopted
side effect unless the latest claim on its current evidence is
`VERIFIED` with no recorded contradiction; `CONTRADICTED` evidence
poisons completion until the evidence itself changes. Structural
verification is the default for handler/caller observations; provider
evidence needs a named authenticating verifier.

**Invariant #20: `EFFECT_VERIFICATION_SOUNDNESS`.** Three halves: a
source census over who may drive the verification journal and who may
start a verification claim, record hygiene (id re-derivation, snapshot
consistency, authority and method discipline), and live cross-journal
soundness (every claim names a real effect and attempt; no COMPLETED
execution over an adopted side effect lacks a current VERIFIED claim
with no contradiction). The canonical estate now walks one side effect
through receipt -> verification -> commit, so `python -m
firewall.invariants --exercise --strict` gates all twenty invariants.
Adversarial coverage lives in `tests/test_v2_9_effect_verification.py`.

### Changed

- `commit_effect` / `run_effect` now verify before completing; the v2.8
  positive controls in `tests/test_v2_8_*.py` were updated to the strict
  verified chain (named authenticators where the receipt is
  provider-labelled), and a succeeded receipt alone no longer closes the
  lease (`effect_unverified:*` refusals leave the lease recoverable).
- The side-effect commit benchmark measures the verified chain; the
  `verification` benchmark group measures the verification stage and the
  fail-closed refusal path.

### Documentation and packaging

- `docs/v2.9-effect-verification.md` (design, strict chain, honest
  non-guarantees) and `docs/v2.9-performance.md` (directional numbers).
- Updated `CHANGELOG.md`, `README.md` and `pyproject.toml` to 2.9.0; the
  invariant census (`tests/test_v2_2_invariants.py`,
  `tests/test_v2_3_invariant_gate.py`) and the CI gate
  (`.github/workflows/security.yml`) now count twenty invariants.


## [2.8.0]

v2.7 closed the gap between ALLOW and the action with an execution lease
and documented exactly where its guarantee stops: between the `STARTED`
transition and the moment the handler's effect lands in the world there
is a window no in-process record can close, because the firewall does
not own the external system. v2.8 does not pretend to close that window.
It makes the boundary **explicit, attestable, idempotent and
recoverable**, so that Agent Firewall's own representation of an
external side effect never claims more certainty, authority or
completion than the protocol actually established. The design, the crash
matrix and the honest non-guarantees are in
[docs/v2.8-side-effect-commit.md](docs/v2.8-side-effect-commit.md); the
measurements are in [docs/v2.8-performance.md](docs/v2.8-performance.md).

The property under test is one sentence: **a side effect must never be
represented as successfully completed unless the firewall can establish
what execution authority existed, what side-effect attempt occurred, and
what completion evidence was observed.** No second authorization system
was built. `FirewallSDK.authorize()` remains the only allow origin
(`AUTHORIZATION_UNIQUENESS` still pins it), every new check is deny-only,
and the whole protocol is an **opt-in** extension of the v2.7 execution
lease: existing v2.7 callers are untouched and keep exactly the v2.7
guarantees (and v2.7 non-guarantees).

### Added

**The side-effect journal (`firewall/effect.py`,
`firewall/effect_store.py`).** A second journal beside the lease journal,
one external side effect per execution lease, with its own five-phase
state machine: `INTENT_RECORDED -> ATTEMPT_STARTED -> SUCCEEDED / FAILED /
UNKNOWN`. The durable intent (outbox) row exists *before* any external
request can be authorized; the attempt is one atomic compare-and-set with
an attempt identifier; confirmed outcomes are irreversible; and `UNKNOWN`
is the explicit three-way outcome that is neither success nor failure and
is never auto-retried -- a timeout after transmission can only be
reconciled by an explicit, evidence-carrying `reconcile_effect`. The
payload is bound by canonical digest, not duplicated. A SQLite backend
(`SQLiteEffectJournal`) shares the execution store's file when one is
configured, so a restart recovers both journals from one database.

**SDK surface (additive, opt-in).** `prepare_effect`, `attempt_effect`,
`record_effect_receipt`, `reconcile_effect`, `commit_effect`,
`run_effect` (one-call form), `expire_lapsed_effects`,
`side_effect_records`. Construction takes `effect_journal=` or
`effect_store_path=`. Every method returns a verdict-shaped result
(`EffectResult` / `ExecutionLeaseOutcome`), never an exception, and every
journal progression re-establishes the execution's authority basis
against live state first -- the same deny-only continuity validation v2.7
runs on the lease.

**Receipts as observations.** A receipt is bound to the execution, the
intent, the effect digest, the idempotency key and the attempt; it
carries an observed three-way outcome, an evidence kind
(`caller_assertion` / `handler_observation` / `provider_evidence`), and
any external request/transaction id as correlation evidence. `receipt !=
proof`; a receipt never grants anything, and an observation that arrives
after authority was lost is recorded truthfully with
`receipt_authority_valid=False` and the execution burned to its terminal
failure -- history is never rewritten because authority changed.

**First-class idempotency.** One lease carries one side-effect row keyed
by its idempotency key. Same lease + same effect + same key repeated many
times returns the same row and never authorizes a second attempt; same
lease + different effect or key is `effect_mismatch`; a different lease
cannot claim a live execution identity; and the same effect on a fresh
execution is a legitimate fresh side effect. Retry storms (timeout ->
retry -> timeout -> retry -> receipt) produce exactly one internally-
authorized attempt.

**`SIDE_EFFECT_COMMIT_INTEGRITY`, the nineteenth registered invariant.**
It checks the side-effect state-machine algebra, a source census in both
directions over who may drive the journal (a future `external_execute`
that writes the journal outside the protocol fails the gate), and the
hygiene of every recorded row crossed against the lease journal: a
replayed receipt cannot produce a second completion, `UNKNOWN` is never
recorded as success, an effect cannot change after authorization, and a
`COMPLETED` execution that adopted the protocol carries the required
completion evidence. `python -m firewall.invariants --exercise --strict`
now reports `19 invariants: 19 holds, 0 violated, 0 unverifiable`; the
canonical estate walks one side effect through prepare -> attempt ->
receipt -> commit alongside the existing executions.

**Eight v2.8 test files**, each class carrying a calibration so a green
run cannot mean "everything was refused":

- `tests/test_v2_8_side_effect_intent.py` (11) -- the durable outbox row,
  its bindings, digest-not-payload, modified-effect refusal.
- `tests/test_v2_8_idempotency.py` (9) -- retry semantics, the legal
  combinations table, the timeout-retry-reconcile storm.
- `tests/test_v2_8_receipts.py` (13) -- receipts as observation,
  evidence kinds, authority changes during effect processing.
- `tests/test_v2_8_uncertain_outcomes.py` (9) -- UNKNOWN != SUCCESS and
  UNKNOWN != FAILURE, reconciliation as the only way out.
- `tests/test_v2_8_recovery.py` (7) -- crash/restart recovery, intent
  lapse vs attempted-row non-lapse, no automatic retry.
- `tests/test_v2_8_concurrency.py` (6) -- one row / one attempt / one
  resolution under thread storms, two SDK instances over one file.
- `tests/test_v2_8_commit_integrity.py` (10) -- the invariant's teeth.
- `tests/test_v2_8_crash_matrix.py` (28) -- the deterministic crash
  matrix and the 21-attack campaign with documented expected results.

**Seven side-effect benchmarks** (`python -m firewall.benchmarks
side_effect`): `effect_authorize`, `effect_lease`, `effect_intent`,
`effect_attempt`, `effect_receipt`, `effect_commit`,
`effect_reconcile` -- the same boundary with one more protection layer
attached each time, plus the recovery path. Directional median results on
a development machine: authorize ~4.3k ops/s, +lease ~3.2k, +intent
~1.0k, +attempt ~750, +receipt ~650, +commit ~580, and the
recovery/reconcile path ~600. The full protocol costs roughly an order of
magnitude below a bare authorize despite containing ~seven continuity
checks, because the signature verification dominates and each added step
is a small read plus one CAS; the recovery number is published rather
than smoothed over.

### Security corrections

- **A prepared side effect can no longer be silently completed.** Once a
  lease carries a durable intent row, the plain v2.7 `complete_execution`
  on that lease is refused with `effect_unresolved:<state>` until the
  effect is resolved by a receipt or reconciliation. The refusal leaves
  the lease in place for recovery; it never guesses.
- **A modified effect never executes under a recorded intent.** An
  attempt, receipt or commit presenting a different effect, effect type
  or idempotency key than the prepared row is `effect_mismatch`.
- **A timeout after transmission is never recorded as success or
  failure.** The three-way `UNKNOWN` is the explicit representation of
  external uncertainty; only an explicit `reconcile_effect` may resolve
  it, and an automatic retry of an unknown side effect is refused (it
  could duplicate a real-world action).
- **A replayed receipt cannot produce a second completion** -- confirmed
  outcomes are irreversible at the state machine and the invariant checks
  every recorded history for a second terminal entry.
- **Receipts arriving after authority loss are recorded truthfully with
  `receipt_authority_valid=False`**, the lease is burned with
  `executed=True`, and no clean completion follows. Revocation, policy
  change, epoch movement, Aegis suspension and risk revocation between
  attempt and receipt each take this path.

### Non-guarantees (stated, not hidden)

The external world is still not transactional. If the external system
processed the request and the firewall only ever saw a timeout, the
effect is `UNKNOWN` until an external-status query or an operator
reconciles it. Internal deduplication cannot un-send an already-sent
external request, and an external system without its own idempotency key
can still receive duplicates from two different executions of the same
logical effect. `provider_evidence` is a label an integration earns by
actually authenticating the provider's response; Agent Firewall does not
verify external systems.

Sections of the v2.8 scope not listed here are not implemented.


All notable changes to Agent Firewall are documented here.

## [2.7.0]

v2.6 proved that concurrent authority changes cannot widen an
authorization decision, and said plainly where the guarantee stops: the
moment `authorize()` returns and the caller begins acting. v2.7 attacks
that remaining boundary -- the gap between ALLOW and the side effect. The
design, the race definitions and the honest non-guarantees are in
[docs/v2.7-execution-lease.md](docs/v2.7-execution-lease.md); the
measurements are in [docs/v2.7-performance.md](docs/v2.7-performance.md).

The property under test is one sentence: **execution must never occur
under authority that the execution context cannot still establish.** No
second authorization system was built. `FirewallSDK.authorize()` remains
the only allow origin (`AUTHORIZATION_UNIQUENESS` still pins it), every
new check is deny-only, and `authorize_execution` is a thin wrapper that
calls `authorize()` first and records a lease only for an allow. Existing
`authorize()` callers are untouched.

### Added

**Execution leases (`firewall/execution_lease.py`,
`firewall/execution_store.py`).** A lease is the recorded continuation of
one authorization decision, bound to the capability fingerprint, agent,
action, canonical request digest, the full delegation chain, the policy
version and the authority-epoch sample the decision was taken under. The
object a caller carries is a reference; the store record is the authority
on lease state, and a forged, copied, edited or stale object is refused.

**An explicit, atomic execution lifecycle.** `AUTHORIZED -> LEASE_ISSUED
-> RESERVED -> STARTED -> COMPLETED`, plus explicit terminal failures
(`DENIED`, `EXPIRED`, `REVOKED`, `ABORTED`). Every transition is a
compare-and-set, so the same lease cannot be reserved twice, a second
lease cannot claim a live `execution_id`, and the forbidden
resurrections (`COMPLETED/REVOKED/EXPIRED -> STARTED`) are unrepresentable
even for a caller holding the store. A SQLite backend
(`SQLiteExecutionLeaseStore`) turns the CAS into one `UPDATE`, so
exactly-once survives across processes and the record survives a restart.

**SDK surface.** `authorize_execution`, `reserve_execution`,
`start_execution`, `complete_execution`, `abort_execution` (accepts a raw
lease id for post-crash recovery), `run_execution` (the one-call form),
`execution_lease_records`, `expire_lapsed_executions`. Every method
returns an `ExecutionLeaseOutcome` (`allowed`, `reason`, `state`,
`lease`): verdict-shaped, never an exception, so a caller's `except
Exception` is never what decides what happened to an execution.
Construction takes `execution_lease_store=` or `execution_store_path=`.

**Continuity validation.** Each progression re-establishes the authority
basis against live state before it advances: issuer trust, signature,
revocation including ancestors, lease and capability time windows, the
delegation chain, the policy version, the authority epoch, Aegis
restrictions and risk state. Unreadable state is a refusal that names it
(`revocation_state_unavailable:`, `clock_unavailable:`, ...), never a
pass. A clean `COMPLETED` is written only when the basis held at the
moment of completion; an execution that loses its authority mid-flight
stops in an explicit terminal state with `executed=True` so the record
says the action may have run.

**`EXECUTION_AUTHORITY_CONTINUITY`, the eighteenth registered invariant.**
It checks the state-machine algebra, a source census in both directions
over who may drive the lease store (a new execution path that bypasses
validation fails the gate), and the hygiene of every recorded execution.
`python -m firewall.invariants --exercise --strict` now reports
`18 invariants: 18 holds, 0 violated, 0 unverifiable`; the estate walks
one execution to a clean `COMPLETED`, one through `STARTED` into a
post-revocation `REVOKED` with `executed=True`, and one aborted before
anything ran.

**84 v2.7 tests across six files**, each class carrying a calibration so a
green run cannot mean "everything was refused":

- `tests/test_v2_7_execution_lease.py` (28) -- what a lease binds, that
  the object is never trusted, serialization-is-not-trust, store algebra.
- `tests/test_v2_7_execution_replay.py` (11) -- single-use leases,
  request/identity/agent binding, one-winner reservation under contention,
  two SQLite instances over one file.
- `tests/test_v2_7_execution_concurrency.py` (8) -- revoke/narrow/suspend/
  epoch-change between every pair of phases, deterministic races, and the
  record-hygiene invariant audited after a load run.
- `tests/test_v2_7_execution_fail_closed.py` (18) -- unreadable stores,
  unwritable lease store, expired lease and capability, authority loss per
  attack, malformed/forged objects, no exception-to-verdict escapes.
- `tests/test_v2_7_execution_continuity.py` (10) -- the invariant's teeth.
- `tests/test_v2_7_execution_recovery.py` (9) -- crash between every pair
  of phases, restart audit, abort-by-id, and the documented non-guarantee
  that an external side effect is not rolled back.

**Five execution benchmarks** (`python -m firewall.benchmarks execution`):
`execution_authorize_only`, `execution_issue`, `execution_validate`,
`execution_reserve`, `execution_denied` -- the same boundary with one more
protection layer attached each time, so the deltas are the honest price of
keeping authority attached to the act. Directional median results on a
development machine: authorize alone ~3.8k ops/s, authorize+lease issue
~2.1-2.8k, +reservation ~1.5k, and the fail-closed refusal (fresh grant,
revoke, reserve) ~1.2k. The denial path is measured honestly per fresh
grant and is *slower* than the allow path; publishing the slow real number
is the point.

### Security corrections

- **An allow can no longer be used after the state that produced it stops
  holding.** Revocation, suspension, risk revocation, issuer untrusting,
  expiry, delegation-lineage loss, policy change and epoch movement
  between authorization and execution each turn the execution into a
  terminal, recorded refusal instead of a guess.
- **A lease that loses authority after STARTED can never be recorded as a
  clean COMPLETED.** It stops in `REVOKED`/`EXPIRED`/`DENIED` with
  `executed=True`. This is the release's core claim: once Agent Firewall
  authorizes an action, the action cannot escape the authority basis that
  authorized it without the firewall producing an explicit, auditable
  failure.
- **Request/capability/agent substitution is refused at every stage** by
  the lease's bound fields, compared against the presented capability and
  the authoritative record -- never against the carried object alone.
- **A forged, copied, modified or stale lease object is refused**, not
  merely ignored: edited binding fields return `lease_mismatch`, an unknown
  id returns `lease_unknown`, and a tampered `state` field changes nothing
  because the record's state is the authority.

### Non-guarantees (stated, not hidden)

The firewall cannot atomically control an external side effect. Between the
`STARTED` transition and the moment the handler's effect lands in the world
there is a window no in-process record can close; the firewall cannot roll
back an external API call it does not control. What v2.7 adds is that the
window is now an explicit, recorded instant, that authority lost *before*
it is caught, and that an interrupted execution can never be recorded as a
clean completion.

Sections of the v2.7 scope not listed here are not implemented.

## [2.6.0] - 2026-09-04

v2.5 attacked the boundary with hostile *input*. v2.6 attacks it with
hostile *timing* — the same well-formed request, against the same healthy
firewall, while the state the eleven gates read is changed underneath them.
The property under test is one sentence: **concurrency must never widen
authority.** The design, the ten self-attack passes and the load figures
are in [docs/v2.6-concurrency.md](docs/v2.6-concurrency.md).

The defect the release exists for is not a race in a store. Every store
synchronises its own reads. It is that an allow was never a statement about
one instant: `authorize()` performs eleven reads at eleven instants and the
verdict asserts something about all of them at once. That implication holds
only while state moves in one direction. A **widening** write landing
between two reads produces an allow describing a composite state that
existed at no single instant — not stale, not wrong about any individual
read, but non-linearizable. `_gate_cryptographic_authority` is gate 10, so
the widest part of that window is a signature verification, by
construction.

No subsystem was added, no configuration surface, and no second place a
request can be allowed. `FirewallSDK.authorize()` remains the only
authorization boundary and `firewall/authorization.py::authorize` remains
the only origin of an allow. Every correction below moves in one direction:
something that used to be allowed, or used to escape without a verdict, is
now a denial that names its cause.

Sections of the v2.6 scope not listed here are not implemented.

### Security corrections (breaking)

**A widening write is now an interval, not an instant.**
`firewall/authority_epoch.py` carries one counter, one in-flight count and
a source label. Every write that can widen authority is bracketed with
`with epoch.widening("<source>")`, which increments `in_flight` on entry
and `finished` on exit. The boundary samples at entry and at commit and
requires `finished` unchanged **and** `in_flight == 0` at both ends
(`EpochSample.covers`). Both halves are load-bearing: comparing `finished`
alone would miss a write that started before the request and had not
returned, where the counter is identical at both ends and the state changed
in the middle.

A window that is not covered is a **denial**, in one of three declared
forms (`EPOCH_DIVERGENCE_PREFIXES`, classified by `is_epoch_denial`):

- `widened_during_authorization:<source>:<n>` — `n` widening writes
  completed inside the request. The only form attributable to a finished
  write.
- `widening_in_flight_at_entry:<source>` — one was already running at
  entry.
- `widening_in_flight_at_commit:<source>` — one was still running at
  commit.

The gates are **not** re-run against the new state and the firewall does
not decide which state was "really" in force. It refuses to issue a verdict
whose premise it cannot establish — `unknown ≠ trusted`, applied to time.
Breaking for any caller that widens authority concurrently with live
traffic: those requests now receive a denial rather than an allow.

**Two boundary escapes, one of them on the shipped path with no
subclassing.** A sweep that sabotages one public method at a time on every
store the boundary reads, then asks whether a verdict still comes back,
found two places where an exception replaced the decision:

- `SemanticChainContext.begin_authorization` raising
  `SemanticBudgetExceeded` — the cumulative amount ceiling, on the bundled
  class. Now `semantic_budget_exceeded:`.
- `SecurityContext.authorize_and_record` raising `SecurityContextError` —
  reachable with shipped components only. It reloads persisted budget
  state from disk inside the terminal gate, so a truncated file, a failed
  integrity hash or an `OSError` on the atomic replace all raise.
  `SecurityBudgetExceeded` is a *subclass* of `SecurityContextError`, so
  the gate caught the one member of the family somebody had in mind and
  let the rest out. Now `security_state_unavailable:`, alongside
  `semantic_state_unavailable:` for the same failure on the semantic read.

**A rollback that raised took the denial with it.** `_gate_transaction`
opens a semantic transaction before it finishes deciding, so every denial
after that point must roll it back first. That rollback was an unguarded
call — and its callers are the `except` handlers whose entire purpose is to
stop an exception replacing a verdict. An `abort()` that raised defeated
them exactly where they were supposed to work: the gate caught the injected
failure, converted it into a denial, and lost the denial on the way out.
The transaction is not a store the SDK holds — it is constructed inside the
gate and handed straight back — so the sweep could not reach it and this
had to be found by reading the gate.

The rollback now goes through `_write_evidence` and a failure is attached
to the denial as `trace["rollback_error"]`. Its own key, not
`evidence_error`: a lost audit record and a reservation that would not roll
back call for different responses. The verdict is not re-decided — it is
already a refusal and there is no narrower answer available — but the
failure is not discarded either, because a reservation that did not roll
back is state the next request will be judged against.

**The revalidation reason now names the epoch dimension.** Continuous
revalidation compares a state snapshot; the epoch is part of that state, so
a widening that moved it is reported by name:
`authority_epoch: '0:0' -> '1:0'; policy_version: ...`. Breaking for anyone
matching that string exactly.

### Added

**`AUTHORITY_EPOCH_COVERAGE`, the seventeenth registered invariant.** It
reads the source tree and checks the `WIDENING_WRITES` census in **both**
directions: a function in the census with no epoch bracket is a violation,
and a bracket in a function *not* in the census is also a violation. The
second direction is the one that matters over time — without it, a later
change could add a widening path and satisfy the invariant by bracketing
it, and the sentence "these are all of them" would never be re-examined by
a human.

It also checks **identity**, not just presence: every epoch-bound store the
SDK holds must satisfy `epoch_of(store) is sdk.authority_epoch`. A store
rebound to a different epoch would leave the boundary sampling an epoch
nothing writes to, and the divergence check would be decoration that never
fires. `set_risk_context`, `set_security_context` and
`set_semantic_context` rebind rather than trust.

`python -m firewall.invariants --exercise --strict` now reports
`17 invariants: 17 holds, 0 violated, 0 unverifiable`. A source-only run
leaves eight unverifiable and says so.

**`WIDENING_WRITES`** — the twelve declared widening writes, with the
absences justified in place: `RevocationRegistry` has no un-revoke; the
lifecycle, replay and key stores only ever add used nonces, spent
capabilities and retired keys; `AegisController.register`/`grant` make
`tracked()` true, which subjects a fingerprint to *more* checks;
`configure_delegation_budget` raises a ceiling no gate reads, and
`authorize_with_delegation_budget` reserves after the whole chain has run,
so bracketing it would produce denials over a value the window never
covered.

**`EPOCH_MEASUREMENT_BRACKETS`** — a second census, because the
both-directions check flags *any* bracket outside `WIDENING_WRITES`,
including the two in `firewall/benchmarks.py` that drive the epoch
primitives to time them. Checked in both directions too, so it cannot rot
into a blind spot. To qualify, a function must construct the epoch it
brackets; bracketing an epoch some SDK also samples is a widening write no
matter what the function is named.

**306 tests across six files**, each class carrying a calibration so a
green run cannot mean "everything was refused":

- `tests/test_v2_6_concurrent_widening.py` (138) — the epoch, its three
  denial forms, and the census in both directions.
- `tests/test_v2_6_boundary_totality.py` (80) — the sabotage sweep, its
  vacuity check, and the rollback that raises.
- `tests/test_v2_6_mutator_census.py` (49) — store/epoch identity.
- `tests/test_v2_6_concurrency_never_widens.py` (18) — the load-only
  findings: exactly-once under contention, one adapter many threads, Aegis
  churn, epoch coverage under a swapped epoch.
- `tests/test_v2_6_revalidation_epoch.py` (12).
- `tests/test_v2_6_grant_state_not_enforcement.py` (9).

**`python -m firewall.benchmarks epoch`** — four benchmarks
(`authorize_epoch`, `epoch_primitives`, `epoch_contention`,
`authorize_under_widening`). Numbers and methodology in
[docs/v2.6-performance.md](docs/v2.6-performance.md). The epoch's cost is a
composed floor of **0.31 %–0.41 %** of an authorization on the measured
machine; `epoch_bound: true` asserts the measured path is the shipped,
protected one. The "same request without the epoch" comparison is
deliberately not implemented: the unprotected boundary is the defect, and
shipping a supported way to run it would put a second, weaker
authorization path in the package.

### Attacks that found nothing, recorded because they ran

Double spend across four ceilings × 16/32/64 threads — exactly *K* allows
for ceiling *K*, every time. Exactly-once replay in four shapes, including
two store objects over one file, where the guarantee belongs to
`nonces(replay_key TEXT PRIMARY KEY)` and not to the per-instance `RLock`.
One adapter under 16 threads — no execution over the ceiling, a budget of
five spent exactly five times, traffic stopped by a revocation landing
mid-flight. Timing overlap across four pacing regimes and 4,800 requests —
`samples == 2 × requests`, so no request decided on an unbracketed window.

**Forged Aegis evidence, 21,821 attempts under load.**
`observe_authorization` is the only way a grant moves toward `ACTIVE`, and
it takes a result object. Four forgeries were fed to it: a genuine allow
belonging to **another capability**, a genuine verdict that was a denial,
an object that is not a verdict, and an allow-shaped dict. The grant never
left `SUSPENDED` and not one of 640 authorizations was allowed. Evidence
did not become authority.

### Documented non-guarantees

**Check-then-act windows are inherent and are not closed.** The epoch
narrows the window *inside* `authorize()` to a bracketed interval and
refuses when that interval was not clean. It says nothing about the time
between the verdict returning and the caller acting on it. Closing that
would require holding authority open across the caller's work, which is a
different design.

**A failed rollback is contained, not undone.** `trace["rollback_error"]`
makes the failure visible on the denial. It does not make the reservation
disappear.

**The epoch's guarantee is conditional on the census being complete.** It
sees exactly what is bracketed — which is why the census is checked in both
directions and why that check is an invariant rather than a code comment.

**Under a continuous widener the behaviour is total refusal.**
`authorize_under_widening` reports `denied_fraction` 0.997–1.0 with
`other_denials == 0`: availability is spent, authority is not. That is the
intended trade and is stated plainly because an operator who resets a
context in a loop will see it. It is not a blanket refusal — one run
allowed 1 of 320, on a genuinely covered window — but it is not a
throughput figure either.

**The load figures are load figures.** 32 threads on one machine with one
GIL is not a distributed deployment. The probes establish that these shapes
did race (writer-cycle counts are reported so a reader can check the shape
was not idle) and that no allow appeared under them. They do not establish
an absence of races at other scales, on other schedulers, or across
processes except where a test says so.

## [2.5.0] - 2026-09-03

v2.5 adds no subsystem and no authorization path. The work was to attack
v2.4's shipped boundary until a guarantee broke, and twenty-two attacks are
recorded in [docs/v2.5-boundary.md](docs/v2.5-boundary.md) — each with the
entry point, a reproduction through the public API, the verdict before and
after, and the direction authority moved.

They divide into four groups. Twelve were places where
`FirewallSDK.authorize()`, or the envelope projection beside it, **raised
instead of deciding** — nine of them on a read of the boundary's *own* state,
which is why the invariant that forbids exactly this held green for three
releases: all eight of its probes were hostile caller input against a healthy
firewall. Five were in the glue between a caller and the boundary, where the
boundary was asked one question and the handler then acted on another. Three
were in the monitoring surface, which reported an authority the boundary was
concurrently denying. One was a defect in a *check*: the invariant that
forbids a second authorization path could not have seen one.

The single allow origin is unchanged and is now pinned by name —
`firewall/authorization.py::authorize`, reached through the one gate
permitted to return an allow. Nothing in this release adds a second one, and
one correction was rejected outright for being one; see *Documented
non-guarantees*.

Sections of the v2.5 scope that are not listed here are not implemented.

### Security corrections (breaking)

Twelve paths where the boundary raised in place of a verdict — nine of them
reads of its own state, three malformed arguments that escaped before any gate
ran. Each is now a denial that names what could not be read. Breaking in one
direction only: a caller who wrapped `authorize()` in `except Exception` and
treated the exception as a refusal now receives that refusal as a verdict it
can log, and a caller who treated it as anything else was authorizing on an
exception.

- **Expiry is no longer skipped when time cannot be established.** This is
  the most serious defect in the release, and no injected hostility was
  needed to reach it: a `CapabilityVerifier` constructed without a `clock` is
  a legitimate configuration — signature verification only, expiry left to
  the firewall's time gate — and `_gate_time` responded to an unreadable
  clock by not checking the window at all. An **expired capability returned
  `authorized`**. A clock that raises, and a clock that returns `nan`, took
  the same path. All four causes are now a denial:
  `clock_unavailable:{no_clock,RuntimeError,ValueError,non_finite}`.
  `CapabilityVerifier` always carries a clock now, so the default
  configuration cannot construct the case.
- **Five of the boundary's own state reads are denials rather than
  exceptions.** Refusal state, risk state, issuer trust, revocation and
  delegation lineage each answered a question the gate chain asks on every
  authorization, and each propagated whatever the store raised:
  `refusal_state_unavailable:{Type}`, `risk_state_unavailable:{Type}`,
  `issuer_trust_unavailable:{Type}`, `revocation_state_unavailable:{Type}`,
  `delegation_chain_unavailable:{Type}`. The bundled
  `SQLiteRevocationStore` behind a closed connection reaches the revocation
  one for real, which is what makes this a defect in the shipped system and
  not only in an injected one.
- **A denial survives the loss of its own evidence.** An unwritable
  lifecycle log, a closed `SQLiteLifecycleStore` or an unwritable audit file
  replaced the *denial* with an `OSError` — the one verdict that must never
  be lost, destroyed by the attempt to record it. The verdict is now
  preserved and the loss travels with it in `trace["evidence_error"]`. On the
  allow path the same failure is `evidence_unavailable:{Type}`: an allow that
  cannot be recorded is withheld, a denial that cannot be recorded is still a
  denial.
- **Malformed arguments are verdicts.** A request whose `__deepcopy__`
  raises, a capability that cannot be fingerprinted, and a capability whose
  `expires_at` is not a number now return `invalid_request:{Type}`,
  `invalid_capability:{Type}` and `capability_time_invalid:{Type}` rather
  than raising before any gate runs.
- **`authority_envelope` returns the bottom envelope rather than raising.**
  The projection documented as yielding bottom on an unresolvable chain
  raised instead when `revocation.is_revoked`, `issuer_trust_store.is_trusted`
  or `delegation_lineage.chain` did, and again on a capability it could not
  fingerprint. Both now yield bottom with `envelope_unavailable:{Type}`.

### One validity window, one time base (breaking)

Stated separately because it is the one correction in the release that is not
purely narrowing. A capability's window was closed with `time.time()` at
issue and opened with the verifier's injected `clock` at authorization, so
any skew between the two displaced the honoured window: a freshly issued
capability was `not_yet_valid` under a clock behind wall time, and the same
skew added a tail past the declared expiry. `issued_at` is now stamped from
the boundary's clock, so one window is measured in one time base.

Under the default configuration this changes nothing at all —
`CapabilityVerifier.clock` *is* `time.time`. Under an injected clock it
removes a false denial (a new allow) in one direction and a late-expiry tail
in the other. Calling that "narrower" would be inaccurate, so it is not
called that.

### Integration corrections (breaking)

Five defects on the surfaces between a caller and the boundary. They share a
root cause worth naming: **the boundary was never bypassed and never wrong.**
It was asked a different question from the one the glue then acted on.

- **A tool call is normalized once, and both halves share the object.**
  `OpenAITool`, `AnthropicTool` and `GenericToolAdapter` each authorized one
  payload and executed another under three different mechanisms — a
  non-idempotent `normalize` given a nested `{"arguments": {...}}` payload, a
  caller mapping whose `get` answered differently on the second read, and a
  hostile `Mapping` re-materialized for the handler after the boundary had
  seen it. In all three the boundary allowed `{"amount": 10}` and the handler
  ran `amount=5000`. The fix is structural rather than defensive: normalize or
  settle once, then hand the *same object* to the boundary and to the handler,
  so there is no second read to disagree with the first.
- **A `request_builder` receives a copy.** Recorded as a regression of the
  fix above rather than a fourth inherited defect. Shipped v2.4 was safe here
  by accident — `execute` and `authorize` each ran their own `normalize`, so a
  mutating builder mutated a copy nobody else held — and collapsing that to
  one normalization handed the builder the very mapping the handler would
  unpack. Found by attacking the fix, closed before shipping, and verified in
  both directions: rebound onto the shipped v2.4 bodies, the mutating builder
  does not reproduce.
- **An unreadable replay store cannot be skipped.** `HTTPFirewall.authorize`
  let a raising `sdk.replay.check_and_consume` escape a method typed
  `-> HTTPDecision`, *after* the boundary had allowed — so a caller's
  `except Exception` skipped not the authorization but the one check that
  block exists to perform. Now `503`, `replay protection error: RuntimeError`.
  `MCPFirewall` already contained the same read, which is what made this a
  divergence between two surfaces rather than a uniform limitation.

Three divergences between MCP and HTTP were re-examined and **kept**, all
measured rather than read off the source: MCP consumes a nonce before
`authorize()` and HTTP after, MCP latches a refusal against the action where
HTTP latches it against the request, and the two refusal shapes stay
distinct. The operator-visible consequence is that "denied" does not mean the
same thing on the two surfaces — after a `constraint_denied`, MCP has spent
the nonce and latched the action, HTTP has spent neither — so a replay or
denial counter read across both is not reading one quantity. Both directions
fail closed, neither creates authority, and unifying either would change
behaviour callers depend on for no security gain. §*Divergences left in
place, and why* of [docs/v2.5-boundary.md](docs/v2.5-boundary.md) has the
table and the reproduction.

### Monitoring corrections (breaking)

Three attacks in which the *monitoring surface* reported an authority
`FirewallSDK.authorize()` was concurrently denying. None of them is a
boundary failure — no enforcement path consumes `revalidated_allowed` as
permission, and the boundary denied throughout — but the surface whose only
job is to notice that authority was withdrawn did not notice.

All three have one shape: `SecurityContextSnapshot` did not cover two of the
things the gate chain reads, so `state_hash()` could not move when they
changed and `revalidate()` answered from the cached verdict.

- **A cached allow survived an Aegis restriction.** After
  `authorize_continuous(...)`, a `suspend()` or a `narrow()` on the grant left
  `revalidated_allowed=True`, `authority_revoked=False` and
  `state_changed=False` while `authorize()` denied `aegis_suspended` or
  `aegis_constraint_denied`. The snapshot now carries `aegis_restrictions`, a
  digest of every restriction binding the chain, built from
  `Restriction.identity()` so that re-applying an identical restriction leaves
  it alone while any change to a kind, key, pattern set or bound moves it —
  including a `lift()`, so a resume is revalidated canonically rather than
  reported from cache.
- **Aegis classified its own suspension as `KEEP`.** The same blindness on a
  second surface, and the one place where it had a visible effect on Aegis's
  behaviour rather than only on a reported `bool`: two snapshots straddling
  `AegisController.suspend` hashed alike, so `classify(ENVIRONMENT_CHANGED,
  ...)` returned the response documented as requiring five positive
  conditions. It now contributes `state_hash_changed` and classifies as
  `REVALIDATE`. Escalate-only by construction — `classify` is a lattice join,
  so an added contribution cannot lower a response.
- **A cached allow survived a latched refusal.** The cheapest reproduction in
  the release: no injected component, no hostile mapping, no race. One
  monitored allow at `{"amount": 10}`, then one ordinary over-ceiling
  `authorize()` at `{"amount": 10_000}` — which latches a refusal through
  `_apply_denial` — and `revalidate()` reported the cached allow with
  `no_material_state_change` while `authorize()` denied `refusal_state`. The
  snapshot now carries `refusal_state`. This one was found by writing down a
  coverage gap and testing the sentence rather than by an attack: the claim
  that latching "only ever subtracts" is true of `authorize()` and false of
  the cache.

Both probes are **state** probes, not second evaluations of a gate. Neither
asks whether the state refuses this request; each reports what state exists,
and a changed digest's only effect is to route revalidation into the path
that calls `authorize()`. They are deliberately coarser than the gates they
stand in for, and that coarseness has a measured price — see *Added*.

### Added

- **A sixteenth invariant, and three of the existing fifteen strengthened.**
  Added only where the attack campaign found a property no invariant covered;
  where one already covered it, the existing invariant was strengthened
  instead of a new entry added to raise the count.
  - `REVALIDATION_CONSISTENCY` — continuous revalidation never reports an
    authority the canonical boundary denies. Sampled over six security-state
    changes and explicitly one-directional: the engine may report a denial
    where the boundary allows, because it subtracts on unreadable state, but
    never the reverse. Each of the two snapshot fields the grid depends on has
    its own negative control, and blinding one does not cover the other —
    dropping `aegis_restrictions` violates on two probes, dropping
    `refusal_state` on a disjoint third.
  - `AUTHORIZATION_UNIQUENESS` now names the function. It forbade a verdict
    being *constructed* outside the two owner modules, which a new function
    inside `firewall/sdk.py` returning `AuthorizationResult(allowed=True, ...)`
    satisfied: with a second authorization path planted in the source tree,
    `python -m firewall.invariants` still printed `8 holds, 0 violated`. The
    check is now a census of all 50 construction sites in the package against
    a closed four-entry allow-list keyed by `(module, enclosing function)`,
    plus a single pinned allow origin
    (`firewall/authorization.py::authorize`) and the one gate permitted to
    return an allow (`_gate_transaction`). A module-level census would have
    waved through every site in `sdk.py`, which is 46 of the 50.
  - `FAIL_CLOSED` now covers unavailable state, not only malformed input. All
    eight of its v2.2 probes were hostile *input* against a healthy SDK, so it
    held green while five of the boundary's own dependency reads could turn a
    decision into an exception. Nine dependency-failure probes were added — 8
    probes to 17 — each with its own positive control, including the two
    evidence-sink probes checked together on opposite verdicts: losing the
    audit record of an allow withholds the allow, losing the audit record of a
    denial must not withhold the denial.
  - `ENVELOPE_SOUNDNESS` no longer swallows the case it was most exposed to.
    A bottom envelope excludes every request, so soundness — *what the
    envelope excludes, the boundary denies* — becomes a claim about every
    request against that grant, and before v2.5 the boundary raised on exactly
    the reads that produce a bottom envelope. The invariant absorbed that raise
    into its `unresolved` census and still reported `HOLDS`, which is
    `FAIL_CLOSED`'s original gap in a second invariant. Three
    unreadable-projection probes now require bottom *and* a denial, each
    proving on its own instance that a legitimate request allows before
    sabotaging it, and the invariant is `UNVERIFIABLE` if any of the three goes
    unexercised.
- **`firewall/benchmarks.py` gains the continuous-authorization path**, in a
  `boundary` group (`python -m firewall.benchmarks boundary`), reported in
  [docs/v2.5-performance.md](docs/v2.5-performance.md). It existed because
  two security fixes landed on a path nothing was measuring. The result
  inverts the intuitive worry: the two new probes cost about **4.5 µs of a
  ~70 µs snapshot**, roughly 0.4% of the authorization they accompany, so
  neither fix has a performance argument against it. The real cost is the
  deliberate coarseness — a revalidation whose digest moved costs ~1.2 ms
  against ~130 µs for one that did not, and the difference is almost exactly
  **one** plain `authorize()`. The v2.4 design note's phrase "costs a
  redundant canonical call" now has a number attached, and it is one
  authorization, not a multiple, and not growing with the number of
  restrictions or refusals latched.
- **192 tests**, taking the suite from 4,087 to **4,279** on Python 3.10, 3.11
  and 3.12. 189 are in six `tests/test_v2_5_*.py` files — the boundary
  totality sweep, the composition campaign, the integration-divergence sweep,
  the stale-revalidation reproductions, the verdict census, and the benchmark
  guards — and every attack row in
  [docs/v2.5-boundary.md](docs/v2.5-boundary.md) is pinned by one of them.
  The other three are in existing files: one self-attack test, and two that
  hold the CI gate's own description to the registry, because the strict
  step's name said `fifteen` for as long as there were sixteen invariants and
  nothing was checking it.
  Two existing v2.3 self-attack tests were **rewritten rather than deleted**:
  they pinned the old mechanism (an unreadable revocation or lineage store
  "yields no verdict at all") as a non-guarantee, and v2.5 turned it into a
  guarantee. The weaker claim that survives either mechanism was kept
  alongside the strictly stronger assertion that replaced it.
- **Two documents.** [docs/v2.5-boundary.md](docs/v2.5-boundary.md) is the
  attack report, the security boundary map, the race matrix, the invariant
  review with its coverage gaps stated, the API totality review, and the
  authority-flow audit. [docs/v2.5-performance.md](docs/v2.5-performance.md)
  is the measurement, including the machine, the methodology, and what the
  numbers do **not** establish.

### Documentation corrections

Four claims that were true of what they described and had been read more
broadly than they were checked. All were corrected in place, next to the
original sentence, rather than by silently rewriting it.

- `docs/v2.2-invariants.md` and `docs/v2.3-self-attack.md` both presented
  `FAIL_CLOSED` as "the authorization path never raises in place of deciding".
  Both now say what the check behind that sentence actually exercised in v2.2
  — malformed input against a healthy SDK — and point at the v2.5 work that
  made it true of unavailable state.
- `docs/v2.2-threat-model.md` gains three adversaries it did not name:
  the dependency saboteur, the evidence breaker, and the time-authority
  splitter. The **untrusted-input injector** row was narrowed to what it
  covered.
- `docs/v2.4-aegis-design.md` relied on `FAIL_CLOSED` for the whole boundary
  in a table of assumptions, and described the classifier's `KEEP` guard as
  requiring positive evidence. Both now carry the correction: `_gate_aegis`
  did hold up its own end, but five other reads did not, and an equal hash is
  positive evidence only to the extent the snapshot covers the state that
  matters.
- `README.md` and `SECURITY.md` had four hard-coded invariant counts, now
  sixteen. `docs/v2.4-aegis.md`'s `15 invariants` transcripts were
  deliberately left alone: a released document describing its own version is
  accurate, and editing it would make it wrong.

### Documented non-guarantees

Stated rather than left to be inferred. §*Coverage gaps, stated* and §*What
v2.5 deliberately did not do* of
[docs/v2.5-boundary.md](docs/v2.5-boundary.md) are the full list; these are
the ones most likely to be misread.

- **The snapshot is now known to be incomplete twice over.** Rows 15 and 22
  were the same defect on two of eleven gate inputs, and both were found by
  looking rather than by a check that could have named them. Nothing
  enumerates the gate inputs against the snapshot's fields, so a twelfth gate,
  or a new mutable store behind an existing one, would repeat it.
  `REVALIDATION_CONSISTENCY` catches the consequence on whatever probes its
  grid contains; it does not establish that the grid is complete, and two of
  its six probes exist because someone went looking.
- **A probe grid is as good as its last audit.** `REVALIDATION_CONSISTENCY`
  shipped with five probes and would have held indefinitely; the sixth was
  added because writing down what the invariant did *not* cover produced a
  reproduction. That is a property of the process, not of the registry.
- **The adapter single-read discipline is per-adapter, not structural.** Rows
  18–20 are fixed at three sites and nothing prevents a fourth adapter from
  reading its payload twice. No invariant can see it: the property is "these
  two reads are the same object", which is a fact about a call rather than
  about the source or the state.
- **`FAIL_CLOSED`'s new probes are not completeness over dependencies, and not
  concurrent failure.** Nine reads on one authorization each; a deployment
  whose stores fail together is not what was measured.
- **Mid-flight narrowing remains outside every invariant.** It is a race, and
  every invariant is sequential. The race matrix records the asymmetry rather
  than closing it.
- **Three invariants are one-directional by construction.**
  `ENVELOPE_SOUNDNESS`, `REVALIDATION_CONSISTENCY` and `MODEL_NON_AUTHORITY`
  each hold in the safe direction only. None is an equivalence.
- **The benchmark figures are one estate, not a deployment.** Depth 2, one
  action, one request shape, no concurrent load, no populated revocation
  registry, no restriction set of any size. `_probe_aegis` digests every
  restriction on the chain, so its cost grows with restrictions, and nothing
  measures that curve. The periodic monitor is switched off in every
  measurement, so what any of this costs per hour is a deployment property.

Four optimizations were identified and **deliberately not made**;
§*Optimizations deliberately not made* of
[docs/v2.5-performance.md](docs/v2.5-performance.md) has all four, including
the two that only cost microseconds. The two that would have reclaimed the
~1.1 ms are the ones worth stating here, and one of them is enforced by a
failing test rather than by this paragraph. Filtering
`_probe_refusal` to the action being revalidated would reclaim the whole
~1.1 ms, but `_capture_snapshot` never receives the caller's `refusal_scope`,
so the filter would be guessing — and a guess that is wrong in the permissive
direction misses a refusal the gate honours, which is the row 22 defect with a
performance justification attached.
`test_the_optimization_this_benchmark_forbids_is_detected` simulates it and
shows the benchmark reporting `no_material_state_change`, the original
defect's exact signature. Short-circuiting the canonical call when only the
refusal digest moved was rejected for a plainer reason: it is the engine
concluding that a refusal does not apply, which is an allow reached outside
`authorize()`.

## [2.4.0] - 2026-09-03

v2.4 adds **Aegis**, an adaptive authority control plane. A live grant can
now be narrowed, suspended, revalidated or revoked while a task is running,
in response to a classified change in the state that grant rested on.

It adds no second authorization path. Aegis holds state, computes bounds,
classifies changes and writes restrictions; it never returns an allow. It
reaches `FirewallSDK.authorize()` through exactly one deny-only gate and
learns what happened through exactly one callback that the SDK invokes
*after* the decision exists. Authority flows from the boundary into Aegis and
never the other way. See [docs/v2.4-aegis.md](docs/v2.4-aegis.md) for the
architecture, the guarantees, and the non-guarantees.

Sections of the v2.4 scope that are not listed here are not implemented.

### Security corrections (breaking)

All are narrowing, and all were found by attacking v2.3's shipped code
rather than by reviewing v2.4's design. One regression test per defect in
`tests/test_v2_4_aegis_corrections.py`; two architectural causes produced
all eight.

- **An unorderable bound no longer bounds nothing while reading as
  restrictive.** Numeric bounds are enforced by negation — `deny if actual >
  ceiling` — and every comparison against `nan` is `False`.
  `firewall/authorization.py::_check_constraints` now denies with
  `constraint_denied` when a numeric bound is `nan`, so a capability whose
  constraints read as `{"amount_max": nan}` admits nothing instead of
  everything. An **infinite** bound is ordered and genuinely means unbounded,
  so it still stands; only the unorderable one is refused. v2.3 closed this
  for the request *value* and left it open for the bound.
- **An unorderable delegation child is no longer accepted as narrower.**
  `firewall/delegation.py::_constraints_are_narrower` refuses a `nan` on
  either side. A child claiming `amount_max: nan` passed the ceiling test
  that both `inf` and `10**9` correctly failed, which left a signed
  delegated capability in circulation whose own stated ceiling bounded
  nothing.
- **A large integer returns a decision instead of raising out of the
  boundary.** `math.isfinite` converts its argument to a float before
  answering, so `math.isfinite(10**400)` raises `OverflowError` — and a
  400-digit integer arrives straight out of `json.loads`. The exception
  escaped `FirewallSDK.authorize()` entirely: no decision, no flight record,
  and a caller left to interpret an exception for itself. The finiteness
  question is now asked only of floats, since a Python `int` is always finite
  and always ordered. The same family of crash was fixed in
  `aegis/envelope.py` and in budget reservation.

- **Five documented totality promises are now implemented.** `_gate_aegis`,
  the commit-time re-read in `_gate_transaction`, `blast_radius`,
  `AegisController.grant` and `DecaySchedule.stage_at` each promised in their
  own docstrings to answer rather than raise, and each had at least one path
  that raised. This matters because the controller is injectable —
  `FirewallSDK(aegis=...)` accepts any object of the right shape — so "the
  bundled controller does not raise" was never the guarantee the callers were
  relying on. Both Aegis read sites now deny with
  `aegis_state_unavailable:{ExcType}` rather than propagating.

### One definition of "narrower" (breaking)

`firewall/attenuation.py` had its own numeric rule, `child <= parent`,
applied to every number regardless of the key's suffix. That was a second,
weaker definition of the same concept and it disagreed with
`_check_constraints` — the function that actually admits or refuses a request
— in three ways: a *lowered* `_min` floor is a widening and was accepted; a
bare unsuffixed numeric is compared for equality at the boundary, so
`amount: 100 -> 50` is a different grant rather than a narrowing; and
`True -> False` passed because `bool` subclasses `int` and `False <= True`
holds.

The boundary denied the resulting children in all three cases —
`_gate_delegation_monotonicity` uses the correct predicate, so the system
failed closed — but `can_attenuate` returned `True` for a widening,
`attenuate` minted capabilities that could never be used, and one legitimate
call drove live state into a **VIOLATED** `CAPABILITY_MONOTONICITY`.
`_constraints_attenuated` now delegates to
`firewall.delegation._constraints_are_narrower`, which is the predicate
`delegate` enforces and `firewall.continuous_auth.predicates` reuses. All
four now agree.

### Added

- **`firewall/aegis/`** — nine modules, 5,382 lines (5,591 with the package
  `__init__`). None of them imports `firewall.sdk`; the dependency direction
  is one-way and load-bearing, and `AegisController` is deliberately absent
  from `AUTHORIZATION_RESULT_OWNERS` so the invariant that polices who may
  construct an `AuthorizationResult` treats an Aegis module doing so as a
  violation.
  - **`state.py`** — a seven-state machine (`ISSUED`, `ACTIVE`,
    `REVALIDATING`, `NARROWED`, `SUSPENDED`, `REVOKED`, `EXPIRED`) ordered by
    *residual authority* rather than by lifecycle. A transition is legal only
    if it does not increase residual authority, with four qualifications:
    terminality is checked first, so nothing leaves `REVOKED` or `EXPIRED`;
    `EXPIRED` is latched rather than re-derived from a clock; and the one
    edge that does restore authority, `REVALIDATING -> ACTIVE`, requires an
    `AuthorizationResult` that is allowed, reasoned `"authorized"`, and
    traced to that capability's fingerprint.
  - **`envelope.py`** — the `AuthorityEnvelope`: twelve fields, every
    request-bounding dimension among them with a named enforcement site at
    the boundary, folded across the delegation chain by a per-dimension
    `meet`. `Envelope(c).excludes(a, r, t)` returning a reason implies
    `authorize(c, a, r)` denies at `t`. The converse is false by design and
    the API says so — `may_admit()` means "this envelope does not itself
    refuse", never "this will be allowed".

  - **`restriction.py`** — the only Aegis state the boundary reads, and
    reduce-only by construction: restrictions accumulate as conjuncts, there
    are two kinds (suspend, and narrow-to-a-constraint-bound), and the only
    widening operation is an explicit, keyed, operator-invoked `lift()`. A
    parent's restriction binds every descendant because the match is
    evaluated over every fingerprint in the chain. At
    `MAX_RESTRICTIONS_PER_GRANT` the next narrowing escalates to a single
    SUSPEND rather than being dropped.
  - **`response.py`** — fifteen triggers mapped onto
    `KEEP < REVALIDATE < NARROW < SUSPEND < REVOKE`, combined by lattice
    join, so the strongest applicable response wins and adding a trigger
    cannot weaken an outcome. An unrecognised trigger is `REVALIDATE` — not
    `KEEP`, which would make an unknown event benign, and not `REVOKE`, which
    would make any unknown string a denial-of-service lever. No trigger maps
    to `KEEP`; `KEEP` is reachable only through a guard that requires five
    positive conditions, so "nothing changed" must be established rather than
    assumed. A mapping-totality check runs at import.
  - **`preflight.py`** — pre-authorization simulation over six ordered
    stages, each reporting `ESTABLISHED` / `NOT_ESTABLISHED` /
    `UNAVAILABLE` and a recommendation from `ALLOW < REVIEW < NARROW <
    SUSPEND < DENY`. Pure, bounded, and never a precondition of an allow. No
    combination of inputs yields an `UNKNOWN` stage with an `ALLOW`
    recommendation, which is what `REVIEW` sitting above `ALLOW` is for.
  - **`blast.py`** — bounded blast-radius analysis over the recorded
    delegation graph: `MAX_NODES = 2048`, `MAX_DEPTH = 64`,
    `MAX_FRONTIER = 4096`. Exceeding any bound resolves to `UNANALYZABLE`
    rather than to a partial answer presented as complete, because
    incompleteness here always means *larger*. Results are labelled
    `derived`, never `observed`.
  - **`decay.py`** — operator-written schedules mapping elapsed time to a
    recommended stage. Autonomous decay was **rejected**, and the module
    docstring says why: `expires_at` already exists, is inside the signature,
    and is enforced by `_gate_time`, so a second time-based authority
    reducer would be a competing representation of the same concept.
    `stage_at` is total, and every unanswerable input — bool, non-numeric,
    non-finite, negative, `OverflowError` on conversion — returns the
    *strongest* stage.
  - **`explain.py`** — the six §17 questions answered from structured state,
    with no generated prose and an explicit `complete` flag that is false
    whenever anything could not be established.
  - **`controller.py`** — the only mutable Aegis state and the only object
    the SDK holds. Two locks, one order (controller then store, never the
    reverse, and the store never calls back), and every method the
    authorization path can reach is total.

- **`FirewallSDK(aegis_enabled=True)`**, or `FirewallSDK(aegis=controller)`
  to inject one. Off by default: an existing deployment gets v2.3 behaviour
  unchanged, because `_gate_aegis` abstains when no controller is attached.
  The new public read is `FirewallSDK.authority_envelope(capability)`, which
  resolves the chain and hands it to the pure `chain_envelope`. Its docstring
  states the three things a caller must know: the result is sound and
  incomplete, Aegis restrictions are **not** folded in, and an unresolvable
  chain yields the bottom envelope rather than an optimistic one.
- **Four new invariants**, taking the registry from eleven to fifteen. Added
  only where Aegis introduces a genuinely new security property; several
  candidates from the v2.4 scope were rejected as restatements of invariants
  that already existed.
  - `UNKNOWN_NON_AUTHORIZATION` — no enumerated unknown or unavailable state
    resolves to a permissive value. Checked exhaustively over the cases,
    not sampled.
  - `ENVELOPE_SOUNDNESS` — what the envelope excludes, the boundary denies.
  - `ENVELOPE_MONOTONICITY` — a child's envelope is contained in its
    parent's, across delegation *and* attenuation.
  - `AEGIS_STATE_TRANSITIONS` — recorded history contains no illegal edge,
    and no `REVALIDATING -> ACTIVE` without a canonical allow traced to that
    fingerprint.
- **`firewall/benchmarks.py`** gains the Aegis measurements, reported in
  [docs/v2.4-performance.md](docs/v2.4-performance.md). Three results worth
  stating: the adaptive gate is below measurement noise on an unrestricted
  grant; a *restricted* authorization is measurably **faster** than an
  unrestricted one, because `_gate_aegis` precedes signature verification and
  denies before the expensive work; and the revocation check is flat at about
  9 µs from zero to four hundred revocations. Nothing was made faster at the
  cost of a security property — simulation is roughly 4× an authorization
  because each replayed case re-signs a capability with a simulation key, and
  that signing is what keeps simulated evidence distinguishable from real
  evidence.
- **384 tests** across eleven `tests/test_v2_4_*.py` files, including
  stateful security-state fuzzing (`_fuzz`), eight named concurrency races
  (`_concurrency`), and the integration-boundary sweep (`_integration_boundary`,
  68 tests) that checks every surface reaches the canonical boundary. Four
  more were added to the existing invariant suites for the four new registry
  entries. The full v2.3 suite passes unchanged; the whole suite goes from
  3,699 to **4,087**, on Python 3.10, 3.11 and 3.12. §17 of
  [docs/v2.4-aegis.md](docs/v2.4-aegis.md) maps each guarantee to the file
  that establishes it.

### Integration corrections (breaking)

Aegis is inherited by every surface rather than integrated into each one:
no surface computes its own allow, so a restriction written once binds MCP,
HTTP, tools, adapters and A2A alike. Sweeping the surfaces to establish that
found two places where the inheritance was real but unreadable.

- **A cross-agent allow now says what established it.**
  `A2ADecision.basis` defaults to `BASIS_RELATIONSHIP_ONLY` (was the
  uninformative `"derived"`), `to_dict()` reports `is_canonical`, and the new
  `A2ADecision.is_canonical` property is `True` only when
  `FirewallSDK.authorize()` produced the decision. `AgentToAgent`'s
  `sdk_provider` is optional because the class is also useful as a pure
  relationship registry — `trust_graph`, `lineage` and
  `effective_permissions` answer questions unrelated to a live request — but
  an `authorize()` allow reached without a provider is a relationship check,
  not an authorization, and a caller enforcing on `allowed` alone could not
  previously tell the difference. The provider-raised case is reported as
  `unavailable`, not canonical: the pipeline was asked and did not answer.
  The object and the CLI both now say which kind of allow it is.
- **All three model adapters tag their output as untrusted.**
  `GenericToolAdapter`, `OpenAITool` and `AnthropicTool` each end `execute()`
  with `mark_untrusted(output, tool=...)`, which is what `protect_tool`
  already applied. The same handler behind two wrappers previously carried
  two different guarantees, and the adapter path was the weaker one — tool
  output is untrusted data, and it must be labelled as such wherever it
  enters.

Four divergences between the surfaces were found, examined, and **kept**,
because unifying them would change behaviour callers depend on for no
security gain: MCP consumes a nonce before authorization while HTTP consumes
one after (so a denied HTTP request does not burn a nonce); the surfaces do
not agree on which exceptions escape versus become refusals; three
`request_builder` calling conventions coexist; and one surface authorizes
against `capabilities[0]` where a caller might expect a search. All four are
documented in §13.3 of [docs/v2.4-aegis.md](docs/v2.4-aegis.md).

### Documented non-guarantees

Stated rather than left to be inferred. §16 of
[docs/v2.4-aegis.md](docs/v2.4-aegis.md) is the full list; these are the ones
most likely to be misread.

- **Envelope soundness runs in one direction only.** An envelope that does
  not exclude a request is not a pre-approval.
- **`canonical_allow_for` is a structural check, not a cryptographic one.**
  It bounds mistakes — a stale, wrong or denied result passed where an allow
  was expected — not an adversary already inside the process. In-process
  integrity is not claimed anywhere in this codebase.
- **State is not an enforcement channel.** The gate reads restrictions, not
  `SecurityState`. Wiring the state machine into the gate would make the
  authorization path depend on a structure whose updates require an
  authorization result.
- **The commit-time re-read covers suspension only.** A narrower-scope
  restriction applied between gate and commit takes effect on the next
  authorization.
- **The restriction cap trades availability for integrity.** Sixteen
  narrowings drive a grant to SUSPEND. Fail-closed, and still a lever. Chosen,
  not overlooked.
- **A withdrawal is two writes.** `revoke_issuer` updates the trust store and
  then refreshes the verifier's copy without one lock across both. Both
  interleavings deny; the reason differs, and in the intermediate state a
  request is refused as `invalid_signature` when the signature is intact and
  the issuer is what changed. The test pins the verdict exactly and bounds the
  reason to the two fail-closed possibilities, rather than pinning a reason
  the scheduler can perturb. A deterministic sibling test constructs the skew
  directly instead of waiting for it — it was observed once in roughly
  130,000 authorizations.
- **A strict invariant run describes an exercised estate, not a deployment.**
  Both run modes print their own scope.

## [2.3.0] - 2026-09-02

v2.3 is a correctness release. It adds no new subsystem and no new
authorization path. The work was to attack v2.2's shipped behaviour and fix
what broke, to remove analytical results that read as verified when they
were not, and to make the invariant gate something CI can actually fail on.

Sections of the v2.3 scope that are not listed here are not implemented.

### Security corrections (breaking)

All three are narrowing. Each closes a path where a request that should
have been denied was allowed. See
[docs/v2.3-security-corrections.md](docs/v2.3-security-corrections.md).

- **A non-finite request value no longer satisfies every numeric bound.**
  `firewall/authorization.py` now denies with `constraint_denied` when a
  request value compared against a numeric constraint is `NaN` or an
  infinity. Every numeric bound is enforced by its negation — the request
  is admitted unless `actual > expected` for a `_max` ceiling, or
  `actual < expected` for a `_min` floor — and `NaN` compares `False`
  against both, so `{"amount": NaN}` passed an `amount_max` of 100 and an
  `amount_min` of 10 simultaneously. `json.loads` accepts the bare tokens
  `NaN`, `Infinity` and `-Infinity` by default, so this was reachable from
  any JSON request body or tool output without the caller doing anything
  unusual. `-inf` was admitted by every ceiling and `+inf` by every floor
  for the same reason.
- **A decision taken while a configured dependency was blind no longer
  reports as authorized.** `FirewallSDK.authorize_continuous` now applies
  the same degradation subtraction that `revalidate()` already applied,
  returning `security_dependency_unavailable: <names>`. v2.2 gated all
  three revalidation paths but not the initial decision, so a capability
  authorized while a wired probe was raising was allowed once and denied by
  every subsequent revalidation of the same request — an intermittent
  fail-open, and precisely the window an attacker who can stop a probe
  answering would aim at. `ContinuousAuthorizationEngine.effective_verdict`
  is now public and still returns a `(bool, reason)` pair; the verdict
  object is constructed only at the authorization boundary, so
  `AUTHORIZATION_UNIQUENESS` still holds.
- **Reconfiguring a delegation budget no longer restores spent allowance.**
  `DelegationBudgetRegistry.configure` rebuilt the state object, resetting
  the consumed total to `0.0`. An exhausted lineage's entire allowance
  could be restored by an administrative call that revoked, re-issued and
  signed nothing. The idempotent case was the dangerous one: a startup path
  re-applying the same limit cleared the ledger on every restart, so the
  budget never bound across restarts. `configure` now adjusts the ceiling
  and preserves the total. A ceiling set below what was already consumed is
  accepted and admits nothing further — narrowing must take effect, not be
  rejected.

  `DelegationBudgetState.reserve` additionally refuses a non-finite amount
  with `ValueError`. A `NaN` reservation was admitted by the same negated
  comparison as above and made `total_amount` `NaN`, after which every
  later comparison was `False` and the budget admitted everything forever.
  Only `authorize_with_delegation_budget` had guarded this, so the
  guarantee rested entirely on one call site.

### Corrected results (breaking)

Analytical output that was wrong or that read as a stronger claim than it
supports. None of these is an authorization path; all of them feed human
and containment decisions.

- **Policy counterfactuals count only cases the simulator could replay.**
  The counterfactual read `after_reason == "authorized"` over every
  outcome. An excluded case has `after_reason is None`, which is
  `!= "authorized"`, so cases that were never evaluated were tallied as
  denials — and enough of them turned a widening into a report of
  `improved`. Counts now come from `report.counted_outcomes` and read the
  `after_allowed` boolean. Nothing counted yields `unknown`, not
  `unchanged`. `CounterfactualResult.complete` states the coverage and
  excluded cases are named in `details` with the reason.
- **A policy that could not be parsed is reported, not dropped.**
  `unanalyzable_policy`, so "no conflicts" stops reading identically to "no
  conflicts among the policies I could read".
- **The constraint-contradiction check now examines the real constraint
  shape.** It read `constraints[namespace]` as an operator dict and looked
  for `eq` beside `neq`; those keys are field names at that level, and
  `validate_constraints` rejects `neq` as a `Capability2` operator
  anywhere, so the check was dead on both counts. `_analyze_satisfiability`
  walks `{namespace: {field: {operator: value}}}` across all six field
  namespaces and the time window, reporting unreachable constraints (dead
  weight that reads as enforcement) and unconditional ones. Silence from
  these checks is the absence of a recognized contradiction, not a proof of
  satisfiability, and a test pins a genuinely unsatisfiable case that is
  deliberately not reported.
- **`PolicyConflict.rules_involved` is a tuple.** It was a generator
  assigned to a tuple field, so `to_dict()` consumed it and every reader
  after the first saw no rules.
- **`verify_policy_safety` no longer claims to use the SDK's
  authorization.** It calls `Capability2.evaluate` and exercises none of
  the identity, provenance, revocation or budget gates. The docstring says
  so, and says the empty tuple is not a safety proof.
- **Intelligence gaps are reported instead of swallowed.**
  `collect_facts()` no longer wraps four of its five sources in
  `except Exception: pass`. Every *configured* source that raises names
  itself in `IntelligenceReport.gaps`; an unwired source does not, because
  unwired is unknown and the caller chose it. `IntelligenceReport.complete`
  makes a blinded engine structurally distinguishable from a clean one —
  previously both produced an empty report. Gaps are carried outside the
  fact list so the agent filter cannot discard them.
- **The immune system's `trust_collapse` rule no longer invents a score.**
  It read `state.get("trust_score", 1.0)`, answering a question it had no
  evidence for with the most reassuring number available. A missing score
  is neither a collapsed score nor a healthy one, so the rule does not
  apply. A non-numeric score no longer raises `TypeError` mid-pass, which
  would have lost the findings for every other agent in the same cycle.

### Renamed (breaking)

Three names each carried two guarantees, and on one side of each pair the
name implied a cryptographic result that side never produces. See
[docs/v2.3-migration.md](docs/v2.3-migration.md).

- `firewall.deception.IntegrityReport` → **`ClaimIntegrityReport`**. It
  meant "eight subsystems were asked about this agent and mostly agreed",
  while `firewall.evidence_integrity.IntegrityReport` means "this
  hash-chained log verifies against its checkpoints and signers". The
  deception result checks no hash and verifies no signature; reading its
  `overall_integrity == "high"` as a verification was exactly the mistake
  the shared name invited.
- `firewall.security_memory.Checkpoint` → **`EvidenceCheckpoint`**. The
  recorder's `Checkpoint` and this one sign different field sets over
  different chains, so neither verifier can check the other's. The recorder
  keeps the name its released audit-artifact format uses.
- `AgentSecurityProfile.trust_score` → **`finding_score`**. `MeshState`'s
  `trust_score` is 0.0 when identity could not be verified and is compared
  against the quarantine threshold; the profile's was 1.0 until something
  was found against the agent. The two run in opposite directions for
  absence, so wiring the profile into the mesh's `trust_provider` would
  have delivered an unchecked agent as fully trusted. `finding_score` is
  what the field always measured.

`MeshState.identity_verified` stays a plain `bool` — the mesh quarantines
on anything short of a verified identity, so it has no use for a third "not
established" value. The five remaining duplicate names are recorded in
`REVIEWED_DUPLICATE_NAMES` with the reason each pair may keep sharing one,
and a test fails if any pair collapses into an alias.

### Removed

- **`firewall.correlation`** (551 lines, zero importers, zero tests). Two
  of its six detection paths were structurally dead: the trust-relationship
  lookup was a bare `pass` inside a swallowed `try`, and
  `temporal_trust_coordination` fired for every pair of agents behind a
  comment reading `# Simplified check`. A detector that fires on every pair
  carries no information. Coordination detection now lives in
  `firewall.intel` as a fourth correlator, where every finding is built
  through `_hypothesis()` and carries an id, clamped confidence, supporting
  facts, a rationale and `basis="inferred"`. Four patterns, each requiring
  two distinct agents and a concrete shared value. Proximity states that no
  trust relationship was checked rather than implying one, and a spanning
  escalation path states that reachability is not exploitability.

### Added

- **`python -m firewall.invariants --exercise --strict` can pass, so it is
  worth failing.** `--strict` exited 2 on every invocation: five of the
  eleven invariants are claims about live state — a signed delegation edge,
  an attenuation, a propagated revocation, an applied policy
  transformation, a simulation that ran — and a source-only run has none of
  them. A gate that always fails is a gate that gets removed, so those five
  were effectively ungated in CI. `firewall/invariants/exercise.py` builds
  the canonical estate entirely through the SDK's public API; nothing
  reaches into a control-plane container and exercising grants no authority.
  The estate is deliberately awkward where it matters — the revocation is
  mid-chain so `REVOCATION_MONOTONICITY` has a descendant to propagate to,
  and the attenuation hangs off the root with no signed parent so it is
  visible only to `CAPABILITY_MONOTONICITY`. What a green exercised run
  establishes is bounded to that estate, and the module docstring and the
  printed output both say so. CI now runs both halves; `cli.yml` had
  stopped at v2.0 and never ran on v2.1, v2.1.1 or v2.2.
- **`tests/test_v2_3_self_attack.py`** — 116 tests, one section per
  question in the mission's final self-attack list, each attempting the
  attack through the real public API and asserting it fails closed. Two
  rules govern the file: attack through the front door, and where the
  system makes no guarantee, pin the non-guarantee instead of faking one. A
  completeness test maps each of the thirteen questions to its section, so
  a deleted section fails rather than quietly shrinking the suite. See
  [docs/v2.3-self-attack.md](docs/v2.3-self-attack.md).

### Documented non-guarantees

Stated rather than left to be inferred. No code change accompanies these;
the previous docstrings implied containment that the code does not provide.

- **`retire_key` is not containment for a stolen key.** A retired key stops
  being the active key and `issue` refuses once no active key remains, but
  capabilities it signed keep verifying — including capabilities forged
  *after* retirement by anyone holding the private key. That is what makes
  `rotate_key` usable: rotation retires the outgoing key, and invalidating
  its signatures would kill every capability in flight at that moment.
  Verification asks whether the signature is genuine and the issuer
  trusted, not whether the key is still in the issuance rotation. The lever
  that does contain a compromised signer is `revoke_issuer`, which refuses
  every capability under that issuer with `untrusted_issuer`.
- **Possession of a trusted signing key is authority.** That is what a
  signature means, and there is no cryptographic answer to it. The boundary
  of the threat model is the key material — `trust_issuer` does *not* import
  an issuer's keys, so naming an issuer as trusted is a strictly smaller
  reach than holding one of its private keys.
- **`known_capabilities()` does not report revocation.** v2.2 described the
  view as preventing a subsystem from pinning a snapshot past a revocation.
  It does not, because revocation is not recorded in that registry at all —
  it lives in the revocation store, which `authorize()` consults directly,
  and a revoked capability stays in the view. Nothing is authorized off the
  view, so this corrects what the view can be read as saying rather than
  closing a hole; a subsystem that needs revocation status must call
  `is_effectively_revoked` rather than iterate. Pinned by test.

## [2.2.0] - 2026-09-01

Sections of the v2.2 scope that are not listed here are not implemented,
and this file is not the place to claim otherwise.

### Security corrections (breaking)

All four are narrowing. None allows anything that v2.1.1 denied. See
[docs/v2.2-migration.md](docs/v2.2-migration.md).

- **Signed delegation lineage is now authoritative over the mutable
  registry.** `FirewallSDK._authorization_chain` reconciles each
  capability's signed `parent_fingerprint` against the resolved chain and
  denies with `delegation_chain_error` when a signed parent has no resolved
  parent, or is not the resolved parent. A capability signed as a
  delegation previously authorized as a **root** when its lineage edge was
  absent, detaching it from transitive revocation of its ancestors and from
  the root's cumulative lineage budget. The reverse case — a resolved
  parent with no signed one — remains allowed: attenuation is exactly that,
  and an extra ancestor only adds constraints.
- **`authorize(cap, action="")` returns a verdict instead of raising.**
  `AuthorizationResult(False, "invalid_action")` for any non-string or
  blank-after-strip action. `RefusalState.check_action` raised `ValueError`
  out of the first gate, breaking the gate chain's contract and handing a
  caller that wraps `authorize` in `except Exception` an unauthorized
  request with no verdict attached. Action names can originate in untrusted
  tool output, so this was reachable from outside.
- **Added a structural delegation-monotonicity gate.** Each child in the
  resolved chain must be narrower than or equal to its parent, or the
  request is denied with `delegation_widening`. v2.1.1 constrained a
  non-monotonic chain's *effective* authority through the ancestor
  intersection but never checked structural narrowness, so a non-monotonic
  chain authorized any request inside the intersection.
- **`FirewallSDK.known_capabilities()` replaces private registry access.**
  Returns a `MappingProxyType` — a live read-only view, so a subsystem
  cannot inject a forged parent, delete an inconvenient ancestor, or pin a
  snapshot past a revocation. Six in-tree modules migrated off private
  registry access (`agents/adapters.py`, `agents/base.py`,
  `containment/controller.py`, `defense/mesh.py`, `network/simulator.py`,
  `ui/v21.py`); the `getattr(sdk, "_capability_registry", {})` form four of
  them used was itself the hazard, since a rename silently yields "this
  agent holds nothing".

### Added

- **Continuous authorization** (`firewall.continuous_auth`): deterministic
  re-evaluation of a live decision when the state it rested on changes.
  Fifteen `RevalidationTrigger` members over identity, task, capability,
  delegation, provenance, posture, risk, trust, policy, environment,
  incident, time and explicit request. It creates **no second engine** — the
  engine re-invokes `FirewallSDK.authorize()` and compares verdicts, and
  `_effective_verdict` can only turn an allow into a deny, never the
  reverse. Every watched subsystem is an explicit `continuous_auth_*`
  constructor argument, because an unwired dependency makes its change
  class undetectable and that must be visible at the call site.
  `PROBE_FAILED` (a configured dependency raised) is distinct from
  `UNKNOWN` (not wired); only the former withholds an allow, as
  `security_dependency_unavailable`. The monitor sweep starts as the final
  statement of `__init__` because it calls back into `authorize()`.
- **Machine-checkable security invariants** (`firewall.invariants`): eleven
  named properties, each stated once in `registry.py` and checked by
  exactly one function, so an invariant with no check is a missing registry
  entry rather than a silently absent property. Status is three-valued —
  `UNVERIFIABLE` is falsy, makes the whole report falsy, and makes
  `assert_all` raise, because accepting it would make the assertion
  satisfiable by breaking the checker. A checker that raises becomes
  `UNVERIFIABLE`, never `HOLDS`. Added `python -m firewall.invariants` with
  an exit-code trichotomy (0 pass / 1 violated / 2 unverifiable under
  `--strict`) so a source-only CI job can gate the six checkable
  invariants without a permanently red gate; `--json` and `--list` also
  supported. Wired into `.github/workflows/security.yml`.
- **Shared provenance vocabulary** (`firewall.platform`): re-exports
  `firewall.network.model.Provenance` rather than declaring a parallel
  enum, so a weakness finding's basis, an attack path's basis and a
  discrepancy signal's provenance stay directly comparable. `combine()`
  never strengthens a claim; `coerce()` degrades an unrecognized label to
  `unknown`.
- **Adversarial weakness search** (`firewall.twin.adversarial`): searches
  the recorded security graph for weaknesses that already exist rather than
  for the consequences of a hypothetical change — confused deputy,
  promotable provenance, unenforced revocation, lateral movement,
  multi-agent attack chains, compromised-agent impact. Bounded and
  guaranteed to terminate. A finding's `basis` is capped at `derived` and
  is the weakest hop it rests on. It imports neither `sdk` nor `policy`,
  and a test walks the module AST to keep that true — its own docstring
  names `FirewallSDK.authorize` in order to say it never calls it, so a
  substring check would fail on that sentence.

- **Adversarial agent defense** (`firewall.adversarial`): deterministic
  signals about discrepancies between what an agent claims and what the
  control plane records — claimed vs registered identity, declared vs
  authorized task, presented capability vs its issuance/revocation/expiry
  state, delegation lineage vs declared parent, dependency provenance vs
  recorded component trust, posture vs observed action, evidence vs
  evidence. `trust_score` and `risk_level` are triage ordering for a human
  or a containment operator; `authorize()` does not read them.
- **Deception and integrity engine** (`firewall.deception`): compares six
  independent claim sources (identity, task, capability, provenance,
  observed behaviour, posture) and reports meaningful contradictions
  explicitly. It does not resolve them by guessing which source is lying —
  `ClaimStatus` distinguishes `VERIFIED`, `CONTRADICTED`, `UNVERIFIED` and
  `UNKNOWN`.
- **Evidence integrity hardening** (`firewall.evidence_integrity`): reports
  *proven tampered*, *could not be checked* and *passed* as three separate
  outcomes, because a report that folds "no tampering found" together with
  "the check never ran" states a guarantee it does not hold. Detects hash
  mismatch, broken links, ordering violations, missing causal parents, bad
  and missing signatures, duplicates, backwards timestamps beyond the drift
  allowance, signing after key revocation, and — against a signed anchor
  only — tail truncation, anchor mismatch and replaced checkpoints.
- **Security Memory 2.0** (`firewall.security_memory`): long-lived evidence
  chains, signed checkpoint continuity, cross-artifact relationships,
  provenance verification, incident reconstruction, evidence indexing, and
  independent verification. Imported chains are held in **quarantine** and
  never merged into the local graph, whose hash link and sequence are
  global; import refuses a known chain id, a known event id, or any
  structural problem, and writes nothing until every check passes. With
  `verify=True` the exporter's signer is required — an evidence store that
  accepts unattributable chains and remembers it could not check them will
  be read as if it had.

### Changed

- `firewall.twin` now re-exports `AdversarialDigitalTwin`,
  `TwinSearchResult`, `WeaknessFinding` and the search bounds. The interim
  `firewall.twin2` package was folded into `firewall.twin` and removed:
  one security concept, one representation.
- `authorize_continuous()` registers only **allowed** decisions with the
  monitor. A denial carries no live authority and revalidation cannot
  withdraw anything from it, so registering denials filled a bounded table
  with entries that evicted the decisions that matter. It also now reuses
  the engine's own request hashing and cache key rather than recomputing
  them, so two canonicalisations cannot drift apart and split one decision
  into two monitor entries.

### Fixed

- **`AttackGraph.trust_transitivity` described reach it had not tested.**
  The guard reduced to `tail_reach["resources"]`, so any resource at all
  was reported under a "reach over sensitive resources" description. It now
  tests `is_sensitive` and names the resources in the finding, making the
  claim checkable by whoever reads it.

### Documented

- Added [docs/v2.2-architecture.md](docs/v2.2-architecture.md),
  [docs/v2.2-security-model.md](docs/v2.2-security-model.md),
  [docs/v2.2-threat-model.md](docs/v2.2-threat-model.md),
  [docs/v2.2-invariants.md](docs/v2.2-invariants.md) and
  [docs/v2.2-migration.md](docs/v2.2-migration.md).
- **Two v2.1 attack-graph analyses cannot fire, and are now documented as
  such rather than removed.** Both are left untouched in
  `firewall.attackgraph`: they return an empty list, which is not an unsafe
  answer, and v2.1 behaviour is not changed on the strength of a v2.2
  observation.
  - `AttackGraph.capability_combinations` reports capability pairs whose
    union reaches a sensitive resource that neither reaches alone. The
    graph records no conjunctive prerequisite, so reach is additive: a
    sensitive resource in the union is in at least one of the pair. The
    condition is unsatisfiable by construction.
  - `AttackGraph.delegation_abuse` reports a `delegates` edge whose
    grantee's reach contains a capability the grantor's does not.
    `reachable()` follows the delegation edge, so the grantor's reach
    always contains the grantee's and the difference is empty for every
    graph. The condition is expressible over what each agent *holds*, but
    in this graph that is the same shape as
    `AdversarialDigitalTwin.search_confused_deputy`. Delegation widening is
    enforced, not merely reported, by the authorization boundary.
- **Documented what a source-only invariant run does not establish.** Five
  of the eleven need an exercised SDK — a delegation edge, an attenuation,
  a revocation, an applied policy transformation, a simulation that ran —
  and report `UNVERIFIABLE`. `tests/test_v2_2_invariants.py` exercises
  them; CI runs both.
- No `docs/v2.2-cli.md` or `docs/v2.2-benchmarks.md`: v2.2 adds no CLI
  surface and no benchmarks. Documenting absent features is a fake
  guarantee.

### Repository

- Stopped tracking five CLI runtime state files (`mesh.json`, `tasks.json`,
  `identities.json`, `provenance.json`, `a2a.json`) and added them to
  `.gitignore`. They are `--state` defaults written into the working
  directory; a committed copy is one run behind whoever ran the CLI last.
- `.github/workflows/security.yml` triggers on `v2.2` and runs
  `python -m firewall.invariants` as a source-tree gate.

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
