# Changelog

All notable changes to Agent Firewall are documented here.

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
- **190 tests**, taking the suite from 4,087 to **4,277** on Python 3.10, 3.11
  and 3.12. 189 are in six `tests/test_v2_5_*.py` files — the boundary
  totality sweep, the composition campaign, the integration-divergence sweep,
  the stale-revalidation reproductions, the verdict census, and the benchmark
  guards — and every attack row in
  [docs/v2.5-boundary.md](docs/v2.5-boundary.md) is pinned by one of them.
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
