"""v2.4 §13: security-state fuzzing over the Aegis control plane.

Not input fuzzing. The unit of randomness here is an *operation on the
security state* -- issue, delegate, authorize, narrow, suspend, lift,
revalidate, expire, revoke, decay -- and the properties are re-checked after
every one of them. A malformed-input fuzzer finds crashes; this one is
looking for a legal-looking sequence of legal-looking operations that ends
with more authority than it started with.

Three things make the properties worth checking rather than decorative.

**The oracle is independent of the implementation.** The machine keeps its
own model of the estate -- a parent map and a ceiling per grant -- and
derives the ceiling that must bind as ``min`` over the chain. It never asks
Aegis what the answer should be. Where the model says a request exceeds the
narrowest ancestor, the boundary must deny; the assertion runs in that
direction only.

**Every assertion is one-directional.** The machine asserts that denials
happen, never that allows happen. That is not timidity about flakiness: a
``constraint_denied`` is memoized into refusal state for the agent's whole
action class, so "this should have been allowed" is not a property of the
system at all once a denial has been asked for. Authority can only be
checked from the subtractive side, which is also the only side a security
failure can appear on.

**The invariant suite runs on the live estate, not a scratch one.** Five of
the seventeen machine-checked invariants audit whatever a deployment actually
recorded, and those five run after every step against the state the fuzzer
has built. The other twelve build their own probe estates, or -- like v2.6's
AUTHORITY_EPOCH_COVERAGE -- check a wiring the fuzzer never touches, so
running them per step would burn time re-checking a fixed grid; they run
once, in :class:`TestTheSuiteItself`, so their silence here means "checked
elsewhere" rather than "not checked".

Minimized failures
------------------

Nothing in this file is currently expected to fail. When it does, the
minimized sequence goes into ``tests/test_v2_4_aegis_corrections.py`` as a
named regression alongside the eight §10 defects, and the fix goes to the
layer that owns the property -- not to the fuzzer.
"""

from __future__ import annotations

import collections
from typing import Optional

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    initialize,
    invariant,
    multiple,
    rule,
    run_state_machine_as_test,
)

from firewall.aegis.decay import DecaySchedule
from firewall.aegis.preflight import Impact, Recommendation
from firewall.aegis.state import (
    RESIDUAL_AUTHORITY,
    TERMINAL_STATES,
    AegisState,
    IllegalTransition,
)
from firewall.invariants import (
    InvariantStatus,
    check_aegis_state_transitions,
    check_capability_monotonicity,
    check_delegation_monotonicity,
    check_envelope_monotonicity,
    check_envelope_soundness,
    check_evidence_integrity,
    check_fail_closed,
    check_revocation_monotonicity,
    check_unknown_non_authorization,
)
from firewall.revocation import AlreadyRevokedError
from firewall.sdk import FirewallSDK

KEY_ID = "fuzz-key"
ACTION = "payments.send"

#: The five invariants that audit a live estate. Re-run after every
#: operation, because the whole point is to catch the step that broke one.
LIVE_INVARIANTS = (
    check_delegation_monotonicity,
    check_capability_monotonicity,
    check_revocation_monotonicity,
    check_envelope_monotonicity,
    check_aegis_state_transitions,
)

#: Restriction keys the machine writes and lifts. A small fixed set, so
#: that a lift has a realistic chance of naming a key that exists -- a lift
#: of an absent key is a no-op and would make the rule mostly inert.
KEYS = ("aegis:ceiling", "aegis:halt", "aegis:review")

#: Amounts the machine requests. Spans the ceilings it hands out, so a
#: request lands on both sides of the model's derived bound often enough for
#: the denial assertion to actually fire.
AMOUNTS = st.integers(min_value=0, max_value=400)

#: Ceilings the machine issues and narrows to. Bounded well above zero so a
#: narrower child is usually constructible.
CEILINGS = st.integers(min_value=1, max_value=200)

#: What the run actually reached, written by the machine and read by
#: :meth:`TestTheSuiteItself.test_the_run_reaches_what_it_claims_to_fuzz`.
#:
#: Every assertion in this file is one-directional -- it fires only when the
#: model says a denial is owed -- so a machine that never built restricted,
#: revoked or over-ceiling state would pass every one of them without
#: checking anything. This counter is what makes that failure mode visible.
#: No rule reads it: a rule whose behaviour depended on it would make the
#: run order-dependent and the shrinker's output meaningless.
REACHED: collections.Counter = collections.Counter()


class AegisEstateMachine(RuleBasedStateMachine):
    """A live SDK, a live Aegis controller, and an independent model of both.

    The model is deliberately thin: a parent map, an own-ceiling map, and a
    set of fingerprints that have been revoked or seen terminal. It is
    enough to derive the two things a security failure would show up in --
    the narrowest ceiling binding a chain, and whether a grant has already
    lost its authority for good -- without reimplementing the boundary. A
    richer model would drift from the implementation and start reporting its
    own bugs as findings.
    """

    grants = Bundle("grants")
    #: Delegated grants only. A separate bundle rather than an ``assume``
    #: inside the rule: a state machine's ``assume`` discards the whole
    #: sequence, not the step, so filtering for "has a parent" that way threw
    #: away half of every session's budget.
    children = Bundle("children")

    def __init__(self) -> None:
        super().__init__()

        self.sdk = FirewallSDK(aegis_enabled=True)
        self.private_key = self.sdk.generate_key(KEY_ID).private_key
        self.aegis = self.sdk.aegis

        #: fingerprint -> the signed capability, so it can be revoked and
        #: re-presented at the boundary later.
        self.capability = {}
        #: fingerprint -> parent fingerprint, or ``None`` for a root.
        self.parent = {}
        #: fingerprint -> the ``amount_max`` in its own signed constraints.
        self.own_ceiling = {}
        #: Fingerprints this machine has revoked through ``sdk.revoke``.
        self.revoked = set()
        #: Fingerprints observed in a terminal Aegis state at any point.
        self.terminal_seen = set()
        #: Requests the boundary allowed, kept for the envelope-soundness
        #: check: ``(fingerprint, amount)``.
        self.allowed = []

        self._agents = 0

    def teardown(self) -> None:
        self.sdk.close()

    # -- the model -----------------------------------------------------

    def _next_agent(self) -> str:
        self._agents += 1
        return f"agent-{self._agents}"

    def _chain(self, fingerprint: str) -> list:
        """``fingerprint`` and every ancestor, nearest first.

        Walks the machine's own parent map rather than the SDK's lineage
        store. Bounded by construction: the map only ever gains edges from
        a child to an already-present parent, so it cannot cycle.
        """

        chain = []
        cursor: Optional[str] = fingerprint

        while cursor is not None:
            chain.append(cursor)
            cursor = self.parent.get(cursor)

        return chain

    def _model_ceiling(self, fingerprint: str) -> int:
        """The narrowest ``amount_max`` over the chain.

        This is the whole authority-envelope claim of §5 reduced to the one
        dimension the machine varies: ``effective = min(own, parent's
        effective)``. Derived here, never read back from Aegis.
        """

        return min(self.own_ceiling[node] for node in self._chain(fingerprint))

    def _chain_is_revoked(self, fingerprint: str) -> bool:
        return any(node in self.revoked for node in self._chain(fingerprint))

    # ==================================================================
    # Growth: the estate gets wider and deeper
    # ==================================================================

    def _issue_root(self, ceiling: int) -> str:
        agent = self._next_agent()
        capability = self.sdk.issue(
            agent=agent,
            capability=ACTION,
            constraints={"amount_max": ceiling},
        )
        fingerprint = self.sdk.fingerprint(capability)

        self.capability[fingerprint] = capability
        self.parent[fingerprint] = None
        self.own_ceiling[fingerprint] = ceiling
        self.aegis.register(fingerprint, agent_id=agent, capability=ACTION)

        return fingerprint

    @initialize(target=grants, ceiling=CEILINGS)
    def the_first_root(self, ceiling):
        """One root before any rule runs, so the estate is never empty.

        Without it Hypothesis would spend the early steps of every run
        drawing from an empty bundle and skipping every rule that needs a
        grant.
        """

        return self._issue_root(ceiling)

    @rule(target=grants, ceiling=CEILINGS)
    def issue_a_root(self, ceiling):
        return self._issue_root(ceiling)

    @rule(targets=(grants, children), parent=grants, ceiling=CEILINGS)
    def delegate(self, parent, ceiling):
        """Mint a child that is narrower than its parent's own ceiling.

        Clamped rather than filtered: ``_constraints_are_narrower`` compares
        the child against the parent's *own* signed constraints, so
        ``min`` of the two is guaranteed to be accepted. Drawing freely and
        discarding the rejections would spend most of the budget on
        ``ValueError`` and never build a deep chain.
        """

        narrowed = min(ceiling, self.own_ceiling[parent])
        agent = self._next_agent()

        try:
            child = self.sdk.delegate(
                self.capability[parent],
                self.private_key,
                delegatee=agent,
                constraints={"amount_max": narrowed},
            ).child
        except ValueError:
            # An expired or otherwise unmintable parent. A refusal here is
            # the safe direction, so the machine records nothing and moves
            # on rather than asserting which parents must be delegable.
            return multiple()

        fingerprint = self.sdk.fingerprint(child)

        self.capability[fingerprint] = child
        self.parent[fingerprint] = parent
        self.own_ceiling[fingerprint] = narrowed
        self.aegis.register(fingerprint, agent_id=agent, capability=ACTION)

        # The signed child is never wider than the signed parent. Checked
        # here, at mint time, because DELEGATION_MONOTONICITY audits the
        # recorded estate and would not see a child that was minted wide
        # and then narrowed before the sweep ran.
        assert narrowed <= self.own_ceiling[parent]
        assert self._model_ceiling(fingerprint) <= self._model_ceiling(parent)

        return fingerprint

    # ==================================================================
    # The boundary
    # ==================================================================

    @rule(fingerprint=grants, amount=AMOUNTS)
    def authorize(self, fingerprint, amount):
        """Ask the canonical boundary, and check only what must be denied.

        The four denial obligations below are the ones with an enforcement
        channel behind them: signed constraints, the revocation registry,
        and the Aegis restriction store (twice). Aegis *state* is
        deliberately absent from the list -- ``expire`` and ``mark_revoked``
        latch a state without writing a restriction, so a grant can sit in
        ``EXPIRED`` while its capability is still valid and still
        authorize. That is the "state is not an enforcement channel"
        property, and asserting otherwise here would pin a guarantee the
        implementation does not make.
        """

        capability = self.capability[fingerprint]
        chain = self._chain(fingerprint)

        # Read before deciding, so the two are evaluated against the same
        # state. Nothing mutates in between: the machine is single-threaded
        # and concurrency is covered in tests/test_v2_4_aegis_concurrency.py.
        envelope = self.sdk.authority_envelope(capability)
        suspension = self.aegis.suspended_in(chain)
        restriction = self.aegis.restriction_reason(
            chain,
            ACTION,
            {"amount": amount},
        )

        outcome = self.sdk.authorize(capability, ACTION, {"amount": amount})

        assert isinstance(outcome.allowed, bool)
        assert isinstance(outcome.reason, str) and outcome.reason

        if amount > self._model_ceiling(fingerprint):
            REACHED["oracle:over_ceiling"] += 1
            assert outcome.allowed is False, (
                f"{amount} exceeds the modelled chain ceiling "
                f"{self._model_ceiling(fingerprint)}: {outcome.reason}"
            )

        if self._chain_is_revoked(fingerprint):
            REACHED["oracle:revoked_chain"] += 1
            assert outcome.allowed is False, (
                f"a revoked chain authorized: {outcome.reason}"
            )

        if suspension is not None:
            REACHED["oracle:suspended"] += 1
            assert outcome.allowed is False, (
                f"a suspended chain authorized: {outcome.reason}"
            )

        if restriction is not None:
            REACHED["oracle:restricted"] += 1
            assert outcome.allowed is False, (
                f"a restricted chain authorized: {outcome.reason}"
            )

        if outcome.allowed:
            REACHED["outcome:allowed"] += 1
            assert outcome.reason == "authorized"
            # ENVELOPE_SOUNDNESS, one-directional: the envelope may admit
            # what the boundary denies, but it must never exclude what the
            # boundary allowed.
            assert envelope.bottom is False
            assert envelope.excludes(ACTION, {"amount": amount}) is None, (
                envelope.excludes(ACTION, {"amount": amount})
            )
            self.allowed.append((fingerprint, amount))
        else:
            REACHED[f"denial:{outcome.reason.split(':')[0]}"] += 1

    @rule(fingerprint=children, amount=AMOUNTS)
    def a_child_never_widens_its_parent(self, fingerprint, amount):
        """If the parent's envelope excludes it, the child's must too.

        The subset relation of §5 read through the surface an operator
        actually uses. Checked on the envelope rather than the boundary
        because the boundary memoizes refusals, so a denial recorded
        against the parent would make the child's denial unfalsifiable.
        """

        parent = self.parent[fingerprint]

        request = {"amount": amount}
        child_envelope = self.sdk.authority_envelope(self.capability[fingerprint])
        parent_envelope = self.sdk.authority_envelope(self.capability[parent])

        if parent_envelope.excludes(ACTION, request) is not None:
            assert child_envelope.excludes(ACTION, request) is not None, (
                f"the parent excludes {amount} and the child does not"
            )

        assert child_envelope.is_subset_of(parent_envelope) is True

    # ==================================================================
    # The Aegis write path
    # ==================================================================

    def _attempt(self, fingerprint: str, operation, **kwargs) -> None:
        """Run a transition and check the one thing every one of them owes.

        A terminal grant must not move. ``_move`` raises
        :class:`IllegalTransition` rather than returning a failure, and
        ``narrow``/``suspend`` write their restriction *before* attempting
        the move, so the post-condition is checked on the recorded state
        rather than on whether the call raised -- a restriction that lands
        while the state refuses to change is the documented behaviour, not
        a violation.
        """

        before = self.aegis.grant(fingerprint)
        before_state = None if before is None else before.state

        try:
            operation(fingerprint, **kwargs)
        except IllegalTransition:
            pass

        after = self.aegis.grant(fingerprint)
        after_state = None if after is None else after.state

        if before_state in TERMINAL_STATES:
            assert after_state is before_state, (
                f"a terminal grant moved: {before_state} -> {after_state}"
            )

        if before_state is not None:
            assert after_state is not None, "a tracked grant became untracked"

    @rule(fingerprint=grants, key=st.sampled_from(KEYS), ceiling=CEILINGS)
    def narrow(self, fingerprint, key, ceiling):
        self._attempt(
            fingerprint,
            self.aegis.narrow,
            key=key,
            reason=f"fuzz narrowing to {ceiling}",
            constraints={"amount_max": ceiling},
        )

    @rule(fingerprint=grants, key=st.sampled_from(KEYS))
    def suspend(self, fingerprint, key):
        self._attempt(
            fingerprint,
            self.aegis.suspend,
            key=key,
            reason="fuzz suspension",
        )

        # A suspension is the one restriction with a total effect, so it is
        # the one whose enforcement can be checked without knowing the
        # request. The store is read through the same helper the gate uses.
        assert self.aegis.suspended_in([fingerprint]) is not None

    @rule(ceiling=CEILINGS, amount=AMOUNTS)
    def a_fresh_suspension_denies_at_the_boundary(self, ceiling, amount):
        """Suspend a grant nothing else has touched, then ask.

        The rule above suspends whatever the bundle offers, which is often
        already revoked or already in refusal state -- and both of those
        gates run before ``_gate_aegis``, so the denial that comes back is
        somebody else's. This one issues its own root under a fresh agent
        id, so the only reason available is the Aegis one and the assertion
        is on the reason rather than merely on the refusal.

        It is also what keeps
        :meth:`TestTheSuiteItself.test_the_run_reaches_what_it_claims_to_fuzz`
        honest: without it, whether the run ever observed an Aegis-channel
        denial depended on the draw.
        """

        fingerprint = self._issue_root(ceiling)
        self.aegis.suspend(fingerprint, key="aegis:halt", reason="fuzz halt")

        outcome = self.sdk.authorize(
            self.capability[fingerprint],
            ACTION,
            {"amount": amount},
        )

        assert outcome.allowed is False
        assert outcome.reason.startswith("aegis_suspended"), outcome.reason
        REACHED[f"denial:{outcome.reason.split(':')[0]}"] += 1

    @rule(fingerprint=grants, key=st.sampled_from(KEYS))
    def lift(self, fingerprint, key):
        """Lift a restriction by name.

        The interesting direction: lifting is the only operation that can
        *raise* residual authority, and it may only raise it as far as
        ``REVALIDATING`` -- which carries none. Reaching ``ACTIVE`` needs an
        authorization to be observed. The ``residual`` invariant below is
        what makes that claim rather than this rule.
        """

        before = self.aegis.grant(fingerprint)
        removed = self.aegis.lift(fingerprint, key, reason="fuzz lift")

        assert isinstance(removed, tuple)

        if before is not None and before.terminal:
            after = self.aegis.grant(fingerprint)
            assert after.state is before.state, "a lift moved a terminal grant"

    @rule(fingerprint=grants)
    def begin_revalidation(self, fingerprint):
        self._attempt(
            fingerprint,
            self.aegis.begin_revalidation,
            reason="fuzz revalidation",
        )

    @rule(fingerprint=grants)
    def expire(self, fingerprint):
        self._attempt(fingerprint, self.aegis.expire, reason="fuzz expiry")

    @rule(fingerprint=grants)
    def mark_revoked(self, fingerprint):
        self._attempt(
            fingerprint,
            self.aegis.mark_revoked,
            reason="fuzz revocation",
        )

    @rule(fingerprint=grants)
    def revoke_at_the_registry(self, fingerprint):
        """The real revocation, which is the one the boundary enforces.

        ``mark_revoked`` above only latches Aegis state. This rule performs
        the revocation the registry owns, and records it in the model so
        every later ``authorize`` on the chain is obliged to deny.
        """

        try:
            self.sdk.revoke(self.capability[fingerprint], reason="fuzz")
        except AlreadyRevokedError:
            assert fingerprint in self.revoked
            return

        self.revoked.add(fingerprint)
        assert self.sdk.is_revoked(self.capability[fingerprint]) is True

        # Revocation binds the next request, not an eventual one. Asked
        # here rather than left to a later draw from the bundle, because the
        # window between revoking and next asking is exactly where a cached
        # chain or a stale envelope would hide -- and because leaving it to
        # chance made the revoked-chain oracle fire once per session
        # instead of once per revocation.
        self.authorize(fingerprint, 0)

    @rule(
        fingerprint=grants,
        first=st.integers(min_value=0, max_value=5),
        second=st.integers(min_value=0, max_value=5),
        ceiling=CEILINGS,
    )
    def attach_a_decay_schedule(self, fingerprint, first, second, ceiling):
        """Attach a schedule that is already due, so the sweep does something.

        Offsets are tiny and sorted: the constructor validates
        ``narrow_after <= suspend_after`` and a schedule dated in the future
        would make ``apply_decay`` a no-op for the length of the run.
        """

        grant = self.aegis.grant(fingerprint)
        assert grant is not None, "a bundled grant was not tracked"

        narrow_after, suspend_after = sorted((float(first), float(second)))
        schedule = DecaySchedule(
            narrow_after=narrow_after,
            suspend_after=suspend_after,
            constraints={"amount_max": ceiling},
            key="aegis:decay",
        )

        self.aegis.register(
            fingerprint,
            agent_id=grant.agent_id,
            capability=grant.capability,
            schedule=schedule,
        )

        # Re-registering must not reset state. A revoked grant that could be
        # re-registered into ``ISSUED`` would be resurrection with extra
        # steps, and attaching a schedule is a write path that touches the
        # same dictionary.
        assert self.aegis.grant(fingerprint).state is grant.state

    @rule()
    def apply_decay(self):
        """Run the sweep. Every record it returns must be subtractive.

        ``apply_decay`` swallows its own illegal transitions into
        ``failures``, so it cannot raise; what is checked is that no record
        reports a state change that gained authority.
        """

        for record in self.aegis.apply_decay():
            assert record.applied, "a decay record applied nothing"

            before, after = record.state_before, record.state_after

            if before is None or after is None:
                # An untracked schedule: no state to move, and the
                # restriction was still written. Enforcement does not
                # depend on the state having changed.
                continue

            assert (
                RESIDUAL_AUTHORITY[after] <= RESIDUAL_AUTHORITY[before]
            ), f"decay raised authority: {before} -> {after}"

    # ==================================================================
    # Analysis, which is never authority
    # ==================================================================

    @rule(fingerprint=grants, amount=AMOUNTS)
    def preflight(self, fingerprint, amount):
        """§6/§7: analysis may object, and may never be the thing that allows.

        Two properties, both of them the ones a reviewer would want checked
        against random state rather than a fixed scenario: an unsized impact
        can never reach ``ALLOW``, and an ``ALLOW`` can never be returned on
        stages that did not all establish their property. The second is what
        stops ``UNKNOWN`` from becoming ``SAFE`` by omission.
        """

        chain = self._chain(fingerprint)
        request = {"amount": amount}

        analysis = self.aegis.preflight(
            ACTION,
            request,
            fingerprints=chain,
            envelope=self.sdk.authority_envelope(self.capability[fingerprint]),
            blast=self.aegis.blast_radius(fingerprint),
        )

        with pytest.raises(TypeError):
            bool(analysis)

        if analysis.impact in (Impact.UNKNOWN, Impact.UNANALYZABLE):
            assert analysis.recommendation is not Recommendation.ALLOW, (
                f"{analysis.impact} reached ALLOW"
            )

        if analysis.recommendation is Recommendation.ALLOW:
            assert analysis.established is True
            assert analysis.impact in (Impact.LOW_IMPACT, Impact.BOUNDED)

        # A standing restriction is visible to analysis too. It has no
        # power to enforce -- the gate does that -- but it must not be
        # recommending an allow the gate is about to refuse.
        if self.aegis.restriction_reason(chain, ACTION, request) is not None:
            assert analysis.recommendation is not Recommendation.ALLOW

    @rule(fingerprint=grants)
    def blast_radius_is_bounded(self, fingerprint):
        radius = self.aegis.blast_radius(fingerprint)

        with pytest.raises(TypeError):
            bool(radius)

        # Reach is bounded by the estate, and an incomplete analysis says so
        # rather than reporting a small number as if it were the answer.
        assert radius.reach >= 0
        assert radius.reach <= len(self.capability) + 1

        if not radius.complete:
            assert radius.unanalyzable

    # ==================================================================
    # Invariants: re-checked after every single operation
    # ==================================================================

    @invariant()
    def terminal_states_are_terminal(self):
        """NO_AUTHORITY_RESURRECTION, checked across steps rather than within one.

        ``_attempt`` checks that one operation did not move a terminal
        grant. This checks that nothing *else* did either -- a decay sweep,
        a lift, an observed authorization, or a re-registration.
        """

        for fingerprint, grant in self.aegis.grants().items():
            REACHED[f"state:{grant.state.value}"] += 1

            if fingerprint in self.terminal_seen:
                assert grant.terminal is True, (
                    f"{fingerprint} left a terminal state"
                )
                assert grant.residual == 0

            if grant.terminal:
                assert grant.residual == 0
                self.terminal_seen.add(fingerprint)

    @invariant()
    def recorded_histories_are_legal(self):
        """AEGIS_STATE_TRANSITIONS at its source.

        The invariant check audits recorded histories as data; this reads
        the same accessor after every operation, so a run names the step
        that wrote the illegal edge instead of the sweep that noticed it.
        """

        assert self.aegis.history_findings() == ()

    @invariant()
    def both_store_reads_agree_about_suspension(self):
        """The two gates must not disagree about whether a grant is suspended.

        ``_gate_aegis`` reads ``restriction_reason``; the commit-time
        re-check reads ``suspended_in``. A suspension visible only to the
        second would pass the first gate and be caught after the
        cryptographic work; one visible only to the first would not be
        caught by the re-check at all.
        """

        for fingerprint in self.aegis.grants():
            if self.aegis.suspended_in([fingerprint]) is None:
                continue

            assert (
                self.aegis.restriction_reason(
                    [fingerprint],
                    ACTION,
                    {"amount": 0},
                )
                is not None
            ), f"{fingerprint} is suspended but no restriction reason was given"

    @invariant()
    def no_grant_is_a_boolean(self):
        """A grant is not a verdict, so it must refuse to be read as one."""

        for grant in self.aegis.grants().values():
            with pytest.raises(TypeError):
                bool(grant)
            break

    @invariant()
    def the_live_invariants_are_not_violated(self):
        """The five estate-auditing invariants, after every operation.

        ``VIOLATED`` fails; ``UNVERIFIABLE`` does not. A check that cannot
        establish its property on a given estate -- nothing revoked yet, no
        delegation yet -- has not found a violation, and treating its
        silence as failure would make the machine report its own coverage
        gaps as security findings. That the estate this machine builds is
        one the checks can actually verify is pinned separately, in
        :class:`TestTheSuiteItself`.
        """

        for check in LIVE_INVARIANTS:
            result = check(self.sdk)

            assert result.status is not InvariantStatus.VIOLATED, (
                f"{result.name}: {result.reason} {result.findings}"
            )


# ``deadline=None`` because the five estate-auditing invariants run after
# every step and their cost grows with the estate, so a per-step deadline
# would fail on estate size rather than on a property. The step count is
# bounded for the same reason: the interesting sequences are the ones that
# reach a terminal state and then keep operating, and those are short.
AegisEstateMachine.TestCase.settings = settings(
    max_examples=40,
    stateful_step_count=40,
    deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.filter_too_much,
        HealthCheck.data_too_large,
    ],
)

TestAegisEstate = AegisEstateMachine.TestCase


#: The coverage run's settings. ``derandomize=True`` where the search above
#: is deliberately random: a coverage assertion has to be a pin, and a pin
#: that depends on the seed is a flake waiting for a bad afternoon.
#:
#: ``database=None`` for the same reason, and it is the less obvious half.
#: With the example database enabled, ``derandomize`` still replays whatever
#: earlier runs left in ``.hypothesis/`` before generating anything, so the
#: sequences depend on what else has run in the working tree -- which showed
#: up as this file passing alone and failing in a full-suite session. No
#: database, no history, same run every time.
COVERAGE_SETTINGS = settings(
    max_examples=35,
    stateful_step_count=40,
    deadline=None,
    derandomize=True,
    database=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.filter_too_much,
        HealthCheck.data_too_large,
    ],
)


# ======================================================================
# The fuzzer's own assertions are not vacuous
# ======================================================================


class TestTheSuiteItself:
    """Two claims the machine makes about itself but cannot check itself.

    The per-step invariant accepts ``UNVERIFIABLE``, which is correct --
    a check with nothing to inspect has not found a violation -- but it
    means a bug that made all five checks permanently unverifiable would
    make the machine silently stop checking anything. So the estate shape
    the machine builds is verified once, here, to be one those checks can
    actually reach a verdict on.

    And the module docstring claims the other ten invariants are "checked
    elsewhere". This is elsewhere.
    """

    def test_the_estate_the_machine_builds_is_verifiable(self):
        """Every live check reaches HOLDS -- not UNVERIFIABLE -- on this shape.

        Built with the same operations the rules use: a root, a narrower
        child, a revocation, a narrowing, and an observed authorization. If
        a future change made one of these checks unverifiable on this
        estate, the per-step assertion would go quiet and this test is what
        notices.
        """

        sdk = FirewallSDK(aegis_enabled=True)
        try:
            private_key = sdk.generate_key(KEY_ID).private_key
            root = sdk.issue(
                agent="agent-1",
                capability=ACTION,
                constraints={"amount_max": 100},
            )
            child = sdk.delegate(
                root,
                private_key,
                delegatee="agent-2",
                constraints={"amount_max": 10},
            ).child
            doomed = sdk.issue(
                agent="agent-3",
                capability=ACTION,
                constraints={"amount_max": 5},
            )

            for capability, agent in (
                (root, "agent-1"),
                (child, "agent-2"),
                (doomed, "agent-3"),
            ):
                sdk.aegis.register(
                    sdk.fingerprint(capability),
                    agent_id=agent,
                    capability=ACTION,
                )

            assert sdk.authorize(child, ACTION, {"amount": 1}).allowed is True
            sdk.revoke(doomed, reason="so revocation has something to audit")
            sdk.aegis.narrow(
                sdk.fingerprint(root),
                key="aegis:ceiling",
                reason="so the state machine has an edge to audit",
                constraints={"amount_max": 50},
            )

            statuses = {
                check(sdk).name: check(sdk).status for check in LIVE_INVARIANTS
            }

            assert statuses, "no live invariant ran"
            for name, status in statuses.items():
                assert status is InvariantStatus.HOLDS, (name, status)
        finally:
            sdk.close()

    def test_the_scratch_estate_invariants_hold(self):
        """The four that build their own probes, run once rather than per step.

        They are independent of anything the machine does -- each builds a
        fresh SDK -- so running them inside the machine would re-check a
        fixed grid up to five hundred times per session and prove nothing
        that this does not.
        """

        for check in (
            check_fail_closed,
            check_envelope_soundness,
            check_unknown_non_authorization,
            check_evidence_integrity,
        ):
            result = check()

            assert result.status is InvariantStatus.HOLDS, (
                f"{result.name}: {result.reason} {result.findings}"
            )

    def test_the_run_reaches_what_it_claims_to_fuzz(self):
        """The machine's assertions are one-directional, so coverage matters.

        Every assertion in this file fires only when the model says a denial
        is owed. A machine that drifted into never building a suspension,
        never revoking, and never asking for more than a ceiling allows
        would satisfy all of them while checking nothing -- the exact
        "decorative" failure §11 names.

        So this runs the machine on a fixed seed and asserts what the run
        actually reached: all seven Aegis states, all four denial obligations
        fired at least once, at least one allow to prove the estate is not
        simply dead, and a denial from each of the three enforcement
        channels -- signed constraints, the revocation registry, and the
        Aegis restriction store.

        It clears the counter first, so it does not matter whether
        ``TestAegisEstate`` ran before it.
        """

        REACHED.clear()
        run_state_machine_as_test(
            AegisEstateMachine,
            settings=COVERAGE_SETTINGS,
        )
        reached = dict(REACHED)

        states = {
            name.split(":", 1)[1]
            for name in reached
            if name.startswith("state:")
        }
        assert states == {state.value for state in AegisState}, states

        for oracle in (
            "over_ceiling",
            "revoked_chain",
            "suspended",
            "restricted",
        ):
            assert reached.get(f"oracle:{oracle}", 0) > 0, oracle

        assert reached.get("outcome:allowed", 0) > 0, (
            "the run never authorized anything, so every denial assertion "
            "in it was vacuous"
        )

        # One denial from each enforcement channel. Named rather than
        # counted: three distinct reasons that all came from the same gate
        # would look like coverage and would not be.
        assert reached.get("denial:constraint_denied", 0) > 0
        assert reached.get("denial:capability_revoked", 0) > 0
        assert any(
            name.startswith("denial:aegis_") and count > 0
            for name, count in reached.items()
        ), sorted(reached)
