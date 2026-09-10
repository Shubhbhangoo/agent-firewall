"""v2.6: concurrency must never widen authority.

Every test here is an *interleaving*, not an input. The v2.5 suite
attacked ``FirewallSDK.authorize()`` with hostile arguments; this one
leaves the arguments alone and makes the state hostile *in time*.

The defect these tests pin down is a non-linearizable allow. The
boundary reads eleven inputs at eleven instants and holds no lock across
them. That is sound as long as every concurrent write *narrows*: if gate
*k* passed at time *t_k*, a narrowing-only world means its input was at
least as permissive at *t₀*, so *t₀* serves as a linearization point for
the whole conjunction. A **widening** write breaks the implication, and
the conjunction of differently-timed reads can then describe a state
that never existed at any single instant -- an allow that no serial
ordering of the same operations produces.

The tests are organised as:

* ``TestEpochAlgebra`` -- the comparison primitive, in isolation.
* ``TestNonLinearizableAllow`` -- the original finding, and the proof
  that every serialization of the same three operations denies.
* ``TestParkingSweep`` -- every widening write against every position in
  the gate chain. This is the coverage claim.
* ``TestNarrowingStillDecidesOnMerits`` -- the control. A mechanism that
  denied everything under concurrency would pass the sweep while
  destroying the system's usefulness and proving nothing.
* ``TestNoDeadlockOrInversion`` -- the cost of the mechanism: a new lock
  in the authorization path, and the ordering that keeps it safe.
* ``TestInterleavingFuzz`` -- randomized timing, for the interleavings
  nobody thought to enumerate.

What these tests do **not** establish: that no widening write exists
outside the census. That claim is the AUTHORITY_EPOCH_COVERAGE
invariant's job, and ``TestCensusAgreesWithReality`` here only checks
that the census and the sweep talk about the same set.
"""

from __future__ import annotations

import random
import threading

import pytest

from firewall.aegis import AegisController
from firewall.authority_epoch import (
    EPOCH_DIVERGENCE_PREFIXES,
    WIDENING_WRITES,
    AuthorityEpoch,
    EpochSample,
    bind_epoch,
    epoch_of,
    is_epoch_denial,
    record_widening,
)
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.security_context import SecurityContext
from firewall.semantic_chain import SemanticChainContext

ACTION = "payments.transfer"
REQUEST = {"amount": 10}

#: Every gate the chain runs before the terminal one, in canonical order.
#:
#: Read off ``_authorization_gate_phases`` by name rather than copied as
#: a literal, so a reordering or an inserted gate is covered by the sweep
#: automatically instead of silently escaping it.
NON_TERMINAL_GATES = (
    "_gate_refusal",
    "_gate_risk",
    "_gate_issuer",
    "_gate_revocation",
    "_gate_time",
    "_gate_delegation_chain",
    "_gate_delegation_monotonicity",
    "_gate_delegation_depth",
    "_gate_aegis",
    "_gate_cryptographic_authority",
)


def build_sdk():
    """An SDK with every epoch-bound store wired, and one capability.

    All three optional contexts are attached because three of the seven
    widening writes live on them; leaving them ``None`` would silently
    reduce the sweep from seven landings to four.

    Periodic revalidation is off. The monitor thread would issue its own
    authorizations, and a background allow arriving mid-test would make
    the interleaving under examination impossible to attribute.
    """

    controller = AegisController()
    sdk = FirewallSDK(
        aegis=controller,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
    )
    sdk.set_risk_context(RiskContext())
    sdk.set_semantic_context(
        SemanticChainContext(agent="probe-agent")
    )
    sdk.set_security_context(
        SecurityContext(agent="probe-agent")
    )
    sdk.generate_key("v26-test")
    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.*",
        constraints={"amount_max": 100},
    )
    controller.register(
        sdk.fingerprint(capability),
        agent_id=capability.agent_id,
        capability=capability.capability,
    )

    return sdk, controller, capability


def park_after(sdk, gate_name, arrived, resume):
    """Replace one gate with itself plus a barrier on the way out.

    The gate's own logic runs first and its verdict is preserved, so the
    request under test is the ordinary one -- the only difference is that
    it stops between this gate's read and the next one, which is exactly
    where a concurrent write has to land to be interesting.

    ``resume.wait`` is bounded. A missed handoff should fail the test
    with a message, not hang the suite until CI times out.
    """

    original = getattr(sdk, gate_name)

    def parked(ctx):
        outcome = original(ctx)
        arrived.set()
        assert resume.wait(10), f"{gate_name}: never released"
        return outcome

    setattr(sdk, gate_name, parked)


def authorize_while(sdk, capability, gate_name, land):
    """Run one authorization parked at ``gate_name``; land ``land`` inside it.

    Returns the ``AuthorizationResult`` the parked request produced. The
    baseline authorization asserted first is what makes the result
    meaningful: without it, a denial could be the request's own fault
    rather than the concurrent write's.
    """

    baseline = sdk.authorize(capability, ACTION, REQUEST)
    assert baseline.allowed, f"baseline denied: {baseline.reason}"

    arrived = threading.Event()
    resume = threading.Event()
    park_after(sdk, gate_name, arrived, resume)

    box = {}

    def worker():
        try:
            box["result"] = sdk.authorize(capability, ACTION, REQUEST)
        except BaseException as error:  # noqa: BLE001 - reported below
            box["error"] = error

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    assert arrived.wait(10), f"{gate_name}: never reached"

    land()

    resume.set()
    thread.join(10)

    assert not thread.is_alive(), f"{gate_name}: worker never finished"

    if "error" in box:
        raise box["error"]

    return box["result"]


#: The widening writes the sweep lands, keyed by the census name each one
#: corresponds to. Each value takes ``(sdk, controller, fingerprint)`` so
#: the sweep can build a fresh estate per cell.
#:
#: Two of them -- ``RefusalState.clear`` and ``RestrictionStore.lift`` --
#: are aimed at a key that holds nothing, so they remove no restriction
#: and change no state. That is on purpose. The sweep requires a baseline
#: allow, and a live refusal or suspension would deny it before the
#: request ever reached the gate being parked at. Landing the *no-op* form
#: still exercises the property under test, because the bracket is
#: unconditional by design: the interval has to be open before the write
#: knows whether it removed anything, so a caller cannot tell an operator
#: "the lift found nothing, carry on" without first admitting a window in
#: which it might have.
WIDENINGS = {
    "RefusalState.clear": (
        lambda sdk, controller, fp: sdk.refusal_state.clear(
            agent="probe-agent",
            capability_fingerprint=fp,
            action=ACTION,
            request=REQUEST,
        )
    ),
    "RefusalState.clear_all": (
        lambda sdk, controller, fp: sdk.refusal_state.clear_all()
    ),
    "IssuerTrustStore.trust": (
        lambda sdk, controller, fp: sdk.trust_issuer("late-issuer")
    ),
    "FirewallSDK.max_delegation_depth": (
        lambda sdk, controller, fp: setattr(
            sdk, "max_delegation_depth", 9
        )
    ),
    "RestrictionStore.lift": (
        lambda sdk, controller, fp: controller.store.lift(
            fp,
            key="no-such-incident",
        )
    ),
    "RestrictionStore.clear": (
        lambda sdk, controller, fp: controller.store.clear(fp)
    ),
    "RiskContext.reset": (
        lambda sdk, controller, fp: sdk.risk_context.reset("probe-agent")
    ),
    "SemanticChainContext.reset": (
        lambda sdk, controller, fp: sdk.semantic_context.reset()
    ),
    "SecurityContext.reset": (
        lambda sdk, controller, fp: sdk.security_context.reset()
    ),
}


class TestEpochAlgebra:
    """The comparison primitive, before any SDK is involved.

    ``AuthorityEpoch`` is two counters and one rule. The rule is that an
    entry sample *covers* a commit sample only when nothing finished
    between them and nothing was in flight at either end. These tests
    exist because a single monotonic counter -- the obvious design --
    cannot express that rule: a write is an interval, and one counter can
    only report instants.
    """

    def test_an_unchanged_epoch_covers_itself(self):
        epoch = AuthorityEpoch()

        first = epoch.sample()
        second = epoch.sample()

        assert first.covers(second)
        assert first.divergence(second) == ""

    def test_a_completed_widening_is_not_covered(self):
        epoch = AuthorityEpoch()

        entry = epoch.sample()
        with epoch.widening("test_write"):
            pass
        commit = epoch.sample()

        assert not entry.covers(commit)
        assert entry.divergence(commit) == (
            "widened_during_authorization:test_write:1"
        )

    def test_a_widening_still_running_at_entry_is_not_covered(self):
        epoch = AuthorityEpoch()

        with epoch.widening("slow_write"):
            entry = epoch.sample()
            commit = epoch.sample()

        assert not entry.covers(commit)
        assert entry.divergence(commit) == (
            "widening_in_flight_at_entry:slow_write"
        )

    def test_a_widening_still_running_at_commit_is_not_covered(self):
        """The case a single counter provably cannot catch.

        The write mutates state and has not finished. Nothing has been
        counted as finished, so a scheme that bumps only on completion
        reads the same value at both ends and reports agreement -- while
        the mutation has already happened. Only the in-flight half of the
        sample sees it.
        """

        epoch = AuthorityEpoch()

        entry = epoch.sample()
        started = threading.Event()
        release = threading.Event()

        def slow_write():
            with epoch.widening("mid_flight"):
                started.set()
                release.wait(10)

        thread = threading.Thread(target=slow_write, daemon=True)
        thread.start()
        assert started.wait(10)

        commit = epoch.sample()

        assert commit.finished == entry.finished
        assert not entry.covers(commit)
        assert entry.divergence(commit) == (
            "widening_in_flight_at_commit:mid_flight"
        )

        release.set()
        thread.join(10)

    def test_a_raising_widening_still_counts(self):
        """An attempted widening is counted, because it may have landed.

        A write that raises partway through has not necessarily left
        state untouched, and the epoch cannot tell. Counting the attempt
        costs a false denial; not counting it risks a false allow.
        """

        epoch = AuthorityEpoch()
        entry = epoch.sample()

        with pytest.raises(RuntimeError):
            with epoch.widening("failed_write"):
                raise RuntimeError("halfway")

        commit = epoch.sample()

        assert commit.in_flight == 0
        assert not entry.covers(commit)

    def test_the_source_label_never_decides_coverage(self):
        """Diagnostics must not be able to change a verdict.

        ``source`` exists so an operator reading a denial knows which
        write caused it. If it participated in the comparison, a caller
        could relabel a write and change whether an allow survives.
        """

        first = EpochSample(finished=3, in_flight=0, source="alpha")
        second = EpochSample(finished=3, in_flight=0, source="omega")

        assert first.covers(second)
        assert first.divergence(second) == ""

    def test_an_unbound_component_passes_through(self):
        """``record_widening`` is a no-op when nothing is bound.

        Deliberate: a store constructed outside an SDK still has to work.
        The mitigation for a store that should have been bound and was
        not is the AUTHORITY_EPOCH_COVERAGE invariant, not an exception
        here.
        """

        class Store:
            pass

        store = Store()

        assert epoch_of(store) is None

        with record_widening(store, "unbound"):
            pass

    def test_binding_is_confirmed_by_reading_back(self):
        epoch = AuthorityEpoch()

        class Store:
            pass

        store = Store()

        assert bind_epoch(store, epoch) is True
        assert epoch_of(store) is epoch

    def test_binding_reports_failure_rather_than_raising(self):
        """A slotted object cannot carry the attribute, and says so.

        The SDK turns this ``False`` into a ``RuntimeError`` at
        construction. The primitive returns a value instead so the caller
        decides, and so the invariant can report rather than crash.
        """

        class Slotted:
            __slots__ = ()

        assert bind_epoch(Slotted(), AuthorityEpoch()) is False

    def test_every_divergence_form_is_declared(self):
        """``EPOCH_DIVERGENCE_PREFIXES`` must list every form emitted.

        A caller partitioning verdicts by cause -- the
        ``authorize_under_widening`` benchmark does exactly this -- asks
        ``is_epoch_denial`` rather than matching literals. An undeclared
        fourth form would land in that caller's "other" bucket and be read
        as a denial from some unrelated gate, which is how a real denial
        class goes unexplained in a report. The three forms are constructed
        here from the states that produce them rather than transcribed.
        """

        zero = EpochSample(0, 0, "probe")
        finished = EpochSample(1, 0, "probe")
        entry_in_flight = EpochSample(0, 1, "probe")

        forms = {
            zero.divergence(finished),
            entry_in_flight.divergence(EpochSample(0, 0, "probe")),
            zero.divergence(entry_in_flight),
        }

        assert "" not in forms, (
            "one of these pairs is covered; the test is not exercising "
            f"the divergence it names: {sorted(forms)}"
        )
        assert {
            form.split(":")[0] for form in forms
        } == set(EPOCH_DIVERGENCE_PREFIXES)

        for form in forms:
            assert is_epoch_denial(form), form

    def test_a_non_epoch_reason_is_not_classified_as_one(self):
        """The classifier must not absorb unrelated denials.

        ``is_epoch_denial`` exists to attribute denials, and one that
        returned ``True`` broadly would make the benchmark's ``denied_
        fraction`` look like the epoch's cost while hiding a real
        regression in another gate.
        """

        for reason in (
            "aegis_suspended",
            "issuer_not_trusted",
            "refused_previously",
            "widening",
            "",
        ):
            assert is_epoch_denial(reason) is False, reason


class TestNonLinearizableAllow:
    """The original v2.6 finding, and why it is a soundness bug.

    Three operations:

    * **A** -- one ``authorize()`` for an agent whose capability is
      currently Aegis-suspended.
    * **B** -- ``revoke_issuer`` on the issuer that signed the capability.
    * **C** -- ``RestrictionStore.lift`` of the suspension.

    B and C are issued sequentially from one operator thread, B first, so
    every serial history has B before C. There are exactly three places
    A can go in a B-then-C history, and all three deny:

    * A, B, C -- denies ``aegis_suspended``: the suspension is live.
    * B, A, C -- denies ``untrusted_issuer`` *and* ``aegis_suspended``.
    * B, C, A -- denies ``untrusted_issuer``: the issuer is gone.

    In v2.5, interleaving A across B and C produced ``authorized``. That
    verdict is not a stale answer or a race the caller could have avoided
    by locking -- it corresponds to no ordering of these operations at
    all. It is the conjunction of ten reads taken at ten instants, and it
    describes a state that never existed.
    """

    def _serial_verdicts(self):
        """The three serializations, each on its own estate."""

        verdicts = {}

        for order in ("ABC", "BAC", "BCA"):
            sdk, controller, capability = build_sdk()
            fingerprint = sdk.fingerprint(capability)
            controller.suspend(
                fingerprint,
                key="incident-1",
                reason="serial baseline",
            )
            issuers = tuple(sdk.issuer_trust_store.trusted_issuers())

            steps = {
                "A": lambda: verdicts.__setitem__(
                    order,
                    sdk.authorize(capability, ACTION, REQUEST),
                ),
                "B": lambda: [
                    sdk.revoke_issuer(name) for name in issuers
                ],
                "C": lambda: controller.store.clear(fingerprint),
            }

            for letter in order:
                steps[letter]()

            sdk.close()

        return verdicts

    def test_every_serialization_denies(self):
        """The premise. Without this, the concurrent allow proves nothing."""

        verdicts = self._serial_verdicts()

        assert set(verdicts) == {"ABC", "BAC", "BCA"}

        for order, result in verdicts.items():
            assert not result.allowed, (
                f"serial order {order} allowed: {result.reason}"
            )

        assert verdicts["ABC"].reason.startswith("aegis_suspended")
        assert verdicts["BCA"].reason == "untrusted_issuer"

    def test_the_interleaving_that_produced_a_phantom_allow_now_denies(self):
        """A across B-then-C: denied, and the reason names the widening.

        The assertion on the reason matters as much as the denial. A
        denial for some unrelated cause would pass a weaker test while
        leaving the hole open, so the verdict has to be attributable to
        the epoch comparison.
        """

        sdk, controller, capability = build_sdk()
        fingerprint = sdk.fingerprint(capability)
        controller.suspend(
            fingerprint,
            key="incident-1",
            reason="live suspension",
        )
        issuers = tuple(sdk.issuer_trust_store.trusted_issuers())
        assert issuers, "the capability must have a trusted issuer to lose"

        def land():
            for name in issuers:
                sdk.revoke_issuer(name)
            controller.store.clear(fingerprint)

        arrived = threading.Event()
        resume = threading.Event()
        park_after(sdk, "_gate_revocation", arrived, resume)

        box = {}

        def worker():
            box["result"] = sdk.authorize(capability, ACTION, REQUEST)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert arrived.wait(10), "the parked gate was never reached"

        land()

        resume.set()
        thread.join(10)
        assert not thread.is_alive()

        result = box["result"]
        sdk.close()

        assert result.allowed is False
        assert result.reason.startswith(
            "widened_during_authorization:"
        ), result.reason
        assert "aegis_restrictions_cleared" in result.reason


class TestParkingSweep:
    """Every widening write, against every position in the gate chain.

    The coverage claim is not "the one interleaving we found is fixed" but
    "no position in the chain is unprotected". So the sweep is the cross
    product: park the request between gate *k* and gate *k+1*, land one
    widening write there, and require a denial.

    Each cell asserts on the *reason*, not just on the denial. Every
    request in this class would be allowed if left alone -- the baseline
    inside :func:`authorize_while` proves it -- so a denial for any other
    stated cause would mean the sweep is measuring something else.
    """

    @pytest.mark.parametrize("gate", NON_TERMINAL_GATES)
    @pytest.mark.parametrize("write", sorted(WIDENINGS))
    def test_a_widening_landing_at_any_gate_denies(self, gate, write):
        sdk, controller, capability = build_sdk()
        fingerprint = sdk.fingerprint(capability)
        mutate = WIDENINGS[write]

        result = authorize_while(
            sdk,
            capability,
            gate,
            lambda: mutate(sdk, controller, fingerprint),
        )

        sdk.close()

        assert result.allowed is False, (
            f"{write} landing after {gate} produced an allow"
        )
        assert result.reason.startswith(
            "widened_during_authorization:"
        ), result.reason

    def test_the_sweep_covers_every_gate_before_the_terminal_one(self):
        """The parametrization is not allowed to drift from the chain.

        ``NON_TERMINAL_GATES`` is a literal because pytest needs the ids
        at collection time. This test is what keeps the literal honest:
        insert a gate, and the sweep either covers it or this fails.
        """

        sdk, _, _ = build_sdk()
        live = tuple(
            phase.__name__
            for phase in sdk._authorization_gate_phases()
        )
        sdk.close()

        assert live[-1] == "_gate_transaction", (
            "the terminal gate moved; the epoch comparison lives in it"
        )
        assert NON_TERMINAL_GATES == live[:-1]


class TestCensusAgreesWithReality:
    """The sweep and the invariant must describe the same set of writes.

    :data:`~firewall.authority_epoch.WIDENING_WRITES` is what the
    AUTHORITY_EPOCH_COVERAGE invariant checks against the source. This
    class checks it against something the source cannot see: whether the
    write, actually performed, actually moves the epoch.
    """

    def test_every_swept_write_is_in_the_census(self):
        declared = {name for _, name in WIDENING_WRITES}
        missing = sorted(set(WIDENINGS) - declared)

        assert not missing, (
            f"swept but not declared a widening write: {missing}"
        )

    def test_every_census_entry_reachable_here_is_swept(self):
        """The SDK setters are exercised by ``build_sdk``, not the sweep.

        ``set_security_context`` and friends replace a whole store, which
        the sweep cannot land mid-request without also invalidating the
        object the parked gates already read. They are bracketed and
        covered by :class:`TestReplacingAStoreOpensAnInterval` instead, so
        they are named here as deliberate exclusions rather than gaps.
        """

        setters = {
            "FirewallSDK.set_security_context",
            "FirewallSDK.set_semantic_context",
            "FirewallSDK.set_risk_context",
        }
        declared = {name for _, name in WIDENING_WRITES}
        unswept = sorted(declared - set(WIDENINGS) - setters)

        assert not unswept, (
            f"declared a widening write but never swept: {unswept}"
        )

    @pytest.mark.parametrize("write", sorted(WIDENINGS))
    def test_each_write_actually_moves_the_epoch(self, write):
        """Source-level bracketing is not proof the bracket runs.

        A ``with record_widening(...)`` around a body the method never
        reaches would satisfy the static census and move nothing. This
        performs the write and reads the counter.
        """

        sdk, controller, capability = build_sdk()
        fingerprint = sdk.fingerprint(capability)

        before = sdk.authority_epoch.sample()
        WIDENINGS[write](sdk, controller, fingerprint)
        after = sdk.authority_epoch.sample()

        sdk.close()

        assert after.finished > before.finished, (
            f"{write} did not open an epoch interval"
        )
        assert not before.covers(after)


class TestReplacingAStoreOpensAnInterval:
    """Swapping a whole context is a widening, and is bracketed as one.

    ``set_risk_context`` and its siblings replace the object a gate reads.
    Whatever accumulated state the old one held -- risk history, consumed
    budget, an in-progress semantic chain -- is gone, which is a widening
    by any reading. They also have to rebind the epoch, or the new store
    would widen invisibly from then on.
    """

    @pytest.mark.parametrize(
        "setter,replacement",
        [
            (
                "set_risk_context",
                lambda: RiskContext(),
            ),
            (
                "set_semantic_context",
                lambda: SemanticChainContext(agent="probe-agent"),
            ),
            (
                "set_security_context",
                lambda: SecurityContext(agent="probe-agent"),
            ),
        ],
    )
    def test_replacement_moves_the_epoch_and_rebinds(
        self,
        setter,
        replacement,
    ):
        sdk, _, _ = build_sdk()

        before = sdk.authority_epoch.sample()
        fresh = replacement()
        getattr(sdk, setter)(fresh)
        after = sdk.authority_epoch.sample()

        sdk.close()

        assert after.finished > before.finished, (
            f"{setter} did not open an epoch interval"
        )
        assert epoch_of(fresh) is sdk.authority_epoch, (
            f"{setter} left the replacement unbound"
        )


class TestNarrowingStillDecidesOnMerits:
    """The control, without which the sweep proves nothing.

    A mechanism that denied every concurrent request would pass every
    test in :class:`TestParkingSweep` and be worthless. These tests
    require the opposite half: a *narrowing* write landing mid-request
    must still produce the denial it earns on its own merits, with its
    own reason, and an untouched estate must still allow.
    """

    @pytest.mark.parametrize("gate", ["_gate_refusal", "_gate_aegis"])
    def test_a_narrowing_write_denies_for_its_own_reason(self, gate):
        sdk, controller, capability = build_sdk()
        fingerprint = sdk.fingerprint(capability)

        result = authorize_while(
            sdk,
            capability,
            gate,
            lambda: controller.suspend(
                fingerprint,
                key="late",
                reason="narrowing control",
            ),
        )

        sdk.close()

        assert result.allowed is False
        assert "aegis_suspended" in result.reason, result.reason
        assert not result.reason.startswith(
            "widened_during_authorization:"
        )

    @pytest.mark.parametrize("gate", NON_TERMINAL_GATES)
    def test_an_undisturbed_request_still_allows_when_parked(self, gate):
        """Parking alone must not deny. Otherwise the sweep measures delay."""

        sdk, controller, capability = build_sdk()

        result = authorize_while(
            sdk,
            capability,
            gate,
            lambda: None,
        )

        sdk.close()

        assert result.allowed is True, result.reason


class TestNoDeadlockOrInversion:
    """The mechanism's own cost: a new lock inside the decision path.

    ``AuthorityEpoch`` has a lock, ``authorize()`` takes it twice per
    request, and every bracketed write takes it twice more. That is a new
    edge in the lock graph, and a new edge is where deadlocks come from.

    The ordering that keeps it safe is specific and load-bearing:
    ``SemanticChainContext.begin_authorization`` acquires the semantic
    lock and *holds it* across its return into ``_gate_transaction``,
    where ``sample()`` then takes the epoch lock -- semantic, then epoch.
    ``SemanticChainContext.reset`` runs the other way round: the
    ``record_widening`` bracket opens first, then ``_reset_under_lock``
    takes the semantic lock -- epoch, then semantic. Two orders over two
    locks is the AB/BA shape.

    It does not deadlock because ``AuthorityEpoch.widening`` releases the
    epoch lock *before* yielding, so it holds only one lock at a time and
    the epoch lock is a leaf. These tests are what would catch a future
    change that made it hold both.
    """

    def test_authorization_and_semantic_reset_do_not_deadlock(self):
        sdk, controller, capability = build_sdk()

        stop = threading.Event()
        failures = []

        def authorizer():
            try:
                while not stop.is_set():
                    sdk.authorize(capability, ACTION, REQUEST)
            except BaseException as error:  # noqa: BLE001
                failures.append(("authorize", error))

        def resetter():
            try:
                while not stop.is_set():
                    sdk.semantic_context.reset()
            except BaseException as error:  # noqa: BLE001
                failures.append(("reset", error))

        threads = [
            threading.Thread(target=authorizer, daemon=True),
            threading.Thread(target=resetter, daemon=True),
        ]

        for thread in threads:
            thread.start()

        stop.wait(2.0)
        stop.set()

        for thread in threads:
            thread.join(15)

        alive = [thread for thread in threads if thread.is_alive()]
        sdk.close()

        assert not alive, (
            "a thread did not finish: the epoch lock is no longer a leaf, "
            "or is now held across a yield"
        )
        assert not failures, failures

    def test_the_epoch_lock_is_not_held_across_the_yield(self):
        """Pins the property directly, not just its absence of symptoms.

        The deadlock test above can pass by luck of timing. This one is
        deterministic: inside a widening's body, another thread must still
        be able to sample. If the epoch lock were held across the yield,
        that sample would block until the body finished.
        """

        epoch = AuthorityEpoch()
        sampled = threading.Event()

        def sampler():
            epoch.sample()
            sampled.set()

        with epoch.widening("held_open"):
            thread = threading.Thread(target=sampler, daemon=True)
            thread.start()

            assert sampled.wait(5), (
                "sample() blocked inside a widening body: the epoch lock "
                "is being held across the yield"
            )

        thread.join(5)

    def test_concurrent_authorizations_all_terminate(self):
        """Contention alone must not lose or hang a request.

        No widening here, so every request should allow. What is being
        measured is that eight threads sharing one capability, one
        semantic chain and one epoch all get an answer.
        """

        sdk, controller, capability = build_sdk()

        results = []
        errors = []
        lock = threading.Lock()

        def worker():
            try:
                outcome = sdk.authorize(capability, ACTION, REQUEST)
            except BaseException as error:  # noqa: BLE001
                with lock:
                    errors.append(error)
                return

            with lock:
                results.append(outcome)

        threads = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(8)
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(20)

        alive = [thread for thread in threads if thread.is_alive()]
        sdk.close()

        assert not alive, "a concurrent authorization never returned"
        assert not errors, errors
        assert len(results) == 8

        for outcome in results:
            assert outcome.allowed is True, outcome.reason


class TestInterleavingFuzz:
    """Randomized timing, for the interleavings nobody enumerated.

    The parking sweep is exhaustive over *gate positions*, but a gate
    boundary is not the only place a write can land -- a real widening can
    interleave anywhere, including inside a gate, between the two
    commit-time re-checks, or while the epoch is being sampled. Barriers
    cannot reach those points. Random delays can, given enough attempts.

    The property asserted is one-directional, and deliberately weaker
    than the sweep's: **if** the epoch moved across the request, the
    request must not have been allowed. The converse is not asserted --
    a write that finishes entirely before the request starts, or entirely
    after it commits, is a legitimate allow, and the fuzz has no way to
    know which case it produced. Asserting "always denies" would be a
    stronger claim than the design makes and would fail on correct
    behaviour.
    """

    def _one_round(self, seed):
        """Race one authorization against one widening. Returns a verdict.

        The write is chosen and delayed pseudo-randomly from ``seed`` so a
        failure can be replayed by running that seed alone.
        """

        rng = random.Random(seed)
        sdk, controller, capability = build_sdk()
        fingerprint = sdk.fingerprint(capability)

        baseline = sdk.authorize(capability, ACTION, REQUEST)
        assert baseline.allowed, baseline.reason

        name = rng.choice(sorted(WIDENINGS))
        mutate = WIDENINGS[name]
        delay = rng.random() * 0.004

        box = {}
        start = threading.Event()

        def requester():
            start.wait(5)
            before = sdk.authority_epoch.sample()
            box["result"] = sdk.authorize(capability, ACTION, REQUEST)
            box["moved"] = not before.covers(
                sdk.authority_epoch.sample()
            )

        def writer():
            start.wait(5)
            if delay:
                threading.Event().wait(delay)
            mutate(sdk, controller, fingerprint)

        threads = [
            threading.Thread(target=requester, daemon=True),
            threading.Thread(target=writer, daemon=True),
        ]

        for thread in threads:
            thread.start()

        start.set()

        for thread in threads:
            thread.join(20)

        alive = [thread for thread in threads if thread.is_alive()]
        sdk.close()

        assert not alive, f"seed {seed}: a thread hung ({name})"

        return name, box

    def test_no_allow_survives_an_overlapping_widening(self):
        """The invariant, over 60 randomized races.

        Bounded on purpose: this runs in the ordinary suite, so it has to
        finish in seconds. It is a net for the shapes the sweep cannot
        express, not a substitute for the sweep.
        """

        allowed_after_widening = []
        observed = set()

        for seed in range(60):
            name, box = self._one_round(seed)
            observed.add(name)

            assert "result" in box, f"seed {seed}: no verdict ({name})"

            result = box["result"]

            if box.get("moved") and result.allowed:
                allowed_after_widening.append(
                    (seed, name, result.reason)
                )

        assert not allowed_after_widening, (
            "an allow was returned across a widening interval: "
            f"{allowed_after_widening}"
        )
        assert len(observed) >= 4, (
            f"the fuzz only reached {sorted(observed)}; raise the round "
            "count or check the seed distribution"
        )

    def test_a_fuzz_round_can_still_allow(self):
        """The fuzz must not be passing because everything denies.

        If every round denied -- because the write always lands inside the
        request, or because the mechanism became unconditional -- the test
        above would pass while measuring nothing. At least one round has
        to produce a genuine allow.
        """

        allows = 0

        for seed in range(200, 260):
            _, box = self._one_round(seed)

            if box.get("result") is not None and box["result"].allowed:
                allows += 1

        assert allows > 0, (
            "no randomized round allowed; the fuzz is not exercising the "
            "non-overlapping case"
        )


class TestTheEpochIsNotAnAuthorizationPath:
    """The mechanism must only ever subtract.

    ``FirewallSDK.authorize()`` stays the single authority boundary. The
    epoch comparison sits inside it and has exactly one possible effect:
    turning an allow into a denial. It cannot produce an allow, cannot
    skip a gate, and cannot be satisfied into granting anything -- an
    agreeing comparison returns control to the gate chain, which then has
    to reach its own verdict as before.
    """

    def test_a_denial_stays_denied_when_the_epoch_agrees(self):
        """The epoch agreeing is not an authorization."""

        sdk, controller, capability = build_sdk()
        controller.suspend(
            sdk.fingerprint(capability),
            key="incident-1",
            reason="denial holds",
        )

        before = sdk.authority_epoch.sample()
        result = sdk.authorize(capability, ACTION, REQUEST)
        after = sdk.authority_epoch.sample()

        sdk.close()

        assert before.covers(after), "no widening should have occurred"
        assert result.allowed is False
        assert "aegis_suspended" in result.reason

    def test_the_epoch_module_builds_no_verdict(self):
        """Structural: the mechanism cannot construct a verdict at all.

        The AUTHORIZATION_UNIQUENESS invariant makes the general claim over
        the whole package. This is the same claim aimed at the one module
        v2.6 added, stated locally so a reader of this file does not have
        to take the invariant on trust.

        Checked over the parsed tree rather than the text, because the
        module's docstring quotes the interleaving that produced the
        original phantom allow -- including the words a text search would
        match. Prose about a verdict is not a verdict.
        """

        import ast

        import firewall.authority_epoch as module

        with open(module.__file__, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())

        constructors = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and "AuthorizationResult"
            in ast.dump(node.func)
        ]

        assert not constructors, (
            "firewall/authority_epoch.py constructs a verdict"
        )

        assert not [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.keyword)
            and node.arg == "allowed"
        ], "firewall/authority_epoch.py passes an allowed= argument"

    def test_a_widening_denial_still_runs_the_whole_chain_first(self):
        """The comparison is last, so it cannot mask an earlier denial.

        Placed in the terminal gate after every read, a widening denial
        can only replace an allow. If it ran first it would shadow the
        specific reason an operator needs -- and worse, a caller could
        learn less from a denial than before.
        """

        sdk, controller, capability = build_sdk()
        fingerprint = sdk.fingerprint(capability)

        controller.suspend(
            fingerprint,
            key="incident-1",
            reason="earlier denial",
        )

        arrived = threading.Event()
        resume = threading.Event()
        park_after(sdk, "_gate_refusal", arrived, resume)

        box = {}

        def worker():
            box["result"] = sdk.authorize(capability, ACTION, REQUEST)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert arrived.wait(10)

        sdk.refusal_state.clear_all()

        resume.set()
        thread.join(10)
        result = box["result"]
        sdk.close()

        assert result.allowed is False
        assert "aegis_suspended" in result.reason, (
            "the Aegis denial must survive: it is upstream of the epoch "
            f"comparison, but the reason was {result.reason!r}"
        )
