"""v2.4 §12: what survives two things happening at once.

Every test here runs real threads against one ``FirewallSDK`` and asserts a
*safety* property, never a timing one. A concurrency test that asserts an
ordering tests the scheduler; a concurrency test that asserts an invariant
tests the system. So the shape is always the same: let the operations race
under a barrier, collect every outcome, and then check the claims that must
hold no matter which interleaving occurred.

The claims, in the order the mission lists the races:

* ``authorize`` + ``revoke`` -- once a revocation is committed, no later
  request is allowed, and no request raises.
* ``authorize`` + ``delegate`` -- minting a child changes no decision about
  the parent.
* ``authorize`` + budget consumption -- the cumulative total never exceeds
  the ceiling, and the number of allows is exactly the number the ceiling
  pays for. This is the one race where an off-by-one is spend.
* ``revalidate`` + ``revoke`` -- ``REVOKED`` is terminal under contention
  too; a revalidation cannot lift a grant back out of it.
* ``revalidate`` + policy change -- withdrawing issuer trust mid-flight
  denies rather than raising.
* ``delegate`` + revoke parent -- a child minted while its parent is being
  revoked is never usable.
* many simultaneous ``execute`` calls -- restrictions dedupe, the state
  settles once, and the recorded history stays auditable.
* ``observe_authorization`` + ``narrow`` -- the Aegis-specific race. A grant
  carrying an enforced restriction is never left in ``ACTIVE``, which is
  the state ``state.py`` defines as "a canonical allow, no restriction".

``ITERATIONS`` is deliberately modest. These tests are not a search for
rare interleavings -- ``tests/test_v2_4_aegis_fuzz.py`` does that job with
randomized operation sequences. Here each race is named, and the point is
that the named race has a checked post-condition at all.
"""

from __future__ import annotations

import threading
import time

import pytest

from firewall.aegis.state import AegisState, IllegalTransition
from firewall.sdk import FirewallSDK

#: Threads per race. Enough to interleave on a real scheduler, small
#: enough that the file stays a second or two.
THREADS = 8
#: Requests per thread in the loops that hammer the boundary.
ITERATIONS = 12

KEY_ID = "concurrency-key"


def _run(workers) -> None:
    """Start every worker at the same barrier, then join them all.

    The barrier matters: threads started in a loop tend to finish in the
    order they were started, which is the one interleaving that proves the
    least.
    """

    barrier = threading.Barrier(len(workers))
    threads = []

    def wrapped(worker):
        def run():
            barrier.wait()
            worker()

        return run

    for worker in workers:
        thread = threading.Thread(target=wrapped(worker))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive(), "a worker did not finish"


def _await(predicate, *, what: str, timeout: float = 20.0) -> None:
    """Block until ``predicate()`` holds, or fail the test saying why.

    Used where a race needs both sides of a change to be *observed* rather
    than merely likely. Sleeping for a while and hoping produces a test that
    passes for scheduling reasons, which is the failure mode this whole file
    is written to avoid; waiting on the condition itself makes the
    before-and-after claim airtight while leaving the overlap real.
    """

    deadline = time.monotonic() + timeout

    while not predicate():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        time.sleep(0.001)


@pytest.fixture
def sdk():
    instance = FirewallSDK(aegis_enabled=True)
    instance.generate_key(KEY_ID)
    yield instance
    instance.close()


def _issue(sdk, *, agent="agent-a", amount_max=100):
    return sdk.issue(
        agent=agent,
        capability="payments.send",
        constraints={"amount_max": amount_max},
    )


# ======================================================================
# authorize + revoke
# ======================================================================


class TestAuthorizeAgainstRevoke:
    def test_a_revocation_is_final_once_it_returns(self, sdk):
        """A request that provably *began* after the revoke returned denies.

        The claim is deliberately phrased around the start of the request
        rather than the order of the recorded outcomes. Appends happen after
        the boundary returns, so a thread that was allowed and then
        descheduled can record its allow after a later thread records its
        denial -- an ordering assertion over the list would fail for
        bookkeeping reasons rather than security ones. Sampling "had the
        revocation already completed when I called?" before each call gives a
        claim with no such ambiguity, and it is the stronger one: it forbids
        an allow from a request that started in the revoked world.
        """

        capability = _issue(sdk)
        outcomes: list = []
        errors: list = []
        lock = threading.Lock()
        revoked = threading.Event()
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                began_after_revocation = revoked.is_set()

                try:
                    result = sdk.authorize(
                        capability,
                        "payments.send",
                        {"amount": 10},
                    )
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return
                with lock:
                    outcomes.append(
                        (
                            result.allowed,
                            result.reason,
                            began_after_revocation,
                        )
                    )

        def counted(predicate):
            def check():
                with lock:
                    return predicate(list(outcomes))

            return check

        def revoke():
            # Both sides of the change are *observed*, not assumed: wait
            # until requests are genuinely in flight, revoke into them, then
            # hold the loops open until a denial has been seen.
            _await(
                counted(lambda seen: len(seen) >= THREADS),
                what="requests to be in flight",
            )
            sdk.revoke(capability, reason="concurrent revoke")
            revoked.set()
            _await(
                counted(
                    lambda seen: any(
                        after and reason == "capability_revoked"
                        for _, reason, after in seen
                    )
                ),
                what="a request begun after the revocation to be denied",
            )
            stop.set()

        _run([hammer] * (THREADS - 1) + [revoke])

        # No request raised: FAIL_CLOSED requires the gate to decide, and a
        # request racing a revocation is exactly where a half-updated store
        # would surface as an exception with no verdict.
        assert errors == []

        # Only two outcomes exist: the allow, and the revocation denial.
        # Nothing incidental leaked out of the race.
        assert {(allowed, reason) for allowed, reason, _ in outcomes} == {
            (True, "authorized"),
            (False, "capability_revoked"),
        }

        after_the_fact = [
            (allowed, reason)
            for allowed, reason, after in outcomes
            if after
        ]
        assert after_the_fact
        assert set(after_the_fact) == {(False, "capability_revoked")}

        # And the revocation holds afterwards, for every fresh request.
        for _ in range(ITERATIONS):
            late = sdk.authorize(
                capability,
                "payments.send",
                {"amount": 10},
            )

            assert late.allowed is False
            assert late.reason == "capability_revoked"

    def test_exactly_one_thread_wins_a_contested_revocation(self, sdk):
        """``revoke`` is not idempotent, and that is the safer choice.

        A second revocation raises :class:`AlreadyRevokedError` rather than
        returning quietly, so "I revoked this" is an unambiguous claim: the
        one caller that did not raise is the one that changed the state.
        Under contention that has to remain exactly one caller -- a registry
        that admitted two would either double-count the revocation or, worse,
        let a losing writer overwrite the winner's record.
        """

        from firewall.revocation import AlreadyRevokedError

        capability = _issue(sdk)
        winners: list = []
        losers: list = []
        unexpected: list = []
        lock = threading.Lock()

        def revoke():
            try:
                sdk.revoke(capability, reason="double revoke")
            except AlreadyRevokedError:
                with lock:
                    losers.append(True)
            except Exception as error:  # noqa: BLE001
                with lock:
                    unexpected.append(error)
            else:
                with lock:
                    winners.append(True)

        _run([revoke] * THREADS)

        assert unexpected == []
        assert len(winners) == 1
        assert len(losers) == THREADS - 1
        assert sdk.is_revoked(capability) is True


# ======================================================================
# authorize + delegate
# ======================================================================


class TestAuthorizeAgainstDelegate:
    def test_minting_children_changes_no_parent_decision(self, sdk):
        private_key = sdk.active_key().private_key
        parent = _issue(sdk)
        reasons: set = set()
        seen = 0
        errors: list = []
        lock = threading.Lock()

        def hammer():
            nonlocal seen

            for _ in range(ITERATIONS):
                try:
                    result = sdk.authorize(
                        parent,
                        "payments.send",
                        {"amount": 10},
                    )
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return
                with lock:
                    seen += 1
                    reasons.add((result.allowed, result.reason))

        def spawn():
            for index in range(ITERATIONS):
                try:
                    sdk.delegate(
                        parent,
                        private_key,
                        delegatee=f"agent-child-{index}",
                        constraints={"amount_max": 50},
                    )
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return

        _run([hammer] * (THREADS - 1) + [spawn])

        assert errors == []
        assert seen == (THREADS - 1) * ITERATIONS
        # Exactly one outcome, and it is the allow: delegation adds
        # authority *below* the parent and must not perturb it.
        assert reasons == {(True, "authorized")}

    def test_a_child_minted_under_contention_never_widens(self, sdk):
        private_key = sdk.active_key().private_key
        parent = _issue(sdk, amount_max=100)
        children: list = []
        errors: list = []
        lock = threading.Lock()

        def spawn():
            for index in range(ITERATIONS):
                try:
                    child = sdk.delegate(
                        parent,
                        private_key,
                        delegatee=(
                            f"agent-child-{threading.get_ident()}-{index}"
                        ),
                        constraints={"amount_max": 50},
                    ).child
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return
                with lock:
                    children.append(child)

        _run([spawn] * THREADS)

        assert errors == []
        assert len(children) == THREADS * ITERATIONS

        for child in children:
            # The signed ceiling is respected and the parent's is not
            # reachable through the child.
            assert (
                sdk.authorize(
                    child,
                    "payments.send",
                    {"amount": 50},
                ).allowed
                is True
            )
            assert (
                sdk.authorize(
                    child,
                    "payments.send",
                    {"amount": 100},
                ).allowed
                is False
            )


# ======================================================================
# authorize + budget consumption
# ======================================================================


class TestBudgetUnderContention:
    def test_the_ceiling_is_never_exceeded(self, sdk):
        """The race where an off-by-one is money.

        ``THREADS * ITERATIONS`` requests of 10 race against a ceiling of
        50. Exactly five may be allowed, the consumed total must land on 50
        exactly, and every refusal must name the budget rather than
        something incidental.
        """

        capability = _issue(sdk, amount_max=100)
        sdk.configure_delegation_budget(capability, max_total_amount=50.0)

        allowed: list = []
        denied: list = []
        errors: list = []
        lock = threading.Lock()

        def spend():
            for _ in range(ITERATIONS):
                try:
                    result = sdk.authorize_with_delegation_budget(
                        capability,
                        "payments.send",
                        {"amount": 10},
                    )
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return
                with lock:
                    (allowed if result.allowed else denied).append(
                        result.reason
                    )

        _run([spend] * THREADS)

        assert errors == []
        assert len(allowed) == 5, (len(allowed), sorted(set(denied)))
        assert sdk.delegation_budget_total(capability) == 50.0
        assert denied
        assert all("budget" in reason for reason in denied), sorted(
            set(denied)
        )

    def test_a_lineage_budget_is_shared_across_children(self, sdk):
        """Descendants consume the root's allowance, concurrently too.

        A per-child budget would let an agent multiply its spend by
        delegating, so the ceiling belongs to the lineage. Under
        contention that means the *sum* over all children is bounded, not
        each child separately.
        """

        private_key = sdk.active_key().private_key
        root = _issue(sdk, amount_max=100)
        sdk.configure_delegation_budget(root, max_total_amount=50.0)

        children = [
            sdk.delegate(
                root,
                private_key,
                delegatee=f"agent-child-{index}",
                constraints={"amount_max": 100},
            ).child
            for index in range(THREADS)
        ]

        allowed: list = []
        lock = threading.Lock()

        def spend(child):
            def run():
                for _ in range(ITERATIONS):
                    result = sdk.authorize_with_delegation_budget(
                        child,
                        "payments.send",
                        {"amount": 10},
                    )
                    if result.allowed:
                        with lock:
                            allowed.append(result.reason)

            return run

        _run([spend(child) for child in children])

        assert len(allowed) == 5
        assert sdk.delegation_budget_total(root) == 50.0


# ======================================================================
# revalidate + revoke, and revalidate + policy change
# ======================================================================


class TestRevalidateAgainstRevoke:
    def test_revoked_stays_revoked_under_contention(self, sdk):
        capability = _issue(sdk)
        fingerprint = sdk.fingerprint(capability)
        controller = sdk.aegis
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        refused: list = []
        lock = threading.Lock()

        def revalidate():
            for _ in range(ITERATIONS):
                try:
                    controller.begin_revalidation(
                        fingerprint,
                        reason="racing the revocation",
                    )
                except IllegalTransition as error:
                    # The expected loser: the grant latched REVOKED first,
                    # and a terminal state has no outgoing edge. Refusing
                    # loudly is the operator-path contract.
                    with lock:
                        refused.append(str(error))

        def revoke():
            try:
                controller.mark_revoked(fingerprint, reason="racing")
            except IllegalTransition:
                pass

        _run([revalidate] * (THREADS - 1) + [revoke])

        grant = controller.grant(fingerprint)

        assert grant.state is AegisState.REVOKED
        assert grant.terminal is True
        # Whatever order the threads ran in, the recorded history is a legal
        # walk -- this is the data AEGIS_STATE_TRANSITIONS audits.
        assert controller.history_findings() == ()
        # And every refusal named terminality rather than something vague.
        for message in refused:
            assert "terminal" in message

    def test_withdrawing_issuer_trust_mid_flight_denies(self, sdk):
        """Withdrawal denies whatever began after it and raises nothing ---
        but the *reason* is not single-valued, because a withdrawal is two
        writes.

        ``revoke_issuer`` updates the trust store and then refreshes the
        verifier's copy of it. A request already in flight can read the old
        trust store and the new verifier: it passes ``_gate_issuer`` and is
        refused further down by ``_gate_cryptographic_authority``, which
        reports a failed verification as ``invalid_signature`` even though
        the signature is intact and the issuer is what changed. Rare --- of
        the order of one request in a hundred thousand here --- and
        fail-closed whichever write lands first, so what follows pins the
        verdict exactly and *bounds* the reason, instead of pinning a reason
        set the scheduler can perturb.
        :meth:`test_the_two_writes_of_a_withdrawal_both_deny` builds that
        intermediate state directly rather than waiting for it.
        """

        sdk.trust_issuer("racing-issuer")
        capability = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
            issuer="racing-issuer",
        )

        outcomes: list = []
        errors: list = []
        lock = threading.Lock()
        withdrawn = threading.Event()
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                began_after_withdrawal = withdrawn.is_set()

                try:
                    result = sdk.authorize(
                        capability,
                        "payments.send",
                        {"amount": 10},
                    )
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return
                with lock:
                    outcomes.append(
                        (
                            result.allowed,
                            result.reason,
                            began_after_withdrawal,
                        )
                    )

        def counted(predicate):
            def check():
                with lock:
                    return predicate(list(outcomes))

            return check

        def withdraw():
            _await(
                counted(lambda seen: len(seen) >= THREADS),
                what="requests to be in flight",
            )
            sdk.revoke_issuer("racing-issuer")
            withdrawn.set()
            _await(
                counted(
                    lambda seen: any(
                        after and reason == "untrusted_issuer"
                        for _, reason, after in seen
                    )
                ),
                what="a request begun after the withdrawal to be denied",
            )
            stop.set()

        _run([hammer] * (THREADS - 1) + [withdraw])

        assert errors == []

        # Something was allowed. The withdrawal only fires once eight
        # requests have been served, so a regression that denied from the
        # very first call would otherwise satisfy every claim below by
        # having nothing to say.
        allowed_outcomes = [
            (allowed, reason)
            for allowed, reason, _ in outcomes
            if allowed
        ]

        assert allowed_outcomes, "no request was ever allowed"
        assert {reason for _, reason in allowed_outcomes} == {"authorized"}

        # The property: nothing that began after the withdrawal returned was
        # allowed. Exact here, because the trust-store write precedes
        # ``withdrawn.set()`` -- so ``_gate_issuer``, which reads the store,
        # is guaranteed to be the gate that refuses these.
        after_withdrawal = [
            (allowed, reason)
            for allowed, reason, after in outcomes
            if after
        ]

        assert after_withdrawal, "no request began after the withdrawal"
        assert all(allowed is False for allowed, _ in after_withdrawal)
        assert {reason for _, reason in after_withdrawal} == {
            "untrusted_issuer"
        }

        # And every denial named a fail-closed reason belonging to this
        # race. Bounded rather than exact: whether the two-write window is
        # observed at all is a scheduling matter, but what may appear in it
        # is not.
        assert {
            reason for allowed, reason, _ in outcomes if not allowed
        } <= {
            "untrusted_issuer",
            "invalid_signature",
        }

        late = sdk.authorize(capability, "payments.send", {"amount": 10})
        assert late.allowed is False
        assert late.reason == "untrusted_issuer"

    def test_the_two_writes_of_a_withdrawal_both_deny(self, sdk):
        """The intermediate state of a withdrawal, built rather than raced.

        ``revoke_issuer`` writes twice --- the trust store, then the
        verifier's copy --- without holding one lock across both, so a
        concurrent request can observe one write and not the other. Waiting
        for that window is a poor test: the sibling above hit it once in
        roughly a hundred and thirty thousand authorizations. Assigning the
        skew directly makes the fail-closed claim deterministic.

        Only one order is constructible: ``_gate_issuer`` reads the store
        and runs first, so a request whose issuer the store still trusts is
        the only one that can reach the verifier at all. The reverse skew
        --- verifier updated, store not --- cannot produce an allow, because
        the gate that would have to pass it is the one reading the stale
        permissive value and it denies on the *new* value only.

        Note also what the assertion on ``sdk.verifier.trusted_issuers``
        establishes: the set is non-empty in this state. An empty set means
        "do not check the issuer" to
        :meth:`firewall.capability.CapabilityVerifier`, so an emptied set
        would make the verifier permissive about issuers rather than
        strict. It is unreachable as a widening: the refresh copies the
        store, so an empty verifier set implies an empty store, and then
        ``_gate_issuer`` refuses first.
        """

        sdk.trust_issuer("racing-issuer")
        capability = sdk.issue(
            agent="agent-a",
            capability="payments.send",
            constraints={"amount_max": 100},
            issuer="racing-issuer",
        )

        baseline = sdk.authorize(capability, "payments.send", {"amount": 10})
        assert baseline.allowed is True

        # Half of a withdrawal: the verifier has caught up, the store has not.
        sdk.verifier.trusted_issuers = {
            issuer
            for issuer in sdk.verifier.trusted_issuers
            if issuer != "racing-issuer"
        }

        assert sdk.is_issuer_trusted("racing-issuer") is True
        assert sdk.verifier.trusted_issuers

        skewed = sdk.authorize(capability, "payments.send", {"amount": 10})

        assert skewed.allowed is False
        assert skewed.reason == "invalid_signature"

        # The whole withdrawal, which is the reason the gate exists.
        sdk.revoke_issuer("racing-issuer")

        settled = sdk.authorize(capability, "payments.send", {"amount": 10})

        assert settled.allowed is False
        assert settled.reason == "untrusted_issuer"


# ======================================================================
# delegate + revoke parent
# ======================================================================


class TestDelegateAgainstParentRevocation:
    def test_a_child_minted_during_its_parents_revocation_is_unusable(
        self, sdk
    ):
        """Revocation propagates to a child that did not exist when it ran.

        Effective revocation is derived from the lineage on every read
        rather than stamped onto descendants at revoke time, so a child
        minted a microsecond too late is still covered. Stamping would
        leave exactly this hole.
        """

        private_key = sdk.active_key().private_key
        parent = _issue(sdk)
        children: list = []
        errors: list = []
        lock = threading.Lock()

        def spawn():
            for index in range(ITERATIONS):
                try:
                    child = sdk.delegate(
                        parent,
                        private_key,
                        delegatee=(
                            f"agent-late-{threading.get_ident()}-{index}"
                        ),
                        constraints={"amount_max": 50},
                    ).child
                except Exception as error:  # noqa: BLE001
                    # Refusing to mint a child from a revoked parent would
                    # also be correct behaviour -- but it is not what this
                    # SDK does, and the test must not silently pass by way
                    # of an exception nobody looked at.
                    with lock:
                        errors.append(error)
                    return
                with lock:
                    children.append(child)

        def revoke():
            sdk.revoke(parent, reason="revoked mid-delegation")

        _run([spawn] * (THREADS - 1) + [revoke])

        assert errors == []
        assert len(children) == (THREADS - 1) * ITERATIONS

        for child in children:
            assert sdk.is_effectively_revoked(child) is True
            outcome = sdk.authorize(
                child,
                "payments.send",
                {"amount": 10},
            )
            assert outcome.allowed is False
            assert outcome.reason == "capability_revoked"


# ======================================================================
# Many simultaneous executions
# ======================================================================


class TestSimultaneousExecution:
    def test_the_same_response_executed_many_times_settles_once(self, sdk):
        from firewall.aegis.response import (
            AdaptiveResponse,
            Classification,
            Contribution,
        )

        capability = _issue(sdk)
        fingerprint = sdk.fingerprint(capability)
        controller = sdk.aegis
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        classification = Classification(
            response=AdaptiveResponse.SUSPEND,
            trigger="incident_opened",
            contributions=(
                Contribution(
                    rule="test",
                    response=AdaptiveResponse.SUSPEND,
                    detail="an incident was opened",
                ),
            ),
            state_changed=True,
            degraded=(),
            details={},
        )

        records: list = []
        lock = threading.Lock()

        def execute():
            for _ in range(ITERATIONS):
                record = controller.execute(fingerprint, classification)
                with lock:
                    records.append(record)

        _run([execute] * THREADS)

        assert len(records) == THREADS * ITERATIONS
        # No executor call reported a failure it did not have to.
        assert all(record.failures == () for record in records), [
            record.failures for record in records if record.failures
        ]

        # One restriction, not one per call: the store dedupes on what a
        # restriction *does*, so a retried response is not a leak.
        restrictions = controller.store.restrictions_for(fingerprint)
        assert len(restrictions) == 1
        assert restrictions[0].suspends is True

        grant = controller.grant(fingerprint)
        assert grant.state is AegisState.SUSPENDED
        # And the state moved exactly once, however many callers asked.
        assert len(grant.history) == 1
        assert controller.history_findings() == ()

    def test_the_suspension_is_enforced_at_the_boundary_afterwards(self, sdk):
        # The executor's job is only done if the boundary refuses.
        from firewall.aegis.response import (
            AdaptiveResponse,
            Classification,
            Contribution,
        )

        capability = _issue(sdk)
        fingerprint = sdk.fingerprint(capability)
        controller = sdk.aegis
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        def execute():
            controller.execute(
                fingerprint,
                Classification(
                    response=AdaptiveResponse.SUSPEND,
                    trigger="incident_opened",
                    contributions=(
                        Contribution(
                            rule="test",
                            response=AdaptiveResponse.SUSPEND,
                            detail="an incident was opened",
                        ),
                    ),
                    state_changed=True,
                    degraded=(),
                    details={},
                ),
            )

        def authorize():
            for _ in range(ITERATIONS):
                sdk.authorize(capability, "payments.send", {"amount": 10})

        _run([authorize] * (THREADS - 1) + [execute])

        outcome = sdk.authorize(capability, "payments.send", {"amount": 10})

        assert outcome.allowed is False
        assert outcome.reason.startswith("aegis_suspended")


# ======================================================================
# observe_authorization + narrow: the Aegis-specific race
# ======================================================================


class TestObservationAgainstNarrowing:
    def test_a_restricted_grant_is_never_left_active(self, sdk):
        """``ACTIVE`` means "allowed, and unrestricted". Both, always.

        The interleavings are all reachable: the allow can land before the
        narrowing writes, between its write and its state move, or after
        both. The write-then-move order in ``narrow`` is deliberate -- the
        restriction must be enforced even if the move is refused -- so this
        checks the pairing the order could have broken.
        """

        capability = _issue(sdk)
        fingerprint = sdk.fingerprint(capability)
        controller = sdk.aegis
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        errors: list = []
        lock = threading.Lock()

        def authorize():
            for _ in range(ITERATIONS):
                try:
                    sdk.authorize(
                        capability,
                        "payments.send",
                        {"amount": 1},
                    )
                except Exception as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    return

        def restrict():
            try:
                controller.narrow(
                    fingerprint,
                    key="aegis:race",
                    reason="narrowed while requests were in flight",
                    constraints={"amount_max": 5},
                )
            except IllegalTransition as error:
                with lock:
                    errors.append(error)

        _run([authorize] * (THREADS - 1) + [restrict])

        assert errors == []

        grant = controller.grant(fingerprint)
        restrictions = controller.store.restrictions_for(fingerprint)

        assert restrictions
        assert grant.state is AegisState.NARROWED
        assert controller.history_findings() == ()

    def test_a_suspension_wins_against_a_concurrent_allow(self, sdk):
        capability = _issue(sdk)
        fingerprint = sdk.fingerprint(capability)
        controller = sdk.aegis
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        def authorize():
            for _ in range(ITERATIONS):
                sdk.authorize(capability, "payments.send", {"amount": 1})

        def halt():
            controller.suspend(
                fingerprint,
                key="aegis:halt",
                reason="suspended while requests were in flight",
            )

        _run([authorize] * (THREADS - 1) + [halt])

        grant = controller.grant(fingerprint)

        assert grant.state is AegisState.SUSPENDED
        assert controller.suspended_in([fingerprint]) == fingerprint
        assert controller.history_findings() == ()
        # The boundary refuses now, whatever it decided while the race ran.
        assert (
            sdk.authorize(
                capability,
                "payments.send",
                {"amount": 1},
            ).allowed
            is False
        )


# ======================================================================
# §9: the timeline, in order
# ======================================================================


class TestContinuousOperation:
    """The §9 sequence, walked one step at a time.

    authority -> task start -> resource change -> delegation -> policy
    change -> parent revoked -> the agent finally attempts its action.

    Not a concurrency test: it is the *sequential* half of the same
    property. Every step re-asks the boundary and asserts what the state at
    that instant permits, because the mandate is that the final action is
    evaluated against the current authoritative state rather than against
    whatever was true when the task began. A system that cached its answer
    at task start would pass every step here except the last two.
    """

    def test_the_final_action_is_evaluated_against_current_state(self, sdk):
        controller = sdk.aegis
        private_key = sdk.active_key().private_key

        # 1. Authority exists.
        sdk.trust_issuer("timeline-issuer")
        parent = sdk.issue(
            agent="agent-worker",
            capability="payments.send",
            constraints={"amount_max": 100},
            issuer="timeline-issuer",
        )
        parent_fingerprint = sdk.fingerprint(parent)
        controller.register(
            parent_fingerprint,
            agent_id=parent.agent_id,
            capability=parent.capability,
        )

        # 2. The task starts: one successful action, which is what makes
        #    the grant ACTIVE rather than merely ISSUED.
        first = sdk.authorize(parent, "payments.send", {"amount": 10})
        assert first.allowed is True
        assert controller.grant(parent_fingerprint).state is AegisState.ACTIVE

        # 3. A resource changes. Aegis narrows; the boundary follows
        #    immediately, mid-task, with no re-issuance.
        controller.narrow(
            parent_fingerprint,
            key="aegis:resource",
            reason="the target account was reclassified",
            constraints={"amount_max": 20},
        )
        assert (
            sdk.authorize(parent, "payments.send", {"amount": 50}).allowed
            is False
        )
        assert (
            sdk.authorize(parent, "payments.send", {"amount": 10}).allowed
            is True
        )

        # 4. Delegation happens *under* a narrowed parent. The child's own
        #    signed ceiling is 100 -- wider than the narrowing -- and it
        #    must not escape it.
        child = sdk.delegate(
            parent,
            private_key,
            delegatee="agent-helper",
            constraints={"amount_max": 100},
        ).child
        child_fingerprint = sdk.fingerprint(child)
        controller.register(
            child_fingerprint,
            agent_id=child.agent_id,
            capability=child.capability,
        )

        blocked = sdk.authorize(child, "payments.send", {"amount": 50})
        assert blocked.allowed is False
        assert blocked.reason == "aegis_constraint_denied:aegis:resource"
        assert (
            sdk.authorize(child, "payments.send", {"amount": 10}).allowed
            is True
        )

        # 5. Policy changes. A depth ceiling of 1 excludes the child and
        #    leaves the parent alone -- a policy change is not a revocation.
        sdk.max_delegation_depth = 1
        depth_denied = sdk.authorize(child, "payments.send", {"amount": 10})
        assert depth_denied.allowed is False
        assert depth_denied.reason == "delegation_depth_exceeded"
        assert (
            sdk.authorize(parent, "payments.send", {"amount": 10}).allowed
            is True
        )
        sdk.max_delegation_depth = None

        # 6. The parent is revoked.
        sdk.revoke(parent, reason="the operator ended the task")

        # 7. The agent attempts its action -- the same call that succeeded
        #    at step 2, with the same capability object, the same action and
        #    the same request. It is refused, and refused for the *current*
        #    reason: revocation outranks the narrowing that was standing a
        #    moment ago, because _gate_revocation precedes _gate_aegis.
        final = sdk.authorize(parent, "payments.send", {"amount": 10})
        assert final.allowed is False
        assert final.reason == "capability_revoked"

        # The child is unusable too, through its parent's revocation.
        assert (
            sdk.authorize(child, "payments.send", {"amount": 10}).reason
            == "capability_revoked"
        )

        # And nothing in the walk recorded an illegal edge.
        assert controller.history_findings() == ()

    def test_a_cached_decision_could_not_pass_this(self, sdk):
        """The control for the timeline: step 2's allow is not reusable.

        Stated separately because it is the actual claim. The same
        ``(capability, action, request)`` triple returns different verdicts
        at different times, so no caller can hold an allow and replay it.
        """

        capability = _issue(sdk)
        fingerprint = sdk.fingerprint(capability)
        sdk.aegis.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        verdicts = []

        def ask():
            return sdk.authorize(capability, "payments.send", {"amount": 10})

        verdicts.append(ask())
        sdk.aegis.suspend(
            fingerprint,
            key="aegis:halt",
            reason="suspended mid-task",
        )
        verdicts.append(ask())
        sdk.aegis.lift(fingerprint, "aegis:halt")
        verdicts.append(ask())
        sdk.revoke(capability, reason="ended")
        verdicts.append(ask())

        assert [item.allowed for item in verdicts] == [
            True,
            False,
            True,
            False,
        ]
        assert [item.reason for item in verdicts] == [
            "authorized",
            "aegis_suspended:aegis:halt",
            "authorized",
            "capability_revoked",
        ]
