"""v2.6: concurrency must never widen authority.

The other v2.6 files pin the mechanism: the epoch algebra, the census, the
gate sweep, the grant-state/enforcement split. They mostly do it serially,
with a parked widening and a controlled interleaving, because a
deterministic test is worth more than a hopeful one.

This file pins the four findings that only exist *under load*, each one
reduced from a scratch probe that ran hotter than these numbers. The
thread counts here are the smallest that reproduced the property while the
probe was being built, because a test that takes a minute gets skipped and
a skipped test pins nothing. Where the probe used 64 threads, the comment
says so.

What is asserted, in every class: no thread obtains authority that a
serial execution would not have granted. Not "no denials" -- denials are
frequently the correct answer here, and three of these shapes are
*expected* to deny most requests. The assertions are one-sided in the
direction that matters:

  * exactly one consumer of a nonce, never two;
  * no execution of an argument the boundary refused;
  * no allow while a suspension stands;
  * no widening write invisible to the boundary that samples it.

Each class also carries a calibration: a case that must *succeed*, so a
green run cannot mean "everything was refused, including the legitimate
traffic".
"""

from __future__ import annotations

import os
import threading
import traceback

import pytest

from firewall.adapters.generic import GenericToolCall, generic_tool
from firewall.aegis import AegisController
from firewall.aegis.state import AegisState
from firewall.authority_epoch import (
    AuthorityEpoch,
    bind_epoch,
    epoch_of,
    is_epoch_denial,
)
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.http import HTTPFirewall
from firewall.invariants.runtime import check_authority_epoch_coverage
from firewall.lifecycle import LifecycleEventType
from firewall.replay import ReplayProtector, make_replay_key
from firewall.replay_store import SQLiteReplayStore
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.security_context import SecurityContext

ACTION = "payments.transfer"
REQUEST = {"amount": 1}

#: Enough contention to interleave, small enough to stay in the suite.
#: The probes behind these tests used 32-64.
THREADS = 16

#: Calls per thread, where a single call per thread would make the outcome
#: depend on whether every thread finishes before one thread wakes.
PER_THREAD = 8


def build_sdk(**kwargs) -> FirewallSDK:
    """An SDK with the background revalidator off.

    Periodic revalidation would write on its own schedule, which turns a
    race with one writer into a race with two and makes a failure hard to
    attribute. The subsystem has its own tests.
    """

    return FirewallSDK(
        aegis=AegisController(),
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
        **kwargs,
    )


def race(worker, threads: int = THREADS):
    """Release ``threads`` workers from one barrier, collect their answers.

    Exceptions are captured rather than raised, so a failure reports every
    thread's outcome instead of whichever one happened to surface first.
    ``BaseException``, because a thread that dies on something outside the
    ``Exception`` hierarchy must not be reported as a clean run.
    """

    barrier = threading.Barrier(threads)
    results: list = []
    errors: list[str] = []
    lock = threading.Lock()

    def run(index: int) -> None:
        try:
            barrier.wait()
            answer = worker(index)
        except BaseException:  # noqa: BLE001 - reported, see above
            line = traceback.format_exc(limit=4)
            with lock:
                errors.append(line)
            return
        with lock:
            results.append(answer)

    pool = [
        threading.Thread(target=run, args=(index,), daemon=True)
        for index in range(threads)
    ]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join(120)

    return results, errors


def no_errors(errors) -> None:
    if errors:
        pytest.fail(
            f"{len(errors)} thread(s) raised instead of returning a "
            f"verdict. First:\n{errors[0]}"
        )


# ----------------------------------------------------------------------
# Replay: the one place whose job is "exactly once"
# ----------------------------------------------------------------------


class TestExactlyOnceUnderContention:
    """Everything else counts to a ceiling. This counts to one.

    Which makes it the sharpest available statement of the v2.6 property:
    two threads presenting the same nonce and both being told yes is a
    widening, with no interpretation needed.
    """

    @staticmethod
    def estate(pattern: str = "payments.*"):
        """A real capability, because a stub cannot key a nonce.

        ``make_replay_key`` fingerprints the capability's *signing
        payload* -- the same bytes the signature covers. A hand-made stub
        has no such payload, and substituting a looser key would be
        testing a keying scheme the firewall does not use.
        """

        sdk = build_sdk()
        signing = sdk.generate_key("v26-replay")
        capability = sdk.issue(
            agent="probe-agent",
            capability=pattern,
            private_key=signing.private_key,
            constraints={"amount_max": 1000},
        )
        return sdk, capability

    def test_one_protector_admits_one_consumer(self) -> None:
        sdk, capability = self.estate()
        protector = ReplayProtector()
        key = make_replay_key("probe-agent", capability, "the-one-nonce")

        results, errors = race(
            lambda _index: protector.check_and_consume(
                key, capability.expires_at
            )
        )
        sdk.close()

        no_errors(errors)
        assert sum(1 for admitted in results if admitted) == 1

    def test_a_second_nonce_still_gets_through(self) -> None:
        """The calibration: exactly-once, not never-once."""

        sdk, capability = self.estate()
        protector = ReplayProtector()
        first = make_replay_key("probe-agent", capability, "nonce-one")
        second = make_replay_key("probe-agent", capability, "nonce-two")

        assert protector.check_and_consume(first, capability.expires_at)
        assert protector.check_and_consume(second, capability.expires_at)
        assert not protector.check_and_consume(first, capability.expires_at)
        sdk.close()

    def test_one_sqlite_store_admits_one_consumer(self, tmp_path) -> None:
        sdk, capability = self.estate()
        store = SQLiteReplayStore(os.path.join(str(tmp_path), "one.db"))
        protector = ReplayProtector(store=store)
        key = make_replay_key("probe-agent", capability, "the-one-nonce")

        results, errors = race(
            lambda _index: protector.check_and_consume(
                key, capability.expires_at
            )
        )
        store.close()
        sdk.close()

        no_errors(errors)
        assert sum(1 for admitted in results if admitted) == 1

    def test_two_stores_on_one_file_admit_one_consumer(
        self, tmp_path
    ) -> None:
        """The per-instance lock protects nothing here, and must not need to.

        ``SQLiteReplayStore`` holds an ``RLock`` per instance. Two
        instances on one file is the sibling-process shape reproduced
        in-process: the lock is irrelevant, and whatever exactly-once
        property survives belongs to ``nonces(replay_key TEXT PRIMARY
        KEY)``. If this ever admits two, the deployment story that says
        "point your workers at one file" is wrong, and no amount of
        in-process locking would have caught it.
        """

        sdk, capability = self.estate()
        path = os.path.join(str(tmp_path), "shared.db")
        left, right = SQLiteReplayStore(path), SQLiteReplayStore(path)
        protectors = (
            ReplayProtector(store=left),
            ReplayProtector(store=right),
        )
        key = make_replay_key("probe-agent", capability, "the-one-nonce")

        results, errors = race(
            lambda index: protectors[
                index % len(protectors)
            ].check_and_consume(key, capability.expires_at)
        )
        left.close()
        right.close()
        sdk.close()

        no_errors(errors)
        assert sum(1 for admitted in results if admitted) == 1

    def test_the_http_surface_admits_one_request(self) -> None:
        """End to end, where authorize-then-consume opens the window.

        ``HTTPFirewall`` deliberately consumes the nonce *after*
        authorization succeeds, so a denied request does not burn one.
        That ordering means every thread can clear the boundary and then
        race on the consume, which is the interesting shape rather than an
        unfortunate one: exactly one 200 is the requirement, and every
        loser must be recorded.
        """

        # ``action_for`` maps POST /payments/transfer to
        # ``http.POST.payments.transfer``, so the capability has to live
        # in the ``http`` namespace. ``payments.*`` here would test the
        # namespace gate and never reach replay at all.
        sdk, capability = self.estate("http.*")
        firewall = HTTPFirewall(sdk)
        request = firewall.request(
            agent="probe-agent",
            method="POST",
            path="/payments/transfer",
            arguments={"amount": 1},
            capability_token=sdk.encode(capability),
            nonce="the-one-nonce",
        )

        results, errors = race(
            lambda _index: firewall.authorize(request)
        )
        no_errors(errors)

        allowed = [decision for decision in results if decision.allowed]
        refused = [
            decision for decision in results if not decision.allowed
        ]
        replayed = len(
            sdk.lifecycle.of_type(LifecycleEventType.REPLAYED)
        )
        sdk.close()

        assert len(allowed) == 1
        assert allowed[0].status_code == 200
        assert {decision.status_code for decision in refused} == {409}
        # Every rejection recorded, not merely returned. A refusal that
        # leaves no trace is how a replay campaign stays invisible.
        assert replayed == len(refused)


# ----------------------------------------------------------------------
# Adapters: a verdict and an execution about the same arguments
# ----------------------------------------------------------------------

CEILING = 100


class TestOneAdapterManyThreads:
    """v2.5 closed this within a single call. This is the concurrent form.

    ``_settled`` materialises the argument mapping so the boundary and the
    handler cannot be shown different values. But one adapter instance
    holds ``capability``, ``action`` and ``chain_id`` across every thread
    that uses it, and if any per-call state leaks between them the symptom
    is specific: a handler runs with an amount the boundary would have
    refused.

    The required outcome is not "no denials". It is that the set of amounts
    that *executed* equals the set that was *allowed*, and that every
    executed amount is under the ceiling. One over-ceiling execution is the
    finding, however many correct denials accompany it.
    """

    @staticmethod
    def estate(*, max_actions=None):
        sdk = build_sdk()
        signing = sdk.generate_key("v26-adapter")
        capability = sdk.issue(
            agent="probe-agent",
            capability="payments.transfer",
            private_key=signing.private_key,
            # Nested, because ``build_request`` emits
            # ``{"tool": ..., "arguments": {...}}`` and ``_check_constraints``
            # refuses when the key a constraint names is absent at the level
            # it names. A top-level ``amount_max`` would deny every request
            # for the wrong reason, and the race would prove nothing.
            constraints={"arguments": {"amount_max": CEILING}},
        )
        if max_actions is not None:
            sdk.set_security_context(
                SecurityContext(
                    agent="probe-agent", max_actions=max_actions
                )
            )
        return sdk, capability

    @staticmethod
    def tool_for(sdk, capability, executed, lock):
        def handler(**arguments):
            # Recording inside the handler is the point: this body runs
            # only if the boundary said yes, so the log *is* the set of
            # amounts that were authorized to spend.
            with lock:
                executed.append(arguments.get("amount"))
            return {"spent": arguments.get("amount")}

        return generic_tool(
            sdk=sdk,
            capability=capability,
            name="transfer",
            handler=handler,
        )

    def test_no_thread_executes_an_amount_over_the_ceiling(self) -> None:
        executed: list = []
        lock = threading.Lock()
        sdk, capability = self.estate()
        tool = self.tool_for(sdk, capability, executed, lock)

        def worker(index):
            # Half legal, half an order of magnitude over, interleaved.
            amount = (index + 1) if index % 2 == 0 else CEILING * 10 + index
            call = GenericToolCall(
                name="transfer", arguments={"amount": amount}
            )
            try:
                tool.execute(call)
                return ("executed", amount)
            except PermissionError:
                return ("denied", amount)

        results, errors = race(worker)
        sdk.close()
        no_errors(errors)

        allowed = sorted(
            amount for state, amount in results if state == "executed"
        )
        # The count is deliberately not asserted. One ``constraint_denied``
        # memoizes a refusal for (agent, action), so later *legal* requests
        # on the same pair are refused without re-asking -- which requests
        # win therefore depends on ordering. That memoization is a
        # narrowing, so it is the right behaviour and the wrong thing to
        # pin a number to. What holds regardless of ordering is below.
        assert sorted(executed) == allowed
        assert [amount for amount in executed if amount > CEILING] == []
        assert executed, (
            "nothing executed at all, so this run says nothing about "
            "whether the ceiling was enforced or the adapter was simply "
            "broken"
        )

    def test_a_budget_is_spent_exactly_once_per_action(self) -> None:
        """Every argument legal, so ``max_actions`` is the only limiter.

        The shape above cannot be reused: its first ``constraint_denied``
        memoizes a refusal that then starves the budget, which can drive
        executions to zero and makes "exactly the budget ran" untestable.
        With every amount under the ceiling the count is exact, and worth
        pinning -- a budget that admits more threads than it has actions is
        the classic concurrent overspend.
        """

        budget = 5
        executed: list = []
        lock = threading.Lock()
        sdk, capability = self.estate(max_actions=budget)
        tool = self.tool_for(sdk, capability, executed, lock)

        def worker(index):
            call = GenericToolCall(
                name="transfer", arguments={"amount": index % CEILING + 1}
            )
            try:
                tool.execute(call)
                return ("executed", 1)
            except PermissionError:
                return ("denied", 0)

        results, errors = race(worker)
        recorded = sdk.security_context.action_count
        sdk.close()
        no_errors(errors)

        assert len(executed) == budget
        # The recorded count is the half that matters for the *next*
        # request: an execution the context did not count is authority
        # spent without being subtracted.
        assert recorded == budget
        assert sum(1 for state, _ in results if state == "denied") == (
            THREADS - budget
        )

    def test_revocation_lands_and_stops_the_traffic(self) -> None:
        """Revocation narrows, so it cannot widen. What is checked is that
        it takes effect promptly and the window does not stay open.

        The revoker waits until the handler has run, so the race has a real
        before and after; a revoke that wins the barrier outright proves
        only that a revoked capability is refused, which is pinned
        elsewhere and serially.

        Executions that *begin* before the revoke commits and reach the
        handler after it returns are not a defect: that is check-then-act,
        inherent to any authorization that is a decision about an instant,
        and v2.6 claims no otherwise. The assertion is what can be
        asserted -- traffic before, denials after, and not every thread on
        the far side of the revoke still executing.
        """

        executed: list = []
        after: list = []
        lock = threading.Lock()
        sdk, capability = self.estate()
        tool = self.tool_for(sdk, capability, executed, lock)

        committed = threading.Event()
        enough = threading.Event()

        def handler(**arguments):
            with lock:
                executed.append(arguments.get("amount"))
                if committed.is_set():
                    after.append(arguments.get("amount"))
                if len(executed) >= 3:
                    enough.set()
            return {"spent": arguments.get("amount")}

        tool.tool.handler = handler

        def worker(index):
            if index == 0:
                enough.wait(30)
                sdk.revoke(capability)
                committed.set()
                return ("revoker", 0, 0)

            # Each worker keeps calling, so the revoke lands in the middle
            # of a stream rather than after it. One call per worker leaves
            # the outcome up to whether fifteen threads finish before one
            # thread wakes, which is a race about the test, not the
            # firewall.
            ran = refused = 0
            call = GenericToolCall(
                name="transfer", arguments={"amount": 1}
            )
            for _ in range(PER_THREAD):
                try:
                    tool.execute(call)
                    ran += 1
                except PermissionError:
                    refused += 1
            return ("worker", ran, refused)

        results, errors = race(worker)
        no_errors(errors)

        # At rest, with every thread joined: the revocation is still in
        # force. A narrowing that expires with the race would be worse than
        # one that arrived late.
        with pytest.raises(PermissionError):
            tool.execute(
                GenericToolCall(name="transfer", arguments={"amount": 1})
            )
        sdk.close()

        ran = sum(count for _, count, _ in results)
        denied = sum(count for _, _, count in results)
        assert ran > 0, "the revoke won the barrier; nothing was raced"
        assert denied > 0, "the revocation never took effect"
        assert len(after) < ran


# ----------------------------------------------------------------------
# Aegis: the one subsystem that can widen
# ----------------------------------------------------------------------


class TestAegisChurnNeverLeaksAnAllow:
    """``lift`` is a declared widening write. So the question is direct.

    ``test_v2_6_grant_state_not_enforcement`` pins the serial statement: a
    grant labelled ``ACTIVE`` or ``REVALIDATING`` under a live suspension
    is refused, because the label is not the enforcement. These tests ask
    whether that survives the label *moving during the read*.
    """

    @staticmethod
    def estate():
        sdk = build_sdk()
        signing = sdk.generate_key("v26-aegis-race")
        capability = sdk.issue(
            agent="probe-agent",
            capability="payments.*",
            private_key=signing.private_key,
            constraints={"amount_max": 1000},
        )
        fingerprint = sdk.fingerprint(capability)
        sdk.aegis.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )
        return sdk, capability, sdk.aegis, fingerprint

    @staticmethod
    def readers_and_a_writer(sdk, capability, writer=None):
        """Readers authorize in a loop; one optional writer churns.

        The writer runs until the readers finish rather than for a fixed
        count, so the churn covers the whole read window instead of
        finishing early and leaving the tail uncontended. No
        ``time.sleep(0)`` in it: yielding the GIL to the back of a
        seventeen-deep runnable queue costs the writer a scheduling quantum
        per participant per iteration, which is how the first draft of the
        forged-evidence shape managed two writes and called it churn.
        """

        stop = threading.Event()
        writes = [0]

        def reader(_index):
            return [
                (outcome.allowed, outcome.reason)
                for outcome in (
                    sdk.authorize(capability, ACTION, REQUEST)
                    for _ in range(PER_THREAD)
                )
            ]

        def churn():
            count = 0
            try:
                while not stop.is_set():
                    writer(count)
                    count += 1
            finally:
                writes[0] = count

        hand = threading.Thread(target=churn, daemon=True)
        if writer:
            hand.start()
        try:
            results, errors = race(reader)
        finally:
            stop.set()
            if writer:
                hand.join(30)

        verdicts = [verdict for batch in results for verdict in batch]
        return verdicts, errors, writes[0]

    def assert_total(self, verdicts, errors) -> None:
        no_errors(errors)
        assert len(verdicts) == THREADS * PER_THREAD
        for allowed, reason in verdicts:
            # Totality, restated per verdict: a boundary returns a decision
            # and a reason for it, under contention as much as at rest.
            assert isinstance(allowed, bool)
            assert reason

    def test_an_idle_suspension_admits_nothing(self) -> None:
        """The floor. If this leaks, nothing further matters."""

        sdk, capability, controller, fingerprint = self.estate()
        controller.suspend(
            fingerprint, key="probe", reason="probe suspension"
        )

        verdicts, errors, _ = self.readers_and_a_writer(sdk, capability)
        sdk.close()

        self.assert_total(verdicts, errors)
        assert [reason for allowed, reason in verdicts if allowed] == []

    def test_narrowing_churn_admits_nothing(self) -> None:
        """Re-suspending under fresh keys throughout.

        Every write narrows, so allows must stay at zero -- and this is the
        shape where a store that briefly empties between two writes, or
        replaces its mapping non-atomically, would show up as an allow.
        """

        sdk, capability, controller, fingerprint = self.estate()
        controller.suspend(
            fingerprint, key="probe", reason="probe suspension"
        )

        verdicts, errors, writes = self.readers_and_a_writer(
            sdk,
            capability,
            lambda count: controller.suspend(
                fingerprint, key=f"churn-{count}", reason="churn"
            ),
        )
        still = controller.suspended_in([fingerprint])
        sdk.close()

        self.assert_total(verdicts, errors)
        assert writes > 0, "the writer never ran; this is the idle shape"
        assert [reason for allowed, reason in verdicts if allowed] == []
        assert still is not None

    def test_forged_evidence_moves_no_grant_and_admits_nothing(
        self,
    ) -> None:
        """``observe_authorization`` is the only edge that widens a grant.

        It takes a result it did not make, so it is the natural target: a
        caller who cannot mint verdicts can still *replay* a real one.
        Four forgeries, in a loop, while the suspension stands -- a genuine
        canonical allow belonging to another capability, a genuine denial,
        a non-verdict, and an allow-shaped mapping.

        Two things must hold, and the second is the one that matters: the
        grant never reaches ``ACTIVE``, and no allow appears *regardless* of
        where the grant ends up, because restrictions are the enforcement.
        """

        sdk, capability, controller, fingerprint = self.estate()
        signing = sdk.generate_key("v26-aegis-other")
        other = sdk.issue(
            agent="probe-agent",
            capability="payments.*",
            private_key=signing.private_key,
            constraints={"amount_max": 1000},
        )
        stolen = sdk.authorize(other, ACTION, REQUEST)
        assert stolen.allowed, "the borrowed allow must really be an allow"

        controller.suspend(
            fingerprint, key="probe", reason="probe suspension"
        )
        refused = sdk.authorize(capability, ACTION, REQUEST)
        assert not refused.allowed

        seen: set = set()
        seen_lock = threading.Lock()

        def writer(count):
            forgery = (
                stolen,             # real allow, wrong fingerprint
                refused,            # real verdict, but a denial
                object(),           # not a verdict at all
                {"allowed": True},  # allow-shaped, unsigned
            )[count % 4]
            controller.observe_authorization(fingerprint, forgery)
            grant = controller.grant(fingerprint)
            with seen_lock:
                seen.add(getattr(grant, "state", None))

        verdicts, errors, writes = self.readers_and_a_writer(
            sdk, capability, writer
        )
        still = controller.suspended_in([fingerprint])
        sdk.close()

        self.assert_total(verdicts, errors)
        assert writes > 0
        assert [reason for allowed, reason in verdicts if allowed] == []
        assert AegisState.ACTIVE not in seen
        assert seen == {AegisState.SUSPENDED}
        assert still is not None

    def test_genuine_widening_leaves_the_two_views_agreeing(self) -> None:
        """Real widening writes under real read load.

        Allows here are *correct*: a lift removes the obstacle and it stays
        removed until the next suspend. Asserting zero would be asserting
        the firewall is broken, and ``allows <= lifts`` is unsound for the
        same reason -- one lift legitimately justifies many later allows.

        What is sound: every verdict is total, nothing escapes, and once
        the churn stops the store and the boundary still agree. A race that
        left those two disagreeing is the finding. The epoch divergence
        denials this produces are counted rather than required: they are
        real, but how many appear is a scheduling accident.
        """

        sdk, capability, controller, fingerprint = self.estate()
        controller.suspend(
            fingerprint, key="probe", reason="probe suspension"
        )

        def writer(_count):
            controller.lift(fingerprint, "probe")
            controller.observe_authorization(
                fingerprint, sdk.authorize(capability, ACTION, REQUEST)
            )
            controller.suspend(
                fingerprint, key="probe", reason="re-suspended"
            )

        verdicts, errors, writes = self.readers_and_a_writer(
            sdk, capability, writer
        )

        # At rest, with no writer running: the two views must match.
        suspended = controller.suspended_in([fingerprint]) is not None
        settled = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        self.assert_total(verdicts, errors)
        assert writes > 0
        assert settled.allowed is not suspended

        # Under genuine widening, every denial must be either Aegis
        # refusing on the merits or a *declared* divergence form. A denial
        # from anywhere else would mean the churn confused a gate into
        # refusing for some third reason, which is not a leak but is not
        # understood either.
        prefixes = {
            reason.split(":", 1)[0]
            for allowed, reason in verdicts
            if not allowed
        }
        assert prefixes <= {
            "aegis_suspended",
            "aegis_suspended_at_commit",
            "widened_during_authorization",
            "widening_in_flight_at_entry",
            "widening_in_flight_at_commit",
        }, f"unexpected denial reason under widening churn: {prefixes}"

        # And the shape has to have actually raced. Every "caught it"
        # denial -- an epoch divergence, or the commit-time re-read of
        # Aegis catching a suspension that landed after its gate -- is
        # evidence of an overlap. Zero of them across this many verdicts
        # means the writer never overlapped a read, which makes everything
        # above a re-run of the idle shape. That is a test-integrity
        # failure, not a security one, and it should still fail.
        caught = [
            reason
            for allowed, reason in verdicts
            if not allowed
            and (
                is_epoch_denial(reason)
                or reason.startswith("aegis_suspended_at_commit")
            )
        ]
        assert caught, (
            f"{writes} widening cycles overlapped "
            f"{len(verdicts)} authorizations and not one was caught "
            "mid-flight; the shape did not race"
        )

    def test_lifting_the_suspension_admits_traffic(self) -> None:
        """The calibration. Without it, every test above passes on a
        firewall that refuses everything unconditionally."""

        sdk, capability, controller, fingerprint = self.estate()
        controller.suspend(
            fingerprint, key="probe", reason="probe suspension"
        )
        controller.lift(fingerprint, "probe")

        verdicts, errors, _ = self.readers_and_a_writer(sdk, capability)
        sdk.close()

        self.assert_total(verdicts, errors)
        assert [reason for allowed, reason in verdicts if not allowed] == []


# ----------------------------------------------------------------------
# The wiring the rest of it rests on
# ----------------------------------------------------------------------


class TestEpochCoverageCatchesASwappedEpoch:
    """Every claim above reduces to one thing: shared epoch identity.

    If the store that widens and the boundary that samples do not hold the
    *same* ``AuthorityEpoch``, then ``covers()`` compares a counter nobody
    increments against itself, returns True forever, and the divergence
    check is decoration. Construction refuses to complete when a store
    cannot be bound, which leaves the case construction cannot see: a store
    rebound afterwards, or the SDK's own epoch replaced.

    ``check_authority_epoch_coverage`` has a live half aimed at exactly
    that. These tests make it earn the name -- an invariant that cannot fail
    is a comment.
    """

    @staticmethod
    def estate() -> FirewallSDK:
        sdk = build_sdk()
        sdk.set_risk_context(RiskContext())
        return sdk

    @staticmethod
    def status(sdk) -> str:
        result = check_authority_epoch_coverage(sdk)
        return getattr(result.status, "name", str(result.status))

    def test_the_baseline_holds(self) -> None:
        """The calibration, and it comes first: a check that reports
        VIOLATED on an untouched SDK proves nothing when it reports it on a
        sabotaged one."""

        sdk = self.estate()
        try:
            assert self.status(sdk) == "HOLDS"
        finally:
            sdk.close()

    def test_a_replaced_epoch_is_caught(self) -> None:
        sdk = self.estate()
        try:
            sdk.authority_epoch = AuthorityEpoch()
            result = check_authority_epoch_coverage(sdk)
            assert getattr(result.status, "name", None) == "VIOLATED"
            # And it must name what came loose, not merely fail: a finding
            # that says "something is wrong" costs an operator the same
            # investigation twice.
            assert result.findings
        finally:
            sdk.close()

    def test_an_object_that_is_not_an_epoch_is_caught(self) -> None:
        """The degenerate substitution, which a duck-typed check would miss
        by asking the impostor whether it agrees with itself."""

        sdk = self.estate()
        try:
            sdk.authority_epoch = object()
            assert self.status(sdk) == "VIOLATED"
        finally:
            sdk.close()

    def test_a_store_rebound_to_a_foreign_epoch_is_caught(self) -> None:
        sdk = self.estate()
        try:
            stores = sdk._authority_epoch_stores()
            victim = next(
                label
                for label, store in sorted(stores.items())
                if store is not None
            )
            bind_epoch(stores[victim], AuthorityEpoch())

            result = check_authority_epoch_coverage(sdk)
            assert getattr(result.status, "name", None) == "VIOLATED"
            assert any(victim in finding for finding in result.findings), (
                f"{victim} was rebound and the findings do not name it: "
                f"{list(result.findings)}"
            )
        finally:
            sdk.close()

    def test_a_late_attachment_is_rebound_rather_than_trusted(self) -> None:
        """A context attached after construction, carrying its own epoch.

        Accepting and rebinding is the better outcome than refusing: the
        store ends up on the epoch the boundary samples either way, and the
        caller is not made responsible for a wiring detail they cannot see.
        What must not happen is accepting and *keeping* the foreign epoch --
        that is a store whose widenings are invisible, installed through the
        front door. So HOLDS is only acceptable here together with evidence
        that the rebind actually happened.
        """

        sdk = self.estate()
        try:
            foreign = RiskContext()
            bind_epoch(foreign, AuthorityEpoch())
            sdk.set_risk_context(foreign)

            assert epoch_of(sdk.risk_context) is sdk.authority_epoch
            assert self.status(sdk) == "HOLDS"
        finally:
            sdk.close()
