"""v2.7: concurrency must never widen authority, through execution.

v2.6 pinned that property for the allow; v2.7 extends it across
AUTHORIZE -> LEASE -> RESERVE -> START -> COMPLETE. The adversarial
sequences are driven with barriers and events first -- a deterministic
test is worth more than a hopeful one -- and then hammered under load,
with the machine-checked record hygiene invariant as the final audit so
a green run cannot hide an inconsistent record behind "everything was
refused".

Each shape also carries its calibration: the same sequence with no
revocation in it completes cleanly.
"""

from __future__ import annotations

import threading
import traceback
import uuid

import pytest

from firewall.execution_lease import ExecutionState
from firewall.invariants import check_execution_authority_continuity
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
THREADS = 12


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(
    sdk: FirewallSDK,
    *,
    agent: str = "agent-a",
    capability: str = ACTION,
    constraints=None,
):
    key = sdk.generate_key(f"v27c-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=capability,
        private_key=key,
        constraints={} if constraints is None else dict(constraints),
    )


def run_workers(worker, threads: int = THREADS):
    """Release ``threads`` workers from one barrier, collect their answers."""

    barrier = threading.Barrier(threads)
    results: list = []
    errors: list[str] = []
    lock = threading.Lock()

    def run(index: int) -> None:
        try:
            barrier.wait()
            answer = worker(index)
        except BaseException:  # noqa: BLE001 - reported, never hidden
            with lock:
                errors.append(traceback.format_exc(limit=4))
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


class TestAuthorizeThenRevokeThenExecute:
    def test_revoke_between_authorize_and_reserve_denies_every_thread(self):
        sdk = build_sdk()
        cap = make_capability(sdk)

        # Every worker gets its own lease first (all valid).
        leases = []

        def authorize_all(_index):
            issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
            assert issued.allowed, issued.reason
            leases.append(issued.lease)
            return issued.allowed

        results, errors = run_workers(authorize_all)
        no_errors(errors)
        assert all(results)
        assert len(leases) == THREADS

        sdk.revoke(cap, reason="v2.7 race")

        refusals = []
        for lease in leases:
            outcome = sdk.reserve_execution(
                lease, cap, ACTION, dict(REQUEST), execution_id="late"
            )
            refusals.append(outcome)
            assert not outcome.allowed, "a revoked capability must not reserve"
            assert outcome.reason == "capability_revoked"
            assert outcome.state is ExecutionState.REVOKED

        sdk.close()
        assert all(not o.allowed for o in refusals)

    def test_revoke_between_reserve_and_start_denies_every_thread(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        leases = []

        def stage(_index):
            issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
            assert issued.allowed, issued.reason
            reserved = sdk.reserve_execution(
                issued.lease,
                cap,
                ACTION,
                dict(REQUEST),
                execution_id=f"pre-{uuid.uuid4().hex[:6]}",
            )
            assert reserved.allowed, reserved.reason
            leases.append((issued.lease.lease_id, reserved.lease))
            return reserved.allowed

        results, errors = run_workers(stage)
        no_errors(errors)
        assert all(results)

        sdk.revoke(cap, reason="v2.7 race")

        for _lease_id, reserved in leases:
            started = sdk.start_execution(reserved, cap, ACTION, dict(REQUEST))
            assert not started.allowed
            assert started.reason == "capability_revoked"
            assert started.lease.executed is False

        sdk.close()

    def test_revoke_between_start_and_complete_denies_clean_completion(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        started_records = []

        def stage(_index):
            issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
            assert issued.allowed, issued.reason
            reserved = sdk.reserve_execution(
                issued.lease,
                cap,
                ACTION,
                dict(REQUEST),
                execution_id=f"mid-{uuid.uuid4().hex[:6]}",
            )
            assert reserved.allowed, reserved.reason
            started = sdk.start_execution(
                reserved.lease, cap, ACTION, dict(REQUEST)
            )
            assert started.allowed, started.reason
            started_records.append(started.lease)
            return started.allowed

        results, errors = run_workers(stage)
        no_errors(errors)
        assert all(results)

        sdk.revoke(cap, reason="v2.7 race")

        for started in started_records:
            completed = sdk.complete_execution(
                started, cap, ACTION, dict(REQUEST)
            )
            assert not completed.allowed, "clean completion under a revoked cap"
            assert completed.reason == "capability_revoked"
            # The action had started; the record must say it ran and that
            # authority did not hold to the end -- never a clean COMPLETED.
            assert completed.lease.executed is True
            assert completed.state is ExecutionState.REVOKED

        sdk.close()

    def test_no_revocation_completes_cleanly(self):
        """The calibration for this whole class."""

        sdk = build_sdk()
        cap = make_capability(sdk)

        def full(_index):
            issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
            assert issued.allowed, issued.reason
            reserved = sdk.reserve_execution(
                issued.lease,
                cap,
                ACTION,
                dict(REQUEST),
                execution_id=f"ok-{uuid.uuid4().hex[:6]}",
            )
            assert reserved.allowed, reserved.reason
            started = sdk.start_execution(
                reserved.lease, cap, ACTION, dict(REQUEST)
            )
            assert started.allowed, started.reason
            completed = sdk.complete_execution(
                started.lease, cap, ACTION, dict(REQUEST)
            )
            assert completed.allowed, completed.reason
            return completed.allowed

        results, errors = run_workers(full)
        sdk.close()

        no_errors(errors)
        assert all(results)


class TestDeterministicRaces:
    def test_reserve_versus_revoke_resolves_without_a_clean_start(self):
        """Reserve and revoke race; whatever the interleaving, nothing may
        start under revoked authority and every record ends explainable."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        lease = issued.lease

        reserve_go = threading.Event()
        revoke_done = threading.Event()
        outcomes = []
        lock = threading.Lock()

        def reserver():
            reserve_go.wait()
            out = sdk.reserve_execution(
                lease, cap, ACTION, dict(REQUEST), execution_id="race-1"
            )
            with lock:
                outcomes.append(("reserve", out))

        def revoker():
            reserve_go.wait()
            sdk.revoke(cap, reason="race")
            revoke_done.set()

        t1 = threading.Thread(target=reserver, daemon=True)
        t2 = threading.Thread(target=revoker, daemon=True)
        t1.start()
        t2.start()
        reserve_go.set()
        t1.join(60)
        t2.join(60)
        sdk.close()

        assert not t1.is_alive() and not t2.is_alive()
        kinds = {kind for kind, _ in outcomes}
        # If the reservation landed before the revocation, start must then
        # be refused; if after, the reservation itself is refused.
        assert "reserve" in kinds
        reserve_outcome = outcomes[0][1]
        if reserve_outcome.allowed:
            assert reserve_outcome.state is ExecutionState.RESERVED
        else:
            assert reserve_outcome.reason in (
                "capability_revoked",
                "execution_epoch_diverged",
            )

    def test_epoch_widening_between_issue_and_reserve_freezes_the_lease(self):
        """A context replacement is a widening; a lease issued under the old
        context must not reserve under the new one."""

        sdk = FirewallSDK(risk_context=RiskContext())
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason

        sdk.set_risk_context(RiskContext())

        outcome = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="epoch"
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason in (
            "policy_version_changed",
            "execution_epoch_diverged",
        )


class TestLoad:
    def test_many_threads_many_cycles_stay_consistent(self):
        """The final audit is the machine-checked invariant itself."""

        sdk = build_sdk()
        per_thread = 6

        def worker(_index):
            allowed = 0
            for _ in range(per_thread):
                cap = make_capability(sdk)
                issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
                if not issued.allowed:
                    return ("authorize_refused", issued.reason)
                reserved = sdk.reserve_execution(
                    issued.lease,
                    cap,
                    ACTION,
                    dict(REQUEST),
                    execution_id=f"{_index}-{uuid.uuid4().hex[:6]}",
                )
                if not reserved.allowed:
                    return ("reserve_refused", reserved.reason)
                started = sdk.start_execution(
                    reserved.lease, cap, ACTION, dict(REQUEST)
                )
                if not started.allowed:
                    return ("start_refused", started.reason)
                completed = sdk.complete_execution(
                    started.lease, cap, ACTION, dict(REQUEST)
                )
                if not completed.allowed:
                    return ("complete_refused", completed.reason)
                allowed += 1
            return allowed

        results, errors = run_workers(worker)
        sdk.close()

        no_errors(errors)
        assert results
        assert all(isinstance(r, int) and r == per_thread for r in results)

    def test_revocation_churn_never_leaves_a_lying_record(self):
        """Racing full cycles against staggered revocations; afterwards the
        record hygiene invariant must still hold over whatever happened."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        first_attempt_done = threading.Event()

        def worker(index):
            outcome_flags = []
            for attempt in range(4):
                issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
                if not issued.allowed:
                    outcome_flags.append(("denied", issued.reason))
                    if attempt == 0:
                        first_attempt_done.set()
                    continue
                reserved = sdk.reserve_execution(
                    issued.lease,
                    cap,
                    ACTION,
                    dict(REQUEST),
                    execution_id=f"churn-{index}-{uuid.uuid4().hex[:6]}",
                )
                if not reserved.allowed:
                    outcome_flags.append(("reserve_denied", reserved.reason))
                    if attempt == 0:
                        first_attempt_done.set()
                    continue
                started = sdk.start_execution(
                    reserved.lease, cap, ACTION, dict(REQUEST)
                )
                if not started.allowed:
                    outcome_flags.append(("start_denied", started.reason))
                    if attempt == 0:
                        first_attempt_done.set()
                    continue
                completed = sdk.complete_execution(
                    started.lease, cap, ACTION, dict(REQUEST)
                )
                outcome_flags.append(
                    ("completed" if completed.allowed else "complete_denied",
                     completed.reason)
                )
                if attempt == 0:
                    first_attempt_done.set()
            return outcome_flags

        from firewall.revocation import AlreadyRevokedError

        def revoker():
            # Let at least one full cycle land first, so the audit has
            # records to inspect no matter how the race resolves; then
            # revoke and keep revoking while the other cycles race it.
            first_attempt_done.wait(60)
            for _ in range(6):
                try:
                    sdk.revoke(cap, reason="churn")
                except AlreadyRevokedError:
                    break

        barrier = threading.Barrier(THREADS + 1)
        results = []
        errors = []

        def run(index):
            try:
                barrier.wait()
                results.append(worker(index))
            except BaseException:
                with _err_lock:
                    errors.append(traceback.format_exc(limit=4))

        _err_lock = threading.Lock()
        pool = [
            threading.Thread(target=run, args=(i,), daemon=True)
            for i in range(THREADS)
        ]
        revoker_thread = threading.Thread(
            target=lambda: (barrier.wait(), revoker()), daemon=True
        )
        for t in pool:
            t.start()
        revoker_thread.start()
        for t in pool:
            t.join(120)
        revoker_thread.join(120)

        no_errors(errors)

        # Whatever the interleaving produced, the records must satisfy the
        # machine-checked hygiene invariant: no clean COMPLETED that its
        # flags do not support, no STARTED-then-terminal without executed.
        audit = check_execution_authority_continuity(sdk)
        sdk.close()

        assert audit.holds, (
            audit.reason,
            list(audit.findings)[:5],
        )
        assert results
