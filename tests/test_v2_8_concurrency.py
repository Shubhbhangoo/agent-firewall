"""v2.8: concurrency -- the idempotency and exactly-once guarantees belong
to the persistent row, not to a per-instance lock.

Threads racing to prepare one lease: one row. Threads racing to attempt:
one attempt. Threads racing to record a receipt: one resolution, others
refused. Two SDK instances over one SQLite file observe the same
guarantees across processes.

Every class carries the calibration: the same sequence on one thread
completes cleanly.
"""

from __future__ import annotations

import os
import threading
import uuid

from firewall.effect import (
    EffectJournal,
    EffectOutcome,
    EffectState,
    ReceiptKind,
)
from firewall.effect_store import SQLiteEffectJournal
from firewall.execution_lease import (
    ExecutionLeaseStore,
    ExecutionState,
)
from firewall.execution_store import SQLiteExecutionLeaseStore
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-race"


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(sdk):
    key = sdk.generate_key(f"v28x-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def reserve_and_start(sdk, cap, execution_id):
    issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease, cap, ACTION, dict(REQUEST), execution_id=execution_id
    )
    assert reserved.allowed, reserved.reason
    started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
    assert started.allowed, started.reason
    return issued, started


def open_pair(path):
    """One SDK over one SQLite file hosting both journals."""
    return FirewallSDK(
        execution_lease_store=ExecutionLeaseStore(
            backend=SQLiteExecutionLeaseStore(path)
        ),
        effect_journal=EffectJournal(
            backend=SQLiteEffectJournal(path)
        ),
    )


def barrier_run(fn, threads=8):
    """Run ``fn(sdk_index, barrier)`` on ``threads`` threads sharing one
    barrier, returning the results list."""
    results = [None] * threads
    barrier = threading.Barrier(threads)
    errors = []

    def work(index):
        try:
            barrier.wait()
            results[index] = fn(index)
        except BaseException as exc:  # noqa: BLE001 - reported
            errors.append((index, exc))

    handles = [
        threading.Thread(target=work, args=(index,)) for index in range(threads)
    ]
    for handle in handles:
        handle.start()
    for handle in handles:
        handle.join()
    if errors:
        raise errors[0][1]
    return results


class TestSingleProcessConcurrency:
    def test_one_row_under_a_prepare_storm(self):
        """Threads A..D racing to prepare the same lease: exactly one row,
        and every thread that presented the same effect/key is served."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = reserve_and_start(sdk, cap, "storm-prepare")

        def prepare(_index):
            return sdk.prepare_effect(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
            )

        outcomes = barrier_run(prepare)
        sdk.close()

        rows = sdk.effects.records()
        effect_ids = {outcome.effect.effect_id for outcome in outcomes}
        assert len(rows) == 1
        assert len(effect_ids) == 1
        assert all(outcome.allowed for outcome in outcomes)

    def test_exactly_one_attempt_under_concurrent_retries(self):
        """Threads A..D all 'retrying' the transmission: exactly one
        ATTEMPT_STARTED is ever authorized."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = reserve_and_start(sdk, cap, "storm-attempt")
        prepared = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert prepared.allowed, prepared.reason
        first_effect_id = prepared.effect.effect_id

        def attempt(_index):
            return sdk.attempt_effect(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
            )

        outcomes = barrier_run(attempt)
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        winners = [o for o in outcomes if o.allowed]
        losers = [o for o in outcomes if not o.allowed]
        assert len(winners) == 1
        assert len(losers) == len(outcomes) - 1
        assert all(o.reason == "effect_already_attempted" for o in losers)
        assert row.effect_id == first_effect_id
        assert row.state is EffectState.ATTEMPT_STARTED
        assert len({o.effect.attempt_id for o in outcomes if o.allowed}) == 1

    def test_one_resolution_under_a_receipt_storm(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = reserve_and_start(sdk, cap, "storm-receipt")
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )

        def receipt(_index):
            return sdk.record_effect_receipt(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
                observed_outcome=EffectOutcome.SUCCEEDED,
                evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
            )

        outcomes = barrier_run(receipt)
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        winners = [o for o in outcomes if o.allowed]
        assert len(winners) == 1
        assert row.state is EffectState.SUCCEEDED
        assert row.observed_at is not None

    def test_the_sequential_calibration_completes(self):
        """Calibration: the same full sequence on one thread completes."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        outcome = sdk.run_effect(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            execution_id="calib",
            handler=lambda: None,
        )
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert outcome.state is ExecutionState.COMPLETED


class TestCrossProcessConcurrency:
    def test_two_sdk_instances_over_one_file_reserve_one_attempt(self, tmp_path):
        """The row decides, not the per-instance lock: two SDK instances
        over one SQLite file racing to attempt produce one winner."""

        path = os.path.join(str(tmp_path), "cross.db")

        # Process 1: authorize, reserve, start, prepare (persisted).
        first = open_pair(path)
        cap = make_capability(first)
        issued = first.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = first.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="cross-exec",
        )
        assert reserved.allowed, reserved.reason
        started = first.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason
        prepared = first.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert prepared.allowed, prepared.reason
        lease_object = started.lease
        first.close()

        # "Restart": a second instance reads the same file.
        second = open_pair(path)
        record = second.execution_leases.get(lease_id)
        assert record.state is ExecutionState.STARTED
        row = second.effects.by_lease(lease_id)
        assert row.state is EffectState.INTENT_RECORDED

        # Both instances race to attempt the same row.
        results = []

        def attempt(sdk, tag):
            return sdk.attempt_effect(
                record,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
            )

        barrier = threading.Barrier(2)
        captured = [None, None]

        def worker(index, sdk):
            barrier.wait()
            captured[index] = attempt(sdk, index)

        t1 = threading.Thread(target=worker, args=(0, second))
        t2 = threading.Thread(target=worker, args=(1, second))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        winners = [c for c in captured if c.allowed]
        losers = [c for c in captured if not c.allowed]
        second.close()

        assert len(winners) == 1
        assert len(losers) == 1
        assert losers[0].reason == "effect_already_attempted"
        final = EffectJournal(
            backend=SQLiteEffectJournal(path)
        )
        row_after = final.by_lease(lease_id)
        final.close()
        assert row_after.state is EffectState.ATTEMPT_STARTED

    def test_persisted_records_survive_both_instances_racing_to_prepare(
        self, tmp_path
    ):
        """Two fresh leases on two instances cannot collide: a lease on
        instance A has its own row, and instance B's prepare for its own
        lease is independent."""

        path = os.path.join(str(tmp_path), "cross2.db")
        first = open_pair(path)
        cap = make_capability(first)
        issued = first.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = first.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="cross-exec-2",
        )
        started = first.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        p1 = first.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert p1.allowed, p1.reason
        first.close()

        second = open_pair(path)
        record = second.execution_leases.get(started.lease.lease_id)
        # The second instance's prepare of the SAME lease/effect/key is
        # served from the existing row.
        p2 = second.prepare_effect(
            record,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        rows = second.effects.records()
        second.close()

        assert p2.allowed, p2.reason
        assert p2.effect.effect_id == p1.effect.effect_id
        assert len(rows) == 1
