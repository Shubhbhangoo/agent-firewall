"""v2.7: crash and recovery analysis of the lease lifecycle.

What survives a process restart, and what the firewall honestly cannot
claim. The SQLite backend persists every transition as an atomic row, so
after a restart an operator can read exactly where each execution
stopped -- reserved, started, or completed -- and no record appears that
the previous process did not write. What no in-process record can do is
roll back an external side effect that already ran; that non-guarantee
is pinned here by showing exactly which records a crash between phases
leaves behind.

Every class carries the calibration: the same lifecycle without a crash
ends in a clean COMPLETED.
"""

from __future__ import annotations

import os
import uuid

import pytest

from firewall.execution_lease import (
    ExecutionLeaseStore,
    ExecutionState,
)
from firewall.execution_store import SQLiteExecutionLeaseStore
from firewall.invariants import check_execution_authority_continuity
from firewall.invariants.model import InvariantStatus
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}


def make_capability(sdk, agent: str = "agent-a"):
    key = sdk.generate_key(f"v27r-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def open_store(path) -> ExecutionLeaseStore:
    return ExecutionLeaseStore(backend=SQLiteExecutionLeaseStore(path))


class TestPersistenceAcrossRestart:
    def test_a_completed_lease_is_still_completed_after_restart(self, tmp_path):
        path = os.path.join(str(tmp_path), "leases.db")
        first = open_store(path)
        sdk = FirewallSDK(execution_lease_store=first)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="persist"
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
        sdk.close()  # closes the internally-tracked handles

        # New process, same file.
        second = open_store(path)
        record = second.get(lease_id)
        audit = check_execution_authority_continuity(
            FirewallSDK(execution_lease_store=second)
        )
        second.close()

        assert record is not None
        assert record.state is ExecutionState.COMPLETED
        assert record.executed is True
        assert audit.status is InvariantStatus.HOLDS

    def test_a_crash_after_start_leaves_a_started_record(self, tmp_path):
        """Crash between STARTED and COMPLETED: the record must say STARTED,
        never COMPLETED, and never pretend nothing ran."""

        path = os.path.join(str(tmp_path), "crash.db")
        first = open_store(path)
        sdk = FirewallSDK(execution_lease_store=first)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="crash"
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason
        # Crash: the handler ran or did not; no COMPLETED is written.
        sdk.close()

        second = open_store(path)
        record = second.get(lease_id)
        # Recovery: the operator aborts the stuck execution by id.
        recovered = FirewallSDK(execution_lease_store=second)
        outcome = recovered.abort_execution(
            lease_id, reason="recovered after crash"
        )
        record_after = second.get(lease_id)
        second.close()

        assert record.state is ExecutionState.STARTED
        assert outcome.allowed, outcome.reason
        assert record_after.state is ExecutionState.ABORTED
        assert record_after.executed is True  # the action may have run

    def test_a_crash_after_reserve_leaves_a_reserved_record(self, tmp_path):
        """Crash between RESERVED and STARTED: nothing ran, and the record
        says so -- the reserved execution can be aborted without lying."""

        path = os.path.join(str(tmp_path), "crash2.db")
        first = open_store(path)
        sdk = FirewallSDK(execution_lease_store=first)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="crash2"
        )
        assert reserved.allowed, reserved.reason
        sdk.close()  # crash before STARTED

        second = open_store(path)
        record = second.get(lease_id)
        recovered = FirewallSDK(execution_lease_store=second)
        outcome = recovered.abort_execution(
            lease_id, reason="never started"
        )
        record_after = second.get(lease_id)
        second.close()

        assert record.state is ExecutionState.RESERVED
        assert outcome.allowed, outcome.reason
        assert record_after.state is ExecutionState.ABORTED
        assert record_after.executed is False  # genuinely nothing ran

    def test_a_crash_before_evidence_leaves_no_false_record(self, tmp_path):
        """Crash between lease issue and reserve: the lease exists but
        nothing executed; no completion was ever written."""

        path = os.path.join(str(tmp_path), "crash3.db")
        first = open_store(path)
        sdk = FirewallSDK(execution_lease_store=first)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        sdk.close()

        second = open_store(path)
        record = second.get(lease_id)
        # The lease has a deadline; the sweep may lapse it. Until then it
        # exists in LEASE_ISSUED and authorizes nothing by itself.
        second.close()

        assert record.state is ExecutionState.LEASE_ISSUED
        assert record.executed is False
        assert record.complete_authority_valid is None

    def test_an_expired_lease_lapses_after_restart(self, tmp_path):
        class Clock:
            def __init__(self):
                self.t = 5000.0

            def __call__(self):
                return self.t

        path = os.path.join(str(tmp_path), "lapse.db")
        clock = Clock()
        backend = SQLiteExecutionLeaseStore(path, clock=clock)
        store = ExecutionLeaseStore(clock=clock, backend=backend)
        sdk = FirewallSDK(
            clock=clock, execution_lease_store=store
        )
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST), ttl=1)
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        sdk.close()

        # A new process, later: the deadline has passed.
        class Later:
            def __call__(self):
                return 9000.0

        later_clock = Later()
        backend2 = SQLiteExecutionLeaseStore(path, clock=later_clock)
        store2 = ExecutionLeaseStore(clock=later_clock, backend=backend2)
        lapsed = store2.expire_lapsed()
        record = store2.get(lease_id)
        backend2.close()

        assert lapsed == 1
        assert record.state is ExecutionState.EXPIRED
        assert record.terminal_reason == "lease_deadline_passed"


class TestCrashRecoveryGuarantees:
    def test_a_clean_run_never_uses_recovery(self):
        """Calibration: without a crash the lifecycle needs no recovery."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        ran = []

        def handler():
            ran.append(1)

        outcome = sdk.run_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            handler=handler,
            execution_id="clean",
        )
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert outcome.state is ExecutionState.COMPLETED
        assert ran == [1]

    def test_the_external_side_effect_is_not_rolled_back(self):
        """The firewall cannot roll back an external API call it does not
        control. What it can do is never *record* the call as a clean
        completion when authority died mid-flight. This test documents the
        boundary: the side effect exists and stays; the record says so."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="ext"
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason

        external_effect = ["payment-sent"]  # already in the world
        sdk.revoke(cap, reason="mid-flight")

        completed = sdk.complete_execution(
            started.lease, cap, ACTION, dict(REQUEST)
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        # The external effect cannot be un-sent. The firewall's job is to
        # say so: REVOKED, executed=True, no clean COMPLETED.
        assert external_effect == ["payment-sent"]
        assert not completed.allowed
        assert record.state is ExecutionState.REVOKED
        assert record.executed is True

    def test_abort_of_a_foreign_or_unknown_lease_is_a_refusal(self):
        sdk = FirewallSDK()
        outcome = sdk.abort_execution("0" * 32)
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_unknown"

    def test_abort_of_an_already_terminal_lease_is_a_refusal(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        aborted = sdk.abort_execution(
            issued.lease, reason="operator"
        )
        assert aborted.allowed, aborted.reason
        again = sdk.abort_execution(issued.lease, reason="twice")
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not again.allowed
        assert again.reason == "lease_terminal:denied"
        assert record.state is ExecutionState.DENIED
