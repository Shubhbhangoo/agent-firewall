"""v2.7: a lease is a continuation, and a continuation happens exactly once.

Extending the v2.6 replay story past the allow: a lease is a record of
one authorization, so the same lease must not drive two executions, a
lease authorized for one request must not execute another, an execution
identity must not name two live executions, and an agent cannot pick up
another agent's lease. Each class carries a calibration -- the same lease
*does* still execute once, and a fresh lease on a finished identity *is*
admitted -- so a green run cannot mean "everything was refused".
"""

from __future__ import annotations

import os
import uuid

import pytest

from firewall.execution_lease import (
    ExecutionLease,
    ExecutionLeaseStore,
    ExecutionState,
)
from firewall.execution_store import SQLiteExecutionLeaseStore
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(
    sdk: FirewallSDK,
    *,
    agent: str = "agent-a",
    capability: str = ACTION,
    constraints=None,
):
    key = sdk.generate_key(f"v27r-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=capability,
        private_key=key,
        constraints={} if constraints is None else dict(constraints),
    )


def issue_lease(sdk, cap=None):
    cap = cap or make_capability(sdk)
    issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    return issued.lease, cap


def race(worker, threads: int = 12):
    import threading
    import traceback

    barrier = threading.Barrier(threads)
    results: list = []
    errors: list[str] = []
    lock = threading.Lock()

    def run(index: int) -> None:
        try:
            barrier.wait()
            answer = worker(index)
        except BaseException:  # noqa: BLE001 - reported, see above
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


class TestSameLeaseIsSingleUse:
    def test_reserving_twice_is_refused(self):
        sdk = build_sdk()
        lease, cap = issue_lease(sdk)
        first = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="one"
        )
        assert first.allowed, first.reason
        second = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="one"
        )
        sdk.close()

        assert not second.allowed
        assert second.reason == "lease_already_reserved"

    def test_starting_a_reserved_lease_twice_is_refused(self):
        sdk = build_sdk()
        lease, cap = issue_lease(sdk)
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="one"
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
        assert started.allowed, started.reason
        again = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert not again.allowed
        assert again.reason == "lease_already_started"

    def test_the_exact_once_winner_under_contention(self):
        """Many threads race to reserve one lease; exactly one wins."""

        sdk = build_sdk()
        lease, cap = issue_lease(sdk)

        results, errors = race(
            lambda index: sdk.reserve_execution(
                lease,
                cap,
                ACTION,
                dict(REQUEST),
                execution_id=f"exec-{index}",
            )
        )
        sdk.close()

        no_errors(errors)
        assert sum(1 for outcome in results if outcome.allowed) == 1
        refused = [o for o in results if not o.allowed]
        # A loser observes either the already-reserved phase or its own
        # stale read of the pre-reservation phase; every loser is a
        # refusal naming the lease, never an allow and never an exception.
        assert refused
        assert all(
            not o.allowed and o.reason.startswith("lease_")
            for o in refused
        )

    def test_two_instances_on_one_sqlite_file_admit_one(self, tmp_path):
        """Cross-process shape reproduced in-process: the row decides."""

        path = os.path.join(str(tmp_path), "shared.db")
        seeded = ExecutionLeaseStore(
            backend=SQLiteExecutionLeaseStore(path)
        )
        lease = seeded.issue(
            capability_fingerprint="f",
            agent_id="a",
            capability="c",
            action="x",
            request_digest="d",
            chain_id=None,
            policy_version="p",
            ttl=60,
        )
        seeded.close()

        # Two fresh stores over one file, both preloaded with that row,
        # race to reserve it. The per-instance lock protects nothing here
        # and must not need to: exactly-once belongs to the UPDATE's
        # ``WHERE state = ?``.
        first = ExecutionLeaseStore(
            backend=SQLiteExecutionLeaseStore(path)
        )
        second = ExecutionLeaseStore(
            backend=SQLiteExecutionLeaseStore(path)
        )
        current = first.get(lease.lease_id)
        assert current is not None

        results, errors = race(
            lambda index: _reserve_on(
                first if index % 2 == 0 else second,
                current,
                f"exec-race-{index}",
            )
        )
        first.close()
        second.close()

        no_errors(errors)
        allowed = [r for r in results if r[0]]
        assert len(allowed) == 1

    def test_a_second_execution_under_a_fresh_lease_is_admitted(self):
        """Calibration: single-use per lease, not never."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        first = issue_lease(sdk, cap)
        lease, _ = first
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="cycle-1"
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
        sdk.complete_execution(started.lease, cap, ACTION, dict(REQUEST))
        second_lease, _ = issue_lease(sdk, cap)
        second = sdk.reserve_execution(
            second_lease, cap, ACTION, dict(REQUEST), execution_id="cycle-2"
        )
        sdk.close()

        assert second.allowed, second.reason


def _reserve_on(store, lease, execution_id):
    try:
        moved = store.transition(
            lease.lease_id,
            ExecutionState.RESERVED,
            execution_id=execution_id,
        )
    except Exception:
        return False, "refused"
    return moved is not None, "allowed"


# ----------------------------------------------------------------------
# Request and identity binding
# ----------------------------------------------------------------------


class TestRequestBinding:
    def test_same_lease_different_request_is_refused_at_every_stage(self):
        sdk = build_sdk()
        lease, cap = issue_lease(sdk)

        wrong_reserve = sdk.reserve_execution(
            lease, cap, ACTION, {"amount": 6}, execution_id="x"
        )
        assert not wrong_reserve.allowed
        assert wrong_reserve.reason == "lease_request_mismatch"

        # Calibration: refused, not burned; the authorized request works.
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="x"
        )
        assert reserved.allowed, reserved.reason

        wrong_start = sdk.start_execution(
            reserved.lease, cap, ACTION, {"amount": 6}
        )
        assert not wrong_start.allowed
        assert wrong_start.reason == "lease_request_mismatch"

        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason

        wrong_complete = sdk.complete_execution(
            started.lease, cap, ACTION, {"amount": 6}
        )
        assert not wrong_complete.allowed
        assert wrong_complete.reason == "lease_request_mismatch"
        sdk.close()

    def test_the_same_request_with_reordered_keys_still_matches(self):
        """The digest is canonical, so serialization order is not identity."""

        sdk = build_sdk()
        cap = make_capability(sdk, agent="agent-z")
        request = {"amount": 5, "note": "hello"}
        reordered = {"note": "hello", "amount": 5}
        issued = sdk.authorize_execution(cap, ACTION, request)
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, reordered, execution_id="canon"
        )
        sdk.close()

        assert reserved.allowed, reserved.reason


class TestExecutionIdentityBinding:
    def test_a_second_lease_cannot_claim_a_live_execution_identity(self):
        sdk = build_sdk()
        lease_a, cap_a = issue_lease(sdk, make_capability(sdk, agent="aa"))
        lease_b, cap_b = issue_lease(sdk, make_capability(sdk, agent="bb"))
        first = sdk.reserve_execution(
            lease_a, cap_a, ACTION, dict(REQUEST), execution_id="shared"
        )
        assert first.allowed, first.reason
        second = sdk.reserve_execution(
            lease_b, cap_b, ACTION, dict(REQUEST), execution_id="shared"
        )
        sdk.close()

        assert not second.allowed
        assert second.reason == "execution_identity_bound"

    def test_a_finished_execution_identity_is_reusable(self):
        """Calibration: an identity labels one *live* execution."""

        sdk = build_sdk()
        lease, cap = issue_lease(sdk)
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="reuse-me"
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
        sdk.complete_execution(started.lease, cap, ACTION, dict(REQUEST))
        lease2, _ = issue_lease(sdk, cap)
        again = sdk.reserve_execution(
            lease2, cap, ACTION, dict(REQUEST), execution_id="reuse-me"
        )
        sdk.close()

        assert again.allowed, again.reason


class TestAgentBinding:
    def test_one_agent_cannot_use_anothers_lease(self):
        sdk = build_sdk()
        lease, cap_a = issue_lease(sdk, make_capability(sdk, agent="agent-a"))
        cap_b = make_capability(sdk, agent="agent-b")
        outcome = sdk.reserve_execution(
            lease, cap_b, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason in (
            "lease_capability_mismatch",
            "lease_identity_mismatch",
        )

    def test_the_owning_agent_still_executes(self):
        """Calibration for the agent-binding class."""

        sdk = build_sdk()
        cap = make_capability(sdk, agent="agent-a")
        lease, _ = issue_lease(sdk, cap)
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="agent-ok"
        )
        sdk.close()

        assert reserved.allowed, reserved.reason
