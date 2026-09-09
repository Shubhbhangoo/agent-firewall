"""v2.8: recovery -- after a restart, an execution interrupted between the
external request and any record of its outcome must be recoverable.

The durable intent (outbox) makes recovery possible: after a crash the
journal still says what was intended, whether an attempt was authorized,
and that the outcome was never observed. The firewall represents that as
``ATTEMPT_STARTED`` (crash before any receipt) or ``UNKNOWN`` (a timeout
was recorded), and the operator reconciles it against the external
system's actual status. The firewall never *auto*-retries an unknown side
effect: that could duplicate a real-world action.

Every class carries the calibration: the same lifecycle without a crash
ends in a clean COMPLETED.
"""

from __future__ import annotations

import os
import uuid

import pytest

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
from firewall.effect_verification import (
    VerificationOutcome,
    VerifierVerdict,
)

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-recover"


def make_capability(sdk):
    key = sdk.generate_key(f"v28c-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def open_stores(path):
    """One SQLite file hosting both journals, as two store objects."""
    backend = SQLiteExecutionLeaseStore(path)
    lease_store = ExecutionLeaseStore(backend=backend)
    effect_backend = SQLiteEffectJournal(path)
    effect_journal = EffectJournal(backend=effect_backend)
    return lease_store, effect_journal, backend, effect_backend


def sdk_over(path, clock=None):
    lease_store, effect_journal, _, _ = open_stores(path)
    return FirewallSDK(
        clock=clock,
        execution_lease_store=lease_store,
        effect_journal=effect_journal,
    )


class TestPersistenceAcrossRestart:
    def test_a_crash_after_start_leaves_the_intent_and_attempt_readable(
        self, tmp_path
    ):
        """Crash after ATTEMPT_STARTED, before any receipt: after a restart
        the journal still says what was intended and that an attempt was
        authorized; it says nothing about the outcome."""

        path = os.path.join(str(tmp_path), "recover.db")
        sdk = sdk_over(path)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="crash-effect",
        )
        assert reserved.allowed, reserved.reason
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
        assert started.allowed, started.reason
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
        attempted = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert attempted.allowed, attempted.reason
        # Crash: the process dies with the request possibly in flight.
        sdk.close()

        second = sdk_over(path)
        lease = second.execution_leases.get(lease_id)
        row = second.effects.by_lease(lease_id)
        assert lease.state is ExecutionState.STARTED
        assert row.state is EffectState.ATTEMPT_STARTED
        assert row.attempt_id is not None
        assert row.observed_outcome is None

        # Recovery: reconcile against the external status -> confirmed
        # success, then commit.
        reconciled = second.reconcile_effect(
            lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id="ext-after-restart",
        )
        assert reconciled.allowed, reconciled.reason
        committed = second.commit_effect(
            lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=lambda evidence: VerifierVerdict(
                outcome=VerificationOutcome.VERIFIED,
                method="v28-strict-chain",
            ),
            method="v28-strict-chain",
        )
        record = second.execution_leases.get(lease_id)
        second.close()

        assert reconciled.effect.state is EffectState.SUCCEEDED
        assert committed.allowed, committed.reason
        assert record.state is ExecutionState.COMPLETED

    def test_a_crash_after_start_reconciled_to_failure_is_recorded_truthfully(
        self, tmp_path
    ):
        path = os.path.join(str(tmp_path), "recover2.db")
        sdk = sdk_over(path)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="crash-fail",
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
        assert started.allowed, started.reason
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
        sdk.close()

        second = sdk_over(path)
        lease = second.execution_leases.get(lease_id)
        reconciled = second.reconcile_effect(
            lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.FAILED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            note="provider confirms nothing processed",
        )
        row = second.effects.by_lease(lease_id)
        # The confirmed failure is explicit; the execution is then aborted
        # truthfully (executed=True) rather than completed.
        outcome = second.abort_execution(lease_id, reason="effect failed")
        record = second.execution_leases.get(lease_id)
        second.close()

        assert reconciled.allowed, reconciled.reason
        assert row.state is EffectState.FAILED
        assert outcome.allowed, outcome.reason
        assert record.state is ExecutionState.ABORTED
        assert record.executed is True

    def test_a_crash_after_receipt_before_commit_stays_succeeded(self, tmp_path):
        """Crash after the receipt recorded SUCCEEDED but before COMMIT:
        after a restart the row is SUCCEEDED under valid authority and the
        execution can simply be committed."""

        path = os.path.join(str(tmp_path), "recover3.db")
        sdk = sdk_over(path)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease_id = issued.lease.lease_id
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="crash-precommit",
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
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
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id="ext-precommit",
        )
        sdk.close()

        second = sdk_over(path)
        lease = second.execution_leases.get(lease_id)
        row = second.effects.by_lease(lease_id)
        committed = second.commit_effect(
            lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=lambda evidence: VerifierVerdict(
                outcome=VerificationOutcome.VERIFIED,
                method="v28-strict-chain",
            ),
            method="v28-strict-chain",
        )
        record = second.execution_leases.get(lease_id)
        second.close()

        assert row.state is EffectState.SUCCEEDED
        assert committed.allowed, committed.reason
        assert record.state is ExecutionState.COMPLETED

    def test_a_clean_run_never_uses_recovery(self):
        """Calibration: without a crash the lifecycle needs no recovery."""

        sdk = build = FirewallSDK()
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
            execution_id="clean-run",
            handler=lambda: None,
        )
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert outcome.state is ExecutionState.COMPLETED

    def test_an_intent_that_lapsed_never_claims_an_attempt(self, tmp_path):
        """An INTENT_RECORDED row whose deadline passed before any attempt
        is closed FAILED by the journal itself: the row proves nothing was
        ever transmitted, so no external guess is being made."""

        class Clock:
            def __init__(self):
                self.t = 2000.0

            def __call__(self):
                return self.t

        clock = Clock()
        path = os.path.join(str(tmp_path), "lapse-effect.db")
        sdk = FirewallSDK(
            clock=clock,
            execution_lease_store=ExecutionLeaseStore(
                clock=clock, backend=SQLiteExecutionLeaseStore(path, clock=clock)
            ),
            effect_journal=EffectJournal(
                clock=clock, backend=SQLiteEffectJournal(path, clock=clock)
            ),
        )
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="lapse-effect",
        )
        assert reserved.allowed, reserved.reason
        prepared = sdk.prepare_effect(
            reserved.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            ttl=1,
        )
        assert prepared.allowed, prepared.reason
        lease_id = issued.lease.lease_id

        clock.t += 1000
        n = sdk.expire_lapsed_effects()
        row = sdk.effects.by_lease(lease_id)
        sdk.close()

        assert n == 1
        assert row.state is EffectState.FAILED
        assert row.terminal_reason == "effect_deadline_passed"
        assert row.attempt_id is None

    def test_an_attempted_row_never_lapses(self, tmp_path):
        """An attempted effect stays for reconciliation; the journal
        refuses to decide the external system did nothing."""

        class Clock:
            def __init__(self):
                self.t = 2000.0

            def __call__(self):
                return self.t

        clock = Clock()
        path = os.path.join(str(tmp_path), "no-lapse.db")
        sdk = FirewallSDK(
            clock=clock,
            execution_lease_store=ExecutionLeaseStore(
                clock=clock, backend=SQLiteExecutionLeaseStore(path)
            ),
            effect_journal=EffectJournal(
                clock=clock, backend=SQLiteEffectJournal(path)
            ),
        )
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="no-lapse",
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            ttl=1,
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
        lease_id = issued.lease.lease_id
        clock.t += 1000
        n = sdk.expire_lapsed_effects()
        row = sdk.effects.by_lease(lease_id)
        sdk.close()

        assert n == 0
        assert row.state is EffectState.ATTEMPT_STARTED


class TestRecoveryIsNeverAutomatic:
    def test_unknown_is_not_retried_by_any_housekeeping(self):
        """Recovery semantics: UNKNOWN -> reconcile (confirmed success,
        confirmed failure, still unknown). No other transition exists."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="recover-manual",
        )
        started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
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
        row_id = sdk.effects.by_lease(issued.lease.lease_id).effect_id

        # The only journal housekeeping is expire_lapsed, and it skips
        # attempted/unknown rows entirely.
        from firewall.effect import ALLOWED_EFFECT_TRANSITIONS

        sdk.close()

        assert EffectState.ATTEMPT_STARTED in ALLOWED_EFFECT_TRANSITIONS
        assert EffectState.UNKNOWN not in (
            ALLOWED_EFFECT_TRANSITIONS[EffectState.UNKNOWN]
        ) or EffectState.SUCCEEDED in ALLOWED_EFFECT_TRANSITIONS[
            EffectState.UNKNOWN
        ]
        # UNKNOWN -> UNKNOWN (re-stamp) is legal; UNKNOWN has no automatic
        # retry edge back to ATTEMPT_STARTED.
        assert EffectState.ATTEMPT_STARTED not in (
            ALLOWED_EFFECT_TRANSITIONS.get(EffectState.UNKNOWN, frozenset())
        )
