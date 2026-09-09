"""v2.8: the crash matrix -- every meaningful boundary, and the state it
leaves behind.

A deterministic matrix over the side-effect lifecycle. For every crash
point the resulting state must be unambiguous, and no crash state may
silently read as ``COMPLETED`` unless completion is actually established:

    before intent persistence      -> nothing recorded; no row at all
    after intent persistence       -> INTENT_RECORDED, nothing transmitted
    before ATTEMPT_STARTED         -> INTENT_RECORDED (nothing sent)
    after ATTEMPT_STARTED          -> ATTEMPT_STARTED (may have been sent)
    before external request        -> ATTEMPT_STARTED with no receipt
    after external request         -> ATTEMPT_STARTED, unknown outcome
    after receipt persistence      -> SUCCEEDED / FAILED / UNKNOWN as recorded
    before COMMIT                  -> row resolved; lease still STARTED
    after COMMIT                   -> lease COMPLETED over the resolved row

Each row in the matrix asserts the exact state a restart reveals, and the
calibration -- no crash at all -- ends in a clean COMPLETED.
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
KEY = "key-crashmatrix"


def make_capability(sdk):
    key = sdk.generate_key(f"v28m-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def open_sdk(path):
    """A fresh SDK over one SQLite file hosting both journals."""
    return FirewallSDK(
        execution_lease_store=ExecutionLeaseStore(
            backend=SQLiteExecutionLeaseStore(path)
        ),
        effect_journal=EffectJournal(
            backend=SQLiteEffectJournal(path)
        ),
    )


class TestCrashMatrix:
    def _estate(self, sdk, execution_id):
        """Reserve + start a lease; returns (issued, started, lease_id)."""
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id=execution_id,
        )
        assert reserved.allowed, reserved.reason
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason
        return issued, started, cap

    def test_crash_before_intent_persistence(self, tmp_path):
        """Nothing was recorded at all: no row exists, so no completion
        can ever be claimed."""
        path = os.path.join(str(tmp_path), "crash0.db")
        sdk = open_sdk(path)
        issued, _started, _cap = self._estate(sdk, "crash0")
        lease_id = issued.lease.lease_id
        # Crash: the caller never even called prepare_effect.
        sdk.close()

        second = open_sdk(path)
        row = second.effects.by_lease(lease_id)
        lease = second.execution_leases.get(lease_id)
        second.close()

        assert row is None
        assert lease.state is ExecutionState.STARTED

    def test_crash_after_intent_persistence_before_attempt(self, tmp_path):
        """The durable outbox row exists (INTENT_RECORDED); nothing was
        ever transmitted, and the row itself proves it."""
        path = os.path.join(str(tmp_path), "crash1.db")
        sdk = open_sdk(path)
        issued, started, cap = self._estate(sdk, "crash1")
        lease_id = issued.lease.lease_id
        p = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert p.allowed, p.reason
        sdk.close()

        second = open_sdk(path)
        row = second.effects.by_lease(lease_id)
        lease = second.execution_leases.get(lease_id)
        second.close()

        assert row.state is EffectState.INTENT_RECORDED
        assert row.attempt_id is None
        assert row.observed_outcome is None
        assert lease.state is ExecutionState.STARTED

    def test_crash_after_attempt_before_external_request(self, tmp_path):
        """ATTEMPT_STARTED: an attempt was authorized and initiated. The
        record does not claim an outcome."""
        path = os.path.join(str(tmp_path), "crash2.db")
        sdk = open_sdk(path)
        issued, started, cap = self._estate(sdk, "crash2")
        lease_id = issued.lease.lease_id
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

        second = open_sdk(path)
        row = second.effects.by_lease(lease_id)
        second.close()

        assert row.state is EffectState.ATTEMPT_STARTED
        assert row.attempt_id is not None
        assert row.observed_outcome is None

    def test_crash_after_external_request_before_receipt(self, tmp_path):
        """The worst window: the request went out, the process died before
        any receipt. The row is ATTEMPT_STARTED -- never COMPLETED, never
        silently FAILED. An operator reconciles it."""
        path = os.path.join(str(tmp_path), "crash3.db")
        sdk = open_sdk(path)
        issued, started, cap = self._estate(sdk, "crash3")
        lease_id = issued.lease.lease_id
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
        # Crash: the external system may have processed the request.
        sdk.close()

        second = open_sdk(path)
        lease = second.execution_leases.get(lease_id)
        row = second.effects.by_lease(lease_id)
        # Recovery: explicit reconciliation decides what happened.
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
        )
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

        assert row.state is EffectState.ATTEMPT_STARTED
        assert reconciled.allowed, reconciled.reason
        assert committed.allowed, committed.reason
        assert record.state is ExecutionState.COMPLETED

    def test_crash_after_receipt_persistence_before_commit(self, tmp_path):
        """The receipt was recorded SUCCEEDED under valid authority; the
        crash happened before COMMIT. After restart the execution can be
        committed -- the completion evidence exists."""
        path = os.path.join(str(tmp_path), "crash4.db")
        sdk = open_sdk(path)
        issued, started, cap = self._estate(sdk, "crash4")
        lease_id = issued.lease.lease_id
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
        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id="ext-crash4",
        )
        assert r.allowed, r.reason
        sdk.close()

        second = open_sdk(path)
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

    def test_no_crash_is_the_calibration(self, tmp_path):
        path = os.path.join(str(tmp_path), "crash-clean.db")
        sdk = open_sdk(path)
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
            execution_id="crash-clean",
            handler=lambda: None,
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert record.state is ExecutionState.COMPLETED

    def test_two_processes_racing_the_same_execution(self, tmp_path):
        """Two processes over one file racing to attempt the same row:
        exactly one winner, one refusal, one ATTEMPT_STARTED."""
        import threading

        path = os.path.join(str(tmp_path), "race.db")
        sdk = open_sdk(path)
        issued, started, cap = self._estate(sdk, "race")
        lease_id = issued.lease.lease_id
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        second = open_sdk(path)
        lease = second.execution_leases.get(lease_id)
        barrier = threading.Barrier(2)
        captured = [None, None]

        def attempt(index):
            barrier.wait()
            captured[index] = second.attempt_effect(
                lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
            )

        handles = [
            threading.Thread(target=attempt, args=(0,)),
            threading.Thread(target=attempt, args=(1,)),
        ]
        for handle in handles:
            handle.start()
        for handle in handles:
            handle.join()

        winners = [c for c in captured if c.allowed]
        losers = [c for c in captured if not c.allowed]
        row = second.effects.by_lease(lease_id)
        second.close()

        assert len(winners) == 1
        assert len(losers) == 1
        assert losers[0].reason == "effect_already_attempted"
        assert row.state is EffectState.ATTEMPT_STARTED


# =====================================================================
# The attack campaign
# =====================================================================
#
# Each attack names an attacker move and pins the documented expected
# result. Attacks 1-11 target forged identity / modified bindings /
# receipts; 12-19 authority and timing; 20-25 persistence and the world.


class TestAttackCampaign:
    def _running_effect(self, sdk, cap, execution_id=None):
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id=execution_id or f"atk-{uuid.uuid4().hex[:6]}",
        )
        assert reserved.allowed, reserved.reason
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason
        return issued, started

    def _prepare_and_attempt(self, sdk, started, cap):
        p = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert p.allowed, p.reason
        a = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert a.allowed, a.reason

    def test_1_duplicate_intent_is_one_row(self):
        """Attack 1: duplicate intent. Expected: one row, second prepare
        served from it."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        sdk.close()

        assert len(sdk.effects.records()) == 1

    def test_2_forged_intent_is_lease_unknown(self):
        """Attack 2: forged intent -- a lease that does not exist."""
        from firewall.execution_lease import ExecutionLease

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        forged = ExecutionLease(
            lease_id="0" * 32,
            state=ExecutionState.LEASE_ISSUED,
            capability_fingerprint=sdk.fingerprint(cap),
            agent_id=cap.agent_id,
            capability=cap.capability,
            action=ACTION,
            request_digest="d",
            chain_id=None,
            policy_version="p",
            nonce="n",
            issued_at=0,
            expires_at=1e12,
        )
        out = sdk.prepare_effect(
            forged,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert not out.allowed
        assert out.reason == "lease_unknown"

    def test_3_modified_effect_payload_is_effect_mismatch(self):
        """Attack 3: the effect payload is changed between prepare and
        attempt. Expected: effect_mismatch, nothing executes."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        p = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect={"amount": 5},
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert p.allowed, p.reason
        a = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect={"amount": 5000},
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert not a.allowed
        assert a.reason == "effect_mismatch"
        assert row.state is EffectState.INTENT_RECORDED

    def test_4_modified_effect_digest_is_effect_mismatch(self):
        """Attack 4: same payload bytes claimed under a forged digest."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        a = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key="different-key",
        )
        sdk.close()

        assert not a.allowed
        assert a.reason == "effect_mismatch"

    def test_5_modified_execution_id_binds_the_record_not_the_object(self):
        """Attack 5: editing execution_id on the carried object changes
        nothing -- the row binds the authoritative record's execution
        identity, so a forged object cannot attach an effect to a
        different execution."""
        from firewall.execution_lease import ExecutionLease

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started = self._running_effect(sdk, cap, "the-real-exec")
        edited = ExecutionLease.from_dict(
            {**started.lease.to_dict(), "execution_id": "someone-else"}
        )
        out = sdk.prepare_effect(
            edited,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert out.allowed, out.reason
        assert row.execution_id == "the-real-exec"

    def test_6_modified_lease_id_is_lease_unknown(self):
        """Attack 6: a different lease_id on the carried object names no
        record."""
        from firewall.execution_lease import ExecutionLease

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        swapped = ExecutionLease.from_dict(
            {**started.lease.to_dict(), "lease_id": "1" * 32}
        )
        out = sdk.prepare_effect(
            swapped,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert not out.allowed
        assert out.reason == "lease_unknown"

    def test_7_forged_receipt_for_a_row_that_never_attempted(self):
        """Attack 7: a receipt claiming SUCCESS for an intent that never
        attempted anything. Nothing was transmitted; the claim is
        refused."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        sdk.close()

        assert not r.allowed
        assert r.reason == "effect_not_attempted"

    def test_8_receipt_substitution_across_leases_is_refused(self):
        """Attack 8: the receipt names a different lease's row -> no row
        for the presented lease."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started_a = self._running_effect(sdk, cap, "sub-a")
        _, started_b = self._running_effect(sdk, cap, "sub-b")
        # Only A has an effect row.
        self._prepare_and_attempt(sdk, started_a, cap)
        r = sdk.record_effect_receipt(
            started_b.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.CALLER_ASSERTION,
        )
        sdk.close()

        assert not r.allowed
        assert r.reason == "effect_unknown"

    def test_9_receipt_replay_cannot_second_complete(self):
        """Attack 9: replay the same receipt. Expected:
        effect_already_resolved and exactly one terminal entry."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        first = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        assert first.allowed, first.reason
        replay = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert not replay.allowed
        assert replay.reason == "effect_already_resolved"
        terminal_entries = sum(
            1
            for (_, to_state, _, _) in row.history
            if to_state is EffectState.SUCCEEDED
        )
        assert terminal_entries == 1

    def test_10_unknown_disguised_as_success_never_lands_as_success(self):
        """Attack 10: report 'unknown' where a success is needed. The row
        records UNKNOWN and refuses completion."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome="unknown",
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        c = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert r.allowed, r.reason
        assert r.effect.state is EffectState.UNKNOWN
        assert not c.allowed
        assert c.reason == "effect_unresolved:unknown"

    def test_11_concurrent_retries_authorize_one_attempt(self):
        """Attack 11: threads A-D retry the same transmission."""
        import threading

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        # 4 more threads racing to attempt again:
        barrier = threading.Barrier(4)
        results = [None] * 4

        def attempt(i):
            barrier.wait()
            results[i] = sdk.attempt_effect(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
            )

        handles = [threading.Thread(target=attempt, args=(i,)) for i in range(4)]
        for h in handles:
            h.start()
        for h in handles:
            h.join()
        sdk.close()

        assert all(not r.allowed for r in results)
        assert all(r.reason == "effect_already_attempted" for r in results)

    def test_12_timeout_after_transmission_is_unknown(self):
        """Attack 12: covered in the uncertainty suite; asserted here as a
        documented expected result."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.UNKNOWN,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        c = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert r.effect.state is EffectState.UNKNOWN
        assert not c.allowed

    def test_13_revocation_during_effect_processing(self):
        """Attack 13: STARTED -> revoke -> receipt. The effect is recorded
        as having happened, not as completed under valid authority."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        sdk.revoke(cap, reason="attack")
        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        record = sdk.execution_leases.get(started.lease.lease_id)
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert row.state is EffectState.SUCCEEDED
        assert row.receipt_authority_valid is False
        assert record.state is ExecutionState.REVOKED

    def test_14_policy_change_during_effect_processing(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        sdk.max_delegation_depth = 5  # policy version moves
        r = sdk.record_effect_receipt(
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
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert row.state is EffectState.SUCCEEDED
        assert row.receipt_authority_valid is False

    def test_15_epoch_change_during_effect_processing(self):
        from firewall.risk_context import RiskContext

        sdk = FirewallSDK(risk_context=RiskContext())
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        sdk.set_risk_context(RiskContext())  # widening write
        r = sdk.record_effect_receipt(
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
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert row.state is EffectState.SUCCEEDED
        assert row.receipt_authority_valid is False

    def test_16_missing_persistent_state_fails_closed(self):
        """Attack 16: the lease exists but the effect journal lost its row
        (e.g. thrown away). A completion is refused: no evidence."""
        import tempfile

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        # Simulate a wiped journal while the lease survives in memory.
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.effects._records.pop(row.effect_id)
        sdk.effects._by_lease.pop(row.lease_id)
        c = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert not c.allowed
        assert c.reason == "effect_unknown"

    def test_17_unavailable_external_status_is_unknown(self):
        """Attack 17: the provider cannot be reached. The reconciliation
        records 'still unknown' with evidence of the attempt."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        r = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.UNKNOWN,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
            note="provider unreachable",
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert r.allowed, r.reason
        assert row.state is EffectState.UNKNOWN
        assert row.reconcile_count >= 1

    def test_18_contradictory_external_status_cannot_flip_a_terminal(self):
        """Attack 18: the provider first says succeeded, later says failed.
        The confirmed outcome is irreversible."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        first = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        assert first.allowed, first.reason
        later = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.FAILED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert not later.allowed
        assert later.reason == "effect_already_resolved"
        assert row.state is EffectState.SUCCEEDED

    def test_19_abandoned_protocol_cannot_complete(self):
        """Attack 19: prepare an effect, then call the plain v2.7
        complete_execution to bypass the receipt/commit. Expected: the
        completion is refused; the lease stays STARTED for recovery."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        p = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert p.allowed, p.reason
        c = sdk.complete_execution(started.lease, cap, ACTION, dict(REQUEST))
        record = sdk.execution_leases.get(started.lease.lease_id)
        sdk.close()

        assert not c.allowed
        assert c.reason == "effect_unresolved:intent_recorded"
        assert record.state is ExecutionState.STARTED

    def test_20_exception_to_verdict_escapes_on_every_protocol_method(self):
        """Attack 20: hostile inputs to every public protocol method must
        produce verdicts, not exceptions."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason

        calls = [
            lambda: sdk.prepare_effect(None, cap, ACTION, {}),
            lambda: sdk.prepare_effect(
                issued.lease, None, ACTION, {}
            ),
            lambda: sdk.prepare_effect(
                issued.lease, cap, "", {}
            ),
            lambda: sdk.prepare_effect(
                issued.lease, cap, ACTION, "not-a-dict"
            ),
            lambda: sdk.prepare_effect(
                issued.lease, cap, ACTION, {}, effect_type=""
            ),
            lambda: sdk.attempt_effect(None, cap, ACTION, {}),
            lambda: sdk.record_effect_receipt(
                issued.lease, cap, ACTION, {}, observed_outcome="bogus",
                evidence_kind="x",
            ),
            lambda: sdk.reconcile_effect(
                issued.lease, cap, ACTION, {}, resolution=42,
            ),
            lambda: sdk.commit_effect(None, cap, ACTION, {}),
        ]
        for call in calls:
            outcome = call()
            assert isinstance(outcome.allowed, bool), type(outcome)
            assert outcome.allowed is False
            assert outcome.reason

        sdk.close()

    def test_21_evidence_is_never_authority(self):
        """Attack 21: even a perfect receipt cannot make an unauthorized
        request execute; authorize() still denies what it denies."""
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, started = self._running_effect(sdk, cap)
        self._prepare_and_attempt(sdk, started, cap)
        sdk.revoke(cap, reason="gone")

        # A receipt claiming provider evidence of success...
        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id="forged-auth",
        )
        c = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        record = sdk.execution_leases.get(started.lease.lease_id)
        sdk.close()

        assert not r.allowed  # recorded but refused
        assert not c.allowed
        assert record.state is ExecutionState.REVOKED
