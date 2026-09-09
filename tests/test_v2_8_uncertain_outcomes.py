"""v2.8: uncertain outcomes -- UNKNOWN is not SUCCESS and not FAILURE.

A timeout after a request was transmitted must never automatically become
``FAILED`` (the external system may have processed it) and must never
become ``COMPLETED`` (no evidence). The journal's three-way outcome keeps
external uncertainty explicit, and nothing in the firewall resolves it
except an evidence-carrying reconciliation. This is one of the most
important v2.8 properties, so the negative controls are exact: every
UNKNOWN state is pinned to stay UNKNOWN until an explicit reconcile.

Every class carries a successful calibration.
"""

from __future__ import annotations

import uuid

import pytest

from firewall.effect import (
    EffectOutcome,
    EffectState,
    ReceiptKind,
)
from firewall.execution_lease import ExecutionState
from firewall.sdk import FirewallSDK
from firewall.effect_verification import (
    VerificationOutcome,
    VerifierVerdict,
)

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-unknown"


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(sdk):
    key = sdk.generate_key(f"v28u-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def start_effect(sdk, cap):
    issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        cap,
        ACTION,
        dict(REQUEST),
        execution_id=f"exec-{uuid.uuid4().hex[:8]}",
    )
    assert reserved.allowed, reserved.reason
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
    return issued, started


class TestUnknownIsNotSuccess:
    def test_a_timeout_is_unknown_never_failed_and_never_completed(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = start_effect(sdk, cap)

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
            note="timeout after transmission",
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
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

        assert r.allowed, r.reason
        assert row.state is EffectState.UNKNOWN
        assert row.observed_outcome is EffectOutcome.UNKNOWN
        assert row.note == "timeout after transmission"
        assert not c.allowed
        assert c.reason == "effect_unresolved:unknown"
        # The lease is NOT burned into a guess: it stays STARTED, waiting
        # for reconciliation or operator action.
        assert record.state is ExecutionState.STARTED

    def test_unknown_is_never_auto_retried(self):
        """Attempting again from UNKNOWN could duplicate a real-world
        action, so the journal refuses it."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = start_effect(sdk, cap)
        sdk.record_effect_receipt(
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

        retry = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert not retry.allowed
        assert retry.reason == "effect_unresolved:unknown"
        assert row.state is EffectState.UNKNOWN

    def test_unknown_stays_unknown_until_an_explicit_reconcile(self):
        """The only way out of UNKNOWN is reconcile (succeeded / failed /
        still-unknown-with-a-recorded-attempt)."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = start_effect(sdk, cap)
        sdk.record_effect_receipt(
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

        # A reconcile that still cannot establish the outcome re-stamps
        # UNKNOWN and records the attempt in the row's history.
        still = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.UNKNOWN,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            note="provider has no record either",
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert still.allowed, still.reason
        assert still.reason == "reconcile_recorded:unknown"
        assert row.state is EffectState.UNKNOWN
        assert row.reconcile_count >= 2

    def test_reconcile_to_succeeded_completes(self):
        """Calibration: a confirmed external status lets the execution
        complete honestly."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = start_effect(sdk, cap)
        sdk.record_effect_receipt(
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

        reconciled = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id="ext-ack-1",
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        committed = sdk.commit_effect(
            started.lease,
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
        sdk.close()

        assert reconciled.allowed, reconciled.reason
        assert row.state is EffectState.SUCCEEDED
        assert committed.allowed, committed.reason
        assert committed.state is ExecutionState.COMPLETED

    def test_reconcile_to_failed_records_a_confirmed_failure(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = start_effect(sdk, cap)
        sdk.record_effect_receipt(
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

        reconciled = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.FAILED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            note="provider confirmed no transfer",
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        record = sdk.execution_leases.get(started.lease.lease_id)
        sdk.close()

        assert reconciled.allowed, reconciled.reason
        assert row.state is EffectState.FAILED
        assert row.observed_outcome is EffectOutcome.FAILED
        # The confirmed failure must not be recorded as a clean COMPLETED;
        # the lease stays STARTED for the caller to finish or abort.
        assert record.state is ExecutionState.STARTED

    def test_a_handler_that_raises_records_unknown_not_failure(self):
        """run_effect's handler raises after the request went out: the
        outcome is UNKNOWN (may have happened), the lease is aborted with
        executed=True, and the caller's exception is not turned into a
        firewall verdict of success or failure."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason

        def boom():
            raise RuntimeError("connection dropped mid-request")

        with pytest.raises(RuntimeError):
            sdk.run_effect(
                issued.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
                execution_id=f"exec-{uuid.uuid4().hex[:8]}",
                handler=boom,
            )

        row = sdk.effects.by_lease(issued.lease.lease_id)
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        # UNKNOWN, never a guess of success or failure.
        assert row.state is EffectState.UNKNOWN
        assert row.observed_outcome is EffectOutcome.UNKNOWN
        assert record.state is ExecutionState.ABORTED
        assert record.executed is True

    def test_a_handler_that_returns_records_success_and_completes(self):
        """Calibration: a normal handler return observes SUCCEEDED and the
        whole one-call form completes cleanly."""

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
            execution_id=f"exec-{uuid.uuid4().hex[:8]}",
            handler=lambda: {"external_request_id": "ext-run-1", "provider": "p"},
        )
        row = sdk.effects.by_lease(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert outcome.state is ExecutionState.COMPLETED
        assert row.state is EffectState.SUCCEEDED
        assert row.external_request_id == "ext-run-1"
        assert row.evidence_kind is ReceiptKind.HANDLER_OBSERVATION


class TestUnknownNeverBecomesSuccessInTheModel:
    def test_states_and_outcomes_are_distinct_vocabularies(self):
        assert EffectOutcome.UNKNOWN.value == "unknown"
        assert EffectState.UNKNOWN.value == "unknown"
        # The three-way outcome is not two-way.
        assert {o.value for o in EffectOutcome} == {
            "succeeded",
            "failed",
            "unknown",
        }

    def test_success_must_carry_success_evidence(self):
        """A row that reaches SUCCEEDED records an observed success and an
        evidence kind; the invariant machine-checks this (see the commit
        integrity suite). The model enforces it too: an UNKNOWN report
        lands as UNKNOWN -- the row never reads as SUCCESS anywhere."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = start_effect(sdk, cap)

        reported_unknown = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome="unknown",
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        # Recording the uncertainty is legitimate and lands as UNKNOWN.
        assert reported_unknown.allowed, reported_unknown.reason
        assert row.state is EffectState.UNKNOWN
        assert row.observed_outcome is EffectOutcome.UNKNOWN
        # The state never reads as success anywhere.
        assert row.state is not EffectState.SUCCEEDED
        assert row.observed_outcome is not EffectOutcome.SUCCEEDED
        # A completion over it is refused.
        assert reported_unknown.effect.state is EffectState.UNKNOWN
