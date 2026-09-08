"""v2.8: commit integrity -- the machine-checked invariant that a side
effect never claims more certainty, authority or completion than the
protocol established.

``SIDE_EFFECT_COMMIT_INTEGRITY`` (registered, the nineteenth invariant)
checks three halves: the side-effect state-machine algebra, a source
census in both directions over who may drive the side-effect journal (a
future ``external_execute(...)`` that writes the journal outside the
protocol fails the gate), and the hygiene of every recorded row crossed
against the lease journal. This file tests the invariant's teeth and its
calibrations.

Every class carries a positive control: the identical state produced
through the real protocol reports HOLDS.
"""

from __future__ import annotations

import uuid

from dataclasses import replace

from firewall.effect import (
    EffectJournal,
    EffectOutcome,
    EffectState,
    ReceiptKind,
    is_terminal_effect,
)
from firewall.execution_lease import (
    ExecutionState,
)
from firewall.invariants import (
    check_side_effect_commit_integrity,
)
from firewall.invariants.model import InvariantStatus
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-integrity"


def make_capability(sdk):
    key = sdk.generate_key(f"v28c-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def walk_clean_side_effect(sdk, cap):
    """The real protocol to a clean SUCCEEDED row on a STARTED lease."""
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
    receipt = sdk.record_effect_receipt(
        started.lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        observed_outcome=EffectOutcome.SUCCEEDED,
        evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        external_request_id="ext-integrity",
    )
    assert receipt.allowed, receipt.reason
    return issued, receipt.effect


def audit(sdk):
    return check_side_effect_commit_integrity(sdk)


class TestCalibrationAndToothlessness:
    def test_the_calibration_records_hold(self):
        """The state the real protocol produces must not be a violation."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, row = walk_clean_side_effect(sdk, cap)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS
        assert row.state is EffectState.SUCCEEDED

    def test_a_fresh_sdk_is_unverifiable_not_violated(self):
        """No recorded side effect means the record half was never
        exercised; the invariant must say so rather than pass."""

        sdk = FirewallSDK()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE

    def test_the_completed_execution_with_its_side_effect_holds(self):
        """The strongest positive control: COMMIT is complete, the lease is
        COMPLETED, and the invariant is HOLDS."""

        sdk = FirewallSDK()
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
            execution_id="full-commit",
            handler=lambda: {"external_request_id": "ext-full"},
        )
        assert outcome.allowed, outcome.reason
        result = audit(sdk)
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert record.state is ExecutionState.COMPLETED
        assert result.status is InvariantStatus.HOLDS


class TestRecordHygieneTeeth:
    def _sdk_with_attempt_row(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, row = walk_clean_side_effect(sdk, cap)
        return sdk, row

    def test_succeeded_without_observed_success_is_a_violation(self):
        """UNKNOWN must never read as SUCCESS, and a SUCCEEDED row must
        carry a success observation."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="tamper-1",
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
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
        row = sdk.effects.by_lease(issued.lease.lease_id)

        # A forged 'SUCCEEDED with no observed outcome and no evidence
        # kind' row -- the exact lie the protocol exists to prevent.
        forged = replace(
            row,
            state=EffectState.SUCCEEDED,
            observed_outcome=None,
            evidence_kind=None,
            history=row.history
            + ((row.state, EffectState.SUCCEEDED, 1.0, "forged"),),
        )
        sdk.effects._records[forged.effect_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("recorded success" in f for f in result.findings)
        assert any("evidence kind" in f for f in result.findings)

    def test_unknown_missing_evidence_kind_is_a_violation(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="tamper-2",
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
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
        row = sdk.effects.by_lease(issued.lease.lease_id)
        forged = replace(
            row,
            state=EffectState.UNKNOWN,
            observed_outcome=EffectOutcome.UNKNOWN,
            evidence_kind=None,
            history=row.history
            + ((row.state, EffectState.UNKNOWN, 1.0, "forged"),),
        )
        sdk.effects._records[forged.effect_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("who reported the uncertainty" in f for f in result.findings)

    def test_a_replayed_terminal_entry_is_a_violation(self):
        """A history that enters a confirmed outcome twice is the trace a
        replayed receipt would leave."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="tamper-3",
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
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
        row = sdk.effects.by_lease(issued.lease.lease_id)
        replayed = replace(
            row,
            state=EffectState.SUCCEEDED,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.CALLER_ASSERTION,
            history=row.history
            + (
                (row.state, EffectState.SUCCEEDED, 1.0, "first"),
                (EffectState.SUCCEEDED, EffectState.SUCCEEDED, 2.0, "replay"),
            ),
        )
        sdk.effects._records[replayed.effect_id] = replayed
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("replayed receipt" in f for f in result.findings)

    def test_attempt_without_attempt_id_is_a_violation(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="tamper-4",
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
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
        row = sdk.effects.by_lease(issued.lease.lease_id)
        forged = replace(row, attempt_id=None)
        sdk.effects._records[forged.effect_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("attempt identifier" in f for f in result.findings)

    def test_a_row_bound_to_no_lease_is_a_violation(self):
        """A receipt can never belong to another -- or to no -- execution."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, row = walk_clean_side_effect(sdk, cap)
        orphan = replace(row, lease_id="0" * 32)
        sdk.effects._records[orphan.effect_id] = orphan
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("which does not exist" in f for f in result.findings)


class TestTheJournalIsNotAuthority:
    def test_the_invariant_grants_nothing(self):
        """A HOLDS report on a healthy journal does not make a denied
        authorization allowed."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, row = walk_clean_side_effect(sdk, cap)
        result = audit(sdk)

        # An unrelated over-ceiling request is still denied.
        denied = sdk.authorize(cap, ACTION, {"amount": 10_000})
        sdk.close()

        assert result.status is InvariantStatus.HOLDS
        assert denied.allowed is False

    def test_evidence_kind_never_advances_a_denied_execution(self):
        """Even provider-labelled evidence cannot resurrect a lease whose
        authority was withdrawn: the receipt flag carries the truth."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="no-resurrect",
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
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
        sdk.revoke(cap, reason="withdrawn")
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
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not r.allowed
        assert record.state is ExecutionState.REVOKED
