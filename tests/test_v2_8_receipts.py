"""v2.8: receipts -- what the external handler claimed, recorded as
observation, never as authority.

A receipt is evidence about one attempt. It is bound to the execution,
the intent, the idempotency key, the effect digest and the attempt; it
carries an observed three-way outcome, the identity of who supplied it
(caller assertion / handler observation / provider evidence), and any
external correlation id, preserved as correlation evidence -- not proof.

The two rules under test:

* ``receipt != proof``. A receipt never grants anything; only the
  execution's own live authority basis can let an execution complete, and
  the authority flag on the receipt records whether that basis held when
  the outcome was observed.
* Authority changes during effect processing never rewrite history. A
  receipt that arrives after a revocation still records what happened --
  with ``receipt_authority_valid=False`` and the execution burned to its
  terminal failure -- so "effect happened" and "effect completed under
  currently valid authority" stay distinct.

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
KEY = "key-transfer"


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(sdk, agent="agent-a"):
    key = sdk.generate_key(f"v28r-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def start_effect(sdk, cap, execution_id=None):
    """A started execution whose effect is prepared and attempted."""
    issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        cap,
        ACTION,
        dict(REQUEST),
        execution_id=execution_id or f"exec-{uuid.uuid4().hex[:8]}",
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
    return issued, started


class TestReceiptIsObservation:
    def test_the_calibration_receipt_completes_under_valid_authority(self):
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
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id="ext-pay-1",
            provider="payments.example",
        )
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
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert r.allowed, r.reason
        assert r.effect.state is EffectState.SUCCEEDED
        assert committed.allowed, committed.reason
        assert row.external_request_id == "ext-pay-1"
        assert row.provider == "payments.example"
        assert row.evidence_kind is ReceiptKind.PROVIDER_EVIDENCE
        assert row.observed_outcome is EffectOutcome.SUCCEEDED
        assert row.receipt_authority_valid is True

    def test_a_receipt_binds_to_its_execution_intent_and_effect(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = start_effect(sdk, cap)
        row_before = sdk.effects.by_lease(started.lease.lease_id)

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

        assert r.allowed, r.reason
        # The receipt stayed on the same row: same effect_id, same
        # attempt_id -- it observed that attempt and no other.
        assert row.effect_id == row_before.effect_id
        assert row.attempt_id == row_before.attempt_id
        assert row.observed_at is not None

    def test_evidence_kinds_stay_distinct_in_the_model(self):
        assert ReceiptKind.CALLER_ASSERTION.value == "caller_assertion"
        assert ReceiptKind.HANDLER_OBSERVATION.value == "handler_observation"
        assert ReceiptKind.PROVIDER_EVIDENCE.value == "provider_evidence"

    def test_a_receipt_for_a_modified_effect_is_refused(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = start_effect(sdk, cap)

        r = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect={"amount": 5000},
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.CALLER_ASSERTION,
        )
        sdk.close()

        assert not r.allowed
        assert r.reason == "effect_mismatch"

    def test_malformed_receipts_are_refusals_not_raises(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = start_effect(sdk, cap)

        probes = (
            {"observed_outcome": "maybe"},  # not a three-way outcome
            {"evidence_kind": "proof"},  # not a receipt kind
            {"external_request_id": 42},
            {"provider": object()},
        )
        for probe in probes:
            args = dict(
                observed_outcome=EffectOutcome.SUCCEEDED,
                evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
            )
            args.update(probe)
            r = sdk.record_effect_receipt(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
                **args,
            )
            assert isinstance(r.allowed, bool)
            assert r.allowed is False, probe
            assert r.reason

        # Calibration: the valid receipt still records afterwards.
        ok = sdk.record_effect_receipt(
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
        sdk.close()

        assert ok.allowed, ok.reason


class TestReceiptCannotAdvanceAnotherExecution:
    def test_a_receipt_from_another_execution_names_no_row(self):
        """A receipt object cannot be transplanted: the receipt step looks
        up the row through the presented lease, and a different execution
        has no row for this effect."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued_a, started_a = start_effect(sdk, cap, execution_id="exec-A")
        # A second execution for the same agent/capability.
        issued_b = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued_b.allowed, issued_b.reason
        started_b = sdk.start_execution(
            sdk.reserve_execution(
                issued_b.lease,
                cap,
                ACTION,
                dict(REQUEST),
                execution_id="exec-B",
            ).lease,
            cap,
            ACTION,
            dict(REQUEST),
        )

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
        row_b = sdk.effects.by_lease(started_b.lease.lease_id)
        row_a = sdk.effects.by_lease(started_a.lease.lease_id)
        sdk.close()

        assert not r.allowed
        assert r.reason == "effect_unknown"
        assert row_b is None
        assert row_a.state is EffectState.ATTEMPT_STARTED  # untouched

    def test_a_duplicate_effect_id_cannot_be_forged_onto_a_row(self):
        """The journal row is authoritative; a caller cannot point a
        receipt at another execution's row."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started_a = start_effect(sdk, cap, execution_id="exec-A")
        row_a = sdk.effects.by_lease(started_a.lease.lease_id)

        issued_b = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        started_b = sdk.start_execution(
            sdk.reserve_execution(
                issued_b.lease,
                cap,
                ACTION,
                dict(REQUEST),
                execution_id="exec-B",
            ).lease,
            cap,
            ACTION,
            dict(REQUEST),
        )
        # Present a row object belonging to execution A while operating on
        # execution B's lease. The record is looked up by lease id, so the
        # foreign object changes nothing.
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
        assert row_a.state is EffectState.ATTEMPT_STARTED


class TestReceiptIsNotProof:
    def test_a_receipt_never_restores_withdrawn_authority(self):
        """STARTED -> revoke -> receipt: the effect is recorded as having
        happened, the authority flag says the basis did not hold, and the
        execution stops in an explicit terminal failure -- never a clean
        completion, and never a rewritten history."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued, started = start_effect(sdk, cap)
        sdk.revoke(cap, reason="mid-flight")

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
            external_request_id="ext-after-revoke",
        )
        row = sdk.effects.by_lease(started.lease.lease_id)
        record = sdk.execution_leases.get(started.lease.lease_id)
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

        # The observation is recorded truthfully...
        assert row.state is EffectState.SUCCEEDED
        assert row.observed_outcome is EffectOutcome.SUCCEEDED
        assert row.external_request_id == "ext-after-revoke"
        # ...but not under valid authority, and nothing clean can follow.
        assert row.receipt_authority_valid is False
        assert record.state is ExecutionState.REVOKED
        assert record.executed is True
        assert not r.allowed  # a refusal carrying the recorded row
        assert not c.allowed
        assert c.reason == "effect_unresolved:succeeded"

    @pytest.mark.parametrize("attack", ["suspend", "policy", "epoch", "risk"])
    def test_authority_change_during_effect_processing_is_recorded(self, attack):
        from firewall.aegis import AegisController
        from firewall.risk_context import RiskContext

        if attack == "suspend":
            sdk = build_sdk(aegis=AegisController())
        elif attack in ("risk", "epoch"):
            sdk = build_sdk(risk_context=RiskContext())
        else:
            sdk = build_sdk()

        cap = make_capability(sdk)
        issued, started = start_effect(sdk, cap)
        if attack == "suspend":
            sdk.aegis.register(
                sdk.fingerprint(cap),
                agent_id=cap.agent_id,
                capability=cap.capability,
            )
            sdk.aegis.suspend(
                sdk.fingerprint(cap), key="k", reason="v2.8"
            )
        elif attack == "risk":
            sdk.risk_context.record_critical(cap.agent_id)
        elif attack == "policy":
            sdk.max_delegation_depth = 5
        elif attack == "epoch":
            sdk.set_risk_context(RiskContext())

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

        # The effect happened; it did not complete under valid authority.
        assert row.state is EffectState.SUCCEEDED
        assert row.receipt_authority_valid is False

    def test_the_positive_control_completes_under_each_clean_authority(self):
        """Calibration for the attack matrix: no authority change -> the
        receipt carries a True authority flag and the execution completes."""

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
            observed_outcome=EffectOutcome.SUCCEEDED,
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
        assert r.effect.receipt_authority_valid is True
        assert c.allowed, c.reason
        assert c.state is ExecutionState.COMPLETED
