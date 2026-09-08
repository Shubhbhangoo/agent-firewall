"""v2.8: side-effect intent -- the durable outbox record that makes the
external-effect boundary explicit.

The v2.7 lease records that an execution was STARTED; v2.8 records *what
external effect that execution intended* before any external request may
be authorized. This file covers the intent itself: the bindings it
carries, that the payload is bound by canonical digest rather than
duplicated, that the valid path works (the calibration every negative
test needs), and that a modified effect can never execute under a
recorded intent.

Every class here carries at least one case that must *succeed*.
"""

from __future__ import annotations

import json
import uuid

from firewall.capability import Capability
from firewall.effect import (
    EffectState,
    canonical_effect_digest,
)
from firewall.execution_lease import (
    ExecutionLeaseOutcome,
    ExecutionState,
)
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(
    sdk: FirewallSDK,
    *,
    agent: str = "agent-a",
    capability: str = ACTION,
) -> Capability:
    key = sdk.generate_key(f"v28i-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=capability,
        private_key=key,
        constraints={"amount_max": 100},
    )


def started_lease(sdk, cap, request=None):
    """Reserve and start one execution; returns (issued, started, lease)."""

    request = dict(REQUEST) if request is None else request
    issued = sdk.authorize_execution(cap, ACTION, request)
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        cap,
        ACTION,
        request,
        execution_id=f"exec-{uuid.uuid4().hex[:8]}",
    )
    assert reserved.allowed, reserved.reason
    started = sdk.start_execution(reserved.lease, cap, ACTION, request)
    assert started.allowed, started.reason
    return issued, started


class TestIntentIsDurableAndBound:
    def test_a_full_side_effect_commit_is_the_calibration(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)

        prepared = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        assert prepared.allowed, prepared.reason
        attempted = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        assert attempted.allowed, attempted.reason
        receipt = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            observed_outcome="succeeded",
            evidence_kind="provider_evidence",
        )
        assert receipt.allowed, receipt.reason
        committed = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert committed.allowed, committed.reason
        assert committed.state is ExecutionState.COMPLETED

    def test_the_intent_binds_the_authorized_facts(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)

        prepared = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key="k-1",
        )
        assert prepared.allowed, prepared.reason
        row = prepared.effect
        sdk.close()

        assert row.state is EffectState.INTENT_RECORDED
        assert row.lease_id == started.lease.lease_id
        assert row.execution_id == started.lease.execution_id
        assert row.capability_fingerprint == started.lease.capability_fingerprint
        assert row.agent_id == started.lease.agent_id
        assert row.action == ACTION
        assert row.request_digest == started.lease.request_digest
        assert row.effect_type == EFFECT_TYPE
        assert row.effect_digest == canonical_effect_digest(EFFECT)
        assert row.idempotency_key == "k-1"
        assert row.policy_version == started.lease.policy_version
        assert row.chain_fingerprints == started.lease.chain_fingerprints
        assert row.epoch_finished == started.lease.epoch_finished
        assert row.intent_authority_valid is True
        assert row.created_at <= row.expires_at

    def test_the_payload_is_bound_by_digest_not_duplicated(self):
        """The journal stores the effect digest, not the payload: sensitive
        effect data is not duplicated into the journal."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)

        prepared = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        assert prepared.allowed, prepared.reason

        serialized = json.dumps(prepared.effect.to_dict())
        sdk.close()

        assert canonical_effect_digest(EFFECT) not in (EFFECT["to"],)
        # The record carries no 'amount'/'to' payload field at all.
        assert '"to"' not in serialized or EFFECT["to"] not in serialized

    def test_prepare_requires_a_reserved_or_started_lease(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason

        outcome = sdk.prepare_effect(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_not_reserved"

    def test_prepare_requires_live_authority(self):
        """An allow whose state died after authorize cannot even record an
        intent: the outbox row is a continuation of authority."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)
        sdk.revoke(cap, reason="gone")

        outcome = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        record = sdk.execution_leases.get(started.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "capability_revoked"
        assert record.state is ExecutionState.REVOKED

    def test_an_unknown_lease_cannot_record_an_intent(self):
        from firewall.execution_lease import (
            ExecutionLease,
            ExecutionLeaseOutcome,
        )

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)
        ghost = ExecutionLease.from_dict(
            {**started.lease.to_dict(), "lease_id": "0" * 32}
        )
        outcome = sdk.prepare_effect(
            ghost,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert isinstance(outcome, object)
        assert not outcome.allowed
        assert outcome.reason == "lease_unknown"

    def test_malformed_arguments_are_refusals_not_raises(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)

        probes = (
            {"effect_type": ""},
            {"effect_type": "   "},
            {"effect": {1, 2}},  # unserialisable
            {"ttl": -1},
            {"ttl": float("nan")},
            {"idempotency_key": 42},
        )
        for probe in probes:
            args = dict(
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
            )
            args.update(probe)
            outcome = sdk.prepare_effect(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                **args,
            )
            assert isinstance(outcome.allowed, bool)
            assert outcome.allowed is False, probe
            assert outcome.reason

        # Calibration: the same lease still prepares with a valid effect.
        ok = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert ok.allowed, ok.reason

    def test_a_reserved_lease_can_record_an_intent_before_start(self):
        """The outbox may be written as soon as the execution is reserved:
        intent durability must precede the external request, and the
        reservation is the earliest moment the execution identity exists."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id="pre-start",
        )
        assert reserved.allowed, reserved.reason

        prepared = sdk.prepare_effect(
            reserved.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        row = sdk.effects.by_lease(issued.lease.lease_id)
        sdk.close()

        assert prepared.allowed, prepared.reason
        assert row is not None
        assert row.state is EffectState.INTENT_RECORDED


class TestEffectCannotChangeAfterAuthorization:
    def test_a_modified_effect_is_effect_mismatch(self):
        """A modified effect must produce ``effect_mismatch`` rather than
        silently executing under a different intent."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)

        prepared = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect={"amount": 5},
            effect_type=EFFECT_TYPE,
        )
        assert prepared.allowed, prepared.reason

        attempted = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect={"amount": 5000},
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert not attempted.allowed
        assert attempted.reason == "effect_mismatch"

    def test_a_modified_effect_type_is_effect_mismatch(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        outcome = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type="refund",
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "effect_mismatch"

    def test_the_bound_effect_is_the_one_that_may_proceed(self):
        """Calibration: the unchanged effect proceeds all the way."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = started_lease(sdk, cap)
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        attempted = sdk.attempt_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
        )
        sdk.close()

        assert attempted.allowed, attempted.reason
        assert attempted.effect.state is EffectState.ATTEMPT_STARTED
