"""v2.8: idempotency -- the same logical side effect, retried, must not
produce multiple internally-authorized attempts.

External systems retry. v2.7 documented that a lease does not make an
action idempotent; v2.8 records the effect the execution intends and the
attempt it authorized, so the *firewall* can be idempotent even when the
external system is not. One execution lease carries exactly one side
effect, keyed by its idempotency key; repeating the same logical effect
returns the same row and cannot authorize a second attempt.

The legal combinations are pinned here:

* same lease + same execution + same effect + same idempotency key  -> the
  same row, reused; no second attempt is ever authorized.
* same lease + different effect or different idempotency key          ->
  ``effect_mismatch``: one lease carries one side effect.
* different lease + same execution                                   ->
  refused at reservation (an execution identity names one live lease).
* same effect + different execution/lease                             -> a
  fresh, legitimate side effect of the next execution.

Every class carries a successful calibration.
"""

from __future__ import annotations

import uuid

import pytest

from firewall.effect import (
    EffectState,
)
from firewall.execution_lease import (
    ExecutionState,
)
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "idem-transfer-1"


def build_sdk(**kwargs) -> FirewallSDK:
    return FirewallSDK(**kwargs)


def make_capability(sdk):
    key = sdk.generate_key(f"v28id-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def reserve_start(sdk, cap, execution_id=None):
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
    return issued, started


def prepare(sdk, lease, cap, key=KEY):
    return sdk.prepare_effect(
        lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )


def attempt(sdk, lease, cap, key=KEY):
    return sdk.attempt_effect(
        lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )


def receipt(sdk, lease, cap, key=KEY, outcome="succeeded"):
    return sdk.record_effect_receipt(
        lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        observed_outcome=outcome,
        evidence_kind="handler_observation",
    )


class TestRetrySemantics:
    def test_repeated_prepare_returns_the_same_row(self):
        """Same lease, same effect, same key, many times: one row."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)

        first = prepare(sdk, started.lease, cap)
        assert first.allowed, first.reason
        effect_id = first.effect.effect_id

        for _ in range(5):
            again = prepare(sdk, started.lease, cap)
            assert again.allowed, again.reason
            assert again.reason == "effect_already_prepared"
            assert again.effect.effect_id == effect_id

        rows = sdk.effects.records()
        sdk.close()

        assert len(rows) == 1
        assert rows[0].idempotency_key == KEY

    def test_an_attempt_cannot_be_authorized_twice(self):
        """A timeout -> retry must not authorize a second real-world
        attempt. After the one atomic ATTEMPT_STARTED, the retry is
        refused with the row in hand."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)
        prepare(sdk, started.lease, cap)

        first = attempt(sdk, started.lease, cap)
        assert first.allowed, first.reason
        attempt_id = first.effect.attempt_id

        for _ in range(5):
            again = attempt(sdk, started.lease, cap)
            assert not again.allowed
            assert again.reason == "effect_already_attempted"
            assert again.effect.attempt_id == attempt_id

        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert row.attempt_id == attempt_id
        assert row.state is EffectState.ATTEMPT_STARTED

    def test_a_replayed_receipt_cannot_produce_a_second_completion(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)
        prepare(sdk, started.lease, cap)
        attempt(sdk, started.lease, cap)

        r = receipt(sdk, started.lease, cap)
        assert r.allowed, r.reason
        for _ in range(3):
            replay = receipt(sdk, started.lease, cap)
            assert not replay.allowed
            assert replay.reason == "effect_already_resolved"

        c = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert c.allowed, c.reason
        # A second commit is refused by the lease machine.
        c2 = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert c2.state is ExecutionState.COMPLETED
        assert c2.reason == "lease_already_completed"

    def test_a_timeout_retry_after_resolution_is_served_not_duplicated(self):
        """The full retry storm: prepare -> attempt -> timeout -> retry ->
        timeout -> retry -> eventual receipt -> commit. One attempt total,
        and the late retries all resolve to the already-recorded outcome."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)

        prepared = prepare(sdk, started.lease, cap)
        assert prepared.allowed
        attempted = attempt(sdk, started.lease, cap)
        assert attempted.allowed

        # Timeout: the caller cannot tell whether the request went out.
        unknown = receipt(sdk, started.lease, cap, outcome="unknown")
        assert unknown.allowed, unknown.reason
        assert unknown.effect.state is EffectState.UNKNOWN

        # The caller retries the transmission: refused -- the effect may
        # already have happened, so only reconciliation may resolve it.
        retry = attempt(sdk, started.lease, cap)
        assert not retry.allowed
        assert retry.reason == "effect_unresolved:unknown"

        # An external status query confirms the request was processed.
        reconciled = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution="succeeded",
            evidence_kind="provider_evidence",
            external_request_id="ext-timeout-1",
        )
        assert reconciled.allowed, reconciled.reason
        assert reconciled.effect.state is EffectState.SUCCEEDED

        committed = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        record = sdk.execution_leases.get(started.lease.lease_id)
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert committed.allowed, committed.reason
        assert record.state is ExecutionState.COMPLETED
        assert row.reconcile_count >= 1


class TestWhichCombinationsAreLegal:
    def test_same_lease_different_effect_is_a_mismatch(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)
        prepare(sdk, started.lease, cap)

        changed = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect={"to": "acct-OTHER", "amount": 5},
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert not changed.allowed
        assert changed.reason == "effect_mismatch"

    def test_same_lease_different_key_is_a_mismatch(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)
        prepare(sdk, started.lease, cap)

        other_key = sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key="a-different-key",
        )
        sdk.close()

        assert not other_key.allowed
        assert other_key.reason == "effect_mismatch"

    def test_different_lease_same_live_execution_is_refused_at_reserve(self):
        """An execution identity names one live execution; a second lease
        cannot claim it, so 'same execution, different lease' cannot even
        be constructed."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        execution_id = "one-execution"
        issued_a = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued_a.allowed, issued_a.reason
        reserved_a = sdk.reserve_execution(
            issued_a.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id=execution_id,
        )
        assert reserved_a.allowed, reserved_a.reason

        issued_b = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued_b.allowed, issued_b.reason
        reserved_b = sdk.reserve_execution(
            issued_b.lease,
            cap,
            ACTION,
            dict(REQUEST),
            execution_id=execution_id,
        )
        sdk.close()

        assert not reserved_b.allowed
        assert reserved_b.reason == "execution_identity_bound"

    def test_same_effect_on_a_fresh_execution_is_a_fresh_side_effect(self):
        """Calibration: two executions of the same logical effect are two
        distinct side effects, each with its own row and attempt."""

        sdk = build_sdk()
        cap = make_capability(sdk)

        rows = []
        for tag in ("exec-1", "exec-2"):
            _, started = reserve_start(sdk, cap, execution_id=tag)
            prepare(sdk, started.lease, cap)
            attempted = attempt(sdk, started.lease, cap)
            assert attempted.allowed, attempted.reason
            rows.append(attempted.effect)
            receipt(sdk, started.lease, cap)
            committed = sdk.commit_effect(
                started.lease,
                cap,
                ACTION,
                dict(REQUEST),
                effect=dict(EFFECT),
                effect_type=EFFECT_TYPE,
                idempotency_key=KEY,
            )
            assert committed.allowed, committed.reason

        sdk.close()

        assert rows[0].effect_id != rows[1].effect_id
        assert rows[0].attempt_id != rows[1].attempt_id

    def test_the_calibration_is_an_unchanged_effect_under_a_valid_lease(self):
        """The canonical positive control for the whole file."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        _, started = reserve_start(sdk, cap)

        prepared = prepare(sdk, started.lease, cap)
        attempted = attempt(sdk, started.lease, cap)
        r = receipt(sdk, started.lease, cap)
        committed = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert prepared.allowed
        assert attempted.allowed
        assert r.allowed
        assert committed.allowed
        assert committed.state is ExecutionState.COMPLETED
