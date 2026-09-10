"""v3.2: temporal security integrity -- attack the twenty-third invariant.

Every release before this one bounded *what* a decision may rest on. v3.2
bounds *when*:

    A security decision is valid only within a provable temporal context.

``TEMPORAL_SECURITY_INTEGRITY`` (the twenty-third registered invariant)
machine-checks the layer that establishes it: every security deadline is
compared inside a context the guard built from an audited clock, no
function that decides an authorization outcome reads a platform clock, the
recorded windows are well formed and ordered, a lease cannot claim a
deadline beyond the duration it was granted, and a wall clock that moved
backwards or a monotonic clock that regressed is refused by name rather
than believed.

This file attacks the boundary from both sides -- the SDK and the
invariant -- over clock rollback, clock jumps, expired leases, stale
attestations, delayed execution, replay windows, restarts, concurrent
expiry races and tampered timestamps. Every class carries a calibration, so
a green run cannot mean "everything was refused".
"""

from __future__ import annotations

import threading
import time
import uuid

from dataclasses import replace

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.effect import (
    EffectOutcome,
    EffectState,
    ReceiptKind,
)
from firewall.effect_verification import (
    VerificationOutcome,
    VerifierVerdict,
)
from firewall.execution_lease import (
    ExecutionLease,
    ExecutionLeaseStore,
    ExecutionState,
)
from firewall.external_attestation import (
    AttestationOutcome,
    build_attestation,
    canonical_external_state_digest,
    freshness_failure,
)
from firewall.invariants import check_temporal_security_integrity
from firewall.invariants import runtime as runtime_module
from firewall.invariants.model import InvariantStatus
from firewall.invariants.runtime import (
    _temporal_probe_findings,
    _temporal_source_findings,
)
from firewall.replay import ReplayKey, ReplayProtector
from firewall.sdk import FirewallSDK
from firewall.temporal import (
    DEFAULT_REGRESSION_TOLERANCE_SECONDS,
    TEMPORAL_ANOMALY_PREFIX,
    TEMPORAL_WINDOW_CLOSED,
    UNGUARDED_GENERATION,
    TemporalContext,
    TemporalError,
    TemporalGuard,
    TemporalWindow,
    bind_temporal,
    default_monotonic_clock,
    platform_clock_quantum,
    sample_temporal,
    temporal_of,
)
from firewall.temporal_store import SQLiteTemporalStore

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-temporal"
ISSUER = "acme-payments"
KEY_ID = "acme-key-1"
PROVIDER = "acme-payments"
EXT_ID = "acme-request-1"

#: A fixed, arbitrary instant. Fixed rather than real time so that every
#: window in this file is arithmetic rather than a race with the wall clock.
BASE = 1_000_000.0


class Clock:
    """A wall clock the test moves. Forward is time; backward is an attack."""

    def __init__(self, value: float = BASE):
        self.value = float(value)

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> float:
        self.value += float(seconds)
        return self.value

    def rewind(self, seconds: float) -> float:
        self.value -= float(seconds)
        return self.value


class Monotonic:
    """A monotonic clock the test moves, so elapsed time is test-controlled.

    Deliberately *not* ``time.monotonic``: a test that measured elapsed time
    with the real clock would be measuring the machine, not the property,
    and could not make "sixty seconds passed while the wall clock froze"
    happen on demand.
    """

    def __init__(self, value: float = 10_000.0):
        self.value = float(value)

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> float:
        self.value += float(seconds)
        return self.value

    def rewind(self, seconds: float) -> float:
        self.value -= float(seconds)
        return self.value


def make_sdk(*, wall=None, mono=None, **kwargs):
    """An SDK on test-controlled clocks, with one external issuer."""

    wall = wall if wall is not None else Clock()
    mono = mono if mono is not None else Monotonic()
    sdk = FirewallSDK(clock=wall, monotonic_clock=mono, **kwargs)
    sdk.generate_key(f"v32-{uuid.uuid4().hex[:8]}")
    sdk.trust_external_issuer(ISSUER, KEY_ID, ISSUER_PRIVATE.public_key())
    return sdk, wall, mono


ISSUER_PRIVATE = Ed25519PrivateKey.generate()


def make_capability(sdk, *, ttl: float = 3_600.0):
    now = float(sdk.verifier.clock())
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        constraints={"amount_max": 100},
        expires_at=now + ttl,
    )


def authorize(sdk, capability):
    return sdk.authorize(capability, action=ACTION, request=dict(REQUEST))


def walk_to_attempt(sdk, capability, *, execution_id="exec-temporal", key=KEY):
    issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        capability,
        ACTION,
        dict(REQUEST),
        execution_id=execution_id,
    )
    assert reserved.allowed, reserved.reason
    started = sdk.start_execution(
        reserved.lease, capability, ACTION, dict(REQUEST)
    )
    assert started.allowed, started.reason
    prepared = sdk.prepare_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )
    assert prepared.allowed, prepared.reason
    attempted = sdk.attempt_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )
    assert attempted.allowed, attempted.reason
    return issued, started


def record_success(sdk, capability, lease, *, key=KEY, ext_id=EXT_ID):
    receipt = sdk.record_effect_receipt(
        lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        observed_outcome=EffectOutcome.SUCCEEDED,
        evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        external_request_id=ext_id,
        provider=PROVIDER,
    )
    assert receipt.allowed, receipt.reason
    return receipt


def envelope_for(
    sdk,
    lease,
    wall,
    *,
    ttl: float = 3_600.0,
    issued_at: float | None = None,
    nonce: str | None = None,
    observed_outcome: str = "succeeded",
):
    """A genuinely signed envelope over the row ``lease`` currently holds."""

    row = sdk.effects.by_lease(lease.lease_id)
    assert row is not None, "no side-effect row to attest"

    return build_attestation(
        issuer_id=ISSUER,
        key_id=KEY_ID,
        private_key=ISSUER_PRIVATE,
        effect_id=row.effect_id,
        lease_id=row.lease_id,
        attempt_id=row.attempt_id,
        effect_digest=row.effect_digest,
        capability_fingerprint=row.capability_fingerprint,
        agent_id=row.agent_id,
        action=row.action,
        idempotency_key=row.idempotency_key,
        state_digest=canonical_external_state_digest(
            {"nonce": uuid.uuid4().hex}
        ),
        external_request_id=row.external_request_id or "",
        observed_outcome=observed_outcome,
        provider=row.provider,
        execution_id=row.execution_id,
        issued_at=issued_at,
        ttl=ttl,
        nonce=nonce,
        clock=wall,
    )


def attest(sdk, lease, capability, envelope, *, key=KEY):
    return sdk.record_attestation(
        lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        attestation=envelope,
    )


def authenticator(evidence):
    return VerifierVerdict(
        outcome=VerificationOutcome.VERIFIED,
        method="acme-authenticator",
        note="acme status api confirmed the recorded request",
    )


def commit(sdk, lease, capability, **kwargs):
    kwargs.setdefault("verifier", authenticator)
    kwargs.setdefault("method", "acme-authenticator")
    return sdk.commit_effect(
        lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        **kwargs,
    )


def audit(sdk):
    return check_temporal_security_integrity(sdk)


def guard_uses_default():
    """The monotonic clock a default-constructed guard samples.

    Read through the guard rather than the module constant, so the test pins
    what the boundary actually does rather than what it says.
    """

    guard = TemporalGuard()
    return guard._monotonic


def deny_startswith(result, prefix: str) -> bool:
    return result.allowed is False and str(result.reason).startswith(prefix)


# ======================================================================
# Calibration: the guard and its windows, on their own terms
# ======================================================================


class TestTemporalGuardCalibration:
    def test_an_honest_clock_yields_a_provable_context(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)

        context = guard.sample(source=wall, name="sdk")

        assert context.provable
        assert context.anomaly is None
        assert context.wall == BASE
        assert context.monotonic == mono.value
        assert context.sequence == 1
        assert context.generation == guard.generation
        assert context.source == "sdk"
        assert guard.suspect() is None

    def test_time_moving_forward_is_not_an_anomaly(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        guard.sample(source=wall, name="sdk")

        wall.advance(86_400.0)
        mono.advance(86_400.0)
        later = guard.sample(source=wall, name="sdk")

        assert later.provable
        assert guard.suspect() is None

    def test_a_wall_regression_is_an_anomaly_and_is_recorded(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        guard.sample(source=wall, name="sdk")

        wall.rewind(30.0)
        mono.advance(1.0)
        rolled = guard.sample(source=wall, name="sdk")

        assert rolled.anomaly == "wall_regression"
        assert guard.suspect() == "wall_regression@sdk"
        assert [reason for _, _, reason in guard.anomalies()] == [
            "wall_regression"
        ]

    def test_a_monotonic_regression_is_an_anomaly(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        guard.sample(source=wall, name="sdk")

        mono.rewind(5.0)
        regressed = guard.sample(source=wall, name="sdk")

        assert regressed.anomaly == "monotonic_regression"

    def test_a_source_stays_suspect_until_an_operator_clears_it(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        guard.sample(source=wall, name="sdk")
        wall.rewind(10.0)
        guard.sample(source=wall, name="sdk")

        assert guard.suspect() is not None

        # A later honest reading does not retract the finding ...
        wall.advance(60.0)
        honest = guard.sample(source=wall, name="sdk")
        assert honest.provable
        assert guard.suspect() is not None

        # ... an operator does.
        guard.clear()
        assert guard.suspect() is None
        # Clearing the anomaly does not move the high-water mark: the next
        # regression must still be detectable.
        wall.rewind(1.0)
        again = guard.sample(source=wall, name="sdk")
        assert again.anomaly == "wall_regression"

    def test_a_tolerance_bounds_how_much_regression_is_tolerated(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono, tolerance=5.0)
        guard.sample(source=wall, name="sdk")

        wall.rewind(3.0)
        tolerated = guard.sample(source=wall, name="sdk")
        assert tolerated.anomaly is None

        wall.rewind(30.0)
        refused = guard.sample(source=wall, name="sdk")
        assert refused.anomaly == "wall_regression"

    def test_sources_are_audited_independently(self):
        """Two clocks at different bases do not flag each other."""

        guard = TemporalGuard(monotonic=Monotonic())
        fast, slow = Clock(2_000.0), Clock(5.0)

        guard.sample(source=fast, name="sdk")
        first_slow = guard.sample(source=slow, name="execution-lease")

        assert first_slow.provable
        assert guard.suspect() is None
        assert set(guard.sources()) == {"sdk", "execution-lease"}

    def test_an_unreadable_clock_raises_rather_than_inventing_a_context(self):
        guard = TemporalGuard(monotonic=Monotonic())

        def broken():
            raise RuntimeError("no clock")

        with pytest.raises(TemporalError):
            guard.sample(source=broken, name="sdk")

        with pytest.raises(TemporalError):
            guard.sample(
                source=lambda: float("nan"),
                name="sdk",
            )

    def test_a_non_finite_monotonic_clock_is_refused(self):
        guard = TemporalGuard(monotonic=lambda: float("inf"))

        with pytest.raises(TemporalError):
            guard.sample(source=Clock(), name="sdk")

    def test_a_window_closes_on_its_monotonic_budget_with_a_frozen_wall(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        opened = guard.sample(source=wall, name="sdk")
        window = guard.window(context=opened, ttl=60.0)

        mono.advance(30.0)
        inside = guard.sample(source=wall, name="sdk")
        assert guard.close_reason(window, inside) is None
        assert window.remaining(inside) == pytest.approx(30.0)

        mono.advance(31.0)
        outside = guard.sample(source=wall, name="sdk")
        assert guard.close_reason(window, outside) == TEMPORAL_WINDOW_CLOSED
        assert window.remaining(outside) == 0.0

    def test_a_window_can_also_carry_an_absolute_deadline(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        opened = guard.sample(source=wall, name="sdk")
        window = guard.window(
            context=opened, ttl=10_000.0, deadline_wall=BASE + 100.0
        )

        wall.advance(200.0)
        mono.advance(200.0)
        later = guard.sample(source=wall, name="sdk")

        assert guard.close_reason(window, later) == TEMPORAL_WINDOW_CLOSED

    def test_an_anomalous_context_covers_no_window(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        opened = guard.sample(source=wall, name="sdk")
        window = guard.window(context=opened, ttl=10_000.0)

        wall.rewind(1.0)
        anomalous = guard.sample(source=wall, name="sdk")

        assert anomalous.anomaly is not None
        assert guard.close_reason(window, anomalous) == "wall_regression"
        assert window.covers(anomalous) is False

    def test_a_window_cannot_be_anchored_at_an_anomalous_instant(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        guard.sample(source=wall, name="sdk")
        wall.rewind(1.0)
        anomalous = guard.sample(source=wall, name="sdk")

        with pytest.raises(TemporalError):
            guard.window(context=anomalous, ttl=60.0)

    def test_a_window_across_generations_uses_its_deadline_only(self):
        """A monotonic reading from another boot means nothing here."""

        window = TemporalWindow(
            source="sdk",
            generation="previous-boot",
            opened_wall=BASE,
            opened_monotonic=123.0,
            ttl=1.0,
            deadline_wall=BASE + 1_000.0,
        )
        context = TemporalContext(
            wall=BASE + 5.0,
            monotonic=9_999.0,
            sequence=1,
            generation="this-boot",
            source="sdk",
        )

        # The monotonic budget is skipped, so the deadline governs ...
        assert window.elapsed(context) is None
        assert window.close_reason(context) is None

        # ... and the deadline still refuses when it passes.
        past = replace(context, wall=BASE + 2_000.0)
        assert window.close_reason(past) == TEMPORAL_WINDOW_CLOSED

    def test_a_window_round_trips_and_refuses_malformed_encodings(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        window = guard.window(
            context=guard.sample(source=wall, name="sdk"),
            ttl=60.0,
            deadline_wall=BASE + 120.0,
        )

        assert TemporalWindow.from_dict(window.to_dict()) == window

        with pytest.raises(TemporalError):
            TemporalWindow.from_dict({"source": "sdk"})

        with pytest.raises(TemporalError):
            TemporalWindow.from_dict(
                {
                    "source": "sdk",
                    "generation": "g",
                    "opened_wall": "later",
                    "opened_monotonic": 1.0,
                }
            )

    def test_the_default_tolerance_is_the_platforms_own_quantum(self):
        """One quantum, not zero, and the reason is measurable.

        A clock cannot differ from itself by less than its own granularity,
        so a sub-quantum movement is two readings of the same tick rather
        than a clock that moved. A zero default classified an unmanipulated
        platform clock as an attack under concurrency -- which is how this
        was found, in `tests/test_v2_6_concurrency_never_widens.py`.
        """

        assert DEFAULT_REGRESSION_TOLERANCE_SECONDS is None

        guard = TemporalGuard()
        quantum = platform_clock_quantum()

        assert quantum > 0.0
        assert guard.tolerance == quantum
        assert guard.tolerance_source == "platform quantum"

        configured = TemporalGuard(tolerance=12.5)
        assert configured.tolerance == 12.5
        assert configured.tolerance_source == "configured"

        explicit_zero = TemporalGuard(tolerance=0.0)
        assert explicit_zero.tolerance == 0.0
        assert explicit_zero.tolerance_source == "configured"

    def test_a_sub_quantum_regression_is_not_an_anomaly(self):
        """Movement the clock cannot represent is not evidence of anything."""

        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono, tolerance=0.05)
        guard.sample(source=wall, name="sdk")

        wall.rewind(0.01)
        sub_quantum = guard.sample(source=wall, name="sdk")
        assert sub_quantum.provable

        wall.rewind(0.20)
        beyond = guard.sample(source=wall, name="sdk")
        assert beyond.anomaly == "wall_regression"

    def test_a_real_rollback_is_caught_whatever_the_quantum(self):
        """The tolerance is bounded by the clock, not by what an attacker
        would like to move."""

        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        guard.sample(source=wall, name="sdk")

        wall.rewind(1.0)  # a second: sixty times this platform's quantum
        rolled = guard.sample(source=wall, name="sdk")

        assert rolled.anomaly == "wall_regression"

    def test_the_default_monotonic_clock_is_the_finest_available(self):
        """Elapsed budgets are measured with the best clock on offer.

        `perf_counter` rather than `monotonic` because the difference is
        measurable: on this development platform `monotonic` is quantised at
        15.6 ms and jittered below a strict high-water mark in 754 of
        320 000 concurrent readings, while `perf_counter` measured zero
        backward readings at 1e-07 resolution.
        """

        clock = default_monotonic_clock()

        assert callable(clock)
        assert guard_uses_default() is clock

        first = clock()
        second = clock()

        assert second >= first

    def test_source_labels_are_validated(self):
        guard = TemporalGuard(monotonic=Monotonic())

        with pytest.raises(ValueError):
            guard.sample(source=Clock(), name="")

        with pytest.raises(ValueError):
            guard.sample(source=Clock(), name="a;b")

    def test_an_unguarded_component_is_unmeasured_not_suspect(self):
        class Component:
            def __init__(self):
                self._clock = Clock(77.0)

        component = Component()
        context = sample_temporal(
            component, name="component", fallback=component._clock
        )

        assert context.unguarded
        assert context.provable is False
        assert context.generation == UNGUARDED_GENERATION

        # And a window can never be measured against it.
        with pytest.raises(TemporalError):
            TemporalGuard(monotonic=Monotonic()).window(
                context=context, ttl=1.0
            )

    def test_a_component_is_sampled_through_its_own_clock(self):
        class Component:
            def __init__(self):
                self._clock = Clock(5_000.0)

        component = Component()
        guard = TemporalGuard(monotonic=Monotonic())

        assert bind_temporal(component, guard)
        assert temporal_of(component) is guard

        context = sample_temporal(
            component, name="component", fallback=component._clock
        )

        # The component's own reading, not the platform's.
        assert context.wall == 5_000.0
        assert context.provable
        assert context.generation == guard.generation


# ======================================================================
# Clock rollback: the attack the release exists to refuse
# ======================================================================


class TestClockRollback:
    def test_a_rollback_after_a_verdict_is_refused_by_name(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        assert authorize(sdk, capability).allowed

        wall.rewind(60.0)
        mono.advance(1.0)
        rolled = authorize(sdk, capability)
        sdk.close()

        assert deny_startswith(rolled, F"{TEMPORAL_ANOMALY_PREFIX}:")
        assert "wall_regression" in rolled.reason

    def test_a_rolled_back_clock_cannot_resurrect_an_expired_capability(self):
        """The core attack: expire, then set the clock back before expiry."""

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=100.0)
        assert authorize(sdk, capability).allowed

        wall.advance(50.0)
        mono.advance(50.0)
        assert authorize(sdk, capability).allowed

        wall.advance(60.0)  # past the window
        mono.advance(60.0)
        expired = authorize(sdk, capability)
        assert expired.allowed is False
        assert expired.reason == "expired"

        wall.rewind(80.0)  # back inside the window, by the clock
        mono.advance(1.0)
        resurrected = authorize(sdk, capability)
        sdk.close()

        assert resurrected.allowed is False
        assert resurrected.reason.startswith(TEMPORAL_ANOMALY_PREFIX)

    def test_a_rollback_creates_no_record_and_no_authority(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        authorize(sdk, capability)
        before = sdk.temporal_state()["sources"]["sdk"]["samples"]

        wall.rewind(5.0)
        rolled = authorize(sdk, capability)
        after = sdk.temporal_state()["sources"]["sdk"]["samples"]
        sdk.close()

        assert rolled.allowed is False
        # The reading was recorded -- it is the evidence for the refusal --
        # and no lease, effect or evidence row was written.
        assert after == before + 1

    def test_a_rollback_is_refused_at_the_commit_as_well_as_at_entry(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        wall.rewind(90.0)
        mono.advance(1.0)
        outcome = commit(sdk, started.lease, capability)
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed is False
        assert TEMPORAL_ANOMALY_PREFIX in outcome.reason
        # Terminally denied rather than left for retry, and the reason is
        # v2.8's rather than this release's: the v2.9 verification stage
        # takes an authority snapshot before recording its verdict, and a
        # snapshot that cannot be taken burns the lease exactly as an
        # unreadable clock has always burned it. Nothing completed, and no
        # record was written claiming it did.
        assert record.state is ExecutionState.DENIED
        assert record.complete_authority_valid is None

    def test_the_boundary_recovers_once_the_clock_is_reconciled(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        authorize(sdk, capability)

        wall.rewind(30.0)
        assert authorize(sdk, capability).allowed is False

        # The clock is set forward again and an operator clears the finding.
        wall.advance(60.0)
        sdk.temporal.clear()
        recovered = authorize(sdk, capability)
        sdk.close()

        assert recovered.allowed is True
        assert recovered.reason == "authorized"

    def test_a_rollback_does_not_widen_a_lease_window(self):
        """Two bounds, and the wall clock is not the one that closes it."""

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        assert issued.allowed
        record = sdk.execution_leases.get(issued.lease.lease_id)
        assert sdk.execution_leases.validity(record) is None

        # A frozen wall clock with 61 s of elapsed time: only the monotonic
        # budget can see it, and it does.
        mono.advance(61.0)
        assert (
            sdk.execution_leases.validity(record)
            == "lease_expired:monotonic_budget"
        )

        # A rolled-back wall clock is refused *earlier* and by name: an
        # anomalous reading is never used for the comparison at all, so
        # there is no frame in which the window looks open.
        wall.rewind(120.0)
        verdict = sdk.execution_leases.validity(record)
        sdk.close()

        assert verdict == f"{TEMPORAL_ANOMALY_PREFIX}:wall_regression"


# ======================================================================
# Clock jumps: forward motion expires, and is not an attack
# ======================================================================


class TestClockJumps:
    def test_a_forward_jump_expires_a_capability(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=100.0)
        assert authorize(sdk, capability).allowed

        wall.advance(10_000.0)
        mono.advance(10_000.0)
        expired = authorize(sdk, capability)
        sdk.close()

        assert expired.allowed is False
        assert expired.reason == "expired"
        # Expiry is not an anomaly: the clock did not lie, the window closed.
        assert not expired.reason.startswith(TEMPORAL_ANOMALY_PREFIX)

    def test_a_forward_jump_leaves_an_in_window_request_allowed(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=10_000.0)

        wall.advance(5_000.0)
        mono.advance(5_000.0)
        allowed = authorize(sdk, capability)
        sdk.close()

        assert allowed.allowed is True
        assert allowed.reason == "authorized"

    def test_a_big_forward_jump_does_not_disable_the_next_check(self):
        """The high-water mark moves with the jump, so a later rollback is
        still detected relative to the new baseline."""

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=1e6)
        assert authorize(sdk, capability).allowed

        wall.advance(1_000.0)
        mono.advance(1_000.0)
        assert authorize(sdk, capability).allowed is True

        wall.rewind(1_500.0)  # behind the *new* high-water, not the old one
        mono.advance(1.0)
        rolled = authorize(sdk, capability)
        sdk.close()

        assert rolled.allowed is False
        assert "wall_regression" in rolled.reason

    def test_a_wall_jump_with_a_frozen_monotonic_clock_is_not_an_anomaly(self):
        """A wall clock running ahead is not an attack: it can only expire."""

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=1e6)
        assert authorize(sdk, capability).allowed

        wall.advance(5_000.0)  # monotonic does not move
        later = authorize(sdk, capability)
        sdk.close()

        assert later.allowed is True
        assert sdk is not None


# ======================================================================
# Lease expiry, delayed execution, and the monotonic budget
# ======================================================================


class TestLeaseExpiryAndDelayedExecution:
    def test_a_lease_past_its_wall_deadline_is_refused(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        assert issued.allowed

        wall.advance(61.0)
        mono.advance(61.0)
        outcome = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="late"
        )
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason == "lease_expired"

    def test_delayed_execution_is_refused_when_only_elapsed_time_passed(self):
        """The wall clock is frozen; 61 s of real time still closes it."""

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        assert issued.allowed

        mono.advance(61.0)
        outcome = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="slow"
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason == "lease_expired:monotonic_budget"
        assert record.state is ExecutionState.EXPIRED

    def test_a_lease_cannot_outlive_its_capability(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=100.0)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=3_600.0
        )
        assert issued.allowed

        wall.advance(150.0)
        mono.advance(150.0)
        outcome = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason == "capability_expired"

    def test_a_tampered_deadline_cannot_beat_the_granted_duration(self):
        """A serialized row claiming a longer deadline is refused the
        extension: the granted TTL is a ceiling on the wall bound."""

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        assert record.ttl_seconds == 60.0

        doctored = replace(record, expires_at=record.issued_at + 100_000.0)
        bound = sdk.execution_leases.absolute_bound(doctored)
        sdk.close()

        assert bound == pytest.approx(record.issued_at + 60.0)

    def test_an_anomalous_clock_refuses_without_burning_the_lease(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=600.0
        )
        assert issued.allowed

        wall.rewind(100.0)
        outcome = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason == f"{TEMPORAL_ANOMALY_PREFIX}:wall_regression"
        assert record.state is ExecutionState.LEASE_ISSUED

    def test_the_lapse_sweep_refuses_to_move_records_under_an_anomaly(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        wall.advance(120.0)
        mono.advance(120.0)
        assert sdk.expire_lapsed_executions() == 1
        record = sdk.execution_leases.get(issued.lease.lease_id)
        assert record.state is ExecutionState.EXPIRED

        second = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        wall.rewind(500.0)
        lapsed = sdk.expire_lapsed_executions()
        still_open = sdk.execution_leases.get(second.lease.lease_id)
        sdk.close()

        assert lapsed == 0
        assert still_open.state is ExecutionState.LEASE_ISSUED

    def test_a_lease_issued_by_an_unbound_store_keeps_wall_semantics(self):
        """The pre-v3.2 behaviour, honestly labelled."""

        wall, mono = Clock(), Monotonic()
        store = ExecutionLeaseStore(clock=wall)
        record = store.issue(
            capability_fingerprint="f",
            agent_id="a",
            capability=ACTION,
            action=ACTION,
            request_digest="d",
            chain_id=None,
            policy_version="p",
            ttl=60.0,
        )

        assert record.issued_monotonic is None
        assert record.ttl_seconds is None
        assert record.temporal_generation is None
        assert store.validity(record) is None

        mono.advance(120.0)  # elapsed time the unbound store cannot see
        assert store.validity(record) is None

        wall.advance(61.0)  # the wall deadline still governs
        assert store.validity(record) == "lease_expired"

    def test_an_unbound_store_refuses_to_issue_under_a_suspect_guard(self):
        wall, mono = Clock(), Monotonic()
        guard = TemporalGuard(monotonic=mono)
        store = ExecutionLeaseStore(clock=wall)
        bind_temporal(store, guard)

        guard.sample(source=wall, name="execution-lease")
        wall.rewind(10.0)

        with pytest.raises(Exception) as caught:
            store.issue(
                capability_fingerprint="f",
                agent_id="a",
                capability=ACTION,
                action=ACTION,
                request_digest="d",
                chain_id=None,
                policy_version="p",
                ttl=60.0,
            )

        assert "anomalous temporal context" in str(caught.value)


# ======================================================================
# Stale attestations
# ======================================================================


class TestStaleAttestations:
    def test_an_old_envelope_is_stale_on_an_honest_clock(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        _issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        envelope = envelope_for(
            sdk, started.lease, wall, issued_at=BASE - 600.0, ttl=1e6
        )
        result = attest(sdk, started.lease, capability, envelope)
        sdk.close()

        assert result.allowed is False
        assert result.reason == "attestation_stale"

    def test_the_monotonic_age_closes_a_claim_the_wall_clock_calls_fresh(self):
        """The wall clock is frozen; the elapsed budget still closes it."""

        sdk, wall, mono = make_sdk(attestation_max_age_seconds=10.0)
        capability = make_capability(sdk)
        _issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        envelope = envelope_for(sdk, started.lease, wall, ttl=10_000.0)
        recorded = attest(sdk, started.lease, capability, envelope)
        assert recorded.allowed, recorded.reason
        assert recorded.record.recorded_monotonic is not None
        assert recorded.record.temporal_generation is not None

        # Thirty seconds of elapsed time, wall clock unchanged: the wall
        # age is still a fraction of a second.
        mono.advance(30.0)
        age = recorded.record.age_at(
            wall.value,
            monotonic=mono.value,
            generation=recorded.record.temporal_generation,
        )
        outcome = commit(
            sdk,
            started.lease,
            capability,
            attestation_required=True,
        )
        sdk.close()

        assert age == pytest.approx(30.0)
        assert outcome.allowed is False
        assert outcome.reason == (
            "effect_unattested:attestation_stale_at_completion"
        )

    def test_a_rollback_makes_an_old_envelope_refused_not_fresh(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        _issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)
        assert attest(
            sdk,
            started.lease,
            capability,
            envelope_for(sdk, started.lease, wall, ttl=10_000.0),
        ).allowed

        wall.rewind(6_000.0)
        mono.advance(1.0)
        result = attest(
            sdk,
            started.lease,
            capability,
            envelope_for(
                sdk,
                started.lease,
                wall,
                issued_at=BASE - 6_000.0,
                ttl=1e6,
                nonce=uuid.uuid4().hex,
            ),
        )
        sdk.close()

        assert result.allowed is False
        assert result.reason == f"{TEMPORAL_ANOMALY_PREFIX}:wall_regression"

    def test_the_journal_owns_the_freshness_definition(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        _issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        envelope = envelope_for(sdk, started.lease, wall, ttl=10_000.0)
        assert sdk.attestations.check_window(envelope=envelope) is None

        expired_envelope = envelope_for(
            sdk, started.lease, wall, issued_at=BASE - 100.0, ttl=10.0
        )
        assert (
            sdk.attestations.check_window(envelope=expired_envelope)
            == "attestation_expired"
        )

        wall.rewind(50.0)
        assert (
            sdk.attestations.check_window(envelope=envelope)
            == f"{TEMPORAL_ANOMALY_PREFIX}:wall_regression"
        )
        sdk.close()

    def test_the_age_takes_the_larger_of_the_two_readings(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        _issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)
        recorded = attest(
            sdk,
            started.lease,
            capability,
            envelope_for(sdk, started.lease, wall, ttl=10_000.0),
        )
        claim = recorded.record
        sdk.close()

        # A rolled-back wall clock reports a *younger* envelope than the
        # monotonic reading does, and the larger age wins.
        wall_age_only = claim.age_at(BASE - 100.0)
        both = claim.age_at(
            BASE - 100.0,
            monotonic=mono.value + 45.0,
            generation=claim.temporal_generation,
        )
        assert both >= wall_age_only
        assert both >= 45.0

        # A generation mismatch drops the monotonic half rather than
        # subtracting two different boots.
        assert claim.age_at(
            BASE + 5.0,
            monotonic=mono.value + 45.0,
            generation="another-boot",
        ) == pytest.approx(5.0)

    def test_freshness_failure_uses_the_effective_age_when_given_one(self):
        assert freshness_failure(
            issued_at=BASE,
            not_before=BASE,
            expires_at=BASE + 10_000.0,
            now=BASE + 1.0,
            max_age=300.0,
        ) is None

        assert freshness_failure(
            issued_at=BASE,
            not_before=BASE,
            expires_at=BASE + 10_000.0,
            now=BASE + 1.0,
            max_age=300.0,
            effective_age=900.0,
        ) == "attestation_stale"

    def test_an_attested_claim_is_never_recorded_under_an_anomaly(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        _issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)
        row = sdk.effects.by_lease(started.lease.lease_id)
        envelope = envelope_for(sdk, started.lease, wall, ttl=10_000.0)

        sdk.attestations._clock = wall
        wall.rewind(20.0)
        # Prime the journal's own source so the regression is detectable.
        sdk.attestations.check_window(envelope=envelope)
        wall.advance(40.0)
        sdk.attestations.check_window(envelope=envelope)
        wall.rewind(20.0)

        result = attest(sdk, started.lease, capability, envelope)
        sdk.close()

        assert result.allowed is False
        assert TEMPORAL_ANOMALY_PREFIX in result.reason
        assert row is not None


# ======================================================================
# Replay windows
# ======================================================================


def replay_key(nonce: str) -> ReplayKey:
    return ReplayKey(
        agent_id="agent-a", capability_fingerprint="fp", nonce=nonce
    )


class TestReplayWindows:
    def test_a_nonce_is_usable_once_inside_its_window(self):
        wall, mono = Clock(), Monotonic()
        protector = ReplayProtector(clock=wall)
        bind_temporal(protector, TemporalGuard(monotonic=mono))
        key = replay_key("n1")

        assert protector.check_and_consume(key, wall.value + 60.0) is True
        assert protector.check_and_consume(key, wall.value + 60.0) is False
        assert protector.seen(key) is True

    def test_a_nonce_is_usable_again_once_its_window_closes(self):
        wall, mono = Clock(), Monotonic()
        protector = ReplayProtector(clock=wall)
        bind_temporal(protector, TemporalGuard(monotonic=mono))
        key = replay_key("n2")

        assert protector.check_and_consume(key, wall.value + 60.0) is True
        wall.advance(61.0)
        assert protector.seen(key) is False
        assert protector.check_and_consume(key, wall.value + 60.0) is True

    def test_the_elapsed_budget_closes_the_window_with_a_frozen_wall(self):
        """A rolled-back or stalled wall clock cannot extend replay state."""

        wall, mono = Clock(), Monotonic()
        protector = ReplayProtector(clock=wall)
        bind_temporal(protector, TemporalGuard(monotonic=mono))
        key = replay_key("n3")

        assert protector.check_and_consume(key, wall.value + 60.0) is True
        mono.advance(61.0)
        assert protector.seen(key) is False

    def test_a_rollback_refuses_rather_than_extending_the_ledger(self):
        wall, mono = Clock(), Monotonic()
        protector = ReplayProtector(clock=wall)
        guard = TemporalGuard(monotonic=mono)
        bind_temporal(protector, guard)
        key = replay_key("n4")

        assert protector.check_and_consume(key, wall.value + 60.0) is True
        wall.rewind(120.0)

        # A fresh nonce is refused, not consumed: the window cannot be read.
        assert (
            protector.check_and_consume(
                replay_key("n5"), wall.value + 60.0
            )
            is False
        )
        # And every lookup reports "already seen", which is the refusal the
        # caller acts on.
        assert protector.seen(key) is True
        assert guard.suspect() is not None

    def test_an_unbound_protector_keeps_wall_semantics(self):
        wall, mono = Clock(), Monotonic()
        protector = ReplayProtector(clock=wall)
        key = replay_key("n6")

        assert protector.check_and_consume(key, wall.value + 60.0) is True
        mono.advance(120.0)
        assert protector.seen(key) is True  # no budget was ever measured
        wall.advance(61.0)
        assert protector.seen(key) is False

    def test_a_regressed_monotonic_clock_closes_an_entry_rather_than_extending_it(self):
        wall, mono = Clock(), Monotonic()
        protector = ReplayProtector(clock=wall)
        bind_temporal(protector, TemporalGuard(monotonic=mono))
        key = replay_key("n7")
        assert protector.check_and_consume(key, wall.value + 600.0) is True

        mono.rewind(5.0)
        assert protector.seen(key) is True  # the refusal direction


# ======================================================================
# Restart and recovery continuity
# ======================================================================


class TestRestartRecovery:
    def test_a_boot_behind_the_previous_generations_floor_is_refused(
        self, tmp_path
    ):
        path = tmp_path / "temporal.sqlite3"

        first, wall, mono = make_sdk(temporal_store_path=path)
        capability = make_capability(first)
        assert authorize(first, capability).allowed
        floor = first.temporal.store.high_water("sdk")
        assert floor is not None
        first.close()

        # The time-machine restart: same store, clock set back.
        second_wall = Clock(BASE - 5_000.0)
        second = FirewallSDK(
            clock=second_wall,
            monotonic_clock=Monotonic(5.0),
            temporal_store_path=path,
        )
        second.generate_key("v32-restart")
        second_capability = make_capability(second)
        refused = second.authorize(
            second_capability, action=ACTION, request=dict(REQUEST)
        )
        second.close()

        assert refused.allowed is False
        assert "cross_restart_regression" in refused.reason

    def test_an_honest_restart_is_accepted_and_the_floor_never_lowers(
        self, tmp_path
    ):
        path = tmp_path / "temporal2.sqlite3"

        first, wall, mono = make_sdk(temporal_store_path=path)
        capability = make_capability(first)
        assert authorize(first, capability).allowed
        first.close()

        later_wall = Clock(BASE + 60.0)
        second = FirewallSDK(
            clock=later_wall,
            monotonic_clock=Monotonic(500.0),
            temporal_store_path=path,
        )
        second.generate_key("v32-restart-2")
        second_capability = make_capability(second)
        allowed = second.authorize(
            second_capability, action=ACTION, request=dict(REQUEST)
        )
        floor = second.temporal.store.high_water("sdk")
        second.close()

        assert allowed.allowed is True

        # A regressing reading must not lower the stored floor: erasing the
        # evidence would be the attack's accomplice.
        store = SQLiteTemporalStore(path)
        try:
            assert floor is not None
            assert store.high_water("sdk") >= floor
        finally:
            store.close()

    def test_a_recovered_lease_uses_its_deadline_not_another_boots_clock(
        self, tmp_path
    ):
        path = tmp_path / "temporal3.sqlite3"

        wall, mono = Clock(), Monotonic()
        first = ExecutionLeaseStore(
            clock=wall, backend=None
        )
        guard_one = TemporalGuard(monotonic=mono)
        bind_temporal(first, guard_one)
        record = first.issue(
            capability_fingerprint="f",
            agent_id="a",
            capability=ACTION,
            action=ACTION,
            request_digest="d",
            chain_id=None,
            policy_version="p",
            ttl=60.0,
        )
        assert record.temporal_generation == guard_one.generation

        # A second process generation, with a monotonic clock near zero --
        # as a real monotonic clock is after a reboot.
        second = ExecutionLeaseStore(clock=wall)
        bind_temporal(second, TemporalGuard(monotonic=Monotonic(1.0)))
        recovered = ExecutionLease.from_dict(
            dict(record.to_dict())
        )

        # Inside the wall deadline: valid, because the monotonic half cannot
        # be compared across boots.
        assert second.monotonic_elapsed(
            recovered,
            second.temporal_context(),
        ) is None
        assert second.validity(recovered) is None

        # Past the wall deadline: refused, and that bound always applied.
        wall.advance(61.0)
        assert second.validity(recovered) == "lease_expired"

    def test_an_unreadable_watermark_store_fails_closed(self, tmp_path):
        class Broken:
            def load_watermarks(self):
                raise RuntimeError("unreachable")

            def save_watermark(self, **kwargs):
                raise RuntimeError("unreachable")

            def close(self):
                pass

        guard = TemporalGuard(
            monotonic=Monotonic(), store=Broken()
        )

        assert guard.boot_anomaly is not None

        context = guard.sample(source=Clock(), name="sdk")
        assert context.provable is False
        assert guard.suspect() is not None

    def test_an_sdk_whose_watermark_store_is_unreadable_denies(
        self, monkeypatch, tmp_path
    ):
        path = tmp_path / "temporal4.sqlite3"

        # The class, not an instance: the SDK builds its own store from the
        # path, so patching an instance here would patch something the SDK
        # never touches and the test would pass for the wrong reason.
        def unreadable(self):
            raise RuntimeError("unreachable")

        monkeypatch.setattr(
            SQLiteTemporalStore, "load_watermarks", unreadable
        )

        sdk = FirewallSDK(
            clock=Clock(),
            monotonic_clock=Monotonic(),
            temporal_store_path=path,
        )
        sdk.generate_key("v32-unreadable-watermark")
        capability = make_capability(sdk)
        refused = authorize(sdk, capability)
        assert sdk.temporal.boot_anomaly is not None
        sdk.close()

        assert refused.allowed is False
        assert refused.reason.startswith(TEMPORAL_ANOMALY_PREFIX)
        assert "watermark_unavailable" in refused.reason


# ======================================================================
# Concurrent operations crossing the expiry boundary
# ======================================================================


class TestConcurrentExpiryRaces:
    def test_exactly_one_reservation_wins_inside_the_window(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=600.0
        )
        assert issued.allowed

        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(6)

        def race(index):
            barrier.wait()
            outcome = sdk.reserve_execution(
                issued.lease,
                capability,
                ACTION,
                dict(REQUEST),
                execution_id=f"race-{index}",
            )
            with lock:
                results.append(outcome)

        threads = [
            threading.Thread(target=race, args=(index,))
            for index in range(6)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert len(results) == 6
        assert sum(1 for outcome in results if outcome.allowed) == 1
        assert record.state is ExecutionState.RESERVED

    def test_nothing_wins_once_the_deadline_has_passed(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=30.0
        )
        assert issued.allowed

        # Cross the boundary *and* roll the wall clock back, so the only
        # reason to refuse is elapsed time.
        mono.advance(31.0)
        wall.rewind(10.0)

        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(4)

        def race(index):
            barrier.wait()
            outcome = sdk.reserve_execution(
                issued.lease,
                capability,
                ACTION,
                dict(REQUEST),
                execution_id=f"late-{index}",
            )
            with lock:
                results.append(outcome)

        threads = [
            threading.Thread(target=race, args=(index,))
            for index in range(4)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert all(outcome.allowed is False for outcome in results)
        assert record.state is not ExecutionState.RESERVED
        assert record.state is not ExecutionState.STARTED

    def test_a_racing_expiry_sweep_never_allows_a_late_start(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=30.0
        )
        assert issued.allowed

        mono.advance(45.0)
        errors = []

        def sweep():
            try:
                sdk.expire_lapsed_executions()
            except Exception as error:  # noqa: BLE001 - recorded below
                errors.append(error)

        def start():
            try:
                sdk.start_execution(
                    issued.lease, capability, ACTION, dict(REQUEST)
                )
            except Exception as error:  # noqa: BLE001 - recorded below
                errors.append(error)

        threads = [
            threading.Thread(target=target)
            for target in (sweep, start, sweep, start)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert errors == []
        assert record.state is not ExecutionState.STARTED


# ======================================================================
# Timestamp tampering, at the boundary and in the records
# ======================================================================


class TestTimestampTampering:
    def _attested(self, **kwargs):
        sdk, wall, mono = make_sdk(**kwargs)
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)
        envelope = envelope_for(sdk, started.lease, wall, ttl=10_000.0)
        result = attest(sdk, started.lease, capability, envelope)
        assert result.allowed, result.reason
        outcome = commit(
            sdk,
            started.lease,
            capability,
            attestation=envelope,
            attestation_required=True,
        )
        assert outcome.allowed, outcome.reason
        return sdk, wall, mono, issued, started, outcome

    def test_a_doctored_lease_deadline_is_a_violation(self):
        sdk, _wall, _mono, issued, _started, _outcome = self._attested()
        stored = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.execution_leases._records[issued.lease.lease_id] = replace(
            stored, expires_at=stored.issued_at + 100_000.0
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "beyond the duration it was granted" in finding
            for finding in result.findings
        )

    def test_a_partial_monotonic_anchor_is_a_violation(self):
        sdk, _wall, _mono, issued, _started, _outcome = self._attested()
        stored = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.execution_leases._records[issued.lease.lease_id] = replace(
            stored, ttl_seconds=None
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "of 3 monotonic anchors" in finding
            for finding in result.findings
        )

    def test_a_completion_stamped_after_its_deadline_is_a_violation(self):
        sdk, _wall, _mono, issued, _started, _outcome = self._attested()
        stored = sdk.execution_leases.get(issued.lease.lease_id)
        late = stored.expires_at + 30.0
        history = list(stored.history)
        from_state, to_state, _at, reason = history[-1]
        history[-1] = (from_state, to_state, late, reason)
        sdk.execution_leases._records[issued.lease.lease_id] = replace(
            stored, history=tuple(history)
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "after the deadline it was granted" in finding
            for finding in result.findings
        )

    def test_out_of_order_verification_timestamps_are_a_violation(self):
        """A claim stamped before the claim recorded before it is a finding.

        The doctoring is done to the *first* claim, moving it forward past
        its successor: the records then describe a firewall that verified a
        claim after verifying something that happened later, which no honest
        sequence produces.
        """

        sdk, _wall, _mono, _issued, _started, _outcome = self._attested()
        claim = sdk.verifications.records()[0]
        row = sdk.effects.records()[0]

        sdk.verifications.record(
            effect_id=row.effect_id,
            lease_id=row.lease_id,
            execution_id=row.execution_id,
            attempt_id=row.attempt_id,
            outcome=claim.outcome,
            method="second-auditor",
            snapshot=dict(claim.snapshot),
            snapshot_digest=claim.snapshot_digest,
            observed_outcome=row.observed_outcome,
            evidence_kind=row.evidence_kind,
            receipt_authority_valid=True,
        )
        ordered = sdk.verifications.records()
        assert len(ordered) == 2
        assert ordered[0].recorded_at <= ordered[1].recorded_at

        sdk.verifications._records[claim.verification_id] = replace(
            claim,
            recorded_at=ordered[1].recorded_at + 5_000.0,
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "recorded before the claim recorded before it" in finding
            for finding in result.findings
        )

    def test_an_attested_claim_outside_its_envelope_window_is_a_violation(self):
        sdk, _wall, _mono, _issued, _started, _outcome = self._attested()
        stored = sdk.attestations.records()[0]
        sdk.attestations._records[stored.attestation_id] = replace(
            stored, recorded_at=stored.expires_at + 1_000.0
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "after the window it names had closed" in finding
            for finding in result.findings
        )

    def test_an_attestation_with_one_anchor_field_is_a_violation(self):
        sdk, _wall, _mono, _issued, _started, _outcome = self._attested()
        stored = sdk.attestations.records()[0]
        sdk.attestations._records[stored.attestation_id] = replace(
            stored, temporal_generation=None
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "one of its two monotonic anchor fields" in finding
            for finding in result.findings
        )

    def test_an_unexplainable_recorded_anomaly_is_a_violation(self):
        sdk, _wall, _mono, _issued, _started, _outcome = self._attested()
        source = sdk.temporal._sources["sdk"]
        source.anomalies.append((BASE, "something_else"))
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "cannot explain" in finding for finding in result.findings
        )

    def test_a_lease_anchored_in_the_future_is_a_violation(self):
        sdk, _wall, mono, issued, _started, _outcome = self._attested()
        stored = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.execution_leases._records[issued.lease.lease_id] = replace(
            stored, issued_monotonic=mono.value + 1_000.0
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "in the future" in finding for finding in result.findings
        )

    def test_an_unbound_store_is_a_violation(self):
        sdk, _wall, _mono, _issued, _started, _outcome = self._attested()
        sdk.execution_leases._temporal_guard = None
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "not bound to this SDK's temporal guard" in finding
            for finding in result.findings
        )

    def test_a_doctored_state_commitment_timestamp_is_a_violation(self):
        sdk, _wall, _mono, _issued, _started, _outcome = self._attested()

        # A second commitment, from a real in-domain write, so there is an
        # order for a doctored timestamp to violate.
        sdk.trust_issuer("second-issuer")
        records = list(sdk.state_commit.records())
        assert len(records) >= 2

        head = records[-1]
        sdk.state_commit._records[-1] = replace(
            head, committed_at=head.committed_at - 100_000.0
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "state commitment is stamped before" in finding
            for finding in result.findings
        )


# ======================================================================
# The invariant's teeth on the source census
# ======================================================================


class TestSourceCensusTeeth:
    def test_the_census_is_closed(self):
        findings, notes = _temporal_source_findings()

        assert findings == ()
        assert any("window sites" in note for note in notes)

    def test_the_probes_pass(self):
        findings, blockers = _temporal_probe_findings()

        assert findings == ()
        assert blockers == ()

    def test_an_undeclared_window_site_is_a_violation(self, monkeypatch):
        """Declaring a site that establishes no context is a violation.

        ``_gate_refusal`` decides a denial and never touches the temporal
        layer, so declaring it a window site is exactly the mistake this
        direction exists to catch: the census would then claim a window is
        measured somewhere it is not.
        """

        monkeypatch.setattr(
            runtime_module,
            "TEMPORAL_WINDOW_SITES",
            frozenset(
                runtime_module.TEMPORAL_WINDOW_SITES
                | {("firewall/sdk.py", "FirewallSDK._gate_refusal")}
            ),
        )
        findings, _ = _temporal_source_findings()

        assert any(
            "declared a temporal window site but establishes no temporal "
            "context" in finding
            for finding in findings
        )

    def test_a_removed_declaration_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "TEMPORAL_WINDOW_SITES",
            frozenset(),
        )
        findings, _ = _temporal_source_findings()

        assert any(
            "compared outside the declared temporal sites" in finding
            or "declared a deadline site" in finding
            for finding in findings
        )

    def test_a_declared_site_that_compares_nothing_is_a_violation(
        self, monkeypatch
    ):
        """A stale census entry is a finding, not a harmless leftover.

        ``check_and_consume`` compares the ``expires_at`` argument it was
        handed -- a local, not a deadline *attribute* -- so declaring it a
        deadline site means the census is describing code that changed.
        """

        monkeypatch.setattr(
            runtime_module,
            "TEMPORAL_DEADLINE_SITES",
            frozenset(
                runtime_module.TEMPORAL_DEADLINE_SITES
                | {
                    (
                        "firewall/replay.py",
                        "ReplayProtector.check_and_consume",
                    )
                }
            ),
        )
        findings, _ = _temporal_source_findings()

        assert any(
            "is declared a deadline site but compares no deadline" in finding
            for finding in findings
        )

    def test_a_missing_module_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "TEMPORAL_WINDOW_SITES",
            frozenset({("firewall/nowhere.py", "Nonexistent.method")}),
        )
        findings, _ = _temporal_source_findings()

        assert any(
            "absent from the package" in finding for finding in findings
        )

    def test_temporal_logic_constructs_no_authorization_verdict(self):
        import ast

        import firewall.temporal as module

        tree = ast.parse(open(module.__file__, encoding="utf-8").read())

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            assert name not in (
                "AuthorizationResult",
                "_result",
                "authorize",
            ), name


# ======================================================================
# The invariant's statuses
# ======================================================================


class TestInvariantStatus:
    def test_a_fresh_sdk_is_unverifiable_not_violated(self):
        sdk = FirewallSDK()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert "sampled no clock" in result.reason

    def test_no_sdk_is_unverifiable(self):
        result = audit(None)

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert "no FirewallSDK" in result.reason
        assert result.holds is False

    def test_an_exercised_sdk_holds(self):
        sdk, _wall, _mono = make_sdk()
        capability = make_capability(sdk)
        assert authorize(sdk, capability).allowed
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS, result.reason
        assert result.details["window_sites"] >= 5

    def test_a_refusal_record_does_not_make_the_invariant_fail(self):
        sdk, wall, _mono = make_sdk()
        capability = make_capability(sdk)
        assert authorize(sdk, capability).allowed
        wall.rewind(30.0)
        assert authorize(sdk, capability).allowed is False

        result = audit(sdk)
        sdk.close()

        # A refusal is the mechanism working, not a violation.
        assert result.status is InvariantStatus.HOLDS

    def test_a_failed_positive_control_is_unverifiable(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "_temporal_probe_findings",
            lambda: ((), ("the honest control was denied",)),
        )
        sdk, _wall, _mono = make_sdk()
        capability = make_capability(sdk)
        authorize(sdk, capability)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert "could not be exercised" in result.reason

    def test_a_failing_probe_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "_temporal_probe_findings",
            lambda: (
                ("a rolled-back wall clock was believed",),
                (),
            ),
        )
        result = audit(None)

        assert result.status is InvariantStatus.VIOLATED


# ======================================================================
# Boundaries: what temporal logic may never do
# ======================================================================


class TestTemporalBoundaries:
    def test_temporal_logic_writes_no_journal(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        authorized = authorize(sdk, capability)
        assert authorized.allowed

        effects = sdk.effects.records()
        leases = sdk.execution_leases.records()
        attestations = sdk.attestations.records()
        verifications = sdk.verifications.records()

        wall.advance(10.0)
        mono.advance(10.0)
        guard = sdk.temporal
        guard.sample(source=wall, name="sdk")
        window = guard.window(context=guard.context_of("sdk"), ttl=60.0)
        assert guard.close_reason(window, guard.context_of("sdk")) is None

        assert sdk.effects.records() == effects
        assert sdk.execution_leases.records() == leases
        assert sdk.attestations.records() == attestations
        assert sdk.verifications.records() == verifications
        sdk.close()

    def test_temporal_logic_changes_no_authorize_verdict(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        before = authorize(sdk, capability)
        assert before.allowed

        sdk.temporal.sample(source=wall, name="sdk")
        guard = sdk.temporal
        guard.window(context=guard.context_of("sdk"), ttl=1.0)

        after = authorize(sdk, capability)
        over = sdk.authorize(
            capability, action=ACTION, request={"amount": 10_000}
        )
        sdk.close()

        assert after.allowed == before.allowed
        assert after.reason == before.reason
        assert over.allowed is False

    def test_the_decision_budget_is_read_only(self):
        sdk = FirewallSDK(
            temporal_decision_budget_seconds=5.0,
        )
        try:
            with pytest.raises(AttributeError):
                sdk.temporal_decision_budget_seconds = 1_000.0
            assert sdk.temporal_decision_budget_seconds == 5.0
        finally:
            sdk.close()

    def test_a_decision_budget_refuses_a_slow_authorization(self, monkeypatch):
        """A decision that outlives its budget is a stale authorization."""

        sdk, wall, mono = make_sdk(
            temporal_decision_budget_seconds=5.0,
        )
        capability = make_capability(sdk)

        original = sdk._gate_delegation_chain

        def slow(ctx):
            # Ten seconds of elapsed time between entry and the terminal
            # gate, with a wall clock that has *not* moved: only the
            # monotonic base can see it.
            mono.advance(10.0)
            return original(ctx)

        monkeypatch.setattr(sdk, "_gate_delegation_chain", slow)
        result = authorize(sdk, capability)
        sdk.close()

        assert result.allowed is False
        assert result.reason == "stale_authorization:decision_budget"

    def test_a_capability_window_closing_during_the_request_is_stale(
        self, monkeypatch
    ):
        """The window closes between the time gate and the terminal gate.

        The clock is moved *after* the cryptographic gate has verified the
        capability -- so signature and window both held when they were
        checked -- and before the terminal gate emits the decision. That is
        the stale authorization the release refuses: the verdict described
        an instant the request has already left.
        """

        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk, ttl=100.0)

        original = sdk._gate_cryptographic_authority

        def cross_the_window(ctx):
            outcome = original(ctx)
            wall.advance(200.0)
            mono.advance(200.0)
            return outcome

        monkeypatch.setattr(
            sdk, "_gate_cryptographic_authority", cross_the_window
        )
        result = authorize(sdk, capability)
        sdk.close()

        assert result.allowed is False
        assert result.reason == "stale_authorization:capability_window"

    def test_the_temporal_store_is_closed_with_the_sdk(self, tmp_path):
        path = tmp_path / "temporal5.sqlite3"
        sdk, _wall, _mono = make_sdk(temporal_store_path=path)
        store = sdk.temporal_store
        assert store is not None
        sdk.close()

        assert store._connection is None

    def test_a_caller_supplied_guard_is_not_closed_by_the_sdk(self, tmp_path):
        guard = TemporalGuard(monotonic=Monotonic())
        sdk = FirewallSDK(temporal_guard=guard)
        sdk.close()

        assert guard.generation
        assert guard.sample(source=Clock(), name="sdk").provable

    def test_both_a_guard_and_a_store_path_is_a_construction_error(
        self, tmp_path
    ):
        with pytest.raises(ValueError):
            FirewallSDK(
                temporal_guard=TemporalGuard(),
                temporal_store_path=tmp_path / "x.sqlite3",
            )

    def test_a_bad_guard_or_budget_is_a_construction_error(self):
        with pytest.raises(TypeError):
            FirewallSDK(temporal_guard=object())

        with pytest.raises(TypeError):
            FirewallSDK(monotonic_clock="not-callable")

        with pytest.raises(ValueError):
            FirewallSDK(temporal_decision_budget_seconds=0.0)

        with pytest.raises(ValueError):
            FirewallSDK(temporal_tolerance_seconds=-1.0)

    def test_an_effect_intent_window_is_audited(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        row = sdk.effects.by_lease(started.lease.lease_id)
        assert row is not None

        assert sdk.effects.temporal_context().provable

        wall.rewind(50.0)
        lapsed = sdk.expire_lapsed_effects()
        still_open = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert issued.allowed
        assert lapsed == 0
        assert still_open.state is EffectState.ATTEMPT_STARTED

    def test_the_effect_intent_still_lapses_on_an_honest_clock(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        _issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            _issued.lease,
            capability,
            ACTION,
            dict(REQUEST),
            execution_id="intent",
        )
        started = sdk.start_execution(
            reserved.lease, capability, ACTION, dict(REQUEST)
        )
        assert sdk.prepare_effect(
            started.lease,
            capability,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            ttl=5.0,
        ).allowed

        wall.advance(60.0)
        mono.advance(60.0)
        lapsed = sdk.expire_lapsed_effects()
        row = sdk.effects.by_lease(started.lease.lease_id)
        sdk.close()

        assert lapsed == 1
        assert row.state is EffectState.FAILED


# ======================================================================
# The release's central claim, asserted as data
# ======================================================================


class TestTemporalContextIsProvable:
    def test_a_lease_records_the_context_it_was_granted_in(self):
        sdk, wall, mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        context = sdk.execution_leases.temporal_context()
        sdk.close()

        assert record.temporal_generation == context.generation
        assert record.issued_monotonic == pytest.approx(
            context.monotonic, abs=1.0
        )
        assert record.ttl_seconds == 60.0
        assert record.expires_at == pytest.approx(record.issued_at + 60.0)

    def test_a_lease_round_trips_its_anchors(self):
        sdk, _wall, _mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        restored = ExecutionLease.from_dict(record.to_dict())

        assert restored.issued_monotonic == record.issued_monotonic
        assert restored.ttl_seconds == record.ttl_seconds
        assert restored.temporal_generation == record.temporal_generation

    def test_a_lease_with_a_nonsense_ttl_is_refused_on_reconstruction(self):
        sdk, _wall, _mono = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(
            capability, ACTION, dict(REQUEST), ttl=60.0
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        payload = record.to_dict()
        payload["ttl_seconds"] = -1.0
        sdk.close()

        with pytest.raises(ValueError):
            ExecutionLease.from_dict(payload)

    def test_concurrent_samples_never_invent_an_anomaly(self):
        """A sample is atomic with respect to its own high-water mark.

        A reading taken outside the lock and compared inside it can be
        ordered the wrong way by a concurrent sampler: two threads read
        100.0 and 100.5, the high-water mark is updated in the order
        (100.5, 100.0), and the second thread's honest reading looks like a
        regression. On a real clock that surfaces as a
        ``temporal_anomaly:monotonic_regression`` denial inside a request
        that had nothing wrong with it -- which is how it was found, in
        ``tests/test_v2_4_aegis_concurrency.py``.
        """

        guard = TemporalGuard(monotonic=lambda: time.monotonic())
        wall = Clock()
        errors: list[str] = []
        anomalies: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker() -> None:
            try:
                barrier.wait()
                for _ in range(200):
                    # A single shared wall clock, read concurrently: the
                    # values are identical, so any anomaly reported here is
                    # the guard's own ordering rather than a clock's.
                    context = guard.sample(source=wall, name="sdk")

                    if context.anomaly is not None:
                        with lock:
                            anomalies.append(context.anomaly)
            except Exception as error:  # noqa: BLE001 - recorded below
                with lock:
                    errors.append(f"{type(error).__name__}: {error}")

        threads = [threading.Thread(target=worker) for _ in range(8)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        state = guard.snapshot()
        samples = state["sources"]["sdk"]["samples"]

        assert errors == []
        assert anomalies == []
        assert guard.suspect() is None
        assert samples == 8 * 200

    def test_concurrent_samples_of_an_advancing_clock_are_ordered(self):
        """The same property while time genuinely moves forward."""

        clock = time.monotonic
        guard = TemporalGuard(monotonic=clock)
        anomalies: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(6)

        class Advancing:
            def __call__(self):
                return time.time()

        wall = Advancing()

        def worker() -> None:
            barrier.wait()
            for _ in range(100):
                context = guard.sample(source=wall, name="sdk")

                if context.anomaly is not None:
                    with lock:
                        anomalies.append(context.anomaly)

        threads = [threading.Thread(target=worker) for _ in range(6)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert anomalies == []
        assert guard.suspect() is None

    def test_two_sdk_generations_have_different_generation_ids(self):
        first, _wall, _mono = make_sdk()
        second, _wall2, _mono2 = make_sdk()
        generation_one = first.temporal.generation
        generation_two = second.temporal.generation
        first.close()
        second.close()

        assert generation_one != generation_two

    def test_the_guard_reports_what_it_has_audited(self):
        sdk, _wall, _mono = make_sdk()
        capability = make_capability(sdk)
        authorize(sdk, capability)
        state = sdk.temporal_state()
        sources = sdk.temporal.sources()
        sdk.close()

        assert "sdk" in state["sources"]
        assert state["tolerance"] == platform_clock_quantum()
        assert state["tolerance_source"] == "platform quantum"
        assert state["boot_anomaly"] is None
        assert "sdk" in sources
        assert state["sources"]["sdk"]["samples"] >= 1
        assert state["sources"]["sdk"]["wall_high_water"] is not None

    def test_the_invariant_is_reported_by_the_registry(self):
        from firewall.invariants import INVARIANTS, invariant

        entry = invariant("TEMPORAL_SECURITY_INTEGRITY")

        assert "provable temporal context" in entry.statement
        assert entry.needs_state is True
        assert len(INVARIANTS) == 24
