"""v2.7: every failure is a refusal with a name, never a guess or a raise.

The lease path must fail closed on the same philosophy as the boundary:
an unreadable store, a forged object, an expired deadline, a revoked or
suspended authority, an unverifiable signature -- each produces an
:class:`ExecutionLeaseOutcome` with ``allowed=False`` and a reason that
names the cause. No ``except Exception`` is ever what decides what
happened to an execution, and no terminal claim is written that the
evidence does not support.

Every class carries its calibration: the identical sequence with healthy
state completes cleanly.
"""

from __future__ import annotations

import uuid

import pytest

from firewall.aegis import AegisController
from firewall.execution_lease import (
    ExecutionLease,
    ExecutionLeaseStore,
    ExecutionState,
)
from firewall.execution_store import SQLiteExecutionLeaseStore
from firewall.risk_context import RiskContext
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
    key = sdk.generate_key(f"v27f-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=capability,
        private_key=key,
        constraints={} if constraints is None else dict(constraints),
    )


def issue(sdk, cap=None):
    cap = cap or make_capability(sdk)
    issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    return issued.lease, cap


class TestUnreadableSecurityState:
    def test_a_closed_revocation_backend_refuses_reserve(self, tmp_path):
        """Unreadable revocation state is indistinguishable from a
        revocation; the refusal must not claim a clean state."""

        from firewall.revocation import RevocationRegistry
        from firewall.revocation_store import SQLiteRevocationStore

        backend = SQLiteRevocationStore(str(tmp_path / "rev.db"))
        registry = RevocationRegistry(backend=backend)
        sdk = build_sdk(revocation_registry=registry)
        lease, cap = issue(sdk)
        backend.close()

        outcome = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="closed"
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason.startswith("revocation_state_unavailable")

    def test_a_raising_aegis_refuses_not_raises(self):
        class BoomAegis(AegisController):
            def restriction_reason(self, fingerprints, action, request):
                raise RuntimeError("boom")

        sdk = build_sdk(aegis=BoomAegis())
        cap = make_capability(sdk)
        # Tracked grants make the gate consult the (raising) controller.
        sdk.aegis.register(
            sdk.fingerprint(cap),
            agent_id=cap.agent_id,
            capability=cap.capability,
        )

        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        if not issued.allowed:
            # The raise hit the authorization gate itself, which must have
            # denied with the unreadable-state reason, not raised.
            assert issued.reason.startswith("aegis_state_unavailable")
            sdk.close()
            return

        # Otherwise the lease exists and the failure surfaces at reserve.
        outcome = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="boom"
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason.startswith("aegis_state_unavailable")

    def test_a_raising_lease_clock_refuses_without_burning(self):
        class FlipClock:
            def __init__(self):
                self.bad = False
                self.t = 2000.0

            def __call__(self):
                if self.bad:
                    raise RuntimeError("clock dead")
                return self.t

        clock = FlipClock()
        store = ExecutionLeaseStore(clock=clock)
        sdk = build_sdk(clock=clock, execution_lease_store=store)
        lease, cap = issue(sdk)
        clock.bad = True

        outcome = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="clock"
        )
        record = store.get(lease.lease_id)
        clock.bad = False
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason.startswith("clock_unavailable")
        # Unreadable time is a refusal of this progression, not a burn:
        # a lease that was never used can be retried against a working
        # clock. (Calibration below proves the retry succeeds.)
        assert record.state is ExecutionState.LEASE_ISSUED

    def test_a_recovered_clock_allows_the_same_lease(self):
        """Calibration for the unreadable-clock class."""

        class FlipClock:
            def __init__(self):
                self.bad = False
                self.t = 2000.0

            def __call__(self):
                if self.bad:
                    raise RuntimeError("clock dead")
                return self.t

        clock = FlipClock()
        store = ExecutionLeaseStore(clock=clock)
        sdk = build_sdk(clock=clock, execution_lease_store=store)
        lease, cap = issue(sdk)
        clock.bad = True
        refused = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="again"
        )
        assert not refused.allowed
        clock.bad = False
        outcome = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="again"
        )
        sdk.close()

        assert outcome.allowed, outcome.reason


class TestUnwritableLeaseStore:
    def test_a_failed_backend_write_refuses_the_progression(self, tmp_path):
        """Evidence (the record) must be written before the phase advances;
        a store that cannot record cannot advance."""

        backend = SQLiteExecutionLeaseStore(str(tmp_path / "leases.db"))
        store = ExecutionLeaseStore(backend=backend)
        sdk = build_sdk(execution_lease_store=store)
        lease, cap = issue(sdk)
        backend.close()

        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="nowrite"
        )
        record = store.get(lease.lease_id)
        sdk.close()

        assert not reserved.allowed
        assert reserved.reason == "lease_store_error"
        # The in-memory record did not advance either: persist-before-
        # publish means a failed write leaves the phase unchanged.
        assert record.state is ExecutionState.LEASE_ISSUED


class TestStaleAndExpired:
    def test_an_expired_lease_is_refused_and_lapses(self):
        class Clock:
            def __init__(self):
                self.t = 3000.0

            def __call__(self):
                return self.t

        clock = Clock()
        store = ExecutionLeaseStore(clock=clock)
        sdk = build_sdk(clock=clock, execution_lease_store=store)
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST), ttl=1)
        assert issued.allowed, issued.reason
        clock.t += 60

        outcome = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="late"
        )
        record = store.get(issued.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_expired"
        assert record.state is ExecutionState.EXPIRED

    def test_a_lease_cannot_outlive_its_capability(self):
        """The capability window bounds the lease: expiry of the grant
        expires the continuation of the grant."""

        class MutableClock:
            def __init__(self):
                self.t = 1000.0

            def __call__(self):
                return self.t

        clock = MutableClock()
        store = ExecutionLeaseStore(clock=clock)
        sdk = build_sdk(clock=clock, execution_lease_store=store)
        key = sdk.generate_key(f"exp-{uuid.uuid4().hex[:8]}").private_key
        cap = sdk.issue(
            agent="agent-a",
            capability=ACTION,
            private_key=key,
            constraints={"amount_max": 100},
            issued_at=1000.0,
            expires_at=1005.0,
        )
        # At t=1001 the capability is valid; the lease (ttl 3600) far
        # outlives it by construction.
        clock.t = 1001.0
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST), ttl=3600)
        assert issued.allowed, issued.reason

        clock.t = 1010.0

        outcome = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="late2"
        )
        record = store.get(issued.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "capability_expired"
        assert record.state is ExecutionState.EXPIRED


class TestAuthorityLossBetweenStages:
    @pytest.mark.parametrize(
        "attack",
        ["revoke", "suspend", "risk", "issuer", "policy", "epoch"],
    )
    def test_reserve_is_refused_after_each_authority_loss(self, attack):
        """Authorize first (the lease exists and is valid), then destroy
        the authority, then ask to reserve: the continuation must fail."""

        sdk = _sdk_for(attack)
        cap = make_capability(sdk, agent="agent-x")

        outcome = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert outcome.allowed, (attack, outcome.reason)

        _apply(attack, sdk, cap)

        reserved = sdk.reserve_execution(
            outcome.lease, cap, ACTION, dict(REQUEST), execution_id="lost"
        )
        sdk.close()

        assert not reserved.allowed, attack
        assert reserved.reason
        # An authority loss invalidates the lease; it stops in an
        # explicit terminal failure, never as a clean completion.
        assert reserved.state in (
            ExecutionState.REVOKED,
            ExecutionState.EXPIRED,
        )
        if attack == "epoch":
            assert reserved.reason in (
                "execution_epoch_diverged",
                "execution_widening_in_flight",
            )
        elif attack == "risk":
            assert reserved.reason == "risk_state_revoked"
        elif attack == "issuer":
            assert reserved.reason == "issuer_untrusted"


def _sdk_for(attack):
    if attack == "suspend":
        return build_sdk(aegis=AegisController())
    if attack in ("risk", "epoch"):
        return build_sdk(risk_context=RiskContext())
    return build_sdk()


def _apply(attack, sdk, cap):
    if attack == "revoke":
        sdk.revoke(cap, reason="v2.7")
    elif attack == "suspend":
        sdk.aegis.register(
            sdk.fingerprint(cap),
            agent_id=cap.agent_id,
            capability=cap.capability,
        )
        sdk.aegis.suspend(
            sdk.fingerprint(cap), key="k", reason="v2.7"
        )
    elif attack == "risk":
        sdk.risk_context.record_critical(cap.agent_id)
    elif attack == "issuer":
        sdk.revoke_issuer(cap.issuer)
    elif attack == "policy":
        sdk.max_delegation_depth = 5
    elif attack == "epoch":
        # Replacing the risk context is a widening write; the epoch moves
        # and the lease issued under the old context no longer covers it.
        sdk.set_risk_context(RiskContext())


class TestDelegationLineageLoss:
    def test_clearing_lineage_freezes_a_delegated_lease(self):
        sdk = build_sdk()
        root = make_capability(sdk, agent="agent-root")
        key = sdk.keys.active().private_key
        child = sdk.delegate(root, key, delegatee="agent-child").child
        issued = sdk.authorize_execution(child, child.capability, dict(REQUEST))
        assert issued.allowed, issued.reason

        sdk.delegation_lineage.clear()

        outcome = sdk.reserve_execution(
            issued.lease, child, child.capability, dict(REQUEST),
            execution_id="nolines",
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        # A capability signed as a delegation with no registered parent
        # cannot authorize as a root.
        assert not outcome.allowed
        assert outcome.reason.startswith("delegation_chain")
        assert record.state in (
            ExecutionState.REVOKED,
            ExecutionState.LEASE_ISSUED,
        )


class TestMalformedAndForged:
    def test_an_execution_id_cannot_be_empty_or_typed_wrong(self):
        sdk = build_sdk()
        lease, cap = issue(sdk)
        for bad in ("", "   ", 42, object()):
            outcome = sdk.reserve_execution(
                lease, cap, ACTION, dict(REQUEST), execution_id=bad
            )
            assert not outcome.allowed
            assert outcome.reason == "invalid_execution_id"
        # Calibration: a lease without an identity is still single-use by
        # its own state; and a proper identity works.
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="proper-id"
        )
        assert reserved.allowed, reserved.reason
        sdk.close()

    def test_a_lease_with_no_record_cannot_be_reserved(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        ghost = ExecutionLease(
            lease_id="f" * 32,
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
        outcome = sdk.reserve_execution(
            ghost, cap, ACTION, dict(REQUEST), execution_id="ghost"
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_unknown"


class TestExceptionToVerdictEscapes:
    def test_no_public_lease_call_raises_on_hostile_input(self):
        """A caller's ``except Exception`` must never be what decides."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed

        calls = [
            lambda: sdk.authorize_execution(object(), ACTION, {}),
            lambda: sdk.authorize_execution(cap, "", {}),
            lambda: sdk.authorize_execution(cap, ACTION, "not-a-dict"),
            lambda: sdk.reserve_execution(None, cap, ACTION, {}),
            lambda: sdk.reserve_execution(
                issued.lease, cap, ACTION, {"unserialisable": {1, 2}},
                execution_id="x",
            ),
            lambda: sdk.start_execution(object(), cap, ACTION, {}),
            lambda: sdk.complete_execution(
                issued.lease, None, ACTION, {}
            ),
            lambda: sdk.abort_execution(object()),
            lambda: sdk.abort_execution("0" * 32),
        ]

        for call in calls:
            outcome = call()
            assert isinstance(outcome.allowed, bool), type(outcome)
            assert outcome.allowed is False
            assert outcome.reason

        sdk.close()

    def test_the_valid_control_path_still_completes(self):
        """Calibration: this file must not be satisfiable by blanket
        refusal."""

        sdk = build_sdk()
        lease, cap = issue(sdk)
        reserved = sdk.reserve_execution(
            lease, cap, ACTION, dict(REQUEST), execution_id="calib"
        )
        assert reserved.allowed, reserved.reason
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        assert started.allowed, started.reason
        completed = sdk.complete_execution(
            started.lease, cap, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert completed.allowed, completed.reason
