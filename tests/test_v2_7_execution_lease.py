"""v2.7: execution leases bind an allow to the facts it authorized.

The v2.6 boundary ends where ``authorize()`` returns. v2.7 records the
continuation -- an execution lease -- and makes each step of the recorded
execution re-establish the authority basis. This file covers the lease
itself: what it binds, how the valid path works (the calibration every
negative test needs), and that the *object* is never trusted -- the store
record and the live state decide.

Every class here carries at least one case that must *succeed*, so a
green run cannot mean "everything was refused".
"""

from __future__ import annotations

import json
import uuid

import pytest

from firewall.capability import Capability
from firewall.execution_lease import (
    ALLOWED_TRANSITIONS,
    ExecutionIdentityBoundError,
    ExecutionLease,
    ExecutionLeaseOutcome,
    ExecutionLeaseStore,
    ExecutionState,
    IllegalTransitionError,
    canonical_request_digest,
    is_terminal,
    transition_allowed,
)
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
) -> Capability:
    key = sdk.generate_key(f"v27-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=capability,
        private_key=key,
        constraints={} if constraints is None else dict(constraints),
    )


def full_cycle(sdk: FirewallSDK, cap: Capability, request=None):
    """The valid control path; returns the completed lease record."""

    issued = sdk.authorize_execution(cap, cap.capability, request)
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        cap,
        cap.capability,
        request,
        execution_id=f"exec-{uuid.uuid4().hex[:8]}",
    )
    assert reserved.allowed, reserved.reason
    started = sdk.start_execution(
        reserved.lease,
        cap,
        cap.capability,
        request,
    )
    assert started.allowed, started.reason
    completed = sdk.complete_execution(
        started.lease,
        cap,
        cap.capability,
        request,
    )
    assert completed.allowed, completed.reason
    return completed.lease


# ----------------------------------------------------------------------
# What a lease binds
# ----------------------------------------------------------------------


class TestTheLeaseBindsTheDecision:
    def test_a_complete_cycle_is_the_calibration(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        lease = full_cycle(sdk, cap, dict(REQUEST))
        sdk.close()

        assert lease.state is ExecutionState.COMPLETED
        assert lease.executed is True
        assert lease.reserve_authority_valid is True
        assert lease.start_authority_valid is True
        assert lease.complete_authority_valid is True

    def test_the_lease_records_the_authorized_facts(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        lease = issued.lease
        fingerprint = sdk.fingerprint(cap)
        sdk.close()

        assert lease.capability_fingerprint == fingerprint
        assert lease.agent_id == cap.agent_id
        assert lease.capability == cap.capability
        assert lease.action == ACTION
        assert lease.request_digest == canonical_request_digest(REQUEST)
        assert lease.issuer == cap.issuer
        assert lease.tool == cap.tool
        assert lease.policy_version  # never empty
        assert lease.issued_at <= lease.expires_at
        assert lease.chain_fingerprints == (fingerprint,)

    def test_the_lease_records_the_delegation_chain_leaf_first(self):
        sdk = build_sdk()
        root = make_capability(sdk, agent="agent-root")
        key = sdk.keys.active().private_key
        child = sdk.delegate(root, key, delegatee="agent-child").child
        issued = sdk.authorize_execution(child, child.capability, dict(REQUEST))
        assert issued.allowed, issued.reason
        chain = issued.lease.chain_fingerprints
        expected = (
            sdk.fingerprint(child),
            sdk.fingerprint(root),
        )
        sdk.close()

        assert chain == expected

    def test_the_lease_has_a_deadline_and_a_nonce(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST), ttl=5)
        assert issued.allowed, issued.reason
        sdk.close()

        assert issued.lease.expires_at - issued.lease.issued_at == pytest.approx(
            5.0
        )
        assert len(issued.lease.nonce) >= 16
        assert len(issued.lease.lease_id) >= 16

    def test_an_invalid_ttl_is_refused_before_any_authorization(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        for bad in (-1, 0, float("nan"), True, "long"):
            outcome = sdk.authorize_execution(cap, ACTION, {}, ttl=bad)
            assert not outcome.allowed
            assert outcome.reason == "invalid_lease_ttl"
        sdk.close()

    def test_authorization_denials_keep_their_reason(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        sdk.revoke(cap, reason="gone")
        outcome = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "capability_revoked"

    def test_a_namespace_denial_never_issues_a_lease(self):
        sdk = build_sdk()
        cap = make_capability(sdk, capability="files.read")
        outcome = sdk.authorize_execution(cap, "payments.send", dict(REQUEST))
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "namespace_denied"

    def test_a_lease_cannot_be_issued_for_a_non_capability(self):
        sdk = build_sdk()
        outcome = sdk.authorize_execution(object(), ACTION, {})
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "invalid_capability"


# ----------------------------------------------------------------------
# The lease object is a reference, never a permission
# ----------------------------------------------------------------------


def forged_lease(**overrides) -> ExecutionLease:
    base = ExecutionLease(
        lease_id="0" * 32,
        state=ExecutionState.LEASE_ISSUED,
        capability_fingerprint="f",
        agent_id="a",
        capability="c",
        action="x",
        request_digest="d",
        chain_id=None,
        policy_version="p",
        nonce="n",
        issued_at=0,
        expires_at=1e12,
    )
    return ExecutionLease.from_dict({**base.to_dict(), **overrides})


class TestTheObjectIsNotTrusted:
    def test_an_unknown_lease_id_is_refused(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        outcome = sdk.reserve_execution(
            forged_lease(), cap, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_unknown"

    def test_a_tampered_nonce_is_refused(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        forged = ExecutionLease.from_dict(
            {**issued.lease.to_dict(), "nonce": "attacker-nonce"}
        )
        outcome = sdk.reserve_execution(forged, cap, ACTION, dict(REQUEST))
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_mismatch"

    def test_a_tampered_state_field_changes_nothing(self):
        """The record's state is authority; the object's state is decoration.

        Setting ``state="completed"`` on the carried object must not let
        an execution skip a phase -- the store's record decides, and it is
        still ``LEASE_ISSUED``.
        """

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        forged = ExecutionLease.from_dict(
            {**issued.lease.to_dict(), "state": "completed"}
        )
        reserved = sdk.reserve_execution(
            forged, cap, ACTION, dict(REQUEST), execution_id="exec-x"
        )
        sdk.close()

        assert reserved.allowed, reserved.reason
        assert reserved.state is ExecutionState.RESERVED

    def test_an_edited_expiry_or_fingerprint_on_the_object_is_refused(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        tampered = ExecutionLease.from_dict(
            {
                **issued.lease.to_dict(),
                "expires_at": issued.lease.expires_at + 1e6,
                "capability_fingerprint": "0" * 64,
            }
        )
        outcome = sdk.reserve_execution(tampered, cap, ACTION, dict(REQUEST))
        sdk.close()

        # The tampered fingerprint disagrees with the record it names.
        assert not outcome.allowed
        assert outcome.reason == "lease_mismatch"

    def test_a_copy_of_a_lease_is_still_single_use(self):
        """Copying a lease does not copy its authority.

        A duplicated object still names the original lease_id, so the
        store's record decides -- and the record is single-use.
        """

        sdk = build_sdk()
        cap = make_capability(sdk)
        first = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert first.allowed
        duplicate = ExecutionLease.from_dict(first.lease.to_dict())
        reserved = sdk.reserve_execution(
            duplicate, cap, ACTION, dict(REQUEST), execution_id="exec-d"
        )
        assert reserved.allowed, reserved.reason
        second = sdk.reserve_execution(
            duplicate, cap, ACTION, dict(REQUEST), execution_id="exec-d2"
        )
        sdk.close()

        assert not second.allowed
        assert second.reason == "lease_already_reserved"

    def test_a_non_lease_object_is_refused_not_raised(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        for bogus in (None, {}, [], "lease-id", 42, object()):
            outcome = sdk.reserve_execution(
                bogus, cap, ACTION, dict(REQUEST)
            )
            assert isinstance(outcome, ExecutionLeaseOutcome)
            assert not outcome.allowed
        sdk.close()

    def test_substituting_another_capability_is_refused(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        other = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        outcome = sdk.reserve_execution(
            issued.lease, other, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "lease_capability_mismatch"

    def test_substituting_a_request_is_refused_and_the_lease_survives(self):
        """A wrong request is a refusal, not a burn: a caller error before
        the reservation must not destroy authority the caller can still
        use correctly."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        wrong = sdk.reserve_execution(
            issued.lease, cap, ACTION, {"amount": 999}
        )
        assert not wrong.allowed
        assert wrong.reason == "lease_request_mismatch"

        # Calibration: the same lease still works with the authorized
        # request.
        right = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="exec-ok"
        )
        sdk.close()

        assert right.allowed, right.reason

    def test_a_fake_allow_shaped_capability_is_refused(self):
        """An object that 'looks allowed' is not a capability."""

        class AllowShaped:
            allowed = True
            capability = ACTION
            agent_id = "agent-a"
            issuer = "trusted-issuer"

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        outcome = sdk.reserve_execution(
            issued.lease, AllowShaped(), ACTION, dict(REQUEST)
        )
        sdk.close()

        assert isinstance(outcome, ExecutionLeaseOutcome)
        assert not outcome.allowed
        assert outcome.reason == "invalid_capability"


# ----------------------------------------------------------------------
# Serialization
# ----------------------------------------------------------------------


class TestSerializationIsNotTrust:
    def test_a_round_tripped_lease_still_executes(self):
        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed
        rebuilt = ExecutionLease.from_dict(
            json.loads(json.dumps(issued.lease.to_dict()))
        )
        reserved = sdk.reserve_execution(
            rebuilt, cap, ACTION, dict(REQUEST), execution_id="exec-s"
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

    def test_a_malformed_serialized_lease_is_refused(self):
        issued = forged_lease()
        data = issued.to_dict()

        for key in ("lease_id", "nonce", "request_digest", "action"):
            broken = dict(data)
            broken[key] = ""
            with pytest.raises(ValueError):
                ExecutionLease.from_dict(broken)

        with pytest.raises(ValueError):
            ExecutionLease.from_dict({**data, "state": "not-a-phase"})

        with pytest.raises(TypeError):
            ExecutionLease.from_dict("not a dict")

    def test_from_dict_reads_what_the_backend_writes(self):
        lease = ExecutionLease(
            lease_id="a" * 32,
            state=ExecutionState.LEASE_ISSUED,
            capability_fingerprint="f",
            agent_id="a",
            capability="c",
            action="x",
            request_digest="d",
            chain_id=None,
            policy_version="p",
            nonce="n",
            issued_at=1,
            expires_at=2,
        )
        rebuilt = ExecutionLease.from_dict(lease.to_dict())
        assert rebuilt.chain_fingerprints == ()
        assert rebuilt.history == ()
        assert rebuilt.details == {}


# ----------------------------------------------------------------------
# The store's state machine
# ----------------------------------------------------------------------


class TestTheStoreStateMachine:
    def test_terminal_states_have_no_outgoing_edges(self):
        for state in ExecutionState:
            if is_terminal(state):
                assert state not in ALLOWED_TRANSITIONS

    def test_forbidden_resurrections_are_refused(self):
        for forbidden in (
            (ExecutionState.COMPLETED, ExecutionState.STARTED),
            (ExecutionState.REVOKED, ExecutionState.STARTED),
            (ExecutionState.EXPIRED, ExecutionState.STARTED),
            (ExecutionState.DENIED, ExecutionState.STARTED),
            (ExecutionState.ABORTED, ExecutionState.STARTED),
            (ExecutionState.COMPLETED, ExecutionState.RESERVED),
        ):
            assert not transition_allowed(*forbidden)

    def test_garbage_states_are_never_legal(self):
        assert transition_allowed("completed", "started") is False
        assert transition_allowed(None, ExecutionState.STARTED) is False
        assert transition_allowed(ExecutionState.STARTED, None) is False
        assert is_terminal("bogus") is True

    def _store_lease(self, store, ttl=60):
        return store.issue(
            capability_fingerprint="f",
            agent_id="a",
            capability="c",
            action="x",
            request_digest="d",
            chain_id=None,
            policy_version="p",
            ttl=ttl,
        )

    def test_the_store_refuses_an_illegal_transition(self):
        store = ExecutionLeaseStore()
        lease = self._store_lease(store)
        store.transition(
            lease.lease_id, ExecutionState.RESERVED, execution_id="e"
        )
        store.transition(lease.lease_id, ExecutionState.STARTED)
        store.transition(
            lease.lease_id, ExecutionState.COMPLETED, executed=True
        )
        with pytest.raises(IllegalTransitionError):
            store.transition(lease.lease_id, ExecutionState.STARTED)
        store.close()

    def test_an_unknown_lease_transition_is_a_none_refusal(self):
        store = ExecutionLeaseStore()
        moved = store.transition(
            "0" * 32, ExecutionState.RESERVED, execution_id="e"
        )
        store.close()

        assert moved is None

    def test_an_execution_identity_is_bound_to_one_live_lease(self):
        store = ExecutionLeaseStore()
        first = self._store_lease(store)
        second = self._store_lease(store)
        store.transition(
            first.lease_id, ExecutionState.RESERVED, execution_id="shared"
        )
        with pytest.raises(ExecutionIdentityBoundError):
            store.transition(
                second.lease_id,
                ExecutionState.RESERVED,
                execution_id="shared",
            )
        store.close()

    def test_a_terminal_lease_releases_its_execution_identity(self):
        store = ExecutionLeaseStore()
        first = self._store_lease(store)
        store.transition(
            first.lease_id, ExecutionState.RESERVED, execution_id="reuse"
        )
        store.transition(first.lease_id, ExecutionState.STARTED)
        store.transition(
            first.lease_id, ExecutionState.COMPLETED, executed=True
        )
        # Identity released: a later lease may reuse the label.
        second = self._store_lease(store)
        moved = store.transition(
            second.lease_id,
            ExecutionState.RESERVED,
            execution_id="reuse",
        )
        store.close()

        assert moved is not None
        assert moved.state is ExecutionState.RESERVED

    def test_expire_lapsed_skips_started_records(self):
        class Clock:
            def __init__(self):
                self.t = 1000.0

            def __call__(self):
                return self.t

        clock = Clock()
        store = ExecutionLeaseStore(clock=clock)
        lease = self._store_lease(store, ttl=1)
        store.transition(
            lease.lease_id, ExecutionState.RESERVED, execution_id="e"
        )
        store.transition(lease.lease_id, ExecutionState.STARTED)
        clock.t += 10
        lapsed = store.expire_lapsed()
        record = store.get(lease.lease_id)
        store.close()

        # STARTED is left alone: the action may genuinely be running.
        assert lapsed == 0
        assert record.state is ExecutionState.STARTED
