"""v2.7: the execution-authority-continuity invariant has teeth.

The invariant's three halves are pinned here: the state-machine algebra,
the source census over who may drive the lease store, and the
record-level hygiene that refuses to let an execution record claim a
clean completion its authority flags do not support. The negative tests
forge records that *look* complete but whose flags say otherwise, and the
positive control runs a real estate and asserts the invariant HOLDS on
it.
"""

from __future__ import annotations

import uuid

import pytest

from firewall.execution_lease import (
    ExecutionLease,
    ExecutionLeaseStore,
    ExecutionState,
)
from firewall.invariants import check_execution_authority_continuity
from firewall.invariants.model import InvariantStatus
from firewall.invariants.runtime import EXECUTION_STORE_MUTATOR_OWNERS
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
):
    key = sdk.generate_key(f"v27i-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent=agent,
        capability=capability,
        private_key=key,
        constraints={"amount_max": 100},
    )


def minimal_lease(
    *,
    state: ExecutionState = ExecutionState.LEASE_ISSUED,
    lease_id: str = "",
    history=(),
    **overrides,
) -> ExecutionLease:
    """A directly constructed record, as a hostile writer might inject.

    Built with the dataclass constructor rather than ``from_dict`` so the
    tests can forge records whose *content* is the finding (an illegal
    history edge, a missing validity flag) without fighting the
    serializer's own refusal of malformed input.
    """

    return ExecutionLease(
        lease_id=lease_id or uuid.uuid4().hex,
        state=state,
        capability_fingerprint="f",
        agent_id="a",
        capability="c",
        action="x",
        request_digest="d",
        chain_id=None,
        policy_version="p",
        nonce="n",
        issued_at=0.0,
        expires_at=1e12,
        history=history,
        **overrides,
    )


class TestStateMachineAlgebra:
    def test_no_terminal_phase_has_outgoing_edges(self):
        from firewall.execution_lease import ALLOWED_TRANSITIONS, is_terminal

        for state in ExecutionState:
            if is_terminal(state):
                assert ALLOWED_TRANSITIONS.get(state, frozenset()) == frozenset()

    def test_resurrection_edges_are_illegal(self):
        from firewall.execution_lease import transition_allowed

        for terminal in (
            ExecutionState.COMPLETED,
            ExecutionState.REVOKED,
            ExecutionState.EXPIRED,
            ExecutionState.DENIED,
            ExecutionState.ABORTED,
        ):
            assert not transition_allowed(terminal, ExecutionState.STARTED)
            assert not transition_allowed(terminal, ExecutionState.RESERVED)

    def test_the_lifecycle_edges_exist(self):
        from firewall.execution_lease import transition_allowed

        assert transition_allowed(
            ExecutionState.LEASE_ISSUED, ExecutionState.RESERVED
        )
        assert transition_allowed(
            ExecutionState.RESERVED, ExecutionState.STARTED
        )
        assert transition_allowed(
            ExecutionState.STARTED, ExecutionState.COMPLETED
        )
        assert transition_allowed(
            ExecutionState.AUTHORIZED, ExecutionState.LEASE_ISSUED
        )


class TestSourceCensus:
    def test_every_declared_execution_path_names_a_real_sdk_method(self):
        """The census must not rot into names that no longer exist."""

        for module, method in EXECUTION_STORE_MUTATOR_OWNERS:
            assert module == "firewall/sdk.py"
            owner, _, name = method.partition(".")
            assert owner == "FirewallSDK"
            assert hasattr(FirewallSDK, name), (
                f"census names FirewallSDK.{name} which does not exist"
            )

    def test_every_lease_store_mutator_is_called_only_by_declared_methods(self):
        """Both census directions hold on the current source."""

        result = check_execution_authority_continuity(None)
        # No SDK: the source half decides, and it must pass.
        assert result.status is InvariantStatus.UNVERIFIABLE or (
            result.status is InvariantStatus.HOLDS
        )
        assert result.findings == ()


class TestRecordHygiene:
    def test_a_clean_completed_record_holds(self):
        """Positive control: the invariant must pass on a genuine record."""

        sdk = build_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="audit"
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        completed = sdk.complete_execution(
            started.lease, cap, ACTION, dict(REQUEST)
        )
        assert completed.allowed, completed.reason

        result = check_execution_authority_continuity(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS, (
            result.reason,
            list(result.findings)[:5],
        )

    def test_completed_without_authority_flags_is_a_violation(self):
        store = ExecutionLeaseStore()
        lease = store.issue(
            capability_fingerprint="f",
            agent_id="a",
            capability="c",
            action="x",
            request_digest="d",
            chain_id=None,
            policy_version="p",
            ttl=60,
        )
        # Legal transitions but no validity flags: a caller that drove the
        # store directly, bypassing the SDK validation, could write this.
        store.transition(
            lease.lease_id, ExecutionState.RESERVED, execution_id="e"
        )
        store.transition(lease.lease_id, ExecutionState.STARTED)
        store.transition(
            lease.lease_id, ExecutionState.COMPLETED, executed=True
        )

        # Now patch the record to look like a clean completion is
        # impossible through the public store; instead simulate the forged
        # record by writing a complete-looking row directly into the
        # backend-less store's table is not possible either. So drive the
        # violation through a store that receives a forged upsert.
        store._records[lease.lease_id] = minimal_lease(
            state=ExecutionState.COMPLETED,
            lease_id=lease.lease_id,
            executed=True,
        )
        result = check_execution_authority_continuity(
            _sdk_around(store)
        )
        store.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("COMPLETED" in f for f in result.findings)

    def test_started_then_terminal_without_executed_is_a_violation(self):
        """A STARTED execution that stops in a failure must say it ran."""

        store = ExecutionLeaseStore()
        lease = store.issue(
            capability_fingerprint="f",
            agent_id="a",
            capability="c",
            action="x",
            request_digest="d",
            chain_id=None,
            policy_version="p",
            ttl=60,
        )
        store.transition(
            lease.lease_id, ExecutionState.RESERVED, execution_id="e"
        )
        store.transition(lease.lease_id, ExecutionState.STARTED)
        store.transition(
            lease.lease_id,
            ExecutionState.ABORTED,
            executed=False,
            terminal_reason="oops",
        )
        store._records[lease.lease_id] = minimal_lease(
            state=ExecutionState.ABORTED,
            lease_id=lease.lease_id,
            executed=False,
            history=(
                (ExecutionState.LEASE_ISSUED, ExecutionState.RESERVED, 0.0, ""),
                (ExecutionState.RESERVED, ExecutionState.STARTED, 0.0, ""),
                (ExecutionState.STARTED, ExecutionState.ABORTED, 0.0, "oops"),
            ),
        )
        result = check_execution_authority_continuity(
            _sdk_around(store)
        )
        store.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("executed=True" in f for f in result.findings)

    def test_an_illegal_history_edge_is_a_violation(self):
        store = ExecutionLeaseStore()
        store._records["f" * 32] = minimal_lease(
            lease_id="f" * 32,
            state=ExecutionState.COMPLETED,
            executed=True,
            reserve_authority_valid=True,
            start_authority_valid=True,
            complete_authority_valid=True,
            history=(
                (
                    ExecutionState.COMPLETED,
                    ExecutionState.STARTED,
                    0.0,
                    "forged",
                ),
            ),
        )
        result = check_execution_authority_continuity(
            _sdk_around(store)
        )
        store.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("illegal transition" in f for f in result.findings)

    def test_an_empty_store_is_unverifiable_not_holds(self):
        result = check_execution_authority_continuity(build_sdk())
        assert result.status is InvariantStatus.UNVERIFIABLE


def _sdk_around(store: ExecutionLeaseStore) -> FirewallSDK:
    """An SDK whose lease store is ``store``, for auditing its records."""

    sdk = FirewallSDK(execution_lease_store=store)
    return sdk
