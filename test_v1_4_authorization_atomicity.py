from __future__ import annotations

import pytest

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)
from firewall.semantic_chain import (
    SemanticChainDenied,
    SemanticChainContext,
    SemanticBudgetExceeded,
)


def make_contexts(
    *,
    semantic_budget=100,
    security_budget=100,
):
    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=semantic_budget,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=security_budget,
    )

    return semantic, security


def authorize(
    semantic,
    security,
    *,
    chain_id,
    amount,
    capability_fingerprint,
):
    tx = semantic.begin_authorization(
        agent="agent-a",
        action="payments.send",
        request={
            "amount": amount,
            "account": "acct-1",
        },
        capability_fingerprint=(
            capability_fingerprint
        ),
        capability="payments.send",
        chain_id=chain_id,
    )

    try:
        security.authorize_and_record(
            request={
                "amount": amount,
                "account": "acct-1",
            },
            capability_fingerprint=(
                capability_fingerprint
            ),
        )
    except Exception:
        tx.abort()
        raise

    tx.commit()


def test_semantic_and_security_success_commit_together():
    semantic, security = make_contexts()

    authorize(
        semantic,
        security,
        chain_id="chain-a",
        amount=40,
        capability_fingerprint="cap-1",
    )

    assert semantic.total_amount() == 40
    assert (
        security.snapshot().total_amount
        == 40
    )

    snapshots = semantic.snapshot()

    assert snapshots[0].actions
    assert len(snapshots[0].actions) == 1


def test_semantic_denial_does_not_charge_security_budget():
    semantic = SemanticChainContext(
        agent="agent-a",
        rules=(
            # A protected sequence that this single action
            # deliberately completes.
        ),
        max_total_amount=100,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    # Use a rule that immediately denies this action.
    semantic.rules = (
        # This assignment is intentionally replaced below
        # because rules are stored immutably as a tuple.
    )

    semantic = SemanticChainContext(
        agent="agent-a",
        rules=(
            __import__(
                "firewall.semantic_chain",
                fromlist=["SemanticRule"],
            ).SemanticRule(
                outcome="blocked",
                sequence=("payments.send",),
                resource_key="account",
                allowed=False,
            ),
        ),
        max_total_amount=100,
    )

    with pytest.raises(
        SemanticChainDenied
    ):
        semantic.begin_authorization(
            agent="agent-a",
            action="payments.send",
            request={
                "amount": 40,
                "account": "acct-1",
            },
            capability_fingerprint="cap-denied",
            capability="payments.send",
            chain_id="chain-a",
        )

    assert semantic.total_amount() == 0
    assert (
        security.snapshot().total_amount
        == 0
    )


def test_security_denial_aborts_semantic_transaction():
    semantic, security = make_contexts(
        semantic_budget=100,
        security_budget=50,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize(
            semantic,
            security,
            chain_id="chain-a",
            amount=60,
            capability_fingerprint="cap-1",
        )

    assert semantic.total_amount() == 0
    assert (
        security.snapshot().total_amount
        == 0
    )

    snapshots = semantic.snapshot()

    # The failed request must not become a committed action.
    committed_actions = [
        action
        for snapshot in snapshots
        for action in snapshot.actions
    ]

    assert committed_actions == []


def test_security_budget_can_fail_after_previous_success():
    semantic, security = make_contexts(
        semantic_budget=1000,
        security_budget=100,
    )

    authorize(
        semantic,
        security,
        chain_id="chain-a",
        amount=60,
        capability_fingerprint="cap-1",
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize(
            semantic,
            security,
            chain_id="chain-b",
            amount=50,
            capability_fingerprint="cap-2",
        )

    assert semantic.total_amount() == 60
    assert security.snapshot().total_amount == 60

    snapshots = semantic.snapshot()

    committed = [
        action
        for snapshot in snapshots
        for action in snapshot.actions
    ]

    assert len(committed) == 1
    assert committed[0].amount == 60


def test_semantic_transaction_can_be_reused_after_security_denial():
    semantic, security = make_contexts(
        semantic_budget=100,
        security_budget=50,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize(
            semantic,
            security,
            chain_id="chain-a",
            amount=60,
            capability_fingerprint="cap-fail",
        )

    # The semantic context must still accept a later
    # request after the failed transaction released its lock.
    authorize(
        semantic,
        security,
        chain_id="chain-b",
        amount=40,
        capability_fingerprint="cap-success",
    )

    assert semantic.total_amount() == 40
    assert (
        security.snapshot().total_amount
        == 40
    )