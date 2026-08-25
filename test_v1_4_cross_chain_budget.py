import pytest
from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)
from firewall.semantic_chain import (
    SemanticChainContext,
)


def authorize_chain(
    semantic,
    security,
    chain_id,
    amount,
):
    tx = semantic.begin_authorization(
        agent="agent-a",
        action="payments.send",
        request={
            "amount": amount,
            "account": "acct-1",
        },
        capability_fingerprint=f"{chain_id}-{amount}",
        capability="payments.send",
        chain_id=chain_id,
    )

    try:
        security.authorize_and_record(
            request={
                "amount": amount,
                "account": "acct-1",
            },
        )
    except Exception:
        tx.abort()
        raise

    tx.commit()


def test_cross_chain_budget_is_global():
    semantic = SemanticChainContext(
        agent="agent-a",
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
    )

    authorize_chain(
        semantic,
        security,
        "chain-a",
        600,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize_chain(
            semantic,
            security,
            "chain-b",
            500,
        )

    snapshot = security.snapshot()

    assert snapshot.total_amount == 600
    assert snapshot.action_count == 1


def test_cross_chain_budget_allows_remaining_amount():
    semantic = SemanticChainContext(
        agent="agent-a",
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
    )

    authorize_chain(
        semantic,
        security,
        "chain-a",
        600,
    )

    authorize_chain(
        semantic,
        security,
        "chain-b",
        400,
    )

    snapshot = security.snapshot()

    assert snapshot.total_amount == 1000
    assert snapshot.action_count == 2


def test_failed_cross_chain_budget_does_not_commit_action():
    semantic = SemanticChainContext(
        agent="agent-a",
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    authorize_chain(
        semantic,
        security,
        "chain-a",
        100,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize_chain(
            semantic,
            security,
            "chain-b",
            1,
        )

    snapshots = semantic.snapshot()

    chain_b = [
        snapshot
        for snapshot in snapshots
        if snapshot.chain_id == "chain-b"
    ]

    # An aborted transaction must not contain an action.
    assert chain_b[0].actions == ()

    assert security.snapshot().total_amount == 100
    assert security.snapshot().action_count == 1


def test_failed_cross_chain_budget_releases_semantic_transaction():
    semantic = SemanticChainContext(
        agent="agent-a",
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    authorize_chain(
        semantic,
        security,
        "chain-a",
        100,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize_chain(
            semantic,
            security,
            "chain-b",
            1,
        )

    # The semantic context must still be usable.
    # An aborted transaction must not leave its lock held.
    tx = semantic.begin_authorization(
        agent="agent-a",
        action="payments.send",
        request={
            "amount": 0,
            "account": "acct-2",
        },
        capability_fingerprint="post-failure",
        capability="payments.send",
        chain_id="chain-c",
    )

    tx.commit()


def test_cross_chain_budget_is_shared_across_many_chain_ids():
    semantic = SemanticChainContext(
        agent="agent-a",
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    authorize_chain(
        semantic,
        security,
        "chain-a",
        25,
    )

    authorize_chain(
        semantic,
        security,
        "chain-b",
        25,
    )

    authorize_chain(
        semantic,
        security,
        "chain-c",
        25,
    )

    authorize_chain(
        semantic,
        security,
        "chain-d",
        25,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        authorize_chain(
            semantic,
            security,
            "chain-e",
            1,
        )

    snapshot = security.snapshot()

    assert snapshot.total_amount == 100
    assert snapshot.action_count == 4