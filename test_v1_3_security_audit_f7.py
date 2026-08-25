from firewall.semantic_chain import SemanticChainContext


def authorize(
    context,
    chain_id,
    amount,
):
    tx = context.begin_authorization(
        agent="agent-a",
        action="payments.send",
        request={"amount": amount},
        capability_fingerprint=f"{chain_id}-{amount}",
        capability="payments.send",
        chain_id=chain_id,
    )

    tx.commit()


def test_semantic_context_does_not_enforce_budget_across_chains():
    context = SemanticChainContext(
        agent="agent-a",
    )

    authorize(
        context,
        "chain-1",
        100,
    )

    authorize(
        context,
        "chain-2",
        100,
    )

    snapshot = context.snapshot()

    total = sum(
        item.total_amount
        for item in snapshot
    )

    assert total == 200

    # This deliberately documents the current behavior:
    # SemanticChainContext has no global budget.
    assert len(snapshot) == 2