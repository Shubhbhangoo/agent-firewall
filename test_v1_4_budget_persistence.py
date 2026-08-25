from __future__ import annotations

import pytest

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)
from firewall.semantic_chain import (
    SemanticChainContext,
)


def authorize(
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
        capability_fingerprint=(
            f"{chain_id}-{amount}"
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
        )
    except Exception:
        tx.abort()
        raise

    tx.commit()


def test_security_budget_survives_restart(tmp_path):
    state_path = (
        tmp_path / "security-state.json"
    )

    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=1000,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    authorize(
        semantic,
        security,
        "chain-a",
        600,
    )

    assert (
        security.snapshot().total_amount
        == 600
    )

    # Simulate process restart.
    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    assert (
        restarted.snapshot().total_amount
        == 600
    )

    # Only 400 remains.
    with pytest.raises(
        SecurityBudgetExceeded
    ):
        restarted.authorize_and_record(
            request={
                "amount": 500,
                "account": "acct-1",
            },
        )

    # A valid remaining amount still works.
    restarted.authorize_and_record(
        request={
            "amount": 400,
            "account": "acct-1",
        },
    )

    assert (
        restarted.snapshot().total_amount
        == 1000
    )


def test_restart_preserves_used_capabilities(tmp_path):
    state_path = (
        tmp_path / "security-state.json"
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    security.authorize_and_record(
        request={
            "amount": 100,
        },
        capability_fingerprint="cap-123",
    )

    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    assert restarted.has_used_capability(
        "cap-123"
    )


def test_corrupt_persisted_security_state_fails_closed(
    tmp_path,
):
    state_path = (
        tmp_path / "security-state.json"
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    security.authorize_and_record(
        request={
            "amount": 600,
        },
    )

    state_path.write_text(
        '{"payload":{"total_amount":0}}',
        encoding="utf-8",
    )

    with pytest.raises(
        Exception
    ):
        SecurityContext(
            agent="agent-a",
            max_total_amount=1000,
            state_path=state_path,
        )


def test_persisted_state_cannot_exceed_configured_budget(
    tmp_path,
):
    state_path = (
        tmp_path / "security-state.json"
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    security.authorize_and_record(
        request={
            "amount": 1000,
        },
    )

    with pytest.raises(
        Exception
    ):
        SecurityContext(
            agent="agent-a",
            max_total_amount=500,
            state_path=state_path,
        )