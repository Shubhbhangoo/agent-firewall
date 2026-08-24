from __future__ import annotations

import threading

import pytest

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)


def test_empty_context():
    context = SecurityContext(
        agent="agent-a",
    )

    snapshot = context.snapshot()

    assert snapshot.agent == "agent-a"
    assert snapshot.action_count == 0
    assert snapshot.total_amount == 0
    assert snapshot.denial_count == 0
    assert snapshot.used_capabilities == ()


def test_action_budget():
    context = SecurityContext(
        agent="agent-a",
        max_actions=2,
    )

    context.record(
        request={"amount": 10},
    )

    context.record(
        request={"amount": 20},
    )

    with pytest.raises(
        SecurityBudgetExceeded,
        match="action budget exceeded",
    ):
        context.record(
            request={"amount": 30},
        )


def test_total_amount_budget():
    context = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    context.record(
        request={"amount": 40},
    )

    context.record(
        request={"amount": 60},
    )

    with pytest.raises(
        SecurityBudgetExceeded,
        match="total amount budget exceeded",
    ):
        context.record(
            request={"amount": 1},
        )


def test_check_does_not_mutate():
    context = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    context.check(
        {"amount": 50}
    )

    snapshot = context.snapshot()

    assert snapshot.action_count == 0
    assert snapshot.total_amount == 0


def test_record_tracks_capability():
    context = SecurityContext(
        agent="agent-a",
    )

    context.record(
        request={"amount": 10},
        capability_fingerprint="cap-123",
    )

    assert context.has_used_capability(
        "cap-123"
    )


def test_denials_are_tracked():
    context = SecurityContext(
        agent="agent-a",
    )

    context.record_denial()
    context.record_denial()

    assert (
        context.snapshot().denial_count
        == 2
    )


def test_negative_amount_rejected():
    context = SecurityContext(
        agent="agent-a",
    )

    with pytest.raises(
        ValueError,
        match="amount cannot be negative",
    ):
        context.record(
            request={"amount": -1},
        )


def test_invalid_amount_rejected():
    context = SecurityContext(
        agent="agent-a",
    )

    with pytest.raises(
        ValueError,
        match="amount must be numeric",
    ):
        context.record(
            request={"amount": "100"},
        )


def test_reset():
    context = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    context.record(
        request={"amount": 50},
        capability_fingerprint="cap-1",
    )

    context.record_denial()

    context.reset()

    snapshot = context.snapshot()

    assert snapshot.action_count == 0
    assert snapshot.total_amount == 0
    assert snapshot.denial_count == 0
    assert snapshot.used_capabilities == ()


def test_concurrent_budget_is_atomic():
    context = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    errors = []

    def worker():
        try:
            context.record(
                request={"amount": 10},
            )
        except SecurityBudgetExceeded:
            errors.append(True)

    threads = [
        threading.Thread(
            target=worker
        )
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    snapshot = context.snapshot()

    assert snapshot.total_amount <= 100
    assert snapshot.action_count <= 10
    assert (
        snapshot.total_amount
        == snapshot.action_count * 10
    )
    assert len(errors) == 10


def test_multiple_capabilities_are_tracked():
    context = SecurityContext(
        agent="agent-a",
    )

    context.record(
        request={"amount": 10},
        capability_fingerprint="cap-a",
    )

    context.record(
        request={"amount": 20},
        capability_fingerprint="cap-b",
    )

    snapshot = context.snapshot()

    assert snapshot.used_capabilities == (
        "cap-a",
        "cap-b",
    )