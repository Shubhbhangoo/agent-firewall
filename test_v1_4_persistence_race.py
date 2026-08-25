from __future__ import annotations

import threading

import pytest

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)


def test_concurrent_persistent_contexts_do_not_exceed_budget(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    results = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            context = SecurityContext(
                agent="agent-a",
                max_total_amount=100,
                state_path=state_path,
            )

            context.authorize_and_record(
                request={
                    "amount": 60,
                },
                capability_fingerprint=f"cap-{index}",
            )

            outcome = "allowed"

        except SecurityBudgetExceeded:
            outcome = "denied"

        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(2)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors

    # At most one $60 authorization may succeed.
    assert results.count("allowed") <= 1
    assert results.count("denied") >= 1


def test_persistent_state_is_not_reset_by_truncated_file(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={
            "amount": 600,
        },
    )

    state_path.write_text(
        '{"payload":{"version":1',
        encoding="utf-8",
    )

    with pytest.raises(Exception):
        SecurityContext(
            agent="agent-a",
            max_total_amount=1000,
            state_path=state_path,
        )


def test_persistent_state_agent_mismatch_fails_closed(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={
            "amount": 600,
        },
    )

    with pytest.raises(Exception):
        SecurityContext(
            agent="agent-b",
            max_total_amount=1000,
            state_path=state_path,
        )


def test_persistent_state_budget_cannot_be_lowered_below_spend(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={
            "amount": 800,
        },
    )

    with pytest.raises(Exception):
        SecurityContext(
            agent="agent-a",
            max_total_amount=700,
            state_path=state_path,
        )


def test_persistent_state_remains_usable_after_failed_write(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={
            "amount": 100,
        },
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        context.authorize_and_record(
            request={
                "amount": 1,
            },
        )

    assert (
        context.snapshot().total_amount
        == 100
    )

    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
        state_path=state_path,
    )

    assert (
        restarted.snapshot().total_amount
        == 100
    )