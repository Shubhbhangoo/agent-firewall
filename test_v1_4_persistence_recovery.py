from __future__ import annotations

import os
import time

import pytest

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
    SecurityContextError,
)


def test_stale_temp_file_does_not_override_last_good_state(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={"amount": 600},
    )

    stale_temp = (
        tmp_path / ".security_context_stale.tmp"
    )

    stale_temp.write_text(
        '{"payload":{"version":1,"agent":"agent-a",'
        '"action_count":0,"total_amount":0,'
        '"denial_count":0,"used_capabilities":[]},'
        '"integrity_hash":"invalid"}',
        encoding="utf-8",
    )

    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    assert (
        restarted.snapshot().total_amount
        == 600
    )


def test_failed_atomic_write_preserves_last_good_state(
    tmp_path,
    monkeypatch,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={"amount": 600},
    )

    original_replace = os.replace

    def fail_replace(*args, **kwargs):
        raise OSError(
            "simulated atomic replace failure"
        )

    monkeypatch.setattr(
        os,
        "replace",
        fail_replace,
    )

    with pytest.raises(SecurityContextError):
        context.authorize_and_record(
            request={"amount": 100},
        )

    monkeypatch.setattr(
        os,
        "replace",
        original_replace,
    )

    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    assert (
        restarted.snapshot().total_amount
        == 600
    )


def test_interrupted_write_does_not_reset_budget(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={"amount": 700},
    )

    temp_path = (
        tmp_path / ".security_context_interrupted.tmp"
    )

    temp_path.write_text(
        '{"payload":{"version":1,',
        encoding="utf-8",
    )

    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    assert (
        restarted.snapshot().total_amount
        == 700
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        restarted.authorize_and_record(
            request={"amount": 400},
        )


def test_persisted_state_remains_integrity_checked_after_recovery(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=1000,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={"amount": 500},
    )

    original = state_path.read_text(
        encoding="utf-8"
    )

    assert original

    # Tamper with the committed state itself.
    state_path.write_text(
        original.replace(
            '"total_amount":500.0',
            '"total_amount":0.0',
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        SecurityContextError
    ):
        SecurityContext(
            agent="agent-a",
            max_total_amount=1000,
            state_path=state_path,
        )


def test_recovery_preserves_exact_budget_boundary(
    tmp_path,
):
    state_path = tmp_path / "security-state.json"

    context = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
        state_path=state_path,
    )

    context.authorize_and_record(
        request={"amount": 99},
    )

    restarted = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
        state_path=state_path,
    )

    with pytest.raises(
        SecurityBudgetExceeded
    ):
        restarted.authorize_and_record(
            request={"amount": 2},
        )

    restarted.authorize_and_record(
        request={"amount": 1},
    )

    assert (
        restarted.snapshot().total_amount
        == 100
    )