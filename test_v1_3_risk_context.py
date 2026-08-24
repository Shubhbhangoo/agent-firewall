import threading

import pytest

from firewall.risk_context import RiskContext, RiskLevel


def test_new_agent_starts_normal():
    ctx = RiskContext()

    assert ctx.level("agent-a") == RiskLevel.NORMAL
    assert ctx.can_authorize("agent-a")


def test_denials_escalate_agent():
    ctx = RiskContext(elevated_after_denials=3)

    ctx.record_denial("agent-a")
    assert ctx.level("agent-a") == RiskLevel.NORMAL

    ctx.record_denial("agent-a")
    assert ctx.level("agent-a") == RiskLevel.NORMAL

    ctx.record_denial("agent-a")
    assert ctx.level("agent-a") == RiskLevel.ELEVATED


def test_escalation_events_reach_restricted():
    ctx = RiskContext(
        elevated_after_denials=100,
        restricted_after_escalations=3,
    )

    ctx.record_escalation("agent-a")
    assert ctx.level("agent-a") == RiskLevel.ELEVATED

    ctx.record_escalation("agent-a")
    assert ctx.level("agent-a") == RiskLevel.ELEVATED

    ctx.record_escalation("agent-a")
    assert ctx.level("agent-a") == RiskLevel.RESTRICTED


def test_critical_event_revokes_agent():
    ctx = RiskContext()

    ctx.record_critical("agent-a")

    assert ctx.level("agent-a") == RiskLevel.REVOKED
    assert not ctx.can_authorize("agent-a")


def test_risk_never_decreases_automatically():
    ctx = RiskContext(elevated_after_denials=1)

    ctx.record_denial("agent-a")

    assert ctx.level("agent-a") == RiskLevel.ELEVATED

    # Merely reading state must not reduce risk.
    assert ctx.level("agent-a") == RiskLevel.ELEVATED


def test_restricted_never_returns_to_elevated_automatically():
    ctx = RiskContext(restricted_after_escalations=1)

    ctx.record_escalation("agent-a")

    assert ctx.level("agent-a") == RiskLevel.RESTRICTED

    ctx.record_denial("agent-a")

    assert ctx.level("agent-a") == RiskLevel.RESTRICTED


def test_revoked_is_terminal_without_explicit_reset():
    ctx = RiskContext()

    ctx.record_critical("agent-a")

    ctx.record_denial("agent-a")
    ctx.record_escalation("agent-a")

    assert ctx.level("agent-a") == RiskLevel.REVOKED
    assert not ctx.can_authorize("agent-a")


def test_agents_have_isolated_state():
    ctx = RiskContext(elevated_after_denials=1)

    ctx.record_denial("agent-a")

    assert ctx.level("agent-a") == RiskLevel.ELEVATED
    assert ctx.level("agent-b") == RiskLevel.NORMAL


def test_reset_only_affects_selected_agent():
    ctx = RiskContext(elevated_after_denials=1)

    ctx.record_denial("agent-a")
    ctx.record_denial("agent-b")

    ctx.reset("agent-a")

    assert ctx.level("agent-a") == RiskLevel.NORMAL
    assert ctx.level("agent-b") == RiskLevel.ELEVATED


def test_reset_is_explicit_not_automatic():
    ctx = RiskContext(elevated_after_denials=1)

    ctx.record_denial("agent-a")

    assert ctx.level("agent-a") == RiskLevel.ELEVATED

    ctx.reset("agent-a")

    assert ctx.level("agent-a") == RiskLevel.NORMAL


def test_snapshot_contains_runtime_counters():
    ctx = RiskContext(elevated_after_denials=2)

    ctx.record_denial("agent-a")
    ctx.record_escalation("agent-a")

    snapshot = ctx.snapshot("agent-a")

    assert snapshot.agent == "agent-a"
    assert snapshot.level == RiskLevel.ELEVATED
    assert snapshot.event_count == 2
    assert snapshot.denial_count == 1
    assert snapshot.escalation_count == 1


def test_unknown_agent_is_initialized_lazily():
    ctx = RiskContext()

    snapshot = ctx.snapshot("agent-new")

    assert snapshot.level == RiskLevel.NORMAL
    assert snapshot.event_count == 0


def test_empty_agent_is_rejected():
    ctx = RiskContext()

    with pytest.raises(ValueError):
        ctx.level("")


def test_invalid_thresholds_are_rejected():
    with pytest.raises(ValueError):
        RiskContext(elevated_after_denials=0)

    with pytest.raises(ValueError):
        RiskContext(restricted_after_escalations=0)

    with pytest.raises(ValueError):
        RiskContext(revoke_after_critical=0)


def test_concurrent_denials_are_not_lost():
    ctx = RiskContext(elevated_after_denials=100)

    threads = [
        threading.Thread(
            target=lambda: ctx.record_denial("agent-a")
        )
        for _ in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    snapshot = ctx.snapshot("agent-a")

    assert snapshot.event_count == 100
    assert snapshot.denial_count == 100


def test_concurrent_escalations_are_serialized():
    ctx = RiskContext(
        elevated_after_denials=1000,
        restricted_after_escalations=100,
    )

    threads = [
        threading.Thread(
            target=lambda: ctx.record_escalation("agent-a")
        )
        for _ in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    snapshot = ctx.snapshot("agent-a")

    assert snapshot.event_count == 100
    assert snapshot.escalation_count == 100
    assert snapshot.level == RiskLevel.RESTRICTED


def test_revoked_state_survives_concurrent_updates():
    ctx = RiskContext()

    ctx.record_critical("agent-a")

    threads = [
        threading.Thread(
            target=ctx.record_denial,
            args=("agent-a",),
        )
        for _ in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert ctx.level("agent-a") == RiskLevel.REVOKED
    assert not ctx.can_authorize("agent-a")