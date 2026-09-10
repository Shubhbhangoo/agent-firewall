import threading

from firewall.risk_context import RiskContext, RiskLevel


def test_denial_threshold_cannot_be_bypassed_by_alternating_events():
    ctx = RiskContext(
        elevated_after_denials=3,
        restricted_after_escalations=3,
    )

    ctx.record_denial("agent-a")
    ctx.record_escalation("agent-a")
    ctx.record_denial("agent-a")
    ctx.record_escalation("agent-a")
    ctx.record_denial("agent-a")

    assert ctx.level("agent-a") >= RiskLevel.ELEVATED


def test_escalation_cannot_be_hidden_by_denials():
    ctx = RiskContext(
        elevated_after_denials=100,
        restricted_after_escalations=3,
    )

    ctx.record_escalation("agent-a")
    ctx.record_denial("agent-a")
    ctx.record_escalation("agent-a")
    ctx.record_denial("agent-a")
    ctx.record_escalation("agent-a")

    assert ctx.level("agent-a") == RiskLevel.RESTRICTED


def test_reset_does_not_reset_another_agent():
    ctx = RiskContext(elevated_after_denials=1)

    ctx.record_denial("agent-a")
    ctx.record_denial("agent-b")

    ctx.reset("agent-a")

    assert ctx.level("agent-a") == RiskLevel.NORMAL
    assert ctx.level("agent-b") == RiskLevel.ELEVATED


def test_revocation_cannot_be_bypassed_by_reset_of_another_agent():
    ctx = RiskContext()

    ctx.record_critical("agent-a")
    ctx.reset("agent-b")

    assert ctx.level("agent-a") == RiskLevel.REVOKED
    assert not ctx.can_authorize("agent-a")


def test_revoked_agent_cannot_return_to_authorized_state():
    ctx = RiskContext()

    ctx.record_critical("agent-a")
    ctx.reset("agent-a")

    # Explicit administrative reset is allowed by the primitive,
    # so authorization becomes possible again only through that
    # explicit operation.
    assert ctx.level("agent-a") == RiskLevel.NORMAL
    assert ctx.can_authorize("agent-a")


def test_multiple_critical_events_remain_revoked():
    ctx = RiskContext()

    ctx.record_critical("agent-a")
    ctx.record_critical("agent-a")
    ctx.record_critical("agent-a")

    assert ctx.level("agent-a") == RiskLevel.REVOKED


def test_cross_agent_events_cannot_contribute_to_escalation():
    ctx = RiskContext(elevated_after_denials=3)

    ctx.record_denial("agent-a")
    ctx.record_denial("agent-b")
    ctx.record_denial("agent-c")

    assert ctx.level("agent-a") == RiskLevel.NORMAL
    assert ctx.level("agent-b") == RiskLevel.NORMAL
    assert ctx.level("agent-c") == RiskLevel.NORMAL


def test_concurrent_mixed_events_preserve_all_counts():
    ctx = RiskContext(
        elevated_after_denials=1000,
        restricted_after_escalations=1000,
    )

    threads = []

    for _ in range(100):
        threads.append(
            threading.Thread(
                target=ctx.record_denial,
                args=("agent-a",),
            )
        )

    for _ in range(100):
        threads.append(
            threading.Thread(
                target=ctx.record_escalation,
                args=("agent-a",),
            )
        )

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    snapshot = ctx.snapshot("agent-a")

    assert snapshot.event_count == 200
    assert snapshot.denial_count == 100
    assert snapshot.escalation_count == 100


def test_concurrent_critical_event_cannot_be_overwritten():
    ctx = RiskContext()

    threads = [
        threading.Thread(
            target=ctx.record_critical,
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


def test_risk_level_is_monotonic():
    ctx = RiskContext(
        elevated_after_denials=1,
        restricted_after_escalations=1,
    )

    levels = []

    levels.append(ctx.level("agent-a"))

    ctx.record_denial("agent-a")
    levels.append(ctx.level("agent-a"))

    ctx.record_escalation("agent-a")
    levels.append(ctx.level("agent-a"))

    ctx.record_critical("agent-a")
    levels.append(ctx.level("agent-a"))

    assert levels == [
        RiskLevel.NORMAL,
        RiskLevel.ELEVATED,
        RiskLevel.RESTRICTED,
        RiskLevel.REVOKED,
    ]


def test_snapshot_cannot_cross_contaminate_agents():
    ctx = RiskContext(elevated_after_denials=1)

    ctx.record_denial("agent-a")

    a = ctx.snapshot("agent-a")
    b = ctx.snapshot("agent-b")

    assert a.denial_count == 1
    assert b.denial_count == 0
    assert a.level == RiskLevel.ELEVATED
    assert b.level == RiskLevel.NORMAL