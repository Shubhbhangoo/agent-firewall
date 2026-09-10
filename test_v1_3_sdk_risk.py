import threading

import pytest

from firewall.risk_context import RiskContext, RiskLevel
from firewall.sdk import FirewallSDK


def make_sdk(*, risk_context=None):
    sdk = FirewallSDK(
        risk_context=risk_context,
    )
    sdk.generate_key("test-key")
    return sdk


def make_capability(
    sdk,
    *,
    agent="agent-a",
    action="payments.lookup",
):
    return sdk.issue(
        agent=agent,
        capability=action,
        key_id="test-key",
    )


def make_limited_capability(
    sdk,
    *,
    agent="agent-a",
    action="payments.send",
):
    return sdk.issue(
        agent=agent,
        capability=action,
        key_id="test-key",
        constraints={
            "amount": {
                "max": 100,
            }
        },
    )


def test_without_risk_context_preserves_existing_behavior():
    sdk = make_sdk()

    capability = make_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "A"},
    )

    assert result.allowed


def test_risk_context_is_optional():
    sdk = FirewallSDK()

    assert sdk.get_risk_context() is None


def test_risk_context_can_be_set_and_retrieved():
    sdk = make_sdk()

    context = RiskContext()

    sdk.set_risk_context(context)

    assert sdk.get_risk_context() is context


def test_invalid_risk_context_is_rejected():
    sdk = FirewallSDK()

    with pytest.raises(TypeError):
        sdk.set_risk_context(object())


def test_denied_authorization_records_risk():
    context = RiskContext(
        elevated_after_denials=1,
    )

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_limited_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 999999},
    )

    assert not result.allowed

    snapshot = context.snapshot("agent-a")

    assert snapshot.denial_count == 1
    assert snapshot.event_count == 1
    assert snapshot.level == RiskLevel.ELEVATED


def test_repeated_denials_escalate_risk():
    context = RiskContext(
        elevated_after_denials=2,
    )

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_limited_capability(sdk)

    request = {
        "amount": 999999,
    }

    first = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    assert not first.allowed
    assert not second.allowed

    snapshot = context.snapshot("agent-a")

    assert snapshot.event_count == 2
    assert snapshot.denial_count == 2
    assert snapshot.level == RiskLevel.ELEVATED


def test_revoked_risk_state_fails_closed():
    context = RiskContext()

    context.record_critical("agent-a")

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "A"},
    )

    assert not result.allowed
    assert result.reason == "risk_state_revoked"


def test_revoked_risk_state_blocks_every_action():
    context = RiskContext()

    context.record_critical("agent-a")

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_capability(
        sdk,
        action="payments.lookup",
    )

    for action in (
        "payments.lookup",
        "payments.prepare",
        "payments.send",
    ):
        result = sdk.authorize(
            capability,
            action,
            {"amount": 0},
        )

        assert not result.allowed
        assert result.reason == "risk_state_revoked"


def test_different_agents_have_isolated_risk_state():
    context = RiskContext()

    context.record_critical("agent-a")

    sdk = make_sdk(
        risk_context=context,
    )

    capability_b = make_capability(
        sdk,
        agent="agent-b",
    )

    result = sdk.authorize(
        capability_b,
        "payments.lookup",
        {"account": "B"},
    )

    assert result.allowed

    assert context.level("agent-a") == RiskLevel.REVOKED
    assert context.level("agent-b") == RiskLevel.NORMAL


def test_risk_context_survives_multiple_authorizations():
    context = RiskContext(
        elevated_after_denials=2,
    )

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_limited_capability(sdk)

    request = {
        "amount": 999999,
    }

    first = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    assert not first.allowed
    assert not second.allowed

    snapshot = context.snapshot("agent-a")

    assert snapshot.event_count == 2
    assert snapshot.denial_count == 2
    assert snapshot.level == RiskLevel.ELEVATED


def test_successful_authorization_does_not_change_risk():
    context = RiskContext(
        elevated_after_denials=100,
    )

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "A"},
    )

    assert result.allowed

    snapshot = context.snapshot("agent-a")

    assert snapshot.event_count == 0
    assert snapshot.denial_count == 0
    assert snapshot.escalation_count == 0
    assert snapshot.level == RiskLevel.NORMAL


def test_risk_context_does_not_affect_other_contexts():
    context_a = RiskContext()
    context_b = RiskContext()

    context_a.record_critical("agent-a")

    sdk_a = make_sdk(
        risk_context=context_a,
    )

    sdk_b = make_sdk(
        risk_context=context_b,
    )

    capability_a = make_capability(sdk_a)

    capability_b = make_capability(
        sdk_b,
        agent="agent-b",
    )

    result_a = sdk_a.authorize(
        capability_a,
        "payments.lookup",
        {"account": "A"},
    )

    result_b = sdk_b.authorize(
        capability_b,
        "payments.lookup",
        {"account": "B"},
    )

    assert not result_a.allowed
    assert result_a.reason == "risk_state_revoked"

    assert result_b.allowed


def test_concurrent_revoked_risk_cannot_bypass_gate():
    context = RiskContext()

    context.record_critical("agent-a")

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_capability(sdk)

    results = []
    lock = threading.Lock()

    def authorize():
        result = sdk.authorize(
            capability,
            "payments.lookup",
            {"account": "A"},
        )

        with lock:
            results.append(result)

    threads = [
        threading.Thread(
            target=authorize,
        )
        for _ in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(results) == 50

    assert all(
        not result.allowed
        for result in results
    )

    assert all(
        result.reason == "risk_state_revoked"
        for result in results
    )


def test_explicit_reset_allows_authorization_again():
    context = RiskContext()

    context.record_critical("agent-a")

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_capability(sdk)

    denied = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "A"},
    )

    assert not denied.allowed
    assert denied.reason == "risk_state_revoked"

    context.reset("agent-a")

    allowed = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "A"},
    )

    assert allowed.allowed


def test_risk_gate_happens_before_semantic_chain_state():
    context = RiskContext()

    context.record_critical("agent-a")

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "A"},
        chain_id="chain-1",
    )

    assert not result.allowed
    assert result.reason == "risk_state_revoked"


def test_risk_denial_is_recorded_for_primitive_constraint_failure():
    context = RiskContext(
        elevated_after_denials=1,
    )

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_limited_capability(sdk)

    result = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 101},
    )

    assert not result.allowed

    snapshot = context.snapshot("agent-a")

    assert snapshot.denial_count == 1
    assert snapshot.level == RiskLevel.ELEVATED


def test_risk_state_is_not_shared_between_sdk_instances():
    context_a = RiskContext()
    context_b = RiskContext()

    context_a.record_critical("agent-a")

    sdk_a = make_sdk(
        risk_context=context_a,
    )

    sdk_b = make_sdk(
        risk_context=context_b,
    )

    capability_a = make_capability(sdk_a)

    capability_b = make_capability(
        sdk_b,
        agent="agent-a",
    )

    result_a = sdk_a.authorize(
        capability_a,
        "payments.lookup",
        {"account": "A"},
    )

    result_b = sdk_b.authorize(
        capability_b,
        "payments.lookup",
        {"account": "A"},
    )

    assert not result_a.allowed
    assert result_a.reason == "risk_state_revoked"

    assert result_b.allowed


def test_risk_context_agent_matches_capability_agent():
    context = RiskContext(
        elevated_after_denials=1,
    )

    sdk = make_sdk(
        risk_context=context,
    )

    capability = make_limited_capability(
        sdk,
        agent="agent-a",
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 999999},
    )

    assert not result.allowed

    assert context.snapshot(
        "agent-a"
    ).denial_count == 1

    assert context.snapshot(
        "agent-b"
    ).denial_count == 0