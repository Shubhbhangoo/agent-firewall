from firewall.security_decision import (
    DecisionReason,
    SecurityDecision,
)


def test_allow_decision():
    decision = SecurityDecision.allow(
        capability_id="cap-123",
        agent="agent-a",
        action="read_file",
        tool="filesystem",
    )

    assert decision.allowed is True
    assert decision.reason == DecisionReason.AUTHORIZED
    assert decision.capability_id == "cap-123"
    assert decision.agent == "agent-a"
    assert decision.action == "read_file"
    assert decision.tool == "filesystem"
    assert bool(decision) is True


def test_deny_decision():
    decision = SecurityDecision.deny(
        DecisionReason.REVOKED,
        capability_id="cap-123",
        agent="agent-a",
        action="read_file",
    )

    assert decision.allowed is False
    assert decision.reason == DecisionReason.REVOKED
    assert bool(decision) is False


def test_decision_is_immutable():
    decision = SecurityDecision.allow()

    try:
        decision.allowed = False
    except Exception:
        pass
    else:
        raise AssertionError(
            "SecurityDecision must be immutable"
        )

def test_authorization_result_exposes_security_decision():
    from firewall.authorization import AuthorizationResult

    result = AuthorizationResult(
        allowed=False,
        reason="revoked",
        trace={
            "capability_id": "cap-123",
            "agent": "agent-a",
            "action": "read_file",
            "tool": "filesystem",
        },
    )

    decision = result.decision

    assert isinstance(
        decision,
        SecurityDecision,
    )
    assert decision.allowed is False
    assert decision.reason == "revoked"
    assert decision.capability_id == "cap-123"
    assert decision.agent == "agent-a"
    assert decision.action == "read_file"
    assert decision.tool == "filesystem"

    
def test_metadata_is_optional():
    decision = SecurityDecision.deny(
        DecisionReason.INTERNAL_ERROR
    )

    assert decision.metadata is None