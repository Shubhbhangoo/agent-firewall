from firewall.north_star import (
    AuthorizationPhase,
    NorthStarPipeline,
)
from firewall.security_decision import (
    DecisionReason,
)


def test_empty_pipeline_allows():
    pipeline = NorthStarPipeline()

    decision = pipeline.evaluate(
        capability=None,
        action="read_file",
    )

    assert decision.allowed is True
    assert decision.reason == DecisionReason.AUTHORIZED


def test_pipeline_stops_at_first_denial():
    calls = []

    def first(state):
        calls.append("first")
        return None

    def second(state):
        calls.append("second")
        return SecurityDecision.deny(
            DecisionReason.REVOKED,
            action=state["action"],
        )

    def third(state):
        calls.append("third")
        return SecurityDecision.allow(
            action=state["action"],
        )

    from firewall.security_decision import SecurityDecision

    pipeline = NorthStarPipeline(
        phases=(
            AuthorizationPhase("first", first),
            AuthorizationPhase("second", second),
            AuthorizationPhase("third", third),
        )
    )

    decision = pipeline.evaluate(
        capability=None,
        action="read_file",
    )

    assert decision.allowed is False
    assert decision.reason == DecisionReason.REVOKED
    assert calls == ["first", "second"]


def test_pipeline_preserves_state():
    seen = {}

    def phase(state):
        seen.update(state)
        return SecurityDecision.deny(
            DecisionReason.CONSTRAINT_DENIED,
            action=state["action"],
        )

    from firewall.security_decision import SecurityDecision

    pipeline = NorthStarPipeline(
        phases=(
            AuthorizationPhase("constraints", phase),
        )
    )

    pipeline.evaluate(
        capability="capability",
        action="pay",
        request={"amount": 100},
        context={"agent": "agent-a"},
    )

    assert seen["capability"] == "capability"
    assert seen["action"] == "pay"
    assert seen["request"] == {"amount": 100}
    assert seen["agent"] == "agent-a"


def test_pipeline_fails_closed_on_phase_error():
    def broken(state):
        raise RuntimeError("boom")

    pipeline = NorthStarPipeline(
        phases=(
            AuthorizationPhase("broken", broken),
        )
    )

    decision = pipeline.evaluate(
        capability=None,
        action="execute",
    )

    assert decision.allowed is False
    assert decision.reason == DecisionReason.INTERNAL_ERROR
    assert decision.metadata["phase"] == "broken"
    assert decision.metadata["error_type"] == "RuntimeError"


def test_phase_validation():
    pipeline = NorthStarPipeline()

    try:
        pipeline.add_phase("", lambda state: None)
    except ValueError:
        pass
    else:
        raise AssertionError("empty phase name must fail")

    try:
        pipeline.add_phase("test", None)
    except TypeError:
        pass
    else:
        raise AssertionError("non-callable evaluator must fail")