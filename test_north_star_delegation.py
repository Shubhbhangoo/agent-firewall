
from firewall.north_star import (
    AuthorizationPhase,
    DelegationAuthority,
    NorthStarPipeline,
    delegation_phase,
)
from firewall.security_decision import (
    DecisionReason,
    SecurityDecision,
)
from firewall.capability import Capability


def make_capability(
    agent: str,
    capability: str,
) -> Capability:
    return Capability(
    agent_id=agent,
    capability=capability,
    constraints={},
    issuer="trusted-issuer",
    issued_at=0.0,
    expires_at=1000.0,
    public_key="test-public-key",
    signature="test-signature",
)


def test_delegation_authority_is_immutable():
    root = make_capability(
        "root",
        "files.read",
    )
    child = make_capability(
        "child",
        "files.read",
    )

    authority = DelegationAuthority.from_chain(
        (child, root)
    )

    assert authority.requested is child
    assert authority.root is root
    assert authority.depth == 2
    assert len(authority.fingerprints) == 2

    try:
        authority.capabilities += (root,)
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "delegation authority must be immutable"
        )


def test_delegation_phase_publishes_authority():
    root = make_capability(
        "root",
        "files.read",
    )
    child = make_capability(
        "child",
        "files.read",
    )
    seen = {}

    def resolver(capability):
        assert capability is child
        return (child, root)

    phase = delegation_phase(
        resolver
    )

    state = {
        "capability": child,
        "action": "files.read",
    }

    assert phase.evaluator(state) is None

    authority = state[
        "delegation_authority"
    ]

    assert isinstance(
        authority,
        DelegationAuthority,
    )
    assert authority.depth == 2
    seen["root"] = authority.root

    assert seen["root"] is root


def test_delegation_phase_rejects_empty_chain():
    child = make_capability(
        "child",
        "files.read",
    )

    phase = delegation_phase(
        lambda capability: ()
    )

    state = {
        "capability": child,
        "action": "files.read",
    }

    decision = phase.evaluator(state)

    assert decision.allowed is False
    assert decision.reason == (
        "delegation_chain_error"
    )


def test_delegation_phase_rejects_cycle():
    child = make_capability(
        "child",
        "files.read",
    )

    phase = delegation_phase(
        lambda capability: (
            child,
            child,
        )
    )

    decision = phase.evaluator(
        {
            "capability": child,
            "action": "files.read",
        }
    )

    assert decision.allowed is False
    assert decision.reason == (
        "delegation_chain_error"
    )


def test_delegation_phase_rejects_excessive_depth():
    root = make_capability(
        "root",
        "files.read",
    )
    child = make_capability(
        "child",
        "files.read",
    )

    phase = delegation_phase(
        lambda capability: (
            child,
            root,
        ),
        max_depth=1,
    )

    decision = phase.evaluator(
        {
            "capability": child,
            "action": "files.read",
        }
    )

    assert decision.allowed is False
    assert decision.reason == (
        "delegation_depth_exceeded"
    )
    assert decision.metadata[
        "depth"
    ] == 2


def test_delegation_phase_fails_closed_on_resolver_error():
    child = make_capability(
        "child",
        "files.read",
    )

    def broken(capability):
        raise RuntimeError(
            "resolver failed"
        )

    phase = delegation_phase(
        broken
    )

    decision = phase.evaluator(
        {
            "capability": child,
            "action": "files.read",
        }
    )

    assert decision.allowed is False
    assert decision.reason == (
        DecisionReason.INTERNAL_ERROR
    )
    assert decision.metadata[
        "error_type"
    ] == "RuntimeError"


def test_delegation_phase_integrates_with_pipeline():
    root = make_capability(
        "root",
        "files.read",
    )
    child = make_capability(
        "child",
        "files.read",
    )

    def resolver(capability):
        return (child, root)

    pipeline = (
        NorthStarPipeline()
        .add_phase_object(
            delegation_phase(resolver)
        )
        .add_phase(
            "final",
            lambda state: SecurityDecision.allow(
                action=state["action"],
                metadata={
                    "delegation_depth": state[
                        "delegation_authority"
                    ].depth,
                },
            ),
        )
    )

    decision = pipeline.evaluate(
        capability=child,
        action="files.read",
    )

    assert decision.allowed is True
    assert decision.metadata[
        "delegation_depth"
    ] == 2
