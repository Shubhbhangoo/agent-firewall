from firewall.sdk import FirewallSDK
from firewall.security_context import SecurityContext
from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticRule,
)


def make_sdk():
    semantic = SemanticChainContext(
        agent="agent-a",
        rules=(
            SemanticRule(
                outcome="payments.transfer",
                sequence=(
                    "payments.lookup",
                    "payments.prepare",
                    "payments.send",
                ),
                resource_key="account",
                allowed=True,
            ),
        ),
    )

    security = SecurityContext(
        agent="agent-a",
        max_actions=2,
    )

    sdk = FirewallSDK(
        semantic_context=semantic,
        security_context=security,
    )

    sdk.generate_key("transaction-test")
    return sdk, semantic


def issue(sdk):
    return sdk.issue(
        agent="agent-a",
        capability="payments.*",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )


def test_semantic_state_does_not_commit_when_security_context_rejects():
    sdk, semantic = make_sdk()
    capability = issue(sdk)

    assert sdk.authorize(
        capability,
        "payments.lookup",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout",
    ).allowed

    assert sdk.authorize(
        capability,
        "payments.prepare",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout",
    ).allowed

    # Semantic layer sees the complete sequence, but SecurityContext
    # must reject before the semantic state becomes committed.
    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "account": "target",
            "amount": 100,
        },
        chain_id="checkout",
    )

    assert result.allowed is False

    snapshot = semantic.snapshot(
        chain_id="checkout"
    )[0]

    assert snapshot.stages == (
        "payments.lookup",
        "payments.prepare",
    )