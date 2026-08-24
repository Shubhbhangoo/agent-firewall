from concurrent.futures import ThreadPoolExecutor

from firewall.sdk import FirewallSDK
from firewall.security_context import SecurityContext
from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticRule,
)


PAYMENT_SEQUENCE = (
    "payments.lookup",
    "payments.prepare",
    "payments.send",
)


def make_sdk(
    *,
    semantic_context=None,
    security_context=None,
):
    sdk = FirewallSDK(
        semantic_context=semantic_context,
        security_context=security_context,
    )
    sdk.generate_key("audit-key")
    return sdk


def make_context(
    *,
    rules=None,
):
    return SemanticChainContext(
        agent="agent-a",
        rules=rules
        or (
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                allowed=False,
            ),
        ),
    )


def make_allowed_context():
    return make_context(
        rules=(
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                allowed=True,
            ),
        ),
    )


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


def authorize(
    sdk,
    capability,
    action,
    *,
    account="target",
    amount=0,
    chain_id="audit-chain",
):
    return sdk.authorize(
        capability,
        action,
        {
            "account": account,
            "amount": amount,
        },
        chain_id=chain_id,
    )


def test_exact_protected_sequence_is_denied():
    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is False
    assert result.reason == "semantic_chain_denied"


def test_explicitly_allowed_workflow_is_allowed():
    sdk = make_sdk(
        semantic_context=make_allowed_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is True


def test_alternate_sequence_does_not_match_protected_sequence():
    """
    The semantic rule is sequence-specific.

    lookup -> confirm -> send is not the configured
    lookup -> prepare -> send workflow.
    """

    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.confirm",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is True


def test_extra_action_breaks_exact_sequence():
    """
    Inserting an unrelated action means the trailing sequence
    no longer equals the protected workflow.
    """

    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.status",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is True


def test_resource_mismatch_does_not_match_protected_sequence():
    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
        account="account-a",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
        account="account-a",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        account="account-b",
        amount=100,
    )

    assert result.allowed is True


def test_different_chain_does_not_inherit_previous_state():
    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
        chain_id="chain-a",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
        chain_id="chain-a",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        chain_id="chain-b",
        amount=100,
    )

    assert result.allowed is True


def test_same_chain_reaches_protected_terminal():
    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    for action in (
        "payments.lookup",
        "payments.prepare",
    ):
        assert authorize(
            sdk,
            capability,
            action,
        ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is False
    assert result.reason == "semantic_chain_denied"


def test_fresh_nonce_does_not_reset_semantic_chain():
    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is False
    assert result.reason == "semantic_chain_denied"

    # A fresh request is still evaluated against the existing
    # semantic chain. It does not erase prior state.
    retry = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert retry.allowed is False
    assert retry.reason == "semantic_chain_denied"


def test_reset_clears_only_selected_chain():
    context = make_context()

    context.authorize_and_record(
        agent="agent-a",
        action="payments.lookup",
        request={"account": "a"},
        capability_fingerprint="cap-a",
        capability="payments.*",
        chain_id="chain-a",
    )

    context.authorize_and_record(
        agent="agent-a",
        action="payments.lookup",
        request={"account": "b"},
        capability_fingerprint="cap-b",
        capability="payments.*",
        chain_id="chain-b",
    )

    context.reset(
        chain_id="chain-a"
    )

    snapshots = {
        snapshot.chain_id: snapshot
        for snapshot in context.snapshot()
    }

    assert "chain-a" not in snapshots
    assert "chain-b" in snapshots


def test_capability_swap_does_not_change_recorded_chain_identity():
    context = make_context()

    context.authorize_and_record(
        agent="agent-a",
        action="payments.lookup",
        request={"account": "target"},
        capability_fingerprint="cap-a",
        capability="payments.*",
        chain_id="chain-a",
    )

    context.authorize_and_record(
        agent="agent-a",
        action="payments.prepare",
        request={"account": "target"},
        capability_fingerprint="cap-b",
        capability="payments.*",
        chain_id="chain-a",
    )

    snapshot = context.snapshot(
        chain_id="chain-a"
    )[0]

    assert snapshot.capability_fingerprints == (
        "cap-a",
        "cap-b",
    )


def test_downstream_security_failure_does_not_commit_semantic_state():
    semantic = make_allowed_context()

    security = SecurityContext(
        agent="agent-a",
        max_actions=2,
    )

    sdk = make_sdk(
        semantic_context=semantic,
        security_context=security,
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
    ).allowed

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is False

    snapshot = semantic.snapshot(
        chain_id="audit-chain"
    )[0]

    assert snapshot.stages == (
        "payments.lookup",
        "payments.prepare",
    )


def test_concurrent_protected_terminal_requests_are_serialized():
    sdk = make_sdk(
        semantic_context=make_context()
    )

    capability = issue(sdk)

    assert authorize(
        sdk,
        capability,
        "payments.lookup",
    ).allowed

    assert authorize(
        sdk,
        capability,
        "payments.prepare",
    ).allowed

    def attempt(_):
        return authorize(
            sdk,
            capability,
            "payments.send",
            amount=100,
        )

    with ThreadPoolExecutor(
        max_workers=16
    ) as executor:
        results = list(
            executor.map(
                attempt,
                range(32),
            )
        )

    assert all(
        result.allowed is False
        for result in results
    )

    assert all(
        result.reason == "semantic_chain_denied"
        for result in results
    )


def test_unconfigured_semantic_context_preserves_existing_behavior():
    sdk = make_sdk()

    capability = issue(sdk)

    result = authorize(
        sdk,
        capability,
        "payments.send",
        amount=100,
    )

    assert result.allowed is True