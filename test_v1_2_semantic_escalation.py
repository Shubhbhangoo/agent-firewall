from concurrent.futures import ThreadPoolExecutor

import pytest

from firewall.http import HTTPFirewall
from firewall.lifecycle import LifecycleEventType
from firewall.security_context import SecurityContext
from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticRule,
)
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool


PAYMENT_SEQUENCE = (
    "payments.lookup",
    "payments.prepare",
    "payments.send",
)


def protected_rules():
    return (
        SemanticRule(
            outcome="payments.transfer",
            sequence=PAYMENT_SEQUENCE,
            resource_key="account",
            allowed=False,
        ),
    )


def allowed_rules():
    return (
        *protected_rules(),
        SemanticRule(
            outcome="payments.transfer",
            sequence=PAYMENT_SEQUENCE,
            resource_key="account",
            allowed=True,
        ),
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
    sdk.generate_key(
        "semantic-escalation-test"
    )
    return sdk


def make_semantic_context(
    *,
    rules=None,
):
    return SemanticChainContext(
        agent="agent-a",
        rules=(
            protected_rules()
            if rules is None
            else rules
        ),
    )


def issue_payments_capability(sdk):
    return sdk.issue(
        agent="agent-a",
        capability="payments.*",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )


def test_lookup_prepare_send_without_allow_rule_is_denied():
    """
    Attack:
        lookup -> prepare -> send

    Each action is individually authorized, but the complete
    workflow represents a sensitive state transition.
    """

    semantic_context = make_semantic_context()

    sdk = make_sdk(
        semantic_context=semantic_context
    )

    capability = issue_payments_capability(
        sdk
    )

    lookup = sdk.authorize(
        capability,
        "payments.lookup",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout-1",
    )

    prepare = sdk.authorize(
        capability,
        "payments.prepare",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout-1",
    )

    send = sdk.authorize(
        capability,
        "payments.send",
        {
            "account": "target",
            "amount": 100,
        },
        chain_id="checkout-1",
    )

    assert lookup.allowed
    assert prepare.allowed
    assert send.allowed is False
    assert (
        send.reason
        == "semantic_chain_denied"
    )


def test_same_workflow_with_explicit_allow_rule_succeeds():
    sdk = make_sdk(
        semantic_context=make_semantic_context(
            rules=allowed_rules()
        )
    )

    capability = issue_payments_capability(
        sdk
    )

    for action in PAYMENT_SEQUENCE:
        result = sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 100
                if action.endswith(
                    ".send"
                )
                else 0,
            },
            chain_id="checkout-1",
        )

        assert result.allowed


def test_lookup_confirm_send_does_not_satisfy_lookup_prepare_send():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    capability = issue_payments_capability(
        sdk
    )

    path = [
        "payments.lookup",
        "payments.confirm",
        "payments.send",
    ]

    for action in path:
        result = sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 100
                if action.endswith(
                    ".send"
                )
                else 0,
            },
            chain_id="checkout-1",
        )

        assert result.allowed


def test_account_mismatch_does_not_satisfy_account_a_rule():
    rules = (
        SemanticRule(
            outcome="payments.transfer",
            sequence=PAYMENT_SEQUENCE,
            resource_key="account",
            allowed=False,
        ),
        SemanticRule(
            outcome="payments.transfer",
            sequence=PAYMENT_SEQUENCE,
            resource_key="account",
            resource_value="account-a",
            allowed=True,
        ),
    )

    sdk = make_sdk(
        semantic_context=make_semantic_context(
            rules=rules
        )
    )

    capability = issue_payments_capability(
        sdk
    )

    assert sdk.authorize(
        capability,
        "payments.lookup",
        {
            "account": "account-a",
            "amount": 0,
        },
        chain_id="checkout-1",
    ).allowed

    assert sdk.authorize(
        capability,
        "payments.prepare",
        {
            "account": "account-a",
            "amount": 0,
        },
        chain_id="checkout-1",
    ).allowed

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "account": "account-b",
            "amount": 100,
        },
        chain_id="checkout-1",
    )

    assert result.allowed


def test_fresh_nonces_cannot_bypass_semantic_chain_protection():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    capability = issue_payments_capability(
        sdk
    )

    for nonce in (
        "semantic-1",
        "semantic-2",
        "semantic-3",
    ):
        assert sdk.consume_nonce(
            "agent-a",
            capability,
            nonce,
        )

    for action in (
        "payments.lookup",
        "payments.prepare",
    ):
        assert sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 0,
            },
            chain_id="checkout-1",
        ).allowed

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "account": "target",
            "amount": 100,
        },
        chain_id="checkout-1",
    )

    assert result.allowed is False
    assert (
        result.reason
        == "semantic_chain_denied"
    )


def test_different_chain_id_does_not_inherit_previous_state():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    capability = issue_payments_capability(
        sdk
    )

    for action in (
        "payments.lookup",
        "payments.prepare",
    ):
        assert sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 0,
            },
            chain_id="checkout-1",
        ).allowed

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "account": "target",
            "amount": 100,
        },
        chain_id="checkout-2",
    )

    assert result.allowed


def test_resetting_one_chain_leaves_other_chains_intact():
    semantic_context = make_semantic_context()

    sdk = make_sdk(
        semantic_context=semantic_context
    )

    capability = issue_payments_capability(
        sdk
    )

    assert sdk.authorize(
        capability,
        "payments.lookup",
        {
            "account": "a",
            "amount": 0,
        },
        chain_id="chain-a",
    ).allowed

    assert sdk.authorize(
        capability,
        "payments.lookup",
        {
            "account": "b",
            "amount": 0,
        },
        chain_id="chain-b",
    ).allowed

    semantic_context.reset(
        chain_id="chain-a"
    )

    assert semantic_context.snapshot(
        chain_id="chain-a"
    )[0].stages == ()

    assert semantic_context.snapshot(
        chain_id="chain-b"
    )[0].stages == (
        "payments.lookup",
    )


def test_unrelated_action_sequences_remain_allowed():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    capability = issue_payments_capability(
        sdk
    )

    for action in (
        "payments.lookup",
        "payments.refund",
        "payments.send",
    ):
        assert sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 1,
            },
            chain_id="checkout-1",
        ).allowed


def test_capability_swapping_cannot_bypass_semantic_protection():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    lookup_cap = sdk.issue(
        agent="agent-a",
        capability="payments.lookup",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    prepare_cap = sdk.issue(
        agent="agent-a",
        capability="payments.prepare",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    send_cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    assert sdk.authorize(
        lookup_cap,
        "payments.lookup",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout-1",
    ).allowed

    assert sdk.authorize(
        prepare_cap,
        "payments.prepare",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout-1",
    ).allowed

    result = sdk.authorize(
        send_cap,
        "payments.send",
        {
            "account": "target",
            "amount": 100,
        },
        chain_id="checkout-1",
    )

    assert result.allowed is False
    assert (
        result.reason
        == "semantic_chain_denied"
    )


def test_delegated_child_cannot_bypass_semantic_chain_state():
    sdk = FirewallSDK(
        semantic_context=SemanticChainContext(
            agent="agent-b",
            rules=protected_rules(),
        )
    )
    sdk.generate_key(
        "semantic-escalation-test"
    )

    parent = issue_payments_capability(
        sdk
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    assert sdk.authorize(
        child,
        "payments.lookup",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout-1",
    ).allowed

    assert sdk.authorize(
        child,
        "payments.prepare",
        {
            "account": "target",
            "amount": 0,
        },
        chain_id="checkout-1",
    ).allowed

    result = sdk.authorize(
        child,
        "payments.send",
        {
            "account": "target",
            "amount": 100,
        },
        chain_id="checkout-1",
    )

    assert result.allowed is False
    assert (
        result.reason
        == "semantic_chain_denied"
    )


def test_concurrent_terminal_actions_cannot_race_past_guard():
    semantic_context = make_semantic_context()

    sdk = make_sdk(
        semantic_context=semantic_context
    )

    capability = issue_payments_capability(
        sdk
    )

    for action in (
        "payments.lookup",
        "payments.prepare",
    ):
        assert sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 0,
            },
            chain_id="checkout-1",
        ).allowed

    def worker(index):
        return sdk.authorize(
            capability,
            "payments.send",
            {
                "account": "target",
                "amount": index,
            },
            chain_id="checkout-1",
        ).allowed

    with ThreadPoolExecutor(
        max_workers=16
    ) as executor:
        results = list(
            executor.map(
                worker,
                range(1, 33),
            )
        )

    snapshot = semantic_context.snapshot(
        chain_id="checkout-1"
    )[0]

    assert not any(results)
    assert snapshot.stages == (
        "payments.lookup",
        "payments.prepare",
    )
    assert len(snapshot.denied) == 32


def test_semantic_denial_integrates_with_security_context():
    security_context = SecurityContext(
        agent="agent-a",
    )

    sdk = make_sdk(
        semantic_context=make_semantic_context(),
        security_context=security_context,
    )

    capability = issue_payments_capability(
        sdk
    )

    for action in (
        "payments.lookup",
        "payments.prepare",
        "payments.send",
    ):
        sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 100
                if action.endswith(
                    ".send"
                )
                else 0,
            },
            chain_id="checkout-1",
        )

    snapshot = security_context.snapshot()

    assert snapshot.action_count == 2
    assert snapshot.denial_count == 1


def test_semantic_denial_integrates_with_lifecycle_events():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    capability = issue_payments_capability(
        sdk
    )

    for action in (
        "payments.lookup",
        "payments.prepare",
        "payments.send",
    ):
        sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 100
                if action.endswith(
                    ".send"
                )
                else 0,
            },
            chain_id="checkout-1",
        )

    denied = sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert any(
        event.reason
        == "semantic_chain_denied"
        for event in denied
    )


def test_http_firewall_cannot_bypass_semantic_guard():
    rules = (
        SemanticRule(
            outcome="payments.transfer",
            sequence=(
                "http.POST.payments.lookup",
                "http.POST.payments.prepare",
                "http.POST.payments.send",
            ),
            resource_key="account",
            allowed=False,
        ),
    )

    sdk = make_sdk(
        semantic_context=make_semantic_context(
            rules=rules
        )
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="http.POST.payments.*",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    token = sdk.encode(
        capability
    )

    firewall = HTTPFirewall(
        sdk,
        require_nonce=False,
    )

    for path in (
        "/payments/lookup",
        "/payments/prepare",
    ):
        decision = firewall.authorize(
            HTTPFirewall.request(
                agent="agent-a",
                method="POST",
                path=path,
                arguments={
                    "account": "target",
                    "amount": 0,
                },
                capability_token=token,
                nonce="",
                chain_id="checkout-1",
            )
        )

        assert decision.allowed

    decision = firewall.authorize(
        HTTPFirewall.request(
            agent="agent-a",
            method="POST",
            path="/payments/send",
            arguments={
                "account": "target",
                "amount": 100,
            },
            capability_token=token,
            nonce="",
            chain_id="checkout-1",
        )
    )

    assert decision.allowed is False
    assert (
        decision.reason
        == "semantic_chain_denied"
    )


def test_tool_adapter_cannot_bypass_semantic_guard():
    sdk = make_sdk(
        semantic_context=make_semantic_context()
    )

    capability = issue_payments_capability(
        sdk
    )

    def handler(**kwargs):
        return kwargs

    def make_tool(action):
        return ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler=handler,
            action=action,
            request_builder=lambda **kwargs: dict(
                kwargs
            ),
            chain_id="checkout-1",
        )

    make_tool("payments.lookup")(
        account="target",
        amount=0,
    )
    make_tool("payments.prepare")(
        account="target",
        amount=0,
    )

    with pytest.raises(
        PermissionError,
        match="semantic_chain_denied",
    ):
        make_tool("payments.send")(
            account="target",
            amount=100,
        )


def test_existing_behavior_unchanged_without_semantic_context():
    sdk = make_sdk()

    capability = issue_payments_capability(
        sdk
    )

    results = [
        sdk.authorize(
            capability,
            action,
            {
                "account": "target",
                "amount": 100
                if action.endswith(
                    ".send"
                )
                else 0,
            },
        )
        for action in PAYMENT_SEQUENCE
    ]

    assert all(
        result.allowed
        for result in results
    )
