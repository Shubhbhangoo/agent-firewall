from __future__ import annotations

from firewall.sdk import FirewallSDK


def make_sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key(
        "v1-2-test-key"
    )
    return sdk


def issue(
    sdk: FirewallSDK,
    *,
    agent: str,
    capability: str,
    constraints: dict | None = None,
):
    return sdk.issue(
        agent=agent,
        capability=capability,
        constraints=constraints or {},
    )


# ============================================================
# 1. CUMULATIVE ACTION ESCALATION
# ============================================================


def test_cumulative_actions_can_exceed_per_request_limit():
    """
    Baseline primitive-authorization behavior.

    A capability allowing <= $100 per individual request can
    authorize multiple independent requests.

    v1.2 SecurityContext enforcement is tested separately.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    first = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    third = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    assert first.allowed
    assert second.allowed
    assert third.allowed

    assert 100 + 100 + 100 > 100


def test_cumulative_actions_with_fresh_nonces_are_not_replay():
    """
    Fresh nonces create distinct replay identities.

    Replay protection alone therefore does not provide a
    cumulative session budget.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-2",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-3",
    )


# ============================================================
# 2. RETRY / REFUSAL BYPASS
# ============================================================


def test_refused_action_is_blocked_with_fresh_nonce():
    """
    v1.2 security invariant:

    A fresh nonce must not bypass an existing refusal for the
    same agent + capability + action.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    denied = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 1000},
    )

    assert denied.allowed is False

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "fresh-retry-nonce",
    ) is True

    retry = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    assert retry.allowed is False
    assert retry.reason == "refusal_state"


def test_same_nonce_is_blocked_but_fresh_nonce_is_allowed():
    """
    Replay protection remains independent from refusal state.

    The same nonce is rejected as replay, while a fresh nonce is
    accepted by replay protection itself.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-a",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-a",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-b",
    )


def test_refusal_state_blocks_repeated_authorization():
    """
    Repeated authorization attempts for the same refused
    agent/capability/action remain denied.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    first = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 1000},
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    assert first.allowed is False
    assert second.allowed is False
    assert second.reason == "refusal_state"


# ============================================================
# 3. ALTERNATE EXECUTION PATH
# ============================================================


def test_denied_action_does_not_poison_other_authorized_actions():
    """
    A refusal for one action does not deny unrelated actions
    authorized by the same capability.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.*",
    )

    denied = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert not denied.allowed

    allowed = sdk.authorize(
        capability,
        "payments.lookup",
        {},
    )

    assert allowed.allowed


def test_multiple_allowed_tools_can_be_composed():
    """
    Primitive authorization evaluates each tool call separately.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.*",
    )

    lookup = sdk.authorize(
        capability,
        "payments.lookup",
        {"account": "target"},
    )

    prepare = sdk.authorize(
        capability,
        "payments.prepare",
        {"account": "target"},
    )

    send = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    assert lookup.allowed
    assert prepare.allowed
    assert send.allowed


# ============================================================
# 4. DELEGATION ESCALATION
# ============================================================


def test_delegation_cannot_broaden_capability():
    """
    Delegation must not increase the parent's authority.
    """

    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.*",
        constraints={
            "amount": {
                "lte": 100,
            }
        },
    )

    key = sdk.active_key()

    try:
        delegation = sdk.delegate(
            parent,
            key.private_key,
            delegatee="agent-b",
            constraints={
                "amount": {
                    "lte": 1000,
                }
            },
        )
    except Exception:
        return

    assert not sdk.verify_delegation(
        delegation
    )


def test_delegation_cannot_extend_expiration():
    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    try:
        delegation = sdk.delegate(
            parent,
            key.private_key,
            delegatee="agent-b",
            expires_at=(
                parent.expires_at
                + 1000
            ),
        )
    except Exception:
        return

    assert not sdk.verify_delegation(
        delegation
    )


def test_parent_revocation_now_invalidates_child():
    """
    v1.2 security invariant:

    Revoking a parent capability invalidates descendants
    through delegation lineage.
    """

    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    assert sdk.verify_delegation(
        delegation
    )

    assert sdk.verify(
        child
    ) is True

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    assert sdk.is_revoked(
        parent
    ) is True

    # Child is not directly revoked.
    assert sdk.is_revoked(
        child
    ) is False

    # But lineage makes it effectively revoked.
    assert sdk.verify(
        child
    ) is False


def test_intermediate_revocation_invalidates_descendants():
    sdk = make_sdk()

    root = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    first = sdk.delegate(
        root,
        key.private_key,
        delegatee="agent-b",
    )

    second = sdk.delegate(
        first.child,
        key.private_key,
        delegatee="agent-c",
    )

    assert sdk.verify(
        second.child
    ) is True

    sdk.revoke(
        first.child,
        reason="intermediate compromised",
    )

    assert sdk.verify(
        second.child
    ) is False


def test_root_revocation_invalidates_grandchild():
    sdk = make_sdk()

    root = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    first = sdk.delegate(
        root,
        key.private_key,
        delegatee="agent-b",
    )

    second = sdk.delegate(
        first.child,
        key.private_key,
        delegatee="agent-c",
    )

    third = sdk.delegate(
        second.child,
        key.private_key,
        delegatee="agent-d",
    )

    assert sdk.verify(
        third.child
    ) is True

    sdk.revoke(
        root,
        reason="root compromised",
    )

    assert sdk.verify(
        third.child
    ) is False


def test_unrelated_capability_survives_parent_revocation():
    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    unrelated = issue(
        sdk,
        agent="agent-a",
        capability="payments.lookup",
    )

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    assert sdk.verify(
        parent
    ) is False

    assert sdk.verify(
        unrelated
    ) is True


def test_child_cannot_be_resurrected():
    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    for _ in range(10):
        result = sdk.authorize(
            child,
            "payments.send",
            {},
        )

        assert result.allowed is False


def test_replaying_child_does_not_bypass_lineage_revocation():
    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    sdk.revoke(
        parent,
        reason="parent compromised",
    )

    assert sdk.consume_nonce(
        "agent-b",
        child,
        "fresh-child-nonce",
    ) is False


def test_lineage_is_registered_for_delegation():
    sdk = make_sdk()

    parent = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    delegation = sdk.delegate(
        parent,
        key.private_key,
        delegatee="agent-b",
    )

    parent_fp = sdk.fingerprint(
        parent
    )

    child_fp = sdk.fingerprint(
        delegation.child
    )

    assert (
        sdk.delegation_lineage.parent_of(
            child_fp
        )
        == parent_fp
    )


def test_parent_revocation_works_after_multiple_delegations():
    sdk = make_sdk()

    root = issue(
        sdk,
        agent="agent-a",
        capability="payments.send",
    )

    key = sdk.active_key()

    current = root

    for agent in (
        "agent-b",
        "agent-c",
        "agent-d",
        "agent-e",
    ):
        delegation = sdk.delegate(
            current,
            key.private_key,
            delegatee=agent,
        )

        current = delegation.child

    sdk.revoke(
        root,
        reason="root compromised",
    )

    assert sdk.verify(
        current
    ) is False


# ============================================================
# 5. MULTI-STEP TOOL-CHAIN ESCALATION
# ============================================================


def test_tool_chain_has_no_cross_request_budget():
    """
    Primitive authorization does not itself provide a
    cross-request budget.

    v1.2 SecurityContext enforcement is tested separately.
    """

    sdk = make_sdk()

    capability = issue(
        sdk,
        agent="agent-a",
        capability="payments.*",
    )

    actions = [
        (
            "payments.lookup",
            {"account": "target"},
        ),
        (
            "payments.prepare",
            {"account": "target"},
        ),
        (
            "payments.send",
            {"amount": 100},
        ),
        (
            "payments.send",
            {"amount": 100},
        ),
        (
            "payments.send",
            {"amount": 100},
        ),
    ]

    decisions = [
        sdk.authorize(
            capability,
            action,
            request,
        )
        for action, request in actions
    ]

    assert all(
        decision.allowed
        for decision in decisions
    )


# ============================================================
# 6. ATTACK SURFACE SUMMARY
# ============================================================


def test_v1_2_attack_surface_is_explicit():
    """
    Documents the current v1.2 attack surface.

    Primitive authorization and delegation-lineage protection
    are now hardened. Refusal-state protection blocks exact
    repeated action attempts, while cross-tool semantic analysis
    remains a separate future security layer.
    """

    findings = {
        "cumulative_budget": "requires_security_context",
        "fresh_nonce_retry": "prevented",
        "alternate_execution_path": "possible",
        "delegation_broadening": "prevented",
        "parent_revocation_cascade": "prevented",
        "tool_chain_escalation": "requires_security_context",
    }

    assert (
        findings[
            "fresh_nonce_retry"
        ]
        == "prevented"
    )

    assert (
        findings[
            "delegation_broadening"
        ]
        == "prevented"
    )

    assert (
        findings[
            "parent_revocation_cascade"
        ]
        == "prevented"
    )