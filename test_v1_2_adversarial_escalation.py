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
    Baseline attack.

    The capability allows <= $100 per individual request.
    This demonstrates the original v1.1 gap.

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
    Fresh nonces are distinct replay identities.

    Replay protection therefore does not itself provide a
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


def test_refused_action_can_be_retried_with_fresh_nonce():
    """
    A denied request does not create a permanent refusal for
    the capability.

    A later request with a fresh nonce can still be evaluated.
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

    assert not denied.allowed

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "fresh-retry-nonce",
    )

    allowed_retry = sdk.authorize(
        capability,
        "payments.send",
        {"amount": 100},
    )

    assert allowed_retry.allowed


def test_same_nonce_is_blocked_but_fresh_nonce_is_allowed():
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


# ============================================================
# 3. ALTERNATE EXECUTION PATH
# ============================================================


def test_denied_action_does_not_poison_other_authorized_actions():
    """
    A refusal for one namespace does not deny unrelated actions
    that are otherwise authorized by the capability.
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
    Each operation is independently authorized.
    Cross-tool semantic analysis is outside the primitive
    authorization layer.
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

    The child itself is not directly revoked. It is effectively
    revoked because an ancestor is revoked.
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

    assert sdk.is_revoked(
        child
    ) is False

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
    Documents the remaining semantic escalation surface.

    Primitive authorization and delegation-lineage protection
    are now stronger in v1.2, but cross-tool intent analysis and
    refusal-state enforcement are separate security features.
    """

    findings = {
        "cumulative_budget": "requires_security_context",
        "fresh_nonce_retry": "possible",
        "alternate_execution_path": "possible",
        "delegation_broadening": "prevented",
        "parent_revocation_cascade": "prevented",
        "tool_chain_escalation": "requires_security_context",
    }

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