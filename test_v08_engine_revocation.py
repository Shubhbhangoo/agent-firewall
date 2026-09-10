import pytest

from firewall.capability import (
    capability_fingerprint,
    generate_capability_key_pair,
    sign_capability,
)

from firewall.engine import Firewall

from firewall.revocation import (
    AlreadyRevokedError,
    RevocationRegistry,
)


class AgentFixture:
    def __init__(
        self,
        agent_id,
        capabilities,
        authenticated=True,
    ):
        self.agent_id = agent_id
        self.capabilities = list(
            capabilities
        )
        self.authenticated = authenticated


def make_capability(
    *,
    agent="finance-agent",
    capability="payments.send",
    constraints=None,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sign_capability(
        private_key=private_key,
        agent_id=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
        issuer="trusted-issuer",
    )


def make_firewall(
    tmp_path,
    *,
    registry=None,
    rules=None,
):
    import yaml

    if rules is None:
        rules = [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ]

    policy_path = (
        tmp_path / "policies.yaml"
    )

    policy_path.write_text(
        yaml.safe_dump(
            {"rules": rules},
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    return Firewall(
        str(policy_path),
        revocation_registry=registry,
    )


# ============================================================
# Registry
# ============================================================


def test_firewall_has_revocation_registry(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    assert isinstance(
        fw.revocation_registry,
        RevocationRegistry,
    )


def test_custom_revocation_registry_is_used(
    tmp_path,
):
    registry = RevocationRegistry()

    fw = make_firewall(
        tmp_path,
        registry=registry,
    )

    assert (
        fw.revocation_registry
        is registry
    )


# ============================================================
# Basic behavior
# ============================================================


def test_active_capability_still_allows(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(tmp_path)

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "allow"


def test_revoked_capability_is_denied(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


def test_revoked_capability_exposes_evidence(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.evidence is not None

    details = getattr(
        decision.evidence,
        "details",
        {},
    )

    assert details.get(
        "revoked"
    ) is True


# ============================================================
# Revocation helpers
# ============================================================


def test_revocation_helper_reports_state(
    tmp_path,
):
    capability = make_capability()

    fw = make_firewall(tmp_path)

    assert not fw.is_capability_revoked(
        capability
    )

    fw.revoke_capability(
        capability
    )

    assert fw.is_capability_revoked(
        capability
    )


def test_revocation_is_idempotency_protected(
    tmp_path,
):
    capability = make_capability()

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        capability
    )

    with pytest.raises(
        AlreadyRevokedError
    ):
        fw.revoke_capability(
            capability
        )


def test_revoke_does_not_mutate_capability(
    tmp_path,
):
    capability = make_capability()

    before = capability.to_dict()

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        capability
    )

    assert (
        capability.to_dict()
        == before
    )


def test_revocation_is_bound_to_fingerprint(
    tmp_path,
):
    first = make_capability(
        capability="payments.send"
    )

    second = make_capability(
        capability="payments.send"
    )

    assert (
        capability_fingerprint(first)
        != capability_fingerprint(second)
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        first
    )

    assert fw.is_capability_revoked(
        first
    )

    assert not fw.is_capability_revoked(
        second
    )


# ============================================================
# Multiple capabilities
# ============================================================


def test_revoked_capability_denied_for_same_agent(
    tmp_path,
):
    capability = make_capability(
        capability="payments.send"
    )

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


def test_revoked_capability_denied_for_wildcard_scope(
    tmp_path,
):
    capability = make_capability(
        capability="payments.*"
    )

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(
        tmp_path,
        rules=[
            {
                "tool": "payments.refund",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.refund",
        {},
    )

    assert decision.action == "deny"


def test_valid_second_capability_can_still_authorize(
    tmp_path,
):
    revoked = make_capability(
        capability="payments.send"
    )

    valid = make_capability(
        capability="payments.send"
    )

    agent = AgentFixture(
        "finance-agent",
        [
            revoked,
            valid,
        ],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        revoked
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "allow"


def test_only_revoked_capabilities_are_denied(
    tmp_path,
):
    first = make_capability(
        capability="payments.send"
    )

    second = make_capability(
        capability="payments.refund"
    )

    agent = AgentFixture(
        "finance-agent",
        [
            first,
            second,
        ],
    )

    fw = make_firewall(
        tmp_path,
        rules=[
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            },
            {
                "tool": "payments.refund",
                "agent": "finance-agent",
                "action": "allow",
            },
        ],
    )

    fw.revoke_capability(
        first
    )

    send = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    refund = fw.check(
        agent,
        "payments.refund",
        {},
    )

    assert send.action == "deny"

    # The engine aggregates capability failures
    # when evaluating multiple capabilities.
    assert (
        send.reason
        == "Capability authorization denied"
    )

    assert refund.action == "allow"


# ============================================================
# Replay
# ============================================================


def test_revoked_capability_does_not_consume_replay_nonce(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.send",
        {
            "amount": 10,
            "nonce": "revoked-nonce",
        },
    )

    assert decision.action == "deny"


def test_active_capability_can_use_replay_nonce(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(tmp_path)

    decision = fw.check(
        agent,
        "payments.send",
        {
            "amount": 10,
            "nonce": "active-nonce",
        },
    )

    assert decision.action == "allow"


# ============================================================
# Policy boundary
# ============================================================


def test_revoked_capability_never_reaches_policy_allow(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(
        tmp_path,
        rules=[
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


# ============================================================
# Approval
# ============================================================


def test_revoked_capability_does_not_create_approval(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(
        tmp_path,
        rules=[
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            }
        ],
    )

    fw.revoke_capability(
        capability
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


def test_capability_revocation_survives_existing_approval(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "finance-agent",
        [capability],
    )

    fw = make_firewall(
        tmp_path,
        rules=[
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            }
        ],
    )

    approval = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert (
        approval.action
        == "approval"
    )

    fw.revoke_capability(
        capability
    )

    approved = fw.approve(
        approval
    )

    assert approved.action == "deny"


# ============================================================
# Legacy compatibility
# ============================================================


def test_legacy_agent_without_v06_capability_still_works(
    tmp_path,
):
    agent = AgentFixture(
        "finance-agent",
        [],
    )

    fw = make_firewall(tmp_path)

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "allow"


# ============================================================
# Agent isolation
# ============================================================


def test_revocation_does_not_cross_agents(
    tmp_path,
):
    first = make_capability(
        agent="agent-a",
        capability="payments.send",
    )

    second = make_capability(
        agent="agent-b",
        capability="payments.send",
    )

    agent_b = AgentFixture(
        "agent-b",
        [second],
    )

    fw = make_firewall(
        tmp_path,
        rules=[
            {
                "tool": "payments.send",
                "agent": "agent-b",
                "action": "allow",
            }
        ],
    )

    fw.revoke_capability(
        first
    )

    decision = fw.check(
        agent_b,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "allow"


# ============================================================
# Reissue behavior
# ============================================================


def test_revoked_old_capability_does_not_revoke_reissue(
    tmp_path,
):
    old = make_capability(
        capability="payments.send"
    )

    new = make_capability(
        capability="payments.send"
    )

    agent = AgentFixture(
        "finance-agent",
        [
            old,
            new,
        ],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(
        old
    )

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "allow"


def test_revoking_both_capabilities_denies(
    tmp_path,
):
    old = make_capability(
        capability="payments.send"
    )

    new = make_capability(
        capability="payments.send"
    )

    agent = AgentFixture(
        "finance-agent",
        [
            old,
            new,
        ],
    )

    fw = make_firewall(tmp_path)

    fw.revoke_capability(old)
    fw.revoke_capability(new)

    decision = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"