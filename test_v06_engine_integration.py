import time

import yaml

from firewall.capability import (
    Capability,
    generate_capability_key_pair,
    sign_capability,
)

from firewall.attenuation import (
    attenuate_capability,
)

from firewall.delegation import (
    delegate_capability,
)

from firewall.engine import Firewall

from firewall.identity import AgentIdentity


def make_policy(tmp_path, rules):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump(
            {"rules": rules}
        ),
        encoding="utf-8",
    )

    return policy


def make_identity(
    agent_id="finance-agent",
    capabilities=None,
):
    return AgentIdentity(
        agent_id=agent_id,
        issuer="trusted-issuer",
        authenticated=True,
        capabilities=frozenset(
            capabilities or set()
        ),
    )


class CapabilityAgent:
    def __init__(
        self,
        agent_id,
        capabilities,
    ):
        self.agent_id = agent_id
        self.issuer = "trusted-issuer"
        self.authenticated = True
        self.capabilities = tuple(
            capabilities
        )


def make_capability(
    private_key,
    **overrides,
):
    now = time.time()

    values = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "constraints": {},
        "issuer": "trusted-issuer",
        "issued_at": now - 10,
        "expires_at": now + 3600,
    }

    values.update(overrides)

    return sign_capability(
        private_key=private_key,
        **values,
    )


# ============================================================
# Basic integration
# ============================================================


def test_capability_object_allows_tool(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        agent_id="finance-agent",
        capability="payments.send",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"


def test_wrong_capability_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.read",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "deny"


def test_expired_capability_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    now = time.time()

    capability = make_capability(
        private_key,
        issued_at=now - 100,
        expires_at=now - 1,
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "deny"


def test_constraint_violation_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 101},
    )

    assert result.action == "deny"


def test_valid_constraint_is_allowed(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"


# ============================================================
# Namespace
# ============================================================


def test_wildcard_capability_allows_child_action(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"


def test_namespace_escalation_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.admin",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.admin",
        {},
    )

    assert result.action == "deny"


def test_other_namespace_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "accounts.read",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "accounts.read",
        {},
    )

    assert result.action == "deny"


# ============================================================
# Attenuation
# ============================================================


def test_attenuated_capability_is_enforced(tmp_path):
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    child = attenuate_capability(
        parent,
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [child],
    )

    allowed = fw.check(
        agent,
        "payments.send",
        {"amount": 100},
    )

    denied = fw.check(
        agent,
        "payments.send",
        {"amount": 101},
    )

    assert allowed.action == "allow"
    assert denied.action == "deny"


def test_attenuated_capability_cannot_expand_scope(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.admin",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.admin",
        {},
    )

    assert result.action == "deny"


# ============================================================
# Delegation
# ============================================================


def test_delegated_capability_authorizes_delegatee(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
        },
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "agent-b",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "agent-b",
        [delegation.child],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"


def test_delegated_constraint_is_enforced(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 100,
        },
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "agent-b",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "agent-b",
        [delegation.child],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 101},
    )

    assert result.action == "deny"


def test_wrong_agent_cannot_use_delegated_capability(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.send",
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "agent-c",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "agent-c",
        [delegation.child],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


# ============================================================
# Tampering
# ============================================================


def test_tampered_capability_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.admin",
        }
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.admin",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [tampered],
    )

    result = fw.check(
        agent,
        "payments.admin",
        {},
    )

    assert result.action == "deny"


def test_tampered_constraint_is_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "constraints": {
                "amount_max": 10000,
            },
        }
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [tampered],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 500},
    )

    assert result.action == "deny"


# ============================================================
# v0.5 compatibility
# ============================================================


def test_string_capabilities_still_work(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={
            "payments.write",
        }
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"


def test_no_v06_capability_preserves_old_behavior(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"


def test_no_capability_denies_when_policy_requires_one(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "deny"


# ============================================================
# Combined controls
# ============================================================


def test_v06_capability_and_budget_both_apply(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 50,
        },
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    first = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    second = fw.check(
        agent,
        "payments.send",
        {"amount": 51},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_v06_capability_and_rate_limit_both_apply(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 1,
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    first = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_v06_capability_and_approval_policy(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            }
        ],
    )

    fw = Firewall(str(policy))

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "approval"

    approved = fw.approve(
        result,
        agent,
    )

    assert approved.action == "allow"