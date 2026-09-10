from __future__ import annotations

import time

import yaml

from firewall.capability import (
    capability_fingerprint,
    generate_capability_key_pair,
    sign_capability,
)
from firewall.delegation import delegate_capability
from firewall.delegation_lineage import DelegationLineage
from firewall.engine import Firewall


class CapabilityAgent:
    def __init__(
        self,
        agent_id: str,
        capabilities,
    ):
        self.agent_id = agent_id
        self.issuer = "trusted-issuer"
        self.authenticated = True
        self.capabilities = tuple(capabilities)


def make_policy(
    tmp_path,
    rules,
):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump(
            {"rules": rules}
        ),
        encoding="utf-8",
    )

    return policy


def make_capability(
    private_key,
    **overrides,
):
    now = time.time()

    values = {
        "agent_id": "agent-a",
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


def make_lineage(
    parent,
    child,
):
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint=capability_fingerprint(
            child
        ),
        parent_fingerprint=capability_fingerprint(
            parent
        ),
    )

    return lineage


def test_legacy_firewall_blocks_child_after_parent_revocation(
    tmp_path,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

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

    lineage = make_lineage(
        parent,
        delegation.child,
    )

    fw = Firewall(
        str(policy),
        delegation_lineage=lineage,
    )

    agent = CapabilityAgent(
        "agent-b",
        [delegation.child],
    )

    before = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert before.action == "allow"

    fw.revoke_capability(
        parent
    )

    after = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert after.action == "deny"
    assert after.reason == "capability_revoked"


def test_legacy_firewall_allows_child_before_parent_revocation(
    tmp_path,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

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

    lineage = make_lineage(
        parent,
        delegation.child,
    )

    fw = Firewall(
        str(policy),
        delegation_lineage=lineage,
    )

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


def test_legacy_firewall_blocks_deep_descendant_when_root_revoked(
    tmp_path,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    root = make_capability(
        private_key,
        agent_id="agent-root",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    child = delegate_capability(
        root,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 500,
        },
    ).child

    grandchild = delegate_capability(
        child,
        private_key,
        "agent-c",
        constraints={
            "amount_max": 250,
        },
    ).child

    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint=capability_fingerprint(
            child
        ),
        parent_fingerprint=capability_fingerprint(
            root
        ),
    )

    lineage.register(
        child_fingerprint=capability_fingerprint(
            grandchild
        ),
        parent_fingerprint=capability_fingerprint(
            child
        ),
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

    fw = Firewall(
        str(policy),
        delegation_lineage=lineage,
    )

    agent = CapabilityAgent(
        "agent-c",
        [grandchild],
    )

    before = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert before.action == "allow"

    fw.revoke_capability(
        root
    )

    after = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert after.action == "deny"
    assert after.reason == "capability_revoked"


def test_legacy_firewall_child_revocation_does_not_affect_unrelated_capability(
    tmp_path,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    parent = make_capability(
        private_key,
        agent_id="agent-root",
        capability="payments.*",
        constraints={
            "amount_max": 1000,
        },
    )

    child_a = delegate_capability(
        parent,
        private_key,
        "agent-a",
        constraints={
            "amount_max": 100,
        },
    ).child

    child_b = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 500,
        },
    ).child

    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint=capability_fingerprint(
            child_a
        ),
        parent_fingerprint=capability_fingerprint(
            parent
        ),
    )

    lineage.register(
        child_fingerprint=capability_fingerprint(
            child_b
        ),
        parent_fingerprint=capability_fingerprint(
            parent
        ),
    )

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "agent-a",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "agent-b",
                "action": "allow",
            },
        ],
    )

    fw = Firewall(
        str(policy),
        delegation_lineage=lineage,
    )

    agent_a = CapabilityAgent(
        "agent-a",
        [child_a],
    )

    agent_b = CapabilityAgent(
        "agent-b",
        [child_b],
    )

    fw.revoke_capability(
        child_a
    )

    denied = fw.check(
        agent_a,
        "payments.send",
        {"amount": 50},
    )

    allowed = fw.check(
        agent_b,
        "payments.send",
        {"amount": 50},
    )

    assert denied.action == "deny"
    assert denied.reason == "capability_revoked"

    assert allowed.action == "allow"


def test_legacy_firewall_fails_closed_on_malformed_lineage(
    tmp_path,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key,
        agent_id="agent-b",
        capability="payments.send",
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

    lineage = DelegationLineage()

    fw = Firewall(
        str(policy),
        delegation_lineage=lineage,
    )

    agent = CapabilityAgent(
        "agent-b",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"