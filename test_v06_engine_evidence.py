import json
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


# ============================================================
# Helpers
# ============================================================


def make_policy(tmp_path, rules):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump(
            {"rules": rules}
        ),
        encoding="utf-8",
    )

    return policy


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


def make_firewall(
    tmp_path,
    action="allow",
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": action,
            }
        ],
    )

    return Firewall(str(policy))


# ============================================================
# Evidence existence
# ============================================================


def test_allow_decision_has_evidence(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
        "allow",
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"
    assert result.evidence is not None


def test_deny_decision_has_evidence(
    tmp_path,
):
    fw = make_firewall(
        tmp_path,
        "deny",
    )

    agent = CapabilityAgent(
        "finance-agent",
        [],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"
    assert result.evidence is not None


def test_approval_decision_has_evidence(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
        "approval",
    )

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
    assert result.evidence is not None


# ============================================================
# Evidence identity
# ============================================================


def test_evidence_contains_agent_id(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert (
        result.evidence.agent_id
        == "finance-agent"
    )


def test_evidence_contains_capability(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert (
        result.evidence.capability
        == "payments.send"
    )


# ============================================================
# Namespace evidence
# ============================================================


def test_namespace_allow_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert (
        result.evidence.namespace_match
        is True
    )


def test_namespace_denial_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.read",
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"

    assert (
        result.evidence.namespace_match
        is False
    )


# ============================================================
# Constraint evidence
# ============================================================


def test_constraint_success_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    fw = make_firewall(
        tmp_path,
    )

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

    assert (
        result.evidence.constraints_ok
        is True
    )


def test_constraint_failure_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    fw = make_firewall(
        tmp_path,
    )

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

    assert (
        result.evidence.constraints_ok
        is False
    )


# ============================================================
# Time evidence
# ============================================================


def test_valid_time_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert (
        result.evidence.time_valid
        is True
    )


def test_expired_time_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    now = time.time()

    capability = make_capability(
        private_key,
        issued_at=now - 100,
        expires_at=now - 1,
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"

    assert (
        result.evidence.time_valid
        is False
    )


# ============================================================
# Reason evidence
# ============================================================


def test_allow_reason_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"
    assert result.evidence.reason


def test_deny_reason_is_recorded(
    tmp_path,
):
    fw = make_firewall(
        tmp_path,
        "deny",
    )

    agent = CapabilityAgent(
        "finance-agent",
        [],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"
    assert result.evidence.reason


def test_approval_reason_is_recorded(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
        "approval",
    )

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
    assert result.evidence.reason


# ============================================================
# Request binding
# ============================================================


def test_evidence_request_id_matches_decision(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
        "approval",
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert (
        result.evidence.request_id
        == result.request_id
    )


# ============================================================
# Attenuation evidence
# ============================================================


def test_attenuated_capability_evidence(
    tmp_path,
):
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

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [child],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 50},
    )

    assert result.action == "allow"

    assert (
        result.evidence.capability
        == "payments.*"
    )

    assert (
        result.evidence.constraints_ok
        is True
    )


# ============================================================
# Delegation evidence
# ============================================================


def test_delegated_capability_evidence(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        capability="payments.*",
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    fw_policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "agent-b",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(
        str(fw_policy)
    )

    agent = CapabilityAgent(
        "agent-b",
        [delegation.child],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"

    assert (
        result.evidence.agent_id
        == "agent-b"
    )

    assert (
        result.evidence.capability
        == "payments.*"
    )


# ============================================================
# Tampering evidence
# ============================================================


def test_tampered_capability_evidence(
    tmp_path,
):
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

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [tampered],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"

    assert result.evidence is not None


# ============================================================
# Evidence serialization
# ============================================================


def test_evidence_serializes_to_json(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    decoded = json.loads(
        result.evidence.to_json()
    )

    assert (
        decoded["decision"]
        == result.action
    )


def test_evidence_does_not_contain_private_key(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    encoded = result.evidence.to_json()

    assert (
        "private_key"
        not in encoded
    )


# ============================================================
# Evidence fingerprint
# ============================================================


def test_evidence_has_fingerprint(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_firewall(
        tmp_path,
    )

    agent = CapabilityAgent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    fingerprint = (
        result.evidence.fingerprint()
    )

    assert isinstance(
        fingerprint,
        str,
    )

    assert len(fingerprint) == 64