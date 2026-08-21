import yaml

from firewall.engine import Firewall
from firewall.identity import (
    AgentIdentity,
    IdentityVerifier,
    generate_key_pair,
    sign_identity,
)


def make_policy(tmp_path, rules):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return policy


def make_identity(
    agent_id="finance-agent",
    capabilities=(),
):
    return AgentIdentity(
        agent_id=agent_id,
        issuer="trusted-issuer",
        authenticated=True,
        capabilities=frozenset(capabilities),
    )


def test_capability_allows_tool(tmp_path):
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
        capabilities={"payments.write"}
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"


def test_missing_capability_denies_tool(tmp_path):
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
        {"amount": 10},
    )

    assert result.action == "deny"


def test_wrong_capability_denies_tool(tmp_path):
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
        capabilities={"payments.read"}
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_multiple_capabilities_are_required(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capabilities": [
                    "payments.write",
                    "payments.approve",
                ],
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={"payments.write"}
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_all_required_capabilities_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capabilities": [
                    "payments.write",
                    "payments.approve",
                ],
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={
            "payments.write",
            "payments.approve",
        }
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"


def test_unknown_capability_does_not_grant_access(
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

    identity = make_identity(
        capabilities={
            "admin",
            "root",
            "payments.read",
        }
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_capability_is_bound_to_agent(
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

    identity = make_identity(
        agent_id="attacker-agent",
        capabilities={"payments.write"},
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_capability_does_not_override_deny(
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
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={"payments.write"}
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_signed_identity_includes_capabilities():
    private_key, _ = generate_key_pair()

    identity = sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
        capabilities={
            "payments.write",
        },
    )

    assert "payments.write" in identity.capabilities


def test_capability_tampering_invalidates_signature():
    private_key, _ = generate_key_pair()

    identity = sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
        capabilities={
            "payments.write",
        },
    )

    tampered = AgentIdentity(
        agent_id=identity.agent_id,
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
        authenticated=True,
        capabilities=frozenset(
            {"payments.admin"}
        ),
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(
        tampered
    ) is False


def test_added_capability_invalidates_signature():
    private_key, _ = generate_key_pair()

    identity = sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
        capabilities={
            "payments.write",
        },
    )

    tampered = AgentIdentity(
        agent_id=identity.agent_id,
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
        authenticated=True,
        capabilities=frozenset(
            {
                "payments.write",
                "payments.admin",
            }
        ),
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(
        tampered
    ) is False


def test_removed_capability_invalidates_signature():
    private_key, _ = generate_key_pair()

    identity = sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
        capabilities={
            "payments.write",
            "payments.approve",
        },
    )

    tampered = AgentIdentity(
        agent_id=identity.agent_id,
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
        authenticated=True,
        capabilities=frozenset(
            {"payments.write"}
        ),
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(
        tampered
    ) is False


def test_capability_order_does_not_change_signature():
    private_key, _ = generate_key_pair()

    identity_a = sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
        capabilities=[
            "payments.write",
            "payments.approve",
        ],
    )

    identity_b = sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
        capabilities=[
            "payments.approve",
            "payments.write",
        ],
    )

    assert identity_a.payload() == identity_b.payload()