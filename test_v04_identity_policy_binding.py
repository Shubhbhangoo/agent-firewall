from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.identity import (
    IdentityVerifier,
    sign_identity,
)
from firewall.engine import Firewall


def make_identity(agent_id):
    private_key = Ed25519PrivateKey.generate()

    return sign_identity(
        private_key,
        agent_id,
        "trusted-issuer",
    )


def make_firewall(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: payments.send
    agent: finance-agent
    amount_gte: 1000
    action: approval

  - tool: payments.send
    agent: finance-agent
    action: allow

  - tool: payments.send
    agent: attacker-agent
    action: deny
""",
        encoding="utf-8",
    )

    return Firewall(
        str(policy_file),
        identity_verifier=IdentityVerifier(
            {"trusted-issuer"}
        ),
    )


def test_verified_finance_identity_gets_finance_policy(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "finance-agent"
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"


def test_verified_finance_identity_gets_amount_policy(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "finance-agent"
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 1500},
    )

    assert result.action == "approval"


def test_attacker_identity_gets_attacker_policy(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "attacker-agent"
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_untrusted_identity_cannot_use_finance_policy(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "finance-agent"
    )

    from firewall.identity import AgentIdentity

    forged = AgentIdentity(
        agent_id=identity.agent_id,
        issuer="evil-issuer",
        public_key=identity.public_key,
        signature=identity.signature,
    )

    result = fw.check(
        forged,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_tampered_identity_cannot_upgrade_permissions(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "finance-agent"
    )

    from firewall.identity import AgentIdentity

    forged = AgentIdentity(
        agent_id="attacker-agent",
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
    )

    result = fw.check(
        forged,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_revoked_finance_identity_loses_policy_access(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "finance-agent"
    )

    fw.identity_verifier.revoke_key(
        identity.public_key
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_retired_finance_identity_loses_policy_access(
    tmp_path,
):
    fw = make_firewall(tmp_path)

    identity = make_identity(
        "finance-agent"
    )

    fw.identity_verifier.retire_key(
        identity.public_key
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"