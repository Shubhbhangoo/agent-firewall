from firewall.engine import Firewall
from firewall.identity import AgentIdentity, IdentityVerifier


def make_firewall(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
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


def test_trusted_identity_is_allowed(tmp_path):
    fw = make_firewall(tmp_path)

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"


def test_untrusted_issuer_cannot_claim_finance_identity(tmp_path):
    fw = make_firewall(tmp_path)

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="evil-issuer",
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_untrusted_agent_cannot_claim_trusted_agent(tmp_path):
    fw = make_firewall(tmp_path)

    identity = AgentIdentity(
        agent_id="attacker-agent",
        issuer="evil-issuer",
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_unknown_issuer_cannot_use_allowed_policy(tmp_path):
    fw = make_firewall(tmp_path)

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="unknown-issuer",
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_verified_identity_is_matched_by_agent_id(tmp_path):
    fw = make_firewall(tmp_path)

    identity = AgentIdentity(
        agent_id="attacker-agent",
        issuer="trusted-issuer",
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_identity_cannot_change_during_request(tmp_path):
    fw = make_firewall(tmp_path)

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"

    assert identity.agent_id == "finance-agent"
    assert identity.issuer == "trusted-issuer"