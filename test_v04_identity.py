from dataclasses import dataclass

import pytest

from firewall.engine import Firewall


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    issuer: str
    authenticated: bool = True


def test_identity_must_be_explicit():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="test-issuer",
    )

    assert identity.agent_id == "finance-agent"
    assert identity.issuer == "test-issuer"
    assert identity.authenticated is True


def test_unknown_identity_is_denied():
    identity = AgentIdentity(
        agent_id="unknown-agent",
        issuer="unknown-issuer",
        authenticated=False,
    )

    assert identity.authenticated is False


def test_authenticated_identity_can_match_policy():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="test-issuer",
    )

    policy_agent = "finance-agent"

    assert identity.authenticated is True
    assert identity.agent_id == policy_agent


def test_spoofed_identity_is_not_authenticated():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="untrusted-source",
        authenticated=False,
    )

    assert identity.authenticated is False


def test_identity_is_immutable():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="test-issuer",
    )

    with pytest.raises(AttributeError):
        identity.agent_id = "admin-agent"


def test_identity_fields_are_required():
    with pytest.raises(TypeError):
        AgentIdentity()


def test_unauthenticated_identity_is_denied(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: test.tool
    agent: finance-agent
    action: allow
""",
        encoding="utf-8",
    )

    fw = Firewall(str(policy_file))

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="untrusted-source",
        authenticated=False,
    )

    result = fw.check(
        identity,
        "test.tool",
        {},
    )

    assert result.action == "deny"