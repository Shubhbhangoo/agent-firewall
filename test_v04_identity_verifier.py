from dataclasses import dataclass

from firewall.engine import Firewall


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    issuer: str


class IdentityVerifier:
    def __init__(self, trusted_issuers):
        self.trusted_issuers = set(trusted_issuers)

    def verify(self, identity):
        if not isinstance(identity, AgentIdentity):
            return False

        return identity.issuer in self.trusted_issuers


def test_trusted_issuer_verifies_identity():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    assert verifier.verify(identity) is True


def test_untrusted_issuer_rejects_identity():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="evil-issuer",
    )

    assert verifier.verify(identity) is False


def test_unknown_identity_type_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify("finance-agent") is False


def test_empty_issuer_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="",
    )

    assert verifier.verify(identity) is False


def test_verified_identity_uses_agent_id():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    assert verifier.verify(identity) is True
    assert identity.agent_id == "finance-agent"


def test_spoofed_issuer_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="admin-agent",
        issuer="evil-issuer",
    )

    assert verifier.verify(identity) is False