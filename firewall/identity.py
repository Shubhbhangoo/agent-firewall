from dataclasses import dataclass


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    issuer: str


class IdentityVerifier:
    def __init__(self, trusted_issuers):
        self.trusted_issuers = frozenset(trusted_issuers)

    def verify(self, identity):
        if not isinstance(identity, AgentIdentity):
            return False

        if not identity.agent_id:
            return False

        if not identity.issuer:
            return False

        return identity.issuer in self.trusted_issuers