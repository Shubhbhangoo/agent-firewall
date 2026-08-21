import base64
import json

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    issuer: str
    public_key: str = ""
    signature: str = ""

    def payload(self):
        return json.dumps(
            {
                "agent_id": self.agent_id,
                "issuer": self.issuer,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


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

        if identity.issuer not in self.trusted_issuers:
            return False

        if not identity.public_key:
            return False

        if not identity.signature:
            return False

        try:
            public_key_bytes = base64.b64decode(
                identity.public_key,
                validate=True,
            )

            signature_bytes = base64.b64decode(
                identity.signature,
                validate=True,
            )

            public_key = Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )

            public_key.verify(
                signature_bytes,
                identity.payload(),
            )

            return True

        except (
            ValueError,
            TypeError,
            InvalidSignature,
        ):
            return False


def generate_key_pair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def sign_identity(
    private_key,
    agent_id,
    issuer,
):
    identity = AgentIdentity(
        agent_id=agent_id,
        issuer=issuer,
    )

    signature = private_key.sign(
        identity.payload()
    )

    public_key = private_key.public_key()

    return AgentIdentity(
        agent_id=agent_id,
        issuer=issuer,
        public_key=base64.b64encode(
            public_key.public_bytes_raw()
        ).decode("ascii"),
        signature=base64.b64encode(
            signature
        ).decode("ascii"),
    )