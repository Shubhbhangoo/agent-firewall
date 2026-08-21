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

    def __init__(
        self,
        trusted_issuers,
        revocation_file=None,
    ):
        self.trusted_issuers = frozenset(
            trusted_issuers
        )

        self.revocation_file = revocation_file
        self.revoked_keys = set()

        self._load_revocations()

    def _load_revocations(self):
        if not self.revocation_file:
            return

        try:
            with open(
                self.revocation_file,
                "r",
                encoding="utf-8",
            ) as f:
                data = json.load(f)

            if not isinstance(data, list):
                self.revoked_keys = set()
                return

            self.revoked_keys = {
                key
                for key in data
                if isinstance(key, str)
            }

        except FileNotFoundError:
            self.revoked_keys = set()

        except (
            OSError,
            json.JSONDecodeError,
        ):
            self.revoked_keys = set()

    def _save_revocations(self):
        if not self.revocation_file:
            return

        with open(
            self.revocation_file,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                sorted(self.revoked_keys),
                f,
                indent=2,
            )

    def revoke_key(self, public_key):
        self.revoked_keys.add(public_key)
        self._save_revocations()

    def unrevoke_key(self, public_key):
        self.revoked_keys.discard(public_key)
        self._save_revocations()

    def verify(self, identity):

        if not isinstance(
            identity,
            AgentIdentity,
        ):
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

        if identity.public_key in self.revoked_keys:
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

            public_key = (
                Ed25519PublicKey.from_public_bytes(
                    public_key_bytes
                )
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

    private_key = (
        Ed25519PrivateKey.generate()
    )

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