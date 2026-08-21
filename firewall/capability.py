from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(
        value.encode("ascii"),
        validate=True,
    )


@dataclass(frozen=True)
class Capability:
    agent_id: str
    capability: str
    constraints: Dict[str, Any]
    issuer: str
    issued_at: float
    expires_at: float
    public_key: str
    signature: str

    def signing_payload(self) -> bytes:
        return _canonical_json(
            {
                "agent_id": self.agent_id,
                "capability": self.capability,
                "constraints": self.constraints,
                "issuer": self.issuer,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
                "public_key": self.public_key,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capability": self.capability,
            "constraints": self.constraints,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def sign_capability(
    private_key: Ed25519PrivateKey,
    agent_id: str,
    capability: str,
    constraints: Optional[Dict[str, Any]] = None,
    issuer: str = "trusted-issuer",
    expires_at: Optional[float] = None,
    issued_at: Optional[float] = None,
) -> Capability:

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise TypeError(
            "private_key must be an Ed25519PrivateKey"
        )

    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError(
            "agent_id must be a non-empty string"
        )

    if not isinstance(capability, str) or not capability:
        raise ValueError(
            "capability must be a non-empty string"
        )

    if not isinstance(issuer, str) or not issuer:
        raise ValueError(
            "issuer must be a non-empty string"
        )

    if constraints is None:
        constraints = {}

    if not isinstance(constraints, dict):
        raise TypeError(
            "constraints must be a dictionary"
        )

    if issued_at is None:
        issued_at = time.time()

    if expires_at is None:
        expires_at = issued_at + 3600

    if not isinstance(issued_at, (int, float)):
        raise TypeError(
            "issued_at must be numeric"
        )

    if not isinstance(expires_at, (int, float)):
        raise TypeError(
            "expires_at must be numeric"
        )

    if expires_at <= issued_at:
        raise ValueError(
            "expires_at must be later than issued_at"
        )

    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes_raw()

    public_key_encoded = _b64encode(
        public_key_bytes
    )

    unsigned = Capability(
        agent_id=agent_id,
        capability=capability,
        constraints=dict(constraints),
        issuer=issuer,
        issued_at=float(issued_at),
        expires_at=float(expires_at),
        public_key=public_key_encoded,
        signature="",
    )

    signature = private_key.sign(
        unsigned.signing_payload()
    )

    return Capability(
        agent_id=unsigned.agent_id,
        capability=unsigned.capability,
        constraints=unsigned.constraints,
        issuer=unsigned.issuer,
        issued_at=unsigned.issued_at,
        expires_at=unsigned.expires_at,
        public_key=unsigned.public_key,
        signature=_b64encode(signature),
    )


class CapabilityVerifier:

    def __init__(
        self,
        trusted_issuers=None,
        clock=None,
    ):
        self.trusted_issuers = set(
            trusted_issuers or []
        )

        self.clock = clock or time.time

    def verify(
        self,
        capability: Capability,
    ) -> bool:

        if not isinstance(
            capability,
            Capability,
        ):
            return False

        if not capability.agent_id:
            return False

        if not capability.capability:
            return False

        if not capability.issuer:
            return False

        if (
            self.trusted_issuers
            and capability.issuer
            not in self.trusted_issuers
        ):
            return False

        if not isinstance(
            capability.constraints,
            dict,
        ):
            return False

        try:

            now = float(self.clock())

            if now < capability.issued_at:
                return False

            if now >= capability.expires_at:
                return False

            public_key_bytes = _b64decode(
                capability.public_key
            )

            signature_bytes = _b64decode(
                capability.signature
            )

            if len(public_key_bytes) != 32:
                return False

            if len(signature_bytes) != 64:
                return False

            public_key = (
                Ed25519PublicKey.from_public_bytes(
                    public_key_bytes
                )
            )

            public_key.verify(
                signature_bytes,
                capability.signing_payload(),
            )

            return True

        except (
            ValueError,
            TypeError,
            InvalidSignature,
        ):
            return False


def generate_capability_key_pair():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    return (
        private_key,
        private_key.public_key(),
    )


def capability_fingerprint(
    capability: Capability,
) -> str:

    payload = capability.signing_payload()

    return hashlib.sha256(
        payload
    ).hexdigest()