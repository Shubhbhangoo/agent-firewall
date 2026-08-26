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


def _canonical_json(
    value: Any,
) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64encode(
    value: bytes,
) -> str:
    return base64.b64encode(
        value
    ).decode("ascii")


def _b64decode(
    value: str,
) -> bytes:
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
    key_id: Optional[str] = None
    tool: Optional[str] = None

    def signing_payload(
        self,
    ) -> bytes:
        payload = {
            "agent_id": self.agent_id,
            "capability": self.capability,
            "constraints": self.constraints,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
        }

        if self.key_id is not None:
            payload["key_id"] = self.key_id

        if self.tool is not None:
            payload["tool"] = self.tool

        return _canonical_json(
            payload
        )

    def to_dict(
        self,
    ) -> Dict[str, Any]:
        result = {
            "agent_id": self.agent_id,
            "capability": self.capability,
            "constraints": self.constraints,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
            "signature": self.signature,
        }

        if self.key_id is not None:
            result["key_id"] = self.key_id

        if self.tool is not None:
            result["tool"] = self.tool

        return result

    def to_json(
        self,
    ) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def sign_capability(
    private_key: Ed25519PrivateKey,
    agent_id: str,
    capability: str,
    constraints: Optional[
        Dict[str, Any]
    ] = None,
    issuer: str = "trusted-issuer",
    expires_at: Optional[float] = None,
    issued_at: Optional[float] = None,
    key_id: Optional[str] = None,
    tool: Optional[str] = None,
) -> Capability:
    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise TypeError(
            "private_key must be an Ed25519PrivateKey"
        )

    if not isinstance(
        agent_id,
        str,
    ) or not agent_id:
        raise ValueError(
            "agent_id must be a non-empty string"
        )

    if not isinstance(
        capability,
        str,
    ) or not capability:
        raise ValueError(
            "capability must be a non-empty string"
        )

    if not isinstance(
        issuer,
        str,
    ) or not issuer:
        raise ValueError(
            "issuer must be a non-empty string"
        )

    if key_id is not None:
        if not isinstance(
            key_id,
            str,
        ):
            raise TypeError(
                "key_id must be a string"
            )

        if not key_id:
            raise ValueError(
                "key_id cannot be empty"
            )

    if tool is not None:
        if not isinstance(
            tool,
            str,
        ):
            raise TypeError(
                "tool must be a string"
            )

        if not tool.strip():
            raise ValueError(
                "tool cannot be empty"
            )

    if constraints is None:
        constraints = {}

    if not isinstance(
        constraints,
        dict,
    ):
        raise TypeError(
            "constraints must be a dictionary"
        )

    if issued_at is None:
        issued_at = time.time()

    if expires_at is None:
        expires_at = issued_at + 3600

    if not isinstance(
        issued_at,
        (int, float),
    ):
        raise TypeError(
            "issued_at must be numeric"
        )

    if not isinstance(
        expires_at,
        (int, float),
    ):
        raise TypeError(
            "expires_at must be numeric"
        )

    if expires_at <= issued_at:
        raise ValueError(
            "expires_at must be later than issued_at"
        )

    public_key = private_key.public_key()

    public_key_bytes = (
        public_key.public_bytes_raw()
    )

    public_key_encoded = _b64encode(
        public_key_bytes
    )

    unsigned = Capability(
        agent_id=agent_id,
        capability=capability,
        constraints=dict(
            constraints
        ),
        issuer=issuer,
        issued_at=float(
            issued_at
        ),
        expires_at=float(
            expires_at
        ),
        public_key=public_key_encoded,
        signature="",
        key_id=key_id,
        tool=tool,
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
        signature=_b64encode(
            signature
        ),
        key_id=unsigned.key_id,
        tool=unsigned.tool,
    )


class CapabilityVerifier:
    def __init__(
        self,
        trusted_issuers=None,
        clock=None,
        trusted_keys=None,
    ):
        self.trusted_issuers = set(
            trusted_issuers or []
        )

        self.clock = (
            clock
            or time.time
        )

        self.trusted_keys = {}

        if trusted_keys:
            for issuer, keys in (
                trusted_keys.items()
            ):
                self.trusted_keys[
                    issuer
                ] = dict(keys)

    def register_key(
        self,
        issuer: str,
        key_id: str,
        public_key: Ed25519PublicKey,
    ) -> None:
        if not isinstance(
            issuer,
            str,
        ) or not issuer:
            raise ValueError(
                "issuer must be a non-empty string"
            )

        if not isinstance(
            key_id,
            str,
        ) or not key_id:
            raise ValueError(
                "key_id must be a non-empty string"
            )

        if not isinstance(
            public_key,
            Ed25519PublicKey,
        ):
            raise TypeError(
                "public_key must be Ed25519PublicKey"
            )

        issuer_keys = (
            self.trusted_keys.setdefault(
                issuer,
                {},
            )
        )

        issuer_keys[
            key_id
        ] = public_key

    def unregister_key(
        self,
        issuer: str,
        key_id: str,
    ) -> None:
        issuer_keys = self.trusted_keys.get(
            issuer
        )

        if issuer_keys is None:
            return

        issuer_keys.pop(
            key_id,
            None,
        )

        if not issuer_keys:
            self.trusted_keys.pop(
                issuer,
                None,
            )

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

        if (
            capability.tool is not None
            and (
                not isinstance(
                    capability.tool,
                    str,
                )
                or not capability.tool.strip()
            )
        ):
            return False

        try:
            now = float(
                self.clock()
            )

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

            if capability.key_id is not None:
                issuer_keys = (
                    self.trusted_keys.get(
                        capability.issuer,
                        {},
                    )
                )

                trusted_public_key = (
                    issuer_keys.get(
                        capability.key_id
                    )
                )

                if trusted_public_key is None:
                    return False

                trusted_bytes = (
                    trusted_public_key.public_bytes_raw()
                )

                if (
                    trusted_bytes
                    != public_key_bytes
                ):
                    return False

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
    payload = (
        capability.signing_payload()
    )

    return hashlib.sha256(
        payload
    ).hexdigest()