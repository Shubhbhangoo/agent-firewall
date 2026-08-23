from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from firewall.capability import (
    generate_capability_key_pair,
)


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    active: bool = True


class IssuerTrustStore:
    """
    Manages trusted issuer identities.

    Issuer identity is deliberately separate from
    cryptographic capability verification in the current
    capability format.
    """

    def __init__(
        self,
        trusted: Optional[
            set[str]
        ] = None,
    ):
        if trusted is not None and not isinstance(
            trusted,
            (set, frozenset),
        ):
            raise TypeError(
                "trusted issuers must be a set"
            )

        self._trusted = set(
            trusted or ()
        )

        self._revoked: set[str] = set()

        self._lock = RLock()

    def trust(
        self,
        issuer: str,
    ) -> None:
        self._validate_name(
            issuer,
            "issuer",
        )

        with self._lock:
            self._revoked.discard(
                issuer
            )
            self._trusted.add(
                issuer
            )

    def revoke(
        self,
        issuer: str,
    ) -> None:
        self._validate_name(
            issuer,
            "issuer",
        )

        with self._lock:
            self._revoked.add(
                issuer
            )

    def is_trusted(
        self,
        issuer: str,
    ) -> bool:
        self._validate_name(
            issuer,
            "issuer",
        )

        with self._lock:
            return (
                issuer in self._trusted
                and issuer not in self._revoked
            )

    def is_revoked(
        self,
        issuer: str,
    ) -> bool:
        self._validate_name(
            issuer,
            "issuer",
        )

        with self._lock:
            return issuer in self._revoked

    def trusted_issuers(
        self,
    ) -> frozenset[str]:
        with self._lock:
            return frozenset(
                self._trusted
                - self._revoked
            )

    @staticmethod
    def _validate_name(
        value: str,
        field: str,
    ) -> None:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field} must be a string"
            )

        if not value.strip():
            raise ValueError(
                f"{field} cannot be empty"
            )


class CapabilityKeyManager:
    """
    Manages signing-key rotation.

    Every generated key receives a stable key_id.
    Rotation creates a new active key and retires
    the previous key.

    Existing capabilities signed with an old key are
    not automatically revoked. Applications must revoke
    those capabilities explicitly when compromise or
    retirement requires it.
    """

    def __init__(self):
        self._keys: dict[
            str,
            KeyRecord,
        ] = {}

        self._active_key_id: str | None = None

        self._lock = RLock()

    def generate(
        self,
        key_id: str,
    ) -> KeyRecord:
        self._validate_key_id(
            key_id
        )

        with self._lock:
            if key_id in self._keys:
                raise ValueError(
                    f"key already exists: {key_id}"
                )

            private_key, public_key = (
                generate_capability_key_pair()
            )

            record = KeyRecord(
                key_id=key_id,
                private_key=private_key,
                public_key=public_key,
                active=True,
            )

            self._keys[key_id] = record

            if self._active_key_id is None:
                self._active_key_id = key_id

            return record

    def rotate(
        self,
        new_key_id: str,
    ) -> KeyRecord:
        self._validate_key_id(
            new_key_id
        )

        with self._lock:
            if new_key_id in self._keys:
                raise ValueError(
                    f"key already exists: {new_key_id}"
                )

            if self._active_key_id is not None:
                current = self._keys[
                    self._active_key_id
                ]

                self._keys[
                    self._active_key_id
                ] = KeyRecord(
                    key_id=current.key_id,
                    private_key=current.private_key,
                    public_key=current.public_key,
                    active=False,
                )

            private_key, public_key = (
                generate_capability_key_pair()
            )

            record = KeyRecord(
                key_id=new_key_id,
                private_key=private_key,
                public_key=public_key,
                active=True,
            )

            self._keys[new_key_id] = record
            self._active_key_id = new_key_id

            return record

    def get(
        self,
        key_id: str,
    ) -> KeyRecord:
        self._validate_key_id(
            key_id
        )

        with self._lock:
            try:
                return self._keys[
                    key_id
                ]
            except KeyError:
                raise KeyError(
                    f"unknown key: {key_id}"
                ) from None

    def active(
        self,
    ) -> KeyRecord:
        with self._lock:
            if self._active_key_id is None:
                raise RuntimeError(
                    "no active key"
                )

            return self._keys[
                self._active_key_id
            ]

    def retire(
        self,
        key_id: str,
    ) -> None:
        self._validate_key_id(
            key_id
        )

        with self._lock:
            record = self.get(
                key_id
            )

            self._keys[key_id] = (
                KeyRecord(
                    key_id=record.key_id,
                    private_key=record.private_key,
                    public_key=record.public_key,
                    active=False,
                )
            )

            if (
                self._active_key_id
                == key_id
            ):
                self._active_key_id = None

    def is_active(
        self,
        key_id: str,
    ) -> bool:
        return self.get(
            key_id
        ).active

    def key_ids(
        self,
    ) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                self._keys.keys()
            )

    @staticmethod
    def _validate_key_id(
        key_id: str,
    ) -> None:
        if not isinstance(
            key_id,
            str,
        ):
            raise TypeError(
                "key_id must be a string"
            )

        if not key_id.strip():
            raise ValueError(
                "key_id cannot be empty"
            )