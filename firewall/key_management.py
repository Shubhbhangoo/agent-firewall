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

from firewall.key_store import (
    SQLiteKeyStore,
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

    With a SQLiteKeyStore, trust state survives restart.
    Without one, state remains in memory only.
    """

    def __init__(
        self,
        trusted: Optional[set[str]] = None,
        *,
        store: Optional[SQLiteKeyStore] = None,
    ):
        if trusted is not None and not isinstance(
            trusted,
            (set, frozenset),
        ):
            raise TypeError(
                "trusted issuers must be a set"
            )

        self._store = store
        self._lock = RLock()

        persisted = (
            set(store.trusted_issuers())
            if store is not None
            else set()
        )

        self._trusted = (
            set(trusted or ())
            | persisted
        )

        self._revoked: set[str] = set()

    def trust(
        self,
        issuer: str,
    ) -> None:
        self._validate_name(
            issuer,
            "issuer",
        )

        with self._lock:
            if self._store is not None:
                self._store.trust_issuer(
                    issuer
                )

            self._trusted.add(
                issuer
            )

            self._revoked.discard(
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
            if self._store is not None:
                self._store.revoke_issuer(
                    issuer
                )

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
            if self._store is not None:
                return issuer in (
                    self._store.trusted_issuers()
                )

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
            if issuer in self._revoked:
                return True

            if self._store is not None:
                return (
                    issuer in self._trusted
                    and not self.is_trusted(
                        issuer
                    )
                )

            return False

    def trusted_issuers(
        self,
    ) -> frozenset[str]:
        with self._lock:
            if self._store is not None:
                persisted = set(
                    self._store.trusted_issuers()
                )

                return frozenset(
                    (
                        self._trusted
                        | persisted
                    )
                    - self._revoked
                )

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
    Manages capability signing keys.

    With a SQLiteKeyStore, the store is the source of truth.
    The in-memory dictionary is only a cache.

    Without a store, state is entirely in memory.
    """

    def __init__(
        self,
        *,
        store: Optional[SQLiteKeyStore] = None,
    ):
        self._store = store

        self._keys: dict[
            str,
            KeyRecord,
        ] = {}

        self._active_key_id: (
            str | None
        ) = None

        self._lock = RLock()

        self._load_persisted_state()

    # ========================================================
    # Load persisted state
    # ========================================================

    def _load_persisted_state(
        self,
    ) -> None:
        if self._store is None:
            return

        with self._lock:
            persisted_ids = (
                self._store.key_ids()
            )

            for key_id in persisted_ids:
                stored = self._store.get_key(
                    key_id
                )

                record = KeyRecord(
                    key_id=stored.key_id,
                    private_key=stored.private_key,
                    public_key=stored.public_key,
                    active=stored.active,
                )

                if record.active:
                    if (
                        self._active_key_id
                        is not None
                    ):
                        raise RuntimeError(
                            "multiple active keys detected"
                        )

                    self._active_key_id = (
                        record.key_id
                    )

                self._keys[
                    record.key_id
                ] = record

    # ========================================================
    # Generate
    # ========================================================

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

            active = (
                self._active_key_id
                is None
            )

            if self._store is not None:
                stored = self._store.save_key(
                    key_id,
                    private_key,
                    public_key,
                    active=active,
                )

                record = KeyRecord(
                    key_id=stored.key_id,
                    private_key=stored.private_key,
                    public_key=stored.public_key,
                    active=stored.active,
                )

            else:
                record = KeyRecord(
                    key_id=key_id,
                    private_key=private_key,
                    public_key=public_key,
                    active=active,
                )

            self._keys[
                key_id
            ] = record

            if active:
                self._active_key_id = (
                    key_id
                )

            return record

    # ========================================================
    # Rotate
    # ========================================================

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

            private_key, public_key = (
                generate_capability_key_pair()
            )

            old_active_id = (
                self._active_key_id
            )

            if self._store is not None:
                stored = self._store.save_key(
                    new_key_id,
                    private_key,
                    public_key,
                    active=True,
                )

                record = KeyRecord(
                    key_id=stored.key_id,
                    private_key=stored.private_key,
                    public_key=stored.public_key,
                    active=True,
                )

            else:
                record = KeyRecord(
                    key_id=new_key_id,
                    private_key=private_key,
                    public_key=public_key,
                    active=True,
                )

            if old_active_id is not None:
                old_record = self.get(
                    old_active_id
                )

                if self._store is not None:
                    self._store.update_key_state(
                        old_active_id,
                        active=False,
                    )

                self._keys[
                    old_active_id
                ] = KeyRecord(
                    key_id=old_record.key_id,
                    private_key=old_record.private_key,
                    public_key=old_record.public_key,
                    active=False,
                )

            self._keys[
                new_key_id
            ] = record

            self._active_key_id = (
                new_key_id
            )

            return record

    # ========================================================
    # Get
    # ========================================================

    def get(
        self,
        key_id: str,
    ) -> KeyRecord:
        self._validate_key_id(
            key_id
        )

        with self._lock:
            if self._store is not None:
                stored = self._store.get_key(
                    key_id
                )

                record = KeyRecord(
                    key_id=stored.key_id,
                    private_key=stored.private_key,
                    public_key=stored.public_key,
                    active=stored.active,
                )

                self._keys[
                    key_id
                ] = record

                return record

            record = self._keys.get(
                key_id
            )

            if record is None:
                raise KeyError(
                    f"unknown key: {key_id}"
                )

            return record

    # ========================================================
    # Active
    # ========================================================

    def active(
        self,
    ) -> KeyRecord:
        with self._lock:
            if self._store is not None:
                stored = self._store.active_key()

                record = KeyRecord(
                    key_id=stored.key_id,
                    private_key=stored.private_key,
                    public_key=stored.public_key,
                    active=stored.active,
                )

                self._keys[
                    record.key_id
                ] = record

                self._active_key_id = (
                    record.key_id
                )

                return record

            if self._active_key_id is None:
                raise RuntimeError(
                    "no active key"
                )

            return self._keys[
                self._active_key_id
            ]

    # ========================================================
    # Retire
    # ========================================================

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

            if self._store is not None:
                self._store.update_key_state(
                    key_id,
                    active=False,
                )

            self._keys[
                key_id
            ] = KeyRecord(
                key_id=record.key_id,
                private_key=record.private_key,
                public_key=record.public_key,
                active=False,
            )

            if (
                self._active_key_id
                == key_id
            ):
                self._active_key_id = None

    # ========================================================
    # State
    # ========================================================

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
            if self._store is not None:
                ids = self._store.key_ids()

                for key_id in ids:
                    self.get(
                        key_id
                    )

                return ids

            return tuple(
                self._keys.keys()
            )

    @property
    def store(
        self,
    ) -> Optional[
        SQLiteKeyStore
    ]:
        return self._store

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