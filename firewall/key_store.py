from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyStoreError(Exception):
    """Base persistent key-store error."""


class KeyStoreCorruptionError(KeyStoreError):
    """Raised when persisted security state is malformed or truncated."""


class KeyStoreCryptoError(KeyStoreError):
    """Raised when encrypted key material cannot be decrypted."""


@dataclass(frozen=True)
class StoredKey:
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    active: bool


class SQLiteKeyStore:
    """
    Persistent signing-key and issuer-trust store.

    Private Ed25519 key material is encrypted at rest with
    AES-256-GCM.

    The master key is supplied by the caller and is never
    persisted by this store.
    """

    NONCE_SIZE = 12
    MASTER_KEY_SIZE = 32

    def __init__(
        self,
        path: str | Path,
        *,
        master_key: bytes,
    ):
        self.path = str(path)

        if not isinstance(master_key, bytes):
            raise TypeError(
                "master_key must be bytes"
            )

        if len(master_key) != self.MASTER_KEY_SIZE:
            raise ValueError(
                "master_key must be exactly 32 bytes"
            )

        self._master_key = bytes(master_key)
        self._lock = RLock()
        self._connection: sqlite3.Connection | None = None

        try:
            self._connection = sqlite3.connect(
                self.path,
                check_same_thread=False,
            )

            self._connection.execute(
                "PRAGMA foreign_keys = ON"
            )
            self._connection.execute(
                "PRAGMA journal_mode = WAL"
            )
            self._connection.execute(
                "PRAGMA synchronous = FULL"
            )

            self._initialize()

        except Exception as exc:
            try:
                if self._connection is not None:
                    self._connection.close()
            except Exception:
                pass

            self._connection = None

            if isinstance(
                exc,
                KeyStoreError,
            ):
                raise

            raise KeyStoreError(
                "failed to initialize key store"
            ) from exc

    # ========================================================
    # Connection
    # ========================================================

    def _require_connection(
        self,
    ) -> sqlite3.Connection:
        if self._connection is None:
            raise KeyStoreError(
                "key store is closed"
            )

        return self._connection

    # ========================================================
    # Initialization
    # ========================================================

    def _initialize(self) -> None:
        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS keys (
                        key_id TEXT PRIMARY KEY,
                        private_key BLOB NOT NULL,
                        public_key BLOB NOT NULL,
                        active INTEGER NOT NULL
                            CHECK(active IN (0, 1))
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS trusted_issuers (
                        issuer TEXT PRIMARY KEY
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS revoked_issuers (
                        issuer TEXT PRIMARY KEY
                    )
                    """
                )

                connection.commit()

            except sqlite3.DatabaseError as exc:
                connection.rollback()

                raise KeyStoreError(
                    "failed to initialize key store"
                ) from exc

    # ========================================================
    # Validation
    # ========================================================

    @staticmethod
    def _validate_key_id(
        key_id: str,
    ) -> str:
        if not isinstance(
            key_id,
            str,
        ):
            raise TypeError(
                "key_id must be a string"
            )

        key_id = key_id.strip()

        if not key_id:
            raise ValueError(
                "key_id cannot be empty"
            )

        return key_id

    @staticmethod
    def _validate_issuer(
        issuer: str,
    ) -> str:
        if not isinstance(
            issuer,
            str,
        ):
            raise TypeError(
                "issuer must be a string"
            )

        issuer = issuer.strip()

        if not issuer:
            raise ValueError(
                "issuer cannot be empty"
            )

        return issuer

    # ========================================================
    # Serialization
    # ========================================================

    @staticmethod
    def _private_bytes(
        private_key: Ed25519PrivateKey,
    ) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def _public_bytes(
        public_key: Ed25519PublicKey,
    ) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # ========================================================
    # Encryption
    # ========================================================

    def _encrypt(
        self,
        key_id: str,
        private_key: Ed25519PrivateKey,
    ) -> bytes:
        plaintext = self._private_bytes(
            private_key
        )

        nonce = os.urandom(
            self.NONCE_SIZE
        )

        ciphertext = AESGCM(
            self._master_key
        ).encrypt(
            nonce,
            plaintext,
            key_id.encode("utf-8"),
        )

        return nonce + ciphertext

    def _decrypt(
        self,
        key_id: str,
        encrypted: bytes,
    ) -> Ed25519PrivateKey:
        if not isinstance(
            encrypted,
            bytes,
        ):
            raise KeyStoreCorruptionError(
                "encrypted key material is not bytes"
            )

        if len(encrypted) <= self.NONCE_SIZE:
            raise KeyStoreCorruptionError(
                "encrypted key material is truncated"
            )

        nonce = encrypted[
            : self.NONCE_SIZE
        ]

        ciphertext = encrypted[
            self.NONCE_SIZE:
        ]

        try:
            plaintext = AESGCM(
                self._master_key
            ).decrypt(
                nonce,
                ciphertext,
                key_id.encode("utf-8"),
            )

        except InvalidTag as exc:
            raise KeyStoreCryptoError(
                f"failed to decrypt key: {key_id}"
            ) from exc

        except Exception as exc:
            raise KeyStoreCryptoError(
                f"failed to decrypt key: {key_id}"
            ) from exc

        try:
            return (
                Ed25519PrivateKey.from_private_bytes(
                    plaintext
                )
            )

        except Exception as exc:
            raise KeyStoreCorruptionError(
                f"decrypted private key is invalid: {key_id}"
            ) from exc

    # ========================================================
    # Save key
    # ========================================================

    def save_key(
        self,
        key_id: str,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        *,
        active: bool,
    ) -> StoredKey:
        key_id = self._validate_key_id(
            key_id
        )

        if not isinstance(
            private_key,
            Ed25519PrivateKey,
        ):
            raise TypeError(
                "private_key must be Ed25519PrivateKey"
            )

        if not isinstance(
            public_key,
            Ed25519PublicKey,
        ):
            raise TypeError(
                "public_key must be Ed25519PublicKey"
            )

        encrypted_private = self._encrypt(
            key_id,
            private_key,
        )

        public_bytes = self._public_bytes(
            public_key
        )

        connection = self._require_connection()

        with self._lock:
            try:
                if active:
                    connection.execute(
                        """
                        UPDATE keys
                        SET active = 0
                        WHERE active = 1
                        """
                    )

                connection.execute(
                    """
                    INSERT INTO keys (
                        key_id,
                        private_key,
                        public_key,
                        active
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        encrypted_private,
                        public_bytes,
                        int(active),
                    ),
                )

                connection.commit()

            except sqlite3.IntegrityError as exc:
                connection.rollback()

                raise KeyStoreError(
                    f"key already exists: {key_id}"
                ) from exc

            except sqlite3.DatabaseError as exc:
                connection.rollback()

                raise KeyStoreError(
                    "failed to persist key"
                ) from exc

        return StoredKey(
            key_id=key_id,
            private_key=private_key,
            public_key=public_key,
            active=bool(active),
        )

    # ========================================================
    # Update key state
    # ========================================================

    def update_key_state(
        self,
        key_id: str,
        *,
        active: bool,
    ) -> None:
        key_id = self._validate_key_id(
            key_id
        )

        connection = self._require_connection()

        with self._lock:
            try:
                cursor = connection.execute(
                    """
                    UPDATE keys
                    SET active = ?
                    WHERE key_id = ?
                    """,
                    (
                        int(active),
                        key_id,
                    ),
                )

                if cursor.rowcount != 1:
                    connection.rollback()

                    raise KeyStoreError(
                        f"unknown key: {key_id}"
                    )

                connection.commit()

            except KeyStoreError:
                raise

            except sqlite3.DatabaseError as exc:
                connection.rollback()

                raise KeyStoreError(
                    "failed to update key state"
                ) from exc

    # ========================================================
    # Get key
    # ========================================================

    def get_key(
        self,
        key_id: str,
    ) -> StoredKey:
        key_id = self._validate_key_id(
            key_id
        )

        connection = self._require_connection()

        with self._lock:
            try:
                row = connection.execute(
                    """
                    SELECT
                        key_id,
                        private_key,
                        public_key,
                        active
                    FROM keys
                    WHERE key_id = ?
                    """,
                    (key_id,),
                ).fetchone()

            except sqlite3.DatabaseError as exc:
                raise KeyStoreError(
                    "failed to read key store"
                ) from exc

        if row is None:
            raise KeyError(
                f"unknown key: {key_id}"
            )

        stored_key_id = str(
            row[0]
        )

        private_key = self._decrypt(
            stored_key_id,
            bytes(row[1]),
        )

        try:
            public_key = (
                Ed25519PublicKey.from_public_bytes(
                    bytes(row[2])
                )
            )

        except Exception as exc:
            raise KeyStoreCorruptionError(
                f"invalid public key: {key_id}"
            ) from exc

        derived_public = (
            private_key.public_key()
        )

        if (
            self._public_bytes(
                derived_public
            )
            != self._public_bytes(
                public_key
            )
        ):
            raise KeyStoreCorruptionError(
                f"private/public key mismatch: {key_id}"
            )

        return StoredKey(
            key_id=stored_key_id,
            private_key=private_key,
            public_key=public_key,
            active=bool(row[3]),
        )

    # ========================================================
    # Active key
    # ========================================================

    def active_key(
        self,
    ) -> StoredKey:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT key_id
                    FROM keys
                    WHERE active = 1
                    ORDER BY key_id
                    """
                ).fetchall()

            except sqlite3.DatabaseError as exc:
                raise KeyStoreError(
                    "failed to read active key"
                ) from exc

        if not rows:
            raise RuntimeError(
                "no active key"
            )

        if len(rows) > 1:
            raise RuntimeError(
                "multiple active keys detected"
            )

        return self.get_key(
            str(rows[0][0])
        )

    # ========================================================
    # Key IDs
    # ========================================================

    def key_ids(
        self,
    ) -> tuple[str, ...]:
        connection = self._require_connection()

        with self._lock:
            try:
                rows = connection.execute(
                    """
                    SELECT key_id
                    FROM keys
                    ORDER BY key_id
                    """
                ).fetchall()

            except sqlite3.DatabaseError as exc:
                raise KeyStoreError(
                    "failed to read key store"
                ) from exc

        return tuple(
            str(row[0])
            for row in rows
        )

    # ========================================================
    # Issuer trust
    # ========================================================

    def trust_issuer(
        self,
        issuer: str,
    ) -> None:
        issuer = self._validate_issuer(
            issuer
        )

        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    DELETE FROM revoked_issuers
                    WHERE issuer = ?
                    """,
                    (issuer,),
                )

                connection.execute(
                    """
                    INSERT OR IGNORE INTO trusted_issuers (
                        issuer
                    )
                    VALUES (?)
                    """,
                    (issuer,),
                )

                connection.commit()

            except sqlite3.DatabaseError as exc:
                connection.rollback()

                raise KeyStoreError(
                    "failed to persist issuer trust"
                ) from exc

    def revoke_issuer(
        self,
        issuer: str,
    ) -> None:
        issuer = self._validate_issuer(
            issuer
        )

        connection = self._require_connection()

        with self._lock:
            try:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO revoked_issuers (
                        issuer
                    )
                    VALUES (?)
                    """,
                    (issuer,),
                )

                connection.commit()

            except sqlite3.DatabaseError as exc:
                connection.rollback()

                raise KeyStoreError(
                    "failed to persist issuer revocation"
                ) from exc

    def trusted_issuers(
        self,
    ) -> frozenset[str]:
        connection = self._require_connection()

        with self._lock:
            try:
                trusted_rows = connection.execute(
                    """
                    SELECT issuer
                    FROM trusted_issuers
                    """
                ).fetchall()

                revoked_rows = connection.execute(
                    """
                    SELECT issuer
                    FROM revoked_issuers
                    """
                ).fetchall()

            except sqlite3.DatabaseError as exc:
                raise KeyStoreError(
                    "failed to read issuer trust state"
                ) from exc

        revoked = {
            str(row[0])
            for row in revoked_rows
        }

        return frozenset(
            str(row[0])
            for row in trusted_rows
            if row[0] not in revoked
        )

    # ========================================================
    # Close
    # ========================================================

    def close(
        self,
    ) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

            self._master_key = b""

    def __enter__(
        self,
    ):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        self.close()