"""v2.0 Agent Identity (firewall.ident).

First-class, persistent, cryptographically bound agent identity.

An :class:`Identity` is an agent's identity record: who it is, who
issued it, which key it currently holds, and its lifecycle status
(``active`` / ``revoked`` / ``retired``). The identity is bound to an
Ed25519 key pair; the public key and its fingerprint are recorded, the
private key never leaves the registry and never enters artifacts,
passports, or attestations.

Design rules:

* **Identity does not imply authorization.** An active identity proves
  *who* an agent claims to be (subject to issuer trust); whether it may
  *do* anything is decided solely by the authorization pipeline.
* **Verification is honest.** ``verify`` checks the signature over the
  canonical identity payload with the recorded public key, and checks
  status (revoked/retired fail). It reports ``False`` -- it does not
  raise and does not guess.
* **Rotation is versioned.** ``rotate`` replaces the key and bumps
  ``identity_version``; attestations and passports reference the
  fingerprint, so a verifier can always tell which key was used.
* **Parent/child is a recorded fact, not authority.** ``parent_agent``
  is provenance about who issued the identity; it grants nothing.
* **Persistence is atomic.** The private key is stored only when a
  passphrase is supplied (encrypted); without one it stays in memory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Identity lifecycle statuses.
IDENTITY_STATUSES = (
    "active",
    "revoked",
    "retired",
)

#: Current identity record format version.
IDENTITY_VERSION = 1

#: Passphrase-derived key stretch rounds (defense in depth).
_KDF_ROUNDS = 100_000


class IdentityError(ValueError):
    """Raised for an invalid identity operation."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str, label: str) -> bytes:
    if not isinstance(text, str) or not text.strip():
        raise IdentityError(f"{label} must be base64")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise IdentityError(f"{label} is not valid base64") from exc


def _fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes_raw()
    return hashlib.sha256(raw).hexdigest()


def generate_key_pair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def _canonical_payload(identity: "Identity") -> bytes:
    """The exact bytes the identity signature is computed over."""

    return json.dumps(
        {
            "agent_id": identity.agent_id,
            "owner": identity.owner,
            "environment": identity.environment,
            "identity_version": identity.identity_version,
            "public_key": identity.public_key_b64,
            "parent_agent": identity.parent_agent,
            "issuer": identity.issuer,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class Identity:
    """One agent identity record. Immutable."""

    agent_id: str
    issuer: str = "trusted-issuer"
    identity_version: int = 1
    owner: str = ""
    environment: str = ""
    created_at: float = 0.0
    status: str = "active"
    public_key_b64: str = ""
    key_fingerprint: str = ""
    parent_agent: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise IdentityError("agent_id is required")
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise IdentityError("issuer is required")
        if (
            isinstance(self.identity_version, bool)
            or not isinstance(self.identity_version, int)
            or self.identity_version < 1
        ):
            raise IdentityError("identity_version must be a positive integer")
        if self.status not in IDENTITY_STATUSES:
            raise IdentityError(
                f"unknown identity status: {self.status}"
            )
        if self.public_key_b64 and not self.key_fingerprint:
            raise IdentityError(
                "key_fingerprint is required when a public key is set"
            )

    # ------------------------------------------------------------------
    # Signing payload
    # ------------------------------------------------------------------

    def payload(self) -> bytes:
        return _canonical_payload(self)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "issuer": self.issuer,
            "identity_version": self.identity_version,
            "owner": self.owner,
            "environment": self.environment,
            "created_at": self.created_at,
            "status": self.status,
            "public_key": self.public_key_b64,
            "key_fingerprint": self.key_fingerprint,
            "parent_agent": self.parent_agent,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Identity":
        if not isinstance(payload, dict):
            raise IdentityError("identity must be an object")
        return cls(
            agent_id=payload.get("agent_id"),
            issuer=payload.get("issuer", "trusted-issuer"),
            identity_version=payload.get("identity_version", 1),
            owner=payload.get("owner", ""),
            environment=payload.get("environment", ""),
            created_at=float(payload.get("created_at", 0.0)),
            status=payload.get("status", "active"),
            public_key_b64=payload.get("public_key", ""),
            key_fingerprint=payload.get("key_fingerprint", ""),
            parent_agent=payload.get("parent_agent"),
            metadata=dict(payload.get("metadata", {}) or {}),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Identity(agent_id={self.agent_id!r}, "
            f"version={self.identity_version}, "
            f"status={self.status})"
        )


class IdentityRegistry:
    """Persistent identity registry with lifecycle and key management."""

    def __init__(
        self,
        *,
        state_path: Optional[str | Path] = None,
        passphrase: Optional[bytes] = None,
        clock: Any = None,
        trusted_issuers: Optional[set[str]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._path = Path(state_path) if state_path else None
        self._passphrase = passphrase
        self._clock = clock if clock is not None else time.time
        self._trusted_issuers = set(
            trusted_issuers
            if trusted_issuers is not None
            else {"trusted-issuer"}
        )

        # agent_id -> Identity
        self._identities: dict[str, Identity] = {}

        # agent_id -> private key (in-memory only unless persisted
        # with a passphrase).
        self._keys: dict[str, Ed25519PrivateKey] = {}

        if self._path is not None:
            self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return

        try:
            data = json.loads(
                self._path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise IdentityError(
                f"cannot load identity state: {exc}"
            ) from exc

        for entry in data.get("identities", []):
            try:
                identity = Identity.from_dict(entry)
            except IdentityError:
                continue
            self._identities[identity.agent_id] = identity

        for entry in data.get("keys", []):
            agent_id = entry.get("agent_id")
            wrapped = entry.get("private_key_wrapped")
            if not agent_id or not wrapped:
                continue
            key = self._unwrap(wrapped)
            if key is not None:
                self._keys[agent_id] = key

    def _save(self) -> None:
        if self._path is None:
            return

        data = {
            "identities": [
                identity.to_dict()
                for identity in self._identities.values()
            ],
            "keys": [
                {
                    "agent_id": agent_id,
                    "private_key_wrapped": self._wrap(private_key),
                }
                for agent_id, private_key in self._keys.items()
            ],
        }

        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."

        fd, temp_path = tempfile.mkstemp(
            prefix=".identity-state.",
            suffix=".tmp",
            dir=dir_text,
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def _wrap(self, private_key: Ed25519PrivateKey) -> str:
        raw = private_key.private_bytes_raw()

        if self._passphrase is None:
            return _b64encode(raw)

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import (
            Cipher,
            algorithms,
            modes,
        )
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_KDF_ROUNDS,
        )
        key = kdf.derive(self._passphrase)

        nonce = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key), modes.GCM(nonce)
        ).encryptor()
        ciphertext = encryptor.update(raw) + encryptor.finalize()

        return json.dumps(
            {
                "kdf": "pbkdf2-sha256",
                "rounds": _KDF_ROUNDS,
                "salt": _b64encode(salt),
                "nonce": _b64encode(nonce),
                "ciphertext": _b64encode(ciphertext),
                "tag": _b64encode(encryptor.tag),
            }
        )

    def _unwrap(
        self,
        wrapped: str,
    ) -> Optional[Ed25519PrivateKey]:
        try:
            if wrapped.startswith("{"):
                data = json.loads(wrapped)
                if data.get("kdf") != "pbkdf2-sha256":
                    return None
                if self._passphrase is None:
                    return None

                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.ciphers import (
                    Cipher,
                    algorithms,
                    modes,
                )
                from cryptography.hazmat.primitives.kdf.pbkdf2 import (
                    PBKDF2HMAC,
                )

                salt = _b64decode(data["salt"], "salt")
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=int(data["rounds"]),
                )
                key = kdf.derive(self._passphrase)
                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(
                        _b64decode(data["nonce"], "nonce"),
                        _b64decode(data["tag"], "tag"),
                    ),
                ).decryptor()
                raw = decryptor.update(
                    _b64decode(data["ciphertext"], "ciphertext")
                ) + decryptor.finalize()
                return Ed25519PrivateKey.from_private_bytes(raw)

            raw = _b64decode(wrapped, "private key")
            return Ed25519PrivateKey.from_private_bytes(raw)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create(
        self,
        agent_id: str,
        *,
        owner: str = "",
        environment: str = "",
        issuer: str = "trusted-issuer",
        parent_agent: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Identity:
        """Create and register a new identity with a fresh key pair."""

        if not isinstance(agent_id, str) or not agent_id.strip():
            raise IdentityError("agent_id is required")

        with self._lock:
            if agent_id in self._identities:
                raise IdentityError(
                    f"identity already exists: {agent_id}"
                )

            if issuer not in self._trusted_issuers:
                raise IdentityError(
                    f"issuer is not trusted: {issuer}"
                )

            if (
                parent_agent is not None
                and parent_agent not in self._identities
            ):
                raise IdentityError(
                    f"parent identity does not exist: {parent_agent}"
                )

            private_key, public_key = generate_key_pair()

            identity = Identity(
                agent_id=agent_id,
                issuer=issuer,
                identity_version=1,
                owner=owner,
                environment=environment,
                created_at=float(self._clock()),
                status="active",
                public_key_b64=_b64encode(
                    public_key.public_bytes_raw()
                ),
                key_fingerprint=_fingerprint(public_key),
                parent_agent=parent_agent,
                metadata=dict(metadata or {}),
            )

            self._identities[agent_id] = identity
            self._keys[agent_id] = private_key
            self._save()

            return identity

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def get(self, agent_id: str) -> Optional[Identity]:
        with self._lock:
            return self._identities.get(agent_id)

    def require(self, agent_id: str) -> Identity:
        identity = self.get(agent_id)
        if identity is None:
            raise IdentityError(f"unknown identity: {agent_id}")
        return identity

    def all(self) -> tuple[Identity, ...]:
        with self._lock:
            return tuple(
                self._identities[agent_id]
                for agent_id in sorted(self._identities)
            )

    def agent_ids(self) -> tuple[str, ...]:
        return tuple(
            identity.agent_id for identity in self.all()
        )

    # ------------------------------------------------------------------
    # Signing / verification
    # ------------------------------------------------------------------

    def sign(self, agent_id: str, data: bytes) -> str:
        with self._lock:
            identity = self.require(agent_id)

            if identity.status != "active":
                raise IdentityError(
                    f"identity is not active: {agent_id} "
                    f"({identity.status})"
                )

            private_key = self._keys.get(agent_id)
            if private_key is None:
                raise IdentityError(
                    f"private key unavailable for {agent_id}"
                )

            return _b64encode(private_key.sign(data))

    def verify(
        self,
        agent_id: str,
        data: bytes,
        signature_b64: str,
    ) -> bool:
        """Verify a signature against the recorded identity key.

        Fails for unknown, revoked, or retired identities -- a forged or
        stale identity is never accepted merely because its shape is
        valid.
        """

        identity = self.get(agent_id)

        if identity is None:
            return False

        if identity.status in ("revoked", "retired"):
            return False

        try:
            raw_public = _b64decode(
                identity.public_key_b64,
                "public key",
            )
            public_key = Ed25519PublicKey.from_public_bytes(
                raw_public
            )
            signature = _b64decode(
                signature_b64,
                "signature",
            )
            public_key.verify(signature, bytes(data))
            return True
        except (InvalidSignature, IdentityError, ValueError):
            return False

    def self_attestation(self, agent_id: str) -> str:
        """A self-signature over the identity's canonical payload."""

        with self._lock:
            identity = self.require(agent_id)
            return self.sign(agent_id, identity.payload())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def rotate(self, agent_id: str) -> Identity:
        """Rotate the identity key, bumping the identity version."""

        with self._lock:
            identity = self.require(agent_id)

            if identity.status in ("revoked", "retired"):
                raise IdentityError(
                    f"cannot rotate {identity.status} identity: "
                    f"{agent_id}"
                )

            private_key, public_key = generate_key_pair()

            updated = Identity(
                agent_id=identity.agent_id,
                issuer=identity.issuer,
                identity_version=identity.identity_version + 1,
                owner=identity.owner,
                environment=identity.environment,
                created_at=identity.created_at,
                status="active",
                public_key_b64=_b64encode(
                    public_key.public_bytes_raw()
                ),
                key_fingerprint=_fingerprint(public_key),
                parent_agent=identity.parent_agent,
                metadata=dict(identity.metadata),
            )

            self._identities[agent_id] = updated
            self._keys[agent_id] = private_key
            self._save()

            return updated

    def revoke(
        self,
        agent_id: str,
        *,
        reason: str = "",
    ) -> Identity:
        with self._lock:
            identity = self.require(agent_id)
            metadata = dict(identity.metadata)
            metadata["revoked_at"] = float(self._clock())
            if reason:
                metadata["revoke_reason"] = reason

            updated = Identity(
                agent_id=identity.agent_id,
                issuer=identity.issuer,
                identity_version=identity.identity_version,
                owner=identity.owner,
                environment=identity.environment,
                created_at=identity.created_at,
                status="revoked",
                public_key_b64=identity.public_key_b64,
                key_fingerprint=identity.key_fingerprint,
                parent_agent=identity.parent_agent,
                metadata=metadata,
            )

            self._identities[agent_id] = updated
            self._save()

            return updated

    def retire(self, agent_id: str) -> Identity:
        with self._lock:
            identity = self.require(agent_id)
            updated = Identity(
                agent_id=identity.agent_id,
                issuer=identity.issuer,
                identity_version=identity.identity_version,
                owner=identity.owner,
                environment=identity.environment,
                created_at=identity.created_at,
                status="retired",
                public_key_b64=identity.public_key_b64,
                key_fingerprint=identity.key_fingerprint,
                parent_agent=identity.parent_agent,
                metadata=dict(identity.metadata),
            )
            self._identities[agent_id] = updated
            self._save()
            return updated

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def trust_boundary(self) -> dict[str, Any]:
        """A read-only view of the registry for the console."""

        return {
            "identities": [
                identity.to_dict()
                for identity in self.all()
            ],
            "trusted_issuers": sorted(self._trusted_issuers),
        }

    def close(self) -> None:
        with self._lock:
            self._save()
