"""Recorder identity: the signing key behind an artifact.

Every flight recorder owns one Ed25519 key pair. The *public* half is
published inside every artifact it produces, so an independent verifier
can check the recorder's signed checkpoints. The *private* half never
enters an artifact; the host application that creates the recorder keeps
it in memory (or persists it itself, outside the artifact format).

Trust model: an artifact proves *internal* consistency -- the hash chain
is unbroken, checkpoints were signed by the key the artifact names. It
cannot prove that the named key belongs to the agent it claims to
record. That is a root-of-trust decision, made out of band by whoever
verifies, for example by pinning the expected recorder fingerprint:

    firewall verify session.afw --expect-recorder <fingerprint>

This is the same model as Sigstore/Cosign and is the strongest portable
guarantee available without a global PKI.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from firewall.recorder.encoding import sha256_hex


class IdentityError(ValueError):
    """Raised for a malformed recorder identity."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str, label: str) -> bytes:
    if not isinstance(text, str) or not text.strip():
        raise IdentityError(
            f"{label} must be a base64 string"
        )

    try:
        return base64.b64decode(
            text.encode("ascii"), validate=True
        )
    except Exception as exc:
        raise IdentityError(
            f"{label} is not valid base64"
        ) from exc


class RecorderIdentity:
    """An Ed25519 recorder signing identity."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey,
    ) -> None:
        self._private = private_key
        self._public = private_key.public_key()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "RecorderIdentity":
        return cls(
            ed25519.Ed25519PrivateKey.generate()
        )

    @classmethod
    def from_private_pem(
        cls,
        pem: bytes,
    ) -> "RecorderIdentity":
        if not isinstance(pem, (bytes, bytearray)):
            raise IdentityError(
                "private key PEM must be bytes"
            )

        try:
            key = serialization.load_pem_private_key(
                bytes(pem),
                password=None,
            )
        except Exception as exc:
            raise IdentityError(
                "cannot load recorder private key"
            ) from exc

        if not isinstance(
            key, ed25519.Ed25519PrivateKey
        ):
            raise IdentityError(
                "recorder identity must be an Ed25519 key"
            )

        return cls(key)

    @classmethod
    def from_private_key(
        cls,
        key: ed25519.Ed25519PrivateKey,
    ) -> "RecorderIdentity":
        if not isinstance(
            key, ed25519.Ed25519PrivateKey
        ):
            raise IdentityError(
                "recorder identity must be an Ed25519 key"
            )
        return cls(key)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def public_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""

        return self._public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def public_b64(self) -> str:
        """Base64 public key, safe to embed in an artifact."""

        return _b64encode(self.public_bytes)

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the public key: the artifact's recorder id."""

        return sha256_hex(self.public_bytes)

    def private_pem(self) -> bytes:
        """PKCS8 PEM of the private key.

        For the *host* to persist. Never write this into an artifact.
        """

        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, data: bytes) -> str:
        """Base64 Ed25519 signature over ``data``."""

        if not isinstance(data, (bytes, bytearray)):
            raise IdentityError(
                "can only sign bytes"
            )

        return _b64encode(
            self._private.sign(bytes(data))
        )

    def verify(
        self,
        data: bytes,
        signature_b64: str,
    ) -> bool:
        """Verify a base64 signature over ``data``.

        Returns ``False`` (never raises) for a bad signature.
        """

        if not isinstance(data, (bytes, bytearray)):
            return False

        try:
            signature = _b64decode(
                signature_b64,
                "signature",
            )
            self._public.verify(
                signature,
                bytes(data),
            )
            return True
        except (InvalidSignature, IdentityError):
            return False


def verify_signature(
    *,
    public_key_b64: str,
    data: bytes,
    signature_b64: str,
) -> bool:
    """Standalone verification against a public key in artifact form."""

    try:
        raw = _b64decode(public_key_b64, "public key")

        if len(raw) != 32:
            return False

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            raw
        )

        signature = _b64decode(signature_b64, "signature")
        public_key.verify(signature, bytes(data))
        return True
    except (
        InvalidSignature,
        IdentityError,
        ValueError,
    ):
        return False


def fingerprint_of_public_key(public_key_b64: str) -> str:
    """Recorder fingerprint for a public key as stored in an artifact."""

    raw = _b64decode(public_key_b64, "public key")
    return sha256_hex(raw)


def public_key_from_b64(public_key_b64: str) -> bytes:
    """Raw public key bytes from the artifact's base64 form."""

    raw = _b64decode(public_key_b64, "public key")

    if len(raw) != 32:
        raise IdentityError(
            "public key must be 32 bytes"
        )

    return raw
