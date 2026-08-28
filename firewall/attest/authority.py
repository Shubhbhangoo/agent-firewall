"""v2.0 Cryptographic Attestation (firewall.attest).

Signed, versioned statements about security-relevant facts, using the
agent identity key with explicit algorithm metadata and a verifier that
distinguishes ``verified`` / ``failed`` / ``unverifiable`` (never
conflated).

``alg`` is recorded so future key algorithms (e.g. post-quantum) can
be introduced without changing the attestation model. Verifiers return
``unverifiable`` for an algorithm they do not support rather than
guessing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from firewall.ident import IdentityRegistry

#: Attestation format version.
ATTESTATION_VERSION = 1

#: Supported signing algorithms.
SUPPORTED_ALGORITHMS = ("Ed25519",)


class AttestationError(ValueError):
    """Raised for an invalid attestation."""


@dataclass(frozen=True)
class Attestation:
    """One signed statement about a security-relevant fact."""

    subject: str
    statement_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    issued_at: float = 0.0
    alg: str = "Ed25519"
    key_fingerprint: str = ""
    signature: str = ""
    nonce: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise AttestationError("subject is required")
        if (
            not isinstance(self.statement_type, str)
            or not self.statement_type.strip()
        ):
            raise AttestationError("statement_type is required")
        if not isinstance(self.alg, str) or not self.alg.strip():
            raise AttestationError("alg is required")
        # Unknown algorithms are deliberately NOT rejected here: the
        # verifier must be able to parse an attestation carrying an
        # algorithm it does not support and answer ``unverifiable``
        # instead of crashing. Only issuance restricts the algorithm.

    # ------------------------------------------------------------------
    # Signed block
    # ------------------------------------------------------------------

    def signed_block(self) -> dict[str, Any]:
        return {
            "attestation_version": ATTESTATION_VERSION,
            "subject": self.subject,
            "statement_type": self.statement_type,
            "payload": dict(self.payload),
            "agent_id": self.agent_id,
            "issued_at": self.issued_at,
            "alg": self.alg,
            "key_fingerprint": self.key_fingerprint,
            "nonce": self.nonce,
        }

    def signed_bytes(self) -> bytes:
        return json.dumps(
            self.signed_block(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestation_version": ATTESTATION_VERSION,
            "subject": self.subject,
            "statement_type": self.statement_type,
            "payload": dict(self.payload),
            "agent_id": self.agent_id,
            "issued_at": self.issued_at,
            "alg": self.alg,
            "key_fingerprint": self.key_fingerprint,
            "signature": self.signature,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Attestation":
        if not isinstance(payload, dict):
            raise AttestationError("attestation must be an object")
        return cls(
            subject=payload.get("subject"),
            statement_type=payload.get("statement_type"),
            payload=dict(payload.get("payload", {}) or {}),
            agent_id=payload.get("agent_id", ""),
            issued_at=float(payload.get("issued_at", 0.0)),
            alg=payload.get("alg", "Ed25519"),
            key_fingerprint=payload.get("key_fingerprint", ""),
            signature=payload.get("signature", ""),
            nonce=payload.get("nonce", ""),
        )


class AttestationAuthority:
    """Issues and verifies attestations under agent identities."""

    def __init__(
        self,
        identity_registry: IdentityRegistry,
        *,
        clock: Any = None,
    ) -> None:
        if not isinstance(identity_registry, IdentityRegistry):
            raise AttestationError(
                "identity_registry must be an IdentityRegistry"
            )
        self._identities = identity_registry
        self._clock = clock if clock is not None else time.time

    # ------------------------------------------------------------------
    # Issue
    # ------------------------------------------------------------------

    def issue(
        self,
        *,
        agent_id: str,
        subject: str,
        statement_type: str,
        payload: Optional[dict[str, Any]] = None,
        nonce: Optional[str] = None,
        alg: str = "Ed25519",
    ) -> Attestation:
        if agent_id is None:
            raise AttestationError("agent_id is required")

        if not isinstance(agent_id, str) or not agent_id.strip():
            raise AttestationError("agent_id is required")

        identity = self._identities.get(agent_id)

        if identity is None:
            raise AttestationError(
                f"unknown identity: {agent_id}"
            )

        if identity.status != "active":
            raise AttestationError(
                f"identity is not active: {agent_id}"
            )

        if alg not in SUPPORTED_ALGORITHMS:
            raise AttestationError(
                f"unsupported algorithm: {alg}"
            )

        import uuid

        attestation = Attestation(
            subject=subject,
            statement_type=statement_type,
            payload=dict(payload or {}),
            agent_id=agent_id,
            issued_at=float(self._clock()),
            alg=alg,
            key_fingerprint=identity.key_fingerprint,
            nonce=nonce or uuid.uuid4().hex,
        )

        signature = self._identities.sign(
            agent_id,
            attestation.signed_bytes(),
        )

        return Attestation(
            subject=attestation.subject,
            statement_type=attestation.statement_type,
            payload=attestation.payload,
            agent_id=attestation.agent_id,
            issued_at=attestation.issued_at,
            alg=attestation.alg,
            key_fingerprint=attestation.key_fingerprint,
            nonce=attestation.nonce,
            signature=signature,
        )

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(
        self,
        attestation: Attestation,
    ) -> dict[str, Any]:
        """Three-state verification, never conflated.

        ``verified``   signature valid against the recorded identity key,
                       identity active, fingerprint matches, algorithm
                       supported.
        ``failed``     a concrete violation: bad signature, revoked/
                       retired identity, fingerprint mismatch.
        ``unverifiable`` the algorithm is not supported or the identity
                       is unknown (cannot prove anything about it).
        """

        if not isinstance(attestation, Attestation):
            return {
                "status": "unverifiable",
                "findings": ["not an attestation"],
            }

        if attestation.alg not in SUPPORTED_ALGORITHMS:
            return {
                "status": "unverifiable",
                "findings": [
                    f"unsupported algorithm: {attestation.alg}"
                ],
            }

        identity = self._identities.get(attestation.agent_id)

        if identity is None:
            return {
                "status": "unverifiable",
                "findings": [
                    f"unknown identity: {attestation.agent_id}"
                ],
            }

        if identity.status in ("revoked", "retired"):
            return {
                "status": "failed",
                "findings": [
                    f"identity is {identity.status}"
                ],
            }

        if (
            attestation.key_fingerprint
            and attestation.key_fingerprint
            != identity.key_fingerprint
        ):
            return {
                "status": "failed",
                "findings": [
                    "attestation key fingerprint does not match the "
                    "recorded identity key"
                ],
            }

        if not attestation.signature:
            return {
                "status": "failed",
                "findings": ["attestation is not signed"],
            }

        valid = self._identities.verify(
            attestation.agent_id,
            attestation.signed_bytes(),
            attestation.signature,
        )

        if not valid:
            return {
                "status": "failed",
                "findings": [
                    "attestation signature does not verify"
                ],
            }

        return {
            "status": "verified",
            "findings": [],
            "agent_id": attestation.agent_id,
            "subject": attestation.subject,
            "statement_type": attestation.statement_type,
            "key_fingerprint": identity.key_fingerprint,
        }
