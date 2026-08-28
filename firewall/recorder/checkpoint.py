"""Signed checkpoints: the recorder's commitment to the chain.

A checkpoint is a lightweight signature over a point in the hash chain.
It names an event sequence number, that event's hash, and how many
events preceded it, and is signed with the recorder's Ed25519 identity.
The verifier checks every checkpoint against the chain and against the
public key embedded in the artifact.

Checkpoints turn a long chain into many short, independently checkable
segments: an attacker who rewrites one event must rewrite every
downstream event *and* re-sign every later checkpoint, which requires
the private key. Frequent checkpoints (every ``checkpoint_every`` events)
bound the blast radius of a single forged link.

The signed block is the canonical encoding of exactly the fields below,
so a verifier in any language can reproduce it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Optional

from firewall.recorder.encoding import canonical_bytes
from firewall.recorder.events import (
    GENESIS_HASH,
    RecorderError,
    _hex_digest,
)
from firewall.recorder.identity import RecorderIdentity


class CheckpointError(RecorderError):
    """Raised for a malformed checkpoint."""


@dataclass(frozen=True)
class Checkpoint:
    """One signed commitment to a point in the event chain."""

    seq: int
    event_hash: str
    event_count: int
    timestamp: float
    signer: str
    signature: str

    # ------------------------------------------------------------------
    # Signed block
    # ------------------------------------------------------------------

    def signed_block(self) -> dict[str, Any]:
        """The exact fields the signature is computed over."""

        return {
            "seq": self.seq,
            "event_hash": self.event_hash,
            "event_count": self.event_count,
            "timestamp": self.timestamp,
            "signer": self.signer,
        }

    def signed_bytes(self) -> bytes:
        return canonical_bytes(
            self.signed_block()
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "event_hash": self.event_hash,
            "event_count": self.event_count,
            "timestamp": self.timestamp,
            "signer": self.signer,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "Checkpoint":
        if not isinstance(payload, dict):
            raise CheckpointError(
                "a checkpoint must be an object"
            )

        seq = payload.get("seq")
        event_count = payload.get("event_count")

        if isinstance(seq, bool) or not isinstance(seq, int):
            raise CheckpointError(
                "checkpoint seq must be an integer"
            )

        if isinstance(event_count, bool) or not isinstance(
            event_count, int
        ):
            raise CheckpointError(
                "checkpoint event_count must be an integer"
            )

        timestamp = payload.get("timestamp")

        if isinstance(timestamp, bool) or not isinstance(
            timestamp, (int, float)
        ):
            raise CheckpointError(
                "checkpoint timestamp must be a number"
            )

        timestamp = float(timestamp)

        if not math.isfinite(timestamp):
            raise CheckpointError(
                "checkpoint timestamp must be finite"
            )

        signer = payload.get("signer")
        signature = payload.get("signature")

        if not isinstance(signer, str) or not signer.strip():
            raise CheckpointError(
                "checkpoint signer must be a non-empty string"
            )

        if not isinstance(signature, str) or not signature.strip():
            raise CheckpointError(
                "checkpoint signature must be a non-empty string"
            )

        return cls(
            seq=seq,
            event_hash=_hex_digest(
                payload.get("event_hash"),
                "checkpoint event_hash",
            ),
            event_count=event_count,
            timestamp=timestamp,
            signer=signer,
            signature=signature,
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Checkpoint(seq={self.seq}, "
            f"event_count={self.event_count}, "
            f"event_hash={self.event_hash[:12]}...)"
        )


def sign_checkpoint(
    identity: RecorderIdentity,
    *,
    seq: int,
    event_hash: str,
    event_count: int,
    timestamp: Optional[float] = None,
) -> Checkpoint:
    """Create and sign a checkpoint at the given chain point."""

    if isinstance(seq, bool) or not isinstance(seq, int):
        raise CheckpointError(
            "seq must be an integer"
        )

    if seq < 1:
        raise CheckpointError(
            "seq must be positive"
        )

    if isinstance(event_count, bool) or not isinstance(
        event_count, int
    ):
        raise CheckpointError(
            "event_count must be an integer"
        )

    if event_count < 1:
        raise CheckpointError(
            "event_count must be positive"
        )

    event_hash = _hex_digest(
        event_hash,
        "event_hash",
    )

    if timestamp is None:
        import time

        timestamp = time.time()

    timestamp = float(timestamp)

    if not math.isfinite(timestamp):
        raise CheckpointError(
            "timestamp must be finite"
        )

    checkpoint = Checkpoint(
        seq=seq,
        event_hash=event_hash,
        event_count=event_count,
        timestamp=timestamp,
        signer=identity.fingerprint,
        signature="",
    )

    signature = identity.sign(
        checkpoint.signed_bytes()
    )

    return Checkpoint(
        seq=seq,
        event_hash=event_hash,
        event_count=event_count,
        timestamp=timestamp,
        signer=identity.fingerprint,
        signature=signature,
    )
