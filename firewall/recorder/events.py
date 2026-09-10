"""The v1.8 security event schema.

A :class:`SecurityEvent` is one atomic, immutable, self-hashing record
in an agent's security history. It captures a single fact about the
security lifecycle -- an authority was issued, a request was allowed or
denied, a containment action was taken -- together with enough
cryptographic material to pin it into an ordered, tamper-evident chain:

``prev_hash`` links to the previous event's hash, and ``hash`` is the
SHA-256 of the canonical encoding of every other field. An event can
never be reordered, removed, or edited without breaking the chain.

The payload holds *material security facts only*. Signatures, private
keys, raw credentials, and unrestricted request bodies are deliberately
out of scope: recording code projects the facts the authorization gates
reason about, never the secrets that prove them. What cannot be recorded
safely is recorded redacted (see :mod:`firewall.recorder.redact`).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from firewall.recorder.encoding import (
    canonical_bytes,
    sha256_hex,
    validate_artifact_value,
)

#: Ceiling on a single recorded string. Long free text belongs in the
#: notes field of the manifest, not in the hashed chain.
MAX_STRING = 500

#: Ceiling on payload keys, mirroring the case model's discipline.
MAX_KEYS = 64

#: Genesis chain head. The first event links to this rather than to
#: nothing, so "no previous event" is a concrete, checkable value.
GENESIS_HASH = "0" * 64


class EventType(str, Enum):
    """The closed set of security lifecycle events."""

    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    AGENT_INITIALIZED = "agent_initialized"
    IDENTITY_BOUND = "identity_bound"
    AUTHORITY_ISSUED = "authority_issued"
    AUTHORITY_DELEGATED = "authority_delegated"
    AUTHORITY_ATTENUATED = "authority_attenuated"
    AUTHORITY_REVOKED = "authority_revoked"
    POLICY_ACTIVE = "policy_active"
    AUTHORIZATION = "authorization"
    TOOL_RESULT = "tool_result"
    SECURITY_STATE = "security_state"
    CONTAINMENT = "containment"
    RISK_CHANGED = "risk_changed"
    NOTE = "note"


class RecorderError(ValueError):
    """Raised for a malformed event or recorder misuse."""


def _text(
    value: Any,
    field_name: str,
    *,
    required: bool = True,
    max_length: int = MAX_STRING,
) -> Optional[str]:
    if value is None:
        if required:
            raise RecorderError(
                f"{field_name} is required"
            )
        return None

    if not isinstance(value, str):
        raise RecorderError(
            f"{field_name} must be a string"
        )

    if required and not value.strip():
        raise RecorderError(
            f"{field_name} must not be empty"
        )

    if len(value) > max_length:
        raise RecorderError(
            f"{field_name} is too long "
            f"(>{max_length} characters)"
        )

    return value


def _finite(
    value: Any,
    field_name: str,
) -> float:
    if isinstance(value, bool) or not isinstance(
        value, (int, float)
    ):
        raise RecorderError(
            f"{field_name} must be a number"
        )

    result = float(value)

    if not math.isfinite(result):
        raise RecorderError(
            f"{field_name} must be finite"
        )

    return result


def _payload(
    value: Any,
) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise RecorderError(
            "payload must be an object"
        )

    if len(value) > MAX_KEYS:
        raise RecorderError(
            "payload has too many keys "
            f"(>{MAX_KEYS})"
        )

    for key in value:
        if not isinstance(key, str):
            raise RecorderError(
                "payload keys must be strings"
            )

    # The payload is hashed canonically and written to disk, so it must
    # be fully representable in the canonical encoding. Rejecting here
    # beats writing an artifact that cannot verify itself.
    validate_artifact_value(value)

    return dict(value)


def _hex_digest(
    value: Any,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise RecorderError(
            f"{field_name} must be a hex string"
        )

    value = value.lower()

    if len(value) != 64:
        raise RecorderError(
            f"{field_name} must be 64 hex characters"
        )

    try:
        int(value, 16)
    except ValueError:
        raise RecorderError(
            f"{field_name} is not valid hex"
        ) from None

    return value


def compute_event_hash(
    *,
    seq: int,
    type: str,
    timestamp: float,
    session: str,
    agent: Optional[str],
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    """SHA-256 of the canonical encoding of every field but ``hash``.

    Both the recorder and the verifier call this exact function, so the
    recorded hash is the value an independent verifier recomputes.
    """

    block = {
        "seq": seq,
        "type": type,
        "timestamp": timestamp,
        "session": session,
        "agent": agent,
        "payload": payload,
        "prev_hash": prev_hash,
    }

    return sha256_hex(
        canonical_bytes(block)
    )


@dataclass(frozen=True)
class SecurityEvent:
    """One atomic record in the security history."""

    seq: int
    type: EventType
    timestamp: float
    session: str
    agent: Optional[str]
    payload: dict[str, Any] = field(
        default_factory=dict
    )
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(
            self.seq, int
        ):
            raise RecorderError(
                "seq must be an integer"
            )

        if self.seq < 1:
            raise RecorderError(
                "seq must be positive"
            )

        if isinstance(self.type, str):
            try:
                event_type = EventType(self.type)
            except ValueError:
                raise RecorderError(
                    f"unknown event type: {self.type}"
                ) from None
            object.__setattr__(self, "type", event_type)
        elif not isinstance(self.type, EventType):
            raise RecorderError(
                "type must be an EventType"
            )

        object.__setattr__(
            self,
            "timestamp",
            _finite(self.timestamp, "timestamp"),
        )

        object.__setattr__(
            self,
            "session",
            _text(self.session, "session"),
        )

        object.__setattr__(
            self,
            "agent",
            _text(self.agent, "agent", required=False),
        )

        object.__setattr__(
            self,
            "payload",
            _payload(self.payload),
        )

        object.__setattr__(
            self,
            "prev_hash",
            _hex_digest(self.prev_hash, "prev_hash"),
        )

        if self.hash:
            object.__setattr__(
                self,
                "hash",
                _hex_digest(self.hash, "hash"),
            )

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def recompute_hash(self) -> str:
        """The hash this event *should* carry."""

        return compute_event_hash(
            seq=self.seq,
            type=self.type.value,
            timestamp=self.timestamp,
            session=self.session,
            agent=self.agent,
            payload=self.payload,
            prev_hash=self.prev_hash,
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "session": self.session,
            "agent": self.agent,
            "payload": dict(self.payload),
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "SecurityEvent":
        if not isinstance(payload, dict):
            raise RecorderError(
                "an event must be an object"
            )

        return cls(
            seq=payload.get("seq"),
            type=payload.get("type"),
            timestamp=payload.get("timestamp"),
            session=payload.get("session"),
            agent=payload.get("agent"),
            payload=payload.get("payload"),
            prev_hash=payload.get(
                "prev_hash",
                GENESIS_HASH,
            ),
            hash=payload.get("hash", ""),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"SecurityEvent(seq={self.seq}, "
            f"type={self.type.value}, "
            f"agent={self.agent!r}, "
            f"hash={self.hash[:12]}...)"
        )
