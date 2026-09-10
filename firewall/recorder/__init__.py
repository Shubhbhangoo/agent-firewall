"""Agent Security Flight Recorder (v1.8).

Records the security-relevant lifecycle of an autonomous agent as an
ordered, tamper-evident chain of events, periodically anchored by signed
checkpoints, and exports it as a portable, independently verifiable
artifact (``.afw``).

The recorder is observational by construction: it never makes an
authorization decision, and wiring it into the SDK records decisions
only after they exist, so recording can never change an outcome.
"""

from firewall.recorder.checkpoint import (
    Checkpoint,
    CheckpointError,
    sign_checkpoint,
)
from firewall.recorder.encoding import (
    EncodingError,
    canonical_bytes,
    sha256_hex,
    validate_artifact_value,
)
from firewall.recorder.events import (
    EventType,
    GENESIS_HASH,
    RecorderError,
    SecurityEvent,
    compute_event_hash,
)
from firewall.recorder.identity import (
    IdentityError,
    RecorderIdentity,
    fingerprint_of_public_key,
    public_key_from_b64,
    verify_signature,
)
from firewall.recorder.recorder import (
    DEFAULT_CHECKPOINT_EVERY,
    DEFAULT_MAX_EVENTS,
    FlightRecorder,
)
from firewall.recorder.redact import (
    MAX_REDACTIONS,
    REDACTED_PLACEHOLDER,
    RedactionError,
    redact_payload,
)

__all__ = [
    "Checkpoint",
    "CheckpointError",
    "DEFAULT_CHECKPOINT_EVERY",
    "DEFAULT_MAX_EVENTS",
    "EncodingError",
    "EventType",
    "FlightRecorder",
    "GENESIS_HASH",
    "IdentityError",
    "MAX_REDACTIONS",
    "REDACTED_PLACEHOLDER",
    "RecorderError",
    "RecorderIdentity",
    "RedactionError",
    "SecurityEvent",
    "canonical_bytes",
    "compute_event_hash",
    "fingerprint_of_public_key",
    "public_key_from_b64",
    "redact_payload",
    "sha256_hex",
    "sign_checkpoint",
    "validate_artifact_value",
    "verify_signature",
]
