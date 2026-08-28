"""Independent verification (v1.8).

Verifies that an agent security artifact's integrity is intact -- chain
unbroken, ordering valid, checkpoints signed by the recorder identity
the artifact names -- and reports one of five distinct statuses:
``verified``, ``failed``, ``unverifiable``, ``incomplete``, or
``redacted``. The verifier never stops at the first problem and never
conflates missing evidence with trustworthy evidence.
"""

from firewall.verify.verifier import (
    Finding,
    VerificationReport,
    VerificationStatus,
    verify_artifact,
    verify_artifact_path,
)

__all__ = [
    "Finding",
    "VerificationReport",
    "VerificationStatus",
    "verify_artifact",
    "verify_artifact_path",
]
