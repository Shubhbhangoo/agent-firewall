"""Independent verification of agent security artifacts.

The verifier does not trust the recorder. Given an artifact -- a file
that may have been edited, truncated, forged, or replayed by anyone -- it
recomputes every hash, walks every chain link, checks every signature,
and reports precisely what it could and could not establish.

Results are one of five deliberately distinct statuses, never conflated:

``verified``
    Every check passed: the chain is unbroken, every checkpoint is
    validly signed by the recorder identity the artifact names, the
    session is finalized, and nothing was redacted.

``failed``
    A concrete integrity violation: a wrong hash, a broken link, a gap
    or reorder in the sequence, an invalid signature, an identity
    mismatch, or a finalized artifact missing its terminal event. The
    artifact must not be treated as trustworthy evidence.

``unverifiable``
    The bytes are not a recognizable artifact at all -- wrong magic,
    unsupported version, malformed JSON, missing envelope fields.

``incomplete``
    Everything that is present verifies, but the session was never
    finalized (or was cut short): missing evidence is reported, never
    silently treated as trustworthy.

``redacted``
    Everything verifies *and* the artifact declares deliberate
    redactions. Integrity is intact; content is missing by design.

A report is a set of :class:`Finding` items plus a status. Verifiers
never stop at the first problem: every check runs and every violation is
reported, so a user sees the whole picture at once.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from firewall.artifact import (
    ArtifactError,
    artifact_from_bytes,
    artifact_from_json,
    artifact_from_path,
    validate_manifest,
)
from firewall.recorder.checkpoint import Checkpoint
from firewall.recorder.events import EventType, GENESIS_HASH, SecurityEvent
from firewall.recorder.identity import (
    fingerprint_of_public_key,
    public_key_from_b64,
    verify_signature,
)


class VerificationStatus(str):
    """The five distinct verification outcomes."""

    VERIFIED = "verified"
    FAILED = "failed"
    UNVERIFIABLE = "unverifiable"
    INCOMPLETE = "incomplete"
    REDACTED = "redacted"


@dataclass(frozen=True)
class Finding:
    """One check result: a problem or an observation."""

    severity: str  # "error" | "warning" | "info"
    code: str
    message: str
    event_seq: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "event_seq": self.event_seq,
        }


@dataclass(frozen=True)
class VerificationReport:
    """The complete result of verifying one artifact."""

    status: str
    findings: tuple[Finding, ...]
    checks: dict[str, bool]
    summary: dict[str, Any]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": [
                finding.to_dict() for finding in self.findings
            ],
            "checks": dict(self.checks),
            "summary": dict(self.summary),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
        )

    # ------------------------------------------------------------------
    # Human output
    # ------------------------------------------------------------------

    def text(self) -> str:
        """A human-readable verification report."""

        lines = [f"status: {self.status}"]

        for finding in self.findings:
            marker = {
                "error": "[X]",
                "warning": "[!]",
                "info": "[i]",
            }.get(finding.severity, "[i]")

            where = (
                f" (event {finding.event_seq})"
                if finding.event_seq is not None
                else ""
            )

            lines.append(
                f"  {marker} {finding.code}{where}: "
                f"{finding.message}"
            )

        summary = self.summary

        lines.append(
            f"  session {summary.get('session_id', '?')} "
            f"({summary.get('event_count', 0)} events, "
            f"{summary.get('checkpoint_count', 0)} checkpoints)"
        )

        if summary.get("recorder_fingerprint"):
            lines.append(
                "  recorder "
                + summary["recorder_fingerprint"]
            )

        return "\n".join(lines)

    @property
    def verified(self) -> bool:
        return self.status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.REDACTED,
        )


# ----------------------------------------------------------------------
# Public entry points
# ----------------------------------------------------------------------


def verify_artifact(
    artifact: Any,
    *,
    expect_recorder: Optional[str] = None,
) -> VerificationReport:
    """Verify an artifact given as a dict, JSON text, or bytes."""

    if isinstance(artifact, dict):
        data = artifact
    elif isinstance(artifact, (bytes, bytearray)):
        try:
            data = artifact_from_bytes(bytes(artifact))
        except ArtifactError as exc:
            return _unverifiable(str(exc))
    elif isinstance(artifact, str):
        try:
            data = artifact_from_json(artifact)
        except ArtifactError as exc:
            return _unverifiable(str(exc))
    else:
        return _unverifiable(
            "artifact must be a mapping, JSON text, or bytes"
        )

    return _verify_parsed(data, expect_recorder=expect_recorder)


def verify_artifact_path(
    path: str | Path,
    *,
    expect_recorder: Optional[str] = None,
) -> VerificationReport:
    """Verify an artifact file on disk."""

    try:
        data = artifact_from_path(path)
    except ArtifactError as exc:
        return _unverifiable(str(exc))

    return _verify_parsed(data, expect_recorder=expect_recorder)


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------


def _unverifiable(message: str) -> VerificationReport:
    return VerificationReport(
        status=VerificationStatus.UNVERIFIABLE,
        findings=(
            Finding(
                severity="error",
                code="unverifiable",
                message=message,
            ),
        ),
        checks={"envelope": False},
        summary={},
    )


def _verify_parsed(
    data: dict[str, Any],
    *,
    expect_recorder: Optional[str],
) -> VerificationReport:
    findings: list[Finding] = []
    checks: dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Envelope
    # ------------------------------------------------------------------

    try:
        validate_manifest(data)
        checks["envelope"] = True
    except ArtifactError as exc:
        return _unverifiable(str(exc))

    session = data.get("session", {})
    recorder = data.get("recorder", {})
    raw_events = data.get("events", [])
    raw_checkpoints = data.get("checkpoints", [])
    raw_redactions = data.get("redactions", [])

    # ------------------------------------------------------------------
    # Session shape
    # ------------------------------------------------------------------

    finalized = session.get("finalized")

    if not isinstance(finalized, bool):
        findings.append(
            Finding(
                severity="error",
                code="session_finalized_invalid",
                message="session.finalized must be a boolean",
            )
        )
        checks["session_shape"] = False
    else:
        checks["session_shape"] = True

    # ------------------------------------------------------------------
    # Events: parse, order, chain, hashes
    # ------------------------------------------------------------------

    events: list[SecurityEvent] = []
    events_ok = True

    for index, entry in enumerate(raw_events):
        seq_expected = index + 1

        try:
            event = SecurityEvent.from_dict(entry)
        except Exception as exc:
            findings.append(
                Finding(
                    severity="error",
                    code="event_malformed",
                    message=(
                        f"event {seq_expected} is malformed: {exc}"
                    ),
                    event_seq=seq_expected,
                )
            )
            events_ok = False
            continue

        if event.seq != seq_expected:
            findings.append(
                Finding(
                    severity="error",
                    code="event_ordering_invalid",
                    message=(
                        f"event {seq_expected} declares seq "
                        f"{event.seq}: events are missing, "
                        "duplicated, or reordered"
                    ),
                    event_seq=seq_expected,
                )
            )
            events_ok = False

        expected_prev = (
            events[-1].hash
            if events
            else GENESIS_HASH
        )

        if event.prev_hash != expected_prev:
            findings.append(
                Finding(
                    severity="error",
                    code="event_chain_broken",
                    message=(
                        f"event {event.seq} does not link to the "
                        "previous event's hash"
                    ),
                    event_seq=event.seq,
                )
            )
            events_ok = False

        recomputed = event.recompute_hash()

        if event.hash != recomputed:
            findings.append(
                Finding(
                    severity="error",
                    code="event_hash_invalid",
                    message=(
                        f"event {event.seq} hash does not match its "
                        "contents"
                    ),
                    event_seq=event.seq,
                )
            )
            events_ok = False

        events.append(event)

    checks["event_chain"] = events_ok

    # ------------------------------------------------------------------
    # Recorder identity
    # ------------------------------------------------------------------

    identity_ok = True
    public_key_b64 = recorder.get("public_key", "")
    recorded_fingerprint = recorder.get("fingerprint", "")

    try:
        public_key = public_key_from_b64(public_key_b64)
    except Exception:
        findings.append(
            Finding(
                severity="error",
                code="recorder_identity_invalid",
                message="recorder.public_key is not a valid 32-byte "
                "Ed25519 key",
            )
        )
        identity_ok = False
        public_key = b""

    if identity_ok:
        computed_fingerprint = fingerprint_of_public_key(
            public_key_b64
        )

        if (
            not isinstance(recorded_fingerprint, str)
            or recorded_fingerprint != computed_fingerprint
        ):
            findings.append(
                Finding(
                    severity="error",
                    code="recorder_identity_inconsistent",
                    message="recorder.fingerprint does not match the "
                    "recorded public key",
                )
            )
            identity_ok = False

        if expect_recorder is not None:
            if recorded_fingerprint != expect_recorder:
                findings.append(
                    Finding(
                        severity="error",
                        code="recorder_not_expected",
                        message=(
                            f"recorder identity {recorded_fingerprint} "
                            f"does not match the expected recorder "
                            f"{expect_recorder}"
                        ),
                    )
                )
                identity_ok = False

    checks["recorder_identity"] = identity_ok

    # ------------------------------------------------------------------
    # Checkpoints: parse, order, anchors, signatures
    # ------------------------------------------------------------------

    checkpoints_ok = True
    checkpoints: list[Checkpoint] = []

    for index, entry in enumerate(raw_checkpoints):
        try:
            checkpoint = Checkpoint.from_dict(entry)
        except Exception as exc:
            findings.append(
                Finding(
                    severity="error",
                    code="checkpoint_malformed",
                    message=f"checkpoint {index + 1} is malformed: {exc}",
                )
            )
            checkpoints_ok = False
            continue

        checkpoints.append(checkpoint)

        if checkpoint.seq < 1 or checkpoint.seq > len(events):
            findings.append(
                Finding(
                    severity="error",
                    code="checkpoint_seq_out_of_range",
                    message=(
                        f"checkpoint anchors event seq "
                        f"{checkpoint.seq}, outside the recorded "
                        f"{len(events)} events"
                    ),
                )
            )
            checkpoints_ok = False
            continue

        anchored = events[checkpoint.seq - 1]

        if checkpoint.event_hash != anchored.hash:
            findings.append(
                Finding(
                    severity="error",
                    code="checkpoint_anchor_mismatch",
                    message=(
                        f"checkpoint at seq {checkpoint.seq} does not "
                        "match the event hash at that position"
                    ),
                    event_seq=checkpoint.seq,
                )
            )
            checkpoints_ok = False

        if checkpoint.event_count != checkpoint.seq:
            findings.append(
                Finding(
                    severity="error",
                    code="checkpoint_count_mismatch",
                    message=(
                        f"checkpoint at seq {checkpoint.seq} declares "
                        f"event_count {checkpoint.event_count}"
                    ),
                )
            )
            checkpoints_ok = False

        if (
            not isinstance(checkpoint.signer, str)
            or checkpoint.signer != recorded_fingerprint
        ):
            findings.append(
                Finding(
                    severity="error",
                    code="checkpoint_signer_mismatch",
                    message=(
                        "checkpoint signer does not match the "
                        "artifact's recorder identity"
                    ),
                    event_seq=checkpoint.seq,
                )
            )
            checkpoints_ok = False

        if public_key:
            valid = verify_signature(
                public_key_b64=public_key_b64,
                data=checkpoint.signed_bytes(),
                signature_b64=checkpoint.signature,
            )

            if not valid:
                findings.append(
                    Finding(
                        severity="error",
                        code="checkpoint_signature_invalid",
                        message=(
                            f"checkpoint at seq {checkpoint.seq} has an "
                            "invalid signature"
                        ),
                        event_seq=checkpoint.seq,
                    )
                )
                checkpoints_ok = False

    for earlier, later in zip(
        checkpoints, checkpoints[1:]
    ):
        if later.seq <= earlier.seq:
            findings.append(
                Finding(
                    severity="error",
                    code="checkpoint_order_invalid",
                    message="checkpoints are not strictly ordered",
                )
            )
            checkpoints_ok = False
            break

    if (
        events_ok
        and checkpoints
        and checkpoints[-1].seq != len(events)
        and finalized is True
    ):
        findings.append(
            Finding(
                severity="warning",
                code="checkpoint_not_covering_end",
                message=(
                    "the final checkpoint does not cover the last "
                    "event; the chain still verifies, but the tail "
                    "is not signed"
                ),
            )
        )

    checks["checkpoints"] = checkpoints_ok

    # ------------------------------------------------------------------
    # Session completeness
    # ------------------------------------------------------------------

    completeness_ok = True

    if finalized is True:
        if not events:
            findings.append(
                Finding(
                    severity="error",
                    code="session_empty",
                    message="a finalized artifact contains no events",
                )
            )
            completeness_ok = False
        elif events[-1].type != EventType.SESSION_ENDED:
            findings.append(
                Finding(
                    severity="error",
                    code="session_terminal_event_missing",
                    message=(
                        "the artifact claims to be finalized but its "
                        "last event is not session_ended; the recording "
                        "was cut short or truncated"
                    ),
                    event_seq=events[-1].seq,
                )
            )
            completeness_ok = False
        else:
            ended_at = session.get("ended_at")

            if ended_at is None:
                findings.append(
                    Finding(
                        severity="warning",
                        code="session_ended_at_missing",
                        message="finalized session carries no ended_at",
                    )
                )
    else:
        if events:
            findings.append(
                Finding(
                    severity="info",
                    code="session_incomplete",
                    message=(
                        "the recording was never finalized; everything "
                        "present verifies, but later events may be "
                        "missing"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    severity="info",
                    code="session_empty",
                    message="the artifact contains no events",
                )
            )

    checks["session_completeness"] = completeness_ok

    # ------------------------------------------------------------------
    # Redactions
    # ------------------------------------------------------------------

    redactions_ok = True
    valid_seqs = {event.seq for event in events}

    for redaction in raw_redactions:
        if not isinstance(redaction, dict):
            findings.append(
                Finding(
                    severity="error",
                    code="redaction_malformed",
                    message="a redaction entry is malformed",
                )
            )
            redactions_ok = False
            continue

        seq = redaction.get("seq")

        if seq not in valid_seqs:
            findings.append(
                Finding(
                    severity="warning",
                    code="redaction_references_missing_event",
                    message=(
                        f"redaction references event {seq}, which is "
                        "not in the recorded chain"
                    ),
                )
            )

    checks["redactions"] = redactions_ok

    # ------------------------------------------------------------------
    # Status resolution
    # ------------------------------------------------------------------

    errors = [
        finding for finding in findings
        if finding.severity == "error"
    ]

    if errors:
        status = VerificationStatus.FAILED
    elif not finalized:
        status = VerificationStatus.INCOMPLETE
    elif raw_redactions:
        status = VerificationStatus.REDACTED
    else:
        status = VerificationStatus.VERIFIED

    report_summary = {
        "session_id": session.get("id"),
        "agent": session.get("agent"),
        "event_count": len(events),
        "checkpoint_count": len(checkpoints),
        "finalized": finalized,
        "recorder_fingerprint": recorded_fingerprint,
        "redaction_count": len(raw_redactions),
    }

    return VerificationReport(
        status=status,
        findings=tuple(findings),
        checks=checks,
        summary=report_summary,
    )
