"""v1.8 verifier unit tests: every status, every tamper class, and
recorder pinning. The verifier must never conflate states."""

from __future__ import annotations

import json

import pytest

from firewall.recorder import EventType, FlightRecorder
from firewall.verify import (
    VerificationStatus,
    verify_artifact,
    verify_artifact_path,
)


def _session(
    *,
    finalize: bool = True,
    checkpoint_every: int = 3,
    secret: bool = False,
    session_id: str = "verify-session",
):
    recorder = FlightRecorder(
        session_id=session_id,
        agent="agent-v",
        checkpoint_every=checkpoint_every,
    )
    recorder.start()
    recorder.record(
        EventType.AUTHORITY_ISSUED,
        {"capability": "payments.send", "issuer": "trusted-issuer"},
    )
    recorder.record(
        EventType.AUTHORIZATION,
        {"action": "payments.send", "allowed": True, "reason": "authorized"},
    )
    recorder.record(
        EventType.AUTHORIZATION,
        {"action": "payments.send", "allowed": False, "reason": "constraint_denied"},
    )
    if secret:
        recorder.record(
            EventType.TOOL_RESULT,
            {"tool": "db", "password": "hunter2"},
        )
    if finalize:
        recorder.finalize()
    return recorder


def test_verified_status():
    recorder = _session()
    report = verify_artifact(recorder.artifact())
    assert report.status == VerificationStatus.VERIFIED
    assert report.verified
    assert report.summary["event_count"] == recorder.event_count


def test_redacted_status_is_distinct_from_verified():
    recorder = _session(secret=True)
    report = verify_artifact(recorder.artifact())
    assert report.status == VerificationStatus.REDACTED
    assert report.verified  # integrity intact
    assert any(
        finding.code == "session_incomplete"
        for finding in report.findings
    ) is False


def test_incomplete_status_when_not_finalized():
    recorder = _session(finalize=False)
    report = verify_artifact(recorder.artifact())
    assert report.status == VerificationStatus.INCOMPLETE
    assert not report.verified
    codes = {finding.code for finding in report.findings}
    assert "session_incomplete" in codes


def test_unverifiable_for_garbage():
    assert (
        verify_artifact("this is not json").status
        == VerificationStatus.UNVERIFIABLE
    )
    assert (
        verify_artifact({"afw": 9}).status
        == VerificationStatus.UNVERIFIABLE
    )
    assert (
        verify_artifact({"afw": 1, "format": "nope", "format_version": 1}).status
        == VerificationStatus.UNVERIFIABLE
    )


def test_tampered_event_payload_fails():
    recorder = _session()
    artifact = recorder.artifact()
    # Flip a recorded denial into an allow: chain hash breaks.
    artifact["events"][3]["payload"]["allowed"] = True
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "event_hash_invalid"
        for finding in report.findings
    )


def test_reordered_events_fail():
    recorder = _session()
    artifact = recorder.artifact()
    artifact["events"][1], artifact["events"][2] = (
        artifact["events"][2],
        artifact["events"][1],
    )
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    codes = {finding.code for finding in report.findings}
    assert "event_ordering_invalid" in codes
    assert "event_chain_broken" in codes


def test_deleted_event_fails():
    recorder = _session()
    artifact = recorder.artifact()
    del artifact["events"][2]
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    codes = {finding.code for finding in report.findings}
    assert "event_ordering_invalid" in codes


def test_forged_checkpoint_signature_fails():
    recorder = _session()
    artifact = recorder.artifact()
    checkpoint = artifact["checkpoints"][-1]
    checkpoint["signature"] = "A" * len(checkpoint["signature"])
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "checkpoint_signature_invalid"
        for finding in report.findings
    )


def test_checkpoint_anchor_mismatch_fails():
    recorder = _session()
    artifact = recorder.artifact()
    artifact["checkpoints"][-1]["event_hash"] = "0" * 64
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "checkpoint_anchor_mismatch"
        for finding in report.findings
    )


def test_recorder_identity_inconsistency_fails():
    recorder = _session()
    artifact = recorder.artifact()
    artifact["recorder"]["fingerprint"] = "0" * 64
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "recorder_identity_inconsistent"
        for finding in report.findings
    )


def test_expect_recorder_pinning():
    recorder = _session()
    report = verify_artifact(
        recorder.artifact(),
        expect_recorder=recorder.identity_fingerprint,
    )
    assert report.status == VerificationStatus.VERIFIED

    report = verify_artifact(
        recorder.artifact(),
        expect_recorder="0" * 64,
    )
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "recorder_not_expected"
        for finding in report.findings
    )


def test_finalized_artifact_missing_terminal_event_fails():
    recorder = _session()
    artifact = recorder.artifact()
    assert artifact["events"][-1]["type"] == "session_ended"
    del artifact["events"][-1]
    artifact["session"]["ended_at"] = None
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "session_terminal_event_missing"
        for finding in report.findings
    )


def test_verifier_reports_all_findings_not_just_first():
    recorder = _session()
    artifact = recorder.artifact()
    artifact["events"][2]["payload"]["reason"] = "changed"
    artifact["checkpoints"][-1]["signature"] = "B" * 88
    report = verify_artifact(artifact)
    codes = {finding.code for finding in report.findings}
    assert "event_hash_invalid" in codes
    assert "checkpoint_signature_invalid" in codes


def test_verify_artifact_path(tmp_path):
    recorder = _session()
    path = tmp_path / "s.afw"
    from firewall.artifact import write_artifact

    write_artifact(recorder.artifact(), path)
    report = verify_artifact_path(path)
    assert report.status == VerificationStatus.VERIFIED


def test_report_json_serializable():
    recorder = _session(secret=True)
    report = verify_artifact(recorder.artifact())
    payload = json.loads(report.to_json())
    assert payload["status"] == "redacted"
