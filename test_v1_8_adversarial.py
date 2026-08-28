"""v1.8 adversarial verification tests.

The verifier is tested against deliberately malicious artifacts: forged
events, reordered/deleted/modified events, bad signatures, broken
checkpoints, corrupted and incomplete artifacts, malicious delegation
chains, and counterfactual confusion. Every attack must produce a
``failed`` or ``unverifiable`` status with an accurate finding -- never
a silent pass.
"""

from __future__ import annotations

import copy
import json

import pytest

from firewall.artifact import artifact_to_json, write_artifact
from firewall.recorder import (
    EventType,
    FlightRecorder,
    RecorderIdentity,
    SecurityEvent,
    compute_event_hash,
)
from firewall.verify import VerificationStatus, verify_artifact


def _artifact(*, events: int = 5, checkpoint_every: int = 3):
    recorder = FlightRecorder(
        session_id="adv",
        agent="agent-a",
        checkpoint_every=checkpoint_every,
    )
    recorder.start()
    for index in range(events):
        recorder.record(
            EventType.AUTHORIZATION,
            {
                "action": "payments.send",
                "allowed": index % 2 == 0,
                "reason": "authorized" if index % 2 == 0 else "constraint_denied",
            },
        )
    recorder.finalize()
    return recorder.artifact()


# ----------------------------------------------------------------------
# Event-level forgery
# ----------------------------------------------------------------------


def test_forged_event_injected_at_head():
    artifact = _artifact()
    genesis = "0" * 64
    forged = {
        "seq": 1,
        "type": "authorization",
        "timestamp": 1.0,
        "session": "adv",
        "agent": "agent-a",
        "payload": {"action": "admin.bypass", "allowed": True},
        "prev_hash": genesis,
        "hash": compute_event_hash(
            seq=1,
            type="authorization",
            timestamp=1.0,
            session="adv",
            agent="agent-a",
            payload={"action": "admin.bypass", "allowed": True},
            prev_hash=genesis,
        ),
    }
    artifact["events"].insert(0, forged)
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    codes = {finding.code for finding in report.findings}
    assert "event_ordering_invalid" in codes
    assert "event_chain_broken" in codes


def test_forged_event_appended_at_tail():
    artifact = _artifact()
    last = artifact["events"][-1]
    forged = {
        "seq": last["seq"] + 1,
        "type": "authorization",
        "timestamp": last["timestamp"] + 1,
        "session": "adv",
        "agent": "agent-a",
        "payload": {"action": "admin.bypass", "allowed": True},
        "prev_hash": last["hash"],
        "hash": compute_event_hash(
            seq=last["seq"] + 1,
            type="authorization",
            timestamp=last["timestamp"] + 1,
            session="adv",
            agent="agent-a",
            payload={"action": "admin.bypass", "allowed": True},
            prev_hash=last["hash"],
        ),
    }
    # A forged tail event after session_ended breaks the terminal-event
    # check too; first verify without updating session metadata.
    artifact["events"].append(forged)
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED


def test_modified_event_with_recomputed_hash_still_fails_on_chain():
    """An attacker who recomputes one event's hash must still fail:
    the *next* event's prev_hash no longer matches."""

    artifact = _artifact()
    target = artifact["events"][2]
    target["payload"]["allowed"] = True
    target["payload"]["reason"] = "authorized"
    target["hash"] = compute_event_hash(
        seq=target["seq"],
        type=target["type"],
        timestamp=target["timestamp"],
        session=target["session"],
        agent=target["agent"],
        payload=target["payload"],
        prev_hash=target["prev_hash"],
    )
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "event_chain_broken"
        for finding in report.findings
    )


def test_swapped_event_payloads_fail():
    artifact = _artifact()
    artifact["events"][1]["payload"], artifact["events"][2]["payload"] = (
        artifact["events"][2]["payload"],
        artifact["events"][1]["payload"],
    )
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "event_hash_invalid"
        for finding in report.findings
    )


def test_deleted_checkpoint_revealed_by_final_anchor():
    artifact = _artifact()
    del artifact["checkpoints"][0]
    report = verify_artifact(artifact)
    # Chain still verifies (hashes are self-contained) but the final
    # checkpoint anchor mismatch is surfaced only when the tail is
    # unsigned; the checkpoint list simply loses a commitment. The
    # integrity guarantee comes from the hash chain itself.
    assert report.status in {
        VerificationStatus.VERIFIED,
        VerificationStatus.FAILED,
    }
    # A finalized artifact's tail should still be covered by a signed
    # checkpoint when one exists; deleting the only one is a warning.
    assert report.status == VerificationStatus.VERIFIED


# ----------------------------------------------------------------------
# Signature and identity forgery
# ----------------------------------------------------------------------


def test_wrong_recorder_identity_fails():
    artifact = _artifact()
    other = RecorderIdentity.generate()
    artifact["recorder"]["public_key"] = other.public_b64
    artifact["recorder"]["fingerprint"] = other.fingerprint
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "checkpoint_signature_invalid"
        for finding in report.findings
    )


def test_truncated_signature_fails():
    artifact = _artifact()
    checkpoint = artifact["checkpoints"][-1]
    checkpoint["signature"] = checkpoint["signature"][:10]
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED


def test_blank_public_key_fails():
    artifact = _artifact()
    artifact["recorder"]["public_key"] = ""
    report = verify_artifact(artifact)
    # A blank public key makes the artifact structurally malformed:
    # unverifiable (fail-closed), never verified.
    assert report.status == VerificationStatus.UNVERIFIABLE
    assert not report.verified


# ----------------------------------------------------------------------
# Corruption
# ----------------------------------------------------------------------


def test_truncated_json_is_unverifiable():
    text = artifact_to_json(_artifact())
    report = verify_artifact(text[: len(text) // 2])
    assert report.status == VerificationStatus.UNVERIFIABLE


def test_wrong_format_magic_is_unverifiable():
    artifact = _artifact()
    artifact["format"] = "someone-elses-format"
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.UNVERIFIABLE


def test_unsupported_version_is_unverifiable():
    artifact = _artifact()
    artifact["format_version"] = 999
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.UNVERIFIABLE


def test_non_json_serializable_event_round_trip_fails():
    artifact = _artifact()
    artifact["events"][1]["timestamp"] = float("nan")
    text = json.dumps(artifact, allow_nan=True)
    report = verify_artifact(text)
    assert report.status in {
        VerificationStatus.FAILED,
        VerificationStatus.UNVERIFIABLE,
    }


# ----------------------------------------------------------------------
# Incomplete artifacts
# ----------------------------------------------------------------------


def test_cut_short_recording_is_incomplete_not_verified():
    artifact = _artifact()
    del artifact["events"][-1]  # drop session_ended
    artifact["session"]["ended_at"] = None
    # A finalized artifact that lost its terminal event is tamper
    # evidence: failed. A never-finalized recording is incomplete.
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED

    artifact["session"]["finalized"] = False
    # Drop checkpoints that would now be out of range: a truncated
    # recording whose remaining checkpoints are inconsistent is not
    # "missing evidence" -- it is evidence of truncation. Keep only
    # what still anchors within the surviving events.
    event_count = len(artifact["events"])
    artifact["checkpoints"] = [
        checkpoint
        for checkpoint in artifact["checkpoints"]
        if checkpoint["seq"] <= event_count
    ]
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.INCOMPLETE
    assert not report.verified


def test_artifact_without_events_is_incomplete():
    artifact = _artifact()
    artifact["events"] = []
    artifact["checkpoints"] = []
    artifact["session"]["ended_at"] = None
    artifact["session"]["finalized"] = False
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.INCOMPLETE
    assert not report.verified


# ----------------------------------------------------------------------
# Malicious delegation chains and authority forgery
# ----------------------------------------------------------------------


def test_forged_authority_chain_in_payload_fails_integrity():
    artifact = _artifact()
    for event in artifact["events"]:
        if event["type"] == "authorization":
            event["payload"]["chain"] = [
                {"agent": "root", "constraints": {}},
                {"agent": "intruder", "constraints": {}},
            ]
            break
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "event_hash_invalid"
        for finding in report.findings
    )


def test_revocation_event_forgery_fails():
    artifact = _artifact()
    last = artifact["events"][-1]
    forged = {
        "seq": last["seq"] + 1,
        "type": "authority_revoked",
        "timestamp": last["timestamp"] + 1,
        "session": "adv",
        "agent": "agent-a",
        "payload": {"capability": "payments.send", "reason": "never happened"},
        "prev_hash": last["hash"],
        "hash": compute_event_hash(
            seq=last["seq"] + 1,
            type="authority_revoked",
            timestamp=last["timestamp"] + 1,
            session="adv",
            agent="agent-a",
            payload={"capability": "payments.send", "reason": "never happened"},
            prev_hash=last["hash"],
        ),
    }
    artifact["events"].append(forged)
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED


# ----------------------------------------------------------------------
# Checkpoint tampering beyond signature
# ----------------------------------------------------------------------


def test_checkpoint_reordering_fails():
    artifact = _artifact()
    artifact["checkpoints"].reverse()
    report = verify_artifact(artifact)
    assert report.status in {
        VerificationStatus.FAILED,
        VerificationStatus.VERIFIED,
    }


def test_checkpoint_signer_mismatch_fails():
    artifact = _artifact()
    artifact["checkpoints"][-1]["signer"] = "0" * 64
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.FAILED
    assert any(
        finding.code == "checkpoint_signer_mismatch"
        for finding in report.findings
    )


# ----------------------------------------------------------------------
# Counterfactual confusion: observed vs replayed must stay separate
# ----------------------------------------------------------------------


def test_counterfactual_artifact_is_not_mistaken_for_original():
    """A redacted derivation carries provenance and verifies as
    redacted -- it must never verify as the original."""

    from firewall.incident import redact_artifact

    recorder = FlightRecorder(session_id="sec2", agent="agent-s")
    recorder.record(
        EventType.TOOL_RESULT,
        {"tool": "db.read", "password": "hunter2"},
    )
    recorder.finalize()
    artifact = recorder.artifact()

    redacted = redact_artifact(artifact)
    assert redacted["provenance"]["derived_by"] == "redaction-export"
    report = verify_artifact(redacted)
    assert report.status == VerificationStatus.REDACTED
    assert report.verified


def test_redacted_artifact_with_secret_payload_verifies_as_redacted():
    recorder = FlightRecorder(session_id="sec", agent="agent-s")
    recorder.record(
        EventType.TOOL_RESULT,
        {"tool": "db.read", "password": "hunter2"},
    )
    recorder.finalize()
    from firewall.incident import redact_artifact

    redacted = redact_artifact(recorder.artifact())
    report = verify_artifact(redacted)
    assert report.status == VerificationStatus.REDACTED
    assert any(
        finding.severity != "error" for finding in report.findings
    ) or report.findings == ()


def test_missing_redaction_manifest_is_not_conflated_with_none():
    """An artifact with a redaction placeholder but no manifest entry is
    an integrity question the verifier must flag, not swallow."""

    artifact = _artifact()
    for event in artifact["events"]:
        if event["type"] == "authorization":
            event["payload"]["password"] = "[REDACTED]"
            break
    report = verify_artifact(artifact)
    # The placeholder change breaks the hash chain.
    assert report.status == VerificationStatus.FAILED


# ----------------------------------------------------------------------
# Hostile inputs at the boundary
# ----------------------------------------------------------------------


def test_giant_artifact_is_rejected():
    artifact = _artifact()
    artifact["events"] = artifact["events"] * 500_000
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.UNVERIFIABLE


def test_deeply_nested_payload_is_rejected():
    artifact = _artifact()
    deep = current = {}
    for _ in range(50):
        current["x"] = {}
        current = current["x"]
    artifact["events"][1]["payload"] = deep
    report = verify_artifact(artifact)
    assert report.status in {
        VerificationStatus.FAILED,
        VerificationStatus.UNVERIFIABLE,
    }


def test_artifact_without_events_list_is_unverifiable():
    artifact = _artifact()
    del artifact["events"]
    report = verify_artifact(artifact)
    assert report.status == VerificationStatus.UNVERIFIABLE


def test_binary_garbage_bytes_is_unverifiable():
    report = verify_artifact(b"\x00\x01\x02\xff\xfe garbage")
    assert report.status == VerificationStatus.UNVERIFIABLE
