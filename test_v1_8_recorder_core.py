"""v1.8 recorder core unit tests: encoding, events, chain, identity,
checkpoints, and artifact determinism."""

from __future__ import annotations

import json

import pytest

from firewall.artifact import (
    artifact_from_json,
    artifact_from_path,
    artifact_to_bytes,
    validate_manifest,
    write_artifact,
)
from firewall.recorder import (
    EventType,
    FlightRecorder,
    GENESIS_HASH,
    RecorderError,
    RecorderIdentity,
    canonical_bytes,
    compute_event_hash,
    redact_payload,
    sign_checkpoint,
    verify_signature,
)
from firewall.verify import verify_artifact


# ----------------------------------------------------------------------
# Canonical encoding
# ----------------------------------------------------------------------


def test_canonical_encoding_is_key_sorted_and_compact():
    left = canonical_bytes({"b": 1, "a": "x"})
    right = canonical_bytes({"a": "x", "b": 1})
    assert left == right
    assert b" " not in left.replace(b"a", b"")


def test_canonical_encoding_rejects_non_finite():
    from firewall.recorder import EncodingError

    with pytest.raises(EncodingError):
        canonical_bytes({"x": float("nan")})
    with pytest.raises(EncodingError):
        canonical_bytes({"x": float("inf")})


def test_canonical_encoding_is_utf8():
    data = canonical_bytes({"note": "caf\u00e9"})
    assert data.decode("utf-8") == '{"note":"caf\u00e9"}'


# ----------------------------------------------------------------------
# Event hashing
# ----------------------------------------------------------------------


def test_event_hash_links_previous():
    first = compute_event_hash(
        seq=1,
        type="session_started",
        timestamp=1.0,
        session="s",
        agent="a",
        payload={"session": "s"},
        prev_hash=GENESIS_HASH,
    )
    second = compute_event_hash(
        seq=2,
        type="authorization",
        timestamp=2.0,
        session="s",
        agent="a",
        payload={"action": "x", "allowed": True},
        prev_hash=first,
    )
    assert len(first) == 64
    assert second != first


def test_event_recompute_hash_matches_recorded():
    recorder = FlightRecorder(session_id="s", agent="a")
    recorder.start()
    recorder.record(
        EventType.AUTHORIZATION,
        {"action": "a", "allowed": True},
    )
    event = recorder.events()[-1]
    assert event.hash == event.recompute_hash()
    assert event.hash == compute_event_hash(
        seq=event.seq,
        type=event.type.value,
        timestamp=event.timestamp,
        session=event.session,
        agent=event.agent,
        payload=event.payload,
        prev_hash=event.prev_hash,
    )


def test_event_rejects_malformed_inputs():
    from firewall.recorder import SecurityEvent

    with pytest.raises(RecorderError):
        SecurityEvent.from_dict(
            {"seq": 0, "type": "authorization", "timestamp": 1.0}
        )
    with pytest.raises(RecorderError):
        SecurityEvent.from_dict(
            {"seq": 1, "type": "not_a_type", "timestamp": 1.0}
        )
    with pytest.raises(RecorderError):
        SecurityEvent.from_dict(
            {"seq": 1, "type": "authorization", "timestamp": float("nan")}
        )


# ----------------------------------------------------------------------
# Recorder chain and checkpoints
# ----------------------------------------------------------------------


def test_recorder_auto_starts_and_finalizes():
    recorder = FlightRecorder(session_id="s1", agent="a1")
    recorder.record(
        EventType.AUTHORITY_ISSUED,
        {"capability": "payments.send"},
    )
    assert recorder.event_count == 2  # auto session_started + issued
    artifact = recorder.finalize()
    assert artifact["session"]["finalized"] is True
    assert artifact["events"][-1]["type"] == "session_ended"


def test_recorder_cannot_record_after_finalize():
    recorder = FlightRecorder(session_id="s2", agent="a2")
    recorder.start()
    recorder.finalize()
    with pytest.raises(RecorderError):
        recorder.record(EventType.NOTE, {"text": "late"})


def test_recorder_checkpoint_every_creates_signed_checkpoints():
    recorder = FlightRecorder(
        session_id="s3",
        agent="a3",
        checkpoint_every=3,
    )
    for index in range(10):
        recorder.record(EventType.NOTE, {"text": str(index)})
    checkpoints = recorder.checkpoints()
    assert len(checkpoints) >= 3
    for checkpoint in checkpoints:
        assert checkpoint.signature
        assert checkpoint.event_count == checkpoint.seq


def test_recorder_identity_round_trip():
    identity = RecorderIdentity.generate()
    data = b"hello"
    signature = identity.sign(data)
    assert identity.verify(data, signature)
    assert not identity.verify(b"tampered", signature)
    # standalone verifier with the artifact's public key form
    assert verify_signature(
        public_key_b64=identity.public_b64,
        data=data,
        signature_b64=signature,
    )
    assert not verify_signature(
        public_key_b64=identity.public_b64,
        data=b"tampered",
        signature_b64=signature,
    )


def test_checkpoint_signature_verifies_with_artifact_public_key():
    recorder = FlightRecorder(session_id="s4", agent="a4")
    recorder.start()
    recorder.record(EventType.NOTE, {"text": "one"})
    checkpoint = recorder.checkpoint()
    assert verify_signature(
        public_key_b64=recorder.identity.public_b64,
        data=checkpoint.signed_bytes(),
        signature_b64=checkpoint.signature,
    )


def test_sign_checkpoint_rejects_bad_inputs():
    identity = RecorderIdentity.generate()
    with pytest.raises(RecorderError):
        sign_checkpoint(identity, seq=0, event_hash="0" * 64, event_count=1)
    with pytest.raises(RecorderError):
        sign_checkpoint(identity, seq=1, event_hash="zz", event_count=1)


# ----------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------


def test_redaction_replaces_sensitive_values_and_records_paths():
    redacted, redactions = redact_payload(
        {
            "user": "alice",
            "password": "hunter2",
            "nested": {"api_key": "abc", "ok": 1},
        }
    )
    assert redacted["user"] == "alice"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["api_key"] == "[REDACTED]"
    assert redacted["nested"]["ok"] == 1
    paths = {entry["path"] for entry in redactions}
    assert paths == {"password", "nested.api_key"}


def test_redaction_keeps_non_sensitive_token_words():
    redacted, redactions = redact_payload(
        {"capability": "token.read", "message": "has a token in it"}
    )
    assert redacted["capability"] == "token.read"
    assert redacted["message"] == "has a token in it"
    assert redactions == []


def test_recorder_redacts_before_hashing():
    recorder = FlightRecorder(session_id="s5", agent="a5")
    recorder.record(
        EventType.AUTHORIZATION,
        {"action": "x", "allowed": True, "password": "hunter2"},
    )
    artifact = recorder.finalize()
    assert len(artifact["redactions"]) == 1
    assert artifact["redactions"][0]["path"] == "password"
    event = artifact["events"][-2]  # authorization (before session_ended)
    assert event["payload"].get("password") == "[REDACTED]"


# ----------------------------------------------------------------------
# Artifact round trip
# ----------------------------------------------------------------------


def test_artifact_deterministic_bytes_and_round_trip(tmp_path):
    recorder = FlightRecorder(session_id="s6", agent="a6")
    recorder.record(EventType.NOTE, {"text": "hello"})
    recorder.finalize()
    artifact = recorder.artifact()

    first = artifact_to_bytes(artifact)
    second = artifact_to_bytes(recorder.artifact())
    assert first == second

    path = write_artifact(artifact, tmp_path / "s.afw")
    loaded = artifact_from_path(path)
    assert loaded["session"]["id"] == "s6"
    assert len(loaded["events"]) == len(artifact["events"])


def test_artifact_json_round_trip_preserves_chain():
    recorder = FlightRecorder(session_id="s7", agent="a7")
    for index in range(5):
        recorder.record(EventType.NOTE, {"text": str(index)})
    recorder.finalize()
    artifact = recorder.artifact()

    text = json.dumps(artifact, sort_keys=True)
    parsed = artifact_from_json(text)
    assert validate_manifest(parsed)["session"]["id"] == "s7"

    report = verify_artifact(parsed)
    assert report.status == "verified"


def test_artifact_rejects_bad_envelope():
    with pytest.raises(Exception):
        validate_manifest({"afw": 99})
    with pytest.raises(Exception):
        validate_manifest({"afw": 1, "format": "other", "format_version": 1})


# ----------------------------------------------------------------------
# Determinism across recorder instances
# ----------------------------------------------------------------------


def test_same_events_produce_same_hashes_across_instances():
    def build(session):
        recorder = FlightRecorder(
            session_id=session,
            agent="a",
            clock=lambda: 1234.5,
        )
        recorder.record(
            EventType.AUTHORIZATION,
            {"action": "payments.send", "allowed": True, "depth": 1},
        )
        recorder.finalize()
        return recorder.artifact()

    left = build("same-events")
    right = build("same-events")

    for left_event, right_event in zip(
        left["events"], right["events"]
    ):
        assert left_event["hash"] == right_event["hash"]
        assert left_event["payload"] == right_event["payload"]
