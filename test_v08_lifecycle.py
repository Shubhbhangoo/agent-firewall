import pytest

from firewall.lifecycle import (
    LifecycleEvent,
    LifecycleEventType,
    LifecycleRecorder,
)


# ============================================================
# Event types
# ============================================================


def test_all_expected_event_types_exist():
    assert (
        LifecycleEventType.ISSUED.value
        == "issued"
    )

    assert (
        LifecycleEventType.DELEGATED.value
        == "delegated"
    )

    assert (
        LifecycleEventType.ATTENUATED.value
        == "attenuated"
    )

    assert (
        LifecycleEventType.USED.value
        == "used"
    )

    assert (
        LifecycleEventType.DENIED.value
        == "denied"
    )

    assert (
        LifecycleEventType.REPLAYED.value
        == "replayed"
    )

    assert (
        LifecycleEventType.REVOKED.value
        == "revoked"
    )

    assert (
        LifecycleEventType.EXPIRED.value
        == "expired"
    )


# ============================================================
# Initialization
# ============================================================


def test_recorder_initializes():
    recorder = LifecycleRecorder()

    assert recorder.size() == 0
    assert recorder.events() == ()


# ============================================================
# Recording
# ============================================================


def test_record_returns_event():
    recorder = LifecycleRecorder(
        clock=lambda: 1000.0
    )

    event = recorder.record(
        LifecycleEventType.ISSUED,
        "abc123",
    )

    assert isinstance(
        event,
        LifecycleEvent,
    )


def test_record_preserves_fields():
    recorder = LifecycleRecorder(
        clock=lambda: 1000.0
    )

    event = recorder.record(
        LifecycleEventType.REVOKED,
        "abc123",
        agent_id="agent-a",
        capability="payments.send",
        issuer="trusted-issuer",
        reason="compromised",
        request_id="req-1",
        details={
            "source": "security-review"
        },
    )

    assert (
        event.event_type
        == LifecycleEventType.REVOKED
    )

    assert event.fingerprint == "abc123"
    assert event.timestamp == 1000.0
    assert event.agent_id == "agent-a"
    assert event.capability == "payments.send"
    assert event.issuer == "trusted-issuer"
    assert event.reason == "compromised"
    assert event.request_id == "req-1"

    assert event.details == {
        "source": "security-review"
    }


def test_record_defaults_are_safe():
    recorder = LifecycleRecorder()

    event = recorder.record(
        LifecycleEventType.USED,
        "abc123",
    )

    assert event.agent_id is None
    assert event.capability is None
    assert event.issuer is None
    assert event.reason == ""
    assert event.request_id == ""
    assert event.details is None


# ============================================================
# Validation
# ============================================================


def test_invalid_event_type_rejected():
    recorder = LifecycleRecorder()

    with pytest.raises(TypeError):
        recorder.record(
            "issued",
            "abc123",
        )


@pytest.mark.parametrize(
    "fingerprint",
    [
        "",
        " ",
        None,
        123,
        [],
        {},
    ],
)
def test_invalid_fingerprint_rejected(
    fingerprint,
):
    recorder = LifecycleRecorder()

    with pytest.raises(
        (TypeError, ValueError)
    ):
        recorder.record(
            LifecycleEventType.ISSUED,
            fingerprint,
        )


def test_empty_details_are_allowed():
    recorder = LifecycleRecorder()

    event = recorder.record(
        LifecycleEventType.USED,
        "abc123",
        details={},
    )

    assert event.details == {}


def test_non_dict_details_rejected():
    recorder = LifecycleRecorder()

    with pytest.raises(TypeError):
        recorder.record(
            LifecycleEventType.USED,
            "abc123",
            details=[],
        )


# ============================================================
# Append-only behavior
# ============================================================


def test_events_are_append_only():
    recorder = LifecycleRecorder()

    recorder.record(
        LifecycleEventType.ISSUED,
        "abc123",
    )

    recorder.record(
        LifecycleEventType.USED,
        "abc123",
    )

    assert recorder.size() == 2


def test_events_returns_tuple():
    recorder = LifecycleRecorder()

    recorder.record(
        LifecycleEventType.ISSUED,
        "abc123",
    )

    assert isinstance(
        recorder.events(),
        tuple,
    )


def test_no_delete_api():
    recorder = LifecycleRecorder()

    assert not hasattr(
        recorder,
        "delete",
    )

    assert not hasattr(
        recorder,
        "remove",
    )

    assert not hasattr(
        recorder,
        "clear",
    )


# ============================================================
# Filtering
# ============================================================


def test_filter_by_fingerprint():
    recorder = LifecycleRecorder()

    recorder.record(
        LifecycleEventType.ISSUED,
        "a",
    )

    recorder.record(
        LifecycleEventType.ISSUED,
        "b",
    )

    recorder.record(
        LifecycleEventType.REVOKED,
        "a",
    )

    events = recorder.for_fingerprint(
        "a"
    )

    assert len(events) == 2
    assert all(
        event.fingerprint == "a"
        for event in events
    )


def test_filter_by_type():
    recorder = LifecycleRecorder()

    recorder.record(
        LifecycleEventType.ISSUED,
        "a",
    )

    recorder.record(
        LifecycleEventType.REVOKED,
        "a",
    )

    recorder.record(
        LifecycleEventType.REVOKED,
        "b",
    )

    revoked = recorder.of_type(
        LifecycleEventType.REVOKED
    )

    assert len(revoked) == 2


def test_filter_preserves_order():
    recorder = LifecycleRecorder(
        clock=iter(
            [
                1.0,
                2.0,
                3.0,
            ]
        ).__next__
    )

    recorder.record(
        LifecycleEventType.ISSUED,
        "a",
    )

    recorder.record(
        LifecycleEventType.USED,
        "a",
    )

    recorder.record(
        LifecycleEventType.REVOKED,
        "a",
    )

    events = recorder.for_fingerprint(
        "a"
    )

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REVOKED,
    ]


# ============================================================
# Serialization
# ============================================================


def test_event_to_dict():
    recorder = LifecycleRecorder(
        clock=lambda: 42.0
    )

    event = recorder.record(
        LifecycleEventType.REVOKED,
        "abc123",
        agent_id="agent-a",
        reason="stolen",
        details={
            "source": "test"
        },
    )

    data = event.to_dict()

    assert data == {
        "event_type": "revoked",
        "fingerprint": "abc123",
        "timestamp": 42.0,
        "agent_id": "agent-a",
        "capability": None,
        "issuer": None,
        "reason": "stolen",
        "request_id": "",
        "details": {
            "source": "test"
        },
    }


def test_to_dict_does_not_expose_mutable_details():
    details = {
        "value": 1
    }

    recorder = LifecycleRecorder()

    event = recorder.record(
        LifecycleEventType.USED,
        "abc123",
        details=details,
    )

    details["value"] = 999

    assert event.details == {
        "value": 1
    }


# ============================================================
# State snapshots
# ============================================================


def test_snapshot_is_stable():
    recorder = LifecycleRecorder()

    recorder.record(
        LifecycleEventType.ISSUED,
        "abc123",
    )

    snapshot = recorder.events()

    recorder.record(
        LifecycleEventType.USED,
        "abc123",
    )

    assert len(snapshot) == 1
    assert recorder.size() == 2