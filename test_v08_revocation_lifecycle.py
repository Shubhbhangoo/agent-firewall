from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.revocation import (
    AlreadyRevokedError,
    RevocationRegistry,
)

from firewall.revocation_store import (
    SQLiteRevocationStore,
)


def test_revoke_creates_revoked_event():
    lifecycle = LifecycleRecorder(
        clock=lambda: 100.0
    )

    registry = RevocationRegistry(
        clock=lambda: 100.0,
        lifecycle_recorder=lifecycle,
    )

    registry.revoke(
        "abc123",
        reason="compromised",
    )

    events = lifecycle.events()

    assert len(events) == 1

    event = events[0]

    assert (
        event.event_type
        == LifecycleEventType.REVOKED
    )

    assert event.fingerprint == "abc123"
    assert event.reason == "compromised"

    assert event.details == {
        "revoked": True,
        "revoked_at": 100.0,
    }


def test_duplicate_revoke_creates_no_second_event():
    lifecycle = LifecycleRecorder()

    registry = RevocationRegistry(
        lifecycle_recorder=lifecycle
    )

    registry.revoke(
        "abc123"
    )

    try:
        registry.revoke(
            "abc123"
        )
    except AlreadyRevokedError:
        pass

    assert lifecycle.size() == 1


def test_multiple_revocations_create_multiple_events():
    lifecycle = LifecycleRecorder()

    registry = RevocationRegistry(
        lifecycle_recorder=lifecycle
    )

    registry.revoke("a")
    registry.revoke("b")
    registry.revoke("c")

    assert lifecycle.size() == 3

    assert [
        event.fingerprint
        for event in lifecycle.events()
    ] == [
        "a",
        "b",
        "c",
    ]


def test_revocation_reason_is_preserved():
    lifecycle = LifecycleRecorder()

    registry = RevocationRegistry(
        lifecycle_recorder=lifecycle
    )

    registry.revoke(
        "abc123",
        reason="private key compromised",
    )

    event = lifecycle.events()[0]

    assert (
        event.reason
        == "private key compromised"
    )


def test_backend_revocation_creates_event(
    tmp_path,
):
    lifecycle = LifecycleRecorder()

    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    registry = RevocationRegistry(
        backend=store,
        lifecycle_recorder=lifecycle,
    )

    registry.revoke(
        "persistent",
        reason="stolen",
    )

    assert lifecycle.size() == 1

    event = lifecycle.events()[0]

    assert (
        event.event_type
        == LifecycleEventType.REVOKED
    )

    assert event.fingerprint == (
        "persistent"
    )

    assert event.reason == "stolen"

    store.close()


def test_backend_duplicate_revoke_creates_no_duplicate_event(
    tmp_path,
):
    lifecycle = LifecycleRecorder()

    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    registry = RevocationRegistry(
        backend=store,
        lifecycle_recorder=lifecycle,
    )

    registry.revoke(
        "persistent"
    )

    try:
        registry.revoke(
            "persistent"
        )
    except AlreadyRevokedError:
        pass

    assert lifecycle.size() == 1

    store.close()


def test_revocation_remains_one_way_with_lifecycle():
    lifecycle = LifecycleRecorder()

    registry = RevocationRegistry(
        lifecycle_recorder=lifecycle
    )

    registry.revoke(
        "abc123"
    )

    assert registry.is_revoked(
        "abc123"
    )

    assert not hasattr(
        registry,
        "unrevoke",
    )

    assert lifecycle.size() == 1