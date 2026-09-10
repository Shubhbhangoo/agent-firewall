from __future__ import annotations

import threading

import pytest

from firewall.lifecycle import (
    LifecycleEvent,
    LifecycleEventType,
)

from firewall.lifecycle_store import (
    LifecycleStoreClosedError,
    LifecycleStoreError,
    SQLiteLifecycleStore,
)


_UNSET = object()


def make_event(
    event_type=LifecycleEventType.USED,
    fingerprint="fp-1",
    timestamp=100.0,
    agent_id="agent-a",
    capability="payments.send",
    issuer="trusted-issuer",
    reason="",
    request_id="req-1",
    details=_UNSET,
):
    if details is _UNSET:
        details = {
            "action": "payments.send",
            "amount": 10,
        }

    return LifecycleEvent(
        event_type=event_type,
        fingerprint=fingerprint,
        timestamp=timestamp,
        agent_id=agent_id,
        capability=capability,
        issuer=issuer,
        reason=reason,
        request_id=request_id,
        details=details,
    )


# ============================================================
# Initialization
# ============================================================


def test_store_initializes(tmp_path):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    assert store.closed is False
    assert store.size() == 0

    store.close()


def test_database_file_is_created(tmp_path):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    assert path.exists()

    store.close()


def test_parent_directory_is_created(tmp_path):
    path = (
        tmp_path
        / "nested"
        / "state"
        / "lifecycle.db"
    )

    store = SQLiteLifecycleStore(path)

    assert path.exists()

    store.close()


# ============================================================
# Append
# ============================================================


def test_append_event(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    event = make_event()

    store.append(event)

    assert store.size() == 1

    store.close()


def test_appended_event_is_returned(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    event = make_event()

    store.append(event)

    events = store.events()

    assert len(events) == 1
    assert events[0] == event

    store.close()


def test_append_preserves_all_fields(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    event = make_event(
        event_type=LifecycleEventType.DENIED,
        fingerprint="abc",
        timestamp=123.5,
        agent_id="agent-z",
        capability="admin.read",
        issuer="issuer-x",
        reason="policy_denied",
        request_id="request-42",
        details={
            "action": "admin.read",
            "request": {
                "id": 5,
            },
        },
    )

    store.append(event)

    actual = store.events()[0]

    assert actual.event_type == (
        LifecycleEventType.DENIED
    )
    assert actual.fingerprint == "abc"
    assert actual.timestamp == 123.5
    assert actual.agent_id == "agent-z"
    assert actual.capability == "admin.read"
    assert actual.issuer == "issuer-x"
    assert actual.reason == "policy_denied"
    assert actual.request_id == "request-42"
    assert actual.details == {
        "action": "admin.read",
        "request": {
            "id": 5,
        },
    }

    store.close()


# ============================================================
# Ordering
# ============================================================


def test_events_preserve_insertion_order(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    first = make_event(
        event_type=LifecycleEventType.ISSUED,
        fingerprint="a",
        timestamp=1.0,
    )

    second = make_event(
        event_type=LifecycleEventType.DELEGATED,
        fingerprint="b",
        timestamp=2.0,
    )

    third = make_event(
        event_type=LifecycleEventType.REVOKED,
        fingerprint="c",
        timestamp=3.0,
    )

    store.append(first)
    store.append(second)
    store.append(third)

    events = store.events()

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.DELEGATED,
        LifecycleEventType.REVOKED,
    ]

    assert [
        event.fingerprint
        for event in events
    ] == [
        "a",
        "b",
        "c",
    ]

    store.close()


# ============================================================
# Restart persistence
# ============================================================


def test_events_survive_restart(tmp_path):
    path = tmp_path / "lifecycle.db"

    first = SQLiteLifecycleStore(path)

    event = make_event(
        fingerprint="persistent",
        timestamp=42.0,
    )

    first.append(event)
    first.close()

    second = SQLiteLifecycleStore(path)

    events = second.events()

    assert len(events) == 1
    assert events[0] == event

    second.close()


def test_multiple_events_survive_restart(tmp_path):
    path = tmp_path / "lifecycle.db"

    first = SQLiteLifecycleStore(path)

    events = [
        make_event(
            fingerprint="a",
            timestamp=1.0,
        ),
        make_event(
            fingerprint="b",
            timestamp=2.0,
        ),
        make_event(
            fingerprint="c",
            timestamp=3.0,
        ),
    ]

    for event in events:
        first.append(event)

    first.close()

    second = SQLiteLifecycleStore(path)

    assert second.events() == tuple(
        events
    )
    assert second.size() == 3

    second.close()


# ============================================================
# Filtering
# ============================================================


def test_filter_by_fingerprint(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    first = make_event(
        fingerprint="same",
        timestamp=1.0,
    )

    second = make_event(
        fingerprint="other",
        timestamp=2.0,
    )

    third = make_event(
        fingerprint="same",
        timestamp=3.0,
    )

    store.append(first)
    store.append(second)
    store.append(third)

    result = store.for_fingerprint(
        "same"
    )

    assert result == (
        first,
        third,
    )

    store.close()


def test_filter_by_event_type(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    issued = make_event(
        event_type=LifecycleEventType.ISSUED,
    )

    used = make_event(
        event_type=LifecycleEventType.USED,
    )

    revoked = make_event(
        event_type=LifecycleEventType.REVOKED,
    )

    store.append(issued)
    store.append(used)
    store.append(revoked)

    result = store.of_type(
        LifecycleEventType.REVOKED
    )

    assert result == (
        revoked,
    )

    store.close()


def test_filter_preserves_global_order(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    first = make_event(
        fingerprint="x",
        timestamp=1,
    )

    second = make_event(
        fingerprint="y",
        timestamp=2,
    )

    third = make_event(
        fingerprint="x",
        timestamp=3,
    )

    store.append(first)
    store.append(second)
    store.append(third)

    assert store.for_fingerprint(
        "x"
    ) == (
        first,
        third,
    )

    store.close()


# ============================================================
# Details
# ============================================================


def test_none_details_round_trip(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    event = make_event(
        details=None
    )

    assert event.details is None

    store.append(event)

    actual = store.events()[0]

    assert actual.details is None

    store.close()


def test_nested_details_round_trip(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    details = {
        "request": {
            "payment": {
                "amount": 10,
            }
        },
        "items": [
            {
                "id": 1,
            },
        ],
    }

    event = make_event(
        details=details
    )

    store.append(event)

    actual = store.events()[0]

    assert actual.details == details

    store.close()


def test_non_json_details_are_rejected(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    event = make_event(
        details={
            "bad": object()
        }
    )

    with pytest.raises(
        LifecycleStoreError
    ):
        store.append(event)

    store.close()


# ============================================================
# Validation
# ============================================================


def test_non_event_rejected(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    with pytest.raises(TypeError):
        store.append(
            "not-an-event"
        )

    store.close()


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
def test_invalid_event_fingerprint_rejected(
    tmp_path,
    fingerprint,
):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    event = make_event(
        fingerprint=fingerprint
    )

    with pytest.raises(
        (TypeError, ValueError)
    ):
        store.append(event)

    store.close()


# ============================================================
# Empty snapshots
# ============================================================


def test_empty_events_returns_tuple(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    assert store.events() == ()
    assert isinstance(
        store.events(),
        tuple,
    )

    store.close()


def test_empty_filter_returns_tuple(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    assert store.for_fingerprint(
        "missing"
    ) == ()

    assert store.of_type(
        LifecycleEventType.USED
    ) == ()

    store.close()


# ============================================================
# Close behavior
# ============================================================


def test_close_is_idempotent(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    store.close()
    store.close()

    assert store.closed is True


def test_append_after_close_rejected(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    store.close()

    with pytest.raises(
        LifecycleStoreClosedError
    ):
        store.append(
            make_event()
        )


def test_events_after_close_rejected(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    store.close()

    with pytest.raises(
        LifecycleStoreClosedError
    ):
        store.events()


def test_size_after_close_rejected(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    store.close()

    with pytest.raises(
        LifecycleStoreClosedError
    ):
        store.size()


# ============================================================
# Context manager
# ============================================================


def test_context_manager_closes_store(tmp_path):
    path = tmp_path / "lifecycle.db"

    with SQLiteLifecycleStore(
        path
    ) as store:
        store.append(
            make_event()
        )

        assert store.closed is False

    assert store.closed is True


# ============================================================
# Repeated reads
# ============================================================


def test_repeated_reads_are_stable(tmp_path):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    events = [
        make_event(
            fingerprint="a",
            timestamp=1.0,
        ),
        make_event(
            fingerprint="b",
            timestamp=2.0,
        ),
    ]

    for event in events:
        store.append(event)

    assert (
        store.events()
        == store.events()
    )

    assert (
        store.for_fingerprint("a")
        == store.for_fingerprint("a")
    )

    assert (
        store.of_type(
            LifecycleEventType.USED
        )
        == store.of_type(
            LifecycleEventType.USED
        )
    )

    store.close()


# ============================================================
# All lifecycle event types
# ============================================================


@pytest.mark.parametrize(
    "event_type",
    list(
        LifecycleEventType
    ),
)
def test_all_lifecycle_event_types_persist(
    tmp_path,
    event_type,
):
    path = tmp_path / "lifecycle.db"

    first = SQLiteLifecycleStore(
        path
    )

    event = make_event(
        event_type=event_type,
        fingerprint=event_type.value,
    )

    first.append(event)
    first.close()

    second = SQLiteLifecycleStore(
        path
    )

    events = second.of_type(
        event_type
    )

    assert len(events) == 1
    assert (
        events[0].event_type
        == event_type
    )
    assert (
        events[0].fingerprint
        == event_type.value
    )

    second.close()


# ============================================================
# Large event history
# ============================================================


def test_large_event_history_round_trip(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    events = [
        make_event(
            fingerprint=f"fp-{index}",
            timestamp=float(index),
        )
        for index in range(250)
    ]

    for event in events:
        store.append(event)

    assert store.size() == 250
    assert store.events() == tuple(
        events
    )

    store.close()


# ============================================================
# Concurrent append
# ============================================================


def test_concurrent_appends_from_one_store(
    tmp_path,
):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            store.append(
                make_event(
                    fingerprint=f"fp-{index}",
                    timestamp=float(index),
                )
            )
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert store.size() == 50

    store.close()


# ============================================================
# Two store instances
# ============================================================


def test_two_store_instances_share_state(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = SQLiteLifecycleStore(path)
    second = SQLiteLifecycleStore(path)

    event = make_event(
        fingerprint="shared"
    )

    first.append(event)

    assert second.events() == (
        event,
    )

    second.close()
    first.close()


def test_second_store_sees_later_events(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = SQLiteLifecycleStore(path)
    second = SQLiteLifecycleStore(path)

    first.append(
        make_event(
            fingerprint="first"
        )
    )

    assert second.size() == 1

    first.append(
        make_event(
            fingerprint="second"
        )
    )

    assert second.size() == 2

    second.close()
    first.close()