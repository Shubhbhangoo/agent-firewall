from __future__ import annotations

import threading

import pytest

from firewall.lifecycle import (
    LifecycleEvent,
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.lifecycle_store import (
    LifecycleStoreError,
    SQLiteLifecycleStore,
)


def make_event(
    *,
    event_type=LifecycleEventType.USED,
    fingerprint="fp-1",
    timestamp=100.0,
    agent_id="agent-a",
    capability="payments.send",
    issuer="trusted-issuer",
    reason="",
    request_id="req-1",
    details=None,
):
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
# Restart invariants
# ============================================================


def test_restart_preserves_complete_history(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        store=store
    )

    recorder.record(
        LifecycleEventType.ISSUED,
        "fp-1",
    )

    recorder.record(
        LifecycleEventType.DELEGATED,
        "fp-1",
    )

    recorder.record(
        LifecycleEventType.ATTENUATED,
        "fp-2",
    )

    recorder.record(
        LifecycleEventType.USED,
        "fp-2",
    )

    recorder.record(
        LifecycleEventType.REVOKED,
        "fp-2",
        reason="compromised",
    )

    before = recorder.events()

    recorder.close()

    store2 = SQLiteLifecycleStore(path)

    restored = LifecycleRecorder(
        store=store2
    )

    assert restored.events() == before
    assert restored.size() == len(before)

    restored.close()


def test_restart_does_not_duplicate_events(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        store=first
    )

    recorder.record(
        LifecycleEventType.ISSUED,
        "fp-1",
    )

    recorder.close()

    second = SQLiteLifecycleStore(path)

    restored = LifecycleRecorder(
        store=second
    )

    assert restored.size() == 1

    restored.close()

    third = SQLiteLifecycleStore(path)

    restored_again = LifecycleRecorder(
        store=third
    )

    assert restored_again.size() == 1

    restored_again.close()


# ============================================================
# Cross-instance visibility
# ============================================================


def test_second_recorder_sees_new_event(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store1 = SQLiteLifecycleStore(path)
    store2 = SQLiteLifecycleStore(path)

    recorder1 = LifecycleRecorder(
        store=store1
    )

    recorder2 = LifecycleRecorder(
        store=store2
    )

    recorder1.record(
        LifecycleEventType.ISSUED,
        "shared",
    )

    assert recorder2.store.events() == (
        recorder1.events()[0],
    )

    recorder2.close()
    recorder1.close()


def test_second_recorder_sees_later_events(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store1 = SQLiteLifecycleStore(path)
    store2 = SQLiteLifecycleStore(path)

    recorder1 = LifecycleRecorder(
        store=store1
    )

    recorder2 = LifecycleRecorder(
        store=store2
    )

    recorder1.record(
        LifecycleEventType.ISSUED,
        "a",
    )

    recorder1.record(
        LifecycleEventType.USED,
        "a",
    )

    assert recorder2.store.size() == 2

    recorder2.close()
    recorder1.close()


# ============================================================
# Concurrent persistence
# ============================================================


def test_concurrent_append_from_multiple_threads(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            store.append(
                make_event(
                    fingerprint=f"fp-{index}",
                    timestamp=float(index),
                    details={
                        "index": index
                    },
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
        for index in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert store.size() == 100

    fingerprints = {
        event.fingerprint
        for event in store.events()
    }

    assert len(fingerprints) == 100

    store.close()


def test_concurrent_recorders_do_not_lose_events(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store1 = SQLiteLifecycleStore(path)
    store2 = SQLiteLifecycleStore(path)

    recorder1 = LifecycleRecorder(
        store=store1
    )

    recorder2 = LifecycleRecorder(
        store=store2
    )

    errors = []
    lock = threading.Lock()

    def worker(
        recorder,
        prefix,
    ):
        for index in range(25):
            try:
                recorder.record(
                    LifecycleEventType.USED,
                    f"{prefix}-{index}",
                )
            except Exception as exc:
                with lock:
                    errors.append(exc)

    thread1 = threading.Thread(
        target=worker,
        args=(recorder1, "a"),
    )

    thread2 = threading.Thread(
        target=worker,
        args=(recorder2, "b"),
    )

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    assert errors == []

    checker = SQLiteLifecycleStore(path)

    assert checker.size() == 50

    checker.close()
    recorder2.close()
    recorder1.close()


# ============================================================
# Data integrity
# ============================================================


def test_nested_details_survive_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    details = {
        "request": {
            "payment": {
                "amount": 10,
                "currency": "USD",
            }
        },
        "metadata": {
            "source": "test",
            "tags": [
                "one",
                "two",
            ],
        },
    }

    first = SQLiteLifecycleStore(path)

    event = make_event(
        details=details
    )

    first.append(event)
    first.close()

    second = SQLiteLifecycleStore(path)

    restored = second.events()[0]

    assert restored.details == details

    second.close()


def test_none_details_survive_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    event = make_event(
        details=None
    )

    first = SQLiteLifecycleStore(path)

    first.append(event)
    first.close()

    second = SQLiteLifecycleStore(path)

    assert second.events()[0].details is None

    second.close()


# ============================================================
# One-way append semantics
# ============================================================


def test_no_update_api_exists(
    tmp_path,
):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    assert not hasattr(
        store,
        "update",
    )

    assert not hasattr(
        store,
        "delete",
    )

    assert not hasattr(
        store,
        "remove",
    )

    store.close()


def test_existing_event_is_not_mutated_by_new_event(
    tmp_path,
):
    store = SQLiteLifecycleStore(
        tmp_path / "lifecycle.db"
    )

    first = make_event(
        fingerprint="first",
        timestamp=1.0,
    )

    second = make_event(
        fingerprint="second",
        timestamp=2.0,
    )

    store.append(first)
    store.append(second)

    events = store.events()

    assert events[0].fingerprint == (
        "first"
    )

    assert events[0].timestamp == 1.0

    assert events[1].fingerprint == (
        "second"
    )

    store.close()


# ============================================================
# Event ordering under concurrency
# ============================================================


def test_concurrent_events_receive_unique_storage_order(
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
                    fingerprint=f"fp-{index}"
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
        for index in range(75)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []

    events = store.events()

    assert len(events) == 75

    assert len({
        event.fingerprint
        for event in events
    }) == 75

    store.close()


# ============================================================
# Corruption handling
# ============================================================


def test_invalid_event_type_in_database_is_detected(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    store._connection.execute(
        """
        INSERT INTO lifecycle_events (
            event_type,
            fingerprint,
            timestamp,
            agent_id,
            capability,
            issuer,
            reason,
            request_id,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "not-real",
            "corrupt",
            1.0,
            "agent",
            "tool",
            "issuer",
            "",
            "",
            None,
        ),
    )

    with pytest.raises(
        LifecycleStoreError
    ):
        store.events()

    store.close()


def test_invalid_details_json_is_detected(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    store._connection.execute(
        """
        INSERT INTO lifecycle_events (
            event_type,
            fingerprint,
            timestamp,
            agent_id,
            capability,
            issuer,
            reason,
            request_id,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            LifecycleEventType.USED.value,
            "corrupt",
            1.0,
            "agent",
            "tool",
            "issuer",
            "",
            "",
            "{invalid-json}",
        ),
    )

    with pytest.raises(
        LifecycleStoreError
    ):
        store.events()

    store.close()


# ============================================================
# Lifecycle separation
# ============================================================


def test_persistence_does_not_cross_fingerprints(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    store.append(
        make_event(
            fingerprint="a"
        )
    )

    store.append(
        make_event(
            fingerprint="b"
        )
    )

    assert len(
        store.for_fingerprint("a")
    ) == 1

    assert len(
        store.for_fingerprint("b")
    ) == 1

    assert (
        store.for_fingerprint("a")[0]
        .fingerprint
        == "a"
    )

    assert (
        store.for_fingerprint("b")[0]
        .fingerprint
        == "b"
    )

    store.close()


def test_persistence_does_not_cross_event_types(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    store.append(
        make_event(
            event_type=LifecycleEventType.USED
        )
    )

    store.append(
        make_event(
            event_type=LifecycleEventType.DENIED
        )
    )

    assert len(
        store.of_type(
            LifecycleEventType.USED
        )
    ) == 1

    assert len(
        store.of_type(
            LifecycleEventType.DENIED
        )
    ) == 1

    store.close()


# ============================================================
# Full lifecycle persistence
# ============================================================


def test_full_lifecycle_survives_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    current_time = [0.0]

    def clock():
        return current_time[0]

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        store=store,
        clock=clock,
    )

    sequence = [
        LifecycleEventType.ISSUED,
        LifecycleEventType.DELEGATED,
        LifecycleEventType.ATTENUATED,
        LifecycleEventType.USED,
        LifecycleEventType.REPLAYED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
        LifecycleEventType.EXPIRED,
    ]

    for index, event_type in enumerate(
        sequence
    ):
        current_time[0] = float(index)

        recorder.record(
            event_type,
            "fp-lifecycle",
        )

    expected = recorder.events()

    recorder.close()

    store2 = SQLiteLifecycleStore(path)

    restored = LifecycleRecorder(
        store=store2,
        clock=clock,
    )

    assert restored.events() == expected

    assert [
        event.event_type
        for event in restored.events()
    ] == sequence

    assert all(
        event.fingerprint
        == "fp-lifecycle"
        for event in restored.events()
    )

    restored.close()


# ============================================================
# Restart after concurrent writes
# ============================================================


def test_restart_after_concurrent_writes(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

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
        for index in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert store.size() == 100

    store.close()

    reopened = SQLiteLifecycleStore(
        path
    )

    assert reopened.size() == 100

    assert len(
        reopened.events()
    ) == 100

    reopened.close()


# ============================================================
# Final consistency
# ============================================================


def test_persistent_history_matches_recorder_history(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        store=store
    )

    for index in range(20):
        recorder.record(
            LifecycleEventType.USED,
            f"fp-{index}",
            details={
                "index": index
            },
        )

    assert recorder.events() == (
        store.events()
    )

    recorder.close()


def test_reopened_history_matches_original(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    first_store = SQLiteLifecycleStore(
        path
    )

    first = LifecycleRecorder(
        store=first_store
    )

    for index in range(20):
        first.record(
            LifecycleEventType.USED,
            f"fp-{index}",
            details={
                "index": index
            },
        )

    expected = first.events()

    first.close()

    second_store = SQLiteLifecycleStore(
        path
    )

    second = LifecycleRecorder(
        store=second_store
    )

    assert second.events() == expected

    second.close()