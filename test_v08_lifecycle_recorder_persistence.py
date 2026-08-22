from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.lifecycle_store import (
    SQLiteLifecycleStore,
)


def test_recorder_persists_events(tmp_path):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        clock=lambda: 100.0,
        store=store,
    )

    recorder.record(
        LifecycleEventType.ISSUED,
        "fp-1",
        agent_id="agent-a",
        capability="payments.send",
    )

    assert recorder.size() == 1
    assert store.size() == 1

    recorder.close()


def test_recorder_restores_events_after_restart(tmp_path):
    path = tmp_path / "lifecycle.db"

    first_store = SQLiteLifecycleStore(
        path
    )

    first = LifecycleRecorder(
        clock=lambda: 100.0,
        store=first_store,
    )

    first.record(
        LifecycleEventType.ISSUED,
        "fp-1",
    )

    first.record(
        LifecycleEventType.USED,
        "fp-1",
    )

    first.close()

    second_store = SQLiteLifecycleStore(
        path
    )

    second = LifecycleRecorder(
        clock=lambda: 200.0,
        store=second_store,
    )

    events = second.events()

    assert len(events) == 2

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
    ]

    second.close()


def test_recorder_restores_order(tmp_path):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        store=store
    )

    recorder.record(
        LifecycleEventType.ISSUED,
        "a",
    )

    recorder.record(
        LifecycleEventType.DELEGATED,
        "a",
    )

    recorder.record(
        LifecycleEventType.ATTENUATED,
        "b",
    )

    recorder.close()

    store2 = SQLiteLifecycleStore(
        path
    )

    restored = LifecycleRecorder(
        store=store2
    )

    assert [
        event.event_type
        for event in restored.events()
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.DELEGATED,
        LifecycleEventType.ATTENUATED,
    ]

    restored.close()


def test_recorder_filtering_works_after_restart(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        store=store
    )

    recorder.record(
        LifecycleEventType.USED,
        "same",
    )

    recorder.record(
        LifecycleEventType.REVOKED,
        "other",
    )

    recorder.close()

    store2 = SQLiteLifecycleStore(
        path
    )

    restored = LifecycleRecorder(
        store=store2
    )

    assert len(
        restored.for_fingerprint(
            "same"
        )
    ) == 1

    assert len(
        restored.of_type(
            LifecycleEventType.REVOKED
        )
    ) == 1

    restored.close()


def test_in_memory_recorder_still_works():
    recorder = LifecycleRecorder(
        clock=lambda: 50.0
    )

    event = recorder.record(
        LifecycleEventType.USED,
        "fp",
    )

    assert recorder.events() == (
        event,
    )

    assert recorder.size() == 1


def test_persistence_failure_does_not_append_memory_event():
    class FailingStore:

        def append(self, event):
            raise RuntimeError(
                "persistence failed"
            )

        def events(self):
            return ()

        def close(self):
            pass

    recorder = LifecycleRecorder(
        store=FailingStore()
    )

    try:
        recorder.record(
            LifecycleEventType.USED,
            "fp",
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "expected persistence failure"
        )

    assert recorder.size() == 0