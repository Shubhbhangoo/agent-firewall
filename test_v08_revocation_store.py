import threading

import pytest

from firewall.revocation_store import (
    SQLiteRevocationStore,
    StoreAlreadyRevokedError,
    StoreInvalidFingerprintError,
)


# ============================================================
# Initialization
# ============================================================


def test_store_initializes(tmp_path):
    path = tmp_path / "revocations.db"

    store = SQLiteRevocationStore(
        path
    )

    assert store.size() == 0

    store.close()


def test_store_creates_database(tmp_path):
    path = tmp_path / "nested" / "revocations.db"

    path.parent.mkdir()

    store = SQLiteRevocationStore(
        path
    )

    assert path.exists()

    store.close()


def test_store_accepts_string_path(tmp_path):
    path = str(
        tmp_path / "revocations.db"
    )

    store = SQLiteRevocationStore(
        path
    )

    assert store.size() == 0

    store.close()


# ============================================================
# Validation
# ============================================================


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
    tmp_path,
    fingerprint,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    with pytest.raises(
        StoreInvalidFingerprintError
    ):
        store.is_revoked(
            fingerprint
        )

    store.close()


def test_fingerprint_whitespace_normalized(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    store.revoke(
        "  abc123  "
    )

    assert store.is_revoked(
        "abc123"
    )

    store.close()


# ============================================================
# Revocation
# ============================================================


def test_revoke_persists_record(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db",
        clock=lambda: 1000.0,
    )

    record = store.revoke(
        "abc123",
        reason="compromised",
    )

    assert record.fingerprint == "abc123"
    assert record.revoked_at == 1000.0
    assert record.reason == "compromised"

    store.close()


def test_revoke_marks_fingerprint(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    store.revoke(
        "abc123"
    )

    assert store.is_revoked(
        "abc123"
    )

    store.close()


def test_unknown_fingerprint_is_active(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    assert not store.is_revoked(
        "abc123"
    )

    store.close()


def test_double_revoke_rejected(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    store.revoke(
        "abc123",
        reason="first",
    )

    with pytest.raises(
        StoreAlreadyRevokedError
    ):
        store.revoke(
            "abc123",
            reason="second",
        )

    record = store.get(
        "abc123"
    )

    assert record.reason == "first"

    store.close()


# ============================================================
# Lookup
# ============================================================


def test_get_returns_none_for_unknown(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    assert store.get(
        "unknown"
    ) is None

    store.close()


def test_get_returns_record(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db",
        clock=lambda: 1234.5,
    )

    store.revoke(
        "abc123",
        reason="stolen",
    )

    record = store.get(
        "abc123"
    )

    assert record.fingerprint == "abc123"
    assert record.revoked_at == 1234.5
    assert record.reason == "stolen"

    store.close()


# ============================================================
# Persistence across restart
# ============================================================


def test_revocation_survives_close_and_reopen(
    tmp_path,
):
    path = tmp_path / "revocations.db"

    first = SQLiteRevocationStore(
        path
    )

    first.revoke(
        "abc123",
        reason="compromised",
    )

    first.close()

    second = SQLiteRevocationStore(
        path
    )

    assert second.is_revoked(
        "abc123"
    )

    record = second.get(
        "abc123"
    )

    assert record.reason == "compromised"

    second.close()


def test_multiple_revocations_survive_restart(
    tmp_path,
):
    path = tmp_path / "revocations.db"

    first = SQLiteRevocationStore(
        path
    )

    first.revoke("a")
    first.revoke("b")
    first.revoke("c")

    first.close()

    second = SQLiteRevocationStore(
        path
    )

    assert second.size() == 3

    assert second.is_revoked("a")
    assert second.is_revoked("b")
    assert second.is_revoked("c")

    second.close()


# ============================================================
# Records
# ============================================================


def test_records_returns_tuple(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    assert isinstance(
        store.records(),
        tuple,
    )

    store.close()


def test_records_returns_all_revocations(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    store.revoke("a")
    store.revoke("b")
    store.revoke("c")

    records = store.records()

    assert {
        record.fingerprint
        for record in records
    } == {"a", "b", "c"}

    store.close()


def test_size_tracks_revocations(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    assert store.size() == 0

    store.revoke("a")
    assert store.size() == 1

    store.revoke("b")
    assert store.size() == 2

    store.close()


# ============================================================
# One-way semantics
# ============================================================


def test_store_has_no_unrevoke(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    assert not hasattr(
        store,
        "unrevoke",
    )

    store.close()


# ============================================================
# Context manager
# ============================================================


def test_context_manager_persists(
    tmp_path,
):
    path = tmp_path / "revocations.db"

    with SQLiteRevocationStore(
        path
    ) as store:
        store.revoke("abc123")

    with SQLiteRevocationStore(
        path
    ) as store:
        assert store.is_revoked(
            "abc123"
        )


# ============================================================
# Concurrency
# ============================================================


def test_concurrent_same_fingerprint_has_one_winner(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    successes = []
    failures = []
    lock = threading.Lock()

    def worker():
        try:
            store.revoke(
                "concurrent"
            )

            with lock:
                successes.append(True)

        except StoreAlreadyRevokedError:
            with lock:
                failures.append(True)

    threads = [
        threading.Thread(
            target=worker
        )
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert len(failures) == 19

    assert store.size() == 1
    assert store.is_revoked(
        "concurrent"
    )

    store.close()


def test_concurrent_different_fingerprints(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    fingerprints = [
        f"fingerprint-{index}"
        for index in range(20)
    ]

    errors = []
    lock = threading.Lock()

    def worker(fingerprint):
        try:
            store.revoke(
                fingerprint
            )
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(fingerprint,),
        )
        for fingerprint in fingerprints
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert store.size() == 20

    for fingerprint in fingerprints:
        assert store.is_revoked(
            fingerprint
        )

    store.close()


# ============================================================
# Crash/reopen style verification
# ============================================================


def test_committed_revoke_is_visible_to_second_connection(
    tmp_path,
):
    path = tmp_path / "revocations.db"

    first = SQLiteRevocationStore(
        path
    )

    second = SQLiteRevocationStore(
        path
    )

    first.revoke(
        "abc123"
    )

    assert second.is_revoked(
        "abc123"
    )

    first.close()
    second.close()


# ============================================================
# Isolation
# ============================================================


def test_separate_databases_are_isolated(
    tmp_path,
):
    first = SQLiteRevocationStore(
        tmp_path / "first.db"
    )

    second = SQLiteRevocationStore(
        tmp_path / "second.db"
    )

    first.revoke(
        "abc123"
    )

    assert first.is_revoked(
        "abc123"
    )

    assert not second.is_revoked(
        "abc123"
    )

    first.close()
    second.close()