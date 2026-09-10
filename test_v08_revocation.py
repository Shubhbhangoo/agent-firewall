import pytest

from firewall.revocation import (
    AlreadyRevokedError,
    InvalidFingerprintError,
    RevocationRegistry,
    RevokedCapabilityError,
)


# ============================================================
# Initialization
# ============================================================


def test_registry_initializes():
    registry = RevocationRegistry()

    assert registry.size() == 0


def test_registry_starts_empty():
    registry = RevocationRegistry()

    assert registry.records() == ()


# ============================================================
# Fingerprint validation
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
    fingerprint,
):
    registry = RevocationRegistry()

    with pytest.raises(
        InvalidFingerprintError
    ):
        registry.is_revoked(
            fingerprint
        )


def test_fingerprint_whitespace_normalized():
    registry = RevocationRegistry()

    registry.revoke(
        "  abc123  "
    )

    assert registry.is_revoked(
        "abc123"
    )


# ============================================================
# Revocation
# ============================================================


def test_revoke_capability():
    registry = RevocationRegistry(
        clock=lambda: 1000.0
    )

    record = registry.revoke(
        "abc123"
    )

    assert record.fingerprint == "abc123"
    assert record.revoked_at == 1000.0


def test_revoke_marks_capability_revoked():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    assert registry.is_revoked(
        "abc123"
    ) is True


def test_non_revoked_capability_is_active():
    registry = RevocationRegistry()

    assert registry.is_revoked(
        "abc123"
    ) is False


def test_revoke_increases_size():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    assert registry.size() == 1


def test_multiple_capabilities_can_be_revoked():
    registry = RevocationRegistry()

    registry.revoke("a")
    registry.revoke("b")
    registry.revoke("c")

    assert registry.size() == 3

    assert registry.is_revoked("a")
    assert registry.is_revoked("b")
    assert registry.is_revoked("c")


# ============================================================
# One-way semantics
# ============================================================


def test_double_revoke_is_rejected():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    with pytest.raises(
        AlreadyRevokedError
    ):
        registry.revoke(
            "abc123"
        )


def test_revoke_never_unrevokes():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    assert registry.is_revoked(
        "abc123"
    ) is True

    assert not hasattr(
        registry,
        "unrevoke",
    )


# ============================================================
# Active requirement
# ============================================================


def test_require_active_allows_active_capability():
    registry = RevocationRegistry()

    registry.require_active(
        "abc123"
    )


def test_require_active_rejects_revoked_capability():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    with pytest.raises(
        RevokedCapabilityError
    ):
        registry.require_active(
            "abc123"
        )


# ============================================================
# Lookup
# ============================================================


def test_get_returns_none_for_active_capability():
    registry = RevocationRegistry()

    assert registry.get(
        "abc123"
    ) is None


def test_get_returns_record_for_revoked_capability():
    registry = RevocationRegistry(
        clock=lambda: 1234.5
    )

    registry.revoke(
        "abc123",
        reason="compromised",
    )

    record = registry.get(
        "abc123"
    )

    assert record is not None
    assert record.fingerprint == "abc123"
    assert record.revoked_at == 1234.5
    assert record.reason == "compromised"


def test_reason_defaults_to_empty():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    record = registry.get(
        "abc123"
    )

    assert record.reason == ""


# ============================================================
# Snapshot
# ============================================================


def test_records_returns_snapshot():
    registry = RevocationRegistry()

    registry.revoke("a")
    registry.revoke("b")

    records = registry.records()

    assert len(records) == 2
    assert {
        record.fingerprint
        for record in records
    } == {"a", "b"}


def test_records_returns_tuple():
    registry = RevocationRegistry()

    assert isinstance(
        registry.records(),
        tuple,
    )


# ============================================================
# Concurrency
# ============================================================


def test_concurrent_first_revoke_wins():
    import threading

    registry = RevocationRegistry()

    results = []
    lock = threading.Lock()

    def worker():
        try:
            registry.revoke(
                "concurrent"
            )
            result = True
        except AlreadyRevokedError:
            result = False

        with lock:
            results.append(result)

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

    assert results.count(True) == 1
    assert results.count(False) == 19
    assert registry.size() == 1


def test_concurrent_reads_are_safe():
    import threading

    registry = RevocationRegistry()

    registry.revoke("abc123")

    results = []
    lock = threading.Lock()

    def worker():
        value = registry.is_revoked(
            "abc123"
        )

        with lock:
            results.append(value)

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

    assert results == [True] * 20