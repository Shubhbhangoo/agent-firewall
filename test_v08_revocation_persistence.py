import pytest

from firewall.revocation import (
    AlreadyRevokedError,
    RevocationRecord,
    RevocationRegistry,
    RevokedCapabilityError,
)

from firewall.revocation_store import (
    SQLiteRevocationStore,
)


def make_store(tmp_path):
    return SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )


# ============================================================
# Memory compatibility
# ============================================================


def test_registry_without_backend_remains_in_memory():
    registry = RevocationRegistry()

    record = registry.revoke(
        "abc123",
        reason="test",
    )

    assert isinstance(
        record,
        RevocationRecord,
    )

    assert registry.is_revoked(
        "abc123"
    )

    assert registry.backend is None


def test_memory_registry_preserves_behavior():
    registry = RevocationRegistry()

    registry.revoke("abc123")

    with pytest.raises(
        AlreadyRevokedError
    ):
        registry.revoke("abc123")

    with pytest.raises(
        RevokedCapabilityError
    ):
        registry.require_active(
            "abc123"
        )


# ============================================================
# Backend wiring
# ============================================================


def test_registry_accepts_sqlite_backend(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    assert registry.backend is store

    store.close()


def test_backend_revoke_returns_registry_record(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    record = registry.revoke(
        "abc123",
        reason="compromised",
    )

    assert isinstance(
        record,
        RevocationRecord,
    )

    assert record.fingerprint == "abc123"
    assert record.reason == "compromised"

    store.close()


def test_backend_is_revoked(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    assert not registry.is_revoked(
        "abc123"
    )

    registry.revoke(
        "abc123"
    )

    assert registry.is_revoked(
        "abc123"
    )

    store.close()


def test_backend_get(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    registry.revoke(
        "abc123",
        reason="stolen",
    )

    record = registry.get(
        "abc123"
    )

    assert isinstance(
        record,
        RevocationRecord,
    )

    assert record.fingerprint == "abc123"
    assert record.reason == "stolen"

    store.close()


def test_backend_size(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    assert registry.size() == 0

    registry.revoke("a")
    registry.revoke("b")

    assert registry.size() == 2

    store.close()


def test_backend_records(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    registry.revoke("a")
    registry.revoke("b")

    records = registry.records()

    assert isinstance(
        records,
        tuple,
    )

    assert {
        record.fingerprint
        for record in records
    } == {"a", "b"}

    store.close()


# ============================================================
# Persistence through registry
# ============================================================


def test_registry_reopen_preserves_revocation(
    tmp_path,
):
    store1 = make_store(tmp_path)

    registry1 = RevocationRegistry(
        backend=store1
    )

    registry1.revoke(
        "persistent",
        reason="compromised",
    )

    store1.close()

    store2 = make_store(tmp_path)

    registry2 = RevocationRegistry(
        backend=store2
    )

    assert registry2.is_revoked(
        "persistent"
    )

    record = registry2.get(
        "persistent"
    )

    assert record.reason == "compromised"

    store2.close()


def test_registry_reopen_preserves_size(
    tmp_path,
):
    store1 = make_store(tmp_path)

    registry1 = RevocationRegistry(
        backend=store1
    )

    registry1.revoke("a")
    registry1.revoke("b")
    registry1.revoke("c")

    store1.close()

    store2 = make_store(tmp_path)

    registry2 = RevocationRegistry(
        backend=store2
    )

    assert registry2.size() == 3

    store2.close()


# ============================================================
# Backend isolation
# ============================================================


def test_two_registries_share_persistent_state(
    tmp_path,
):
    store1 = make_store(tmp_path)
    store2 = make_store(tmp_path)

    registry1 = RevocationRegistry(
        backend=store1
    )

    registry2 = RevocationRegistry(
        backend=store2
    )

    registry1.revoke(
        "shared",
        reason="test",
    )

    assert registry2.is_revoked(
        "shared"
    )

    record = registry2.get(
        "shared"
    )

    assert record.reason == "test"

    store1.close()
    store2.close()


# ============================================================
# Duplicate protection
# ============================================================


def test_backend_duplicate_revoke_uses_registry_exception(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    registry.revoke(
        "duplicate"
    )

    with pytest.raises(
        AlreadyRevokedError
    ):
        registry.revoke(
            "duplicate"
        )

    store.close()


# ============================================================
# One-way behavior
# ============================================================


def test_persistent_registry_has_no_unrevoke(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    assert not hasattr(
        registry,
        "unrevoke",
    )

    store.close()


# ============================================================
# Active requirement
# ============================================================


def test_persistent_registry_require_active(
    tmp_path,
):
    store = make_store(tmp_path)

    registry = RevocationRegistry(
        backend=store
    )

    registry.revoke(
        "revoked"
    )

    with pytest.raises(
        RevokedCapabilityError
    ):
        registry.require_active(
            "revoked"
        )

    store.close()


# ============================================================
# Existing records
# ============================================================


def test_registry_reads_records_created_directly_by_store(
    tmp_path,
):
    store = make_store(tmp_path)

    store.revoke(
        "direct",
        reason="direct-store",
    )

    registry = RevocationRegistry(
        backend=store
    )

    assert registry.is_revoked(
        "direct"
    )

    record = registry.get(
        "direct"
    )

    assert record.reason == (
        "direct-store"
    )

    store.close()


def test_registry_does_not_duplicate_backend_records(
    tmp_path,
):
    store = make_store(tmp_path)

    store.revoke("existing")

    registry = RevocationRegistry(
        backend=store
    )

    assert registry.size() == 1
    assert len(
        registry.records()
    ) == 1

    store.close()