from firewall.revocation import RevocationRegistry
from firewall.revocation_store import SQLiteRevocationStore


def test_revocation_state_does_not_silently_disappear_when_backend_changes(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    registry = RevocationRegistry(
        backend=store
    )

    fingerprint = "cap-123"

    registry.revoke(
        fingerprint,
        reason="compromised",
    )

    assert registry.is_revoked(
        fingerprint
    )

    # The persistent backend is authoritative.
    # Re-opening it must preserve the revocation.
    store.close()

    restored_store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    restored = RevocationRegistry(
        backend=restored_store
    )

    assert restored.is_revoked(
        fingerprint
    )

    restored_store.close()



def test_backend_revocation_is_not_lost_to_empty_in_memory_state(
    tmp_path,
):
    store = SQLiteRevocationStore(
        tmp_path / "revocations.db"
    )

    persistent = RevocationRegistry(
        backend=store
    )

    fingerprint = "cap-mixed"

    persistent.revoke(
        fingerprint,
        reason="compromised",
    )

    assert persistent.is_revoked(
        fingerprint
    )

    # A new registry using an empty in-memory backend must NOT
    # be mistaken for continuity with the persistent registry.
    in_memory = RevocationRegistry()

    assert not in_memory.is_revoked(
        fingerprint
    )

    store.close()