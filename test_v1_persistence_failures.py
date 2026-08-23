from __future__ import annotations

import os
import sqlite3

import pytest

from firewall.key_store import (
    KeyStoreCorruptionError,
    KeyStoreCryptoError,
    KeyStoreError,
)

from firewall.sdk import (
    FirewallSDK,
)


def make_master_key() -> bytes:
    return os.urandom(32)


def make_sdk(
    path,
    master_key,
):
    return FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )


# ============================================================
# Wrong master key
# ============================================================


def test_wrong_master_key_fails_closed_on_restart(
    tmp_path,
):
    path = tmp_path / "keys.db"
    original_master_key = make_master_key()

    sdk = make_sdk(
        path,
        original_master_key,
    )

    sdk.generate_key("key-1")
    sdk.close()

    with pytest.raises(
        KeyStoreCryptoError
    ):
        make_sdk(
            path,
            make_master_key(),
        )


def test_wrong_master_key_never_creates_fresh_key(
    tmp_path,
):
    path = tmp_path / "keys.db"
    original_master_key = make_master_key()

    sdk = make_sdk(
        path,
        original_master_key,
    )

    sdk.generate_key("original-key")
    sdk.close()

    with pytest.raises(
        KeyStoreCryptoError
    ):
        make_sdk(
            path,
            make_master_key(),
        )


# ============================================================
# Corrupt encrypted key material
# ============================================================


def test_corrupt_private_key_fails_closed(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        UPDATE keys
        SET private_key = ?
        WHERE key_id = ?
        """,
        (
            b"corrupted-key-material",
            "key-1",
        ),
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        (
            KeyStoreCryptoError,
            KeyStoreCorruptionError,
        )
    ):
        make_sdk(
            path,
            master_key,
        )


def test_truncated_private_key_fails_closed(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        UPDATE keys
        SET private_key = ?
        WHERE key_id = ?
        """,
        (
            b"",
            "key-1",
        ),
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        KeyStoreCorruptionError
    ):
        make_sdk(
            path,
            master_key,
        )


# ============================================================
# Public key corruption
# ============================================================


def test_corrupt_public_key_fails_closed(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        UPDATE keys
        SET public_key = ?
        WHERE key_id = ?
        """,
        (
            b"not-a-valid-public-key",
            "key-1",
        ),
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        KeyStoreCorruptionError
    ):
        make_sdk(
            path,
            master_key,
        )


# ============================================================
# Active state corruption
# ============================================================


def test_multiple_active_keys_fail_closed(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.generate_key("key-2")
    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        UPDATE keys
        SET active = 1
        """
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        RuntimeError,
        match="multiple active keys",
    ):
        make_sdk(
            path,
            master_key,
        )


def test_no_active_key_does_not_create_fallback_key(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.retire_key("key-1")
    sdk.close()

    sdk = make_sdk(
        path,
        master_key,
    )

    with pytest.raises(
        ValueError,
        match="no active key",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
        )

    assert sdk.key_manager.key_ids() == (
        "key-1",
    )

    sdk.close()


# ============================================================
# Closed store
# ============================================================


def test_closed_key_store_fails_explicitly(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")

    sdk.key_store.close()

    with pytest.raises(
        KeyStoreError,
        match="closed",
    ):
        sdk.active_key()


def test_closed_key_store_does_not_fallback_to_memory(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")

    sdk.key_store.close()

    with pytest.raises(
        KeyStoreError,
        match="closed",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
        )


# ============================================================
# Corrupt database schema
# ============================================================


def test_corrupted_database_fails_explicitly(
    tmp_path,
):
    path = tmp_path / "keys.db"

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        CREATE TABLE keys (
            completely_wrong_column TEXT
        )
        """
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        KeyStoreError
    ):
        make_sdk(
            path,
            make_master_key(),
        )


# ============================================================
# Deleted database
# ============================================================


def test_replaced_database_does_not_silently_restore_keys(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.close()

    path.unlink()

    sdk = make_sdk(
        path,
        master_key,
    )

    assert (
        sdk.key_manager.key_ids()
        == ()
    )

    with pytest.raises(
        ValueError,
        match="no active key",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
        )

    sdk.close()


# ============================================================
# Issuer trust persistence
# ============================================================


def test_corrupt_trust_state_does_not_grant_new_issuer(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.trust_issuer(
        "issuer-a"
    )

    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        "DELETE FROM trusted_issuers"
    )

    connection.commit()
    connection.close()

    sdk = make_sdk(
        path,
        master_key,
    )

    assert (
        sdk.is_issuer_trusted(
            "issuer-a"
        )
        is False
    )

    sdk.close()


def test_restarting_with_corrupt_key_store_never_falls_back_to_memory(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert sdk.verify(
        capability
    ) is True

    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        UPDATE keys
        SET private_key = ?
        WHERE key_id = ?
        """,
        (
            b"destroyed",
            "key-1",
        ),
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        (
            KeyStoreCryptoError,
            KeyStoreCorruptionError,
        )
    ):
        make_sdk(
            path,
            master_key,
        )


# ============================================================
# Master key validation
# ============================================================


@pytest.mark.parametrize(
    "bad_master_key",
    [
        b"",
        b"short",
        os.urandom(31),
        os.urandom(33),
        None,
        "not-bytes",
    ],
)
def test_invalid_master_key_fails_closed(
    tmp_path,
    bad_master_key,
):
    with pytest.raises(
        (
            TypeError,
            ValueError,
        )
    ):
        make_sdk(
            tmp_path / "keys.db",
            bad_master_key,
        )


# ============================================================
# Persistence remains authoritative
# ============================================================


def test_persistent_sdk_never_silently_switches_to_memory(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")
    sdk.close()

    restarted = make_sdk(
        path,
        master_key,
    )

    assert (
        restarted.key_store
        is not None
    )

    assert (
        restarted.key_manager.key_ids()
        == ("key-1",)
    )

    restarted.close()


# ============================================================
# Security invariant
# ============================================================


def test_persistence_failure_never_produces_new_authority(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    sdk = make_sdk(
        path,
        master_key,
    )

    sdk.generate_key("key-1")

    original = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert sdk.verify(
        original
    ) is True

    sdk.close()

    connection = sqlite3.connect(
        path
    )

    connection.execute(
        """
        UPDATE keys
        SET private_key = ?
        WHERE key_id = ?
        """,
        (
            b"broken",
            "key-1",
        ),
    )

    connection.commit()
    connection.close()

    with pytest.raises(
        (
            KeyStoreCryptoError,
            KeyStoreCorruptionError,
        )
    ):
        make_sdk(
            path,
            master_key,
        )