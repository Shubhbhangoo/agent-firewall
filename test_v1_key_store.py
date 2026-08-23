from __future__ import annotations

import os
import sqlite3

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.key_store import (
    KeyStoreCorruptionError,
    KeyStoreCryptoError,
    KeyStoreError,
    SQLiteKeyStore,
)


def make_master_key() -> bytes:
    return os.urandom(32)


def make_keys():
    return generate_capability_key_pair()


def test_key_survives_restart(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    private_key, public_key = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            private_key,
            public_key,
            active=True,
        )

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        restored = store.get_key(
            "key-1"
        )

        assert restored.key_id == "key-1"
        assert restored.active is True
        assert (
            restored.public_key.public_bytes_raw()
            == public_key.public_bytes_raw()
        )
        assert (
            restored.private_key.private_bytes_raw()
            == private_key.private_bytes_raw()
        )


def test_active_key_survives_restart(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    private_key, public_key = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            private_key,
            public_key,
            active=True,
        )

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        active = store.active_key()

        assert active.key_id == "key-1"
        assert active.active is True


def test_multiple_key_ids_survive_restart(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    first_private, first_public = make_keys()
    second_private, second_public = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            first_private,
            first_public,
            active=True,
        )

        store.save_key(
            "key-2",
            second_private,
            second_public,
            active=False,
        )

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        assert store.key_ids() == (
            "key-1",
            "key-2",
        )


def test_private_key_is_encrypted_at_rest(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    private_key, public_key = make_keys()
    raw_private = private_key.private_bytes_raw()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            private_key,
            public_key,
            active=True,
        )

    database_bytes = path.read_bytes()

    assert raw_private not in database_bytes


def test_wrong_master_key_fails_closed(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    private_key, public_key = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            private_key,
            public_key,
            active=True,
        )

    wrong_key = make_master_key()

    with SQLiteKeyStore(
        path,
        master_key=wrong_key,
    ) as store:
        with pytest.raises(
            KeyStoreCryptoError
        ):
            store.get_key(
                "key-1"
            )


def test_private_public_mismatch_is_detected(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    private_key, public_key = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            private_key,
            public_key,
            active=True,
        )

    other_private, _ = make_keys()

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
            b"not-valid-encrypted-material",
            "key-1",
        ),
    )

    connection.commit()
    connection.close()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        with pytest.raises(
            (
                KeyStoreCryptoError,
                KeyStoreCorruptionError,
            )
        ):
            store.get_key(
                "key-1"
            )


def test_trusted_issuer_survives_restart(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.trust_issuer(
            "issuer-a"
        )

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        assert store.trusted_issuers() == {
            "issuer-a"
        }


def test_revoked_issuer_is_not_trusted_after_restart(
    tmp_path,
):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.trust_issuer(
            "issuer-a"
        )
        store.revoke_issuer(
            "issuer-a"
        )

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        assert store.trusted_issuers() == frozenset()


def test_retrust_issuer_survives_restart(tmp_path):
    path = tmp_path / "keys.db"
    master_key = make_master_key()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.trust_issuer(
            "issuer-a"
        )
        store.revoke_issuer(
            "issuer-a"
        )
        store.trust_issuer(
            "issuer-a"
        )

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        assert store.trusted_issuers() == {
            "issuer-a"
        }


@pytest.mark.parametrize(
    "master_key",
    [
        b"",
        b"short",
        os.urandom(31),
        os.urandom(33),
        None,
        "not-bytes",
    ],
)
def test_invalid_master_key_rejected(
    tmp_path,
    master_key,
):
    with pytest.raises(
        (
            TypeError,
            ValueError,
        )
    ):
        SQLiteKeyStore(
            tmp_path / "keys.db",
            master_key=master_key,
        )


def test_unknown_key_fails(tmp_path):
    with SQLiteKeyStore(
        tmp_path / "keys.db",
        master_key=make_master_key(),
    ) as store:
        with pytest.raises(
            KeyError
        ):
            store.get_key(
                "missing"
            )


def test_duplicate_key_fails(tmp_path):
    master_key = make_master_key()
    path = tmp_path / "keys.db"

    first_private, first_public = make_keys()
    second_private, second_public = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            first_private,
            first_public,
            active=True,
        )

        with pytest.raises(
            KeyStoreError
        ):
            store.save_key(
                "key-1",
                second_private,
                second_public,
                active=False,
            )


def test_active_save_demotes_previous_active(
    tmp_path,
):
    master_key = make_master_key()
    path = tmp_path / "keys.db"

    first_private, first_public = make_keys()
    second_private, second_public = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            first_private,
            first_public,
            active=True,
        )

        store.save_key(
            "key-2",
            second_private,
            second_public,
            active=True,
        )

        assert (
            store.get_key(
                "key-1"
            ).active
            is False
        )

        assert (
            store.active_key().key_id
            == "key-2"
        )


def test_update_key_state(tmp_path):
    master_key = make_master_key()
    path = tmp_path / "keys.db"

    private_key, public_key = make_keys()

    with SQLiteKeyStore(
        path,
        master_key=master_key,
    ) as store:
        store.save_key(
            "key-1",
            private_key,
            public_key,
            active=True,
        )

        store.update_key_state(
            "key-1",
            active=False,
        )

        assert (
            store.get_key(
                "key-1"
            ).active
            is False
        )


def test_update_unknown_key_fails(tmp_path):
    with SQLiteKeyStore(
        tmp_path / "keys.db",
        master_key=make_master_key(),
    ) as store:
        with pytest.raises(
            KeyStoreError
        ):
            store.update_key_state(
                "missing",
                active=False,
            )


def test_closed_store_fails_explicitly(tmp_path):
    store = SQLiteKeyStore(
        tmp_path / "keys.db",
        master_key=make_master_key(),
    )

    store.close()

    with pytest.raises(
        KeyStoreError,
        match="closed",
    ):
        store.key_ids()