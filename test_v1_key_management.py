from __future__ import annotations

import pytest

from firewall.key_management import (
    CapabilityKeyManager,
    IssuerTrustStore,
)


# ============================================================
# Issuer trust
# ============================================================


def test_trusted_issuer_is_trusted():
    store = IssuerTrustStore(
        {"issuer-a"}
    )

    assert store.is_trusted(
        "issuer-a"
    ) is True


def test_unknown_issuer_is_not_trusted():
    store = IssuerTrustStore(
        {"issuer-a"}
    )

    assert store.is_trusted(
        "issuer-b"
    ) is False


def test_revoke_issuer():
    store = IssuerTrustStore(
        {"issuer-a"}
    )

    store.revoke(
        "issuer-a"
    )

    assert store.is_trusted(
        "issuer-a"
    ) is False

    assert store.is_revoked(
        "issuer-a"
    ) is True


def test_trust_reactivates_revoked_issuer():
    store = IssuerTrustStore(
        {"issuer-a"}
    )

    store.revoke(
        "issuer-a"
    )

    store.trust(
        "issuer-a"
    )

    assert store.is_trusted(
        "issuer-a"
    ) is True

    assert store.is_revoked(
        "issuer-a"
    ) is False


def test_revoke_unknown_issuer():
    store = IssuerTrustStore()

    store.revoke(
        "issuer-a"
    )

    assert store.is_revoked(
        "issuer-a"
    ) is True


def test_trusted_issuers_excludes_revoked():
    store = IssuerTrustStore(
        {
            "issuer-a",
            "issuer-b",
        }
    )

    store.revoke(
        "issuer-a"
    )

    assert store.trusted_issuers() == {
        "issuer-b"
    }


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " ",
        None,
        123,
        [],
    ],
)
def test_invalid_issuer_rejected(
    bad,
):
    store = IssuerTrustStore()

    with pytest.raises(
        (TypeError, ValueError)
    ):
        store.trust(bad)


# ============================================================
# Key manager
# ============================================================


def test_generate_first_key_becomes_active():
    manager = CapabilityKeyManager()

    record = manager.generate(
        "key-1"
    )

    assert record.key_id == "key-1"
    assert record.active is True
    assert manager.active() == record


def test_generate_second_key_does_not_replace_active():
    manager = CapabilityKeyManager()

    first = manager.generate(
        "key-1"
    )

    manager.generate(
        "key-2"
    )

    assert manager.active() == first


def test_rotate_retires_old_key():
    manager = CapabilityKeyManager()

    first = manager.generate(
        "key-1"
    )

    second = manager.rotate(
        "key-2"
    )

    assert first.active is True
    assert second.active is True

    assert manager.is_active(
        "key-1"
    ) is False

    assert manager.is_active(
        "key-2"
    ) is True

    assert manager.active() == second


def test_rotated_key_material_is_distinct():
    manager = CapabilityKeyManager()

    first = manager.generate(
        "key-1"
    )

    second = manager.rotate(
        "key-2"
    )

    assert (
        first.public_key.public_bytes_raw()
        != second.public_key.public_bytes_raw()
    )


def test_retire_active_key():
    manager = CapabilityKeyManager()

    manager.generate(
        "key-1"
    )

    manager.retire(
        "key-1"
    )

    assert manager.is_active(
        "key-1"
    ) is False

    with pytest.raises(
        RuntimeError
    ):
        manager.active()


def test_retire_non_active_key():
    manager = CapabilityKeyManager()

    manager.generate(
        "key-1"
    )

    manager.generate(
        "key-2"
    )

    manager.retire(
        "key-2"
    )

    assert manager.is_active(
        "key-1"
    ) is True


def test_get_key():
    manager = CapabilityKeyManager()

    created = manager.generate(
        "key-1"
    )

    assert manager.get(
        "key-1"
    ) == created


def test_unknown_key_rejected():
    manager = CapabilityKeyManager()

    with pytest.raises(
        KeyError
    ):
        manager.get(
            "missing"
        )


def test_duplicate_key_rejected():
    manager = CapabilityKeyManager()

    manager.generate(
        "key-1"
    )

    with pytest.raises(
        ValueError
    ):
        manager.generate(
            "key-1"
        )


def test_duplicate_rotation_key_rejected():
    manager = CapabilityKeyManager()

    manager.generate(
        "key-1"
    )

    with pytest.raises(
        ValueError
    ):
        manager.rotate(
            "key-1"
        )


def test_key_ids_are_stable():
    manager = CapabilityKeyManager()

    manager.generate(
        "key-1"
    )

    manager.rotate(
        "key-2"
    )

    assert manager.key_ids() == (
        "key-1",
        "key-2",
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " ",
        None,
        123,
        [],
    ],
)
def test_invalid_key_id_rejected(
    bad,
):
    manager = CapabilityKeyManager()

    with pytest.raises(
        (TypeError, ValueError)
    ):
        manager.generate(bad)