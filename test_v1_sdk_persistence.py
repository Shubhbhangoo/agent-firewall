from __future__ import annotations

import os

import pytest

from firewall.key_store import (
    KeyStoreCryptoError,
)
from firewall.sdk import (
    FirewallSDK,
)


def make_master_key():
    return os.urandom(32)


def test_sdk_key_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "firewall-keys.db"
    )

    master_key = make_master_key()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    sdk.generate_key(
        "key-1"
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    public_key = (
        capability.public_key
    )

    sdk.close()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    active = sdk.active_key()

    assert active.key_id == "key-1"

    capability_2 = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert (
        capability_2.public_key
        == public_key
    )

    assert sdk.verify(
        capability
    ) is True

    assert sdk.verify(
        capability_2
    ) is True

    sdk.close()


def test_sdk_rotation_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "firewall-keys.db"
    )

    master_key = make_master_key()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    sdk.generate_key(
        "key-1"
    )

    first = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    sdk.rotate_key(
        "key-2"
    )

    second = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    sdk.close()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    active = sdk.active_key()

    assert active.key_id == "key-2"

    third = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    assert (
        third.public_key
        == second.public_key
    )

    assert (
        first.public_key
        != second.public_key
    )

    assert sdk.verify(
        first
    ) is True

    assert sdk.verify(
        second
    ) is True

    assert sdk.verify(
        third
    ) is True

    sdk.close()


def test_sdk_retired_key_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "firewall-keys.db"
    )

    master_key = make_master_key()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    sdk.generate_key(
        "key-1"
    )

    sdk.retire_key(
        "key-1"
    )

    sdk.close()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    assert sdk.is_issuer_trusted(
        "trusted-issuer"
    ) is True

    with pytest.raises(
        ValueError,
        match="no active key",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
        )

    sdk.close()


def test_sdk_issuer_trust_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "firewall-keys.db"
    )

    master_key = make_master_key()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    sdk.trust_issuer(
        "issuer-a"
    )

    assert sdk.is_issuer_trusted(
        "issuer-a"
    ) is True

    sdk.close()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    assert sdk.is_issuer_trusted(
        "issuer-a"
    ) is True

    sdk.close()


def test_sdk_issuer_revocation_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "firewall-keys.db"
    )

    master_key = make_master_key()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    sdk.trust_issuer(
        "issuer-a"
    )

    sdk.revoke_issuer(
        "issuer-a"
    )

    assert sdk.is_issuer_trusted(
        "issuer-a"
    ) is False

    sdk.close()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    assert sdk.is_issuer_trusted(
        "issuer-a"
    ) is False

    sdk.close()


def test_sdk_wrong_master_key_fails_closed(
    tmp_path,
):
    path = (
        tmp_path
        / "firewall-keys.db"
    )

    master_key = make_master_key()

    sdk = FirewallSDK(
        key_store_path=path,
        master_key=master_key,
    )

    sdk.generate_key(
        "key-1"
    )

    sdk.close()

    with pytest.raises(
        KeyStoreCryptoError
    ):
        FirewallSDK(
            key_store_path=path,
            master_key=make_master_key(),
        )


def test_key_store_path_requires_master_key(
    tmp_path,
):
    with pytest.raises(
        ValueError,
        match="master_key is required",
    ):
        FirewallSDK(
            key_store_path=(
                tmp_path
                / "keys.db"
            )
        )


def test_key_store_and_key_manager_are_mutually_exclusive(
    tmp_path,
):
    from firewall.key_management import (
        CapabilityKeyManager,
    )

    with pytest.raises(
        ValueError,
        match="either key_manager",
    ):
        FirewallSDK(
            key_store_path=(
                tmp_path
                / "keys.db"
            ),
            master_key=make_master_key(),
            key_manager=CapabilityKeyManager(),
        )