from __future__ import annotations

import pytest

from firewall.replay import ReplayProtector
from firewall.replay_store import SQLiteReplayStore
from firewall.sdk import FirewallSDK


def create_sdk(
    path,
) -> FirewallSDK:
    sdk = FirewallSDK(
        replay_store_path=path,
    )

    sdk.generate_key(
        "key-1"
    )

    return sdk


def test_sdk_replay_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    sdk = create_sdk(
        path
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    ) is True

    sdk.close()

    sdk = create_sdk(
        path
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    ) is False

    sdk.close()


def test_different_nonce_remains_available_after_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    sdk = create_sdk(
        path
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    ) is True

    sdk.close()

    sdk = create_sdk(
        path
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-2",
    ) is True

    sdk.close()


def test_replay_store_is_exposed(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    sdk = create_sdk(
        path
    )

    assert (
        sdk.replay_store
        is not None
    )

    assert (
        sdk.replay.store
        is sdk.replay_store
    )

    sdk.close()


def test_replay_protector_and_store_are_mutually_exclusive(
    tmp_path,
):
    protector = ReplayProtector()

    with pytest.raises(
        ValueError,
        match="either replay_protector",
    ):
        FirewallSDK(
            replay_protector=protector,
            replay_store_path=(
                tmp_path
                / "replay.db"
            ),
        )


def test_persistent_replay_rejects_same_nonce(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    sdk = create_sdk(
        path
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "same",
    ) is True

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "same",
    ) is False

    sdk.close()


def test_persistent_replay_store_can_be_injected(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    store = SQLiteReplayStore(
        path
    )

    sdk = FirewallSDK(
        replay_store=store,
    )

    sdk.generate_key(
        "key-1"
    )

    assert (
        sdk.replay_store
        is store
    )

    assert (
        sdk.replay.store
        is store
    )

    sdk.close()