from __future__ import annotations

import time

import pytest

from firewall.replay_store import (
    ReplayStoreError,
    SQLiteReplayStore,
)


def future_time(
    seconds: float = 3600,
) -> float:
    return time.time() + seconds


def test_nonce_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    expires_at = future_time()

    with SQLiteReplayStore(
        path
    ) as store:
        assert store.consume(
            "nonce-1",
            expires_at,
        ) is True

    with SQLiteReplayStore(
        path
    ) as store:
        assert store.contains(
            "nonce-1"
        ) is True


def test_duplicate_nonce_is_rejected(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    expires_at = future_time()

    with SQLiteReplayStore(
        path
    ) as store:
        assert store.consume(
            "nonce-1",
            expires_at,
        ) is True

        assert store.consume(
            "nonce-1",
            expires_at,
        ) is False


def test_expired_nonce_is_removed(
    tmp_path,
):
    current = [1000.0]

    def clock():
        return current[0]

    path = (
        tmp_path
        / "replay.db"
    )

    with SQLiteReplayStore(
        path,
        clock=clock,
    ) as store:
        assert store.consume(
            "nonce-1",
            1100,
        ) is True

        assert store.contains(
            "nonce-1"
        ) is True

        current[0] = 1200.0

        assert store.contains(
            "nonce-1"
        ) is False


def test_records_contains_live_entries(
    tmp_path,
):
    path = (
        tmp_path
        / "replay.db"
    )

    expires_a = future_time()
    expires_b = future_time(
        7200
    )

    with SQLiteReplayStore(
        path
    ) as store:
        store.consume(
            "a",
            expires_a,
        )

        store.consume(
            "b",
            expires_b,
        )

        records = store.records()

        assert [
            record.key
            for record in records
        ] == [
            "a",
            "b",
        ]


def test_closed_store_fails(
    tmp_path,
):
    store = SQLiteReplayStore(
        tmp_path
        / "replay.db"
    )

    store.close()

    with pytest.raises(
        ReplayStoreError,
        match="closed",
    ):
        store.contains(
            "nonce-1"
        )


def test_empty_key_rejected(
    tmp_path,
):
    with SQLiteReplayStore(
        tmp_path
        / "replay.db"
    ) as store:
        with pytest.raises(
            ValueError
        ):
            store.consume(
                "",
                future_time(),
            )