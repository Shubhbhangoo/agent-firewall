from __future__ import annotations
from threading import Barrier
from concurrent.futures import ThreadPoolExecutor

from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("key-1")
    return sdk


def test_concurrent_nonce_consumption_has_single_winner():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    def consume():
        return sdk.consume_nonce(
            "agent-a",
            capability,
            "same-nonce",
        )

    with ThreadPoolExecutor(
        max_workers=32
    ) as pool:
        results = list(
            pool.map(
                lambda _: consume(),
                range(100),
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == 99


def test_concurrent_different_nonces_can_succeed():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    def consume(index):
        return sdk.consume_nonce(
            "agent-a",
            capability,
            f"nonce-{index}",
        )

    with ThreadPoolExecutor(
        max_workers=32
    ) as pool:
        results = list(
            pool.map(
                consume,
                range(100),
            )
        )

    assert all(results)

def test_concurrent_revoke_and_authorize_never_allows_after_revocation():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    barrier = Barrier(2)

    results = []

    def authorize():
        barrier.wait()
        results.append(
            sdk.is_authorized(
                capability,
                "payments.send",
                {},
            )
        )

    def revoke():
        barrier.wait()
        sdk.revoke(
            capability,
            reason="concurrency-test",
        )

    with ThreadPoolExecutor(
        max_workers=2
    ) as pool:
        futures = [
            pool.submit(authorize),
            pool.submit(revoke),
        ]

        for future in futures:
            future.result()

    assert sdk.is_revoked(
        capability
    ) is True

    # Once revocation has committed, no subsequent
    # authorization may succeed.
    assert sdk.is_authorized(
        capability,
        "payments.send",
        {},
    ) is False


def test_concurrent_key_generation_does_not_create_multiple_active_keys():
    sdk = FirewallSDK()

    def generate(index):
        return sdk.generate_key(
            f"key-{index}"
        )

    with ThreadPoolExecutor(
        max_workers=16
    ) as pool:
        records = list(
            pool.map(
                generate,
                range(16),
            )
        )

    active = [
        record
        for record in records
        if record.active
    ]

    assert len(active) == 1

def test_concurrent_key_rotation_keeps_one_active_key():
    sdk = make_sdk()

    barrier = Barrier(2)

    def rotate(key_id):
        barrier.wait()
        return sdk.rotate_key(key_id)

    with ThreadPoolExecutor(
        max_workers=2
    ) as pool:
        futures = [
            pool.submit(
                rotate,
                "key-2",
            ),
            pool.submit(
                rotate,
                "key-3",
            ),
        ]

        results = []

        for future in futures:
            try:
                results.append(
                    future.result()
                )
            except ValueError:
                # Duplicate/competing rotation may legitimately
                # lose the race, but must not corrupt state.
                pass

    active = [
        key_id
        for key_id in sdk.key_manager.key_ids()
        if sdk.key_manager.is_active(key_id)
    ]

    assert len(active) == 1
    assert sdk.active_key().key_id in {
        "key-2",
        "key-3",
    }

    assert len(results) >= 1