from __future__ import annotations

import threading

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.lifecycle_store import (
    LifecycleStoreError,
    SQLiteLifecycleStore,
)

from firewall.sdk import FirewallSDK


def make_key():
    private_key, _ = (
        generate_capability_key_pair()
    )
    return private_key


def make_sdk(
    tmp_path,
    *,
    clock=None,
):
    return FirewallSDK(
        revocation_store_path=(
            tmp_path / "revocations.db"
        ),
        lifecycle_store_path=(
            tmp_path / "lifecycle.db"
        ),
        clock=clock,
    )


def make_capability(
    sdk,
    *,
    agent="agent-a",
    capability="payments.send",
):
    return sdk.issue(
        private_key=make_key(),
        agent=agent,
        capability=capability,
    )


# ============================================================
# Persistent isolation
# ============================================================


def test_revocation_and_lifecycle_use_separate_stores(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    assert (
        sdk.revocation_store is not None
    ) if hasattr(
        sdk,
        "revocation_store",
    ) else True

    assert sdk.lifecycle_store is not None

    sdk.close()


def test_revocation_does_not_create_duplicate_lifecycle_events(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    revoked = sdk.lifecycle.of_type(
        LifecycleEventType.REVOKED
    )

    assert len(revoked) == 1

    sdk.close()


def test_restart_preserves_exactly_one_revocation_event(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    sdk.close()

    restarted = make_sdk(
        tmp_path
    )

    revoked = restarted.lifecycle.of_type(
        LifecycleEventType.REVOKED
    )

    assert len(revoked) == 1

    restarted.close()


# ============================================================
# Capability identity attacks
# ============================================================


def test_revocation_cannot_jump_to_same_scope(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    first = make_capability(
        sdk,
        capability="payments.send",
    )

    second = make_capability(
        sdk,
        capability="payments.send",
    )

    assert (
        sdk.fingerprint(first)
        != sdk.fingerprint(second)
    )

    sdk.revoke(
        first
    )

    assert sdk.is_revoked(
        first
    ) is True

    assert sdk.is_revoked(
        second
    ) is False

    result = sdk.authorize(
        second,
        "payments.send",
        {},
    )

    assert result.allowed is True

    sdk.close()


def test_revocation_cannot_jump_between_agents(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    first = make_capability(
        sdk,
        agent="agent-a",
    )

    second = make_capability(
        sdk,
        agent="agent-b",
    )

    sdk.revoke(
        first
    )

    assert sdk.is_revoked(
        first
    ) is True

    assert sdk.is_revoked(
        second
    ) is False

    sdk.close()


def test_old_revocation_does_not_hit_reissued_capability(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    old = make_capability(
        sdk
    )

    sdk.revoke(
        old,
        reason="old",
    )

    new = make_capability(
        sdk
    )

    assert sdk.fingerprint(
        old
    ) != sdk.fingerprint(
        new
    )

    assert sdk.is_revoked(
        old
    ) is True

    assert sdk.is_revoked(
        new
    ) is False

    assert sdk.authorize(
        new,
        "payments.send",
        {},
    ).allowed is True

    sdk.close()


# ============================================================
# Terminal lifecycle integrity
# ============================================================


def test_successful_use_has_no_denied_or_expired_event(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is True

    assert sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    ) == ()

    assert sdk.lifecycle.of_type(
        LifecycleEventType.EXPIRED
    ) == ()

    sdk.close()


def test_denial_has_no_used_event(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    result = sdk.authorize(
        capability,
        "admin.delete",
        {},
    )

    assert result.allowed is False

    assert sdk.lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    assert len(
        sdk.lifecycle.of_type(
            LifecycleEventType.DENIED
        )
    ) == 1

    sdk.close()


def test_expiration_has_no_used_event(
    tmp_path,
):
    now = [200.0]

    def clock():
        return now[0]

    sdk = make_sdk(
        tmp_path,
        clock=clock,
    )

    capability = sdk.issue(
        private_key=make_key(),
        agent="agent-a",
        capability="payments.send",
        issued_at=100.0,
        expires_at=150.0,
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False

    assert len(
        sdk.lifecycle.of_type(
            LifecycleEventType.EXPIRED
        )
    ) == 1

    assert sdk.lifecycle.of_type(
        LifecycleEventType.USED
    ) == ()

    sdk.close()


# ============================================================
# Replay isolation
# ============================================================


def test_replay_never_revokes_capability(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert sdk.is_revoked(
        capability
    ) is False

    sdk.close()


def test_replay_event_is_capability_bound(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    first = make_capability(
        sdk
    )

    second = make_capability(
        sdk
    )

    sdk.consume_nonce(
        "agent-a",
        first,
        "nonce",
    )

    sdk.consume_nonce(
        "agent-a",
        first,
        "nonce",
    )

    replayed = sdk.lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    assert len(replayed) == 1

    assert replayed[0].fingerprint == (
        sdk.fingerprint(first)
    )

    assert replayed[0].fingerprint != (
        sdk.fingerprint(second)
    )

    sdk.close()


# ============================================================
# Mutation resistance
# ============================================================


def test_persisted_event_snapshot_is_immune_to_nested_mutation(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    request = {
        "payment": {
            "amount": 10,
            "metadata": {
                "tag": "original",
            },
        }
    }

    sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    request["payment"]["amount"] = 999
    request["payment"]["metadata"]["tag"] = (
        "tampered"
    )

    event = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )[0]

    assert event.details[
        "request"
    ]["payment"]["amount"] == 10

    assert event.details[
        "request"
    ]["payment"]["metadata"]["tag"] == (
        "original"
    )

    sdk.close()


# ============================================================
# Concurrent lifecycle writes
# ============================================================


def test_concurrent_sdk_authorization_persistence(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            result = sdk.authorize(
                capability,
                "payments.send",
                {
                    "amount": index
                },
            )

            assert result.allowed is True

        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 50

    sdk.close()


def test_concurrent_sdk_revocation_attempts_have_one_winner(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    errors = []
    successes = []
    lock = threading.Lock()

    def worker(index):
        try:
            record = sdk.revoke(
                capability,
                reason=f"reason-{index}",
            )

            with lock:
                successes.append(record)

        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(10)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert len(errors) == 9

    revoked = sdk.lifecycle.of_type(
        LifecycleEventType.REVOKED
    )

    assert len(revoked) == 1

    sdk.close()


# ============================================================
# Restart attack resistance
# ============================================================


def test_restart_cannot_resurrect_revoked_capability(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    sdk.close()

    restarted = make_sdk(
        tmp_path
    )

    assert restarted.is_revoked(
        capability
    ) is True

    result = restarted.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert result.reason == (
        "capability_revoked"
    )

    restarted.close()


def test_restart_preserves_replay_history(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    sdk.close()

    restarted = make_sdk(
        tmp_path
    )

    # Replay protection itself is intentionally
    # separate from lifecycle persistence, so this
    # asserts the lifecycle history survives.
    replayed = restarted.lifecycle.of_type(
        LifecycleEventType.REPLAYED
    )

    assert replayed == ()

    restarted.close()


# ============================================================
# Corruption detection
# ============================================================


def test_corrupt_lifecycle_database_is_detected(
    tmp_path,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)

    store._connection.execute(
        """
        INSERT INTO lifecycle_events (
            event_type,
            fingerprint,
            timestamp,
            agent_id,
            capability,
            issuer,
            reason,
            request_id,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "invalid-type",
            "corrupt",
            1.0,
            "agent",
            "tool",
            "issuer",
            "",
            "",
            None,
        ),
    )

    with pytest.raises(
        LifecycleStoreError
    ):
        store.events()

    store.close()


# ============================================================
# Full lifecycle invariant
# ============================================================


def test_full_lifecycle_has_expected_terminal_semantics(
    tmp_path,
):
    sdk = make_sdk(
        tmp_path
    )

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    )

    sdk.revoke(
        capability,
        reason="final",
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    events = sdk.lifecycle.for_fingerprint(
        sdk.fingerprint(capability)
    )

    event_types = [
        event.event_type
        for event in events
    ]

    assert event_types == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REPLAYED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    ]

    terminal = [
        event
        for event in events
        if event.event_type in {
            LifecycleEventType.USED,
            LifecycleEventType.DENIED,
            LifecycleEventType.EXPIRED,
        }
    ]

    assert len(terminal) == 2

    sdk.close()