import threading

import pytest

from firewall.capability import (
    generate_capability_key_pair,
    sign_capability,
)

from firewall.replay import (
    ReplayKey,
    ReplayProtector,
    capability_replay_fingerprint,
    generate_nonce,
    is_replay,
    make_replay_key,
)


def make_capability(
    private_key,
    **overrides,
):
    values = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "constraints": {},
        "issuer": "trusted-issuer",
        "issued_at": 1000,
        "expires_at": 2000,
    }

    values.update(overrides)

    return sign_capability(
        private_key=private_key,
        **values,
    )


def make_protector():
    return ReplayProtector(
        clock=lambda: 1500
    )


# ============================================================
# ReplayKey
# ============================================================


def test_replay_key_string():
    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert (
        key.as_string()
        == "agent-a:fingerprint:nonce-1"
    )


def test_replay_key_is_immutable():
    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    with pytest.raises(
        AttributeError
    ):
        key.agent_id = "agent-b"


# ============================================================
# Nonces
# ============================================================


def test_nonce_is_generated():
    nonce = generate_nonce()

    assert isinstance(
        nonce,
        str,
    )

    assert nonce


def test_generated_nonces_are_different():
    first = generate_nonce()
    second = generate_nonce()

    assert first != second


# ============================================================
# Fingerprints
# ============================================================


def test_capability_fingerprint_is_stable():
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    first = capability_replay_fingerprint(
        capability
    )

    second = capability_replay_fingerprint(
        capability
    )

    assert first == second


def test_different_capabilities_have_different_fingerprints():
    private_key, _ = (
        generate_capability_key_pair()
    )

    first = make_capability(
        private_key,
        capability="payments.send",
    )

    second = make_capability(
        private_key,
        capability="payments.refund",
    )

    assert (
        capability_replay_fingerprint(
            first
        )
        != capability_replay_fingerprint(
            second
        )
    )


# ============================================================
# Replay keys
# ============================================================


def test_make_replay_key():
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    key = make_replay_key(
        "finance-agent",
        capability,
        "nonce-1",
    )

    assert key.agent_id == "finance-agent"
    assert key.nonce == "nonce-1"
    assert key.capability_fingerprint


def test_empty_agent_rejected():
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    with pytest.raises(ValueError):
        make_replay_key(
            "",
            capability,
            "nonce-1",
        )


def test_empty_nonce_rejected():
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    with pytest.raises(ValueError):
        make_replay_key(
            "agent-a",
            capability,
            "",
        )


# ============================================================
# First use
# ============================================================


def test_first_use_is_allowed():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        2000,
    ) is True


def test_first_use_marks_key_seen():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    protector.check_and_consume(
        key,
        2000,
    )

    assert protector.seen(
        key
    ) is True


# ============================================================
# Replay detection
# ============================================================


def test_second_use_is_rejected():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        2000,
    ) is True

    assert protector.check_and_consume(
        key,
        2000,
    ) is False


def test_is_replay_helper():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert is_replay(
        protector,
        key,
    ) is False

    protector.check_and_consume(
        key,
        2000,
    )

    assert is_replay(
        protector,
        key,
    ) is True


# ============================================================
# Agent binding
# ============================================================


def test_different_agents_do_not_share_replay_key():
    protector = make_protector()

    first = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    second = ReplayKey(
        "agent-b",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        first,
        2000,
    ) is True

    assert protector.check_and_consume(
        second,
        2000,
    ) is True


# ============================================================
# Capability binding
# ============================================================


def test_different_capabilities_do_not_share_replay_key():
    protector = make_protector()

    first = ReplayKey(
        "agent-a",
        "fingerprint-a",
        "nonce-1",
    )

    second = ReplayKey(
        "agent-a",
        "fingerprint-b",
        "nonce-1",
    )

    assert protector.check_and_consume(
        first,
        2000,
    ) is True

    assert protector.check_and_consume(
        second,
        2000,
    ) is True


# ============================================================
# Expiration
# ============================================================


def test_expired_key_is_rejected():
    protector = ReplayProtector(
        clock=lambda: 2000
    )

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        2000,
    ) is False


def test_future_expiry_is_accepted():
    protector = ReplayProtector(
        clock=lambda: 1500
    )

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        2000,
    ) is True


# ============================================================
# Cleanup
# ============================================================


def test_expired_entries_are_cleaned():
    current_time = [1500]

    protector = ReplayProtector(
        clock=lambda: current_time[0]
    )

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        1600,
    ) is True

    assert protector.size() == 1

    current_time[0] = 1700

    assert protector.size() == 0
    assert protector.seen(key) is False


def test_non_expired_entries_remain():
    current_time = [1500]

    protector = ReplayProtector(
        clock=lambda: current_time[0]
    )

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    protector.check_and_consume(
        key,
        2000,
    )

    current_time[0] = 1900

    assert protector.seen(
        key
    ) is True


# ============================================================
# Clear / size
# ============================================================


def test_size_counts_entries():
    protector = make_protector()

    for index in range(3):
        protector.check_and_consume(
            ReplayKey(
                "agent-a",
                f"fingerprint-{index}",
                f"nonce-{index}",
            ),
            2000,
        )

    assert protector.size() == 3


def test_clear_removes_entries():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    protector.check_and_consume(
        key,
        2000,
    )

    protector.clear()

    assert protector.size() == 0
    assert protector.seen(key) is False


# ============================================================
# Invalid inputs
# ============================================================


def test_invalid_replay_key_type_rejected():
    protector = make_protector()

    with pytest.raises(TypeError):
        protector.check_and_consume(
            "invalid",
            2000,
        )


def test_negative_expiry_is_rejected_by_time():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        -1,
    ) is False


# ============================================================
# Concurrency
# ============================================================


def test_concurrent_first_use_only_one_wins():
    protector = make_protector()

    key = ReplayKey(
        "agent-a",
        "fingerprint",
        "nonce-1",
    )

    results = []
    lock = threading.Lock()

    def worker():
        value = protector.check_and_consume(
            key,
            2000,
        )

        with lock:
            results.append(value)

    threads = [
        threading.Thread(
            target=worker
        )
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 19


def test_different_nonces_can_be_used_concurrently():
    protector = make_protector()

    results = []

    def worker(index):
        key = ReplayKey(
            "agent-a",
            "fingerprint",
            f"nonce-{index}",
        )

        results.append(
            protector.check_and_consume(
                key,
                2000,
            )
        )

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

    assert all(results)
    assert len(results) == 10


# ============================================================
# Capability-bound replay
# ============================================================


def test_same_nonce_different_capabilities_allowed():
    private_key, _ = (
        generate_capability_key_pair()
    )

    first_capability = make_capability(
        private_key,
        capability="payments.send",
    )

    second_capability = make_capability(
        private_key,
        capability="payments.refund",
    )

    protector = make_protector()

    first_key = make_replay_key(
        "finance-agent",
        first_capability,
        "nonce-1",
    )

    second_key = make_replay_key(
        "finance-agent",
        second_capability,
        "nonce-1",
    )

    assert protector.check_and_consume(
        first_key,
        2000,
    ) is True

    assert protector.check_and_consume(
        second_key,
        2000,
    ) is True


def test_same_capability_same_nonce_rejected():
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = make_capability(
        private_key
    )

    protector = make_protector()

    first_key = make_replay_key(
        "finance-agent",
        capability,
        "nonce-1",
    )

    second_key = make_replay_key(
        "finance-agent",
        capability,
        "nonce-1",
    )

    assert protector.check_and_consume(
        first_key,
        2000,
    ) is True

    assert protector.check_and_consume(
        second_key,
        2000,
    ) is False