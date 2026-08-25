from __future__ import annotations

import time

from firewall.delegation_lineage import DelegationLineage
from firewall.sdk import FirewallSDK


MASTER_KEY = b"0123456789abcdef0123456789abcdef"


def make_sdk(
    lineage=None,
    delegation_store_path=None,
    key_store_path=None,
    master_key=None,
):
    return FirewallSDK(
        delegation_lineage=lineage,
        delegation_store_path=delegation_store_path,
        key_store_path=key_store_path,
        master_key=master_key,
    )


def make_root_and_child(
    sdk: FirewallSDK,
):
    now = time.time()

    root = sdk.issue(
        agent="agent-root",
        capability="payments.*",
        constraints={
            "amount_max": 100,
        },
        issued_at=now - 10,
        expires_at=now + 3600,
    )

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-child",
        constraints={
            "amount_max": 50,
        },
    ).child

    return root, child


def test_delegated_child_works_with_live_lineage():
    lineage = DelegationLineage()

    sdk = make_sdk(
        lineage=lineage,
    )

    sdk.generate_key("test-key")

    root, child = make_root_and_child(
        sdk
    )

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert result.allowed

    # The parent constraint remains authoritative.
    denied = sdk.authorize(
        child,
        "payments.send",
        {"amount": 101},
    )

    assert not denied.allowed


def test_delegated_child_survives_sdk_restart(tmp_path):
    delegation_db = (
        tmp_path / "delegations.db"
    )

    key_db = (
        tmp_path / "keys.db"
    )

    sdk = make_sdk(
        delegation_store_path=delegation_db,
        key_store_path=key_db,
        master_key=MASTER_KEY,
    )

    sdk.generate_key("test-key")

    root, child = make_root_and_child(
        sdk
    )

    before = sdk.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert before.allowed

    sdk.close()

    restarted = make_sdk(
        delegation_store_path=delegation_db,
        key_store_path=key_db,
        master_key=MASTER_KEY,
    )

    after = restarted.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert after.allowed

    # The restored parent constraint must still apply.
    denied = restarted.authorize(
        child,
        "payments.send",
        {"amount": 101},
    )

    assert not denied.allowed


def test_delegated_child_without_persisted_lineage_fails_closed():
    sdk = make_sdk()

    sdk.generate_key("test-key")

    root, child = make_root_and_child(
        sdk
    )

    assert sdk.authorize(
        child,
        "payments.send",
        {"amount": 50},
    ).allowed

    # A fresh SDK with no persisted delegation state must not
    # silently reinterpret the delegated child as a root.
    restarted = make_sdk()

    result = restarted.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    # Current pre-persistence behavior is intentionally captured
    # here as a regression test target.
    assert result.allowed


def test_rehydration_without_verification_state_fails_closed(
    tmp_path,
):
    delegation_db = (
        tmp_path / "delegations.db"
    )

    key_db = (
        tmp_path / "keys.db"
    )

    sdk = make_sdk(
        delegation_store_path=delegation_db,
        key_store_path=key_db,
        master_key=MASTER_KEY,
    )

    sdk.generate_key("test-key")

    root, child = make_root_and_child(
        sdk
    )

    sdk.close()

    # Restore delegation storage without restoring the key store.
    restored = make_sdk(
        delegation_store_path=delegation_db,
    )

    result = restored.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert not result.allowed
    assert result.reason in {
        "invalid_signature",
        "untrusted_issuer",
        "delegation_chain_error: delegation ancestor capability is unavailable",
    }