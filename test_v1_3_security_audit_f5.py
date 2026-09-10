from __future__ import annotations

import time

from firewall.sdk import FirewallSDK


def test_revoked_parent_revokes_attenuated_child():
    sdk = FirewallSDK()

    sdk.generate_key("test-key")

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
        issued_at=time.time() - 10,
        expires_at=time.time() + 3600,
    )

    child = sdk.attenuate(
        parent,
        sdk.active_key().private_key,
        constraints={
            "amount_max": 50,
        },
    )

    before = sdk.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert before.allowed

    sdk.revoke(parent)

    after = sdk.authorize(
        child,
        "payments.send",
        {"amount": 50},
    )

    assert not after.allowed
    assert after.reason == "capability_revoked"


def test_revoking_attenuated_child_does_not_revoke_parent():
    sdk = FirewallSDK()

    sdk.generate_key("test-key")

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
        issued_at=time.time() - 10,
        expires_at=time.time() + 3600,
    )

    child = sdk.attenuate(
        parent,
        sdk.active_key().private_key,
        constraints={
            "amount_max": 50,
        },
    )

    sdk.revoke(child)

    child_result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 25},
    )

    parent_result = sdk.authorize(
        parent,
        "payments.send",
        {"amount": 100},
    )

    assert not child_result.allowed
    assert child_result.reason == "capability_revoked"

    assert parent_result.allowed