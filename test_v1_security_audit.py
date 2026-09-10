from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from firewall.mcp import (
    MCPAuthorizationError,
    MCPFirewall,
)
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("key-1")
    return sdk


def test_revocation_beats_replay_reuse():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    sdk.revoke(
        capability,
        reason="audit",
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce-1",
    ) is False

    assert sdk.is_authorized(
        capability,
        "payments.send",
        {},
    ) is False


def test_rotation_preserves_old_capability_verification():
    sdk = make_sdk()

    old_capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    sdk.rotate_key("key-2")

    new_capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    assert old_capability.key_id == "key-1"
    assert new_capability.key_id == "key-2"

    assert sdk.verify(
        old_capability
    ) is True

    assert sdk.verify(
        new_capability
    ) is True


def test_retired_key_cannot_issue():
    sdk = make_sdk()

    sdk.retire_key(
        "key-1"
    )

    with pytest.raises(
        ValueError,
        match="no active key",
    ):
        sdk.issue(
            agent="agent-a",
            capability="payments.send",
        )


def test_policy_failure_does_not_authorize():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "and": [
                {
                    "currency": {
                        "eq": "USD",
                    }
                },
                {
                    "amount": {
                        "lte": 100,
                    }
                },
            ]
        },
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "currency": "USD",
            "amount": 101,
        },
    )

    assert result.allowed is False


def test_mcp_denial_never_reaches_handler():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        expires_at=4_000_000_000,
    )

    token = sdk.encode(
        capability
    )

    request = firewall.request(
        agent="agent-a",
        tool="admin.delete",
        arguments={},
        capability_token=token,
        nonce="audit-1",
    )

    called = False

    def handler(arguments):
        nonlocal called
        called = True
        return "BAD"

    with pytest.raises(
        MCPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called is False


def test_concurrent_same_nonce_has_one_authority():
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
            "audit-nonce",
        )

    with ThreadPoolExecutor(
        max_workers=16
    ) as pool:
        results = list(
            pool.map(
                lambda _: consume(),
                range(32),
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == 31