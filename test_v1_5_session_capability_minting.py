from __future__ import annotations

import time

import pytest

from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("session-key")
    return sdk


def test_session_mint_creates_tool_bound_capability():
    sdk = make_sdk()

    capability = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        ttl=60,
    )

    assert capability.agent_id == "agent-a"
    assert capability.tool == "filesystem.read"
    assert capability.expires_at > capability.issued_at


def test_session_capability_expires_after_ttl():
    sdk = make_sdk()

    capability = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=1,
    )

    assert (
        capability.expires_at
        == capability.issued_at + 1
    )


def test_session_capability_cannot_be_used_for_another_tool():
    sdk = make_sdk()

    capability = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=60,
    )

    result = sdk.authorize(
        capability,
        "bash",
        {},
    )

    assert not result.allowed
    assert result.reason == "tool_binding_denied"


def test_session_capability_requires_explicit_network_grant():
    sdk = make_sdk()

    capability = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=60,
    )

    result = sdk.authorize(
        capability,
        "network.request",
        {
            "url": "https://example.com",
        },
    )

    assert not result.allowed


def test_session_capability_cannot_use_negative_ttl():
    sdk = make_sdk()

    with pytest.raises(ValueError):
        sdk.mint_session_capability(
            agent="agent-a",
            tool="filesystem.read",
            capability="filesystem.read",
            ttl=-1,
        )


def test_session_capability_has_fresh_expiration():
    sdk = make_sdk()

    before = time.time()

    capability = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=60,
    )

    after = time.time()

    assert before <= capability.issued_at <= after
    assert (
        capability.expires_at
        == capability.issued_at + 60
    )