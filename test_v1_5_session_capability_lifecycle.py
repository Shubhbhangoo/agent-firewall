from __future__ import annotations

import time

import pytest

from firewall.capability import (
    Capability,
    sign_capability,
)

from firewall.attenuation import (
    can_attenuate,
)
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("session-key")
    return sdk


def test_session_capability_attenuation_preserves_tool_binding():
    sdk = make_sdk()

    parent = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        ttl=60,
    )

    child = sdk.attenuate(
        parent,
        sdk.active_key().private_key,
        constraints={
            "resource": "/proj",
        },
    )

    assert child.tool == "filesystem.read"

    allowed = sdk.authorize(
        child,
        "filesystem.read",
        {
            "resource": "/proj",
        },
    )

    denied = sdk.authorize(
        child,
        "filesystem.write",
        {
            "resource": "/proj",
        },
    )

    assert allowed.allowed
    assert not denied.allowed
    assert denied.reason == "tool_binding_denied"


def test_session_capability_cannot_attenuate_to_different_tool():
    sdk = make_sdk()

    parent = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        ttl=60,
    )

    now = time.time()

    tampered_child = sign_capability(
        sdk.active_key().private_key,
        agent_id=parent.agent_id,
        capability=parent.capability,
        constraints=dict(parent.constraints),
        issuer=parent.issuer,
        issued_at=now,
        expires_at=parent.expires_at,
        key_id=parent.key_id,
        tool="bash",
    )

    assert not can_attenuate(
        parent,
        tampered_child,
    )


def test_session_capability_delegation_preserves_tool_binding():
    sdk = make_sdk()

    parent = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        ttl=60,
    )

    delegation = sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee="agent-b",
        constraints={
            "resource": "/proj",
        },
    )

    child = delegation.child

    assert child.tool == "filesystem.read"

    allowed = sdk.authorize(
        child,
        "filesystem.read",
        {
            "resource": "/proj",
        },
    )

    denied = sdk.authorize(
        child,
        "bash",
        {
            "command": "ls",
        },
    )

    assert allowed.allowed
    assert not denied.allowed
    assert denied.reason == "tool_binding_denied"


def test_delegated_session_capability_cannot_outlive_parent_expiration():
    sdk = make_sdk()

    parent = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=1,
    )

    delegation = sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    assert child.expires_at <= parent.expires_at


def test_session_capability_cannot_be_delegated_with_longer_expiration():
    sdk = make_sdk()

    parent = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=60,
    )

    with pytest.raises(ValueError):
        sdk.delegate(
            parent,
            sdk.active_key().private_key,
            delegatee="agent-b",
            expires_at=parent.expires_at + 100,
        )


def test_session_capability_remains_short_lived_after_delegation():
    sdk = make_sdk()

    parent = sdk.mint_session_capability(
        agent="agent-a",
        tool="filesystem.read",
        capability="filesystem.read",
        ttl=60,
    )

    child = sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    now = time.time()

    assert child.expires_at >= now
    assert child.expires_at <= parent.expires_at