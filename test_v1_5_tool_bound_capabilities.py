from __future__ import annotations

import time

import pytest

from firewall.capability import generate_capability_key_pair
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")
    return sdk


def test_capability_is_bound_to_exact_tool():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        issued_at=time.time() - 1,
        expires_at=time.time() + 3600,
    )

    allowed = sdk.authorize(
        capability,
        "filesystem.read",
        {
            "resource": "/proj",
        },
    )

    denied = sdk.authorize(
        capability,
        "filesystem.write",
        {
            "resource": "/proj",
        },
    )

    assert allowed.allowed
    assert not denied.allowed


def test_read_capability_does_not_imply_bash():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        issued_at=time.time() - 1,
        expires_at=time.time() + 3600,
    )

    result = sdk.authorize(
        capability,
        "bash",
        {
            "command": "ls /proj",
        },
    )

    assert not result.allowed


def test_network_requires_separate_capability():
    sdk = make_sdk()

    filesystem_capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        issued_at=time.time() - 1,
        expires_at=time.time() + 3600,
    )

    result = sdk.authorize(
        filesystem_capability,
        "network.request",
        {
            "url": "https://example.com",
        },
    )

    assert not result.allowed


def test_capability_resource_scope_is_enforced():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        issued_at=time.time() - 1,
        expires_at=time.time() + 3600,
    )

    allowed = sdk.authorize(
        capability,
        "filesystem.read",
        {
            "resource": "/proj",
        },
    )

    denied = sdk.authorize(
        capability,
        "filesystem.read",
        {
            "resource": "/secrets",
        },
    )

    assert allowed.allowed
    assert not denied.allowed


def test_expired_tool_capability_is_denied():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        issued_at=time.time() - 100,
        expires_at=time.time() - 1,
    )

    result = sdk.authorize(
        capability,
        "filesystem.read",
        {
            "resource": "/proj",
        },
    )

    assert not result.allowed


def test_tool_name_cannot_be_broadened_by_wildcard_request():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        constraints={
            "resource": "/proj",
        },
        issued_at=time.time() - 1,
        expires_at=time.time() + 3600,
    )

    result = sdk.authorize(
        capability,
        "filesystem.*",
        {
            "resource": "/proj",
        },
    )

    assert not result.allowed