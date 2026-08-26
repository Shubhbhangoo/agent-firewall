from __future__ import annotations

import json

from firewall.authorization import authorize
from firewall.capability import (
    Capability,
    capability_fingerprint,
)
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("trace-key")
    return sdk


def test_namespace_denial_contains_capability_identity():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
    )

    result = sdk.authorize(
        capability,
        "filesystem.write",
        {},
    )

    assert not result.allowed
    assert result.reason == "namespace_denied"

    trace = result.trace
    assert trace is not None
    assert trace["capability_id"] == capability_fingerprint(
        capability
    )
    assert trace["agent"] == "agent-a"
    assert trace["action"] == "filesystem.write"
    assert trace["reason"] == "namespace_denied"


def test_tool_binding_denial_identifies_bound_capability():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        tool="filesystem.read",
    )

    result = sdk.authorize(
        capability,
        "bash",
        {},
    )

    assert not result.allowed
    assert result.reason == "tool_binding_denied"

    trace = result.trace

    assert trace["capability_id"] == capability_fingerprint(
        capability
    )
    assert trace["agent"] == "agent-a"
    assert trace["action"] == "bash"
    assert trace["reason"] == "tool_binding_denied"
    assert trace["tool"] == "filesystem.read"


def test_constraint_denial_contains_capability_identity():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": 101,
        },
    )

    assert not result.allowed
    assert result.reason == "constraint_denied"

    trace = result.trace

    assert trace["capability_id"] == capability_fingerprint(
        capability
    )
    assert trace["agent"] == "agent-a"
    assert trace["action"] == "payments.send"
    assert trace["reason"] == "constraint_denied"


def test_expired_capability_contains_capability_identity():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
        issued_at=100.0,
        expires_at=200.0,
    )

    result = authorize(
        capability,
        "filesystem.read",
        {},
        clock=lambda: 200.0,
    )

    assert not result.allowed
    assert result.reason == "expired"

    trace = result.trace

    assert trace["capability_id"] == capability_fingerprint(
        capability
    )
    assert trace["agent"] == "agent-a"
    assert trace["action"] == "filesystem.read"
    assert trace["reason"] == "expired"


def test_invalid_signature_trace_does_not_leak_signed_payload():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    tampered = Capability(
        agent_id=capability.agent_id,
        capability=capability.capability,
        constraints={
            "amount_max": 999999,
        },
        issuer=capability.issuer,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        public_key=capability.public_key,
        signature=capability.signature,
        key_id=capability.key_id,
        tool=capability.tool,
    )

    result = authorize(
        tampered,
        "payments.send",
        {
            "amount": 50,
        },
        verifier=sdk.verifier,
    )

    assert not result.allowed
    assert result.reason == "invalid_signature"

    trace = result.trace

    assert trace["capability_id"] == capability_fingerprint(
        tampered
    )
    assert trace["agent"] == "agent-a"
    assert trace["action"] == "payments.send"
    assert trace["reason"] == "invalid_signature"

    assert "signature" not in trace
    assert "public_key" not in trace
    assert "constraints" not in trace
    assert "payload" not in trace


def test_successful_authorization_has_trace():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
    )

    result = sdk.authorize(
        capability,
        "filesystem.read",
        {},
    )

    assert result.allowed
    assert result.reason == "authorized"

    trace = result.trace

    assert trace is not None
    assert trace["capability_id"] == capability_fingerprint(
        capability
    )
    assert trace["agent"] == "agent-a"
    assert trace["action"] == "filesystem.read"
    assert trace["reason"] == "authorized"


def test_trace_for_delegated_child_identifies_child_capability():
    sdk = make_sdk()

    parent = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    delegation = sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee="agent-b",
    )

    child = delegation.child

    result = sdk.authorize(
        child,
        "payments.refund",
        {},
    )

    assert not result.allowed
    assert result.reason == "namespace_denied"

    trace = result.trace

    assert trace["capability_id"] == capability_fingerprint(
        child
    )
    assert trace["capability_id"] != (
        capability_fingerprint(parent)
    )
    assert trace["agent"] == "agent-b"
    assert trace["action"] == "payments.refund"
    assert trace["reason"] == "namespace_denied"


def test_trace_is_json_serializable():
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="filesystem.read",
    )

    result = sdk.authorize(
        capability,
        "filesystem.write",
        {},
    )

    assert not result.allowed

    serialized = json.dumps(
        result.trace,
        sort_keys=True,
    )

    assert serialized
