from __future__ import annotations

from firewall.mcp import (
    MCPAuthorizationError,
    MCPFirewall,
    MCPRequest,
)
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("key-1")
    return sdk


def make_request(
    sdk,
    *,
    agent="agent-a",
    tool="payments.send",
    arguments=None,
    nonce="nonce-1",
):
    capability = sdk.issue(
        agent=agent,
        capability=tool,
        constraints={},
        expires_at=4_000_000_000,
    )

    token = sdk.encode(
        capability
    )

    return MCPRequest(
        agent=agent,
        tool=tool,
        arguments=(
            {}
            if arguments is None
            else arguments
        ),
        capability_token=token,
        nonce=nonce,
    ), capability


def test_valid_request_allows():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is True
    assert decision.reason == "authorized"


def test_agent_mismatch_is_denied():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk,
        agent="agent-a",
    )

    forged = MCPRequest(
        agent="agent-b",
        tool=request.tool,
        arguments=request.arguments,
        capability_token=request.capability_token,
        nonce="nonce-agent-mismatch",
    )

    decision = firewall.authorize(
        forged
    )

    assert decision.allowed is False
    assert (
        "agent" in decision.reason
    )


def test_missing_nonce_is_denied():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk,
        require_nonce=True,
    )

    request, _ = make_request(
        sdk
    )

    forged = MCPRequest(
        agent=request.agent,
        tool=request.tool,
        arguments=request.arguments,
        capability_token=request.capability_token,
        nonce="",
    )

    decision = firewall.authorize(
        forged
    )

    assert decision.allowed is False
    assert decision.reason == "nonce is required"


def test_replay_is_denied():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk
    )

    first = firewall.authorize(
        request
    )

    second = firewall.authorize(
        request
    )

    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == "replay detected"


def test_revoked_capability_is_denied():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, capability = (
        make_request(
            sdk
        )
    )

    sdk.revoke(
        capability,
        reason="security-test",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False


def test_invalid_capability_is_denied():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request = MCPRequest(
        agent="agent-a",
        tool="payments.send",
        arguments={},
        capability_token="not-a-token",
        nonce="nonce-invalid",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False
    assert (
        decision.reason.startswith(
            "invalid capability:"
        )
    )


def test_unauthorized_tool_is_denied():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk,
        tool="payments.send",
    )

    forged = MCPRequest(
        agent=request.agent,
        tool="admin.delete",
        arguments=request.arguments,
        capability_token=request.capability_token,
        nonce="nonce-tool-mismatch",
    )

    decision = firewall.authorize(
        forged
    )

    assert decision.allowed is False


def test_handler_is_not_called_on_denial():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk
    )

    forged = MCPRequest(
        agent=request.agent,
        tool="admin.delete",
        arguments=request.arguments,
        capability_token=request.capability_token,
        nonce="nonce-denied-handler",
    )

    called = False

    def handler(arguments):
        nonlocal called
        called = True
        return "executed"

    try:
        firewall.execute(
            forged,
            handler,
        )
    except MCPAuthorizationError:
        pass

    assert called is False


def test_valid_request_executes_handler():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk,
        arguments={
            "amount": 50
        },
    )

    seen = []

    def handler(arguments):
        seen.append(arguments)
        return "ok"

    result = firewall.execute(
        request,
        handler,
    )

    assert result == "ok"
    assert seen == [
        {
            "amount": 50
        }
    ]


def test_non_callable_handler_is_rejected():
    sdk = make_sdk()
    firewall = MCPFirewall(
        sdk
    )

    request, _ = make_request(
        sdk
    )

    try:
        firewall.execute(
            request,
            "not-callable",
        )
    except TypeError as exc:
        assert (
            "handler must be callable"
            in str(exc)
        )
    else:
        raise AssertionError(
            "expected TypeError"
        )


def test_request_builder_rejects_non_dict_arguments():
    try:
        MCPFirewall.request(
            agent="agent-a",
            tool="payments.send",
            arguments="bad",
            capability_token="token",
            nonce="nonce",
        )
    except TypeError as exc:
        assert (
            "arguments must be a dictionary"
            in str(exc)
        )
    else:
        raise AssertionError(
            "expected TypeError"
        )