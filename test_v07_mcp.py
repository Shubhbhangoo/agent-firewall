import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.mcp import (
    MCPAuthorizationError,
    MCPDecision,
    MCPFirewall,
    MCPRequest,
)

from firewall.sdk import FirewallSDK


def make_sdk():
    return FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        }
    )


def make_capability(
    sdk,
    *,
    agent="finance-agent",
    capability="payments.send",
    constraints=None,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
    )


def make_request(
    sdk,
    *,
    agent="finance-agent",
    tool="payments.send",
    arguments=None,
    nonce="nonce-1",
):
    capability = make_capability(
        sdk,
        agent=agent,
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
    )


def make_adapter():
    return MCPFirewall(
        make_sdk()
    )


# ============================================================
# Initialization
# ============================================================


def test_mcp_initializes():
    adapter = make_adapter()

    assert adapter.sdk is not None
    assert adapter.require_nonce is True


def test_mcp_rejects_invalid_sdk():
    with pytest.raises(TypeError):
        MCPFirewall("invalid")


def test_nonce_requirement_can_be_disabled():
    adapter = MCPFirewall(
        make_sdk(),
        require_nonce=False,
    )

    assert adapter.require_nonce is False


# ============================================================
# Request object
# ============================================================


def test_request_builder():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    request = MCPFirewall.request(
        agent="finance-agent",
        tool="payments.send",
        arguments={"amount": 10},
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    assert isinstance(
        request,
        MCPRequest,
    )


def test_request_defaults_arguments():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    request = MCPFirewall.request(
        agent="finance-agent",
        tool="payments.send",
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    assert request.arguments == {}


def test_request_copies_arguments():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    arguments = {
        "amount": 10
    }

    request = MCPFirewall.request(
        agent="finance-agent",
        tool="payments.send",
        arguments=arguments,
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    arguments["amount"] = 999

    assert request.arguments[
        "amount"
    ] == 10


def test_request_rejects_non_dict_arguments():
    sdk = make_sdk()

    capability = make_capability(
        sdk
    )

    with pytest.raises(TypeError):
        MCPFirewall.request(
            agent="finance-agent",
            tool="payments.send",
            arguments=[],
            capability_token=sdk.encode(
                capability
            ),
            nonce="nonce-1",
        )


# ============================================================
# Decode
# ============================================================


def test_decode_valid_capability():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk
    )

    restored = adapter.decode_capability(
        sdk.encode(capability)
    )

    assert (
        restored.to_dict()
        == capability.to_dict()
    )


def test_decode_invalid_capability_rejected():
    adapter = make_adapter()

    with pytest.raises(Exception):
        adapter.decode_capability(
            "garbage"
        )


# ============================================================
# Authorization
# ============================================================


def test_authorize_valid_request():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk
    )

    decision = adapter.authorize(
        request
    )

    assert isinstance(
        decision,
        MCPDecision,
    )

    assert decision.allowed is True


def test_authorize_returns_tool():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        tool="payments.send",
    )

    decision = adapter.authorize(
        request
    )

    assert (
        decision.tool
        == "payments.send"
    )


def test_authorize_returns_agent():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        agent="finance-agent",
    )

    decision = adapter.authorize(
        request
    )

    assert (
        decision.agent
        == "finance-agent"
    )


def test_wrong_tool_denied():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        tool="payments.admin",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False


def test_wrong_agent_denied():
    sdk = make_sdk()

    capability = make_capability(
        sdk,
        agent="agent-a",
    )

    request = MCPRequest(
        agent="agent-b",
        tool="payments.send",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    decision = MCPFirewall(
        sdk
    ).authorize(
        request
    )

    assert decision.allowed is False


# ============================================================
# Constraints
# ============================================================


def test_constraint_allowed():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={
            "amount": 50
        },
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is True


def test_constraint_denied():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={
            "amount": 101
        },
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False


# ============================================================
# Replay
# ============================================================


def test_first_nonce_allowed():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="nonce-1",
    )

    assert adapter.authorize(
        request
    ).allowed is True


def test_replayed_nonce_denied():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="nonce-1",
    )

    first = adapter.authorize(
        request
    )

    second = adapter.authorize(
        request
    )

    assert first.allowed is True
    assert second.allowed is False
    assert (
        second.reason
        == "replay detected"
    )


def test_different_nonce_allowed():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    first = make_request(
        sdk,
        nonce="nonce-1",
    )

    second = make_request(
        sdk,
        nonce="nonce-2",
    )

    assert adapter.authorize(
        first
    ).allowed is True

    assert adapter.authorize(
        second
    ).allowed is True


def test_missing_nonce_denied():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False
    assert (
        decision.reason
        == "nonce is required"
    )


def test_nonce_can_be_disabled():
    sdk = make_sdk()

    adapter = MCPFirewall(
        sdk,
        require_nonce=False,
    )

    request = make_request(
        sdk,
        nonce="",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is True


# ============================================================
# Capability tampering
# ============================================================


def test_tampered_token_denied():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk
    )

    token = sdk.encode(
        capability
    )

    tampered = (
        token[:-1]
        + (
            "A"
            if token[-1] != "A"
            else "B"
        )
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={},
        capability_token=tampered,
        nonce="nonce-1",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False


def test_garbage_token_denied():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={},
        capability_token="garbage",
        nonce="nonce-1",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False


# ============================================================
# Wildcards
# ============================================================


def test_wildcard_allows_child_tool():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    assert adapter.authorize(
        request
    ).allowed is True


def test_wildcard_denies_other_namespace():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="accounts.read",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    assert adapter.authorize(
        request
    ).allowed is False


# ============================================================
# Enforcement
# ============================================================


def test_enforce_allows_valid_request():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk
    )

    decision = adapter.enforce(
        request
    )

    assert decision.allowed is True


def test_enforce_rejects_invalid_request():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        tool="payments.admin",
    )

    with pytest.raises(
        MCPAuthorizationError
    ):
        adapter.enforce(
            request
        )


def test_enforce_replay_rejected():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk
    )

    adapter.enforce(
        request
    )

    with pytest.raises(
        MCPAuthorizationError
    ):
        adapter.enforce(
            request
        )


# ============================================================
# Execution
# ============================================================


def test_execute_calls_handler():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={
            "amount": 50
        },
    )

    seen = []

    def handler(arguments):
        seen.append(arguments)
        return "ok"

    result = adapter.execute(
        request,
        handler,
    )

    assert result == "ok"
    assert seen == [
        {
            "amount": 50
        }
    ]


def test_execute_does_not_call_denied_handler():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        tool="payments.admin",
    )

    called = []

    def handler(arguments):
        called.append(True)
        return "bad"

    with pytest.raises(
        MCPAuthorizationError
    ):
        adapter.execute(
            request,
            handler,
        )

    assert called == []


def test_execute_rejects_non_callable():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk
    )

    with pytest.raises(TypeError):
        adapter.execute(
            request,
            "not callable",
        )


def test_execute_passes_arguments_only():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={
            "amount": 25,
            "currency": "USD",
        },
    )

    def handler(arguments):
        return arguments

    result = adapter.execute(
        request,
        handler,
    )

    assert result == {
        "amount": 25,
        "currency": "USD",
    }


# ============================================================
# End-to-end
# ============================================================


def test_complete_mcp_flow():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="payments.send",
        constraints={
            "amount_max": 100,
        },
    )

    token = sdk.encode(
        capability
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={
            "amount": 75
        },
        capability_token=token,
        nonce="request-1",
    )

    result = adapter.execute(
        request,
        lambda args: {
            "status": "sent",
            "amount": args[
                "amount"
            ],
        },
    )

    assert result == {
        "status": "sent",
        "amount": 75,
    }


def test_complete_mcp_replay_flow():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="request-1",
    )

    first = adapter.authorize(
        request
    )

    second = adapter.authorize(
        request
    )

    assert first.allowed is True
    assert second.allowed is False


def test_complete_mcp_constraint_flow():
    sdk = make_sdk()
    adapter = MCPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100,
        },
    )

    request = MCPRequest(
        agent="finance-agent",
        tool="payments.send",
        arguments={
            "amount": 101
        },
        capability_token=sdk.encode(
            capability
        ),
        nonce="request-1",
    )

    with pytest.raises(
        MCPAuthorizationError
    ):
        adapter.execute(
            request,
            lambda args: "should-not-run",
        )