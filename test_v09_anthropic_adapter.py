from __future__ import annotations

import pytest

from firewall.adapters.anthropic import (
    AnthropicTool,
    anthropic_tool,
)

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.sdk import FirewallSDK


def make_capability(
    sdk,
    *,
    capability="payments.send",
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability=capability,
    )


def test_anthropic_definition():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="send_payment",
        description="Send a payment.",
        input_schema={
            "type": "object",
            "properties": {
                "amount": {
                    "type": "number",
                }
            },
            "required": [
                "amount"
            ],
        },
    )

    assert tool.definition() == {
        "name": "send_payment",
        "description": "Send a payment.",
        "input_schema": {
            "type": "object",
            "properties": {
                "amount": {
                    "type": "number",
                }
            },
            "required": [
                "amount"
            ],
        },
    }

    sdk.close()


def test_anthropic_tool_executes():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount * 2,
        name="double",
    )

    call = {
        "id": "toolu_123",
        "name": "double",
        "input": {
            "amount": 5,
        },
    }

    assert tool.execute(call) == 10

    sdk.close()


def test_anthropic_factory():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = anthropic_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="test_tool",
    )

    assert isinstance(
        tool,
        AnthropicTool,
    )

    sdk.close()


def test_anthropic_normalizes_call():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
        name="echo",
    )

    normalized = tool.normalize(
        {
            "id": "toolu_1",
            "name": "echo",
            "input": {
                "value": 7,
            },
        }
    )

    assert normalized.name == "echo"
    assert normalized.arguments == {
        "value": 7,
    }

    sdk.close()


def test_anthropic_defaults_missing_input():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="empty",
    )

    normalized = tool.normalize(
        {
            "name": "empty",
        }
    )

    assert normalized.arguments == {}

    sdk.close()


def test_anthropic_wrong_name_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="expected",
    )

    with pytest.raises(
        ValueError
    ):
        tool.normalize(
            {
                "name": "different",
                "input": {},
            }
        )

    sdk.close()


def test_anthropic_invalid_call_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="test",
    )

    with pytest.raises(
        TypeError
    ):
        tool.normalize(
            "bad"
        )

    sdk.close()


def test_anthropic_invalid_input_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="test",
    )

    with pytest.raises(
        TypeError
    ):
        tool.normalize(
            {
                "name": "test",
                "input": "bad",
            }
        )

    sdk.close()


def test_anthropic_denied_tool_never_executes():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: calls.append(
            True
        ),
        name="danger",
    )

    sdk.revoke(
        capability,
        reason="revoked",
    )

    with pytest.raises(
        PermissionError
    ):
        tool.execute(
            {
                "name": "danger",
                "input": {},
            }
        )

    assert calls == []

    sdk.close()


def test_anthropic_denial_creates_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "no",
        name="danger",
    )

    sdk.revoke(
        capability,
        reason="revoked",
    )

    with pytest.raises(
        PermissionError
    ):
        tool.execute(
            {
                "name": "danger",
                "input": {},
            }
        )

    denied = sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1
    assert denied[0].reason == (
        "capability_revoked"
    )

    sdk.close()


def test_anthropic_success_creates_used_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
        name="echo",
    )

    assert tool.execute(
        {
            "name": "echo",
            "input": {
                "value": 7,
            },
        }
    ) == 7

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].details[
        "request"
    ] == {
        "tool": "echo",
        "input": {
            "value": 7,
        },
    }

    sdk.close()


def test_anthropic_custom_action_requires_authority():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "no",
        name="custom",
        action="payments.custom",
    )

    result = tool.authorize(
        {
            "name": "custom",
            "input": {},
        }
    )

    assert result.allowed is False
    assert result.reason == (
        "namespace_denied"
    )

    sdk.close()


def test_anthropic_wildcard_allows_custom_action():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="custom",
        action="payments.custom",
    )

    assert tool.execute(
        {
            "name": "custom",
            "input": {},
        }
    ) == "ok"

    sdk.close()


def test_anthropic_custom_request_builder():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="payment",
        request_builder=lambda args: {
            "amount": args["amount"],
            "source": "anthropic",
        },
    )

    assert tool.execute(
        {
            "name": "payment",
            "input": {
                "amount": 25,
            },
        }
    ) == 25

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert used[0].details[
        "request"
    ] == {
        "amount": 25,
        "source": "anthropic",
    }

    sdk.close()


def test_anthropic_invalid_sdk():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        AnthropicTool(
            sdk="bad",
            capability=capability,
            handler=lambda: None,
        )

    sdk.close()


def test_anthropic_invalid_capability():
    sdk = FirewallSDK()

    with pytest.raises(
        TypeError
    ):
        AnthropicTool(
            sdk=sdk,
            capability="bad",
            handler=lambda: None,
        )

    sdk.close()


def test_anthropic_invalid_handler():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        AnthropicTool(
            sdk=sdk,
            capability=capability,
            handler="bad",
        )

    sdk.close()


def test_anthropic_empty_name():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        ValueError
    ):
        AnthropicTool(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            name="",
        )

    sdk.close()


def test_anthropic_invalid_schema():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        AnthropicTool(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            input_schema="bad",
        )

    sdk.close()