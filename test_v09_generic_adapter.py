from __future__ import annotations

import pytest

from firewall.adapters.generic import (
    GenericToolAdapter,
    GenericToolCall,
    generic_tool,
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


def test_generic_call_representation():
    call = GenericToolCall(
        name="send_payment",
        arguments={
            "amount": 10,
        },
    )

    assert call.name == "send_payment"
    assert call.arguments == {
        "amount": 10,
    }


def test_generic_tool_executes():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount * 2,
        name="send_payment",
    )

    call = GenericToolCall(
        name="send_payment",
        arguments={
            "amount": 10,
        },
    )

    assert tool.execute(call) == 20

    sdk.close()


def test_generic_tool_is_callable():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value + 1,
        name="calculate",
    )

    call = GenericToolCall(
        name="calculate",
        arguments={
            "value": 4,
        },
    )

    assert tool(call) == 5

    sdk.close()


def test_generic_factory():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = generic_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="test_tool",
    )

    assert isinstance(
        tool,
        GenericToolAdapter,
    )

    sdk.close()


def test_wrong_tool_name_is_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="expected",
    )

    call = GenericToolCall(
        name="different",
        arguments={},
    )

    with pytest.raises(
        ValueError
    ):
        tool.authorize(call)

    sdk.close()


def test_invalid_call_is_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="test_tool",
    )

    with pytest.raises(
        TypeError
    ):
        tool.authorize("bad")

    sdk.close()


def test_denied_generic_tool_never_executes():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: calls.append(True),
        name="test_tool",
    )

    sdk.revoke(
        capability,
        reason="revoked",
    )

    call = GenericToolCall(
        name="test_tool",
        arguments={},
    )

    with pytest.raises(
        PermissionError
    ):
        tool.execute(call)

    assert calls == []

    sdk.close()


def test_denied_generic_tool_records_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "no",
        name="test_tool",
    )

    sdk.revoke(
        capability,
        reason="revoked",
    )

    call = GenericToolCall(
        name="test_tool",
        arguments={},
    )

    with pytest.raises(
        PermissionError
    ):
        tool.execute(call)

    denied = sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1
    assert denied[0].reason == (
        "capability_revoked"
    )

    sdk.close()


def test_successful_generic_tool_records_used():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
        name="echo",
    )

    call = GenericToolCall(
        name="echo",
        arguments={
            "value": 7,
        },
    )

    assert tool.execute(call) == 7

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].details[
        "request"
    ] == {
        "tool": "echo",
        "arguments": {
            "value": 7,
        },
    }

    sdk.close()


def test_custom_action_still_requires_authority():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "no",
        name="custom_tool",
        action="payments.custom",
    )

    call = GenericToolCall(
        name="custom_tool",
        arguments={},
    )

    result = tool.authorize(call)

    assert result.allowed is False
    assert result.reason == (
        "namespace_denied"
    )

    sdk.close()


def test_wildcard_allows_custom_action():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="custom_tool",
        action="payments.custom",
    )

    call = GenericToolCall(
        name="custom_tool",
        arguments={},
    )

    assert tool.execute(call) == "ok"

    sdk.close()


def test_custom_request_builder():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="payment",
        request_builder=lambda args: {
            "amount": args["amount"],
            "source": "generic",
        },
    )

    call = GenericToolCall(
        name="payment",
        arguments={
            "amount": 25,
        },
    )

    assert tool.execute(call) == 25

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert used[0].details[
        "request"
    ] == {
        "amount": 25,
        "source": "generic",
    }

    sdk.close()


def test_request_builder_must_return_dict():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        name="tool",
        request_builder=lambda args: "bad",
    )

    call = GenericToolCall(
        name="tool",
        arguments={},
    )

    with pytest.raises(
        TypeError
    ):
        tool.authorize(call)

    sdk.close()


def test_invalid_sdk_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        GenericToolAdapter(
            sdk="bad",
            capability=capability,
            handler=lambda: None,
        )

    sdk.close()


def test_invalid_capability_rejected():
    sdk = FirewallSDK()

    with pytest.raises(
        TypeError
    ):
        GenericToolAdapter(
            sdk=sdk,
            capability="bad",
            handler=lambda: None,
        )

    sdk.close()


def test_invalid_handler_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        GenericToolAdapter(
            sdk=sdk,
            capability=capability,
            handler="bad",
        )

    sdk.close()


def test_empty_name_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        ValueError
    ):
        GenericToolAdapter(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            name="",
        )

    sdk.close()


def test_empty_action_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        ValueError
    ):
        GenericToolAdapter(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            name="tool",
            action="",
        )

    sdk.close()