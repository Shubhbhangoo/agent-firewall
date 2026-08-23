from __future__ import annotations

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.sdk import FirewallSDK

from firewall.tools import (
    ProtectedTool,
    protect_tool,
)


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


def test_protected_tool_executes():
    sdk = FirewallSDK()
    capability = make_capability(sdk)

    calls = []

    def handler(amount):
        calls.append(amount)
        return amount * 2

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=handler,
    )

    assert tool(10) == 20
    assert calls == [10]

    sdk.close()


def test_protected_tool_is_callable():
    sdk = FirewallSDK()
    capability = make_capability(sdk)

    def handler():
        return "ok"

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=handler,
    )

    assert callable(tool)

    sdk.close()


def test_protected_tool_preserves_metadata():
    sdk = FirewallSDK()
    capability = make_capability(sdk)

    def handler(value):
        """Example tool."""
        return value

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=handler,
    )

    assert tool.__name__ == "handler"
    assert tool.__doc__ == "Example tool."

    sdk.close()


def test_denied_tool_never_executes():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    def handler():
        calls.append(True)

    sdk.revoke(
        capability,
        reason="revoked",
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=handler,
    )

    with pytest.raises(
        PermissionError
    ):
        tool()

    assert calls == []

    sdk.close()


def test_denied_tool_creates_denied_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "no",
    )

    sdk.revoke(
        capability,
        reason="revoked",
    )

    with pytest.raises(
        PermissionError
    ):
        tool()

    denied = sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1
    assert denied[0].reason == (
        "capability_revoked"
    )

    sdk.close()


def test_successful_tool_creates_used_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
    )

    assert tool() == "ok"

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    sdk.close()


def test_default_action_uses_capability_name():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
    )

    result = tool.authorize()

    assert result.allowed is True

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert used[0].details[
        "action"
    ] == "payments.send"

    sdk.close()


def test_custom_action_is_supported():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        action="payments.custom",
    )

    result = tool.authorize()

    assert result.allowed is True

    sdk.close()


def test_custom_action_still_requires_capability_authority():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "should-not-run",
        action="payments.custom",
    )

    result = tool.authorize()

    assert result.allowed is False
    assert result.reason == (
        "namespace_denied"
    )

    sdk.close()


def test_request_contains_arguments():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda a, b=2: a + b,
    )

    assert tool(3, b=4) == 7

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    request = used[0].details[
        "request"
    ]

    assert request["args"] == (
        3,
    )

    assert request["kwargs"] == {
        "b": 4,
    }

    sdk.close()


def test_custom_request_builder():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    def request_builder(
        amount,
    ):
        return {
            "amount": amount,
            "kind": "payment",
        }

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        request_builder=request_builder,
    )

    assert tool(25) == 25

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert used[0].details[
        "request"
    ] == {
        "amount": 25,
        "kind": "payment",
    }

    sdk.close()


def test_request_builder_must_return_dict():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = ProtectedTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        request_builder=lambda: "bad",
    )

    with pytest.raises(
        TypeError
    ):
        tool()

    sdk.close()


def test_protect_tool_factory():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = protect_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda x: x + 1,
    )

    assert isinstance(
        tool,
        ProtectedTool,
    )

    assert tool(4) == 5

    sdk.close()


def test_invalid_sdk_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        ProtectedTool(
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
        ProtectedTool(
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
        ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler="not-callable",
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
        ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            action="",
        )

    sdk.close()


def test_request_builder_must_be_callable():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            request_builder="bad",
        )

    sdk.close()