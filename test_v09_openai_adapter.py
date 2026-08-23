from __future__ import annotations

import pytest

from firewall.adapters.openai import (
    OpenAITool,
    openai_tool,
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


def test_openai_definition():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="send_payment",
        description="Send a payment.",
        parameters={
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

    definition = tool.definition()

    assert definition == {
        "type": "function",
        "function": {
            "name": "send_payment",
            "description": "Send a payment.",
            "parameters": {
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
        },
    }

    sdk.close()


def test_openai_tool_executes():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount * 2,
        name="double",
    )

    assert tool.execute(
        {
            "amount": 5,
        }
    ) == 10

    sdk.close()


def test_openai_tool_is_callable():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value + 1,
    )

    assert tool(
        {
            "value": 4,
        }
    ) == 5

    sdk.close()


def test_openai_factory_returns_tool():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = openai_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
    )

    assert isinstance(
        tool,
        OpenAITool,
    )

    sdk.close()


def test_openai_denied_tool_does_not_execute():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda: calls.append(
            True
        ),
    )

    sdk.revoke(
        capability,
        reason="revoked",
    )

    with pytest.raises(
        PermissionError
    ):
        tool.execute()

    assert calls == []

    sdk.close()


def test_openai_denial_creates_denied_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
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
        tool.execute()

    denied = sdk.lifecycle.of_type(
        LifecycleEventType.DENIED
    )

    assert len(denied) == 1
    assert denied[0].reason == (
        "capability_revoked"
    )

    sdk.close()


def test_openai_success_creates_used_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda value: value,
    )

    assert tool.execute(
        {
            "value": 7
        }
    ) == 7

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].details[
        "request"
    ] == {
        "args": (),
        "kwargs": {
            "value": 7,
        },
    }

    sdk.close()


def test_openai_authorize_does_not_execute():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda: calls.append(
            True
        ),
    )

    result = tool.authorize()

    assert result.allowed is True
    assert calls == []

    sdk.close()


def test_openai_arguments_must_be_dict():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
    )

    with pytest.raises(
        TypeError
    ):
        tool.execute("bad")

    with pytest.raises(
        TypeError
    ):
        tool.authorize("bad")

    sdk.close()


def test_openai_custom_action_still_requires_authority():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "bad",
        action="payments.custom",
    )

    result = tool.authorize()

    assert result.allowed is False
    assert result.reason == (
        "namespace_denied"
    )

    sdk.close()


def test_openai_wildcard_allows_custom_action():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "ok",
        action="payments.custom",
    )

    assert tool.execute() == "ok"

    sdk.close()


def test_openai_default_name_comes_from_handler():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    def my_function():
        return "ok"

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=my_function,
    )

    assert tool.definition()[
        "function"
    ]["name"] == "my_function"

    sdk.close()


def test_openai_default_description_comes_from_docstring():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    def my_function():
        """My tool description."""
        return "ok"

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=my_function,
    )

    assert tool.definition()[
        "function"
    ]["description"] == (
        "My tool description."
    )

    sdk.close()


def test_openai_custom_request_builder():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        request_builder=lambda amount: {
            "amount": amount,
            "source": "openai",
        },
    )

    assert tool.execute(
        {
            "amount": 25,
        }
    ) == 25

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert used[0].details[
        "request"
    ] == {
        "amount": 25,
        "source": "openai",
    }

    sdk.close()


def test_openai_invalid_sdk_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        OpenAITool(
            sdk="bad",
            capability=capability,
            handler=lambda: None,
        )

    sdk.close()


def test_openai_invalid_capability_rejected():
    sdk = FirewallSDK()

    with pytest.raises(
        TypeError
    ):
        OpenAITool(
            sdk=sdk,
            capability="bad",
            handler=lambda: None,
        )

    sdk.close()


def test_openai_invalid_handler_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        OpenAITool(
            sdk=sdk,
            capability=capability,
            handler="bad",
        )

    sdk.close()


def test_openai_empty_name_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        ValueError
    ):
        OpenAITool(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            name="",
        )

    sdk.close()


def test_openai_invalid_parameters_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    with pytest.raises(
        TypeError
    ):
        OpenAITool(
            sdk=sdk,
            capability=capability,
            handler=lambda: None,
            parameters="bad",
        )

    sdk.close()