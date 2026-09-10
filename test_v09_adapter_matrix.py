from __future__ import annotations

import pytest

from firewall.adapters import (
    AnthropicTool,
    GenericToolAdapter,
    GenericToolCall,
    OpenAITool,
    anthropic_tool,
    generic_tool,
    normalize_tool_call,
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


def test_all_adapter_exports_are_available():
    assert GenericToolAdapter is not None
    assert GenericToolCall is not None
    assert generic_tool is not None

    assert OpenAITool is not None
    assert openai_tool is not None

    assert AnthropicTool is not None
    assert anthropic_tool is not None

    assert normalize_tool_call is not None


def test_generic_openai_anthropic_share_same_security_core():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    generic = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="payment",
        action="payments.send",
    )

    openai = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="payment",
        action="payments.send",
    )

    anthropic = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="payment",
        action="payments.send",
    )

    generic_result = generic.execute(
        GenericToolCall(
            name="payment",
            arguments={
                "amount": 10,
            },
        )
    )

    openai_result = openai.execute(
        {
            "name": "payment",
            "arguments": {
                "amount": 20,
            },
        }
    )

    anthropic_result = anthropic.execute(
        {
            "name": "payment",
            "input": {
                "amount": 30,
            },
        }
    )

    assert generic_result == 10
    assert openai_result == 20
    assert anthropic_result == 30

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 3

    sdk.close()


def test_revocation_blocks_all_adapters():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    generic = generic_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "generic",
        name="generic",
        action="payments.send",
    )

    openai = openai_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "openai",
        name="openai",
        action="payments.send",
    )

    anthropic = anthropic_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "anthropic",
        name="anthropic",
        action="payments.send",
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    with pytest.raises(PermissionError):
        generic(
            GenericToolCall(
                name="generic",
                arguments={},
            )
        )

    with pytest.raises(PermissionError):
        openai.execute(
            {
                "name": "openai",
                "arguments": {},
            }
        )

    with pytest.raises(PermissionError):
        anthropic.execute(
            {
                "name": "anthropic",
                "input": {},
            }
        )

    assert generic is not None
    assert openai is not None
    assert anthropic is not None

    sdk.close()


def test_namespace_boundary_is_consistent_across_adapters():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    generic = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda: "generic",
        name="generic",
        action="payments.refund",
    )

    openai = OpenAITool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "openai",
        name="openai",
        action="payments.refund",
    )

    anthropic = AnthropicTool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "anthropic",
        name="anthropic",
        action="payments.refund",
    )

    generic_result = generic.authorize(
        GenericToolCall(
            name="generic",
            arguments={},
        )
    )

    openai_result = openai.authorize(
        {}
    )

    anthropic_result = anthropic.authorize(
        {
            "name": "anthropic",
            "input": {},
        }
    )

    assert generic_result.allowed is False
    assert openai_result.allowed is False
    assert anthropic_result.allowed is False

    assert generic_result.reason == (
        "namespace_denied"
    )

    assert openai_result.reason == (
        "namespace_denied"
    )

    assert anthropic_result.reason == (
        "namespace_denied"
    )

    sdk.close()


def test_normalizer_feeds_generic_adapter():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    tool = GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=lambda amount: amount,
        name="payment",
    )

    normalized = normalize_tool_call(
        {
            "name": "payment",
            "arguments": {
                "amount": 42,
            },
        }
    )

    assert normalized == GenericToolCall(
        name="payment",
        arguments={
            "amount": 42,
        },
    )

    assert tool.execute(
        normalized
    ) == 42

    sdk.close()


def test_all_adapters_record_same_terminal_semantics():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.*",
    )

    generic = generic_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "generic",
        name="generic",
        action="payments.send",
    )

    openai = openai_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "openai",
        name="openai",
        action="payments.send",
    )

    anthropic = anthropic_tool(
        sdk=sdk,
        capability=capability,
        handler=lambda: "anthropic",
        name="anthropic",
        action="payments.send",
    )

    generic(
        GenericToolCall(
            name="generic",
            arguments={},
        )
    )

    openai.execute(
        {
            "name": "openai",
            "arguments": {},
        }
    )

    anthropic.execute(
        {
            "name": "anthropic",
            "input": {},
        }
    )

    events = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(events) == 3

    assert all(
        event.event_type
        == LifecycleEventType.USED
        for event in events
    )

    sdk.close()


def test_adapter_public_all_matches_exports():
    import firewall.adapters as adapters

    expected = {
        "GenericToolAdapter",
        "GenericToolCall",
        "generic_tool",
        "OpenAITool",
        "openai_tool",
        "AnthropicTool",
        "anthropic_tool",
        "normalize_tool_call",
    }

    assert set(
        adapters.__all__
    ) == expected


def test_adapter_exports_have_no_duplicates():
    import firewall.adapters as adapters

    assert len(
        adapters.__all__
    ) == len(
        set(adapters.__all__)
    )


def test_star_import_adapter_surface():
    namespace = {}

    exec(
        "from firewall.adapters import *",
        namespace,
    )

    expected = {
        "GenericToolAdapter",
        "GenericToolCall",
        "generic_tool",
        "OpenAITool",
        "openai_tool",
        "AnthropicTool",
        "anthropic_tool",
        "normalize_tool_call",
    }

    for name in expected:
        assert name in namespace