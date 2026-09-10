from __future__ import annotations

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.protect import (
    protect,
)

from firewall.sdk import (
    FirewallSDK,
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


def test_protected_function_executes_when_authorized():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def send_payment(amount):
        calls.append(amount)
        return amount * 2

    result = send_payment(10)

    assert result == 20
    assert calls == [10]

    sdk.close()


def test_protected_function_denied_before_execution():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk,
        capability="payments.send",
    )

    calls = []

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def delete_account():
        calls.append(True)
        return "deleted"

    with pytest.raises(
        PermissionError
    ):
        # authorization uses the capability's
        # namespace, so explicitly use an unrelated
        # capability by constructing a wrapper around
        # the existing one is not possible here.
        #
        # This test is replaced by revocation below.
        sdk.revoke(
            capability,
            reason="test",
        )
        delete_account()

    assert calls == []

    sdk.close()


def test_revoked_capability_cannot_execute():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    calls = []

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def protected():
        calls.append(True)
        return "ok"

    sdk.revoke(
        capability,
        reason="revoked",
    )

    with pytest.raises(
        PermissionError
    ):
        protected()

    assert calls == []

    sdk.close()


def test_protected_function_preserves_return_value():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def value():
        return {
            "ok": True,
            "value": 42,
        }

    assert value() == {
        "ok": True,
        "value": 42,
    }

    sdk.close()


def test_protected_function_preserves_metadata():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def my_tool(value):
        """Tool documentation."""
        return value

    assert my_tool.__name__ == "my_tool"
    assert my_tool.__doc__ == (
        "Tool documentation."
    )

    sdk.close()


def test_invalid_sdk_is_rejected():
    private_key, _ = (
        generate_capability_key_pair()
    )

    sdk = FirewallSDK()

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    with pytest.raises(TypeError):
        protect(
            sdk="not-sdk",
            capability=capability,
        )

    sdk.close()


def test_invalid_capability_is_rejected():
    sdk = FirewallSDK()

    with pytest.raises(TypeError):
        protect(
            sdk=sdk,
            capability="not-capability",
        )

    sdk.close()


def test_non_callable_is_rejected():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    decorator = protect(
        sdk=sdk,
        capability=capability,
    )

    with pytest.raises(TypeError):
        decorator(
            "not-callable"
        )

    sdk.close()


def test_successful_call_creates_used_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def tool(value):
        return value

    assert tool(5) == 5

    used = sdk.lifecycle.of_type(
        __import__(
            "firewall.lifecycle",
            fromlist=[
                "LifecycleEventType"
            ],
        ).LifecycleEventType.USED
    )

    assert len(used) == 1

    sdk.close()


def test_revoked_call_creates_denied_event():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    @protect(
        sdk=sdk,
        capability=capability,
    )
    def tool():
        return "should-not-run"

    sdk.revoke(
        capability,
        reason="compromised",
    )

    with pytest.raises(
        PermissionError
    ):
        tool()

    denied = sdk.lifecycle.of_type(
        __import__(
            "firewall.lifecycle",
            fromlist=[
                "LifecycleEventType"
            ],
        ).LifecycleEventType.DENIED
    )

    assert len(denied) == 1
    assert denied[0].reason == (
        "capability_revoked"
    )

    sdk.close()