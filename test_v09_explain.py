from __future__ import annotations

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.explain import (
    LifecycleExplanation,
    explain,
    explain_request,
)

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
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


def test_explain_existing_capability():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    result = explain(
        sdk.lifecycle,
        fingerprint,
    )

    assert isinstance(
        result,
        LifecycleExplanation,
    )

    assert result.exists is True
    assert result.fingerprint == fingerprint
    assert result.used is True
    assert result.revoked is False
    assert result.latest_type == (
        LifecycleEventType.USED
    )

    sdk.close()


def test_explain_missing_capability():
    recorder = LifecycleRecorder()

    result = explain(
        recorder,
        "missing",
    )

    assert result.exists is False
    assert result.events == ()
    assert result.latest is None
    assert result.latest_type is None
    assert result.revoked is False
    assert result.used is False
    assert result.denied is False
    assert result.expired is False
    assert result.replayed is False


def test_explain_reveals_revocation():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    result = explain(
        sdk.lifecycle,
        sdk.fingerprint(
            capability
        ),
    )

    assert result.revoked is True
    assert result.latest_type == (
        LifecycleEventType.REVOKED
    )

    sdk.close()


def test_explain_reveals_denial():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability,
        reason="compromised",
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert result.reason == (
        "capability_revoked"
    )

    explanation = explain(
        sdk.lifecycle,
        sdk.fingerprint(
            capability
        ),
    )

    assert explanation.denied is True
    assert explanation.revoked is True
    assert explanation.latest_type == (
        LifecycleEventType.DENIED
    )

    sdk.close()

def test_explain_reveals_expiration():
    clock_value = [200.0]

    def clock():
        return clock_value[0]

    sdk = FirewallSDK(
        clock=clock
    )

    capability = make_capability(
        sdk
    )

    # Replace the capability with one whose
    # expiration is in the past relative to the
    # controlled clock.
    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
        issued_at=100.0,
        expires_at=150.0,
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    explanation = explain(
        sdk.lifecycle,
        sdk.fingerprint(
            capability
        ),
    )

    assert explanation.expired is True
    assert explanation.latest_type == (
        LifecycleEventType.EXPIRED
    )

    sdk.close()


def test_explain_reveals_replay():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    assert sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce",
    )

    assert not sdk.consume_nonce(
        "agent-a",
        capability,
        "nonce",
    )

    explanation = explain(
        sdk.lifecycle,
        sdk.fingerprint(
            capability
        ),
    )

    assert explanation.replayed is True

    sdk.close()


def test_explain_preserves_event_order():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    sdk.revoke(
        capability,
        reason="test",
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    explanation = explain(
        sdk.lifecycle,
        sdk.fingerprint(
            capability
        ),
    )

    assert [
        event.event_type
        for event in explanation.events
    ] == [
        LifecycleEventType.ISSUED,
        LifecycleEventType.USED,
        LifecycleEventType.REVOKED,
        LifecycleEventType.DENIED,
    ]

    sdk.close()


def test_explain_to_dict():
    sdk = FirewallSDK()

    capability = make_capability(
        sdk
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    explanation = explain(
        sdk.lifecycle,
        sdk.fingerprint(
            capability
        ),
    )

    data = explanation.to_dict()

    assert data["exists"] is True
    assert data["used"] is True
    assert data["fingerprint"] == (
        sdk.fingerprint(
            capability
        )
    )
    assert len(data["events"]) == 2

    sdk.close()


def test_explain_request_finds_matching_events():
    recorder = LifecycleRecorder()

    recorder.record(
        LifecycleEventType.USED,
        "fp-1",
        request_id="req-1",
    )

    recorder.record(
        LifecycleEventType.DENIED,
        "fp-2",
        request_id="req-2",
    )

    recorder.record(
        LifecycleEventType.REPLAYED,
        "fp-1",
        request_id="req-1",
    )

    events = explain_request(
        recorder,
        "req-1",
    )

    assert len(events) == 2

    assert [
        event.event_type
        for event in events
    ] == [
        LifecycleEventType.USED,
        LifecycleEventType.REPLAYED,
    ]


def test_explain_request_missing_returns_empty():
    recorder = LifecycleRecorder()

    assert explain_request(
        recorder,
        "missing",
    ) == ()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " ",
        None,
        123,
        [],
        {},
    ],
)
def test_explain_rejects_invalid_fingerprint(
    bad,
):
    recorder = LifecycleRecorder()

    with pytest.raises(
        (TypeError, ValueError)
    ):
        explain(
            recorder,
            bad,
        )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " ",
        None,
        123,
        [],
        {},
    ],
)
def test_explain_request_rejects_invalid_request_id(
    bad,
):
    recorder = LifecycleRecorder()

    with pytest.raises(
        (TypeError, ValueError)
    ):
        explain_request(
            recorder,
            bad,
        )


def test_explain_rejects_invalid_recorder():
    with pytest.raises(
        TypeError
    ):
        explain(
            "bad",
            "fingerprint",
        )


def test_explain_request_rejects_invalid_recorder():
    with pytest.raises(
        TypeError
    ):
        explain_request(
            "bad",
            "request",
        )