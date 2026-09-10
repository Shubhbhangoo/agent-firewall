from __future__ import annotations

import time

import pytest

from firewall.capability import (
    capability_fingerprint,
    generate_capability_key_pair,
)

from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)

from firewall.sdk import FirewallSDK


def make_capability(
    sdk,
    *,
    capability="payments.*",
    constraints=None,
    expires_at=None,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    if expires_at is None:
        expires_at = time.time() + 3600

    result = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
        expires_at=expires_at,
    )

    return result, private_key


def test_attenuate_creates_attenuated_event():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        constraints={"amount_max": 100},
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={"amount_max": 50},
    )

    events = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )

    assert len(events) == 1

    event = events[0]

    assert event.fingerprint == (
        capability_fingerprint(child)
    )

    assert event.details[
        "parent_fingerprint"
    ] == capability_fingerprint(parent)

    assert event.details[
        "constraints"
    ] == child.constraints

    assert event.details[
        "expires_at"
    ] == child.expires_at

    sdk.close()


def test_attenuate_emits_exactly_one_event():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk
    )

    before = lifecycle.size()

    sdk.attenuate(
        parent,
        private_key,
    )

    assert lifecycle.size() == (
        before + 1
    )

    assert len(
        lifecycle.of_type(
            LifecycleEventType.ATTENUATED
        )
    ) == 1

    sdk.close()


def test_multiple_attenuations_emit_multiple_events():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        constraints={"amount_max": 100},
    )

    first = sdk.attenuate(
        parent,
        private_key,
        constraints={"amount_max": 80},
    )

    second = sdk.attenuate(
        parent,
        private_key,
        constraints={"amount_max": 50},
    )

    events = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )

    assert len(events) == 2

    assert events[0].fingerprint == (
        capability_fingerprint(first)
    )

    assert events[1].fingerprint == (
        capability_fingerprint(second)
    )

    sdk.close()


def test_attenuation_event_records_parent():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk
    )

    child = sdk.attenuate(
        parent,
        private_key,
    )

    event = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )[0]

    assert event.fingerprint == (
        capability_fingerprint(child)
    )

    assert event.details[
        "parent_fingerprint"
    ] == capability_fingerprint(parent)

    sdk.close()


def test_parent_and_child_fingerprints_differ():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        constraints={"amount_max": 100},
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={"amount_max": 25},
    )

    assert (
        capability_fingerprint(parent)
        != capability_fingerprint(child)
    )

    sdk.close()


def test_attenuation_event_preserves_child_scope():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        capability="payments.*",
    )

    child = sdk.attenuate(
        parent,
        private_key,
    )

    event = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )[0]

    assert event.capability == (
        child.capability
    )

    assert event.capability == (
        "payments.*"
    )

    sdk.close()


def test_attenuation_event_preserves_child_agent():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk
    )

    child = sdk.attenuate(
        parent,
        private_key,
    )

    event = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )[0]

    assert event.agent_id == (
        child.agent_id
    )

    sdk.close()


def test_attenuation_event_preserves_child_issuer():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk
    )

    child = sdk.attenuate(
        parent,
        private_key,
    )

    event = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )[0]

    assert event.issuer == (
        child.issuer
    )

    sdk.close()


def test_attenuation_event_records_child_constraints():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        constraints={"amount_max": 100},
    )

    child = sdk.attenuate(
        parent,
        private_key,
        constraints={"amount_max": 50},
    )

    event = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )[0]

    assert event.details[
        "constraints"
    ] == child.constraints

    sdk.close()


def test_attenuation_with_narrower_constraint_emits_event():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        constraints={"amount_max": 100},
    )

    sdk.attenuate(
        parent,
        private_key,
        constraints={"amount_max": 1},
    )

    assert len(
        lifecycle.of_type(
            LifecycleEventType.ATTENUATED
        )
    ) == 1

    sdk.close()


def test_attenuation_event_records_child_expiration():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    now = time.time()

    parent, private_key = make_capability(
        sdk,
        expires_at=now + 3600,
    )

    child = sdk.attenuate(
        parent,
        private_key,
        expires_at=now + 1800,
    )

    event = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )[0]

    assert event.details[
        "expires_at"
    ] == child.expires_at

    assert child.expires_at < (
        parent.expires_at
    )

    sdk.close()


def test_failed_attenuation_creates_no_event():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, _ = make_capability(
        sdk
    )

    before = lifecycle.size()

    with pytest.raises(Exception):
        sdk.attenuate(
            parent,
            "not-a-private-key",
        )

    assert lifecycle.size() == before

    assert lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    ) == ()

    sdk.close()


def test_broader_attenuation_creates_no_event():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk,
        constraints={"amount_max": 50},
    )

    before = lifecycle.size()

    with pytest.raises(ValueError):
        sdk.attenuate(
            parent,
            private_key,
            constraints={"amount_max": 100},
        )

    assert lifecycle.size() == before

    assert lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    ) == ()

    sdk.close()


def test_issue_then_attenuate_order():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    parent, private_key = make_capability(
        sdk
    )

    child = sdk.attenuate(
        parent,
        private_key,
    )

    events = lifecycle.events()

    assert len(events) == 2

    assert (
        events[0].event_type
        == LifecycleEventType.ISSUED
    )

    assert (
        events[1].event_type
        == LifecycleEventType.ATTENUATED
    )

    assert events[0].fingerprint == (
        capability_fingerprint(parent)
    )

    assert events[1].fingerprint == (
        capability_fingerprint(child)
    )

    sdk.close()


def test_attenuation_chain_is_recorded():
    lifecycle = LifecycleRecorder()
    sdk = FirewallSDK(
        lifecycle_recorder=lifecycle
    )

    root, private_key = make_capability(
        sdk,
        constraints={"amount_max": 100},
    )

    child = sdk.attenuate(
        root,
        private_key,
        constraints={"amount_max": 75},
    )

    grandchild = sdk.attenuate(
        child,
        private_key,
        constraints={"amount_max": 25},
    )

    events = lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )

    assert len(events) == 2

    assert events[0].fingerprint == (
        capability_fingerprint(child)
    )

    assert events[0].details[
        "parent_fingerprint"
    ] == capability_fingerprint(root)

    assert events[1].fingerprint == (
        capability_fingerprint(grandchild)
    )

    assert events[1].details[
        "parent_fingerprint"
    ] == capability_fingerprint(child)

    sdk.close()


def test_default_sdk_records_attenuation_event():
    sdk = FirewallSDK()

    parent, private_key = make_capability(
        sdk
    )

    child = sdk.attenuate(
        parent,
        private_key,
    )

    events = sdk.lifecycle.of_type(
        LifecycleEventType.ATTENUATED
    )

    assert len(events) == 1

    assert events[0].fingerprint == (
        capability_fingerprint(child)
    )

    assert events[0].details[
        "parent_fingerprint"
    ] == capability_fingerprint(parent)

    sdk.close()