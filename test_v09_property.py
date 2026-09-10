from __future__ import annotations

import copy

import pytest
from hypothesis import (
    given,
    settings,
    strategies as st,
)

from firewall.adapters.generic import GenericToolCall
from firewall.adapters.normalize import normalize_tool_call
from firewall.capability import generate_capability_key_pair
from firewall.lifecycle import (
    LifecycleEventType,
    LifecycleRecorder,
)
from firewall.lifecycle_store import SQLiteLifecycleStore
from firewall.sdk import FirewallSDK


# ============================================================
# Strategies
# ============================================================

names = st.text(
    alphabet=st.characters(
        whitelist_categories=(
            "Ll",
            "Lu",
            "Nd",
        ),
    ),
    min_size=1,
    max_size=30,
).filter(
    lambda value: value.strip() != ""
)


simple_values = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(
        min_value=-100000,
        max_value=100000,
    ),
    st.text(
        max_size=100,
    ),
)


json_scalars = simple_values


json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(
            children,
            max_size=8,
        ),
        st.dictionaries(
            st.text(
                min_size=1,
                max_size=20,
            ),
            children,
            max_size=8,
        ),
    ),
    max_leaves=30,
)


json_objects = st.dictionaries(
    st.text(
        min_size=1,
        max_size=20,
    ),
    json_values,
    min_size=1,
    max_size=10,
)


# ============================================================
# Normalization
# ============================================================

@given(
    name=names,
    arguments=json_objects,
)
def test_normalization_preserves_arguments(
    name,
    arguments,
):
    original = copy.deepcopy(arguments)

    result = normalize_tool_call(
        name=name,
        arguments=arguments,
    )

    assert result.name == name
    assert result.arguments == original

    arguments.clear()

    assert result.arguments == original


@given(
    name=names,
    arguments=json_objects,
)
def test_normalization_mapping_form_matches_keyword_form(
    name,
    arguments,
):
    left = normalize_tool_call(
        name=name,
        arguments=arguments,
    )

    right = normalize_tool_call(
        {
            "name": name,
            "arguments": arguments,
        }
    )

    assert left == right


@given(
    name=names,
    arguments=json_objects,
)
def test_normalization_existing_generic_call_is_snapshot(
    name,
    arguments,
):
    original_arguments = copy.deepcopy(
        arguments
    )

    original = GenericToolCall(
        name=name,
        arguments=arguments,
    )

    normalized = normalize_tool_call(
        original
    )

    assert normalized == original
    assert normalized is not original

    arguments.clear()

    assert normalized.arguments == (
        original_arguments
    )


# ============================================================
# Lifecycle recorder
# ============================================================

@given(
    fingerprint=names,
    request_id=names,
)
def test_lifecycle_event_round_trip_in_memory(
    fingerprint,
    request_id,
):
    recorder = LifecycleRecorder(
        clock=lambda: 123.0
    )

    event = recorder.record(
        LifecycleEventType.USED,
        fingerprint,
        request_id=request_id,
        details={
            "request": {
                "value": 42,
            }
        },
    )

    assert recorder.events() == (
        event,
    )

    assert event.fingerprint == fingerprint
    assert event.request_id == request_id


@given(
    fingerprint=names,
    request=json_objects,
)
def test_lifecycle_nested_details_are_snapshots(
    fingerprint,
    request,
):
    original = copy.deepcopy(request)

    recorder = LifecycleRecorder(
        clock=lambda: 100.0
    )

    event = recorder.record(
        LifecycleEventType.USED,
        fingerprint,
        details={
            "request": copy.deepcopy(request)
        },
    )

    request.clear()

    assert event.details["request"] == original


# ============================================================
# Persistent lifecycle store
# ============================================================

@given(
    fingerprint=names,
    details=json_objects,
)
@settings(
    max_examples=25,
    deadline=None,
)
def test_persistent_lifecycle_round_trip(
    tmp_path_factory,
    fingerprint,
    details,
):
    path = (
        tmp_path_factory.mktemp(
            "lifecycle_round_trip"
        )
        / "lifecycle.db"
    )

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        clock=lambda: 50.0,
        store=store,
    )

    recorder.record(
        LifecycleEventType.USED,
        fingerprint,
        details=details,
    )

    expected = recorder.events()

    recorder.close()

    reopened = SQLiteLifecycleStore(path)

    restored = LifecycleRecorder(
        clock=lambda: 999.0,
        store=reopened,
    )

    assert restored.events() == expected

    restored.close()


@given(
    fingerprints=st.lists(
        names,
        min_size=1,
        max_size=20,
        unique=True,
    )
)
@settings(
    max_examples=25,
    deadline=None,
)
def test_persistent_lifecycle_preserves_order(
    tmp_path_factory,
    fingerprints,
):
    path = (
        tmp_path_factory.mktemp(
            "lifecycle_order"
        )
        / "lifecycle.db"
    )

    store = SQLiteLifecycleStore(path)

    recorder = LifecycleRecorder(
        clock=lambda: 100.0,
        store=store,
    )

    for fingerprint in fingerprints:
        recorder.record(
            LifecycleEventType.USED,
            fingerprint,
        )

    recorder.close()

    reopened = SQLiteLifecycleStore(path)

    events = reopened.events()

    assert [
        event.fingerprint
        for event in events
    ] == fingerprints

    assert all(
        event.event_type
        == LifecycleEventType.USED
        for event in events
    )

    reopened.close()


# ============================================================
# SDK lifecycle behavior
# ============================================================

@given(
    request=json_objects,
)
def test_sdk_successful_use_records_same_request(
    request,
):
    sdk = FirewallSDK()

    private_key, _ = generate_capability_key_pair()

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    original = copy.deepcopy(request)

    result = sdk.authorize(
        capability,
        "payments.send",
        request,
    )

    assert result.allowed is True

    request.clear()

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 1

    assert used[0].details["request"] == original

    sdk.close()


@given(
    amount=st.integers(
        min_value=-100000,
        max_value=100000,
    )
)
def test_sdk_repeated_authorization_is_stable(
    amount,
):
    sdk = FirewallSDK()

    private_key, _ = generate_capability_key_pair()

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    first = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": amount,
        },
    )

    second = sdk.authorize(
        capability,
        "payments.send",
        {
            "amount": amount,
        },
    )

    assert first.allowed is True
    assert second.allowed is True

    used = sdk.lifecycle.of_type(
        LifecycleEventType.USED
    )

    assert len(used) == 2

    assert all(
        event.details["request"]["amount"]
        == amount
        for event in used
    )

    sdk.close()


# ============================================================
# Capability transport
# ============================================================

@given(
    capability_name=names,
)
def test_capability_transport_round_trip(
    capability_name,
):
    sdk = FirewallSDK()

    private_key, _ = generate_capability_key_pair()

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability=capability_name,
    )

    token = sdk.encode(capability)
    decoded = sdk.decode(token)

    assert decoded == capability

    sdk.close()


# ============================================================
# Defensive cases
# ============================================================

@given(
    name=names,
)
def test_normalization_rejects_non_mapping_arguments(
    name,
):
    with pytest.raises(TypeError):
        normalize_tool_call(
            name=name,
            arguments="invalid",
        )


@given(
    name=names,
)
def test_normalization_rejects_empty_call_name(
    name,
):
    with pytest.raises(ValueError):
        normalize_tool_call(
            name="   ",
            arguments={},
        )


# ============================================================
# GenericToolCall immutability contract
# ============================================================

@given(
    name=names,
    arguments=json_objects,
)
def test_generic_tool_call_dataclass_is_frozen(
    name,
    arguments,
):
    call = GenericToolCall(
        name=name,
        arguments=arguments,
    )

    with pytest.raises(Exception):
        call.name = "changed"