from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from firewall.refusal_state import RefusalState


def make_state() -> RefusalState:
    return RefusalState()


def test_empty_state():
    state = make_state()

    assert state.size() == 0


def test_record_and_lookup():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert state.is_refused(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    )


def test_reason_is_preserved():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert state.reason(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    ) == "constraint_denied"


def test_changed_request_is_not_refused():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert not state.is_refused(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 50},
    )


def test_changed_action_is_not_refused():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert not state.is_refused(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.lookup",
        request={"amount": 1000},
    )


def test_changed_capability_is_not_refused():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert not state.is_refused(
        agent="agent-a",
        capability_fingerprint="cap-2",
        action="payments.send",
        request={"amount": 1000},
    )


def test_changed_agent_is_not_refused():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert not state.is_refused(
        agent="agent-b",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    )


def test_same_request_with_different_key_order_is_same_intent():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={
            "amount": 1000,
            "currency": "USD",
        },
        reason="constraint_denied",
    )

    assert state.is_refused(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={
            "currency": "USD",
            "amount": 1000,
        },
    )


def test_check_returns_record():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    result = state.check(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    )

    assert result is not None
    assert result.reason == "constraint_denied"
    assert (
        result.key.request_fingerprint
    )


def test_missing_request_has_no_refusal():
    state = make_state()

    with pytest.raises(ValueError):
        state.check(
            agent="agent-a",
            capability_fingerprint="cap-1",
            action="payments.send",
            request=None,
        )


def test_clear_specific_refusal():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    assert state.clear(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    )

    assert not state.is_refused(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    )


def test_clear_missing_refusal():
    state = make_state()

    assert not state.clear(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
    )


def test_snapshot():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.refund",
        request={"amount": 1000},
        reason="namespace_denied",
    )

    snapshot = state.snapshot()

    assert len(snapshot) == 2

    assert {
        record.reason
        for record in snapshot
    } == {
        "constraint_denied",
        "namespace_denied",
    }


def test_size():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 2000},
        reason="constraint_denied",
    )

    assert state.size() == 2


def test_clear_all():
    state = make_state()

    state.record(
        agent="agent-a",
        capability_fingerprint="cap-1",
        action="payments.send",
        request={"amount": 1000},
        reason="constraint_denied",
    )

    state.clear_all()

    assert state.size() == 0


def test_concurrent_recording_is_safe():
    state = make_state()

    def worker(index: int):
        state.record(
            agent="agent-a",
            capability_fingerprint=f"cap-{index}",
            action="payments.send",
            request={"amount": index},
            reason="constraint_denied",
        )

    with ThreadPoolExecutor(
        max_workers=16
    ) as executor:
        list(
            executor.map(
                worker,
                range(100),
            )
        )

    assert state.size() == 100


def test_invalid_agent_rejected():
    state = make_state()

    with pytest.raises(ValueError):
        state.record(
            agent="",
            capability_fingerprint="cap-1",
            action="payments.send",
            request={"amount": 1000},
            reason="denied",
        )


def test_invalid_capability_rejected():
    state = make_state()

    with pytest.raises(ValueError):
        state.record(
            agent="agent-a",
            capability_fingerprint="",
            action="payments.send",
            request={"amount": 1000},
            reason="denied",
        )


def test_invalid_action_rejected():
    state = make_state()

    with pytest.raises(ValueError):
        state.record(
            agent="agent-a",
            capability_fingerprint="cap-1",
            action="",
            request={"amount": 1000},
            reason="denied",
        )


def test_invalid_reason_rejected():
    state = make_state()

    with pytest.raises(ValueError):
        state.record(
            agent="agent-a",
            capability_fingerprint="cap-1",
            action="payments.send",
            request={"amount": 1000},
            reason="",
        )


def test_non_serializable_request_rejected():
    state = make_state()

    with pytest.raises(Exception):
        state.record(
            agent="agent-a",
            capability_fingerprint="cap-1",
            action="payments.send",
            request={
                "amount": object(),
            },
            reason="constraint_denied",
        )