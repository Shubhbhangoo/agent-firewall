from concurrent.futures import ThreadPoolExecutor

import pytest

from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticChainDenied,
    SemanticRule,
)


PAYMENT_SEQUENCE = (
    "payments.lookup",
    "payments.prepare",
    "payments.send",
)


def protected_context():
    return SemanticChainContext(
        agent="agent-a",
        rules=(
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                allowed=False,
            ),
        ),
    )


def record(
    context,
    action,
    request,
    *,
    chain_id="chain-a",
    fingerprint="cap-1",
    capability="payments.*",
):
    context.authorize_and_record(
        agent="agent-a",
        action=action,
        request=request,
        capability_fingerprint=fingerprint,
        capability=capability,
        chain_id=chain_id,
    )


def test_protected_sequence_denied_without_allow_rule():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
    )
    record(
        context,
        "payments.prepare",
        {"account": "acct-a"},
    )

    with pytest.raises(SemanticChainDenied):
        record(
            context,
            "payments.send",
            {
                "account": "acct-a",
                "amount": 100,
            },
        )

    snapshot = context.snapshot(
        chain_id="chain-a"
    )[0]

    assert snapshot.stages == (
        "payments.lookup",
        "payments.prepare",
    )
    assert snapshot.terminal_outcomes == (
        "payments.transfer",
    )


def test_matching_allow_rule_permits_protected_sequence():
    context = SemanticChainContext(
        agent="agent-a",
        rules=(
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                allowed=False,
            ),
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                allowed=True,
            ),
        ),
    )

    for action in PAYMENT_SEQUENCE:
        record(
            context,
            action,
            {"account": "acct-a"},
        )

    assert context.snapshot(
        chain_id="chain-a"
    )[0].stages == PAYMENT_SEQUENCE


def test_alternate_path_does_not_match_protected_sequence():
    context = protected_context()

    for action in (
        "payments.lookup",
        "payments.confirm",
        "payments.send",
    ):
        record(
            context,
            action,
            {"account": "acct-a"},
        )

    assert context.snapshot(
        chain_id="chain-a"
    )[0].terminal_outcomes == ()


def test_resource_mismatch_does_not_match_account_specific_rule():
    context = SemanticChainContext(
        agent="agent-a",
        rules=(
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                resource_value="acct-a",
                allowed=False,
            ),
            SemanticRule(
                outcome="payments.transfer",
                sequence=PAYMENT_SEQUENCE,
                resource_key="account",
                resource_value="acct-a",
                allowed=True,
            ),
        ),
    )

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
    )
    record(
        context,
        "payments.prepare",
        {"account": "acct-a"},
    )
    record(
        context,
        "payments.send",
        {
            "account": "acct-b",
            "amount": 100,
        },
    )

    assert context.snapshot(
        chain_id="chain-a"
    )[0].terminal_outcomes == ()


def test_chain_ids_are_isolated():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
        chain_id="chain-a",
    )
    record(
        context,
        "payments.prepare",
        {"account": "acct-a"},
        chain_id="chain-a",
    )

    record(
        context,
        "payments.send",
        {
            "account": "acct-a",
            "amount": 100,
        },
        chain_id="chain-b",
    )

    assert context.snapshot(
        chain_id="chain-b"
    )[0].stages == (
        "payments.send",
    )


def test_reset_one_chain_leaves_other_chain_intact():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
        chain_id="chain-a",
    )
    record(
        context,
        "payments.lookup",
        {"account": "acct-b"},
        chain_id="chain-b",
    )

    context.reset(
        chain_id="chain-a"
    )

    assert context.snapshot(
        chain_id="chain-a"
    )[0].stages == ()
    assert context.snapshot(
        chain_id="chain-b"
    )[0].stages == (
        "payments.lookup",
    )


def test_reset_all_chains():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
        chain_id="chain-a",
    )
    record(
        context,
        "payments.lookup",
        {"account": "acct-b"},
        chain_id="chain-b",
    )

    context.reset()

    assert context.snapshot() == ()


def test_capability_fingerprints_are_tracked():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
        fingerprint="cap-a",
    )
    record(
        context,
        "payments.prepare",
        {"account": "acct-a"},
        fingerprint="cap-b",
    )

    snapshot = context.snapshot(
        chain_id="chain-a"
    )[0]

    assert snapshot.capability_fingerprints == (
        "cap-a",
        "cap-b",
    )


def test_nested_resource_extraction_is_deterministic():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {
            "arguments": {
                "account": "acct-a",
            }
        },
    )

    snapshot = context.snapshot(
        chain_id="chain-a"
    )[0]

    assert snapshot.actions[0].resources == {
        "account": "acct-a",
    }


def test_concurrent_terminal_actions_do_not_race_past_guard():
    context = protected_context()

    record(
        context,
        "payments.lookup",
        {"account": "acct-a"},
    )
    record(
        context,
        "payments.prepare",
        {"account": "acct-a"},
    )

    def worker(index):
        try:
            record(
                context,
                "payments.send",
                {
                    "account": "acct-a",
                    "amount": index,
                },
            )
            return True
        except SemanticChainDenied:
            return False

    with ThreadPoolExecutor(
        max_workers=16
    ) as executor:
        results = list(
            executor.map(
                worker,
                range(32),
            )
        )

    snapshot = context.snapshot(
        chain_id="chain-a"
    )[0]

    assert not any(results)
    assert snapshot.stages == (
        "payments.lookup",
        "payments.prepare",
    )
    assert len(snapshot.denied) == 32
