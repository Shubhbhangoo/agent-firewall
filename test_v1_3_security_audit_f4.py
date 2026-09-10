from __future__ import annotations

import threading

import pytest

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)
from firewall.semantic_chain import (
    SemanticChainContext,
    SemanticChainDenied,
    SemanticRule,
)


def make_semantic_context():
    return SemanticChainContext(
        agent="agent-a",
        rules=(
            SemanticRule(
                outcome="blocked",
                sequence=(
                    "payments.lookup",
                    "payments.send",
                ),
                resource_key="account",
                allowed=False,
            ),
        ),
    )


def make_security_context(
    max_actions=1000,
):
    return SecurityContext(
        agent="agent-a",
        max_actions=max_actions,
        max_total_amount=10000,
    )


def begin_lookup(
    semantic,
    fingerprint="fp",
):
    return semantic.begin_authorization(
        agent="agent-a",
        action="payments.lookup",
        request={
            "account": "acct-1",
        },
        capability_fingerprint=fingerprint,
        capability="payments.lookup",
    )


def test_security_budget_failure_releases_semantic_lock():
    semantic = make_semantic_context()

    security = make_security_context(
        max_actions=0,
    )

    tx = begin_lookup(
        semantic,
        fingerprint="fp-1",
    )

    try:
        with pytest.raises(
            SecurityBudgetExceeded
        ):
            security.authorize_and_record(
                request={
                    "account": "acct-1",
                },
            )
    finally:
        tx.abort()

    # A second transaction must be able to acquire
    # the semantic lock immediately.
    tx2 = begin_lookup(
        semantic,
        fingerprint="fp-2",
    )

    tx2.commit()


def test_semantic_transaction_commit_releases_lock():
    semantic = make_semantic_context()

    tx = begin_lookup(
        semantic,
    )

    tx.commit()

    tx2 = begin_lookup(
        semantic,
        fingerprint="fp-2",
    )

    tx2.commit()


def test_semantic_transaction_abort_releases_lock():
    semantic = make_semantic_context()

    tx = begin_lookup(
        semantic,
    )

    tx.abort()

    tx2 = begin_lookup(
        semantic,
        fingerprint="fp-2",
    )

    tx2.commit()


def test_double_commit_is_idempotent():
    semantic = make_semantic_context()

    tx = begin_lookup(
        semantic,
    )

    tx.commit()
    tx.commit()

    snapshot = semantic.snapshot()

    assert len(snapshot) == 1
    assert len(snapshot[0].actions) == 1


def test_double_abort_is_idempotent():
    semantic = make_semantic_context()

    tx = begin_lookup(
        semantic,
    )

    tx.abort()
    tx.abort()

    tx2 = begin_lookup(
        semantic,
        fingerprint="fp-2",
    )

    tx2.commit()


def test_concurrent_semantic_and_security_authorization_completes():
    semantic = make_semantic_context()

    security = make_security_context(
        max_actions=1000,
    )

    errors = []

    def worker(index):
        try:
            for iteration in range(25):
                tx = begin_lookup(
                    semantic,
                    fingerprint=f"{index}-{iteration}",
                )

                try:
                    security.authorize_and_record(
                        request={
                            "account": "acct-1",
                        },
                    )
                except Exception:
                    tx.abort()
                    raise

                tx.commit()

        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(4)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(
            timeout=10
        )

    assert all(
        not thread.is_alive()
        for thread in threads
    )

    assert not errors

    snapshot = security.snapshot()

    assert snapshot.action_count == 100


def test_semantic_denial_releases_lock():
    semantic = make_semantic_context()

    first = begin_lookup(
        semantic,
    )
    first.commit()

    with pytest.raises(
        SemanticChainDenied
    ):
        semantic.begin_authorization(
            agent="agent-a",
            action="payments.send",
            request={
                "account": "acct-1",
            },
            capability_fingerprint="fp-2",
            capability="payments.send",
        )

    # A denied semantic decision must not leave
    # the context permanently locked.
    tx = begin_lookup(
        semantic,
        fingerprint="fp-3",
    )

    tx.commit()