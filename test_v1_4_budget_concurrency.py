from __future__ import annotations

import threading

from firewall.security_context import (
    SecurityBudgetExceeded,
    SecurityContext,
)
from firewall.semantic_chain import (
    SemanticBudgetExceeded,
    SemanticChainContext,
)


def authorize_chain(
    semantic,
    security,
    chain_id,
    amount,
):
    tx = None

    try:
        tx = semantic.begin_authorization(
            agent="agent-a",
            action="payments.send",
            request={
                "amount": amount,
                "account": "acct-1",
            },
            capability_fingerprint=(
                f"{chain_id}-{amount}"
            ),
            capability="payments.send",
            chain_id=chain_id,
        )

        security.authorize_and_record(
            request={
                "amount": amount,
                "account": "acct-1",
            },
        )

        tx.commit()
        tx = None

    except (
        SecurityBudgetExceeded,
        SemanticBudgetExceeded,
    ):
        if tx is not None:
            tx.abort()
        raise

    except Exception:
        if tx is not None:
            tx.abort()
        raise


def test_concurrent_cross_chain_budget_never_overspends():
    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=100,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    results = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            authorize_chain(
                semantic,
                security,
                f"chain-{index}",
                60,
            )
            outcome = "allowed"
        except (
            SecurityBudgetExceeded,
            SemanticBudgetExceeded,
        ):
            outcome = "denied"
        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(2)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert results.count("allowed") == 1
    assert results.count("denied") == 1

    assert semantic.total_amount() <= 100
    assert security.snapshot().total_amount <= 100


def test_many_concurrent_chains_share_one_budget():
    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=100,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    results = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            authorize_chain(
                semantic,
                security,
                f"chain-{index}",
                10,
            )
            outcome = "allowed"
        except (
            SecurityBudgetExceeded,
            SemanticBudgetExceeded,
        ):
            outcome = "denied"
        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert results.count("allowed") == 10
    assert results.count("denied") == 10

    assert semantic.total_amount() == 100
    assert security.snapshot().total_amount == 100


def test_failed_concurrent_budget_attempts_do_not_commit_semantic_actions():
    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=100,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    authorize_chain(
        semantic,
        security,
        "initial",
        100,
    )

    results = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            authorize_chain(
                semantic,
                security,
                f"overflow-{index}",
                1,
            )
            outcome = "allowed"
        except (
            SecurityBudgetExceeded,
            SemanticBudgetExceeded,
        ):
            outcome = "denied"
        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(10)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert results == ["denied"] * 10

    assert semantic.total_amount() == 100
    assert security.snapshot().total_amount == 100

    snapshots = semantic.snapshot()

    overflow_actions = [
        action
        for snapshot in snapshots
        if snapshot.chain_id.startswith("overflow-")
        for action in snapshot.actions
    ]

    assert overflow_actions == []


def test_concurrent_budget_exact_boundary():
    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=100,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    results = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            authorize_chain(
                semantic,
                security,
                f"boundary-{index}",
                25,
            )
            outcome = "allowed"
        except (
            SecurityBudgetExceeded,
            SemanticBudgetExceeded,
        ):
            outcome = "denied"
        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(outcome)

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
        thread.join()

    assert not errors
    assert results.count("allowed") == 4
    assert results.count("denied") == 0

    assert semantic.total_amount() == 100
    assert security.snapshot().total_amount == 100


def test_concurrent_budget_remaining_amount_is_atomic():
    semantic = SemanticChainContext(
        agent="agent-a",
        max_total_amount=100,
    )

    security = SecurityContext(
        agent="agent-a",
        max_total_amount=100,
    )

    authorize_chain(
        semantic,
        security,
        "seed",
        90,
    )

    results = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            authorize_chain(
                semantic,
                security,
                f"remaining-{index}",
                10,
            )
            outcome = "allowed"
        except (
            SecurityBudgetExceeded,
            SemanticBudgetExceeded,
        ):
            outcome = "denied"
        except Exception as exc:
            with lock:
                errors.append(exc)
            return

        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(10)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors
    assert results.count("allowed") == 1
    assert results.count("denied") == 9

    assert semantic.total_amount() == 100
    assert security.snapshot().total_amount == 100