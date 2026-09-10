from __future__ import annotations

import threading
import time

from firewall.delegation_lineage import DelegationLineage
from firewall.sdk import FirewallSDK


def make_sdk():
    sdk = FirewallSDK(
        delegation_lineage=DelegationLineage(),
    )
    sdk.generate_key("test-key")
    return sdk


def make_root(sdk):
    now = time.time()

    return sdk.issue(
        agent="agent-root",
        capability="payments.send",
        constraints={"amount_max": 1000},
        issued_at=now,
        expires_at=now + 3600,
    )


def test_concurrent_authorization_is_stable():
    sdk = make_sdk()
    root = make_root(sdk)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
        constraints={"amount_max": 500},
    ).child

    results = []
    errors = []

    def authorize():
        try:
            result = sdk.authorize(
                child,
                "payments.send",
                {"amount": 100},
            )
            results.append(result.allowed)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=authorize)
        for _ in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 100
    assert all(results)


def test_concurrent_revocation_never_causes_exception():
    sdk = make_sdk()
    root = make_root(sdk)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    results = []
    errors = []

    barrier = threading.Barrier(51)

    def authorize():
        try:
            barrier.wait()

            result = sdk.authorize(
                child,
                "payments.send",
                {},
            )

            results.append(result)
        except Exception as exc:
            errors.append(exc)

    def revoke():
        try:
            barrier.wait()
            sdk.revoke(root)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=authorize)
        for _ in range(50)
    ]

    threads.append(
        threading.Thread(target=revoke)
    )

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 50

    # Once the root is revoked, every later authorization
    # must fail closed.
    assert sdk.is_effectively_revoked(child)


def test_concurrent_sibling_authorization_isolated():
    sdk = make_sdk()
    root = make_root(sdk)

    child_a = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-a",
        constraints={"amount_max": 100},
    ).child

    child_b = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
        constraints={"amount_max": 500},
    ).child

    results_a = []
    results_b = []
    errors = []

    def authorize_a():
        try:
            for _ in range(100):
                results_a.append(
                    sdk.authorize(
                        child_a,
                        "payments.send",
                        {"amount": 50},
                    ).allowed
                )
        except Exception as exc:
            errors.append(exc)

    def authorize_b():
        try:
            for _ in range(100):
                results_b.append(
                    sdk.authorize(
                        child_b,
                        "payments.send",
                        {"amount": 400},
                    ).allowed
                )
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=authorize_a),
        threading.Thread(target=authorize_b),
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert all(results_a)
    assert all(results_b)


def test_concurrent_lineage_reads_are_safe():
    lineage = DelegationLineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    lineage.register(
        child_fingerprint="grandchild",
        parent_fingerprint="child",
    )

    errors = []
    results = []

    def read_lineage():
        try:
            results.append(
                lineage.chain("grandchild")
            )

            results.append(
                lineage.parent_of("grandchild")
            )

            results.append(
                lineage.snapshot()
            )
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=read_lineage)
        for _ in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []

    assert all(
        result == ("child", "parent")
        for result in results[0::3]
    )

    assert all(
        result == "child"
        for result in results[1::3]
    )


def test_concurrent_delegation_registration_is_safe():
    sdk = make_sdk()
    root = make_root(sdk)

    children = []
    errors = []

    def delegate(index):
        try:
            child = sdk.delegate(
                root,
                sdk.active_key().private_key,
                delegatee=f"agent-{index}",
            ).child

            children.append(child)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(
            target=delegate,
            args=(index,),
        )
        for index in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert len(children) == 50

    snapshot = sdk.delegation_lineage.snapshot()

    assert len(snapshot) == 50


def test_concurrent_root_revocation_is_serialized():
    sdk = make_sdk()
    root = make_root(sdk)

    errors = []

    def revoke():
        try:
            sdk.revoke(root)
        except Exception:
            # Already-revoked races are expected.
            pass

    threads = [
        threading.Thread(target=revoke)
        for _ in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert sdk.is_effectively_revoked(root)
    assert errors == []


def test_authorization_after_completed_revocation_is_denied():
    sdk = make_sdk()
    root = make_root(sdk)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    sdk.revoke(root)

    for _ in range(100):
        result = sdk.authorize(
            child,
            "payments.send",
            {},
        )

        assert not result.allowed
        assert result.reason == "capability_revoked"


def test_concurrent_authorization_and_repeated_lineage_reads():
    sdk = make_sdk()
    root = make_root(sdk)

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    errors = []

    def authorize_loop():
        try:
            for _ in range(100):
                sdk.authorize(
                    child,
                    "payments.send",
                    {},
                )
        except Exception as exc:
            errors.append(exc)

    def lineage_loop():
        try:
            fingerprint = sdk.delegation_lineage.chain(
                sdk._capability_registry
                and next(
                    fp
                    for fp, capability
                    in sdk._capability_registry.items()
                    if capability == child
                )
            )

            for _ in range(100):
                assert len(fingerprint) == 1
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(
            target=authorize_loop
        ),
        threading.Thread(
            target=lineage_loop
        ),
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []