import threading

import pytest

from firewall.delegation_lineage import (
    DelegationLineage,
    DelegationLineageError,
    LineageCycleError,
)


def make_lineage(**kwargs):
    return DelegationLineage(**kwargs)


def test_root_capability_has_no_parent():
    lineage = make_lineage()

    assert lineage.parent_of("root") is None
    assert lineage.chain("root") == ()


def test_child_records_parent():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    assert lineage.parent_of("child") == "parent"
    assert lineage.chain("child") == ("parent",)


def test_deep_lineage_preserves_ancestry():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    lineage.register(
        child_fingerprint="grandchild",
        parent_fingerprint="child",
    )

    lineage.register(
        child_fingerprint="great-grandchild",
        parent_fingerprint="grandchild",
    )

    assert lineage.chain("great-grandchild") == (
        "grandchild",
        "child",
        "parent",
    )


def test_unknown_parent_lookup_returns_none():
    lineage = make_lineage()

    assert lineage.parent_of("unknown") is None


def test_unknown_capability_has_empty_chain():
    lineage = make_lineage()

    assert lineage.chain("unknown") == ()


def test_direct_descendant_detection():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    assert lineage.is_descendant_of(
        child_fingerprint="child",
        ancestor_fingerprint="parent",
    )


def test_transitive_descendant_detection():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    lineage.register(
        child_fingerprint="grandchild",
        parent_fingerprint="child",
    )

    assert lineage.is_descendant_of(
        child_fingerprint="grandchild",
        ancestor_fingerprint="parent",
    )


def test_capability_is_not_descendant_of_itself():
    lineage = make_lineage()

    assert not lineage.is_descendant_of(
        child_fingerprint="same",
        ancestor_fingerprint="same",
    )


def test_siblings_are_not_descendants():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child-a",
        parent_fingerprint="root",
    )

    lineage.register(
        child_fingerprint="child-b",
        parent_fingerprint="root",
    )

    assert not lineage.is_descendant_of(
        child_fingerprint="child-a",
        ancestor_fingerprint="child-b",
    )

    assert not lineage.is_descendant_of(
        child_fingerprint="child-b",
        ancestor_fingerprint="child-a",
    )


def test_separate_lineage_trees_are_isolated():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child-a",
        parent_fingerprint="root-a",
    )

    lineage.register(
        child_fingerprint="child-b",
        parent_fingerprint="root-b",
    )

    assert lineage.chain("child-a") == ("root-a",)
    assert lineage.chain("child-b") == ("root-b",)

    assert not lineage.is_descendant_of(
        child_fingerprint="child-a",
        ancestor_fingerprint="root-b",
    )


def test_same_child_same_parent_is_idempotent():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    assert lineage.parent_of("child") == "parent"


def test_child_cannot_be_reparented():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent-a",
    )

    with pytest.raises(DelegationLineageError):
        lineage.register(
            child_fingerprint="child",
            parent_fingerprint="parent-b",
        )


def test_self_delegation_is_rejected():
    lineage = make_lineage()

    with pytest.raises(LineageCycleError):
        lineage.register(
            child_fingerprint="same",
            parent_fingerprint="same",
        )


def test_reparenting_existing_child_prevents_cycle():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    with pytest.raises(DelegationLineageError):
        lineage.register(
            child_fingerprint="child",
            parent_fingerprint="child",
        )


def test_existing_lineage_cannot_be_rewired_into_cycle():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    with pytest.raises(DelegationLineageError):
        lineage.register(
            child_fingerprint="b",
            parent_fingerprint="c",
        )


def test_long_lineage_is_preserved():
    lineage = make_lineage(max_depth=64)

    for index in range(1, 11):
        lineage.register(
            child_fingerprint=f"node-{index}",
            parent_fingerprint=f"node-{index - 1}",
        )

    chain = lineage.chain("node-10")

    assert chain == tuple(
        f"node-{index}"
        for index in range(9, -1, -1)
    )


def test_maximum_depth_boundary():
    lineage = make_lineage(max_depth=2)

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    assert lineage.chain("c") == (
        "b",
        "a",
    )


def test_chain_enforces_depth_when_chain_exceeds_limit():
    lineage = make_lineage(max_depth=2)

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    lineage.register(
        child_fingerprint="d",
        parent_fingerprint="c",
    )

    with pytest.raises(DelegationLineageError):
        lineage.chain("d")


def test_invalid_max_depth_is_rejected():
    with pytest.raises(ValueError):
        DelegationLineage(max_depth=0)

    with pytest.raises(ValueError):
        DelegationLineage(max_depth=-1)

    with pytest.raises(ValueError):
        DelegationLineage(max_depth=True)


def test_empty_child_fingerprint_is_rejected():
    lineage = make_lineage()

    with pytest.raises(ValueError):
        lineage.register(
            child_fingerprint="",
            parent_fingerprint="parent",
        )


def test_empty_parent_fingerprint_is_rejected():
    lineage = make_lineage()

    with pytest.raises(ValueError):
        lineage.register(
            child_fingerprint="child",
            parent_fingerprint="",
        )


def test_non_string_child_fingerprint_is_rejected():
    lineage = make_lineage()

    with pytest.raises(ValueError):
        lineage.register(
            child_fingerprint=123,
            parent_fingerprint="parent",
        )


def test_non_string_parent_fingerprint_is_rejected():
    lineage = make_lineage()

    with pytest.raises(ValueError):
        lineage.register(
            child_fingerprint="child",
            parent_fingerprint=123,
        )


def test_snapshot_contains_all_edges():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child-b",
        parent_fingerprint="parent-b",
    )

    lineage.register(
        child_fingerprint="child-a",
        parent_fingerprint="parent-a",
    )

    snapshot = lineage.snapshot()

    assert len(snapshot) == 2

    assert snapshot[0].child_fingerprint == "child-a"
    assert snapshot[0].parent_fingerprint == "parent-a"

    assert snapshot[1].child_fingerprint == "child-b"
    assert snapshot[1].parent_fingerprint == "parent-b"


def test_snapshot_is_deterministically_sorted():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="z-child",
        parent_fingerprint="z-parent",
    )

    lineage.register(
        child_fingerprint="a-child",
        parent_fingerprint="a-parent",
    )

    snapshot = lineage.snapshot()

    assert [
        record.child_fingerprint
        for record in snapshot
    ] == [
        "a-child",
        "z-child",
    ]


def test_clear_removes_all_edges():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child-a",
        parent_fingerprint="parent-a",
    )

    lineage.register(
        child_fingerprint="child-b",
        parent_fingerprint="parent-b",
    )

    lineage.clear()

    assert lineage.snapshot() == ()
    assert lineage.parent_of("child-a") is None
    assert lineage.parent_of("child-b") is None
    assert lineage.chain("child-a") == ()


def test_clear_allows_reuse_of_fingerprints():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent-a",
    )

    lineage.clear()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent-b",
    )

    assert lineage.parent_of("child") == "parent-b"


def test_concurrent_registration_preserves_all_edges():
    lineage = make_lineage()

    errors = []

    def register(index):
        try:
            lineage.register(
                child_fingerprint=f"child-{index}",
                parent_fingerprint="root",
            )
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(
            target=register,
            args=(index,),
        )
        for index in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert len(lineage.snapshot()) == 100

    for index in range(100):
        assert lineage.parent_of(
            f"child-{index}"
        ) == "root"


def test_concurrent_same_edge_registration_is_safe():
    lineage = make_lineage()

    errors = []

    def register():
        try:
            lineage.register(
                child_fingerprint="child",
                parent_fingerprint="parent",
            )
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=register)
        for _ in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert lineage.parent_of("child") == "parent"
    assert len(lineage.snapshot()) == 1


def test_concurrent_conflicting_parent_registration_has_single_parent():
    lineage = make_lineage()

    errors = []

    def register(parent):
        try:
            lineage.register(
                child_fingerprint="child",
                parent_fingerprint=parent,
            )
        except DelegationLineageError:
            pass
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(
            target=register,
            args=("parent-a",),
        ),
        threading.Thread(
            target=register,
            args=("parent-b",),
        ),
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []

    assert lineage.parent_of("child") in {
        "parent-a",
        "parent-b",
    }

    assert len(lineage.snapshot()) == 1


def test_chain_is_deterministic():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    expected = (
        "b",
        "a",
    )

    assert lineage.chain("c") == expected
    assert lineage.chain("c") == expected
    assert lineage.chain("c") == expected


def test_descendant_check_is_deterministic():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    for _ in range(10):
        assert lineage.is_descendant_of(
            child_fingerprint="c",
            ancestor_fingerprint="a",
        )


def test_root_remains_non_descendant_of_all_other_nodes():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="root",
    )

    assert not lineage.is_descendant_of(
        child_fingerprint="root",
        ancestor_fingerprint="child",
    )


def test_lineage_snapshot_does_not_change_without_mutation():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="child",
        parent_fingerprint="parent",
    )

    first = lineage.snapshot()
    second = lineage.snapshot()

    assert first == second


def test_concurrent_reads_are_safe():
    lineage = make_lineage()

    lineage.register(
        child_fingerprint="b",
        parent_fingerprint="a",
    )

    lineage.register(
        child_fingerprint="c",
        parent_fingerprint="b",
    )

    errors = []

    def read():
        try:
            lineage.parent_of("c")
            lineage.chain("c")
            lineage.is_descendant_of(
                child_fingerprint="c",
                ancestor_fingerprint="a",
            )
            lineage.snapshot()
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=read)
        for _ in range(100)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []