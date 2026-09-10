from firewall.delegation_lineage import (
    DelegationLineage,
    DelegationLineageError,
)


def test_max_depth_allows_chain_at_limit():
    lineage = DelegationLineage(
        max_depth=2,
    )

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


def test_max_depth_rejects_chain_beyond_limit():
    lineage = DelegationLineage(
        max_depth=2,
    )

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

    try:
        lineage.chain("d")
    except DelegationLineageError:
        return

    raise AssertionError(
        "delegation chain exceeded max_depth"
    )