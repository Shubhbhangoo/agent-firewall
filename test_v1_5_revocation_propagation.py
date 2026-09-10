from firewall.revocation import AlreadyRevokedError

from firewall.sdk import FirewallSDK
import pytest


def make_sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key("revocation-key")
    return sdk


def make_chain(sdk: FirewallSDK):
    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    b = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child

    c = sdk.delegate(
        b,
        sdk.active_key().private_key,
        delegatee="agent-c",
    ).child

    d = sdk.delegate(
        c,
        sdk.active_key().private_key,
        delegatee="agent-d",
    ).child

    return root, b, c, d


def test_revoking_root_denies_every_descendant():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    assert sdk.verify(root)
    assert sdk.verify(b)
    assert sdk.verify(c)
    assert sdk.verify(d)

    sdk.revoke(
        root,
        reason="root compromised",
    )

    assert sdk.verify(root) is False
    assert sdk.verify(b) is False
    assert sdk.verify(c) is False
    assert sdk.verify(d) is False


def test_revoking_intermediate_denies_descendants_but_not_root():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    sdk.revoke(
        b,
        reason="intermediate compromised",
    )

    assert sdk.verify(root) is True
    assert sdk.verify(b) is False
    assert sdk.verify(c) is False
    assert sdk.verify(d) is False


def test_revoking_leaf_does_not_revoke_ancestors():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    sdk.revoke(
        d,
        reason="leaf compromised",
    )

    assert sdk.verify(root) is True
    assert sdk.verify(b) is True
    assert sdk.verify(c) is True
    assert sdk.verify(d) is False


def test_authorization_denies_descendant_after_root_revocation():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    sdk.revoke(
        root,
        reason="root compromised",
    )

    result = sdk.authorize(
        d,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_authorization_denies_descendant_after_intermediate_revocation():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    sdk.revoke(
        b,
        reason="intermediate compromised",
    )

    result = sdk.authorize(
        d,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_revoking_one_branch_does_not_revoke_sibling_branch():
    sdk = make_sdk()

    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    b1 = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b1",
    ).child

    b2 = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b2",
    ).child

    c1 = sdk.delegate(
        b1,
        sdk.active_key().private_key,
        delegatee="agent-c1",
    ).child

    c2 = sdk.delegate(
        b2,
        sdk.active_key().private_key,
        delegatee="agent-c2",
    ).child

    sdk.revoke(
        b1,
        reason="branch compromised",
    )

    assert sdk.verify(root) is True
    assert sdk.verify(b1) is False
    assert sdk.verify(c1) is False

    assert sdk.verify(b2) is True
    assert sdk.verify(c2) is True


def test_revocation_is_transitive_across_multiple_levels():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    sdk.revoke(
        c,
        reason="deep compromise",
    )

    assert sdk.verify(root) is True
    assert sdk.verify(b) is True
    assert sdk.verify(c) is False
    assert sdk.verify(d) is False


def test_revocation_propagation_does_not_delete_lineage():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    root_fp = sdk.fingerprint(root)
    b_fp = sdk.fingerprint(b)
    c_fp = sdk.fingerprint(c)
    d_fp = sdk.fingerprint(d)

    sdk.revoke(
        b,
        reason="intermediate compromised",
    )

    assert (
        sdk.delegation_lineage.parent_of(b_fp)
        == root_fp
    )

    assert (
        sdk.delegation_lineage.parent_of(c_fp)
        == b_fp
    )

    assert (
        sdk.delegation_lineage.parent_of(d_fp)
        == c_fp
    )


def test_repeated_revocation_is_rejected():
    sdk = make_sdk()
    root, b, c, d = make_chain(sdk)

    sdk.revoke(
        root,
        reason="compromised",
    )

    with pytest.raises(
        AlreadyRevokedError,
        match="already revoked",
    ):
        sdk.revoke(
            root,
            reason="compromised again",
        )

    assert sdk.verify(root) is False
    assert sdk.verify(b) is False
    assert sdk.verify(c) is False
    assert sdk.verify(d) is False