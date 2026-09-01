"""v2.2 §2-§3 capability and delegation security.

The invariant under test is `child authority <= parent authority`, and
that it holds transitively: authority(C) <= authority(B) <= authority(A)
<= authority(root).

The sharper cases here are about the *two* records of a delegation edge.
`delegate_capability` binds the parent's fingerprint into the child's
signed payload; `DelegationLineage` records the same edge as mutable
state. Only the signature is unforgeable, so where they disagree
authorization has to follow the signature. Several tests below attack the
registry directly to confirm it cannot be used to re-parent, orphan, or
otherwise launder a legitimately signed capability into wider authority.
"""

import time

import pytest

from firewall.capability import Capability, sign_capability
from firewall.delegation_lineage import (
    DelegationLineage,
    DelegationLineageError,
    LineageCycleError,
)
from firewall.sdk import FirewallSDK
from firewall.continuous_auth.predicates import is_narrower_than


def make_sdk(**kwargs) -> FirewallSDK:
    sdk = FirewallSDK(**kwargs)
    sdk.generate_key("test-key")
    return sdk


def private_key(sdk):
    return sdk.keys.active().private_key


# --------------------------------------------------------------------------
# §2 Capability security: the narrowing matrix
# --------------------------------------------------------------------------


def test_delegation_with_equal_constraints_is_permitted():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data"]}
    )
    child = sdk.delegate(
        root,
        private_key(sdk),
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    ).child

    assert sdk.authorize(child, "read", {"paths": "/data"}).allowed


def test_delegation_narrowing_a_list_is_permitted():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root",
        capability="read",
        constraints={"paths": ["/data", "/logs"]},
    )
    child = sdk.delegate(
        root,
        private_key(sdk),
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    ).child

    assert sdk.authorize(child, "read", {"paths": "/data"}).allowed
    # The narrowed-away value is refused, which is what narrowing means.
    assert not sdk.authorize(child, "read", {"paths": "/logs"}).allowed


def test_delegation_widening_a_list_is_refused():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data"]}
    )

    with pytest.raises(ValueError, match="broaden"):
        sdk.delegate(
            root,
            private_key(sdk),
            delegatee="agent-a",
            constraints={"paths": ["/data", "/etc/shadow"]},
        )


def test_delegation_raising_a_numeric_ceiling_is_refused():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="payments.send", constraints={"amount_max": 100}
    )

    with pytest.raises(ValueError, match="broaden"):
        sdk.delegate(
            root,
            private_key(sdk),
            delegatee="agent-a",
            constraints={"amount_max": 10_000},
        )


def test_delegation_lowering_a_numeric_ceiling_is_permitted():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="payments.send", constraints={"amount_max": 100}
    )
    child = sdk.delegate(
        root,
        private_key(sdk),
        delegatee="agent-a",
        constraints={"amount_max": 10},
    ).child

    assert sdk.authorize(child, "payments.send", {"amount": 5}).allowed
    assert not sdk.authorize(child, "payments.send", {"amount": 50}).allowed


def test_delegation_dropping_a_parent_constraint_is_refused():
    """Removing a limit is widening, even though the dict gets smaller."""
    sdk = make_sdk()
    root = sdk.issue(
        agent="root",
        capability="payments.send",
        constraints={"amount_max": 100, "paths": ["/data"]},
    )

    with pytest.raises(ValueError, match="broaden"):
        sdk.delegate(
            root,
            private_key(sdk),
            delegatee="agent-a",
            constraints={"paths": ["/data"]},
        )


def test_delegation_adding_a_constraint_is_permitted():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="payments.send", constraints={"amount_max": 100}
    )
    child = sdk.delegate(
        root,
        private_key(sdk),
        delegatee="agent-a",
        constraints={"amount_max": 100, "region": ["eu"]},
    ).child

    assert sdk.authorize(
        child, "payments.send", {"amount": 5, "region": "eu"}
    ).allowed
    assert not sdk.authorize(
        child, "payments.send", {"amount": 5, "region": "us"}
    ).allowed


def test_delegation_cannot_extend_expiry():
    sdk = make_sdk()
    now = time.time()
    root = sdk.issue(agent="root", capability="read", expires_at=now + 60)

    with pytest.raises(ValueError):
        sdk.delegate(
            root,
            private_key(sdk),
            delegatee="agent-a",
            expires_at=now + 86_400,
        )


def test_malformed_delegation_input_is_refused():
    sdk = make_sdk()

    with pytest.raises((TypeError, ValueError)):
        sdk.delegate("not-a-capability", private_key(sdk), delegatee="agent-a")

    with pytest.raises((TypeError, ValueError)):
        sdk.delegate(
            sdk.issue(agent="root", capability="read"),
            private_key(sdk),
            delegatee="",
        )


def test_authorizing_a_non_capability_is_refused_not_raised():
    sdk = make_sdk()

    result = sdk.authorize({"capability": "read"}, "read", {})

    assert not result.allowed
    assert result.reason == "invalid_capability"


def test_revoked_parent_revokes_the_delegated_child():
    sdk = make_sdk()
    root = sdk.issue(agent="root", capability="read")
    child = sdk.delegate(root, private_key(sdk), delegatee="agent-a").child

    assert sdk.authorize(child, "read", {}).allowed

    sdk.revoke(root)

    result = sdk.authorize(child, "read", {})
    assert not result.allowed
    assert result.reason == "capability_revoked"


def test_expired_parent_expires_the_delegated_child():
    # Start the injected clock slightly ahead of the real clock that
    # stamps ``issued_at``, so the capability is inside its validity
    # window rather than not-yet-valid.
    now = [time.time() + 5]
    sdk = make_sdk(clock=lambda: now[0])
    root = sdk.issue(agent="root", capability="read", expires_at=now[0] + 60)
    child = sdk.delegate(
        root, private_key(sdk), delegatee="agent-a", expires_at=now[0] + 60
    ).child

    assert sdk.authorize(child, "read", {}).allowed

    now[0] += 120

    assert not sdk.authorize(child, "read", {}).allowed


# --------------------------------------------------------------------------
# §3 Delegation security: transitivity
# --------------------------------------------------------------------------


def test_effective_authority_is_the_intersection_of_the_whole_chain():
    """A grandchild is bound by its grandparent, not just its parent."""
    sdk = make_sdk()
    key = private_key(sdk)

    root = sdk.issue(
        agent="root",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    middle = sdk.delegate(
        root, key, delegatee="agent-b", constraints={"amount_max": 50}
    ).child
    leaf = sdk.delegate(
        middle, key, delegatee="agent-c", constraints={"amount_max": 10}
    ).child

    assert sdk.authorize(leaf, "payments.send", {"amount": 10}).allowed
    assert not sdk.authorize(leaf, "payments.send", {"amount": 11}).allowed


def test_revoking_the_root_revokes_the_whole_subtree():
    sdk = make_sdk()
    key = private_key(sdk)

    root = sdk.issue(agent="root", capability="read")
    middle = sdk.delegate(root, key, delegatee="agent-b").child
    leaf = sdk.delegate(middle, key, delegatee="agent-c").child

    assert sdk.authorize(leaf, "read", {}).allowed

    sdk.revoke(root)

    assert not sdk.authorize(middle, "read", {}).allowed
    assert not sdk.authorize(leaf, "read", {}).allowed


def test_revoking_a_child_leaves_the_parent_intact():
    """Revocation propagates down the tree, never up it."""
    sdk = make_sdk()
    root = sdk.issue(agent="root", capability="read")
    child = sdk.delegate(root, private_key(sdk), delegatee="agent-a").child

    sdk.revoke(child)

    assert not sdk.authorize(child, "read", {}).allowed
    assert sdk.authorize(root, "read", {}).allowed


def test_authorization_time_depth_ceiling_is_enforced():
    # Depth counts the whole chain, so a root is depth 1 and its direct
    # delegate is depth 2.
    sdk = make_sdk(max_delegation_depth=2)
    key = private_key(sdk)

    root = sdk.issue(agent="root", capability="read")
    middle = sdk.delegate(root, key, delegatee="agent-b").child
    leaf = sdk.delegate(middle, key, delegatee="agent-c").child

    assert sdk.authorize(middle, "read", {}).allowed

    result = sdk.authorize(leaf, "read", {})
    assert not result.allowed
    assert result.reason == "delegation_depth_exceeded"


def test_lineage_refuses_self_parenting():
    lineage = DelegationLineage()

    with pytest.raises(LineageCycleError):
        lineage.register(child_fingerprint="a" * 64, parent_fingerprint="a" * 64)


def test_lineage_refuses_a_cycle():
    lineage = DelegationLineage()
    lineage.register(child_fingerprint="b" * 64, parent_fingerprint="a" * 64)
    lineage.register(child_fingerprint="c" * 64, parent_fingerprint="b" * 64)

    # The closing edge of the cycle: a's proposed parent c already
    # reaches a. Rejected at write time, so the corrupt edge is never
    # persisted for a reader to trip over.
    with pytest.raises(LineageCycleError):
        lineage.register(child_fingerprint="a" * 64, parent_fingerprint="c" * 64)

    assert lineage.parent_of("a" * 64) is None
    assert lineage.chain("c" * 64) == ("b" * 64, "a" * 64)


def test_lineage_refuses_a_second_parent_for_one_child():
    """An edge is write-once. Re-parenting is the escalation this blocks."""
    lineage = DelegationLineage()
    lineage.register(child_fingerprint="b" * 64, parent_fingerprint="a" * 64)

    with pytest.raises(DelegationLineageError, match="different parent"):
        lineage.register(child_fingerprint="b" * 64, parent_fingerprint="c" * 64)

    # Re-registering the same edge is idempotent, not an error.
    lineage.register(child_fingerprint="b" * 64, parent_fingerprint="a" * 64)
    assert lineage.parent_of("b" * 64) == "a" * 64


def test_lineage_enforces_a_depth_ceiling():
    lineage = DelegationLineage(max_depth=3)

    previous = "0" * 64
    for index in range(1, 5):
        lineage.register(
            child_fingerprint=str(index) * 64, parent_fingerprint=previous
        )
        previous = str(index) * 64

    with pytest.raises(DelegationLineageError, match="maximum depth"):
        lineage.register(child_fingerprint="9" * 64, parent_fingerprint=previous)


def test_unresolvable_ancestor_fails_closed():
    """A broken chain must not fall back to the child's own rights."""
    sdk = make_sdk()
    cap = sdk.issue(
        agent="agent-a", capability="read", constraints={"paths": ["/data"]}
    )
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(cap),
        parent_fingerprint="0" * 64,
    )

    result = sdk.authorize(cap, "read", {"paths": "/data"})

    assert not result.allowed
    assert "delegation_chain_error" in result.reason


# --------------------------------------------------------------------------
# Signed lineage vs registered lineage
# --------------------------------------------------------------------------


def test_a_delegated_capability_cannot_authorize_as_a_root():
    """Losing the lineage edge must not promote a delegate to a root.

    The child's signature names its parent. If the registry has no edge,
    the resolved chain is just the child -- so the monotonicity gate has
    nothing to compare, the effective-authority intersection loses the
    parent's constraints, transitive revocation of the parent no longer
    reaches it, and the cumulative lineage budget resets to a fresh one.
    Detaching from an ancestor is not a narrowing.
    """
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data"]}
    )
    child = sdk.delegate(
        root,
        private_key(sdk),
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    ).child

    assert child.parent_fingerprint == sdk.fingerprint(root)
    assert sdk.authorize(child, "read", {"paths": "/data"}).allowed

    # Drop the edge, keeping the signed capability byte-for-byte intact.
    sdk.delegation_lineage.clear()

    result = sdk.authorize(child, "read", {"paths": "/data"})
    assert not result.allowed
    assert "delegation_chain_error" in result.reason
    assert "no delegation parent is registered" in result.reason


def test_orphaning_a_delegate_does_not_reset_transitive_revocation():
    """The concrete escalation the orphan check closes."""
    sdk = make_sdk()
    root = sdk.issue(agent="root", capability="read")
    child = sdk.delegate(root, private_key(sdk), delegatee="agent-a").child

    sdk.revoke(root)
    assert not sdk.authorize(child, "read", {}).allowed

    sdk.delegation_lineage.clear()

    # Without the signed-lineage check this would be allowed again: the
    # child itself was never revoked, and the ancestor walk now finds
    # nothing to check.
    assert not sdk.authorize(child, "read", {}).allowed


def test_a_delegate_cannot_be_re_parented_to_a_wider_parent():
    """Signed parent wins over registered parent.

    ``DelegationLineage`` already refuses to overwrite an edge, so this
    reaches the check the way an attacker with store access would: the
    registry is rebuilt from scratch with the child bound to a wider
    capability it was never delegated from.
    """
    sdk = make_sdk()
    key = private_key(sdk)

    narrow_root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data"]}
    )
    wide_root = sdk.issue(
        agent="root",
        capability="read",
        constraints={"paths": ["/data", "/etc/shadow"]},
    )

    child = sdk.delegate(
        narrow_root,
        key,
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    ).child

    sdk.delegation_lineage.clear()
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(child),
        parent_fingerprint=sdk.fingerprint(wide_root),
    )

    result = sdk.authorize(child, "read", {"paths": "/data"})

    assert not result.allowed
    assert "does not match its registered delegation parent" in result.reason


def test_re_parenting_is_refused_even_when_the_new_parent_is_narrower():
    """The check is about agreement, not about which parent is stricter.

    A monotonicity-only check would accept this, because a narrower
    parent passes ``child <= parent``. But the resolved chain would still
    be a lineage nobody signed, and the same mechanism would then accept
    a wider one whenever the child's own constraints happened to cover
    it.
    """
    sdk = make_sdk()
    key = private_key(sdk)

    signed_parent = sdk.issue(
        agent="root",
        capability="read",
        constraints={"paths": ["/data", "/logs"]},
    )
    # Pinned to the signed parent's timestamp on purpose. ``delegate``
    # copies the parent's ``issued_at`` into the child, so a decoy issued
    # a clock tick later is *newer* than the child and
    # ``is_narrower_than`` refuses it with "child issued before parent"
    # -- a real rule, but not the one under test. Leaving it unpinned
    # made the outcome depend on whether the platform clock ticked
    # between two adjacent calls.
    other_parent = sdk.issue(
        agent="root",
        capability="read",
        constraints={"paths": ["/data"]},
        issued_at=signed_parent.issued_at,
    )
    child = sdk.delegate(
        signed_parent,
        key,
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    ).child

    assert is_narrower_than(other_parent, child).monotonic

    sdk.delegation_lineage.clear()
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(child),
        parent_fingerprint=sdk.fingerprint(other_parent),
    )

    outcome = sdk.authorize(child, "read", {"paths": "/data"})

    assert not outcome.allowed
    # The reason is asserted so the test cannot pass because some other
    # rule happened to deny -- the claim is specifically that the
    # registered parent disagreeing with the signed one is refused.
    assert "does not match its registered delegation parent" in (
        outcome.reason
    )


def test_a_mid_chain_delegate_cannot_be_re_parented():
    """The check walks the whole chain, not just the leaf."""
    sdk = make_sdk()
    key = private_key(sdk)

    root = sdk.issue(
        agent="root",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    decoy = sdk.issue(
        agent="root",
        capability="payments.send",
        constraints={"amount_max": 1_000_000},
        # Pinned to ``root``'s timestamp: see the note in
        # test_re_parenting_is_refused_even_when_the_new_parent_is_narrower.
        issued_at=root.issued_at,
    )
    middle = sdk.delegate(
        root, key, delegatee="agent-b", constraints={"amount_max": 100}
    ).child
    leaf = sdk.delegate(
        middle, key, delegatee="agent-c", constraints={"amount_max": 100}
    ).child

    assert sdk.authorize(leaf, "payments.send", {"amount": 10}).allowed

    sdk.delegation_lineage.clear()
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(leaf),
        parent_fingerprint=sdk.fingerprint(middle),
    )
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(middle),
        parent_fingerprint=sdk.fingerprint(decoy),
    )

    outcome = sdk.authorize(leaf, "payments.send", {"amount": 10})

    assert not outcome.allowed
    # Reason asserted for the same reason as the leaf case: a denial from
    # anywhere else would leave the re-parenting claim untested.
    assert "does not match its registered delegation parent" in (
        outcome.reason
    )


def test_attenuated_capabilities_still_authorize():
    """Attenuation does not sign a parent_fingerprint.

    The check must not require one, or the entire attenuation path
    becomes unauthorizable. An extra registered ancestor only adds
    constraints, so a resolved parent with no signed claim is safe.
    """
    sdk = make_sdk()
    root = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    child = sdk.attenuate(
        root, private_key(sdk), constraints={"amount_max": 10}
    )

    assert child.parent_fingerprint is None
    assert sdk.delegation_lineage.parent_of(sdk.fingerprint(child)) == (
        sdk.fingerprint(root)
    )
    assert sdk.authorize(child, "payments.send", {"amount": 5}).allowed
    assert not sdk.authorize(child, "payments.send", {"amount": 50}).allowed


def test_a_forged_parent_fingerprint_does_not_survive_signing():
    """The field is inside the signed payload, so it cannot be edited.

    ``dataclasses.replace`` on a signed capability produces something
    whose signature no longer verifies -- which is the property that lets
    the resolver trust the field at all.
    """
    from dataclasses import replace

    sdk = make_sdk()
    root = sdk.issue(agent="root", capability="read")
    child = sdk.delegate(root, private_key(sdk), delegatee="agent-a").child

    tampered = replace(child, parent_fingerprint="f" * 64)

    sdk.delegation_lineage.clear()
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(tampered),
        parent_fingerprint="f" * 64,
    )

    result = sdk.authorize(tampered, "read", {})
    assert not result.allowed


def test_a_self_signed_capability_cannot_claim_a_parent_it_does_not_have():
    """Signing your own capability does not let you name a rich parent.

    Anyone can mint a capability with an arbitrary ``parent_fingerprint``
    under their own key. The issuer-trust and signature gates handle the
    untrusted-key case; this asserts that even when the key *is* trusted,
    naming a parent obliges the lineage to produce it.
    """
    sdk = make_sdk()
    key = private_key(sdk)

    victim = sdk.issue(
        agent="victim",
        capability="payments.send",
        constraints={"amount_max": 1_000_000},
    )

    forged = sign_capability(
        key,
        agent_id="attacker",
        capability="payments.send",
        constraints={"amount_max": 1_000_000},
        issuer="trusted-issuer",
        issued_at=time.time(),
        expires_at=time.time() + 3600,
        parent_fingerprint=sdk.fingerprint(victim),
    )

    assert isinstance(forged, Capability)

    result = sdk.authorize(forged, "payments.send", {"amount": 10})
    assert not result.allowed
    assert "delegation_chain_error" in result.reason
