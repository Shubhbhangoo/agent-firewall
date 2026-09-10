"""v1.6 North Star observability metadata.

The North Star ``delegation`` phase publishes an immutable
``DelegationAuthority`` into pipeline state. This test pins the first
*in-pipeline consumer* of that publication: the ``canonical_authorization``
phase enriches the returned ``SecurityDecision`` with the observed
delegation depth as ``metadata["delegation_depth"]``.

The enrichment is observability only. It must never change the allow/deny
outcome, the reason, or any identity field -- the North Star decision stays
semantically equivalent to ``authorize()`` (that invariant is locked by
``test_v1_6_north_star_equivalence``), but it now carries strictly more
information than the raw ``authorize()`` result, which never sets metadata.

Depth is the length of the resolved authority: an issued root capability
has depth 1, its direct delegate depth 2, a grandchild depth 3.
"""

from __future__ import annotations

from firewall.sdk import FirewallSDK


ACTION = "payments.send"
REQUEST = {"amount": 1}

# A 64-char hex string that is never the fingerprint of any issued
# capability, so registering it as an ancestor guarantees a missing
# ancestor when the chain is resolved (mirrors the equivalence suite).
MISSING_ANCESTOR = "0" * 64


def _make_sdk(max_delegation_depth=None) -> FirewallSDK:
    sdk = FirewallSDK(max_delegation_depth=max_delegation_depth)
    sdk.generate_key("obs-key")
    return sdk


def _issue_root(sdk: FirewallSDK):
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
    )


def _delegate(sdk: FirewallSDK, parent, delegatee: str):
    return sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee=delegatee,
    ).child


def _build_lineage(sdk: FirewallSDK):
    """Return (root[d1], child[d2], grandchild[d3]) on ``sdk``."""

    root = _issue_root(sdk)
    child = _delegate(sdk, root, "agent-b")
    grandchild = _delegate(sdk, child, "agent-c")
    return root, child, grandchild


def _comparable(decision):
    # Mirrors test_v1_6_north_star_equivalence: the key-independent fields
    # that authorize() and authorize_north_star() must agree on. Metadata
    # is deliberately excluded -- it is additive North Star observability.
    return (
        decision.allowed,
        decision.reason,
        decision.agent,
        decision.action,
        decision.tool,
    )


# ------------------------------------------------------------------
# Allow path: the observed depth is surfaced on the decision.
# ------------------------------------------------------------------


def test_root_allow_surfaces_depth_one():
    sdk = _make_sdk()
    root = _issue_root(sdk)

    decision = sdk.authorize_north_star(root, ACTION, REQUEST)

    assert decision.allowed is True
    assert decision.reason == "authorized"
    assert decision.metadata is not None
    assert decision.metadata["delegation_depth"] == 1


def test_direct_delegate_surfaces_depth_two():
    sdk = _make_sdk()
    _root, child, _grandchild = _build_lineage(sdk)

    decision = sdk.authorize_north_star(child, ACTION, REQUEST)

    assert decision.allowed is True
    assert decision.metadata["delegation_depth"] == 2


def test_grandchild_surfaces_depth_three():
    sdk = _make_sdk()
    _root, _child, grandchild = _build_lineage(sdk)

    decision = sdk.authorize_north_star(grandchild, ACTION, REQUEST)

    assert decision.allowed is True
    assert decision.metadata["delegation_depth"] == 3


# ------------------------------------------------------------------
# North Star is strictly richer than the raw authorize() result.
# ------------------------------------------------------------------


def test_direct_path_carries_no_depth_metadata():
    # The direct authorize() decision has no metadata; the depth posture is
    # something the North Star pipeline adds, not something authorize() owns.
    sdk = _make_sdk()
    _root, _child, grandchild = _build_lineage(sdk)

    direct = sdk.authorize(
        capability=grandchild,
        action=ACTION,
        request=REQUEST,
    ).decision

    assert direct.metadata is None


def test_metadata_does_not_break_equivalence():
    # The allow path is side-effect free, so both paths run on one SDK. The
    # comparable fields must still match exactly; the metadata is additive.
    sdk = _make_sdk()
    _root, _child, grandchild = _build_lineage(sdk)

    north_star = sdk.authorize_north_star(grandchild, ACTION, REQUEST)
    direct = sdk.authorize(
        capability=grandchild,
        action=ACTION,
        request=REQUEST,
    ).decision

    assert _comparable(north_star) == _comparable(direct)
    # The enrichment lives only on the North Star path.
    assert north_star.metadata["delegation_depth"] == 3
    assert direct.metadata is None


# ------------------------------------------------------------------
# Observability holds on denials too, and fails closed when the
# authority could not be published.
# ------------------------------------------------------------------


def test_depth_exceeded_denial_still_reports_observed_depth():
    # A depth-ceiling denial should still carry the depth that was observed,
    # so an operator can see how deep the rejected chain actually was.
    sdk = _make_sdk(max_delegation_depth=2)
    _root, _child, grandchild = _build_lineage(sdk)

    decision = sdk.authorize_north_star(grandchild, ACTION, REQUEST)

    assert decision.allowed is False
    assert decision.reason == "delegation_depth_exceeded"
    assert decision.metadata["delegation_depth"] == 3


def test_broken_chain_has_no_depth_metadata():
    # When lineage resolution fails, the observational phase records the
    # error instead of publishing an authority, so there is no depth to
    # surface. The enrichment fails closed to the unmodified decision.
    sdk = _make_sdk()
    cap = _issue_root(sdk)
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(cap),
        parent_fingerprint=MISSING_ANCESTOR,
    )

    decision = sdk.authorize_north_star(cap, ACTION, REQUEST)

    assert decision.allowed is False
    assert decision.reason == (
        "delegation_chain_error: "
        "delegation ancestor capability is unavailable"
    )
    assert decision.metadata is None


def test_invalid_capability_has_no_depth_metadata():
    # No Capability instance -> the observational phase never publishes an
    # authority -> the decision is returned unenriched.
    sdk = _make_sdk()

    decision = sdk.authorize_north_star(None, ACTION, REQUEST)

    assert decision.allowed is False
    assert decision.reason == "invalid_capability"
    assert decision.metadata is None
