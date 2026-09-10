"""v1.6 North Star opt-in delegation-depth policy.

North Star publishes an immutable ``DelegationAuthority`` describing the
effective delegation lineage. This test pins the first downstream gate to
*consume* that authority: an optional ceiling on the effective delegation
depth, configured through ``FirewallSDK(max_delegation_depth=...)``.

The policy is deliberately opt-in. With the default (``None``) the gate is
a no-op, so the v1.5 baseline and the North Star equivalence invariant are
untouched. When configured, the ceiling is enforced by the *shared* gate
tuple, so ``authorize()`` and ``authorize_north_star()`` cannot diverge --
the depth-exceeded scenario below asserts exactly that.

Depth is the length of the resolved authority: an issued root capability
has depth 1, its direct delegate depth 2, a grandchild depth 3.

Scenarios that observe a denial use a *fresh* SDK per path, because
``authorize()`` has security side effects (lifecycle, risk/security denial
recording); sharing one SDK across both paths would let the first call's
side effects change the second call's result.
"""

from __future__ import annotations

import pytest

from firewall.sdk import FirewallSDK


ACTION = "payments.send"
REQUEST = {"amount": 1}


def _make_sdk(max_delegation_depth=None) -> FirewallSDK:
    sdk = FirewallSDK(max_delegation_depth=max_delegation_depth)
    sdk.generate_key("depth-key")
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


# ------------------------------------------------------------------
# Default: policy disabled -> no behavior change.
# ------------------------------------------------------------------


def test_default_policy_allows_deep_chains():
    # With no ceiling configured, a depth-3 delegated chain authorizes on
    # its own merit exactly as it did before the gate existed.
    sdk = _make_sdk()
    _root, _child, grandchild = _build_lineage(sdk)

    result = sdk.authorize(
        capability=grandchild,
        action=ACTION,
        request=REQUEST,
    )

    assert result.allowed is True
    assert result.reason == "authorized"


def test_default_policy_leaves_attribute_none():
    sdk = _make_sdk()

    assert sdk.max_delegation_depth is None


# ------------------------------------------------------------------
# Configured ceiling: over-depth is denied, within-limit is allowed.
# ------------------------------------------------------------------


def test_configured_limit_denies_over_depth():
    sdk = _make_sdk(max_delegation_depth=2)
    _root, _child, grandchild = _build_lineage(sdk)

    result = sdk.authorize(
        capability=grandchild,
        action=ACTION,
        request=REQUEST,
    )

    assert result.allowed is False
    assert result.reason == "delegation_depth_exceeded"


def test_within_limit_is_allowed():
    sdk = _make_sdk(max_delegation_depth=2)
    root, child, _grandchild = _build_lineage(sdk)

    # Depth 1 (root) and depth 2 (direct delegate) are at or below the
    # ceiling and authorize normally.
    assert sdk.authorize(
        capability=root,
        action=ACTION,
        request=REQUEST,
    ).allowed is True

    assert sdk.authorize(
        capability=child,
        action=ACTION,
        request=REQUEST,
    ).allowed is True


def test_depth_equal_to_limit_is_allowed():
    # Boundary: the ceiling is inclusive. depth == max_delegation_depth
    # must be allowed; only strictly deeper chains are denied.
    sdk = _make_sdk(max_delegation_depth=3)
    _root, _child, grandchild = _build_lineage(sdk)

    result = sdk.authorize(
        capability=grandchild,
        action=ACTION,
        request=REQUEST,
    )

    assert result.allowed is True
    assert result.reason == "authorized"


def test_depth_one_over_limit_is_denied():
    sdk = _make_sdk(max_delegation_depth=1)
    root, child, _grandchild = _build_lineage(sdk)

    # Root (depth 1) is allowed; its direct delegate (depth 2) is one
    # over the ceiling and denied.
    assert sdk.authorize(
        capability=root,
        action=ACTION,
        request=REQUEST,
    ).allowed is True

    denied = sdk.authorize(
        capability=child,
        action=ACTION,
        request=REQUEST,
    )

    assert denied.allowed is False
    assert denied.reason == "delegation_depth_exceeded"


# ------------------------------------------------------------------
# Equivalence: authorize() and authorize_north_star() agree under policy.
# ------------------------------------------------------------------


def _comparable(decision):
    # capability_id is a key-derived fingerprint that legitimately differs
    # across independently keyed SDKs; every other field is key-independent
    # and must match. Mirrors test_v1_6_north_star_equivalence.
    return (
        decision.allowed,
        decision.reason,
        decision.agent,
        decision.action,
        decision.tool,
    )


def test_north_star_agrees_on_depth_denial():
    # Fresh SDK per path: the denial records lifecycle/risk side effects,
    # so the two paths must not share one SDK.
    direct_sdk = _make_sdk(max_delegation_depth=2)
    _r1, _c1, grandchild_direct = _build_lineage(direct_sdk)
    direct = direct_sdk.authorize(
        capability=grandchild_direct,
        action=ACTION,
        request=REQUEST,
    ).decision

    ns_sdk = _make_sdk(max_delegation_depth=2)
    _r2, _c2, grandchild_ns = _build_lineage(ns_sdk)
    north_star = ns_sdk.authorize_north_star(
        grandchild_ns,
        ACTION,
        REQUEST,
    )

    assert direct.allowed is False
    assert direct.reason == "delegation_depth_exceeded"
    assert _comparable(north_star) == _comparable(direct)


def test_north_star_agrees_on_within_limit_allow():
    # The within-limit allow has no denial side effect, so both paths can
    # run on one SDK and must agree, including the reason.
    sdk = _make_sdk(max_delegation_depth=3)
    _root, _child, grandchild = _build_lineage(sdk)

    north_star = sdk.authorize_north_star(
        grandchild,
        ACTION,
        REQUEST,
    )
    direct = sdk.authorize(
        capability=grandchild,
        action=ACTION,
        request=REQUEST,
    ).decision

    assert _comparable(north_star) == _comparable(direct)
    assert north_star.allowed is True
    assert north_star.reason == "authorized"


# ------------------------------------------------------------------
# Constructor validation (mirrors the generic North Star phase).
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        True,
        False,
        "2",
        2.0,
    ],
)
def test_rejects_non_integer_limit(bad):
    with pytest.raises(TypeError):
        FirewallSDK(max_delegation_depth=bad)


@pytest.mark.parametrize(
    "bad",
    [
        0,
        -1,
    ],
)
def test_rejects_non_positive_limit(bad):
    with pytest.raises(ValueError):
        FirewallSDK(max_delegation_depth=bad)
