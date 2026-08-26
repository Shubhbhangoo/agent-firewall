"""v1.6 North Star equivalence.

authorize_north_star() must produce exactly the same canonical
SecurityDecision as the authoritative authorize() path. North Star owns
the ordering and control flow, but authorize() remains the single
authority for the decision itself, so the two paths must agree on the
allow/deny outcome, the reason (including precedence between competing
denials), and the decision's identifying fields.

Each scenario is built on a *fresh* SDK for each path, because authorize()
has security side effects (lifecycle, refusal, risk/security denial
recording, budget/replay consumption). Running both paths against the same
SDK would let the first call's side effects change the second call's
result, which would make the comparison meaningless.
"""

from __future__ import annotations

from firewall.sdk import FirewallSDK


TRUSTED_ISSUER = "trusted-issuer"
UNTRUSTED_ISSUER = "attacker-issuer"

# A 64-char hex string that is never the fingerprint of any issued
# capability, so registering it as an ancestor guarantees a missing
# ancestor when the chain is resolved.
MISSING_ANCESTOR = "0" * 64


def _comparable(decision):
    # capability_id is a signature-derived fingerprint. Two independently
    # keyed SDKs sign the same logical capability with different keys, so
    # the fingerprint legitimately differs across fresh SDKs. Every other
    # field is key-independent and must match. Full-tuple equality
    # (including capability_id) is asserted separately on a single SDK.
    return (
        decision.allowed,
        decision.reason,
        decision.agent,
        decision.action,
        decision.tool,
    )


def _full_tuple(decision):
    return (
        decision.allowed,
        decision.reason,
        decision.capability_id,
        decision.agent,
        decision.action,
        decision.tool,
    )


# ------------------------------------------------------------------
# Scenario builders. Each returns (sdk, capability, action, request)
# on a freshly constructed SDK.
# ------------------------------------------------------------------


def _build_allow():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )
    return sdk, cap, "payments.send", {"amount": 1}


def _build_invalid_capability():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    return sdk, None, "payments.send", {"amount": 1}


def _build_revoked():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )
    sdk.revoke(cap, reason="compromised")
    return sdk, cap, "payments.send", {"amount": 1}


def _build_untrusted_issuer():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    # Issue under the trusted issuer, then revoke trust so the same
    # capability is now presented by an untrusted issuer.
    sdk.trust_issuer(UNTRUSTED_ISSUER)
    cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        issuer=UNTRUSTED_ISSUER,
    )
    sdk.revoke_issuer(UNTRUSTED_ISSUER)
    return sdk, cap, "payments.send", {"amount": 1}


def _build_constraint_denied():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    return sdk, cap, "payments.send", {"amount": 500}


def _build_broken_chain():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )
    # Register a parent that was never issued: the lineage knows the
    # ancestor fingerprint but the capability registry does not hold it,
    # so chain resolution fails closed with delegation_chain_error.
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(cap),
        parent_fingerprint=MISSING_ANCESTOR,
    )
    return sdk, cap, "payments.send", {"amount": 1}


def _build_revoked_and_broken_chain():
    # Precedence case: revocation (checked before chain resolution in
    # authorize()) must win over the broken chain. The pre-fix North Star
    # delegation gate would have surfaced delegation_chain_error first.
    sdk = FirewallSDK()
    sdk.generate_key("k")
    cap = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(cap),
        parent_fingerprint=MISSING_ANCESTOR,
    )
    sdk.revoke(cap, reason="compromised")
    return sdk, cap, "payments.send", {"amount": 1}


SCENARIOS = {
    "allow": (_build_allow, True, "authorized"),
    "invalid_capability": (
        _build_invalid_capability,
        False,
        "invalid_capability",
    ),
    "revoked": (_build_revoked, False, "capability_revoked"),
    "untrusted_issuer": (
        _build_untrusted_issuer,
        False,
        "untrusted_issuer",
    ),
    "constraint_denied": (
        _build_constraint_denied,
        False,
        "constraint_denied",
    ),
    "broken_chain": (
        _build_broken_chain,
        False,
        "delegation_chain_error: "
        "delegation ancestor capability is unavailable",
    ),
    "revoked_and_broken_chain": (
        _build_revoked_and_broken_chain,
        False,
        "capability_revoked",
    ),
}


def _run_direct(builder):
    sdk, cap, action, request = builder()
    return sdk.authorize(action=action, capability=cap, request=request).decision


def _run_north_star(builder):
    sdk, cap, action, request = builder()
    return sdk.authorize_north_star(cap, action, request)


def test_north_star_matches_direct_authorize():
    for name, (builder, expected_allowed, expected_reason) in SCENARIOS.items():
        direct = _run_direct(builder)
        north_star = _run_north_star(builder)

        # The direct path is the authority; confirm it produces the reason
        # we expect so a silent change to authorize() is also caught.
        assert direct.allowed is expected_allowed, (
            name,
            direct.reason,
        )
        assert direct.reason == expected_reason, (
            name,
            direct.reason,
        )

        # North Star must produce the identical canonical decision
        # (aside from the key-derived fingerprint; see _comparable).
        assert _comparable(north_star) == _comparable(direct), name


def test_north_star_full_decision_matches_direct_on_same_sdk():
    # The allow path has no denial/refusal side effect that would change a
    # subsequent decision on the same SDK, so both paths can be compared on
    # one SDK to prove full-tuple equality, including the capability_id.
    sdk, cap, action, request = _build_allow()

    north_star = sdk.authorize_north_star(cap, action, request)
    direct = sdk.authorize(cap, action, request).decision

    assert _full_tuple(north_star) == _full_tuple(direct)
    assert north_star.capability_id == sdk.fingerprint(cap)


def test_north_star_publishes_delegation_authority_without_gating():
    # A broken chain must not be pre-empted by the observational delegation
    # phase; the authoritative reason must come from authorize().
    decision = _run_north_star(_build_broken_chain)

    assert decision.allowed is False
    assert decision.reason == (
        "delegation_chain_error: "
        "delegation ancestor capability is unavailable"
    )


def test_north_star_allow_carries_capability_identity():
    sdk, cap, action, request = _build_allow()
    decision = sdk.authorize_north_star(cap, action, request)

    assert decision.allowed is True
    assert decision.reason == "authorized"
    assert decision.capability_id == sdk.fingerprint(cap)
    assert decision.agent == "agent-a"
    assert decision.action == "payments.send"
