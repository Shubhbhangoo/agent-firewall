"""Demo scenarios for the Agent Firewall console.

Everything in this module is **clearly marked demo data**. It exists so
the console has something real to show when it is not attached to a live
system.

These scenarios are not simulations. Each one builds a genuine
:class:`~firewall.sdk.FirewallSDK`, issues real signed capabilities
through the public API, and then asks the *real* authorization pipeline
for a decision. The console reports whatever the SDK returns.

Each scenario builds its own fresh SDK. That mirrors the discipline the
project's own test-suite uses: ``authorize()`` has security side effects
(lifecycle records, refusal memoization, risk escalation, budget and
replay consumption), so sharing one SDK across scenarios would let an
earlier evaluation change a later one's outcome.

A scenario declares the reason it is *designed* to demonstrate, but that
value is never presented as the outcome. The console compares it with
the reason the SDK actually returned and flags any divergence, so a
scenario that stops being accurate becomes visible instead of silently
misleading.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK


DEMO_ISSUER = "trusted-issuer"
UNTRUSTED_ISSUER = "rogue-issuer"

#: A 64-char hex string that is never a real capability fingerprint, so
#: registering it as an ancestor guarantees an unresolvable lineage.
MISSING_ANCESTOR = "0" * 64


@dataclass
class DemoRequest:
    """One prepared, ready-to-evaluate authorization request."""

    sdk: FirewallSDK
    capability: Optional[Capability]
    action: str
    request: dict[str, Any]
    agents: tuple[str, ...] = ()
    #: Requests replayed through the real pipeline before the observed
    #: one, used by scenarios whose behavior depends on prior state.
    warmup: tuple[tuple[Any, str, dict], ...] = ()
    #: Extra capabilities to show in the inventory panel.
    inventory: tuple[Capability, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    intent: str
    expects: str
    group: str
    builder: Callable[[], DemoRequest] = field(
        repr=False
    )


# ======================================================================
# Workspace helpers
# ======================================================================


def _workspace(
    **kwargs: Any,
) -> FirewallSDK:
    """Create a fresh, fully in-memory demo SDK with one signing key.

    No store paths are passed, so the workspace persists nothing to
    disk. A real ``RiskContext`` is attached so the console shows genuine
    risk state transitions rather than an inert panel. An optional
    ``recorder`` keyword attaches a v1.8 flight recorder so console
    activity is captured after the fact.
    """

    kwargs.setdefault(
        "risk_context",
        RiskContext(),
    )

    sdk = FirewallSDK(**kwargs)
    sdk.generate_key("console-demo-key")
    return sdk


def _issue(
    sdk: FirewallSDK,
    *,
    agent: str = "agent-alpha",
    capability: str = "payments.send",
    constraints: Optional[dict] = None,
    **kwargs: Any,
) -> Capability:
    return sdk.issue(
        agent=agent,
        capability=capability,
        constraints=(
            {"amount_max": 1000}
            if constraints is None
            else constraints
        ),
        **kwargs,
    )


def _delegate(
    sdk: FirewallSDK,
    parent: Capability,
    delegatee: str,
) -> Capability:
    return sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee=delegatee,
    ).child


def _chain(
    sdk: FirewallSDK,
    **issue_kwargs: Any,
) -> tuple[Capability, Capability, Capability]:
    """Return a (root, child, grandchild) lineage: depth 1, 2, 3."""

    root = _issue(sdk, **issue_kwargs)
    child = _delegate(
        sdk,
        root,
        "agent-beta",
    )
    grandchild = _delegate(
        sdk,
        child,
        "agent-gamma",
    )
    return root, child, grandchild


# ======================================================================
# Scenario builders
# ======================================================================


def _build_allow_root() -> DemoRequest:
    sdk = _workspace()
    cap = _issue(sdk)

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 250},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "Directly issued capability, depth 1.",
            "Request satisfies the amount_max constraint.",
        ),
    )


def _build_allow_delegated() -> DemoRequest:
    sdk = _workspace()
    root, child, grandchild = _chain(sdk)

    return DemoRequest(
        sdk=sdk,
        capability=grandchild,
        action="payments.send",
        request={"amount": 250},
        agents=(
            "agent-alpha",
            "agent-beta",
            "agent-gamma",
        ),
        inventory=(root, child, grandchild),
        notes=(
            "Two delegation hops: alpha -> beta -> gamma.",
            "Every ancestor must independently authorize the "
            "same action.",
        ),
    )


def _build_constraint_denied() -> DemoRequest:
    sdk = _workspace()
    cap = _issue(
        sdk,
        constraints={"amount_max": 100},
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 5000},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "Request exceeds the constraint bound to the "
            "capability at signing time.",
        ),
    )


def _build_attenuation_denied() -> DemoRequest:
    sdk = _workspace()
    root = _issue(
        sdk,
        constraints={"amount_max": 1000},
    )
    child = sdk.attenuate(
        root,
        sdk.active_key().private_key,
        constraints={"amount_max": 50},
    )

    return DemoRequest(
        sdk=sdk,
        capability=child,
        action="payments.send",
        request={"amount": 500},
        agents=("agent-alpha",),
        inventory=(root, child),
        notes=(
            "Attenuation narrows authority: the parent allows "
            "1000, the attenuated child only 50.",
            "A request valid for the parent is denied for the child.",
        ),
    )


def _build_tool_binding_denied() -> DemoRequest:
    sdk = _workspace()
    cap = _issue(
        sdk,
        capability="payments",
        tool="payments.send",
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.refund",
        request={"amount": 10},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "The capability is cryptographically bound to the "
            "tool 'payments.send'.",
            "A different action cannot reuse it, even inside the "
            "same namespace.",
        ),
    )


def _build_revoked() -> DemoRequest:
    sdk = _workspace()
    cap = _issue(sdk)
    sdk.revoke(
        cap,
        reason="credential compromise",
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 250},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "The capability itself is revoked.",
        ),
    )


def _build_revoked_ancestor() -> DemoRequest:
    sdk = _workspace()
    root, child, grandchild = _chain(sdk)
    sdk.revoke(
        root,
        reason="root authority compromised",
    )

    return DemoRequest(
        sdk=sdk,
        capability=grandchild,
        action="payments.send",
        request={"amount": 250},
        agents=(
            "agent-alpha",
            "agent-beta",
            "agent-gamma",
        ),
        inventory=(root, child, grandchild),
        notes=(
            "Only the root was revoked; the grandchild was not "
            "touched.",
            "Revocation is transitive down the lineage.",
        ),
    )


def _build_untrusted_issuer() -> DemoRequest:
    sdk = _workspace()
    sdk.trust_issuer(UNTRUSTED_ISSUER)
    cap = _issue(
        sdk,
        issuer=UNTRUSTED_ISSUER,
    )
    sdk.revoke_issuer(UNTRUSTED_ISSUER)

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 250},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "The capability was validly issued, then the issuer "
            "lost trust.",
            "Trust is evaluated at authorization time, not at "
            "issue time.",
        ),
    )


def _build_expired() -> DemoRequest:
    sdk = _workspace()
    now = time.time()
    cap = _issue(
        sdk,
        issued_at=now - 7200,
        expires_at=now - 3600,
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 250},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "Validity window closed one hour ago.",
        ),
    )


def _build_not_yet_valid() -> DemoRequest:
    sdk = _workspace()
    now = time.time()
    cap = _issue(
        sdk,
        issued_at=now + 3600,
        expires_at=now + 7200,
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 250},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "Validity window opens in one hour.",
        ),
    )


def _build_depth_exceeded() -> DemoRequest:
    sdk = _workspace(max_delegation_depth=2)
    root, child, grandchild = _chain(sdk)

    return DemoRequest(
        sdk=sdk,
        capability=grandchild,
        action="payments.send",
        request={"amount": 250},
        agents=(
            "agent-alpha",
            "agent-beta",
            "agent-gamma",
        ),
        inventory=(root, child, grandchild),
        notes=(
            "This workspace is configured with "
            "max_delegation_depth=2.",
            "The grandchild resolves to depth 3 and is refused "
            "before any signature work.",
        ),
    )


def _build_broken_chain() -> DemoRequest:
    sdk = _workspace()
    cap = _issue(sdk)
    sdk.delegation_lineage.register(
        child_fingerprint=sdk.fingerprint(cap),
        parent_fingerprint=MISSING_ANCESTOR,
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 250},
        agents=("agent-alpha",),
        inventory=(cap,),
        notes=(
            "The lineage references an ancestor that cannot be "
            "resolved.",
            "Unresolvable authority fails closed rather than "
            "falling back to the child's own rights.",
        ),
    )


def _build_refusal_state() -> DemoRequest:
    sdk = _workspace()
    cap = _issue(
        sdk,
        constraints={"amount_max": 100},
    )
    denied = (
        cap,
        "payments.send",
        {"amount": 5000},
    )

    return DemoRequest(
        sdk=sdk,
        capability=cap,
        action="payments.send",
        request={"amount": 5000},
        agents=("agent-alpha",),
        inventory=(cap,),
        warmup=(denied,),
        notes=(
            "The identical request was already denied once.",
            "The refusal is memoized, so it short-circuits at the "
            "first gate instead of re-running verification.",
        ),
    )


def _build_invalid_capability() -> DemoRequest:
    sdk = _workspace()

    return DemoRequest(
        sdk=sdk,
        capability=None,
        action="payments.send",
        request={"amount": 250},
        notes=(
            "No capability was presented at all.",
        ),
    )


# ======================================================================
# Registry
# ======================================================================

SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="allow_root",
        title="Direct capability",
        intent="A validly issued capability used within its constraints.",
        expects="authorized",
        group="allow",
        builder=_build_allow_root,
    ),
    Scenario(
        id="allow_delegated",
        title="Delegated chain",
        intent="Depth-3 lineage where every ancestor also authorizes.",
        expects="authorized",
        group="allow",
        builder=_build_allow_delegated,
    ),
    Scenario(
        id="constraint_denied",
        title="Constraint exceeded",
        intent="Request violates a constraint signed into the capability.",
        expects="constraint_denied",
        group="deny",
        builder=_build_constraint_denied,
    ),
    Scenario(
        id="attenuation_denied",
        title="Attenuated authority",
        intent="Narrowed child rejects what its parent would allow.",
        expects="constraint_denied",
        group="deny",
        builder=_build_attenuation_denied,
    ),
    Scenario(
        id="tool_binding_denied",
        title="Tool binding",
        intent="Tool-bound capability reused for a different action.",
        expects="tool_binding_denied",
        group="deny",
        builder=_build_tool_binding_denied,
    ),
    Scenario(
        id="revoked",
        title="Revoked capability",
        intent="Capability revoked after issue.",
        expects="capability_revoked",
        group="deny",
        builder=_build_revoked,
    ),
    Scenario(
        id="revoked_ancestor",
        title="Transitive revocation",
        intent="Revoking the root invalidates the whole lineage.",
        expects="capability_revoked",
        group="deny",
        builder=_build_revoked_ancestor,
    ),
    Scenario(
        id="untrusted_issuer",
        title="Issuer trust withdrawn",
        intent="Issuer trust revoked after the capability was signed.",
        expects="untrusted_issuer",
        group="deny",
        builder=_build_untrusted_issuer,
    ),
    Scenario(
        id="expired",
        title="Expired capability",
        intent="Validity window has closed.",
        expects="expired",
        group="deny",
        builder=_build_expired,
    ),
    Scenario(
        id="not_yet_valid",
        title="Not yet valid",
        intent="Validity window has not opened.",
        expects="not_yet_valid",
        group="deny",
        builder=_build_not_yet_valid,
    ),
    Scenario(
        id="depth_exceeded",
        title="Depth policy",
        intent="Lineage deeper than the configured ceiling.",
        expects="delegation_depth_exceeded",
        group="deny",
        builder=_build_depth_exceeded,
    ),
    Scenario(
        id="broken_chain",
        title="Unresolvable lineage",
        intent="A delegation ancestor is missing from the registry.",
        expects="delegation_chain_error",
        group="deny",
        builder=_build_broken_chain,
    ),
    Scenario(
        id="refusal_state",
        title="Memoized refusal",
        intent="A repeat of an already-denied request.",
        expects="refusal_state",
        group="deny",
        builder=_build_refusal_state,
    ),
    Scenario(
        id="invalid_capability",
        title="No capability",
        intent="Request presented without any capability.",
        expects="invalid_capability",
        group="deny",
        builder=_build_invalid_capability,
    ),
)


SCENARIOS_BY_ID: dict[str, Scenario] = {
    scenario.id: scenario
    for scenario in SCENARIOS
}


def scenario_catalog() -> list[dict[str, Any]]:
    """Project the scenario registry for the console."""

    return [
        {
            "id": scenario.id,
            "title": scenario.title,
            "intent": scenario.intent,
            "expects": scenario.expects,
            "group": scenario.group,
        }
        for scenario in SCENARIOS
    ]
