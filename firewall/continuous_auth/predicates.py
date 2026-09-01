"""v2.2 Authority Monotonicity Predicates.

Formal, structural predicates that enforce:
- delegation cannot increase authority
- attenuation cannot increase authority
- revocation cannot increase authority
- recovery cannot silently restore broader authority
- policy transformation cannot silently widen authority

These are reusable security predicates for use across the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from firewall.capability import Capability, capability_fingerprint
from firewall.capability2 import Capability2
from firewall.delegation import Delegation
from firewall.delegation_lineage import DelegationLineage
from firewall.revocation import RevocationRegistry


@dataclass(frozen=True)
class MonotonicityResult:
    """Result of a monotonicity check."""

    monotonic: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.monotonic


def is_narrower_than(parent: Any, child: Any) -> MonotonicityResult:
    """
    Structural check: is `child` at most as powerful as `parent`?

    This is the core monotonicity predicate. It works for:
    - firewall.capability.Capability (v1 constraints)
    - firewall.capability2.Capability2 (v2.1 composable constraints)
    - firewall.delegation.Delegation
    - firewall.task.Task

    Returns a MonotonicityResult with details.
    """
    # Handle Capability2 (v2.1)
    if isinstance(parent, Capability2) and isinstance(child, Capability2):
        return _is_capability2_narrower(parent, child)

    # Handle v1 Capability
    if isinstance(parent, Capability) and isinstance(child, Capability):
        return _is_capability_narrower(parent, child)

    # Handle Delegation
    if isinstance(parent, Delegation) and isinstance(child, Delegation):
        return _is_delegation_narrower(parent, child)

    # Task-like objects (permission maps). Both sides must be the same type,
    # so that an unrelated object that happens to expose `permissions` cannot
    # be compared against a real Task and reported monotonic.
    if (
        type(parent) is type(child)
        and hasattr(parent, "permissions")
        and hasattr(child, "permissions")
    ):
        return _is_task_narrower(parent, child)

    return MonotonicityResult(
        monotonic=False,
        reason=f"unsupported types for monotonicity check: {type(parent).__name__} -> {type(child).__name__}",
    )


def _is_capability2_narrower(parent: Capability2, child: Capability2) -> MonotonicityResult:
    """Check Capability2 narrowing using structural comparison.

    ``Capability2.is_narrower_than`` is the authority on the answer. The
    loops below exist only to localise *which* namespace widened, so that
    the denial reason is actionable. If they cannot localise it we still
    deny: a structural check that cannot explain itself must not be
    allowed to overturn the authoritative verdict.
    """
    if child.is_narrower_than(parent):
        return MonotonicityResult(
            monotonic=True,
            reason="child is structurally narrower than or equal to parent",
        )

    for namespace in child.constraints:
        if namespace not in parent.constraints:
            return MonotonicityResult(
                monotonic=False,
                reason=f"child constrains namespace '{namespace}' that parent does not",
                details={"namespace": namespace, "child_value": child.constraints[namespace]},
            )
        if not _capability2_namespace_narrower(
            parent.constraints[namespace], child.constraints[namespace], namespace
        ):
            return MonotonicityResult(
                monotonic=False,
                reason=f"child widens namespace '{namespace}'",
                details={
                    "namespace": namespace,
                    "parent_value": parent.constraints[namespace],
                    "child_value": child.constraints[namespace],
                },
            )

    for namespace in parent.constraints:
        if namespace not in child.constraints:
            return MonotonicityResult(
                monotonic=False,
                reason=f"child drops namespace '{namespace}' that parent constrains (widening)",
                details={"namespace": namespace, "parent_value": parent.constraints[namespace]},
            )

    # Fail closed. is_narrower_than() said no; we could not attribute it to
    # a specific namespace, which means the two disagree and the state is
    # not understood. Deny rather than guess.
    return MonotonicityResult(
        monotonic=False,
        reason=(
            "child is not narrower than parent, but the widening could not be "
            "attributed to a namespace (denying: unlocalised widening)"
        ),
        details={
            "parent_constraints": dict(parent.constraints),
            "child_constraints": dict(child.constraints),
        },
    )


def _capability2_namespace_narrower(parent_val: Any, child_val: Any, namespace: str) -> bool:
    """Check if child_val is narrower than parent_val for a specific namespace."""
    from firewall.capability2.constraints import _narrower_or_equal
    return _narrower_or_equal(child_val, parent_val, namespace)


def _is_capability_narrower(parent: Capability, child: Capability) -> MonotonicityResult:
    """Check v1 Capability narrowing using _constraints_are_narrower.

    This mirrors the structural half of :meth:`Delegation.is_valid` so that
    the two cannot drift apart. It deliberately does *not* require the agent
    to differ: ``child <= parent`` is the invariant, and equal authority
    satisfies it. "Delegatee must differ from delegator" is a delegation
    *validity* rule enforced by ``delegate_capability``, not a monotonicity
    rule, and asserting it here would deny an unchanged capability compared
    against itself.
    """
    from firewall.delegation import _constraints_are_narrower

    if child.capability != parent.capability:
        return MonotonicityResult(
            monotonic=False,
            reason=f"capability name changed: {parent.capability} -> {child.capability}",
        )

    if child.issuer != parent.issuer:
        return MonotonicityResult(
            monotonic=False,
            reason=f"issuer changed: {parent.issuer} -> {child.issuer}",
        )

    if child.public_key != parent.public_key:
        return MonotonicityResult(
            monotonic=False,
            reason="signing key changed across delegation",
        )

    if child.tool != parent.tool:
        return MonotonicityResult(
            monotonic=False,
            reason=f"tool binding changed: {parent.tool} -> {child.tool}",
        )

    if child.issued_at < parent.issued_at:
        return MonotonicityResult(
            monotonic=False,
            reason="child issued before parent",
        )

    if child.expires_at > parent.expires_at:
        return MonotonicityResult(
            monotonic=False,
            reason="child expires after parent",
        )

    if not _constraints_are_narrower(parent.constraints, child.constraints):
        return MonotonicityResult(
            monotonic=False,
            reason="child constraints are not narrower than parent",
            details={
                "parent_constraints": dict(parent.constraints),
                "child_constraints": dict(child.constraints),
            },
        )

    return MonotonicityResult(
        monotonic=True,
        reason="v1 capability child is narrower than or equal to parent",
    )


def _is_delegation_narrower(parent: Delegation, child: Delegation) -> MonotonicityResult:
    """Check delegation narrowing."""
    # Parent delegation's child becomes the parent for the next delegation
    return _is_capability_narrower(parent.child, child.child)


def _is_task_narrower(parent: Any, child: Any) -> MonotonicityResult:
    """Check task narrowing (permissions intersection)."""
    parent_perms = getattr(parent, "permissions", {}) or {}
    child_perms = getattr(child, "permissions", {}) or {}

    # Child permissions must be subset of parent permissions
    for action, allowed in child_perms.items():
        parent_allowed = parent_perms.get(action)
        if parent_allowed is None:
            return MonotonicityResult(
                monotonic=False,
                reason=f"child has permission '{action}' not in parent",
                details={"action": action},
            )
        if isinstance(allowed, list) and isinstance(parent_allowed, list):
            if not set(allowed).issubset(set(parent_allowed)):
                return MonotonicityResult(
                    monotonic=False,
                    reason=f"child permission '{action}' widens parent",
                    details={"action": action, "parent": parent_allowed, "child": allowed},
                )
        elif allowed != parent_allowed:
            return MonotonicityResult(
                monotonic=False,
                reason=f"child permission '{action}' differs from parent",
                details={"action": action, "parent": parent_allowed, "child": allowed},
            )

    return MonotonicityResult(
        monotonic=True,
        reason="task child permissions are subset of parent",
    )


def authority_monotonicity_check(
    *,
    original_capability: Capability,
    derived_capability: Capability,
    delegation_lineage: DelegationLineage,
    revocation_registry: RevocationRegistry,
) -> MonotonicityResult:
    """
    Comprehensive authority monotonicity check.

    Verifies that a derived capability does not exceed the authority of
    its ancestor chain, considering:
    1. Structural narrowing (constraints)
    2. Delegation lineage validity (no cycles, no missing ancestors)
    3. Revocation status (no revoked ancestors)
    4. Expiration (child not expiring after parent)
    """
    # 1. Structural narrowing
    structural = is_narrower_than(original_capability, derived_capability)
    if not structural:
        return MonotonicityResult(
            monotonic=False,
            reason=f"structural widening: {structural.reason}",
            details=structural.details,
        )

    # 2. Delegation lineage validity
    original_fp = capability_fingerprint(original_capability)
    derived_fp = capability_fingerprint(derived_capability)

    try:
        chain = delegation_lineage.chain(derived_fp)
    except Exception as e:
        return MonotonicityResult(
            monotonic=False,
            reason=f"delegation lineage invalid: {e}",
        )

    if original_fp not in chain:
        return MonotonicityResult(
            monotonic=False,
            reason="original capability not in derived capability's delegation chain",
        )

    # 3. Revocation check - no ancestor should be revoked
    for ancestor_fp in chain:
        if revocation_registry.is_revoked(ancestor_fp):
            return MonotonicityResult(
                monotonic=False,
                reason=f"ancestor capability revoked: {ancestor_fp}",
                details={"revoked_ancestor": ancestor_fp},
            )

    # Also check original capability itself
    if revocation_registry.is_revoked(original_fp):
        return MonotonicityResult(
            monotonic=False,
            reason="original capability revoked",
        )

    # 4. Expiration check
    if derived_capability.expires_at > original_capability.expires_at:
        return MonotonicityResult(
            monotonic=False,
            reason="derived capability expires after original",
            details={
                "original_expires": original_capability.expires_at,
                "derived_expires": derived_capability.expires_at,
            },
        )

    return MonotonicityResult(
        monotonic=True,
        reason="authority monotonicity verified: structural narrowing + valid lineage + no revocation + valid expiration",
    )


def delegation_monotonicity_check(
    *,
    parent_delegation: Delegation,
    child_delegation: Delegation,
    delegation_lineage: DelegationLineage,
    revocation_registry: RevocationRegistry,
) -> MonotonicityResult:
    """Check that a delegation chain maintains monotonic narrowing."""
    # The child delegation's parent capability is the parent delegation's child
    return authority_monotonicity_check(
        original_capability=parent_delegation.parent,
        derived_capability=child_delegation.child,
        delegation_lineage=delegation_lineage,
        revocation_registry=revocation_registry,
    )


def revocation_monotonicity_check(
    *,
    capability: Capability,
    delegation_lineage: DelegationLineage,
    revocation_registry: RevocationRegistry,
    before_revocation: bool,
    after_revocation: bool,
    revoked_fingerprint: str,
) -> MonotonicityResult:
    """
    Check that revocation cannot increase effective authority.

    REVOCATION_MONOTONICITY: revoking a fingerprint must never make any
    capability authorized that was previously denied. Concretely, after the
    revocation both the revoked fingerprint itself and every descendant of
    it must be *effectively* revoked -- descendants inherit revocation by
    walking the lineage, so a descendant that does not resolve as revoked is
    an escalation path and a violation.

    ``before_revocation``/``after_revocation`` are the revocation state of
    ``revoked_fingerprint`` observed either side of the event; this function
    only has work to do on a false -> true transition.
    """
    if before_revocation or not after_revocation:
        return MonotonicityResult(
            monotonic=True,
            reason="revocation state unchanged or not a revocation event",
        )

    if not revocation_registry.is_revoked(revoked_fingerprint):
        return MonotonicityResult(
            monotonic=False,
            reason=(
                "revocation was reported as applied but the registry does not "
                f"report {revoked_fingerprint} as revoked"
            ),
            details={"revoked_fingerprint": revoked_fingerprint},
        )

    try:
        descendants = _get_descendants(delegation_lineage, revoked_fingerprint)
    except Exception as exc:
        # An unwalkable lineage means we cannot show that descendants were
        # contained. Fail closed rather than assert an invariant we did not
        # verify.
        return MonotonicityResult(
            monotonic=False,
            reason=f"could not enumerate descendants of revoked capability: {exc}",
            details={"revoked_fingerprint": revoked_fingerprint},
        )

    unrevoked: list[str] = []
    for descendant in descendants:
        if not _is_effectively_revoked(
            descendant, delegation_lineage, revocation_registry
        ):
            unrevoked.append(descendant)

    if unrevoked:
        return MonotonicityResult(
            monotonic=False,
            reason=(
                "descendants of a revoked capability are still effectively "
                "authorized (revocation did not propagate)"
            ),
            details={
                "revoked_fingerprint": revoked_fingerprint,
                "unrevoked_descendants": unrevoked,
            },
        )

    return MonotonicityResult(
        monotonic=True,
        reason=(
            "revocation maintains monotonicity: revoked capability and all "
            f"{len(descendants)} descendant(s) are effectively revoked"
        ),
        details={"descendant_count": len(descendants)},
    )


def _is_effectively_revoked(
    fingerprint: str,
    lineage: DelegationLineage,
    revocation_registry: RevocationRegistry,
) -> bool:
    """True when the fingerprint or any lineage ancestor is revoked.

    A lineage that cannot be walked (cycle, over-depth) is treated as
    revoked: unknown is not trusted, and refusing to answer must not read as
    "still authorized".
    """
    if revocation_registry.is_revoked(fingerprint):
        return True

    try:
        ancestors = lineage.chain(fingerprint)
    except Exception:
        return True

    return any(revocation_registry.is_revoked(a) for a in ancestors)


def _get_descendants(lineage: DelegationLineage, ancestor_fp: str) -> list[str]:
    """Get all descendants of a capability fingerprint.

    Iterative with an explicit visited set. ``DelegationLineage.register``
    rejects cycles, but this walks a snapshot of persisted state that may
    have been corrupted or restored from an untrusted store, so recursion
    over a cycle must not be able to overflow the stack.
    """
    children: dict[str, list[str]] = {}
    for record in lineage.snapshot():
        children.setdefault(record.parent_fingerprint, []).append(
            record.child_fingerprint
        )

    descendants: list[str] = []
    seen: set[str] = {ancestor_fp}
    frontier = list(children.get(ancestor_fp, ()))

    while frontier:
        current = frontier.pop()
        if current in seen:
            continue
        seen.add(current)
        descendants.append(current)
        frontier.extend(children.get(current, ()))

    return descendants


def recovery_monotonicity_check(
    *,
    original_authority: tuple[dict, ...],
    restored_authority: tuple[dict, ...],
) -> MonotonicityResult:
    """
    Check that recovery cannot silently restore broader authority than
    what was suspended during quarantine.
    """
    original_keys = {_authority_key(a) for a in original_authority}
    restored_keys = {_authority_key(a) for a in restored_authority}

    # Restored must be subset of original
    if not restored_keys.issubset(original_keys):
        extra = restored_keys - original_keys
        return MonotonicityResult(
            monotonic=False,
            reason=f"recovery restored authority not in original suspension: {extra}",
            details={"extra_keys": list(extra)},
        )

    return MonotonicityResult(
        monotonic=True,
        reason="recovery only restored subset of suspended authority",
    )


def policy_transformation_monotonicity_check(
    *,
    old_policy: Capability2,
    new_policy: Capability2,
) -> MonotonicityResult:
    """
    Check that a policy transformation does not silently widen authority.

    The new policy must be narrower than or equal to the old policy.
    """
    return is_narrower_than(old_policy, new_policy)


def _authority_key(authority: dict) -> str:
    """Generate a key for an authority record."""
    import json
    try:
        rendered = json.dumps(authority.get("constraints", {}), sort_keys=True, default=repr)
    except Exception:
        rendered = repr(authority.get("constraints", {}))
    return "\x00".join([
        authority.get("capability", ""),
        authority.get("tool", "") or "",
        authority.get("issuer", "") or "",
        rendered,
    ])