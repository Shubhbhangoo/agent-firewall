from __future__ import annotations

from firewall.capability import (
    Capability,
    sign_capability,
)
from firewall.delegation import _constraints_are_narrower


def _constraints_attenuated(
    parent: dict,
    child: dict,
) -> bool:
    """Is ``child`` at most as permissive as ``parent``?

    Delegates to :func:`firewall.delegation._constraints_are_narrower`,
    which is the same predicate ``delegate`` enforces and the same one
    ``firewall.continuous_auth.predicates`` reuses, so all three agree
    with ``firewall.authorization._check_constraints`` -- the boundary
    that actually admits or refuses a request.

    This function previously had its own numeric rule, ``child <=
    parent``, applied to every number regardless of the key's suffix.
    That was a second, weaker definition of "narrower" and it disagreed
    with the boundary in three ways:

    * **A lowered ``_min`` floor is a widening.** ``amount_min: 100 ->
      1`` admits a superset of requests. ``delegate`` refused it and
      ``attenuate`` accepted it.
    * **A bare numeric must be equal.** ``_check_constraints`` compares
      an unsuffixed numeric for equality, so ``amount: 100 -> 50`` is
      not a narrowing but a different grant, one that no longer admits
      what the parent admitted.
    * **``True -> False`` passed.** ``bool`` is a subclass of ``int``,
      so the numeric branch fired first and ``False <= True`` held. A
      scalar constraint is compared for equality at the boundary, so the
      child admitted ``False`` where the parent admitted only ``True``.

    In all three cases the boundary denied the resulting child --
    ``_gate_delegation_monotonicity`` uses the correct predicate, so the
    system failed closed -- but ``can_attenuate`` returned ``True`` for a
    widening, ``attenuate`` minted capabilities that could never be
    used, and a single legitimate call drove live state into a VIOLATED
    CAPABILITY_MONOTONICITY. One name must not carry two definitions.
    """

    return _constraints_are_narrower(
        parent,
        child,
    )


def can_attenuate(
    parent: Capability,
    child: Capability,
) -> bool:
    if not isinstance(parent, Capability):
        return False

    if not isinstance(child, Capability):
        return False

    if child.agent_id != parent.agent_id:
        return False

    if child.issuer != parent.issuer:
        return False

    if child.public_key != parent.public_key:
        return False

    if child.capability != parent.capability:
        return False

    if child.tool != parent.tool:
        return False

    if child.issued_at < parent.issued_at:
        return False

    if child.expires_at > parent.expires_at:
        return False

    if not _constraints_attenuated(
        parent.constraints,
        child.constraints,
    ):
        return False

    return True


def attenuate_capability(
    parent: Capability,
    private_key,
    constraints: dict | None = None,
    expires_at: float | None = None,
) -> Capability:
    if not isinstance(
        parent,
        Capability,
    ):
        raise TypeError(
            "parent must be a Capability"
        )

    if constraints is None:
        constraints = dict(
            parent.constraints
        )

    if expires_at is None:
        expires_at = parent.expires_at

    child = sign_capability(
        private_key,
        agent_id=parent.agent_id,
        capability=parent.capability,
        constraints=constraints,
        issuer=parent.issuer,
        issued_at=parent.issued_at,
        expires_at=expires_at,
        tool=parent.tool,
    )

    if not can_attenuate(
        parent,
        child,
    ):
        raise ValueError(
            "Child capability is not a valid attenuation"
        )

    return child