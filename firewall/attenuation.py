from __future__ import annotations

from typing import Any

from firewall.capability import (
    Capability,
    sign_capability,
)


def _constraint_is_narrower(
    parent: Any,
    child: Any,
) -> bool:
    """
    Return True when the child constraint does not
    grant more authority than the parent constraint.
    """

    if parent == child:
        return True

    # Numeric maximums can only decrease.
    if isinstance(parent, (int, float)) and isinstance(
        child, (int, float)
    ):
        return child <= parent

    # Numeric minimums can only increase.
    if isinstance(parent, (int, float)) and isinstance(
        child, (int, float)
    ):
        return child >= parent

    # Strings and booleans represent exact restrictions.
    # They cannot be changed during attenuation.
    if isinstance(parent, (str, bool)):
        return parent == child

    # Lists/sets can only become smaller.
    if isinstance(parent, (list, tuple, set, frozenset)):
        try:
            return set(child).issubset(set(parent))
        except TypeError:
            return False

    return False


def _constraints_attenuated(
    parent: dict,
    child: dict,
) -> bool:
    """
    Every child constraint must preserve or reduce
    the authority granted by the parent.

    Removing a parent constraint is NOT attenuation,
    because the missing constraint could grant more authority.
    """

    for key, parent_value in parent.items():

        if key not in child:
            return False

        child_value = child[key]

        if isinstance(
            parent_value,
            dict,
        ):

            if not isinstance(
                child_value,
                dict,
            ):
                return False

            if not _constraints_attenuated(
                parent_value,
                child_value,
            ):
                return False

        else:

            if not _constraint_is_narrower(
                parent_value,
                child_value,
            ):
                return False

    # New child constraints are allowed.
    # They only restrict the capability further.
    return True


def can_attenuate(
    parent: Capability,
    child: Capability,
) -> bool:
    """
    Check whether child is no more powerful than parent.
    """

    if not isinstance(parent, Capability):
        return False

    if not isinstance(child, Capability):
        return False

    # The capability must belong to the same agent.
    if child.agent_id != parent.agent_id:
        return False

    # Issuer cannot change.
    if child.issuer != parent.issuer:
        return False

    # Child must use the same public signing key.
    if child.public_key != parent.public_key:
        return False

    # Capability scope cannot be broadened.
    if child.capability != parent.capability:
        return False

    # Child cannot become valid before parent.
    if child.issued_at < parent.issued_at:
        return False

    # Child cannot live longer than parent.
    if child.expires_at > parent.expires_at:
        return False

    # Constraints must remain equal or narrower.
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
    """
    Create a narrower capability from a parent capability.

    The child is signed by the same private key and can
    never have greater authority than the parent.
    """

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
    )

    if not can_attenuate(
        parent,
        child,
    ):
        raise ValueError(
            "Child capability is not a valid attenuation"
        )

    return child