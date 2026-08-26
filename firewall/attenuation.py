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
    if parent == child:
        return True

    if isinstance(parent, (int, float)) and isinstance(
        child, (int, float)
    ):
        return child <= parent

    if isinstance(parent, str):
        return parent == child

    if isinstance(parent, bool):
        return parent == child

    if isinstance(
        parent,
        (list, tuple, set, frozenset),
    ):
        try:
            return set(child).issubset(
                set(parent)
            )
        except TypeError:
            return False

    return False


def _constraints_attenuated(
    parent: dict,
    child: dict,
) -> bool:
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

    return True


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