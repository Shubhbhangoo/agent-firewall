from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from firewall.capability import Capability, sign_capability


def _constraints_are_narrower(
    parent: dict,
    child: dict,
) -> bool:
    for key, parent_value in parent.items():
        if key not in child:
            return False

        child_value = child[key]

        if isinstance(parent_value, dict):
            if not isinstance(child_value, dict):
                return False

            if not _constraints_are_narrower(
                parent_value,
                child_value,
            ):
                return False

            continue

        if isinstance(parent_value, (int, float)):
            if not isinstance(child_value, (int, float)):
                return False

            if key.endswith("_max"):
                if child_value > parent_value:
                    return False
            elif key.endswith("_min"):
                if child_value < parent_value:
                    return False
            elif child_value != parent_value:
                return False

            continue

        if isinstance(
            parent_value,
            (list, tuple, set, frozenset),
        ):
            try:
                if not set(child_value).issubset(
                    set(parent_value)
                ):
                    return False
            except (TypeError, ValueError):
                return False

            continue

        if child_value != parent_value:
            return False

    return True


@dataclass(frozen=True)
class Delegation:
    parent: Capability
    child: Capability
    delegator: str
    delegatee: str

    def is_valid(self) -> bool:
        if not isinstance(
            self.parent,
            Capability,
        ):
            return False

        if not isinstance(
            self.child,
            Capability,
        ):
            return False

        if not self.delegator:
            return False

        if not self.delegatee:
            return False

        if self.parent.agent_id != self.delegator:
            return False

        if self.child.agent_id != self.delegatee:
            return False

        if self.child.agent_id == self.parent.agent_id:
            return False

        if self.child.issuer != self.parent.issuer:
            return False

        if self.child.public_key != self.parent.public_key:
            return False

        if self.child.capability != self.parent.capability:
            return False

        if self.child.issued_at < self.parent.issued_at:
            return False

        if self.child.expires_at > self.parent.expires_at:
            return False

        if not _constraints_are_narrower(
            self.parent.constraints,
            self.child.constraints,
        ):
            return False

        return True


def delegate_capability(
    parent: Capability,
    private_key,
    delegatee: str,
    constraints: Optional[dict] = None,
    expires_at: Optional[float] = None,
) -> Delegation:

    if not isinstance(
        parent,
        Capability,
    ):
        raise TypeError(
            "parent must be a Capability"
        )

    if not delegatee:
        raise ValueError(
            "delegatee must be a non-empty string"
        )

    if delegatee == parent.agent_id:
        raise ValueError(
            "delegatee must differ from parent agent"
        )

    if constraints is None:
        constraints = dict(parent.constraints)

    if not isinstance(
        constraints,
        dict,
    ):
        raise TypeError(
            "constraints must be a dictionary"
        )

    if expires_at is None:
        expires_at = parent.expires_at

    if expires_at > parent.expires_at:
        raise ValueError(
            "delegation cannot extend expiration"
        )

    if not _constraints_are_narrower(
        parent.constraints,
        constraints,
    ):
        raise ValueError(
            "delegation cannot broaden constraints"
        )

    child = sign_capability(
        private_key,
        agent_id=delegatee,
        capability=parent.capability,
        constraints=dict(constraints),
        issuer=parent.issuer,
        issued_at=parent.issued_at,
        expires_at=expires_at,
    )

    delegation = Delegation(
        parent=parent,
        child=child,
        delegator=parent.agent_id,
        delegatee=delegatee,
    )

    if not delegation.is_valid():
        raise ValueError(
            "invalid delegation"
        )

    return delegation


def verify_delegation(
    delegation: Delegation,
    verifier,
    clock=None,
) -> bool:

    if not isinstance(
        delegation,
        Delegation,
    ):
        return False

    if not delegation.is_valid():
        return False

    if not verifier.verify(
        delegation.parent
    ):
        return False

    if not verifier.verify(
        delegation.child
    ):
        return False

    if clock is not None:
        now = float(clock())

        if now < delegation.parent.issued_at:
            return False

        if now >= delegation.parent.expires_at:
            return False

        if now < delegation.child.issued_at:
            return False

        if now >= delegation.child.expires_at:
            return False

    return True


def can_delegate(
    capability: Capability,
) -> bool:
    return isinstance(
        capability,
        Capability,
    )