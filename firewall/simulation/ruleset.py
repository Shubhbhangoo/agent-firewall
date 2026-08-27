"""The globally scoped rules a person can author.

A :class:`RuleSet` is deliberately small. It holds exactly the two rules
that the existing authorization pipeline already enforces globally:

* ``max_delegation_depth`` -- the ceiling applied by the delegation-depth
  gate. ``None`` leaves the policy disabled.
* ``trusted_issuers`` -- the set consulted by the issuer gate.

It is *not* a policy language. There is no rule here that the gates do
not already implement, and adding one would mean adding a second
authorization system, which this package exists to avoid. Per-capability
narrowing is expressed where it already lives: in a capability's
constraints, authored through ``issue``/``attenuate``/``delegate``.

Validation mirrors the SDK's own contract for ``max_delegation_depth``
(reject ``bool`` and non-``int`` as a type error, reject non-positive
values) so a rule set can never be constructed that the SDK would refuse
to accept.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from firewall.simulation.case import (
    MAX_KEYS,
    MAX_STRING,
    SimulationError,
)


class RuleSet:
    """An immutable set of globally scoped authorization rules."""

    __slots__ = (
        "_depth",
        "_issuers",
    )

    def __init__(
        self,
        *,
        max_delegation_depth: Optional[int] = None,
        trusted_issuers: Iterable[str] = (),
    ):
        self._depth = _depth(max_delegation_depth)
        self._issuers = _issuers(trusted_issuers)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def max_delegation_depth(
        self,
    ) -> Optional[int]:
        return self._depth

    @property
    def trusted_issuers(self) -> frozenset[str]:
        return self._issuers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RuleSet):
            return NotImplemented

        return (
            self._depth == other._depth
            and self._issuers == other._issuers
        )

    def __hash__(self) -> int:
        return hash((self._depth, self._issuers))

    def __repr__(self) -> str:
        return (
            "RuleSet(max_delegation_depth="
            f"{self._depth!r}, trusted_issuers="
            f"{sorted(self._issuers)!r})"
        )

    # ------------------------------------------------------------------
    # Derivation
    # ------------------------------------------------------------------

    @classmethod
    def from_sdk(cls, sdk: Any) -> "RuleSet":
        """Snapshot the rules a live SDK is currently enforcing."""

        return cls(
            max_delegation_depth=getattr(
                sdk,
                "max_delegation_depth",
                None,
            ),
            trusted_issuers=sdk.issuer_trust_store.trusted_issuers(),
        )

    def replace(
        self,
        **changes: Any,
    ) -> "RuleSet":
        """Return a copy with the named rules changed."""

        unknown = set(changes) - {
            "max_delegation_depth",
            "trusted_issuers",
        }

        if unknown:
            raise SimulationError(
                "unknown rule: "
                + ", ".join(sorted(unknown))
            )

        return RuleSet(
            max_delegation_depth=changes.get(
                "max_delegation_depth",
                self._depth,
            ),
            trusted_issuers=changes.get(
                "trusted_issuers",
                self._issuers,
            ),
        )

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def diff(
        self,
        other: "RuleSet",
    ) -> dict[str, Any]:
        """Describe the change from ``self`` to ``other``."""

        if not isinstance(other, RuleSet):
            raise SimulationError(
                "can only diff against a RuleSet"
            )

        changes: dict[str, Any] = {}

        if self._depth != other._depth:
            changes["max_delegation_depth"] = {
                "before": self._depth,
                "after": other._depth,
            }

        trusted = other._issuers - self._issuers
        untrusted = self._issuers - other._issuers

        if trusted or untrusted:
            changes["trusted_issuers"] = {
                "trusted": sorted(trusted),
                "untrusted": sorted(untrusted),
            }

        return changes

    def describe(
        self,
        other: Optional["RuleSet"] = None,
    ) -> list[str]:
        """Human-readable lines for the change, newest intent first."""

        if other is None:
            lines = []

            if self._depth is None:
                lines.append(
                    "delegation depth is unbounded"
                )
            else:
                lines.append(
                    "delegation depth is capped at "
                    f"{self._depth}"
                )

            lines.append(
                f"{len(self._issuers)} trusted issuer(s)"
            )

            return lines

        changes = self.diff(other)
        lines = []

        depth = changes.get(
            "max_delegation_depth"
        )

        if depth is not None:
            before = (
                "unbounded"
                if depth["before"] is None
                else depth["before"]
            )
            after = (
                "unbounded"
                if depth["after"] is None
                else depth["after"]
            )
            lines.append(
                "delegation depth "
                f"{before} -> {after}"
            )

        issuers = changes.get("trusted_issuers")

        if issuers is not None:
            if issuers["trusted"]:
                lines.append(
                    "trust "
                    + ", ".join(issuers["trusted"])
                )
            if issuers["untrusted"]:
                lines.append(
                    "untrust "
                    + ", ".join(
                        issuers["untrusted"]
                    )
                )

        if not lines:
            lines.append("no rule changes")

        return lines

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    def apply_to(self, sdk: Any) -> "RuleSet":
        """Make a live SDK enforce these rules.

        Returns the rule set that was in force beforehand, so the caller
        can restore it. This is the only mutating operation in the
        package, and :class:`~firewall.simulation.rollout.Rollout` is the
        only thing that calls it outside of an isolated replay workspace.
        """

        previous = RuleSet.from_sdk(sdk)

        # Depth first: raising the ceiling can only ever widen, and
        # lowering it can only ever narrow, so neither ordering leaves a
        # window where more is permitted than either rule set allows.
        sdk.max_delegation_depth = self._depth

        for issuer in sorted(
            previous._issuers - self._issuers
        ):
            sdk.revoke_issuer(issuer)

        for issuer in sorted(
            self._issuers - previous._issuers
        ):
            sdk.trust_issuer(issuer)

        return previous

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_delegation_depth": self._depth,
            "trusted_issuers": sorted(
                self._issuers
            ),
        }

    def to_json(
        self,
        *,
        indent: int = 2,
    ) -> str:
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
        )

    @classmethod
    def from_dict(
        cls,
        payload: Any,
    ) -> "RuleSet":
        if not isinstance(payload, dict):
            raise SimulationError(
                "a rule set must be an object"
            )

        unknown = set(payload) - {
            "max_delegation_depth",
            "trusted_issuers",
        }

        if unknown:
            raise SimulationError(
                "unknown rule: "
                + ", ".join(sorted(unknown))
            )

        return cls(
            max_delegation_depth=payload.get(
                "max_delegation_depth"
            ),
            trusted_issuers=payload.get(
                "trusted_issuers"
            )
            or (),
        )

    @classmethod
    def from_json(cls, text: str) -> "RuleSet":
        try:
            payload = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise SimulationError(
                "rule set is not valid JSON"
            ) from exc

        return cls.from_dict(payload)


def _depth(value: Any) -> Optional[int]:
    if value is None:
        return None

    # Mirrors FirewallSDK's own contract exactly, so a rule set can never
    # hold a depth the SDK would reject.
    if isinstance(value, bool) or not isinstance(
        value,
        int,
    ):
        raise SimulationError(
            "max_delegation_depth must be an integer"
        )

    if value <= 0:
        raise SimulationError(
            "max_delegation_depth must be positive"
        )

    return value


def _issuers(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()

    if isinstance(value, (str, bytes)):
        raise SimulationError(
            "trusted_issuers must be a collection of strings"
        )

    try:
        items = list(value)
    except TypeError as exc:
        raise SimulationError(
            "trusted_issuers must be iterable"
        ) from exc

    if len(items) > MAX_KEYS:
        raise SimulationError(
            "too many trusted issuers"
        )

    out = set()

    for item in items:
        if not isinstance(item, str):
            raise SimulationError(
                "trusted_issuers must contain strings"
            )

        if not item.strip():
            raise SimulationError(
                "an issuer must not be empty"
            )

        if len(item) > MAX_STRING:
            raise SimulationError(
                "an issuer name is too long"
            )

        out.add(item)

    return frozenset(out)
