"""Replayable authorization requests.

A :class:`RequestCase` is the *material facts* of one authorization
request: the shape of the capability chain that made it, the request
payload, and the decision that was observed. It deliberately does not
carry a :class:`~firewall.capability.Capability`, a signature, or a
public key -- a case is meant to be written to disk, reviewed in a pull
request, and replayed in a throwaway workspace, none of which should
involve real signing material.

Because a replay re-issues capabilities with a fresh simulation key, a
case reproduces the facts the authorization gates *reason about* (agent,
capability name, issuer, constraints, delegation depth and lineage, tool
binding, revocation) rather than the original bytes. Whether that
reproduction was faithful is not assumed -- :mod:`firewall.simulation.replay`
measures it per case and reports the cases where it did not hold.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Optional

#: Ceiling on a single user-supplied string in a case, matching the
#: console's own input ceiling.
MAX_STRING = 200

#: Ceiling on a constraint or request map, matching the console's.
MAX_KEYS = 32

#: Replay lifetime used when a case does not record one.
DEFAULT_LIFETIME_SECONDS = 3600.0


class SimulationError(Exception):
    """Raised for a malformed case, case set, or rule set."""


def _text(
    value: Any,
    field_name: str,
    *,
    required: bool = True,
) -> Optional[str]:
    if value is None:
        if required:
            raise SimulationError(
                f"{field_name} is required"
            )
        return None

    if not isinstance(value, str):
        raise SimulationError(
            f"{field_name} must be a string"
        )

    if required and not value.strip():
        raise SimulationError(
            f"{field_name} must not be empty"
        )

    if len(value) > MAX_STRING:
        raise SimulationError(
            f"{field_name} is too long"
        )

    return value


def _mapping(
    value: Any,
    field_name: str,
) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise SimulationError(
            f"{field_name} must be an object"
        )

    if len(value) > MAX_KEYS:
        raise SimulationError(
            f"{field_name} has too many keys"
        )

    for key in value:
        if not isinstance(key, str):
            raise SimulationError(
                f"{field_name} keys must be strings"
            )

    # A case is written to disk and read back, so it must survive a JSON
    # round trip. Rejecting here beats discovering it at replay time.
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise SimulationError(
            f"{field_name} is not JSON-serializable"
        ) from exc

    return deepcopy(value)


@dataclass(frozen=True)
class DelegationHop:
    """One delegation step: who received authority, and narrowed how."""

    delegatee: str
    constraints: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        _text(self.delegatee, "delegatee")
        object.__setattr__(
            self,
            "constraints",
            _mapping(
                self.constraints,
                "hop constraints",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "delegatee": self.delegatee,
            "constraints": deepcopy(
                self.constraints
            ),
        }

    @classmethod
    def from_dict(
        cls,
        payload: Any,
    ) -> "DelegationHop":
        if not isinstance(payload, dict):
            raise SimulationError(
                "a delegation hop must be an object"
            )

        return cls(
            delegatee=payload.get("delegatee"),
            constraints=payload.get("constraints"),
        )


@dataclass(frozen=True)
class RequestCase:
    """One replayable authorization request."""

    case_id: str
    action: str
    capability: str
    root_agent: str
    issuer: str = "trusted-issuer"
    root_constraints: dict[str, Any] = field(
        default_factory=dict
    )
    hops: tuple[DelegationHop, ...] = ()
    request: dict[str, Any] = field(
        default_factory=dict
    )
    tool: Optional[str] = None
    lifetime: float = DEFAULT_LIFETIME_SECONDS
    revoked_agents: tuple[str, ...] = ()
    expired: bool = False
    baseline_allowed: Optional[bool] = None
    baseline_reason: Optional[str] = None
    recorded_at: Optional[float] = None
    note: Optional[str] = None

    def __post_init__(self) -> None:
        for name in (
            "case_id",
            "action",
            "capability",
            "root_agent",
            "issuer",
        ):
            _text(getattr(self, name), name)

        _text(self.tool, "tool", required=False)
        _text(self.note, "note", required=False)

        object.__setattr__(
            self,
            "root_constraints",
            _mapping(
                self.root_constraints,
                "root_constraints",
            ),
        )
        object.__setattr__(
            self,
            "request",
            _mapping(self.request, "request"),
        )

        hops = tuple(self.hops or ())

        for hop in hops:
            if not isinstance(hop, DelegationHop):
                raise SimulationError(
                    "hops must be DelegationHop values"
                )

        if len(hops) > MAX_KEYS:
            raise SimulationError(
                "too many delegation hops"
            )

        object.__setattr__(self, "hops", hops)

        revoked = tuple(self.revoked_agents or ())

        for agent in revoked:
            _text(agent, "revoked agent")

        object.__setattr__(
            self,
            "revoked_agents",
            revoked,
        )

        if isinstance(self.lifetime, bool) or not isinstance(
            self.lifetime,
            (int, float),
        ):
            raise SimulationError(
                "lifetime must be a number"
            )

        if (
            self.lifetime != self.lifetime
            or self.lifetime in (
                float("inf"),
                float("-inf"),
            )
        ):
            raise SimulationError(
                "lifetime must be finite"
            )

        if self.lifetime <= 0:
            raise SimulationError(
                "lifetime must be positive"
            )

        if not isinstance(self.expired, bool):
            raise SimulationError(
                "expired must be a boolean"
            )

        if self.baseline_allowed is not None:
            if not isinstance(
                self.baseline_allowed,
                bool,
            ):
                raise SimulationError(
                    "baseline_allowed must be a boolean"
                )

        _text(
            self.baseline_reason,
            "baseline_reason",
            required=False,
        )

    # ------------------------------------------------------------------
    # Derived facts
    # ------------------------------------------------------------------

    @property
    def depth(self) -> int:
        """Effective delegation depth: the root counts as 1."""

        return 1 + len(self.hops)

    @property
    def agent(self) -> str:
        """The agent that actually made the request."""

        if self.hops:
            return self.hops[-1].delegatee

        return self.root_agent

    @property
    def agents(self) -> tuple[str, ...]:
        """Every agent in the chain, root first."""

        return (self.root_agent,) + tuple(
            hop.delegatee for hop in self.hops
        )

    @property
    def reproducible(self) -> bool:
        """Whether a fresh workspace can reconstruct this case.

        An already-expired capability cannot be re-created by issuing a
        new one, so such a case is replayed but never counted toward a
        blast-radius claim.
        """

        return not self.expired

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "action": self.action,
            "capability": self.capability,
            "root_agent": self.root_agent,
            "issuer": self.issuer,
            "root_constraints": deepcopy(
                self.root_constraints
            ),
            "hops": [
                hop.to_dict() for hop in self.hops
            ],
            "request": deepcopy(self.request),
            "tool": self.tool,
            "lifetime": self.lifetime,
            "revoked_agents": list(
                self.revoked_agents
            ),
            "expired": self.expired,
            "baseline_allowed": self.baseline_allowed,
            "baseline_reason": self.baseline_reason,
            "recorded_at": self.recorded_at,
            "note": self.note,
        }

    @classmethod
    def from_dict(
        cls,
        payload: Any,
    ) -> "RequestCase":
        if not isinstance(payload, dict):
            raise SimulationError(
                "a case must be an object"
            )

        raw_hops = payload.get("hops") or []

        if not isinstance(raw_hops, list):
            raise SimulationError(
                "hops must be a list"
            )

        raw_revoked = (
            payload.get("revoked_agents") or []
        )

        if not isinstance(raw_revoked, list):
            raise SimulationError(
                "revoked_agents must be a list"
            )

        lifetime = payload.get("lifetime")

        return cls(
            case_id=payload.get("case_id"),
            action=payload.get("action"),
            capability=payload.get("capability"),
            root_agent=payload.get("root_agent"),
            issuer=payload.get(
                "issuer",
                "trusted-issuer",
            ),
            root_constraints=payload.get(
                "root_constraints"
            ),
            hops=tuple(
                DelegationHop.from_dict(hop)
                for hop in raw_hops
            ),
            request=payload.get("request"),
            tool=payload.get("tool"),
            lifetime=(
                DEFAULT_LIFETIME_SECONDS
                if lifetime is None
                else lifetime
            ),
            revoked_agents=tuple(raw_revoked),
            expired=bool(payload.get("expired")),
            baseline_allowed=payload.get(
                "baseline_allowed"
            ),
            baseline_reason=payload.get(
                "baseline_reason"
            ),
            recorded_at=payload.get("recorded_at"),
            note=payload.get("note"),
        )


class CaseSet:
    """An ordered, de-duplicated collection of cases."""

    def __init__(
        self,
        cases: Iterable[RequestCase] = (),
    ):
        self._cases: dict[str, RequestCase] = {}

        for case in cases:
            self.add(case)

    def add(
        self,
        case: RequestCase,
    ) -> None:
        if not isinstance(case, RequestCase):
            raise SimulationError(
                "a case set holds RequestCase values"
            )

        # Last write wins: re-recording the same request should refresh
        # its observed decision rather than duplicate the case.
        self._cases[case.case_id] = case

    def __iter__(self) -> Iterator[RequestCase]:
        return iter(self._cases.values())

    def __len__(self) -> int:
        return len(self._cases)

    def __contains__(self, case_id: object) -> bool:
        return case_id in self._cases

    def get(
        self,
        case_id: str,
    ) -> Optional[RequestCase]:
        return self._cases.get(case_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "cases": [
                case.to_dict() for case in self
            ],
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
    ) -> "CaseSet":
        if not isinstance(payload, dict):
            raise SimulationError(
                "a case set must be an object"
            )

        raw = payload.get("cases")

        if raw is None:
            raise SimulationError(
                "case set is missing 'cases'"
            )

        if not isinstance(raw, list):
            raise SimulationError(
                "'cases' must be a list"
            )

        return cls(
            RequestCase.from_dict(entry)
            for entry in raw
        )

    @classmethod
    def from_json(
        cls,
        text: str,
    ) -> "CaseSet":
        try:
            payload = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise SimulationError(
                "case set is not valid JSON"
            ) from exc

        return cls.from_dict(payload)
