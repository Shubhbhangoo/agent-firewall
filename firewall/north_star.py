from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Optional,
)

from firewall.capability import (
    Capability,
    capability_fingerprint,
)
from firewall.security_decision import (
    DecisionReason,
    SecurityDecision,
)


@dataclass(frozen=True)
class AuthorizationPhase:
    """
    One phase in the North Star authorization pipeline.

    A phase receives the current authorization state and returns
    a SecurityDecision when it wants to terminate the pipeline,
    or None when authorization should continue.
    """

    name: str
    evaluator: Callable[
        [dict[str, Any]],
        Optional[SecurityDecision],
    ]


@dataclass(frozen=True)
class DelegationAuthority:
    """
    Immutable representation of effective delegation lineage.

    The first capability is the capability presented by the caller.
    Remaining capabilities are its registered ancestors.

    North Star does not replace the existing SDK delegation
    enforcement here. It establishes a canonical, immutable
    representation that later phases can consume.
    """

    capabilities: tuple[Capability, ...]
    fingerprints: tuple[str, ...]

    @property
    def depth(self) -> int:
        return len(self.capabilities)

    @property
    def requested(self) -> Capability:
        return self.capabilities[0]

    @property
    def root(self) -> Capability:
        return self.capabilities[-1]

    @classmethod
    def from_chain(
        cls,
        chain: tuple[Capability, ...],
    ) -> "DelegationAuthority":
        if not isinstance(chain, tuple):
            chain = tuple(chain)

        if not chain:
            raise ValueError(
                "delegation chain cannot be empty"
            )

        if any(
            not isinstance(
                capability,
                Capability,
            )
            for capability in chain
        ):
            raise TypeError(
                "delegation chain must contain "
                "Capability objects"
            )

        fingerprints = tuple(
            capability_fingerprint(
                capability
            )
            for capability in chain
        )

        if len(set(fingerprints)) != len(
            fingerprints
        ):
            raise ValueError(
                "delegation chain contains a cycle"
            )

        return cls(
            capabilities=chain,
            fingerprints=fingerprints,
        )


def delegation_phase(
    resolver: Callable[
        [Capability],
        tuple[Capability, ...],
    ],
    *,
    max_depth: Optional[int] = None,
) -> AuthorizationPhase:
    """
    Create a North Star delegation phase.

    The resolver remains responsible for retrieving the established
    SDK delegation lineage. North Star validates that lineage and
    publishes an immutable DelegationAuthority into pipeline state.

    No budget or authorization side effects occur in this phase.
    """

    if not callable(resolver):
        raise TypeError(
            "delegation resolver must be callable"
        )

    if max_depth is not None:
        if (
            isinstance(max_depth, bool)
            or not isinstance(max_depth, int)
        ):
            raise TypeError(
                "max_depth must be an integer"
            )

        if max_depth <= 0:
            raise ValueError(
                "max_depth must be positive"
            )

    def evaluate(
        state: dict[str, Any],
    ) -> Optional[SecurityDecision]:
        capability = state.get(
            "capability"
        )

        if not isinstance(
            capability,
            Capability,
        ):
            return SecurityDecision.deny(
                "invalid_capability",
                action=state.get(
                    "action",
                    "",
                ),
                metadata={
                    "phase": "delegation",
                },
            )

        try:
            chain = resolver(
                capability
            )
            authority = (
                DelegationAuthority.from_chain(
                    chain
                )
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            return SecurityDecision.deny(
                "delegation_chain_error",
                action=state.get(
                    "action",
                    "",
                ),
                metadata={
                    "phase": "delegation",
                    "error_type": type(
                        exc
                    ).__name__,
                },
            )
        except Exception as exc:
            return SecurityDecision.deny(
                DecisionReason.INTERNAL_ERROR,
                action=state.get(
                    "action",
                    "",
                ),
                metadata={
                    "phase": "delegation",
                    "error_type": type(
                        exc
                    ).__name__,
                },
            )

        if max_depth is not None:
            if authority.depth > max_depth:
                return SecurityDecision.deny(
                    "delegation_depth_exceeded",
                    action=state.get(
                        "action",
                        "",
                    ),
                    metadata={
                        "phase": "delegation",
                        "depth": authority.depth,
                        "max_depth": max_depth,
                    },
                )

        state["delegation_authority"] = (
            authority
        )

        return None

    return AuthorizationPhase(
        name="delegation",
        evaluator=evaluate,
    )


class NorthStarPipeline:
    """
    Canonical v1.6 authorization pipeline.

    North Star defines the ordering and control flow of security
    decisions while individual security components continue to own
    their specialized enforcement rules.

    Phases are immutable. Adding a phase returns a new pipeline,
    preventing accidental mutation of an already configured pipeline.
    """

    def __init__(
        self,
        phases: Optional[
            tuple[AuthorizationPhase, ...]
        ] = None,
    ):
        if phases is None:
            phases = ()

        if not isinstance(
            phases,
            tuple,
        ):
            phases = tuple(phases)

        for phase in phases:
            if not isinstance(
                phase,
                AuthorizationPhase,
            ):
                raise TypeError(
                    "phases must contain "
                    "AuthorizationPhase objects"
                )

        self._phases = phases

    @property
    def phases(
        self,
    ) -> tuple[AuthorizationPhase, ...]:
        return self._phases

    def add_phase(
        self,
        name: str,
        evaluator: Callable[
            [dict[str, Any]],
            Optional[SecurityDecision],
        ],
    ) -> "NorthStarPipeline":
        if not isinstance(
            name,
            str,
        ) or not name.strip():
            raise ValueError(
                "phase name must be a non-empty string"
            )

        if not callable(evaluator):
            raise TypeError(
                "phase evaluator must be callable"
            )

        return NorthStarPipeline(
            phases=(
                *self._phases,
                AuthorizationPhase(
                    name=name,
                    evaluator=evaluator,
                ),
            )
        )

    def add_phase_object(
        self,
        phase: AuthorizationPhase,
    ) -> "NorthStarPipeline":
        if not isinstance(
            phase,
            AuthorizationPhase,
        ):
            raise TypeError(
                "phase must be an AuthorizationPhase"
            )

        return NorthStarPipeline(
            phases=(
                *self._phases,
                phase,
            )
        )

    def evaluate(
        self,
        *,
        capability: Any,
        action: str,
        request: Optional[dict] = None,
        context: Optional[
            dict[str, Any]
        ] = None,
    ) -> SecurityDecision:
        state: dict[str, Any] = {
            "capability": capability,
            "action": action,
            "request": (
                {}
                if request is None
                else request
            ),
        }

        if context:
            state.update(context)

        for phase in self._phases:
            try:
                decision = phase.evaluator(
                    state
                )
            except Exception as exc:
                return SecurityDecision.deny(
                    DecisionReason.INTERNAL_ERROR,
                    action=action,
                    metadata={
                        "phase": phase.name,
                        "error_type": type(
                            exc
                        ).__name__,
                    },
                )

            if decision is not None:
                return decision

        return SecurityDecision.allow(
            action=action,
            metadata={
                "pipeline": "north_star",
            },
        )
