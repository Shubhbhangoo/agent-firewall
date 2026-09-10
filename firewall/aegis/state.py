"""The Aegis grant state machine.

Seven states, derived from what the implementation can actually observe
rather than assumed from a candidate list. A state earned its place only
by being *distinguishable*: there is something the system does in that
state and does not do in the others.

    ISSUED        registered, never authorized -- no USED lifecycle event
    ACTIVE        at least one canonical allow observed, no restriction
    NARROWED      a restriction is active and admits a strict subset
    SUSPENDED     a restriction is active and admits nothing
    REVALIDATING  Aegis's knowledge is in flight or stale
    REVOKED       terminal, backed by the revocation registry
    EXPIRED       terminal, latched on observation

Residual authority orders them:

    REVOKED = EXPIRED = REVALIDATING < SUSPENDED < NARROWED < ACTIVE = ISSUED

``REVALIDATING`` sits at the bottom on purpose. While Aegis does not know
whether a grant still holds, its advisory answer withholds -- unknown is
not trusted. That is also what makes the machine's central rule sound:

**A transition is legal iff it does not increase residual authority**,
with exactly two additional conditions:

1. ``REVALIDATING -> ACTIVE`` is the one edge that increases residual
   authority. It requires an ``AuthorizationResult`` that the canonical
   boundary produced and that allowed. Aegis consumes a verdict; it never
   makes one.
2. ``NARROWED | SUSPENDED -> REVALIDATING`` requires naming the
   restriction being lifted, so a caller cannot clear a restriction it
   does not know exists.

and one absolute: **a terminal state has no outgoing edges.** Residual
authority alone would permit ``REVOKED -> REVALIDATING`` (both are zero),
which is the first step of an authority resurrection. Terminality is
therefore checked separately and first.

``EXPIRED`` is latched rather than re-derived from the clock, so a clock
moving backwards cannot un-expire an Aegis grant. The boundary derives
expiry independently in ``_gate_time`` and the verifier; latching is
strictly the safer of the two readings and never widens.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping, Optional

from firewall.authorization import AuthorizationResult


class AegisState(str, Enum):
    """The seven states. ``str`` based so reports serialise without a shim."""

    ISSUED = "issued"
    ACTIVE = "active"
    REVALIDATING = "revalidating"
    NARROWED = "narrowed"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


#: How much authority a grant retains in each state. Only the ordering
#: matters; the absolute numbers are arbitrary and never arithmetic.
RESIDUAL_AUTHORITY: Mapping[AegisState, int] = {
    AegisState.ISSUED: 3,
    AegisState.ACTIVE: 3,
    AegisState.NARROWED: 2,
    AegisState.SUSPENDED: 1,
    AegisState.REVALIDATING: 0,
    AegisState.REVOKED: 0,
    AegisState.EXPIRED: 0,
}

#: No outgoing edges. Checked before the residual-authority rule, which
#: would otherwise permit ``REVOKED -> REVALIDATING``.
TERMINAL_STATES = frozenset(
    {
        AegisState.REVOKED,
        AegisState.EXPIRED,
    }
)

#: The one edge that may increase residual authority, and only against a
#: canonical allow.
EVIDENCED_EDGES = frozenset(
    {
        (AegisState.REVALIDATING, AegisState.ACTIVE),
    }
)
#: Edges that require naming the restriction being cleared.
LIFT_EDGES = frozenset(
    {
        (AegisState.NARROWED, AegisState.REVALIDATING),
        (AegisState.SUSPENDED, AegisState.REVALIDATING),
    }
)


class IllegalTransition(ValueError):
    """The requested transition is not an edge of the machine.

    A ``ValueError`` rather than a custom hierarchy root because callers
    inside the authorization path must not distinguish "Aegis refused" from
    "Aegis broke": both fail closed, and FAIL_CLOSED requires the gate to
    decide rather than raise.
    """


def residual_authority(state: AegisState) -> int:
    return RESIDUAL_AUTHORITY[state]


def transition_is_legal(
    from_state: AegisState,
    to_state: AegisState,
) -> bool:
    """The structural rule, with no reference to evidence.

    Evidence and lift keys are *additional* requirements checked by
    :meth:`AegisGrant.transition`; a caller asking only "is this an edge"
    gets the shape of the machine.
    """

    if from_state in TERMINAL_STATES:
        return False

    if from_state == to_state:
        return True

    if (from_state, to_state) in EVIDENCED_EDGES:
        return True

    return residual_authority(to_state) <= residual_authority(from_state)
def canonical_allow_for(
    fingerprint: str,
    evidence: Any,
) -> bool:
    """Is ``evidence`` a canonical allow for ``fingerprint``?

    Four independent structural conditions, which together match only
    what ``firewall.authorization._result(..., True, "authorized")``
    produces: the type, the allow, the canonical reason, and a trace
    naming this capability. Each is checked separately so that a verdict
    failing any one of them is refused -- an allow carrying some other
    reason is a verdict the boundary reached by another route, and it is
    not this edge's evidence.

    This is a *structural* binding, not a cryptographic one, and the
    distinction is stated rather than glossed. A caller with in-process
    code execution can fabricate an object that satisfies all four -- but
    such a caller can also just call ``FirewallSDK.authorize()`` and get a
    real one, so the forgery buys nothing. What the check does buy is that
    no ordinary path -- a recommendation, a risk score, a simulation
    outcome, a monitoring verdict, a truthy sentinel -- can be mistaken for
    an allow.
    """

    if not isinstance(evidence, AuthorizationResult):
        return False

    if evidence.allowed is not True:
        return False

    if evidence.reason != "authorized":
        return False

    trace = evidence.trace

    if not isinstance(trace, Mapping):
        return False

    return trace.get("capability_id") == fingerprint
@dataclass(frozen=True)
class Transition:
    """One recorded edge. The history is the explanation (§17)."""

    from_state: AegisState
    to_state: AegisState
    at: float
    reason: str
    #: The ``RevalidationTrigger`` value that produced it, when a change
    #: rather than an operator drove the transition.
    trigger: Optional[str] = None
    #: For an evidenced edge: the fingerprint the canonical allow named.
    evidence: Optional[str] = None
    #: For a lift edge: the restriction key that was cleared.
    lifted: Optional[str] = None

    def describe(self) -> dict:
        return {
            "from": self.from_state.value,
            "to": self.to_state.value,
            "at": self.at,
            "reason": self.reason,
            "trigger": self.trigger,
            "evidence": self.evidence,
            "lifted": self.lifted,
        }

    @property
    def widens(self) -> bool:
        return residual_authority(self.to_state) > residual_authority(
            self.from_state
        )
@dataclass(frozen=True)
class AegisGrant:
    """A capability's Aegis state and the transitions that produced it.

    Immutable. :meth:`transition` returns a new grant, so a caller holding
    an old one cannot observe a state that was later left -- and cannot
    write one back either.
    """

    fingerprint: str
    agent_id: str
    capability: str
    state: AegisState = AegisState.ISSUED
    history: tuple[Transition, ...] = ()
    created_at: float = field(default_factory=time.time)

    def __bool__(self) -> bool:
        raise TypeError(
            "an AegisGrant is not a decision; read .state, or call "
            "FirewallSDK.authorize() to decide"
        )

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def residual(self) -> int:
        return residual_authority(self.state)

    def can_transition_to(self, to_state: AegisState) -> bool:
        return transition_is_legal(self.state, to_state)
    def transition(
        self,
        to_state: AegisState,
        reason: str,
        *,
        at: Optional[float] = None,
        trigger: Optional[str] = None,
        evidence: Any = None,
        lifted: Optional[str] = None,
    ) -> "AegisGrant":
        """Move to ``to_state``, or raise :class:`IllegalTransition`.

        Raising rather than returning the unchanged grant: a caller that
        believes it suspended a grant must not carry on as if it had.
        """

        if not isinstance(to_state, AegisState):
            raise IllegalTransition(f"not a state: {to_state!r}")

        if self.state in TERMINAL_STATES:
            raise IllegalTransition(
                f"{self.state.value} is terminal; "
                f"{self.state.value} -> {to_state.value} would resurrect "
                f"authority"
            )

        if not transition_is_legal(self.state, to_state):
            raise IllegalTransition(
                f"{self.state.value} -> {to_state.value} increases residual "
                f"authority and is not an evidenced edge"
            )

        edge = (self.state, to_state)
        evidence_fingerprint: Optional[str] = None

        if edge in EVIDENCED_EDGES:
            if not canonical_allow_for(self.fingerprint, evidence):
                raise IllegalTransition(
                    f"{self.state.value} -> {to_state.value} requires a "
                    f"canonical allow for {self.fingerprint}; Aegis does not "
                    f"produce one"
                )

            evidence_fingerprint = self.fingerprint

        if edge in LIFT_EDGES and not lifted:
            raise IllegalTransition(
                f"{self.state.value} -> {to_state.value} requires naming the "
                f"restriction being lifted"
            )
        recorded = Transition(
            from_state=self.state,
            to_state=to_state,
            at=time.time() if at is None else float(at),
            reason=reason,
            trigger=trigger,
            evidence=evidence_fingerprint,
            lifted=lifted,
        )

        return replace(
            self,
            state=to_state,
            history=self.history + (recorded,),
        )

    def describe(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "state": self.state.value,
            "residual_authority": self.residual,
            "terminal": self.terminal,
            "created_at": self.created_at,
            "history": [item.describe() for item in self.history],
        }


def history_violations(grant: AegisGrant) -> tuple[str, ...]:
    """Findings about a recorded history, for AEGIS_STATE_TRANSITIONS.

    Checks the history as *data*, independently of the code that produced
    it. An invariant that re-ran ``transition`` to decide whether the
    history was legal would be testing the checker against itself.
    """

    findings: list[str] = []
    state = None

    for index, item in enumerate(grant.history):
        if state is not None and item.from_state is not state:
            findings.append(
                f"history[{index}]: starts at {item.from_state.value} but the "
                f"previous transition ended at {state.value}"
            )
        if item.from_state in TERMINAL_STATES:
            findings.append(
                f"history[{index}]: leaves the terminal state "
                f"{item.from_state.value}"
            )

        edge = (item.from_state, item.to_state)

        if item.widens and edge not in EVIDENCED_EDGES:
            findings.append(
                f"history[{index}]: {item.from_state.value} -> "
                f"{item.to_state.value} widens residual authority on an edge "
                f"that carries no evidence requirement"
            )

        if edge in EVIDENCED_EDGES and item.evidence != grant.fingerprint:
            findings.append(
                f"history[{index}]: evidenced edge "
                f"{item.from_state.value} -> {item.to_state.value} records "
                f"evidence {item.evidence!r}, not this grant's fingerprint"
            )

        if edge in LIFT_EDGES and not item.lifted:
            findings.append(
                f"history[{index}]: lift edge {item.from_state.value} -> "
                f"{item.to_state.value} names no restriction"
            )

        if item.from_state is not item.to_state and not transition_is_legal(
            item.from_state,
            item.to_state,
        ):
            findings.append(
                f"history[{index}]: {item.from_state.value} -> "
                f"{item.to_state.value} is not an edge of the machine"
            )

        state = item.to_state

    if state is not None and state is not grant.state:
        findings.append(
            f"grant state is {grant.state.value} but its history ends at "
            f"{state.value}"
        )

    return tuple(findings)
