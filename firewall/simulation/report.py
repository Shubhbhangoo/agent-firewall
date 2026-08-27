"""What a rule change would do.

A :class:`SimulationReport` is an evidence document, not a
recommendation. It states which replayed requests changed outcome, which
ones it could not faithfully reproduce, and why -- and it keeps those two
populations strictly separate, because a blast-radius number that quietly
includes cases the simulator got wrong is worse than no number at all.

Every count in a report is derived from decisions returned by the real
authorization pipeline. The report itself computes nothing about whether a
request *should* be allowed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

#: Outcome classifications, in the order a reviewer cares about them.
UNCHANGED = "unchanged"
NEWLY_DENIED = "newly_denied"
NEWLY_ALLOWED = "newly_allowed"
REASON_CHANGED = "reason_changed"
ERRORED = "error"

CHANGE_KINDS = (
    NEWLY_DENIED,
    NEWLY_ALLOWED,
    REASON_CHANGED,
    UNCHANGED,
    ERRORED,
)


@dataclass(frozen=True)
class CaseOutcome:
    """One case, evaluated under both rule sets."""

    case_id: str
    action: str
    capability: str
    agent: str
    agents: tuple[str, ...]
    depth: int
    change: str
    before_allowed: Optional[bool] = None
    before_reason: Optional[str] = None
    after_allowed: Optional[bool] = None
    after_reason: Optional[str] = None
    baseline_reason: Optional[str] = None
    reproducible: bool = True
    faithful: bool = True
    error: Optional[str] = None
    note: Optional[str] = None

    @property
    def counted(self) -> bool:
        """Whether this case may back a claim about the rule change.

        A case counts only when the simulator both reconstructed it and
        reproduced the decision that was originally observed. Anything
        else is reported, but never counted.
        """

        return (
            self.error is None
            and self.reproducible
            and self.faithful
        )

    @property
    def changed(self) -> bool:
        return self.change not in (
            UNCHANGED,
            ERRORED,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "action": self.action,
            "capability": self.capability,
            "agent": self.agent,
            "agents": list(self.agents),
            "depth": self.depth,
            "change": self.change,
            "before_allowed": self.before_allowed,
            "before_reason": self.before_reason,
            "after_allowed": self.after_allowed,
            "after_reason": self.after_reason,
            "baseline_reason": self.baseline_reason,
            "reproducible": self.reproducible,
            "faithful": self.faithful,
            "counted": self.counted,
            "error": self.error,
            "note": self.note,
        }


@dataclass(frozen=True)
class SimulationReport:
    """The result of replaying a case set under two rule sets."""

    before: dict[str, Any]
    after: dict[str, Any]
    diff: dict[str, Any]
    description: tuple[str, ...]
    outcomes: tuple[CaseOutcome, ...] = ()
    skipped: int = 0
    caveats: tuple[str, ...] = field(
        default_factory=tuple
    )

    # ------------------------------------------------------------------
    # Aggregates
    # ------------------------------------------------------------------

    @property
    def counted_outcomes(
        self,
    ) -> tuple[CaseOutcome, ...]:
        return tuple(
            outcome
            for outcome in self.outcomes
            if outcome.counted
        )

    @property
    def excluded_outcomes(
        self,
    ) -> tuple[CaseOutcome, ...]:
        return tuple(
            outcome
            for outcome in self.outcomes
            if not outcome.counted
        )

    def by_change(
        self,
        kind: str,
        *,
        counted_only: bool = True,
    ) -> tuple[CaseOutcome, ...]:
        source = (
            self.counted_outcomes
            if counted_only
            else self.outcomes
        )

        return tuple(
            outcome
            for outcome in source
            if outcome.change == kind
        )

    @property
    def totals(self) -> dict[str, int]:
        counted = self.counted_outcomes

        return {
            "cases": len(self.outcomes),
            "counted": len(counted),
            "excluded": len(
                self.excluded_outcomes
            ),
            "skipped": self.skipped,
            NEWLY_DENIED: len(
                self.by_change(NEWLY_DENIED)
            ),
            NEWLY_ALLOWED: len(
                self.by_change(NEWLY_ALLOWED)
            ),
            REASON_CHANGED: len(
                self.by_change(REASON_CHANGED)
            ),
            UNCHANGED: len(
                self.by_change(UNCHANGED)
            ),
            ERRORED: len(
                self.by_change(
                    ERRORED,
                    counted_only=False,
                )
            ),
        }

    @property
    def blast_radius(self) -> dict[str, Any]:
        """Who and what a newly denying rule would stop."""

        denied = self.by_change(NEWLY_DENIED)

        agents = sorted(
            {
                outcome.agent
                for outcome in denied
            }
        )
        capabilities = sorted(
            {
                outcome.capability
                for outcome in denied
            }
        )
        actions = sorted(
            {
                outcome.action
                for outcome in denied
            }
        )
        reasons = sorted(
            {
                outcome.after_reason
                for outcome in denied
                if outcome.after_reason
            }
        )

        return {
            "newly_denied": len(denied),
            "agents": agents,
            "capabilities": capabilities,
            "actions": actions,
            "reasons": reasons,
        }

    @property
    def safe(self) -> bool:
        """Whether the change denies nothing that works today.

        Deliberately conservative: a case the simulator could not stand
        behind makes the answer ``False``, because "we could not tell"
        must never read as "nothing breaks".
        """

        return (
            not self.by_change(NEWLY_DENIED)
            and not self.excluded_outcomes
            and self.skipped == 0
        )

    # ------------------------------------------------------------------
    # Presentation
    # ------------------------------------------------------------------

    def summary(self) -> str:
        totals = self.totals
        radius = self.blast_radius

        parts = [
            "; ".join(self.description)
            or "no rule changes",
            f"{totals['counted']} of {totals['cases']} "
            "case(s) counted",
        ]

        if radius["newly_denied"]:
            parts.append(
                f"{radius['newly_denied']} newly denied "
                f"({', '.join(radius['agents'])})"
            )
        else:
            parts.append("nothing newly denied")

        if totals[NEWLY_ALLOWED]:
            parts.append(
                f"{totals[NEWLY_ALLOWED]} newly allowed"
            )

        if totals["excluded"]:
            parts.append(
                f"{totals['excluded']} not counted"
            )

        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": dict(self.before),
            "after": dict(self.after),
            "diff": dict(self.diff),
            "description": list(self.description),
            "totals": self.totals,
            "blast_radius": self.blast_radius,
            "safe": self.safe,
            "summary": self.summary(),
            "caveats": list(self.caveats),
            "outcomes": [
                outcome.to_dict()
                for outcome in self.outcomes
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
