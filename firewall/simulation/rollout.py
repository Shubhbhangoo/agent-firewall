"""Staged rule promotion: observe -> warn -> enforce.

This is governance, not authorization. A :class:`Rollout` decides nothing
about any request; it decides whether a *rule set* has earned the right to
take effect. The only thing it can ultimately do is call
:meth:`RuleSet.apply_to`, which sets the same two knobs a Python caller
could set directly.

The value is in what it refuses to skip:

* A rule set cannot be enforced before it has been simulated.
* A simulation whose evidence is stale -- run against a different set of
  live rules than the ones now in force -- does not count.
* A rule set that newly denies traffic, or that the simulator could not
  fully stand behind, cannot be enforced without an explicit
  acknowledgement recorded in the history.
* Enforcing snapshots the previous rules, so a rollback is always
  available and always exact.

Every transition is appended to an immutable history, so "who changed the
depth ceiling, on what evidence" has an answer.
"""

from __future__ import annotations

import copy
import time
from enum import Enum
from typing import Any, Iterable, Optional

from firewall.simulation.case import (
    CaseSet,
    RequestCase,
)
from firewall.simulation.replay import (
    MAX_CASES,
    simulate,
)
from firewall.simulation.report import (
    NEWLY_DENIED,
    SimulationReport,
)
from firewall.simulation.ruleset import RuleSet


class RolloutError(Exception):
    """Raised when a promotion step is not permitted yet."""


class RolloutStage(str, Enum):
    """How far a candidate rule set has progressed."""

    #: Proposed. Nothing has been evaluated and nothing is in force.
    OBSERVE = "observe"

    #: Simulated. The evidence exists; the rules are still not in force.
    WARN = "warn"

    #: In force on the target SDK.
    ENFORCE = "enforce"

    #: Withdrawn, or rolled back after being enforced.
    REVERTED = "reverted"


class Rollout:
    """A candidate rule set, and the evidence for promoting it."""

    def __init__(
        self,
        sdk: Any,
        candidate: RuleSet,
        *,
        label: str = "candidate",
    ):
        if not isinstance(candidate, RuleSet):
            raise RolloutError(
                "candidate must be a RuleSet"
            )

        if not isinstance(label, str) or not label.strip():
            raise RolloutError(
                "label must be a non-empty string"
            )

        self.sdk = sdk
        self.candidate = candidate
        self.label = label

        self._stage = RolloutStage.OBSERVE
        self._report: Optional[SimulationReport] = None

        #: The rules the simulation's "before" side was taken from. If
        #: the live rules move afterwards, the evidence is stale.
        self._evidence_baseline: Optional[RuleSet] = None

        #: Rules in force immediately before this one was enforced.
        self._restore_point: Optional[RuleSet] = None

        self._history: list[dict[str, Any]] = []

        self._log(
            "proposed",
            detail={
                "candidate": candidate.to_dict(),
                "current": self.current().to_dict(),
            },
        )

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def stage(self) -> RolloutStage:
        return self._stage

    @property
    def report(
        self,
    ) -> Optional[SimulationReport]:
        return self._report

    @property
    def history(self) -> tuple[dict[str, Any], ...]:
        # A deep copy: the history is advertised as immutable, and a
        # caller must not be able to rewrite what was recorded.
        return tuple(
            copy.deepcopy(entry)
            for entry in self._history
        )

    def current(self) -> RuleSet:
        """The rules the target SDK is enforcing right now."""

        return RuleSet.from_sdk(self.sdk)

    @property
    def evidence_is_current(self) -> bool:
        """Whether the simulation still describes today's rules."""

        if self._report is None:
            return False

        return (
            self._evidence_baseline
            == self.current()
        )

    def _log(
        self,
        event: str,
        *,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        self._history.append(
            {
                "seq": len(self._history) + 1,
                "timestamp": time.time(),
                "event": event,
                "stage": self._stage.value,
                "label": self.label,
                "detail": detail or {},
            }
        )

    # ------------------------------------------------------------------
    # observe -> warn
    # ------------------------------------------------------------------

    def simulate(
        self,
        cases: Iterable[RequestCase] | CaseSet,
        *,
        limit: int = MAX_CASES,
    ) -> SimulationReport:
        """Gather the evidence. Never touches the target SDK."""

        if self._stage is RolloutStage.ENFORCE:
            raise RolloutError(
                "already enforced; propose a new rollout to change "
                "the rules again"
            )

        if self._stage is RolloutStage.REVERTED:
            raise RolloutError(
                "this rollout was reverted and cannot be re-simulated"
            )

        baseline = self.current()

        report = simulate(
            cases,
            baseline,
            self.candidate,
            limit=limit,
        )

        self._report = report
        self._evidence_baseline = baseline
        self._stage = RolloutStage.WARN

        self._log(
            "simulated",
            detail={
                "summary": report.summary(),
                "totals": report.totals,
                "blast_radius": report.blast_radius,
                "safe": report.safe,
            },
        )

        return report

    # ------------------------------------------------------------------
    # warn -> enforce
    # ------------------------------------------------------------------

    def promote(
        self,
        *,
        acknowledge: bool = False,
        actor: str = "console",
    ) -> RuleSet:
        """Put the candidate into force. Returns the restore point."""

        if self._stage is RolloutStage.ENFORCE:
            raise RolloutError(
                "already enforced"
            )

        if self._stage is RolloutStage.REVERTED:
            raise RolloutError(
                "this rollout was reverted"
            )

        if self._report is None:
            raise RolloutError(
                "simulate before promoting: a rule set is not "
                "enforced on an unexamined guess"
            )

        if not self.evidence_is_current:
            raise RolloutError(
                "the live rules changed since this was simulated; "
                "re-simulate before promoting"
            )

        blocking = self._blocking_findings()

        if blocking and not acknowledge:
            raise RolloutError(
                "promotion refused: "
                + "; ".join(blocking)
                + " -- pass acknowledge=True to accept this"
            )

        restore_point = self.candidate.apply_to(
            self.sdk
        )

        self._restore_point = restore_point
        self._stage = RolloutStage.ENFORCE

        self._log(
            "enforced",
            detail={
                "actor": actor,
                "acknowledged": bool(blocking)
                and acknowledge,
                "findings": blocking,
                "restore_point": restore_point.to_dict(),
                "enforced": self.candidate.to_dict(),
            },
        )

        return restore_point

    def _blocking_findings(self) -> list[str]:
        """Reasons a promotion should not be silent."""

        report = self._report

        if report is None:
            return ["no simulation evidence"]

        findings = []

        denied = report.totals[NEWLY_DENIED]

        if denied:
            radius = report.blast_radius
            findings.append(
                f"{denied} recorded request(s) would be newly denied "
                f"for {', '.join(radius['agents'])}"
            )

        excluded = len(report.excluded_outcomes)

        if excluded:
            findings.append(
                f"{excluded} case(s) could not be verified, so the "
                "effect on them is unknown"
            )

        if report.skipped:
            findings.append(
                f"{report.skipped} case(s) were not replayed"
            )

        return findings

    # ------------------------------------------------------------------
    # Reversal
    # ------------------------------------------------------------------

    def rollback(
        self,
        *,
        actor: str = "console",
    ) -> RuleSet:
        """Restore the rules that were in force before promotion."""

        if self._stage is not RolloutStage.ENFORCE:
            raise RolloutError(
                "nothing to roll back: this rollout is not enforced"
            )

        assert self._restore_point is not None

        restored = self._restore_point
        displaced = restored.apply_to(self.sdk)

        self._stage = RolloutStage.REVERTED

        self._log(
            "rolled_back",
            detail={
                "actor": actor,
                "restored": restored.to_dict(),
                "displaced": displaced.to_dict(),
            },
        )

        return restored

    def withdraw(
        self,
        *,
        actor: str = "console",
    ) -> None:
        """Abandon a candidate that was never enforced."""

        if self._stage is RolloutStage.ENFORCE:
            raise RolloutError(
                "already enforced; roll back instead of withdrawing"
            )

        if self._stage is RolloutStage.REVERTED:
            return

        self._stage = RolloutStage.REVERTED

        self._log(
            "withdrawn",
            detail={"actor": actor},
        )

    # ------------------------------------------------------------------
    # Projection
    # ------------------------------------------------------------------

    def state(self) -> dict[str, Any]:
        report = self._report

        return {
            "label": self.label,
            "stage": self._stage.value,
            "candidate": self.candidate.to_dict(),
            "current": self.current().to_dict(),
            "evidence_is_current": (
                self.evidence_is_current
            ),
            "blocking": self._blocking_findings()
            if report is not None
            else ["no simulation evidence"],
            "restore_point": (
                self._restore_point.to_dict()
                if self._restore_point is not None
                else None
            ),
            "report": (
                report.to_dict()
                if report is not None
                else None
            ),
            "history": list(self._history),
        }
